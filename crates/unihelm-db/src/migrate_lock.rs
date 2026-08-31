//! The advisory lock that serialises schema work on one database *file*.
//!
//! `unihelm-agentd` owns the schema (spec §5.1, §5.5), and after this module
//! landed it is the only production process that migrates. That is a rule, and
//! a rule enforced by nothing is a rule the next `Db::open(...)` breaks. This
//! lock turns it into an invariant, and covers the cases ownership alone cannot:
//!
//! * `--dev`, where there is no systemd ordering and `unihelm-web --dev` has to
//!   migrate for itself because there may be no agent at all. This is the
//!   reporter's repro (`tests/gates/budgets.sh` starts both daemons at once).
//! * `unihelm doctor` / `create-admin` / any CLI command run while the agent is
//!   restarting — nothing orders the CLI against anything.
//! * agentd crash-looping under `Restart=always`, containers, or anyone running
//!   the binaries under their own supervisor.
//!
//! sqlx cannot do this for us: `Migrate::lock`/`unlock` for SQLite are literally
//! `Ok(())` (unlike Postgres), so `Migrator::run` has no cross-process exclusion.
//! Two processes read an empty `_sqlx_migrations`, both decide migration 1 is
//! pending, and the loser dies on `table users already exists`.
//!
//! Three choices here are load-bearing:
//!
//! 1. **`flock(2)`, not `fcntl` record locks.** POSIX record locks are per
//!    (process, inode): closing *any* fd on the file drops every lock the
//!    process holds on it, and SQLite's unix VFS opens and closes the database
//!    behind our back. `flock` belongs to the open file description, so our fd
//!    is the only thing that governs it.
//! 2. **A sidecar file, never the database.** Restore replaces the `.db` inode,
//!    and a lock on a replaced inode locks nothing. The suffix is deliberately
//!    not `.lock` — that is what SQLite's `unix-dotfile` VFS would use.
//! 3. **Never unlinked.** Unlink-then-recreate is exactly how two processes end
//!    up flocking two different inodes and both winning.
//!
//! Ordering invariant: this lock is always taken *before* any SQLite lock and
//! released after, and never from inside a transaction. Keep it that way and a
//! deadlock against SQLite's own locking is not expressible. Corollary: never
//! call a locking `Db::open*` while a guard is alive — `flock` conflicts between
//! two fds in the same process, so that would wedge you against yourself.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::DbError;

/// Same family as SQLite's own `-wal` / `-shm`, so `grant_db_access` can carry
/// it through the one loop that already knows about the database's siblings.
pub const LOCK_SUFFIX: &str = "-migrate.lock";

/// Long enough for a cold migration on a small VPS, short enough to sit well
/// inside systemd's 90s default `TimeoutStartSec`.
pub(crate) const DEFAULT_WAIT: Duration = Duration::from_secs(30);

const POLL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    /// Held by every process for the length of its schema *check*, so a
    /// non-owner never decides "this schema is incomplete" against an answer
    /// that is being written as it reads.
    Shared,
    /// Held by whoever migrates, across check-and-apply.
    Exclusive,
}

/// The path of the lock file beside `db`.
pub fn lock_path(db: &Path) -> PathBuf {
    let mut name = db.as_os_str().to_os_string();
    name.push(LOCK_SUFFIX);
    PathBuf::from(name)
}

/// Released when dropped, by closing the fd — which the kernel also does on
/// SIGKILL, OOM kill and panic. There is no stale-lock state to clean up, which
/// is the whole reason to prefer `flock` to a pidfile.
#[derive(Debug)]
pub(crate) struct SchemaLock {
    /// `None` when locking was unavailable and we chose to proceed anyway.
    _file: Option<File>,
}

impl SchemaLock {
    /// A guard that holds nothing, for in-memory databases and for the
    /// degraded paths below.
    pub(crate) fn unheld() -> Self {
        Self { _file: None }
    }
}

/// Take the lock, or fail.
///
/// Only the exclusive (migrating) path uses this: proceeding to rewrite a schema
/// without exclusion is the bug this module exists to prevent.
pub(crate) async fn acquire(db: &Path, mode: Mode, wait: Duration) -> Result<SchemaLock, DbError> {
    let path = lock_path(db);
    let Some(file) = open_lock_file(&path, mode)? else {
        // The two modes cannot degrade the same way, because they do not fail the
        // same way. A reader that proceeds unserialised can only read a schema
        // mid-migration and get a stale answer — sqlx commits each migration and
        // its `_sqlx_migrations` row in one transaction, so there is no torn
        // state to see. A *writer* that proceeds unserialised is precisely the
        // bug this module exists to prevent, and the doc above promises it
        // cannot happen; permitting it here made that promise false.
        //
        // The old reasoning was that a directory we may not write is a directory
        // no second process is writing either. That is a guess about other
        // processes drawn from our own permissions, and it is wrong wherever the
        // directory is group-writable. It is also not a case that arises for the
        // real owner: agentd is root and owns /var/lib/unihelm.
        if mode == Mode::Exclusive {
            return Err(DbError::SchemaLockUnavailable { path });
        }
        tracing::warn!(
            path = %path.display(),
            "no schema lock available here; reading unserialised"
        );
        return Ok(SchemaLock::unheld());
    };
    match flock_until(&file, &path, mode, wait).await {
        Outcome::Locked => Ok(SchemaLock { _file: Some(file) }),
        Outcome::Unsupported => Ok(SchemaLock::unheld()),
        Outcome::TimedOut => Err(DbError::SchemaLockBusy { path, waited: wait }),
        Outcome::Failed(e) => Err(DbError::Corrupt {
            field: "schema lock",
            detail: format!("could not lock {}: {e}", path.display()),
        }),
    }
}

/// Take the lock if we can, and carry on if we cannot.
///
/// For the shared (read-only) path. A reader that skips the lock can only read a
/// *stale* schema version, never an inconsistent one — sqlx commits each
/// migration and its `_sqlx_migrations` row in one transaction. So a missing or
/// contended lock file must never be the reason the panel will not boot.
pub(crate) async fn acquire_or_skip(db: &Path, mode: Mode, wait: Duration) -> SchemaLock {
    match acquire(db, mode, wait).await {
        Ok(guard) => guard,
        Err(e) => {
            tracing::warn!(error = %e, "reading the schema without the lock");
            SchemaLock::unheld()
        }
    }
}

/// `Ok(None)` means "there is no lock file we may use here", which the callers
/// above turn into an unheld guard.
fn open_lock_file(path: &Path, mode: Mode) -> Result<Option<File>, DbError> {
    // `flock` needs no write access, but `create` does. Mode 0644 so a
    // root-created file is still usable by the unprivileged web process even
    // before `grant_db_access` has chowned it.
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        .open(path)
    {
        Ok(f) => Ok(Some(f)),
        Err(e) if is_permission_like(&e) => {
            // A reader only needs to open it; the owner is the one that creates
            // it. Fall back to a read-only open of an existing file.
            if mode == Mode::Shared
                && let Ok(f) = File::open(path)
            {
                return Ok(Some(f));
            }
            tracing::warn!(path = %path.display(), error = %e, "cannot open the schema lock");
            Ok(None)
        }
        Err(e) => Err(DbError::Corrupt {
            field: "schema lock",
            detail: format!("could not open {}: {e}", path.display()),
        }),
    }
}

fn is_permission_like(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::EROFS)
    )
}

enum Outcome {
    Locked,
    /// Some NFS mounts. Honest consequence: the race is still there.
    Unsupported,
    TimedOut,
    Failed(std::io::Error),
}

async fn flock_until(file: &File, path: &Path, mode: Mode, wait: Duration) -> Outcome {
    let op = match mode {
        Mode::Shared => libc::LOCK_SH,
        Mode::Exclusive => libc::LOCK_EX,
    } | libc::LOCK_NB;

    let started = Instant::now();
    let mut announced = false;
    loop {
        // SAFETY: `file` owns a valid fd for the whole call, and `flock`
        // dereferences no pointers.
        if unsafe { libc::flock(file.as_raw_fd(), op) } == 0 {
            return Outcome::Locked;
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EWOULDBLOCK) | Some(libc::EINTR) => {}
            Some(libc::ENOLCK) | Some(libc::EOPNOTSUPP) | Some(libc::EINVAL) => {
                tracing::warn!(
                    path = %path.display(), error = %err,
                    "this filesystem does not support flock; proceeding unserialised"
                );
                return Outcome::Unsupported;
            }
            _ => return Outcome::Failed(err),
        }
        // Non-blocking + poll rather than a blocking flock on a worker thread:
        // it buys a bounded deadline and a log line, which is what keeps
        // `unihelm doctor` from merely looking hung.
        if !announced && started.elapsed() >= Duration::from_secs(1) {
            announced = true;
            tracing::info!(
                path = %path.display(),
                "another unihelm process holds the schema lock; waiting"
            );
        }
        if started.elapsed() >= wait {
            return Outcome::TimedOut;
        }
        tokio::time::sleep(POLL).await;
    }
}

// TODO(msrv): `std::fs::File::lock()` / `try_lock()` would remove both unsafe
// blocks, but they stabilised in Rust 1.89 and the workspace MSRV is 1.88.
// Bumping the MSRV inside a bugfix is the wrong trade; revisit later.
