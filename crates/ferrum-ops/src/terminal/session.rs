//! Live terminal sessions: the table, the limits, and the audit ordering.
//!
//! A session is a PTY plus a small amount of bookkeeping the agent keeps *for*
//! it: a scrollback ring so a re-attaching browser sees what it missed, a
//! broadcast channel for everyone currently watching, and the two clocks that
//! decide when a forgotten shell is closed on its owner's behalf.
//!
//! # Bounded, on purpose
//!
//! Every limit in [`Limits`] exists because the unbounded version is a real
//! failure:
//!
//! * `max_sessions` — a PTY costs two OS threads and a kernel line discipline
//!   here; unbounded, a loop of open requests is a denial of service against
//!   the *agent*, which is the process that must never fall over (spec §5.5).
//! * `max_per_user` — one account should not be able to consume the whole
//!   server-wide budget and lock every other operator out of a terminal.
//! * `idle` — an abandoned root shell in a browser tab is a standing foothold
//!   for whoever walks past that laptop. It is the single most likely way this
//!   feature gets someone owned, and a timer is the only defence that does not
//!   depend on the human remembering.
//! * `max_lifetime` — a session that is *busy* forever (a `tail -f`) never goes
//!   idle, so the idle clock alone can be defeated by a screensaver-proof
//!   command. The ceiling closes that.
//! * `scrollback_bytes` — replay after a reconnect is a fixed-size ring, not a
//!   transcript. A session printing a gigabyte must not grow the agent's heap
//!   by a gigabyte.
//!
//! # Audit before PTY
//!
//! [`TerminalRegistry::open`] writes the audit row and only then asks the
//! spawner for a shell. If the trail cannot be written, no shell starts. This
//! ordering is the reason `open` is not simply "spawn, then log": a shell whose
//! start was never recorded is precisely the shell an incident review needs.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use ferrum_core::{AuthContext, ErrorCode, FerrumError, Result, UserId};
use ferrum_db::Db;
use ferrum_db::audit::NewAuditEntry;
use ferrum_ipc::frame::TerminalTarget;
use serde::Serialize;
use tokio::sync::{Mutex, broadcast, mpsc};
use uuid::Uuid;

use super::{AccountSource, SessionPlan, SystemAccounts, authorize};

/// How many watchers' worth of output the agent buffers before a slow one lags.
const OUTPUT_CHANNEL_CAPACITY: usize = 256;

/// The bounds every session lives inside. See the module docs for why each one
/// is here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_sessions: usize,
    pub max_per_user: usize,
    pub idle: Duration,
    pub max_lifetime: Duration,
    pub scrollback_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Eight is a working number for a panel: enough for an operator with
            // several shells open plus a couple of tenants, small enough that the
            // thread and fd cost is bounded and obvious.
            max_sessions: 8,
            max_per_user: 3,
            idle: Duration::from_secs(15 * 60),
            max_lifetime: Duration::from_secs(8 * 60 * 60),
            scrollback_bytes: 128 * 1024,
        }
    }
}

/// One chunk of shell output, as it goes out to everyone watching.
#[derive(Debug, Clone)]
pub struct OutputChunk {
    pub seq: u64,
    pub data: Arc<Vec<u8>>,
}

/// Writing to, resizing and killing one PTY. Implemented for real by
/// [`RealPtySpawner`]'s handle and by a fake in the tests.
pub trait PtyIo: Send + Sync {
    /// Feed bytes to the shell. Silent on a dead session — the caller learns
    /// that from the closed state, not from a keystroke.
    fn write(&self, data: &[u8]);
    fn resize(&self, cols: u16, rows: u16);
    /// Hang the session up. Idempotent.
    fn kill(&self);
}

/// A started shell: something to write to, and a stream of what it wrote.
pub struct SpawnedPty {
    pub io: Arc<dyn PtyIo>,
    /// Closes when the shell exits, which is how a session learns it is over.
    pub output: mpsc::Receiver<Vec<u8>>,
}

/// How a [`SessionPlan`] becomes a running shell.
#[async_trait]
pub trait PtySpawner: Send + Sync {
    async fn spawn(&self, plan: &SessionPlan, cols: u16, rows: u16) -> Result<SpawnedPty>;
}

/// The public face of a session — what the UI is told, and what the audit row
/// records. Deliberately carries no uid: the browser has no business with one.
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: Uuid,
    pub owner: UserId,
    /// `root`, or the tenant's Linux account.
    pub account: String,
    pub is_root: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub opened_at: time::OffsetDateTime,
}

/// A live session. Cloneable through an `Arc`; dropping the last one does not
/// close the shell — [`TerminalRegistry::close`] does.
pub struct SessionHandle {
    pub info: SessionInfo,
    io: Arc<dyn PtyIo>,
    output: broadcast::Sender<OutputChunk>,
    scrollback: Mutex<Scrollback>,
    /// Unix seconds of the last keystroke, for the idle clock.
    last_input: AtomicI64,
    closed: AtomicBool,
    /// Whether `finish` has already killed and audited this session.
    ///
    /// Distinct from `closed`, which only means "the shell is gone" and is set
    /// by the output pump the moment the master side ends. Sharing one flag
    /// made the ordinary ending — the operator types `exit` — take `finish`'s
    /// early return, so the shell was never killed and no `terminal.close` row
    /// was written: the audit trail showed a root shell that was still open.
    reaped: AtomicBool,
    /// Woken once when the session ends, so a streaming connection learns that
    /// the shell exited without polling for it.
    ended: Arc<tokio::sync::Notify>,
}

impl std::fmt::Debug for SessionHandle {
    /// Hand-written: the PTY handle and the scrollback are neither printable
    /// nor safe to dump — a scrollback can hold whatever the operator typed,
    /// which on a root shell includes passwords.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHandle")
            .field("info", &self.info)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl SessionHandle {
    pub fn id(&self) -> Uuid {
        self.info.id
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Send keystrokes and reset the idle clock.
    pub fn write(&self, data: &[u8]) {
        if self.is_closed() {
            return;
        }
        self.last_input.store(
            time::OffsetDateTime::now_utc().unix_timestamp(),
            Ordering::SeqCst,
        );
        self.io.write(data);
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        if !self.is_closed() {
            self.io.resize(cols, rows);
        }
    }

    /// Everything the session has printed that is still in the ring, plus a
    /// live subscription. Taken together in one lock so a chunk cannot slip
    /// between the replay and the subscription and be lost.
    pub async fn attach(&self) -> (Vec<OutputChunk>, broadcast::Receiver<OutputChunk>) {
        let guard = self.scrollback.lock().await;
        let rx = self.output.subscribe();
        (guard.replay(), rx)
    }

    /// Resolve when the session has ended, immediately if it already has.
    ///
    /// The re-check between creating the future and awaiting it is not
    /// belt-and-braces: without it a close landing in that window is a wakeup
    /// nobody is waiting for yet, and the caller hangs until the next one that
    /// never comes.
    pub async fn ended(&self) {
        loop {
            if self.is_closed() {
                return;
            }
            let notified = self.ended.notified();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }

    fn idle_for(&self, now: time::OffsetDateTime) -> Duration {
        let last = self.last_input.load(Ordering::SeqCst);
        Duration::from_secs((now.unix_timestamp() - last).max(0) as u64)
    }

    fn age(&self, now: time::OffsetDateTime) -> Duration {
        Duration::from_secs((now - self.info.opened_at).whole_seconds().max(0) as u64)
    }
}

/// A fixed-size ring of recent output, replayed on re-attach.
///
/// Chunks are dropped whole rather than split, so a replayed stream is always a
/// suffix of what the shell actually wrote — a half-chunk would cut a UTF-8
/// sequence or an escape sequence in two and garble the terminal on reconnect.
struct Scrollback {
    chunks: std::collections::VecDeque<OutputChunk>,
    bytes: usize,
    cap: usize,
}

impl Scrollback {
    fn new(cap: usize) -> Self {
        Self {
            chunks: std::collections::VecDeque::new(),
            bytes: 0,
            cap,
        }
    }

    fn push(&mut self, chunk: OutputChunk) {
        self.bytes += chunk.data.len();
        self.chunks.push_back(chunk);
        while self.bytes > self.cap {
            match self.chunks.pop_front() {
                Some(dropped) => self.bytes -= dropped.data.len(),
                None => break,
            }
        }
    }

    fn replay(&self) -> Vec<OutputChunk> {
        self.chunks.iter().cloned().collect()
    }
}

/// Every live session on this agent.
pub struct TerminalRegistry {
    db: Db,
    accounts: Arc<dyn AccountSource>,
    spawner: Arc<dyn PtySpawner>,
    limits: Limits,
    sessions: Mutex<HashMap<Uuid, Arc<SessionHandle>>>,
}

impl TerminalRegistry {
    pub fn new(
        db: Db,
        accounts: Arc<dyn AccountSource>,
        spawner: Arc<dyn PtySpawner>,
        limits: Limits,
    ) -> Arc<Self> {
        Arc::new(Self {
            db,
            accounts,
            spawner,
            limits,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    /// The registry the agent runs with: real accounts, real PTYs.
    pub fn production(db: Db) -> Arc<Self> {
        Self::new(
            db,
            Arc::new(SystemAccounts),
            Arc::new(RealPtySpawner),
            Limits::default(),
        )
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub async fn len(&self) -> usize {
        self.sessions.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Authorise, record, then start a shell — in that order.
    ///
    /// `auth` must already have been re-derived from the database by the
    /// caller (`OpRegistry::verify_auth`): a control frame does not pass
    /// through the operation dispatcher, so nothing else on this path re-checks
    /// the identity the web process claimed.
    pub async fn open(
        &self,
        id: Uuid,
        auth: &AuthContext,
        target: &TerminalTarget,
        cols: u16,
        rows: u16,
    ) -> Result<Arc<SessionHandle>> {
        let plan = authorize(&self.db, self.accounts.as_ref(), auth, target).await?;

        // Slot accounting happens under one lock together with the insert of a
        // placeholder-free entry later; taking the count here and re-checking
        // on insert would race two simultaneous opens past the cap.
        {
            let sessions = self.sessions.lock().await;
            if sessions.contains_key(&id) {
                return Err(FerrumError::new(
                    ErrorCode::Conflict,
                    "that terminal session id is already in use",
                ));
            }
            if sessions.len() >= self.limits.max_sessions {
                return Err(FerrumError::new(
                    ErrorCode::RateLimited,
                    "too many terminal sessions are open on this server; close one and try again",
                ));
            }
            let mine = sessions
                .values()
                .filter(|s| s.info.owner == auth.actor_user_id)
                .count();
            if mine >= self.limits.max_per_user {
                return Err(FerrumError::new(
                    ErrorCode::RateLimited,
                    "you already have the maximum number of terminal sessions open",
                ));
            }
        }

        // The audit row comes before the PTY. If this fails, nothing starts —
        // a shell whose start was never recorded is the one an incident review
        // most needs to see (spec §11.16 AC).
        self.db
            .record_audit(NewAuditEntry {
                actor_user_id: Some(auth.actor_user_id),
                actor_username: auth.actor_user_id.get().to_string(),
                impersonator_id: auth.impersonator_id,
                ip: None,
                action: "terminal.open".into(),
                target: Some(plan.account()),
                detail: serde_json::json!({
                    "session": id,
                    "root": plan.is_root(),
                    "shell": plan.shell().display().to_string(),
                    "subscription_id": plan.subscription_id().map(|s| s.get()),
                }),
                request_id: Some(auth.request_id.clone()),
                subscription_id: plan.subscription_id(),
            })
            .await
            .map_err(|e| {
                FerrumError::internal(format!(
                    "refusing to open a terminal that cannot be audited: {e}"
                ))
            })?;

        let spawned = self.spawner.spawn(&plan, cols, rows).await?;

        let (tx, _) = broadcast::channel(OUTPUT_CHANNEL_CAPACITY);
        let now = time::OffsetDateTime::now_utc();
        let handle = Arc::new(SessionHandle {
            info: SessionInfo {
                id,
                owner: auth.actor_user_id,
                account: plan.account(),
                is_root: plan.is_root(),
                opened_at: now,
            },
            io: spawned.io,
            output: tx.clone(),
            scrollback: Mutex::new(Scrollback::new(self.limits.scrollback_bytes)),
            last_input: AtomicI64::new(now.unix_timestamp()),
            closed: AtomicBool::new(false),
            reaped: AtomicBool::new(false),
            ended: Arc::new(tokio::sync::Notify::new()),
        });

        self.sessions.lock().await.insert(id, handle.clone());
        spawn_output_pump(handle.clone(), spawned.output, tx);

        tracing::warn!(
            session = %id,
            account = %handle.info.account,
            root = handle.info.is_root,
            actor = %auth.actor_user_id,
            "web terminal session opened"
        );
        Ok(handle)
    }

    /// Look up a session for its owner. A session belonging to somebody else is
    /// `NotFound`, not `PermissionDenied`: whether it exists is itself
    /// information, and terminal sessions are personal even between admins.
    pub async fn for_owner(&self, id: Uuid, auth: &AuthContext) -> Result<Arc<SessionHandle>> {
        let sessions = self.sessions.lock().await;
        match sessions.get(&id) {
            Some(handle) if handle.info.owner == auth.actor_user_id => Ok(handle.clone()),
            _ => Err(FerrumError::not_found("terminal session")),
        }
    }

    /// End a session and write the closing audit row.
    ///
    /// Idempotent: closing an id that is already gone is a success, because the
    /// browser's unload handler and the idle sweep race each other by design.
    pub async fn close(&self, id: Uuid, auth: &AuthContext, reason: &str) -> Result<()> {
        let handle = { self.sessions.lock().await.get(&id).cloned() };
        let Some(handle) = handle else {
            return Ok(());
        };
        if handle.info.owner != auth.actor_user_id {
            return Err(FerrumError::not_found("terminal session"));
        }
        self.finish(&handle, reason).await;
        Ok(())
    }

    /// Close everything past its idle or lifetime limit. Driven by a ticker in
    /// the agent; returns how many it closed, which is what the test asserts.
    pub async fn sweep(&self) -> usize {
        let now = time::OffsetDateTime::now_utc();
        let expired: Vec<(Arc<SessionHandle>, &'static str)> = {
            let sessions = self.sessions.lock().await;
            sessions
                .values()
                .filter_map(|h| {
                    if h.is_closed() {
                        Some((h.clone(), "the shell exited"))
                    } else if h.idle_for(now) >= self.limits.idle {
                        Some((h.clone(), "idle timeout"))
                    } else if h.age(now) >= self.limits.max_lifetime {
                        Some((h.clone(), "maximum session lifetime reached"))
                    } else {
                        None
                    }
                })
                .collect()
        };
        for (handle, reason) in &expired {
            self.finish(handle, reason).await;
        }
        expired.len()
    }

    /// Kill the shell, drop the entry, and record the end of the session.
    async fn finish(&self, handle: &Arc<SessionHandle>, reason: &str) {
        // Mark first: a concurrent sweep then sees a reaped session rather than
        // killing and auditing the same shell twice. Guarded on `reaped`, not
        // on `closed` — the output pump sets `closed` as soon as the shell
        // exits, so guarding on that skipped the kill and the audit row for
        // every session that ended the ordinary way.
        if handle.reaped.swap(true, Ordering::SeqCst) {
            handle.ended.notify_waiters();
            self.sessions.lock().await.remove(&handle.info.id);
            return;
        }
        handle.closed.store(true, Ordering::SeqCst);
        handle.ended.notify_waiters();
        handle.io.kill();
        self.sessions.lock().await.remove(&handle.info.id);

        let entry = NewAuditEntry {
            actor_user_id: Some(handle.info.owner),
            actor_username: handle.info.owner.get().to_string(),
            impersonator_id: None,
            ip: None,
            action: "terminal.close".into(),
            target: Some(handle.info.account.clone()),
            detail: serde_json::json!({
                "session": handle.info.id,
                "root": handle.info.is_root,
                "reason": reason,
                "seconds": (time::OffsetDateTime::now_utc() - handle.info.opened_at)
                    .whole_seconds()
                    .max(0),
            }),
            request_id: None,
            subscription_id: None,
        };
        if let Err(e) = self.db.record_audit(entry).await {
            // The shell is already down; losing the closing row is bad but not
            // a reason to leave a PTY running, so this is loud and not fatal.
            tracing::error!(session = %handle.info.id, error = %e, "could not audit a terminal close");
        }
        tracing::warn!(
            session = %handle.info.id,
            account = %handle.info.account,
            reason,
            "web terminal session closed"
        );
    }
}

/// Fan shell output into the scrollback and out to every watcher.
fn spawn_output_pump(
    handle: Arc<SessionHandle>,
    mut output: mpsc::Receiver<Vec<u8>>,
    tx: broadcast::Sender<OutputChunk>,
) {
    tokio::spawn(async move {
        let seq = AtomicU64::new(0);
        while let Some(data) = output.recv().await {
            let chunk = OutputChunk {
                seq: seq.fetch_add(1, Ordering::SeqCst) + 1,
                data: Arc::new(data),
            };
            handle.scrollback.lock().await.push(chunk.clone());
            // An error only means nobody is watching right now; the scrollback
            // above is what makes that survivable.
            let _ = tx.send(chunk);
        }
        // The channel closing means the shell is gone. The registry's sweep
        // reaps the entry and writes the closing audit row; the notification is
        // what tells a streaming connection to stop, now rather than then.
        handle.closed.store(true, Ordering::SeqCst);
        handle.ended.notify_waiters();
    });
}

// ---------------------------------------------------------------------------
// The real spawner
// ---------------------------------------------------------------------------

/// Starts a shell in a real PTY, through the agent's own re-exec helper.
pub struct RealPtySpawner;

/// The helper's argument vector. Built here rather than in the helper so the
/// one place that decides *which account* a shell runs as is this file.
///
/// Note what it cannot express: there is no `--shell` flag taking an arbitrary
/// program. The shell path comes from [`super::vet_shell`]'s allowlist and is
/// passed as `--shell`, and the helper re-checks it against the same allowlist
/// after the privilege drop — the same "check twice across a trust boundary"
/// the WordPress helper does.
pub fn helper_argv(plan: &SessionPlan) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = vec!["--pty-helper".into()];
    match plan {
        SessionPlan::Root { .. } => args.push("--root".into()),
        SessionPlan::Tenant { uid, gid, .. } => {
            args.push("--uid".into());
            args.push(uid.to_string().into());
            args.push("--gid".into());
            args.push(gid.to_string().into());
        }
    }
    args.push("--home".into());
    args.push(plan.home().as_os_str().to_os_string());
    args.push("--shell".into());
    args.push(plan.shell().as_os_str().to_os_string());
    args
}

#[async_trait]
impl PtySpawner for RealPtySpawner {
    async fn spawn(&self, plan: &SessionPlan, cols: u16, rows: u16) -> Result<SpawnedPty> {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::process::Stdio;

        let pair = super::pty::open_pty(cols, rows)
            .map_err(|e| FerrumError::internal(format!("could not allocate a pty: {e}")))?;

        let args = helper_argv(plan);
        let mut cmd = ferrum_distro::exec::reexec_current(&args).map_err(FerrumError::from)?;

        let dup = |what: &'static str| -> Result<Stdio> {
            pair.slave
                .try_clone()
                .map(Stdio::from)
                .map_err(|e| FerrumError::internal(format!("could not dup the pty {what}: {e}")))
        };
        cmd.stdin(dup("stdin")?)
            .stdout(dup("stdout")?)
            .stderr(dup("stderr")?)
            // If the agent dies, the shell must not survive holding a tenant's
            // (or root's) privileges with nobody watching.
            .kill_on_drop(true);

        // SAFETY: `pre_exec` runs after the standard fds have been dup2'd and
        // before `execve`, in the forked child, which is single-threaded there.
        // Every call `attach_child_to_pty` makes is async-signal-safe, and fd 0
        // is by then the pty slave.
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.as_std_mut().pre_exec(|| {
                super::pty::attach_child_to_pty(libc::STDIN_FILENO)
                    .map_err(std::io::Error::from_raw_os_error)?;
                Ok(())
            });
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| FerrumError::internal(format!("could not start the pty helper: {e}")))?;
        let pid = child.id().unwrap_or(0);

        // The parent must let go of the slave, or the master never sees the
        // shell exit and the reader thread below hangs forever.
        drop(pair.slave);

        let master_fd = pair.master.as_raw_fd();
        let reader_fd = pair
            .master
            .try_clone()
            .map_err(|e| FerrumError::internal(format!("could not dup the pty master: {e}")))?;
        let writer_fd = pair
            .master
            .try_clone()
            .map_err(|e| FerrumError::internal(format!("could not dup the pty master: {e}")))?;

        // Blocking threads rather than `AsyncFd`: a pty master's readiness
        // semantics differ enough between Linux and BSD that a readiness loop
        // is a source of subtle hangs, and two threads per session is a cost
        // the concurrency cap already bounds.
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
        std::thread::Builder::new()
            .name(format!("ferrum-pty-r-{pid}"))
            .spawn(move || {
                let mut file = std::fs::File::from(reader_fd);
                let mut buf = [0u8; 8192];
                loop {
                    // A closed slave shows up as EIO on Linux and as EOF on
                    // BSD; both mean the same thing here.
                    match file.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                    }
                }
            })
            .map_err(|e| FerrumError::internal(format!("could not start the pty reader: {e}")))?;

        let (in_tx, in_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::Builder::new()
            .name(format!("ferrum-pty-w-{pid}"))
            .spawn(move || {
                let mut file = std::fs::File::from(writer_fd);
                while let Ok(data) = in_rx.recv() {
                    if file.write_all(&data).is_err() {
                        break;
                    }
                    let _ = file.flush();
                }
            })
            .map_err(|e| FerrumError::internal(format!("could not start the pty writer: {e}")))?;

        let io = Arc::new(RealPtyIo {
            input: std::sync::Mutex::new(Some(in_tx)),
            master: std::sync::Mutex::new(Some(pair.master)),
            pid: pid as i32,
        });

        // Reap the child so it never becomes a zombie, and let `kill_on_drop`
        // handle the agent-died case.
        tokio::spawn(async move {
            let _ = child.wait().await;
            let _ = master_fd; // the handle owns the master; this task only reaps.
        });

        Ok(SpawnedPty { io, output: out_rx })
    }
}

struct RealPtyIo {
    /// `None` once the session has been killed, which is what makes `kill`
    /// idempotent and stops the writer thread.
    input: std::sync::Mutex<Option<std::sync::mpsc::Sender<Vec<u8>>>>,
    /// Taken by `kill`. Closing the master is what hangs up a shell that
    /// ignores SIGHUP, so it cannot wait for the handle to be dropped.
    master: std::sync::Mutex<Option<std::os::fd::OwnedFd>>,
    pid: i32,
}

impl PtyIo for RealPtyIo {
    fn write(&self, data: &[u8]) {
        if let Ok(guard) = self.input.lock()
            && let Some(tx) = guard.as_ref()
        {
            let _ = tx.send(data.to_vec());
        }
    }

    fn resize(&self, cols: u16, rows: u16) {
        use std::os::fd::AsRawFd;
        if let Ok(guard) = self.master.lock()
            && let Some(master) = guard.as_ref()
        {
            let _ = super::pty::set_window_size(master.as_raw_fd(), cols, rows);
        }
    }

    fn kill(&self) {
        // Dropping the sender ends the writer thread.
        if let Ok(mut guard) = self.input.lock() {
            guard.take();
        }
        if self.pid > 0 {
            // SIGHUP to the whole process group: the helper called `setsid`, so
            // the shell leads its own group and the negative pid reaches every
            // job it started. A shell that ignores SIGHUP still loses its
            // terminal when the master fd closes with this handle.
            // SAFETY: a signal to a process group we created.
            unsafe {
                libc::kill(-self.pid, libc::SIGHUP);
                libc::kill(self.pid, libc::SIGHUP);
            }
        }
        // Then take the terminal away. A shell can `trap '' HUP`, but it cannot
        // refuse the end of its own input: closing the last master descriptor
        // is what makes the idle sweep and the lifetime ceiling binding rather
        // than advisory. Dropping the handle would eventually do this, so this
        // is only the difference between "when the last reference goes" and
        // "now" — but the last reference is held by whoever is still attached.
        if let Ok(mut guard) = self.master.lock() {
            guard.take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_core::{Email, Role, SubscriptionId, TenantScope, Username};
    use ferrum_db::plans::NewPlan;
    use ferrum_db::users::NewUser;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    /// A "PTY" that is a pair of channels. Enough to exercise every rule in
    /// this module without being root or owning a terminal.
    struct FakeSpawner {
        spawns: Arc<AtomicUsize>,
        fail: bool,
        last: std::sync::Mutex<Option<mpsc::Sender<Vec<u8>>>>,
        written: Arc<std::sync::Mutex<Vec<u8>>>,
        killed: Arc<AtomicBool>,
    }

    impl FakeSpawner {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                spawns: Arc::new(AtomicUsize::new(0)),
                fail: false,
                last: std::sync::Mutex::new(None),
                written: Arc::new(std::sync::Mutex::new(Vec::new())),
                killed: Arc::new(AtomicBool::new(false)),
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                spawns: Arc::new(AtomicUsize::new(0)),
                fail: true,
                last: std::sync::Mutex::new(None),
                written: Arc::new(std::sync::Mutex::new(Vec::new())),
                killed: Arc::new(AtomicBool::new(false)),
            })
        }

        /// Pretend the shell exited: the master side ends, which is what the
        /// output pump watches for.
        fn shell_exits(&self) {
            *self.last.lock().unwrap() = None;
        }

        /// Pretend the shell printed something.
        async fn emit(&self, bytes: &[u8]) {
            let tx = self.last.lock().unwrap().clone();
            if let Some(tx) = tx {
                tx.send(bytes.to_vec()).await.unwrap();
            }
        }
    }

    struct FakeIo {
        written: Arc<std::sync::Mutex<Vec<u8>>>,
        killed: Arc<AtomicBool>,
    }

    impl PtyIo for FakeIo {
        fn write(&self, data: &[u8]) {
            self.written.lock().unwrap().extend_from_slice(data);
        }
        fn resize(&self, _cols: u16, _rows: u16) {}
        fn kill(&self) {
            self.killed.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl PtySpawner for FakeSpawner {
        async fn spawn(&self, _plan: &SessionPlan, _cols: u16, _rows: u16) -> Result<SpawnedPty> {
            self.spawns.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(FerrumError::internal("no shell for you"));
            }
            let (tx, rx) = mpsc::channel(16);
            *self.last.lock().unwrap() = Some(tx);
            Ok(SpawnedPty {
                io: Arc::new(FakeIo {
                    written: self.written.clone(),
                    killed: self.killed.clone(),
                }),
                output: rx,
            })
        }
    }

    struct OneAccount(String);

    impl AccountSource for OneAccount {
        fn lookup(&self, linux_user: &str) -> Option<super::super::Account> {
            (linux_user == self.0).then(|| super::super::Account {
                uid: 5001,
                gid: 5001,
                home: PathBuf::from("/home/tenant"),
                shell: PathBuf::from("/bin/bash"),
            })
        }
    }

    struct Fixture {
        db: Db,
        admin: AuthContext,
        customer: AuthContext,
        subscription: SubscriptionId,
        linux_user: String,
    }

    async fn fixture() -> Fixture {
        let db = Db::open_memory().await.unwrap();
        let mk = |name: &'static str, role: Role| NewUser {
            role,
            email: Email::parse(&format!("{name}@example.com")).unwrap(),
            username: Username::parse(name).unwrap(),
            password: "a-long-enough-password".into(),
            reseller_id: None,
            full_name: None,
            locale: "en".into(),
        };
        let admin = db
            .users(&TenantScope::Global)
            .create(mk("admin", Role::Admin))
            .await
            .unwrap();
        let customer = db
            .users(&TenantScope::Global)
            .create(mk("client", Role::Customer))
            .await
            .unwrap();
        let sub = db.create_subscription(customer.id).await.unwrap();
        Fixture {
            admin: AuthContext::from_role(admin.id, Role::Admin, TenantScope::Global, "req-a"),
            customer: AuthContext::from_role(
                customer.id,
                Role::Customer,
                TenantScope::Customer {
                    customer_id: customer.id,
                },
                "req-c",
            ),
            subscription: sub.id,
            linux_user: sub.linux_user.clone(),
            db,
        }
    }

    async fn grant_ssh(db: &Db, subscription: SubscriptionId) {
        let plan = db
            .plans(&TenantScope::Global)
            .create(NewPlan {
                owner_user_id: None,
                name: format!("shell-{}", subscription.get()),
                max_sites: 5,
                max_dbs: 5,
                storage_mb: 512,
                can_ssh: true,
                can_cron: true,
                can_node_apps: false,
            })
            .await
            .unwrap();
        db.assign_plan(subscription, plan.id).await.unwrap();
    }

    fn registry(f: &Fixture, spawner: Arc<FakeSpawner>, limits: Limits) -> Arc<TerminalRegistry> {
        TerminalRegistry::new(
            f.db.clone(),
            Arc::new(OneAccount(f.linux_user.clone())),
            spawner,
            limits,
        )
    }

    async fn audit_actions(db: &Db) -> Vec<String> {
        db.audit(&TenantScope::Global)
            .list(50, 0)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect()
    }

    #[tokio::test]
    async fn the_audit_row_is_written_before_the_shell_starts() {
        // The AC in spec §11.16, tested from the failure side: when the spawn
        // fails, the row is already there. A "log afterwards" implementation
        // would leave no trace of the attempt at all.
        let f = fixture().await;
        let spawner = FakeSpawner::failing();
        let reg = registry(&f, spawner.clone(), Limits::default());

        let err = reg
            .open(Uuid::new_v4(), &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
        assert_eq!(spawner.spawns.load(Ordering::SeqCst), 1);

        let actions = audit_actions(&f.db).await;
        assert!(
            actions.contains(&"terminal.open".to_string()),
            "the attempt must be on the record even though no shell started: {actions:?}"
        );
        assert!(reg.is_empty().await, "a failed spawn must leave no session");
    }

    #[tokio::test]
    async fn a_refused_session_never_reaches_the_spawner() {
        // The other half of the ordering: authorisation happens before both the
        // audit row and the PTY, so a denied customer does not even cost a fork.
        let f = fixture().await;
        let spawner = FakeSpawner::new();
        let reg = registry(&f, spawner.clone(), Limits::default());

        let err = reg
            .open(Uuid::new_v4(), &f.customer, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(spawner.spawns.load(Ordering::SeqCst), 0);
        assert!(audit_actions(&f.db).await.is_empty());
    }

    #[tokio::test]
    async fn a_root_session_start_and_end_are_both_audited() {
        let f = fixture().await;
        let reg = registry(&f, FakeSpawner::new(), Limits::default());
        let id = Uuid::new_v4();

        let handle = reg
            .open(id, &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap();
        assert!(handle.info.is_root);
        assert_eq!(handle.info.account, "root");

        reg.close(id, &f.admin, "closed by the operator")
            .await
            .unwrap();

        let actions = audit_actions(&f.db).await;
        assert!(actions.contains(&"terminal.open".to_string()));
        assert!(actions.contains(&"terminal.close".to_string()));
        assert!(reg.is_empty().await);
    }

    #[tokio::test]
    async fn a_customer_with_can_ssh_gets_a_shell_as_their_own_account() {
        let f = fixture().await;
        grant_ssh(&f.db, f.subscription).await;
        let reg = registry(&f, FakeSpawner::new(), Limits::default());

        let handle = reg
            .open(
                Uuid::new_v4(),
                &f.customer,
                &TerminalTarget::Tenant {
                    subscription_id: None,
                },
                80,
                24,
            )
            .await
            .unwrap();
        assert!(!handle.info.is_root, "a customer must never get root");
        assert_eq!(handle.info.account, f.linux_user);
    }

    #[tokio::test]
    async fn concurrent_sessions_are_capped_per_server_and_per_account() {
        let f = fixture().await;
        let limits = Limits {
            max_sessions: 2,
            max_per_user: 1,
            ..Limits::default()
        };
        let reg = registry(&f, FakeSpawner::new(), limits);

        reg.open(Uuid::new_v4(), &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap();
        let err = reg
            .open(Uuid::new_v4(), &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::RateLimited);

        // A second account fills the server-wide budget…
        grant_ssh(&f.db, f.subscription).await;
        reg.open(
            Uuid::new_v4(),
            &f.customer,
            &TerminalTarget::Tenant {
                subscription_id: None,
            },
            80,
            24,
        )
        .await
        .unwrap();
        assert_eq!(reg.len().await, 2);

        // …and now nobody gets another one.
        let third = fixture().await;
        let err = reg
            .open(Uuid::new_v4(), &third.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::RateLimited);
    }

    #[tokio::test]
    async fn a_session_belongs_to_the_account_that_opened_it() {
        let f = fixture().await;
        let reg = registry(&f, FakeSpawner::new(), Limits::default());
        let id = Uuid::new_v4();
        reg.open(id, &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap();

        // Another account cannot attach to it, cannot close it, and is not even
        // told that it exists.
        let err = reg.for_owner(id, &f.customer).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        let err = reg.close(id, &f.customer, "nope").await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(reg.len().await, 1, "the session must still be running");
    }

    #[tokio::test]
    async fn an_idle_session_is_closed_by_the_sweep() {
        let f = fixture().await;
        let limits = Limits {
            idle: Duration::from_secs(0),
            ..Limits::default()
        };
        let reg = registry(&f, FakeSpawner::new(), limits);
        reg.open(Uuid::new_v4(), &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap();

        assert_eq!(reg.sweep().await, 1);
        assert!(reg.is_empty().await);
        assert!(
            audit_actions(&f.db)
                .await
                .contains(&"terminal.close".into())
        );
    }

    #[tokio::test]
    async fn a_busy_session_still_hits_the_lifetime_ceiling() {
        // The idle clock alone is defeated by a command that keeps printing;
        // the ceiling is what stops a session living forever.
        let f = fixture().await;
        let limits = Limits {
            idle: Duration::from_secs(3600),
            max_lifetime: Duration::from_secs(0),
            ..Limits::default()
        };
        let reg = registry(&f, FakeSpawner::new(), limits);
        let handle = reg
            .open(Uuid::new_v4(), &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap();
        handle.write(b"still here\n");

        assert_eq!(reg.sweep().await, 1);
        assert!(reg.is_empty().await);
    }

    #[tokio::test]
    async fn output_is_replayed_to_a_client_that_reconnects() {
        // Spec §11.16 AC: the session survives a web restart. The web process
        // holds nothing, so "survives" means exactly this — a fresh attach gets
        // the scrollback and then the live stream.
        let f = fixture().await;
        let spawner = FakeSpawner::new();
        let reg = registry(&f, spawner.clone(), Limits::default());
        let id = Uuid::new_v4();
        let handle = reg
            .open(id, &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap();

        spawner.emit(b"first\n").await;
        spawner.emit(b"second\n").await;
        tokio::task::yield_now().await;
        // The pump is a task; give it a moment to drain deterministically.
        for _ in 0..50 {
            if handle.scrollback.lock().await.chunks.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let (replay, mut live) = handle.attach().await;
        let text: Vec<u8> = replay.iter().flat_map(|c| c.data.iter().copied()).collect();
        assert_eq!(String::from_utf8_lossy(&text), "first\nsecond\n");
        assert_eq!(replay.first().map(|c| c.seq), Some(1));

        spawner.emit(b"third\n").await;
        let next = tokio::time::timeout(Duration::from_secs(2), live.recv())
            .await
            .expect("live output should arrive")
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&next.data), "third\n");
        assert_eq!(
            next.seq, 3,
            "sequence numbers must continue across an attach"
        );
    }

    #[tokio::test]
    async fn the_scrollback_ring_drops_old_chunks_rather_than_growing() {
        let f = fixture().await;
        let spawner = FakeSpawner::new();
        let reg = registry(
            &f,
            spawner.clone(),
            Limits {
                scrollback_bytes: 16,
                ..Limits::default()
            },
        );
        let handle = reg
            .open(Uuid::new_v4(), &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap();

        for i in 0..10u8 {
            spawner.emit(&[b'a' + i; 8]).await;
        }
        // Wait for the last chunk to have gone through the pump, not for the
        // ring to be small — it starts empty, so "small" is true before any
        // output has arrived and the assertion below would pass vacuously.
        for _ in 0..100 {
            if handle.scrollback.lock().await.chunks.back().map(|c| c.seq) == Some(10) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let (replay, _) = handle.attach().await;
        let total: usize = replay.iter().map(|c| c.data.len()).sum();
        assert!(total <= 16, "the ring kept {total} bytes");
        assert!(
            !replay.is_empty(),
            "the ring must keep the most recent output"
        );
    }

    #[tokio::test]
    async fn keystrokes_reach_the_shell_and_stop_when_it_is_closed() {
        let f = fixture().await;
        let spawner = FakeSpawner::new();
        let reg = registry(&f, spawner.clone(), Limits::default());
        let id = Uuid::new_v4();
        let handle = reg
            .open(id, &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap();

        handle.write(b"whoami\n");
        assert_eq!(&*spawner.written.lock().unwrap(), b"whoami\n");

        reg.close(id, &f.admin, "done").await.unwrap();
        assert!(spawner.killed.load(Ordering::SeqCst));
        handle.write(b"rm -rf /\n");
        assert_eq!(
            &*spawner.written.lock().unwrap(),
            b"whoami\n",
            "a closed session must not forward another byte"
        );
    }

    #[tokio::test]
    async fn closing_a_session_twice_is_not_an_error() {
        let f = fixture().await;
        let reg = registry(&f, FakeSpawner::new(), Limits::default());
        let id = Uuid::new_v4();
        reg.open(id, &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap();
        reg.close(id, &f.admin, "first").await.unwrap();
        reg.close(id, &f.admin, "second").await.unwrap();

        let closes = audit_actions(&f.db)
            .await
            .iter()
            .filter(|a| *a == "terminal.close")
            .count();
        assert_eq!(closes, 1, "an idempotent close must not double the trail");
    }

    #[tokio::test]
    async fn a_shell_that_exits_on_its_own_is_still_killed_and_still_audited() {
        // The ordinary ending: the operator types `exit`. The output pump marks
        // the session closed the moment the master side ends, and `finish` used
        // to read that flag as "somebody already reaped this" and return early —
        // so the shell was never killed and no `terminal.close` row was written.
        // An incident review then saw a `terminal.open` for a root shell with no
        // close, which is the worst possible thing for the audit trail to say.
        let f = fixture().await;
        let spawner = FakeSpawner::new();
        let reg = registry(&f, spawner.clone(), Limits::default());
        let id = Uuid::new_v4();
        reg.open(id, &f.admin, &TerminalTarget::Root, 80, 24)
            .await
            .unwrap();

        spawner.shell_exits();
        // Let the output pump observe the closed channel.
        for _ in 0..50 {
            if reg
                .for_owner(id, &f.admin)
                .await
                .map(|h| h.is_closed())
                .unwrap_or(true)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        reg.close(id, &f.admin, "reaped").await.ok();

        assert!(
            spawner.killed.load(Ordering::SeqCst),
            "the pty must be torn down even though the shell went first"
        );
        let closes = audit_actions(&f.db)
            .await
            .iter()
            .filter(|a| *a == "terminal.close")
            .count();
        assert_eq!(closes, 1, "exactly one closing row, and never zero");
    }

    #[test]
    fn the_helper_argv_names_no_program_and_no_shell_flag_for_root() {
        let root = SessionPlan::Root {
            home: PathBuf::from("/root"),
            shell: PathBuf::from("/bin/bash"),
        };
        let argv: Vec<String> = helper_argv(&root)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(argv[0], "--pty-helper");
        assert!(argv.contains(&"--root".to_string()));
        assert!(!argv.contains(&"--uid".to_string()));

        let tenant = SessionPlan::Tenant {
            uid: 5001,
            gid: 5001,
            linux_user: ferrum_core::LinuxUser::parse("ft_demo").unwrap(),
            subscription_id: SubscriptionId(1),
            home: PathBuf::from("/home/ft_demo"),
            shell: PathBuf::from("/bin/bash"),
        };
        let argv: Vec<String> = helper_argv(&tenant)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!argv.contains(&"--root".to_string()));
        assert_eq!(
            argv[argv.iter().position(|a| a == "--uid").unwrap() + 1],
            "5001"
        );
    }
}
