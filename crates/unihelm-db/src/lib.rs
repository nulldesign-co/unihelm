//! `unihelm-db` — SQLite state for the whole panel (spec §4.1, §9).
//!
//! The panel has **no external database dependency**: a control panel that needs
//! MariaDB running to tell you why MariaDB is down has the dependency arrow
//! pointing the wrong way. Everything lives in one SQLite file in WAL mode.
//!
//! Two rules shape this crate:
//!
//! 1. **Repositories take a [`unihelm_core::TenantScope`], not raw ids.** You
//!    cannot write an un-scoped tenant query by accident — you have to ask for
//!    [`TenantScope::Global`] on purpose (spec §6.1).
//! 2. **Single-writer discipline.** `unihelm-agentd` owns writes to tasks and
//!    metrics; `unihelm-web` owns sessions and audit. Keeping the writers apart is
//!    what avoids `SQLITE_BUSY` storms under load (spec §5.5).
//! 3. **`unihelm-agentd` owns the schema.** It is the only production process
//!    that migrates, and it does so under an exclusive `flock` (see
//!    [`migrate_lock`]). Everything else — `unihelm-web`, `unihelm doctor`,
//!    `unihelm user create-admin`, every CLI session — uses [`Db::open`], which
//!    never creates the file and never applies a migration. The doors are named
//!    so the short, obvious one is the safe one.
//!
//! TODO(scope): queries use the runtime `sqlx::query_as` API rather than the
//! compile-time-checked `query_as!` macros. The macros need either a live
//! `DATABASE_URL` at build time or a committed `.sqlx` offline cache, and a
//! hermetic `cargo build` matters more while the schema is still moving. Revisit
//! before the Phase 2 schema lands; the query strings do not change, only the
//! call syntax.

pub mod alerts;
pub mod audit;
pub mod backups;
pub mod branding;
pub mod certificates;
pub mod cron;
pub mod databases;
pub mod dns;
pub mod firewall;
pub mod imports;
pub mod mail;
pub mod migrate_lock;

/// Where [`Db::open`] keeps the advisory lock that serialises schema changes.
///
/// Exposed so that code which removes a database file — a backup's temporary
/// snapshot, say — can remove the sidecar it left beside it too.
pub fn schema_lock_path(db: &std::path::Path) -> std::path::PathBuf {
    migrate_lock::lock_path(db)
}
pub mod models;
pub mod node_apps;
pub mod panel;
pub mod password;
pub mod plans;
pub mod plugins;
pub mod quota;
pub mod revisions;
pub mod scheduler;
pub mod scope;
pub mod secrets;
pub mod sessions;
pub mod settings;
pub mod sites;
pub mod stack;
pub mod subscriptions;
pub mod tasks;
pub mod users;
pub mod waf;
pub mod webhooks;
pub mod wordpress;

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Sqlite, SqlitePool, Transaction};

pub use alerts::{AlertEvent, AlertKind, AlertRule, ChannelKind, NotifyChannel};
pub use backups::{
    BackupRepo, BackupRun, BackupSchedule, BackupScope, NewBackupRepo, NewBackupSchedule, RepoKind,
    RepoSecrets, RunOutcome, RunStatus,
};
pub use branding::{
    AssetKind, Branding, BrandingAsset, BrandingField, BrandingUpdate, ImageType, ResolvedAsset,
    ResolvedBranding,
};
pub use certificates::{AcmeAccount, CertKind, CertStatus, Certificate};
pub use cron::{CronJob, CronJobUpdate, NewCronJob};
pub use databases::{Database, DbEngine, DbUser, NewDatabase, NewDbUser};
pub use dns::{DnsProvider, DnsProviderKind};
pub use firewall::{FwRuleRecord, SentinelBan};
pub use imports::{ImportPlanRecord, ImportSource, NewImportPlan};
pub use mail::{MailRelay, NewMailRelay, TlsMode};
pub use models::*;
pub use node_apps::{NewNodeApp, NodeApp, NodeEnv};
pub use plans::{NewPlan, Plan, PlanUpdate};
pub use plugins::{NewPlugin, PluginRecord, PluginSignature};
pub use quota::{QuotaLimits, QuotaProject};
pub use revisions::ConfigRevision;
pub use scheduler::ScheduledJob;
pub use scope::ScopeFilter;
pub use secrets::MasterKey;
pub use sites::{NewSite, Site, SiteStatus, SiteType, SiteUpdate, WwwPolicy};
pub use stack::{ComponentStatus, StackComponent};
pub use subscriptions::{Subscription, SubscriptionStatus};
pub use waf::{NewWafExclusion, WafExclusion, WafMode, WafSitePolicy};
pub use webhooks::{DueDelivery, NewWebhook, Webhook, WebhookDelivery};
pub use wordpress::{NewWpInstall, WpInstall};

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("stored {field} is not valid: {detail}")]
    Corrupt { field: &'static str, detail: String },

    #[error("{0}")]
    Domain(#[from] unihelm_core::UnihelmError),

    #[error("{what} not found")]
    NotFound { what: &'static str },

    #[error("{what} already exists")]
    Conflict { what: &'static str },

    #[error(
        "no panel database at {path} yet — unihelm-agentd creates it on first start \
         (systemctl start unihelm-agentd)"
    )]
    NotInitialised { path: std::path::PathBuf },

    #[error("the panel database at {path} is not ready: {state}")]
    SchemaNotReady {
        path: std::path::PathBuf,
        state: SchemaState,
    },

    #[error(
        "another process has held the schema lock on {path} for {waited:?} — check \
         `systemctl status unihelm-agentd`"
    )]
    SchemaLockBusy {
        path: std::path::PathBuf,
        waited: Duration,
    },

    #[error(
        "cannot open the schema lock at {path}, so this process cannot prove it is \
         the only one migrating — refusing rather than rewriting the schema \
         unserialised. Check that the directory is writable by the account \
         running unihelm-agentd."
    )]
    SchemaLockUnavailable { path: std::path::PathBuf },
}

pub type Result<T, E = DbError> = std::result::Result<T, E>;

impl From<DbError> for unihelm_core::UnihelmError {
    fn from(e: DbError) -> Self {
        use unihelm_core::{ErrorCode, UnihelmError};
        match e {
            DbError::Domain(inner) => inner,
            DbError::NotFound { what } => UnihelmError::not_found(what),
            DbError::Conflict { what } => {
                UnihelmError::new(ErrorCode::AlreadyExists, format!("{what} already exists"))
            }
            // Everything else is our problem, not the caller's: report a generic
            // internal error and keep the detail in the log.
            other => {
                tracing::error!(error = %other, "database failure");
                UnihelmError::internal("a database error occurred")
            }
        }
    }
}

/// The migrations this binary carries.
///
/// One source of truth for both [`Db::migrate`] and [`Db::schema_state`], so the
/// two can never disagree about what "current" means.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Where a database's schema sits relative to the binary looking at it.
///
/// Every variant's `Display` is a sentence somebody reads in a log at 3am, and
/// it names the command that fixes it. The thing it replaces is
/// `migration failed: while executing migration 1: table users already exists`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaState {
    /// No `_sqlx_migrations` rows: nothing has ever migrated this file.
    Empty,
    /// Everything this binary knows is applied, and every checksum matches.
    Ready { version: i64 },
    /// The owner has not caught up yet.
    Behind {
        applied: Option<i64>,
        expected: i64,
        pending: usize,
    },
    /// Migrated by a newer Unihelm than this binary. A downgrade.
    Ahead { applied: i64, expected: i64 },
    /// An applied migration's checksum differs from this build's copy.
    /// Forward-only migrations cannot repair this.
    Diverged { version: i64 },
    /// Recorded as started and never finished.
    Dirty { version: i64 },
}

impl SchemaState {
    /// Is this a state the agent is about to fix by itself?
    ///
    /// A downgrade, a checksum mismatch or a dirty migration will still be true
    /// in forty-five seconds, so waiting on those would only hide them.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Empty | Self::Behind { .. })
    }
}

impl std::fmt::Display for SchemaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready { version } => write!(f, "schema {version:04} applied"),
            Self::Empty => f.write_str(
                "no migrations have been applied — unihelm-agentd creates the schema on \
                 start: systemctl start unihelm-agentd",
            ),
            Self::Behind {
                applied,
                expected,
                pending,
            } => write!(
                f,
                "schema is at {}, this build expects {expected:04} ({pending} pending) — \
                 restart the agent to apply them: systemctl restart unihelm-agentd",
                match applied {
                    Some(v) => format!("{v:04}"),
                    None => "no migrations".into(),
                }
            ),
            Self::Ahead { applied, expected } => write!(
                f,
                "schema {applied:04} was applied by a newer Unihelm; this build knows \
                 {expected:04} — install the matching version rather than downgrading a \
                 live panel"
            ),
            Self::Diverged { version } => write!(
                f,
                "migration {version:04} was applied with different content than this build \
                 ships; forward-only migrations cannot repair this — restore from backup"
            ),
            Self::Dirty { version } => write!(
                f,
                "migration {version:04} was recorded as started and never finished"
            ),
        }
    }
}

/// The panel database handle.
#[derive(Clone, Debug)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Open a panel database that already exists, and take its schema as it
    /// stands. **Never creates the file, never migrates.**
    ///
    /// This is the door for every process that is not the agent: `unihelm-web`,
    /// `unihelm doctor`, `unihelm user create-admin`, every CLI session. The
    /// unprivileged, internet-facing half of the panel does not rewrite a
    /// root-owned schema (spec §5.1, §5.5) — and until this existed it did,
    /// which is how two processes ended up racing sqlx's migrator.
    ///
    /// The schema check runs under a *shared* lock, so a non-owner never
    /// concludes "this install is broken" from a schema that is mid-migration.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        // `create_if_missing(false)` answers a missing file with SQLite error
        // 14, "unable to open database file", which tells an operator nothing.
        // Check first, so the error names the file and the daemon that makes it.
        if !path.exists() {
            return Err(DbError::NotInitialised {
                path: path.to_path_buf(),
            });
        }
        let db = Self::attach(path, false).await?;
        let state = {
            let _shared = migrate_lock::acquire_or_skip(
                path,
                migrate_lock::Mode::Shared,
                migrate_lock::DEFAULT_WAIT,
            )
            .await;
            db.schema_state().await?
        };
        match state {
            SchemaState::Ready { .. } => Ok(db),
            // A mixed-version box mid-upgrade. Refusing here would break every
            // window where the two binaries differ, so this is a warning.
            SchemaState::Ahead { applied, expected } => {
                tracing::warn!(applied, expected, "the schema is newer than this binary");
                Ok(db)
            }
            other => {
                db.close().await;
                Err(DbError::SchemaNotReady {
                    path: path.to_path_buf(),
                    state: other,
                })
            }
        }
    }

    /// [`Db::open`], but wait for the owner to finish first.
    ///
    /// `unihelm-web` uses this. Waiting rather than failing fast is not
    /// politeness: with `Restart=always`, `RestartSec=2` and
    /// `StartLimitBurst=10`, failing fast puts the unit permanently in `failed`
    /// about twenty seconds into a slow agent start. It also keeps
    /// `tests/gates/budgets.sh`, which starts both daemons at once, passing
    /// unmodified.
    ///
    /// Only the states the agent is about to fix are waited on; see
    /// [`SchemaState::is_transient`].
    pub async fn open_waiting(path: impl AsRef<Path>, limit: Duration) -> Result<Self> {
        let path = path.as_ref();
        let deadline = tokio::time::Instant::now() + limit;
        let mut announced = false;
        loop {
            let expired = tokio::time::Instant::now() >= deadline;
            match Self::open(path).await {
                Ok(db) => return Ok(db),
                Err(DbError::NotInitialised { .. }) if !expired => {
                    if !announced {
                        announced = true;
                        tracing::info!(
                            path = %path.display(),
                            "waiting for unihelm-agentd to create the panel database"
                        );
                    }
                }
                Err(DbError::SchemaNotReady { state, .. }) if !expired && state.is_transient() => {
                    if !announced {
                        announced = true;
                        tracing::info!(%state, "waiting for unihelm-agentd to migrate the panel database");
                    }
                }
                Err(e) => return Err(e),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Open, creating the file if needed, then apply pending migrations under an
    /// **exclusive** lock.
    ///
    /// Only the schema's owner calls this: `unihelm-agentd`, and a `--dev`
    /// instance (where there may be no agent at all, so the dev half has to
    /// migrate for itself — the lock is what makes that safe).
    pub async fn open_and_migrate(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| DbError::Corrupt {
                field: "database directory",
                detail: e.to_string(),
            })?;
        }

        // The guard covers pool creation as well as the migration, deliberately:
        // sqlx issues `PRAGMA journal_mode = WAL` on connect, and the first
        // rollback->WAL conversion wants an exclusive lock that does not
        // reliably honour the busy handler. Two processes creating this file at
        // the same instant is a second, smaller race, closed here for free.
        let guard = migrate_lock::acquire(
            path,
            migrate_lock::Mode::Exclusive,
            migrate_lock::DEFAULT_WAIT,
        )
        .await?;

        let db = Self::attach(path, true).await?;
        if let SchemaState::Diverged { version } = db.schema_state().await? {
            db.close().await;
            return Err(DbError::SchemaNotReady {
                path: path.to_path_buf(),
                state: SchemaState::Diverged { version },
            });
        }
        db.migrate().await?;
        drop(guard);
        Ok(db)
    }

    /// Open whatever is at `path` and report its schema, applying nothing and
    /// requiring nothing.
    ///
    /// For `unihelm doctor`, whose job is to describe the system rather than
    /// change it. Until this existed, the command an operator runs *because*
    /// something looks wrong was itself a migrator — and, on a machine where the
    /// agent had never run, it conjured a fully migrated database owned by
    /// whoever typed it and then reported it healthy.
    pub async fn open_unchecked(path: impl AsRef<Path>) -> Result<(Self, SchemaState)> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(DbError::NotInitialised {
                path: path.to_path_buf(),
            });
        }
        let db = Self::attach(path, false).await?;
        // A short cap, and never fatal: `doctor` must not hang behind another
        // process's migration.
        let _shared =
            migrate_lock::acquire_or_skip(path, migrate_lock::Mode::Shared, Duration::from_secs(2))
                .await;
        let state = db.schema_state().await?;
        Ok((db, state))
    }

    /// A private in-memory database, for tests.
    pub async fn open_memory() -> Result<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .expect("the in-memory URL is a constant")
            .foreign_keys(true);
        // An in-memory database lives inside one connection, so the pool must
        // hold exactly one and never close it.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await?;
        let db = Self { pool };
        // No lock: an in-memory database is private to one connection and has
        // nobody to race.
        db.migrate().await?;
        Ok(db)
    }

    async fn attach(path: &Path, create: bool) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            // Only the owner creates the file. A non-owner that creates it makes
            // an empty database owned by the wrong user — which is how
            // `/var/lib/unihelm/panel.db` ends up owned by `unihelm` on a box
            // where the agent has never run.
            .create_if_missing(create)
            // WAL keeps readers from blocking the single writer — the whole
            // reason the panel stays responsive while a task is running.
            .journal_mode(SqliteJournalMode::Wal)
            // NORMAL is durable across process crashes (which is what our
            // crash-only design cares about) without an fsync per commit.
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(10))
            .pragma("cache_size", "-16000");

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(15))
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }

    /// Read-only, and safe to call on a database somebody else owns: it takes a
    /// read lock only, which under WAL never blocks on the writer.
    pub async fn schema_state(&self) -> Result<SchemaState> {
        let recorded: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sqlite_master \
             WHERE type = 'table' AND name = '_sqlx_migrations'",
        )
        .fetch_one(&self.pool)
        .await?;
        if recorded == 0 {
            return Ok(SchemaState::Empty);
        }

        let applied: Vec<(i64, Vec<u8>, bool)> = sqlx::query_as(
            "SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(&self.pool)
        .await?;
        if applied.is_empty() {
            return Ok(SchemaState::Empty);
        }
        if let Some((version, _, _)) = applied.iter().find(|(_, _, ok)| !ok) {
            return Ok(SchemaState::Dirty { version: *version });
        }

        // The same checksum comparison `Migrator::run` makes — but now every
        // process makes it on every start, not just whichever one migrated.
        for m in MIGRATOR.iter() {
            if let Some((_, seen, _)) = applied.iter().find(|(v, _, _)| *v == m.version)
                && seen.as_slice() != m.checksum.as_ref()
            {
                return Ok(SchemaState::Diverged { version: m.version });
            }
        }

        // Set difference, never `max(applied) == max(known)`: the migrations
        // directory legitimately has holes (0016 is allocated and unlanded, and
        // `tests/gates/migrations.sh` tolerates one contiguous gap on purpose).
        let expected = MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0);
        let pending = MIGRATOR
            .iter()
            .filter(|m| !applied.iter().any(|(v, _, _)| *v == m.version))
            .count();
        let newest = applied.last().map(|(v, _, _)| *v);

        Ok(match (pending, newest) {
            (0, Some(a)) if a > expected => SchemaState::Ahead {
                applied: a,
                expected,
            },
            (0, _) => SchemaState::Ready { version: expected },
            (pending, applied) => SchemaState::Behind {
                applied,
                expected,
                pending,
            },
        })
    }

    /// Apply any pending migrations. Forward-only and checked in CI (spec §4.1).
    ///
    /// Private on purpose: the only way in is [`Db::open_and_migrate`], which
    /// holds the exclusive lock across check-and-apply. Never call this while a
    /// [`migrate_lock::SchemaLock`] is alive — `flock` conflicts between two fds
    /// in the same process, so that deadlocks you against yourself.
    async fn migrate(&self) -> Result<()> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn begin(&self) -> Result<Transaction<'static, Sqlite>> {
        Ok(self.pool.begin().await?)
    }

    /// `PRAGMA integrity_check`, surfaced by `unihelm doctor` (spec §5.5).
    pub async fn integrity_check(&self) -> Result<String> {
        let row: (String,) = sqlx::query_as("PRAGMA integrity_check")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// Current time, to the second, in UTC — the panel's one clock.
pub fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("0 is a valid nanosecond")
}

/// Format a timestamp the way every column in the schema stores it.
pub fn to_sql_time(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .expect("OffsetDateTime always formats as RFC 3339")
}

/// Parse a timestamp column.
pub fn from_sql_time(s: &str) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).map_err(|e| {
        DbError::Corrupt {
            field: "timestamp",
            detail: format!("`{s}` is not RFC 3339: {e}"),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrations_apply_to_a_fresh_database() {
        let db = Db::open_memory().await.unwrap();
        assert_eq!(db.integrity_check().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn migrations_are_idempotent() {
        let db = Db::open_memory().await.unwrap();
        db.migrate()
            .await
            .expect("re-running migrations must be a no-op");
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        let db = Db::open_memory().await.unwrap();
        let err = sqlx::query("INSERT INTO sessions (id, user_id, csrf, created_at, last_seen_at, expires_at) VALUES ('x', 999, 'c', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")
            .execute(db.pool())
            .await;
        assert!(
            err.is_err(),
            "a session for a non-existent user must be refused"
        );
    }

    #[tokio::test]
    async fn check_constraints_reject_bad_enums() {
        let db = Db::open_memory().await.unwrap();
        let err = sqlx::query(
            "INSERT INTO users (role, email, username, pass_hash, created_at, updated_at)
             VALUES ('superadmin', 'a@b.com', 'a', 'x', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .execute(db.pool())
        .await;
        assert!(
            err.is_err(),
            "the role CHECK constraint must hold at the storage layer too"
        );
    }

    #[test]
    fn timestamps_roundtrip() {
        let t = now();
        assert_eq!(from_sql_time(&to_sql_time(t)).unwrap(), t);
    }
}
