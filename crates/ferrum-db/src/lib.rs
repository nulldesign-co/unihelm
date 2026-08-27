//! `ferrum-db` — SQLite state for the whole panel (spec §4.1, §9).
//!
//! The panel has **no external database dependency**: a control panel that needs
//! MariaDB running to tell you why MariaDB is down has the dependency arrow
//! pointing the wrong way. Everything lives in one SQLite file in WAL mode.
//!
//! Two rules shape this crate:
//!
//! 1. **Repositories take a [`ferrum_core::TenantScope`], not raw ids.** You
//!    cannot write an un-scoped tenant query by accident — you have to ask for
//!    [`TenantScope::Global`] on purpose (spec §6.1).
//! 2. **Single-writer discipline.** `ferrum-agentd` owns writes to tasks and
//!    metrics; `ferrum-web` owns sessions and audit. Keeping the writers apart is
//!    what avoids `SQLITE_BUSY` storms under load (spec §5.5).
//!
//! TODO(scope): queries use the runtime `sqlx::query_as` API rather than the
//! compile-time-checked `query_as!` macros. The macros need either a live
//! `DATABASE_URL` at build time or a committed `.sqlx` offline cache, and a
//! hermetic `cargo build` matters more while the schema is still moving. Revisit
//! before the Phase 2 schema lands; the query strings do not change, only the
//! call syntax.

pub mod audit;
pub mod certificates;
pub mod databases;
pub mod firewall;
pub mod models;
pub mod panel;
pub mod password;
pub mod quota;
pub mod plans;
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

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Sqlite, SqlitePool, Transaction};

pub use certificates::{AcmeAccount, CertKind, CertStatus, Certificate};
pub use databases::{Database, DbEngine, DbUser, NewDatabase, NewDbUser};
pub use firewall::{FwRuleRecord, SentinelBan};
pub use models::*;
pub use quota::{QuotaLimits, QuotaProject};
pub use plans::{NewPlan, Plan, PlanUpdate};
pub use revisions::ConfigRevision;
pub use scheduler::ScheduledJob;
pub use scope::ScopeFilter;
pub use secrets::MasterKey;
pub use sites::{NewSite, Site, SiteStatus, SiteType, SiteUpdate, WwwPolicy};
pub use stack::{ComponentStatus, StackComponent};
pub use subscriptions::{Subscription, SubscriptionStatus};

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("stored {field} is not valid: {detail}")]
    Corrupt { field: &'static str, detail: String },

    #[error("{0}")]
    Domain(#[from] ferrum_core::FerrumError),

    #[error("{what} not found")]
    NotFound { what: &'static str },

    #[error("{what} already exists")]
    Conflict { what: &'static str },
}

pub type Result<T, E = DbError> = std::result::Result<T, E>;

impl From<DbError> for ferrum_core::FerrumError {
    fn from(e: DbError) -> Self {
        use ferrum_core::{ErrorCode, FerrumError};
        match e {
            DbError::Domain(inner) => inner,
            DbError::NotFound { what } => FerrumError::not_found(what),
            DbError::Conflict { what } => {
                FerrumError::new(ErrorCode::AlreadyExists, format!("{what} already exists"))
            }
            // Everything else is our problem, not the caller's: report a generic
            // internal error and keep the detail in the log.
            other => {
                tracing::error!(error = %other, "database failure");
                FerrumError::internal("a database error occurred")
            }
        }
    }
}

/// The panel database handle.
#[derive(Clone, Debug)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Open (creating if needed) the panel database and run migrations.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| DbError::Corrupt {
                field: "database directory",
                detail: e.to_string(),
            })?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            // WAL keeps readers from blocking the single writer — the whole
            // reason the panel stays responsive while a task is running.
            .journal_mode(SqliteJournalMode::Wal)
            // NORMAL is durable across process crashes (which is what our
            // crash-only design cares about) without an fsync per commit.
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(10))
            .pragma("cache_size", "-16000");

        Self::from_options(options).await
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
        db.migrate().await?;
        Ok(db)
    }

    async fn from_options(options: SqliteConnectOptions) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(15))
            .connect_with(options)
            .await?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// Apply any pending migrations. Forward-only and checked in CI (spec §4.1).
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn begin(&self) -> Result<Transaction<'static, Sqlite>> {
        Ok(self.pool.begin().await?)
    }

    /// `PRAGMA integrity_check`, surfaced by `ferrum doctor` (spec §5.5).
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
