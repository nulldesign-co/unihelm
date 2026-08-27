//! Backup repositories, schedules and run history (spec §11.10).
//!
//! This module is book-keeping only: it never talks to restic and never holds
//! a plaintext password. Sealing and opening happen in `ferrum_ops::backup`,
//! which is where the [`crate::MasterKey`] lives; what is stored here is
//! ciphertext, and the types below are deliberately shaped so that the sealed
//! columns cannot be serialised out to an API client by accident.
//!
//! Two scoping rules, both of which the SQL enforces rather than the caller:
//!
//! 1. **A repository is server-wide.** Repositories hold credentials and a
//!    password; deciding where backups go is an administrator's job
//!    ([`ferrum_core::Permission::BackupManage`] plus [`ScopeFilter::All`]).
//!    The repository list is therefore not tenant-scoped — it is refused
//!    outright to a scoped caller by the operation layer.
//! 2. **Runs and schedules are.** A customer may see the history of their own
//!    subscription's backups and nothing else, which is a filter on
//!    `subscription_id` — and a panel-scope row, whose `subscription_id` is
//!    NULL, is visible only to an admin.

use ferrum_core::{SubscriptionId, TenantScope};
use serde::{Deserialize, Serialize};

use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// Where a repository lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoKind {
    /// A directory on this server (or an already-mounted network filesystem).
    Local,
    /// Any S3-compatible endpoint: AWS, MinIO, Backblaze, ArvanCloud
    /// (spec §11.10).
    S3,
}

impl RepoKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            RepoKind::Local => "local",
            RepoKind::S3 => "s3",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "local" => RepoKind::Local,
            "s3" => RepoKind::S3,
            other => {
                return Err(DbError::Corrupt {
                    field: "backup_repos.kind",
                    detail: format!("unknown repository kind `{other}`"),
                });
            }
        })
    }
}

/// What a backup covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupScope {
    /// The panel itself: its database, `/etc/ferrum` and the state directory
    /// (certificates and ACME accounts included).
    Panel,
    /// One tenant's home directory.
    Subscription,
}

impl BackupScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            BackupScope::Panel => "panel",
            BackupScope::Subscription => "subscription",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "panel" => BackupScope::Panel,
            "subscription" => BackupScope::Subscription,
            other => {
                return Err(DbError::Corrupt {
                    field: "backup scope",
                    detail: format!("unknown backup scope `{other}`"),
                });
            }
        })
    }
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Ok,
    Failed,
}

impl RunStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Ok => "ok",
            RunStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "running" => RunStatus::Running,
            "ok" => RunStatus::Ok,
            "failed" => RunStatus::Failed,
            other => {
                return Err(DbError::Corrupt {
                    field: "backup_runs.status",
                    detail: format!("unknown run status `{other}`"),
                });
            }
        })
    }
}

/// A repository as the API sees it.
///
/// The sealed columns are **not** fields of this struct. That is the point: a
/// handler cannot leak a password it was never handed, and adding
/// `#[serde(skip)]` to a field that does exist is one careless edit away from
/// being removed. When an operation needs the ciphertext it asks for it
/// explicitly through [`Db::backup_repo_secrets`].
#[derive(Debug, Clone, Serialize)]
pub struct BackupRepo {
    pub id: i64,
    pub kind: RepoKind,
    pub label: String,
    pub path_or_url: String,
    /// Whether credentials are stored, never what they are.
    pub has_credentials: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

/// The sealed halves, fetched on purpose and never serialised.
#[derive(Debug, Clone)]
pub struct RepoSecrets {
    pub password_sealed: String,
    pub credentials_sealed: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct BackupRepoRow {
    id: i64,
    kind: String,
    label: String,
    path_or_url: String,
    credentials_sealed: Option<String>,
    created_at: String,
    updated_at: String,
}

impl TryFrom<BackupRepoRow> for BackupRepo {
    type Error = DbError;

    fn try_from(r: BackupRepoRow) -> Result<Self> {
        Ok(BackupRepo {
            id: r.id,
            kind: RepoKind::parse(&r.kind)?,
            label: r.label,
            path_or_url: r.path_or_url,
            has_credentials: r.credentials_sealed.is_some(),
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

/// A new repository. Both sealed values arrive already encrypted.
#[derive(Debug, Clone)]
pub struct NewBackupRepo {
    pub kind: RepoKind,
    pub label: String,
    pub path_or_url: String,
    pub password_sealed: String,
    pub credentials_sealed: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupSchedule {
    pub id: i64,
    pub repo_id: i64,
    pub scope: BackupScope,
    pub subscription_id: Option<i64>,
    pub cron: String,
    pub keep_daily: i64,
    pub keep_weekly: i64,
    pub keep_monthly: i64,
    pub enabled: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct BackupScheduleRow {
    id: i64,
    repo_id: i64,
    scope: String,
    subscription_id: Option<i64>,
    cron: String,
    keep_daily: i64,
    keep_weekly: i64,
    keep_monthly: i64,
    enabled: i64,
}

impl TryFrom<BackupScheduleRow> for BackupSchedule {
    type Error = DbError;

    fn try_from(r: BackupScheduleRow) -> Result<Self> {
        Ok(BackupSchedule {
            id: r.id,
            repo_id: r.repo_id,
            scope: BackupScope::parse(&r.scope)?,
            subscription_id: r.subscription_id,
            cron: r.cron,
            keep_daily: r.keep_daily,
            keep_weekly: r.keep_weekly,
            keep_monthly: r.keep_monthly,
            enabled: r.enabled != 0,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NewBackupSchedule {
    pub repo_id: i64,
    pub scope: BackupScope,
    pub subscription_id: Option<SubscriptionId>,
    pub cron: String,
    pub keep_daily: i64,
    pub keep_weekly: i64,
    pub keep_monthly: i64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRun {
    pub id: i64,
    pub schedule_id: Option<i64>,
    pub repo_id: i64,
    pub scope: BackupScope,
    pub subscription_id: Option<i64>,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub finished_at: Option<time::OffsetDateTime>,
    pub status: RunStatus,
    pub snapshot_id: Option<String>,
    pub bytes: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct BackupRunRow {
    id: i64,
    schedule_id: Option<i64>,
    repo_id: i64,
    scope: String,
    subscription_id: Option<i64>,
    started_at: String,
    finished_at: Option<String>,
    status: String,
    snapshot_id: Option<String>,
    bytes: Option<i64>,
    error: Option<String>,
}

impl TryFrom<BackupRunRow> for BackupRun {
    type Error = DbError;

    fn try_from(r: BackupRunRow) -> Result<Self> {
        Ok(BackupRun {
            id: r.id,
            schedule_id: r.schedule_id,
            repo_id: r.repo_id,
            scope: BackupScope::parse(&r.scope)?,
            subscription_id: r.subscription_id,
            started_at: from_sql_time(&r.started_at)?,
            finished_at: r.finished_at.as_deref().map(from_sql_time).transpose()?,
            status: RunStatus::parse(&r.status)?,
            snapshot_id: r.snapshot_id,
            bytes: r.bytes,
            error: r.error,
        })
    }
}

/// How a finished run ended, as one value rather than a status plus three
/// fields a caller could combine incoherently.
#[derive(Debug, Clone)]
pub enum RunOutcome {
    Ok {
        snapshot_id: Option<String>,
        bytes: Option<i64>,
    },
    Failed {
        error: String,
    },
}

pub struct BackupRepoQuery<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn backups(&self, scope: &TenantScope) -> BackupRepoQuery<'_> {
        BackupRepoQuery {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    // -----------------------------------------------------------------------
    // repositories — administrator-only, so unscoped by construction
    // -----------------------------------------------------------------------

    pub async fn create_backup_repo(&self, new: NewBackupRepo) -> Result<BackupRepo> {
        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, BackupRepoRow>(
            "INSERT INTO backup_repos
                 (kind, label, path_or_url, credentials_sealed, password_sealed,
                  created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             RETURNING id, kind, label, path_or_url, credentials_sealed,
                       created_at, updated_at",
        )
        .bind(new.kind.as_str())
        .bind(&new.label)
        .bind(&new.path_or_url)
        .bind(&new.credentials_sealed)
        .bind(&new.password_sealed)
        .bind(&ts)
        .fetch_one(self.pool())
        .await
        .map_err(|e| unique_label(e, "backup repository"))?;
        row.try_into()
    }

    pub async fn backup_repos(&self) -> Result<Vec<BackupRepo>> {
        let rows = sqlx::query_as::<_, BackupRepoRow>(
            "SELECT id, kind, label, path_or_url, credentials_sealed, created_at, updated_at
             FROM backup_repos ORDER BY label",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    pub async fn backup_repo(&self, id: i64) -> Result<Option<BackupRepo>> {
        let row = sqlx::query_as::<_, BackupRepoRow>(
            "SELECT id, kind, label, path_or_url, credentials_sealed, created_at, updated_at
             FROM backup_repos WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    /// The sealed password and credentials for a repository.
    ///
    /// A separate call from [`Db::backup_repo`] on purpose: the ciphertext is
    /// needed only on the path that is about to run restic, and everything
    /// else — every list, every API response — is served by a type that does
    /// not contain it at all.
    pub async fn backup_repo_secrets(&self, id: i64) -> Result<RepoSecrets> {
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT password_sealed, credentials_sealed FROM backup_repos WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        let (password_sealed, credentials_sealed) = row.ok_or(DbError::NotFound {
            what: "backup repository",
        })?;
        Ok(RepoSecrets {
            password_sealed,
            credentials_sealed,
        })
    }

    /// Does any run — successful or failed — still reference this repository?
    ///
    /// Asked *before* a delete so the caller can say "this repository has
    /// snapshots recorded against it" instead of letting the `ON DELETE
    /// RESTRICT` surface as an opaque SQLite error the operator cannot act on.
    pub async fn backup_repo_has_runs(&self, id: i64) -> Result<bool> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM backup_runs WHERE repo_id = ?1")
            .bind(id)
            .fetch_one(self.pool())
            .await?;
        Ok(row.0 > 0)
    }

    pub async fn delete_backup_repo(&self, id: i64) -> Result<()> {
        let done = sqlx::query("DELETE FROM backup_repos WHERE id = ?1")
            .bind(id)
            .execute(self.pool())
            .await?;
        if done.rows_affected() == 0 {
            return Err(DbError::NotFound {
                what: "backup repository",
            });
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // the panel database's own consistent snapshot
    // -----------------------------------------------------------------------

    /// Write a consistent copy of the panel database to `path`.
    ///
    /// **Never copy the database file instead.** The panel runs SQLite in WAL
    /// mode (see [`Db::open`]), where the `.db` file alone is an arbitrarily
    /// stale prefix of the truth: committed transactions live in `panel.db-wal`
    /// until a checkpoint folds them in. `cp panel.db` during a backup
    /// therefore produces a file that restores to *some* earlier state, or —
    /// if a checkpoint lands mid-copy — to no valid state at all. It is the
    /// classic backup that only fails when you finally need it.
    ///
    /// `VACUUM INTO` runs inside a read transaction, so what lands on disk is
    /// one committed snapshot: WAL contents included, no torn pages, no
    /// separate `-wal` sidecar to remember to carry. It also compacts, which
    /// is why the output is usually smaller than the live file.
    ///
    /// The destination must not exist; SQLite refuses to overwrite, and that
    /// refusal is worth keeping rather than papering over — an existing file
    /// at that path means something else is already using it.
    ///
    /// The path is **bound**, not interpolated: `VACUUM INTO` takes an SQL
    /// expression, and a bound parameter is one. Even though every caller
    /// today builds the path itself, a string-formatted filename in a
    /// statement is the shape of a SQL injection, and the shape is what future
    /// readers copy.
    ///
    /// The existence check afterwards is not belt-and-braces. Against a
    /// database opened as `sqlite::memory:` this statement returns success and
    /// writes **no file at all** — verified, and the reason
    /// `a_snapshot_that_was_never_written_is_reported_as_a_failure` exists. A
    /// backup routine that trusted the `Ok` would tar up a path that is not
    /// there, or — worse — record a successful run having archived nothing.
    /// Silence is the one failure mode a backup system may not have, so the
    /// post-condition is checked rather than assumed.
    pub async fn vacuum_into(&self, path: &std::path::Path) -> Result<()> {
        let target = path.to_str().ok_or_else(|| DbError::Corrupt {
            field: "backup snapshot path",
            detail: format!("{} is not valid UTF-8", path.display()),
        })?;
        sqlx::query("VACUUM INTO ?1")
            .bind(target)
            .execute(self.pool())
            .await?;
        if !path.is_file() {
            return Err(DbError::Corrupt {
                field: "backup snapshot",
                detail: format!(
                    "SQLite reported a successful `VACUUM INTO {}` but wrote no file there",
                    path.display()
                ),
            });
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // schedules
    // -----------------------------------------------------------------------

    pub async fn create_backup_schedule(&self, new: NewBackupSchedule) -> Result<BackupSchedule> {
        let row = sqlx::query_as::<_, BackupScheduleRow>(
            "INSERT INTO backup_schedules
                 (repo_id, scope, subscription_id, cron, keep_daily, keep_weekly,
                  keep_monthly, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             RETURNING *",
        )
        .bind(new.repo_id)
        .bind(new.scope.as_str())
        .bind(new.subscription_id.map(|s| s.get()))
        .bind(&new.cron)
        .bind(new.keep_daily)
        .bind(new.keep_weekly)
        .bind(new.keep_monthly)
        .bind(i64::from(new.enabled))
        .fetch_one(self.pool())
        .await?;
        row.try_into()
    }

    /// Every enabled schedule, for the scheduler's due pass.
    ///
    /// Unscoped: this runs under the system identity, which has no tenant.
    pub async fn enabled_backup_schedules(&self) -> Result<Vec<BackupSchedule>> {
        let rows = sqlx::query_as::<_, BackupScheduleRow>(
            "SELECT * FROM backup_schedules WHERE enabled = 1 ORDER BY id",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    pub async fn set_backup_schedule_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let done = sqlx::query("UPDATE backup_schedules SET enabled = ?2 WHERE id = ?1")
            .bind(id)
            .bind(i64::from(enabled))
            .execute(self.pool())
            .await?;
        if done.rows_affected() == 0 {
            return Err(DbError::NotFound {
                what: "backup schedule",
            });
        }
        Ok(())
    }

    pub async fn delete_backup_schedule(&self, id: i64) -> Result<()> {
        let done = sqlx::query("DELETE FROM backup_schedules WHERE id = ?1")
            .bind(id)
            .execute(self.pool())
            .await?;
        if done.rows_affected() == 0 {
            return Err(DbError::NotFound {
                what: "backup schedule",
            });
        }
        Ok(())
    }

    /// When a schedule last *started* a run, successful or not.
    ///
    /// Started, not finished: the due check exists to stop a schedule firing
    /// twice for one cron minute, and a run that is still going has already
    /// consumed that minute.
    pub async fn last_backup_run_start(
        &self,
        schedule_id: i64,
    ) -> Result<Option<time::OffsetDateTime>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT started_at FROM backup_runs WHERE schedule_id = ?1
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(schedule_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|(t,)| from_sql_time(&t)).transpose()
    }

    // -----------------------------------------------------------------------
    // runs
    // -----------------------------------------------------------------------

    /// Record that a run has begun. The row exists before restic starts, so a
    /// crash mid-backup leaves evidence rather than silence.
    pub async fn start_backup_run(
        &self,
        schedule_id: Option<i64>,
        repo_id: i64,
        scope: BackupScope,
        subscription_id: Option<SubscriptionId>,
    ) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO backup_runs
                 (schedule_id, repo_id, scope, subscription_id, started_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, 'running')
             RETURNING id",
        )
        .bind(schedule_id)
        .bind(repo_id)
        .bind(scope.as_str())
        .bind(subscription_id.map(|s| s.get()))
        .bind(to_sql_time(now()))
        .fetch_one(self.pool())
        .await?;
        Ok(row.0)
    }

    pub async fn finish_backup_run(&self, run_id: i64, outcome: RunOutcome) -> Result<()> {
        let ts = to_sql_time(now());
        let done = match outcome {
            RunOutcome::Ok { snapshot_id, bytes } => {
                sqlx::query(
                    "UPDATE backup_runs
                     SET status = 'ok', finished_at = ?2, snapshot_id = ?3, bytes = ?4
                     WHERE id = ?1 AND status = 'running'",
                )
                .bind(run_id)
                .bind(&ts)
                .bind(snapshot_id)
                .bind(bytes)
                .execute(self.pool())
                .await?
            }
            RunOutcome::Failed { error } => {
                sqlx::query(
                    "UPDATE backup_runs
                     SET status = 'failed', finished_at = ?2, error = ?3
                     WHERE id = ?1 AND status = 'running'",
                )
                .bind(run_id)
                .bind(&ts)
                // Bounded: restic's failure text can be a wall of output, and
                // this column is read by a UI list.
                .bind(truncate(&error, 4000))
                .execute(self.pool())
                .await?
            }
        };
        if done.rows_affected() == 0 {
            return Err(DbError::NotFound {
                what: "running backup run",
            });
        }
        Ok(())
    }
}

impl BackupRepoQuery<'_> {
    /// Backup runs this caller may see.
    ///
    /// Panel-scope runs have a NULL `subscription_id` and are therefore
    /// invisible to every scoped caller — which is the intent: a panel backup
    /// covers the whole server's state, including every other tenant.
    pub async fn runs(&self, limit: i64, offset: i64) -> Result<Vec<BackupRun>> {
        let limit = limit.clamp(1, 500);
        let offset = offset.max(0);

        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, BackupRunRow>(
                    "SELECT * FROM backup_runs ORDER BY started_at DESC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, BackupRunRow>(
                    "SELECT r.* FROM backup_runs r
                     JOIN subscriptions s ON s.id = r.subscription_id
                     JOIN users u         ON u.id = s.customer_id
                     WHERE u.reseller_id = ?1
                     ORDER BY r.started_at DESC LIMIT ?2 OFFSET ?3",
                )
                .bind(reseller_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, BackupRunRow>(
                    "SELECT r.* FROM backup_runs r
                     JOIN subscriptions s ON s.id = r.subscription_id
                     WHERE s.customer_id = ?1
                     ORDER BY r.started_at DESC LIMIT ?2 OFFSET ?3",
                )
                .bind(customer_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, BackupRunRow>(
                    "SELECT * FROM backup_runs WHERE subscription_id = ?1
                     ORDER BY started_at DESC LIMIT ?2 OFFSET ?3",
                )
                .bind(subscription_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Schedules this caller may see, under the same rules as [`Self::runs`].
    pub async fn schedules(&self) -> Result<Vec<BackupSchedule>> {
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, BackupScheduleRow>("SELECT * FROM backup_schedules ORDER BY id")
                    .fetch_all(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, BackupScheduleRow>(
                    "SELECT b.* FROM backup_schedules b
                     JOIN subscriptions s ON s.id = b.subscription_id
                     JOIN users u         ON u.id = s.customer_id
                     WHERE u.reseller_id = ?1 ORDER BY b.id",
                )
                .bind(reseller_id)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, BackupScheduleRow>(
                    "SELECT b.* FROM backup_schedules b
                     JOIN subscriptions s ON s.id = b.subscription_id
                     WHERE s.customer_id = ?1 ORDER BY b.id",
                )
                .bind(customer_id)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, BackupScheduleRow>(
                    "SELECT * FROM backup_schedules WHERE subscription_id = ?1 ORDER BY id",
                )
                .bind(subscription_id)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(TryInto::try_into).collect()
    }
}

/// Turn SQLite's UNIQUE violation into the panel's own conflict error.
fn unique_label(e: sqlx::Error, what: &'static str) -> DbError {
    let text = e.to_string();
    if text.contains("UNIQUE constraint failed") {
        DbError::Conflict { what }
    } else {
        DbError::Sqlx(e)
    }
}

/// Clamp a string to `max` **characters** (not bytes), so a multi-byte
/// character is never cut in half into invalid UTF-8.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::NewUser;
    use ferrum_core::{Email, Role, UserId, Username};

    async fn db() -> Db {
        Db::open_memory().await.unwrap()
    }

    fn repo(label: &str) -> NewBackupRepo {
        NewBackupRepo {
            kind: RepoKind::Local,
            label: label.into(),
            path_or_url: "/srv/backups".into(),
            password_sealed: "deadbeef".into(),
            credentials_sealed: None,
        }
    }

    async fn customer(db: &Db, name: &str) -> UserId {
        db.users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Customer,
                email: Email::parse(&format!("{name}@example.com")).unwrap(),
                username: Username::parse(name).unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn a_repository_row_never_carries_its_password_to_a_caller() {
        // The whole reason `BackupRepo` omits the sealed columns: a handler
        // that serialises whatever the repository hands it cannot leak what it
        // was never given (spec §12 rule 6).
        let db = db().await;
        let created = db.create_backup_repo(repo("nightly")).await.unwrap();
        let rendered = serde_json::to_string(&created).unwrap();
        assert!(!rendered.contains("deadbeef"), "{rendered}");
        assert!(rendered.contains("nightly"));
        assert!(!created.has_credentials);

        // …and the ciphertext is still reachable when something genuinely
        // needs it.
        let secrets = db.backup_repo_secrets(created.id).await.unwrap();
        assert_eq!(secrets.password_sealed, "deadbeef");
        assert!(secrets.credentials_sealed.is_none());
    }

    #[tokio::test]
    async fn two_repositories_cannot_share_a_label() {
        let db = db().await;
        db.create_backup_repo(repo("nightly")).await.unwrap();
        let err = db.create_backup_repo(repo("nightly")).await.unwrap_err();
        assert!(matches!(err, DbError::Conflict { .. }), "{err}");
    }

    #[tokio::test]
    async fn a_subscription_schedule_without_a_subscription_is_refused_by_the_schema() {
        let db = db().await;
        let r = db.create_backup_repo(repo("nightly")).await.unwrap();
        let err = db
            .create_backup_schedule(NewBackupSchedule {
                repo_id: r.id,
                scope: BackupScope::Subscription,
                subscription_id: None,
                cron: "0 3 * * *".into(),
                keep_daily: 7,
                keep_weekly: 4,
                keep_monthly: 6,
                enabled: true,
            })
            .await;
        assert!(
            err.is_err(),
            "the CHECK must stop a tenant schedule with no tenant"
        );
    }

    #[tokio::test]
    async fn a_run_is_recorded_before_it_finishes_so_a_crash_leaves_evidence() {
        let db = db().await;
        let r = db.create_backup_repo(repo("nightly")).await.unwrap();
        let run = db
            .start_backup_run(None, r.id, BackupScope::Panel, None)
            .await
            .unwrap();

        let open = db.backups(&TenantScope::Global).runs(10, 0).await.unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].status, RunStatus::Running);
        assert!(open[0].finished_at.is_none());

        db.finish_backup_run(
            run,
            RunOutcome::Ok {
                snapshot_id: Some("abc123".into()),
                bytes: Some(4096),
            },
        )
        .await
        .unwrap();

        let done = db.backups(&TenantScope::Global).runs(10, 0).await.unwrap();
        assert_eq!(done[0].status, RunStatus::Ok);
        assert_eq!(done[0].snapshot_id.as_deref(), Some("abc123"));
        assert!(done[0].finished_at.is_some());
    }

    #[tokio::test]
    async fn finishing_a_run_twice_is_refused_rather_than_rewriting_history() {
        let db = db().await;
        let r = db.create_backup_repo(repo("nightly")).await.unwrap();
        let run = db
            .start_backup_run(None, r.id, BackupScope::Panel, None)
            .await
            .unwrap();
        db.finish_backup_run(
            run,
            RunOutcome::Failed {
                error: "repository is locked".into(),
            },
        )
        .await
        .unwrap();

        let err = db
            .finish_backup_run(
                run,
                RunOutcome::Ok {
                    snapshot_id: None,
                    bytes: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::NotFound { .. }), "{err}");
    }

    #[tokio::test]
    async fn a_customer_never_sees_a_panel_scope_run() {
        // A panel backup covers every tenant's data. Its run row must not be
        // visible to a tenant, and the NULL subscription_id is what makes the
        // scoped query drop it.
        let db = db().await;
        let repo_id = db.create_backup_repo(repo("nightly")).await.unwrap().id;
        let alice = customer(&db, "alice").await;
        let sub = db.create_subscription(alice).await.unwrap();

        db.start_backup_run(None, repo_id, BackupScope::Panel, None)
            .await
            .unwrap();
        db.start_backup_run(None, repo_id, BackupScope::Subscription, Some(sub.id))
            .await
            .unwrap();

        let admin = db.backups(&TenantScope::Global).runs(10, 0).await.unwrap();
        assert_eq!(admin.len(), 2);

        let theirs = db
            .backups(&TenantScope::Customer { customer_id: alice })
            .runs(10, 0)
            .await
            .unwrap();
        assert_eq!(theirs.len(), 1);
        assert_eq!(theirs[0].scope, BackupScope::Subscription);
    }

    #[tokio::test]
    async fn one_customer_cannot_see_another_customers_runs() {
        let db = db().await;
        let repo_id = db.create_backup_repo(repo("nightly")).await.unwrap().id;
        let alice = customer(&db, "alice").await;
        let bob = customer(&db, "bob").await;
        let alice_sub = db.create_subscription(alice).await.unwrap();
        let bob_sub = db.create_subscription(bob).await.unwrap();

        db.start_backup_run(None, repo_id, BackupScope::Subscription, Some(alice_sub.id))
            .await
            .unwrap();
        db.start_backup_run(None, repo_id, BackupScope::Subscription, Some(bob_sub.id))
            .await
            .unwrap();

        let theirs = db
            .backups(&TenantScope::Customer { customer_id: bob })
            .runs(10, 0)
            .await
            .unwrap();
        assert_eq!(theirs.len(), 1);
        assert_eq!(theirs[0].subscription_id, Some(bob_sub.id.get()));
    }

    #[tokio::test]
    async fn deleting_a_schedule_keeps_the_history_of_what_it_did() {
        // ON DELETE SET NULL, not CASCADE: the record of a backup that ran is
        // evidence, and turning off a schedule must not erase it.
        let db = db().await;
        let r = db.create_backup_repo(repo("nightly")).await.unwrap();
        let schedule = db
            .create_backup_schedule(NewBackupSchedule {
                repo_id: r.id,
                scope: BackupScope::Panel,
                subscription_id: None,
                cron: "0 3 * * *".into(),
                keep_daily: 7,
                keep_weekly: 4,
                keep_monthly: 6,
                enabled: true,
            })
            .await
            .unwrap();
        db.start_backup_run(Some(schedule.id), r.id, BackupScope::Panel, None)
            .await
            .unwrap();

        db.delete_backup_schedule(schedule.id).await.unwrap();

        let runs = db.backups(&TenantScope::Global).runs(10, 0).await.unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].schedule_id, None);
    }

    #[tokio::test]
    async fn a_repository_with_history_cannot_be_deleted_out_from_under_it() {
        // ON DELETE RESTRICT on backup_runs.repo_id: snapshots still exist in
        // that bucket, and losing the panel's record of them would leave data
        // nobody can account for.
        let db = db().await;
        let r = db.create_backup_repo(repo("nightly")).await.unwrap();
        db.start_backup_run(None, r.id, BackupScope::Panel, None)
            .await
            .unwrap();
        assert!(db.delete_backup_repo(r.id).await.is_err());
    }

    #[tokio::test]
    async fn the_last_run_start_is_what_the_scheduler_reads() {
        let db = db().await;
        let r = db.create_backup_repo(repo("nightly")).await.unwrap();
        let schedule = db
            .create_backup_schedule(NewBackupSchedule {
                repo_id: r.id,
                scope: BackupScope::Panel,
                subscription_id: None,
                cron: "*/5 * * * *".into(),
                keep_daily: 7,
                keep_weekly: 4,
                keep_monthly: 6,
                enabled: true,
            })
            .await
            .unwrap();

        assert!(
            db.last_backup_run_start(schedule.id)
                .await
                .unwrap()
                .is_none()
        );
        db.start_backup_run(Some(schedule.id), r.id, BackupScope::Panel, None)
            .await
            .unwrap();
        assert!(
            db.last_backup_run_start(schedule.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn only_enabled_schedules_reach_the_scheduler() {
        let db = db().await;
        let r = db.create_backup_repo(repo("nightly")).await.unwrap();
        let make = |enabled| NewBackupSchedule {
            repo_id: r.id,
            scope: BackupScope::Panel,
            subscription_id: None,
            cron: "0 3 * * *".into(),
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 6,
            enabled,
        };
        let on = db.create_backup_schedule(make(true)).await.unwrap();
        db.create_backup_schedule(make(false)).await.unwrap();

        let due = db.enabled_backup_schedules().await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, on.id);

        db.set_backup_schedule_enabled(on.id, false).await.unwrap();
        assert!(db.enabled_backup_schedules().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn vacuum_into_writes_a_snapshot_that_opens_as_a_database() {
        // The panel-scope backup's first step. A snapshot that cannot be
        // opened is worse than no backup at all, so the assertion is that the
        // file *is a database with our rows in it*, not merely that it exists.
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("panel.db");
        let db = Db::open(&live).await.unwrap();
        db.create_backup_repo(repo("nightly")).await.unwrap();

        let snapshot = dir.path().join("snapshot.db");
        db.vacuum_into(&snapshot).await.unwrap();
        assert!(snapshot.is_file());

        let restored = Db::open(&snapshot).await.unwrap();
        let repos = restored.backup_repos().await.unwrap();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].label, "nightly");
        assert_eq!(restored.integrity_check().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn a_snapshot_that_was_never_written_is_reported_as_a_failure() {
        // SQLite answers `VACUUM INTO` on an in-memory database with success
        // and writes nothing. Without the post-condition in `vacuum_into` the
        // caller would go on to hand restic a path that does not exist — or,
        // if the path happened to hold something else, back up the wrong file
        // and record a healthy run. A backup that quietly archives nothing is
        // the failure this whole module exists to prevent (spec §11.10).
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_memory().await.unwrap();
        let target = dir.path().join("nowhere.db");

        let err = db.vacuum_into(&target).await.unwrap_err();
        assert!(matches!(err, DbError::Corrupt { .. }), "{err}");
        assert!(!target.exists());
    }

    #[tokio::test]
    async fn vacuum_into_refuses_to_overwrite_an_existing_file() {
        // SQLite's own refusal, kept rather than worked around: a file already
        // sitting at the destination means something else is using that path.
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().join("panel.db")).await.unwrap();
        let occupied = dir.path().join("taken.db");
        std::fs::write(&occupied, b"not ours").unwrap();
        assert!(db.vacuum_into(&occupied).await.is_err());
    }

    #[tokio::test]
    async fn a_hostile_snapshot_path_is_a_bound_parameter_not_a_statement() {
        // The path is bound, so a filename containing SQL is a filename. If it
        // were interpolated, this would run `VACUUM` against a nonsense target
        // and then try to execute a second statement.
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().join("panel.db")).await.unwrap();
        let hostile = dir.path().join("x'; DROP TABLE backup_repos; --");
        // May or may not succeed depending on the filesystem; what must hold
        // is that the table is still there afterwards.
        let _ = db.vacuum_into(&hostile).await;
        assert!(db.backup_repos().await.is_ok(), "the table must survive");
    }

    #[test]
    fn a_long_failure_message_is_cut_on_a_character_boundary() {
        // restic can fail with a wall of output; the column is read by a list.
        let wide = "é".repeat(5000);
        let cut = truncate(&wide, 4000);
        assert_eq!(cut.chars().count(), 4000);
        assert!(std::str::from_utf8(cut.as_bytes()).is_ok());
    }
}
