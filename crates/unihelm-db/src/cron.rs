//! Per-subscription cron jobs (spec §11.8).
//!
//! A thin, strictly scoped table. The interesting decisions are one level up in
//! `unihelm_ops::cron` — the schedule grammar, the command rules and the
//! crontab rendering all live there, because they are about what is safe to
//! write into a file cron will execute, not about storage.
//!
//! What this module *is* responsible for is that a caller can only ever reach
//! the jobs their [`TenantScope`] can see. Every read and every write goes
//! through [`CronJobRepo`], and the two whole-subscription helpers that do not
//! ([`Db::cron_jobs_for_render`], [`Db::set_cron_last_error`]) are called only
//! after an operation has already resolved the subscription through the
//! caller's scope — the same contract [`Db::create_site`] and
//! [`Db::create_node_app`] work under.

use serde::Serialize;
use unihelm_core::{SubscriptionId, TenantScope};

use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// How many jobs one subscription may hold.
///
/// Spec §11.8 asks for a "plan-capped count", and the `plans` table has no
/// cron column to cap with (§6.2 ships `can_cron` as a yes/no). This constant
/// is the interim ceiling and exists for a narrower reason than a plan limit:
/// the whole crontab is rendered into one IPC payload and fed to `crontab` on
/// a pipe, so the number of jobs has to be bounded by *something* that is not
/// the tenant's patience. A `max_cron_jobs` plan column supersedes it.
pub const MAX_JOBS_PER_SUBSCRIPTION: i64 = 100;

#[derive(Debug, Clone, Serialize)]
pub struct CronJob {
    pub id: i64,
    pub subscription_id: SubscriptionId,
    /// Five canonical whitespace-separated fields (`unihelm_ops::cron`).
    pub schedule: String,
    pub command: String,
    pub enabled: bool,
    /// Why this subscription's crontab could not be installed last time, if it
    /// could not. Cleared by the next successful install.
    pub last_error: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CronJobRow {
    pub id: i64,
    pub subscription_id: i64,
    pub schedule: String,
    pub command: String,
    pub enabled: i64,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<CronJobRow> for CronJob {
    type Error = DbError;

    fn try_from(r: CronJobRow) -> Result<Self> {
        Ok(CronJob {
            id: r.id,
            subscription_id: SubscriptionId(r.subscription_id),
            schedule: r.schedule,
            command: r.command,
            // The CHECK constraint keeps this to 0/1; `!= 0` tolerates a
            // hand-edited database rather than refusing to load it, same as
            // `plans`.
            enabled: r.enabled != 0,
            last_error: r.last_error,
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

/// A job to create. Both text fields must already be canonical — the operation
/// layer validates and normalises before anything reaches here.
#[derive(Debug, Clone)]
pub struct NewCronJob {
    pub subscription_id: SubscriptionId,
    pub schedule: String,
    pub command: String,
    pub enabled: bool,
}

/// A partial update. `None` leaves the column alone.
#[derive(Debug, Clone, Default)]
pub struct CronJobUpdate {
    pub schedule: Option<String>,
    pub command: Option<String>,
    pub enabled: Option<bool>,
}

pub struct CronJobRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn cron_jobs(&self, scope: &TenantScope) -> CronJobRepo<'_> {
        CronJobRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    /// Create a job, refusing past [`MAX_JOBS_PER_SUBSCRIPTION`].
    ///
    /// Not scoped: the caller resolved the subscription through their own
    /// scope first (same contract as [`Db::create_node_app`]). The cap is
    /// enforced inside the INSERT rather than as a read-then-write, so two
    /// concurrent creates cannot both see "99 jobs" and both insert.
    pub async fn create_cron_job(&self, new: NewCronJob) -> Result<CronJob> {
        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, CronJobRow>(
            "INSERT INTO cron_jobs
                 (subscription_id, schedule, command, enabled, last_error,
                  created_at, updated_at)
             SELECT ?1, ?2, ?3, ?4, NULL, ?5, ?5
             WHERE (SELECT COUNT(*) FROM cron_jobs WHERE subscription_id = ?1) < ?6
             RETURNING *",
        )
        .bind(new.subscription_id.get())
        .bind(&new.schedule)
        .bind(&new.command)
        .bind(i64::from(new.enabled))
        .bind(&ts)
        .bind(MAX_JOBS_PER_SUBSCRIPTION)
        .fetch_optional(self.pool())
        .await?;

        // A `WHERE` that excludes every candidate row inserts nothing and
        // returns nothing — which is the cap, not a missing subscription.
        // (A subscription that does not exist fails the foreign key instead
        // and arrives as a Sqlx error.)
        let row = row.ok_or(DbError::Conflict {
            what: "cron job (this subscription is at its job limit)",
        })?;
        CronJob::try_from(row)
    }

    /// Every job of one subscription, in the order the crontab renders them.
    ///
    /// Deliberately un-scoped and deliberately *not* paginated: this is the
    /// input to the crontab file, and a page of it would silently drop a
    /// tenant's jobs off the end of their own schedule. The row count is
    /// bounded by [`MAX_JOBS_PER_SUBSCRIPTION`].
    ///
    /// The ORDER BY is the render order and is a property of the *set*, not of
    /// insertion history: sorting by `(schedule, command, id)` means the same
    /// jobs always produce byte-identical output however they were created, so
    /// a re-render that changed nothing really is a no-op.
    pub async fn cron_jobs_for_render(&self, id: SubscriptionId) -> Result<Vec<CronJob>> {
        let rows = sqlx::query_as::<_, CronJobRow>(
            "SELECT * FROM cron_jobs WHERE subscription_id = ?1
             ORDER BY schedule ASC, command ASC, id ASC",
        )
        .bind(id.get())
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(CronJob::try_from).collect()
    }

    /// Record (or clear) the reason this subscription's crontab could not be
    /// installed.
    ///
    /// Whole-subscription rather than per-job because that is what the failure
    /// is: the crontab is installed as one file, so when the install fails no
    /// job in it took effect, and marking only the job the caller happened to
    /// be editing would leave the others claiming a schedule they do not have.
    pub async fn set_cron_last_error(&self, id: SubscriptionId, error: Option<&str>) -> Result<()> {
        sqlx::query(
            "UPDATE cron_jobs SET last_error = ?2, updated_at = ?3 WHERE subscription_id = ?1",
        )
        .bind(id.get())
        .bind(error)
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(())
    }
}

impl CronJobRepo<'_> {
    /// One job, if this scope may see it.
    pub async fn by_id(&self, id: i64) -> Result<Option<CronJob>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, CronJobRow>("SELECT * FROM cron_jobs WHERE id = ?1")
                    .bind(id)
                    .fetch_optional(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, CronJobRow>(
                    "SELECT c.* FROM cron_jobs c
                     JOIN subscriptions sub ON sub.id = c.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE c.id = ?1 AND u.reseller_id = ?2",
                )
                .bind(id)
                .bind(reseller_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, CronJobRow>(
                    "SELECT c.* FROM cron_jobs c
                     JOIN subscriptions sub ON sub.id = c.subscription_id
                     WHERE c.id = ?1 AND sub.customer_id = ?2",
                )
                .bind(id)
                .bind(customer_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, CronJobRow>(
                    "SELECT * FROM cron_jobs WHERE id = ?1 AND subscription_id = ?2",
                )
                .bind(id)
                .bind(subscription_id)
                .fetch_optional(self.db.pool())
                .await?
            }
        };
        row.map(CronJob::try_from).transpose()
    }

    /// Every job this scope can see, newest last, in render order.
    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<CronJob>> {
        let limit = limit.clamp(1, 500);
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, CronJobRow>(
                    "SELECT * FROM cron_jobs
                     ORDER BY subscription_id ASC, schedule ASC, command ASC, id ASC
                     LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, CronJobRow>(
                    "SELECT c.* FROM cron_jobs c
                     JOIN subscriptions sub ON sub.id = c.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE u.reseller_id = ?1
                     ORDER BY c.subscription_id ASC, c.schedule ASC, c.command ASC, c.id ASC
                     LIMIT ?2 OFFSET ?3",
                )
                .bind(reseller_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, CronJobRow>(
                    "SELECT c.* FROM cron_jobs c
                     JOIN subscriptions sub ON sub.id = c.subscription_id
                     WHERE sub.customer_id = ?1
                     ORDER BY c.subscription_id ASC, c.schedule ASC, c.command ASC, c.id ASC
                     LIMIT ?2 OFFSET ?3",
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
                sqlx::query_as::<_, CronJobRow>(
                    "SELECT * FROM cron_jobs WHERE subscription_id = ?1
                     ORDER BY schedule ASC, command ASC, id ASC
                     LIMIT ?2 OFFSET ?3",
                )
                .bind(subscription_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(CronJob::try_from).collect()
    }

    /// Update a job this scope can see.
    ///
    /// `subscription_id` is not updatable on purpose: moving a job between
    /// tenants would move a command from one Linux account to another, and
    /// there is no request shape where that is what somebody meant.
    pub async fn update(&self, id: i64, update: CronJobUpdate) -> Result<CronJob> {
        // Scoped read first: an UPDATE with the scope inlined would touch zero
        // rows for both "not yours" and "no such job", and the two must not be
        // told apart by anybody outside the scope anyway — but going through
        // `by_id` keeps the scope rules in exactly one place.
        self.by_id(id)
            .await?
            .ok_or(DbError::NotFound { what: "cron job" })?;

        sqlx::query(
            "UPDATE cron_jobs SET
                 schedule   = COALESCE(?2, schedule),
                 command    = COALESCE(?3, command),
                 enabled    = COALESCE(?4, enabled),
                 updated_at = ?5
             WHERE id = ?1",
        )
        .bind(id)
        .bind(update.schedule.as_deref())
        .bind(update.command.as_deref())
        .bind(update.enabled.map(i64::from))
        .bind(to_sql_time(now()))
        .execute(self.db.pool())
        .await?;

        self.by_id(id)
            .await?
            .ok_or(DbError::NotFound { what: "cron job" })
    }

    /// Delete a job, returning the row that was removed so the caller knows
    /// whose crontab to re-render.
    pub async fn delete(&self, id: i64) -> Result<CronJob> {
        let job = self
            .by_id(id)
            .await?
            .ok_or(DbError::NotFound { what: "cron job" })?;
        sqlx::query("DELETE FROM cron_jobs WHERE id = ?1")
            .bind(id)
            .execute(self.db.pool())
            .await?;
        Ok(job)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::NewUser;
    use unihelm_core::{Email, Role, UserId, Username};

    /// Two customers under one reseller, plus a third under nobody, each with
    /// a subscription — the shape every scope assertion below needs.
    async fn seed() -> (Db, UserId, SubscriptionId, SubscriptionId) {
        let db = Db::open_memory().await.unwrap();
        let global = TenantScope::Global;
        let mk = |name: &'static str, role: Role, reseller: Option<UserId>| NewUser {
            role,
            email: Email::parse(&format!("{name}@example.com")).unwrap(),
            username: Username::parse(name).unwrap(),
            password: "a-long-enough-password".into(),
            reseller_id: reseller,
            full_name: None,
            locale: "en".into(),
        };
        let reseller = db
            .users(&global)
            .create(mk("reseller", Role::Reseller, None))
            .await
            .unwrap();
        let mine = db
            .users(&global)
            .create(mk("mine", Role::Customer, Some(reseller.id)))
            .await
            .unwrap();
        let theirs = db
            .users(&global)
            .create(mk("theirs", Role::Customer, None))
            .await
            .unwrap();
        let a = db.create_subscription(mine.id).await.unwrap();
        let b = db.create_subscription(theirs.id).await.unwrap();
        (db, mine.id, a.id, b.id)
    }

    fn job(sub: SubscriptionId, schedule: &str, command: &str) -> NewCronJob {
        NewCronJob {
            subscription_id: sub,
            schedule: schedule.into(),
            command: command.into(),
            enabled: true,
        }
    }

    #[tokio::test]
    async fn a_customer_can_neither_see_nor_delete_another_tenants_job() {
        let (db, customer, mine, theirs) = seed().await;
        let ours = db
            .create_cron_job(job(mine, "0 3 * * *", "backup.sh"))
            .await
            .unwrap();
        let alien = db
            .create_cron_job(job(theirs, "0 4 * * *", "other.sh"))
            .await
            .unwrap();

        let scope = TenantScope::Customer {
            customer_id: customer,
        };
        assert!(db.cron_jobs(&scope).by_id(ours.id).await.unwrap().is_some());
        assert!(
            db.cron_jobs(&scope)
                .by_id(alien.id)
                .await
                .unwrap()
                .is_none(),
            "another tenant's job must not be visible"
        );

        let listed = db.cron_jobs(&scope).list(100, 0).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, ours.id);

        // And the delete path refuses on the same rule rather than a second one.
        assert!(matches!(
            db.cron_jobs(&scope).delete(alien.id).await,
            Err(DbError::NotFound { .. })
        ));
        assert!(matches!(
            db.cron_jobs(&scope)
                .update(alien.id, CronJobUpdate::default())
                .await,
            Err(DbError::NotFound { .. })
        ));
        // Still there, from a scope that can see it.
        assert!(
            db.cron_jobs(&TenantScope::Global)
                .by_id(alien.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn deleting_a_subscription_takes_its_cron_jobs_with_it() {
        // Spec §11.8 AC: removing a subscription removes its crontab entries.
        // The rows are the half of that this table owns.
        let (db, _, mine, _) = seed().await;
        let created = db
            .create_cron_job(job(mine, "0 3 * * *", "backup.sh"))
            .await
            .unwrap();

        sqlx::query("DELETE FROM subscriptions WHERE id = ?1")
            .bind(mine.get())
            .execute(db.pool())
            .await
            .unwrap();

        assert!(
            db.cron_jobs(&TenantScope::Global)
                .by_id(created.id)
                .await
                .unwrap()
                .is_none(),
            "ON DELETE CASCADE must remove the job with its subscription"
        );
    }

    #[tokio::test]
    async fn the_render_order_depends_on_the_job_set_and_not_on_insertion_order() {
        // Byte-identical output for the same set of jobs is what makes a
        // re-render that changed nothing a genuine no-op.
        let (db, _, mine, _) = seed().await;
        for (schedule, command) in [("5 * * * *", "b.sh"), ("0 3 * * *", "a.sh")] {
            db.create_cron_job(job(mine, schedule, command))
                .await
                .unwrap();
        }
        let forward: Vec<String> = db
            .cron_jobs_for_render(mine)
            .await
            .unwrap()
            .into_iter()
            .map(|j| format!("{} {}", j.schedule, j.command))
            .collect();
        assert_eq!(forward, vec!["0 3 * * * a.sh", "5 * * * * b.sh"]);
    }

    #[tokio::test]
    async fn a_subscription_cannot_exceed_its_job_limit() {
        let (db, _, mine, _) = seed().await;
        for n in 0..MAX_JOBS_PER_SUBSCRIPTION {
            db.create_cron_job(job(mine, "0 3 * * *", &format!("job{n}.sh")))
                .await
                .unwrap();
        }
        let err = db
            .create_cron_job(job(mine, "0 3 * * *", "one-too-many.sh"))
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Conflict { .. }), "{err:?}");
        assert_eq!(
            db.cron_jobs_for_render(mine).await.unwrap().len() as i64,
            MAX_JOBS_PER_SUBSCRIPTION
        );
    }

    #[tokio::test]
    async fn an_apply_failure_is_recorded_against_every_job_of_the_subscription() {
        // The crontab installs as one file: when it fails, no job in it took
        // effect, so no job in it may claim otherwise.
        let (db, _, mine, theirs) = seed().await;
        db.create_cron_job(job(mine, "0 3 * * *", "a.sh"))
            .await
            .unwrap();
        db.create_cron_job(job(mine, "0 4 * * *", "b.sh"))
            .await
            .unwrap();
        let untouched = db
            .create_cron_job(job(theirs, "0 5 * * *", "c.sh"))
            .await
            .unwrap();

        db.set_cron_last_error(mine, Some("crontab: command not found"))
            .await
            .unwrap();
        for j in db.cron_jobs_for_render(mine).await.unwrap() {
            assert_eq!(j.last_error.as_deref(), Some("crontab: command not found"));
        }
        assert_eq!(
            db.cron_jobs(&TenantScope::Global)
                .by_id(untouched.id)
                .await
                .unwrap()
                .unwrap()
                .last_error,
            None,
            "another subscription's crontab did not fail"
        );

        db.set_cron_last_error(mine, None).await.unwrap();
        assert!(
            db.cron_jobs_for_render(mine)
                .await
                .unwrap()
                .iter()
                .all(|j| j.last_error.is_none())
        );
    }

    #[tokio::test]
    async fn an_update_changes_only_the_fields_it_names() {
        let (db, _, mine, _) = seed().await;
        let created = db
            .create_cron_job(job(mine, "0 3 * * *", "backup.sh"))
            .await
            .unwrap();

        let updated = db
            .cron_jobs(&TenantScope::Global)
            .update(
                created.id,
                CronJobUpdate {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(!updated.enabled);
        assert_eq!(updated.schedule, "0 3 * * *");
        assert_eq!(updated.command, "backup.sh");
        assert_eq!(updated.subscription_id, mine);
    }
}
