//! Stored migration plans (spec §11.15).
//!
//! The dry run *is* the feature, so the plan has to outlive the request that
//! produced it: `import.plan` writes a row here and returns its id, and
//! `import.apply` executes the JSON in that row. There is deliberately no way
//! to apply a plan that was never stored — see `0017_imports.sql` for why that
//! matters more than it looks.
//!
//! Two things in here are worth reading twice:
//!
//! * [`Db::claim_import_plan`] is the double-apply guard, and it is a
//!   conditional UPDATE rather than a read-then-write. Two administrators
//!   clicking "apply" on the same plan is not exotic, and a check-then-set
//!   would let both through — SQLite would serialise the two writes and both
//!   would see `applied_at IS NULL` on their read. `UPDATE … WHERE applied_at
//!   IS NULL` makes exactly one of them see `rows_affected == 1`.
//! * Scoping goes through the subscription the plan targets, the same join
//!   [`crate::cron`] uses. A plan id outside the caller's scope reads as
//!   `Ok(None)`, indistinguishable from one that does not exist.

use serde::Serialize;
use unihelm_core::{SubscriptionId, TenantScope, UserId};

use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// Which importer produced a plan. Mirrors the `source_kind` CHECK in
/// `0017_imports.sql`; parsing on the way out is what keeps the two in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportSource {
    Cpanel,
    Aapanel,
}

impl ImportSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            ImportSource::Cpanel => "cpanel",
            ImportSource::Aapanel => "aapanel",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cpanel" => Some(ImportSource::Cpanel),
            "aapanel" => Some(ImportSource::Aapanel),
            _ => None,
        }
    }
}

/// One stored dry run.
#[derive(Debug, Clone, Serialize)]
pub struct ImportPlanRecord {
    pub id: i64,
    pub source_kind: ImportSource,
    pub source_path: String,
    pub source_fingerprint: String,
    pub subscription_id: SubscriptionId,
    /// The plan document, exactly as it was shown to the operator. Kept as a
    /// string here: this layer never looks inside it.
    pub plan_json: String,
    pub created_by: Option<UserId>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub applied_at: Option<time::OffsetDateTime>,
    pub applied_task_id: Option<String>,
    pub outcome_json: Option<String>,
}

impl ImportPlanRecord {
    /// Has this plan already been executed?
    pub const fn is_applied(&self) -> bool {
        self.applied_at.is_some()
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ImportPlanRow {
    pub id: i64,
    pub source_kind: String,
    pub source_path: String,
    pub source_fingerprint: String,
    pub subscription_id: i64,
    pub plan_json: String,
    pub created_by: Option<i64>,
    pub created_at: String,
    pub applied_at: Option<String>,
    pub applied_task_id: Option<String>,
    pub outcome_json: Option<String>,
}

impl TryFrom<ImportPlanRow> for ImportPlanRecord {
    type Error = DbError;

    fn try_from(r: ImportPlanRow) -> Result<Self> {
        Ok(ImportPlanRecord {
            id: r.id,
            source_kind: ImportSource::parse(&r.source_kind).ok_or(DbError::Corrupt {
                field: "import_plans.source_kind",
                detail: r.source_kind.clone(),
            })?,
            source_path: r.source_path,
            source_fingerprint: r.source_fingerprint,
            subscription_id: SubscriptionId(r.subscription_id),
            plan_json: r.plan_json,
            created_by: r.created_by.map(UserId),
            created_at: from_sql_time(&r.created_at)?,
            applied_at: r.applied_at.as_deref().map(from_sql_time).transpose()?,
            applied_task_id: r.applied_task_id,
            outcome_json: r.outcome_json,
        })
    }
}

/// What storing a dry run needs.
#[derive(Debug, Clone)]
pub struct NewImportPlan {
    pub source_kind: ImportSource,
    pub source_path: String,
    pub source_fingerprint: String,
    pub subscription_id: SubscriptionId,
    pub plan_json: String,
    pub created_by: Option<UserId>,
}

pub struct ImportPlanRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn import_plans(&self, scope: &TenantScope) -> ImportPlanRepo<'_> {
        ImportPlanRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    /// Store a dry run.
    ///
    /// Unscoped by design, like [`Db::create_site`]: the caller resolved
    /// `subscription_id` through their own scope to get here.
    pub async fn create_import_plan(&self, new: NewImportPlan) -> Result<ImportPlanRecord> {
        let row = sqlx::query_as::<_, ImportPlanRow>(
            "INSERT INTO import_plans
                 (source_kind, source_path, source_fingerprint, subscription_id,
                  plan_json, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             RETURNING *",
        )
        .bind(new.source_kind.as_str())
        .bind(&new.source_path)
        .bind(&new.source_fingerprint)
        .bind(new.subscription_id.get())
        .bind(&new.plan_json)
        .bind(new.created_by.map(|u| u.get()))
        .bind(to_sql_time(now()))
        .fetch_one(self.pool())
        .await?;
        ImportPlanRecord::try_from(row)
    }

    /// Take ownership of a plan for one apply, or report that somebody already
    /// has.
    ///
    /// `Ok(true)` means this caller is the one that may proceed. The window
    /// between claiming and finishing is intentionally the whole apply: a plan
    /// whose apply crashed stays claimed, and re-running it would create a
    /// second set of sites and databases on top of a half-finished first set.
    /// Recovering from that is an operator decision (make a fresh plan), not
    /// something to paper over with a retry.
    pub async fn claim_import_plan(&self, id: i64, task_id: Option<&str>) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE import_plans
                SET applied_at = ?2, applied_task_id = ?3
              WHERE id = ?1 AND applied_at IS NULL",
        )
        .bind(id)
        .bind(to_sql_time(now()))
        .bind(task_id)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Record what the apply actually did. Called once, after the apply
    /// finishes — including when it failed part-way, which is exactly the case
    /// somebody will need to read.
    pub async fn set_import_outcome(&self, id: i64, outcome_json: &str) -> Result<()> {
        sqlx::query("UPDATE import_plans SET outcome_json = ?2 WHERE id = ?1")
            .bind(id)
            .bind(outcome_json)
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

impl ImportPlanRepo<'_> {
    /// One plan, if this scope may see it.
    pub async fn by_id(&self, id: i64) -> Result<Option<ImportPlanRecord>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, ImportPlanRow>("SELECT * FROM import_plans WHERE id = ?1")
                    .bind(id)
                    .fetch_optional(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, ImportPlanRow>(
                    "SELECT p.* FROM import_plans p
                     JOIN subscriptions sub ON sub.id = p.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE p.id = ?1 AND u.reseller_id = ?2",
                )
                .bind(id)
                .bind(reseller_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, ImportPlanRow>(
                    "SELECT p.* FROM import_plans p
                     JOIN subscriptions sub ON sub.id = p.subscription_id
                     WHERE p.id = ?1 AND sub.customer_id = ?2",
                )
                .bind(id)
                .bind(customer_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, ImportPlanRow>(
                    "SELECT * FROM import_plans WHERE id = ?1 AND subscription_id = ?2",
                )
                .bind(id)
                .bind(subscription_id)
                .fetch_optional(self.db.pool())
                .await?
            }
        };
        row.map(ImportPlanRecord::try_from).transpose()
    }

    /// Recent plans this scope can see, newest first.
    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<ImportPlanRecord>> {
        let limit = limit.clamp(1, 200);
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, ImportPlanRow>(
                    "SELECT * FROM import_plans ORDER BY id DESC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, ImportPlanRow>(
                    "SELECT p.* FROM import_plans p
                     JOIN subscriptions sub ON sub.id = p.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE u.reseller_id = ?1
                     ORDER BY p.id DESC LIMIT ?2 OFFSET ?3",
                )
                .bind(reseller_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, ImportPlanRow>(
                    "SELECT p.* FROM import_plans p
                     JOIN subscriptions sub ON sub.id = p.subscription_id
                     WHERE sub.customer_id = ?1
                     ORDER BY p.id DESC LIMIT ?2 OFFSET ?3",
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
                sqlx::query_as::<_, ImportPlanRow>(
                    "SELECT * FROM import_plans
                     WHERE subscription_id = ?1
                     ORDER BY id DESC LIMIT ?2 OFFSET ?3",
                )
                .bind(subscription_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(ImportPlanRecord::try_from).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unihelm_core::{Email, Role, Username};

    async fn seeded() -> (Db, SubscriptionId, UserId) {
        let db = Db::open_memory().await.unwrap();
        let user = db
            .users(&TenantScope::Global)
            .create(crate::users::NewUser {
                role: Role::Customer,
                email: Email::parse("imp@example.com").unwrap(),
                username: Username::parse("imp").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let sub = db.create_subscription(user.id).await.unwrap();
        (db, sub.id, user.id)
    }

    fn new_plan(sub: SubscriptionId, by: UserId) -> NewImportPlan {
        NewImportPlan {
            source_kind: ImportSource::Cpanel,
            source_path: "/root/cpmove-bob.tar.gz".into(),
            source_fingerprint: "deadbeef".into(),
            subscription_id: sub,
            plan_json: r#"{"sites":[]}"#.into(),
            created_by: Some(by),
        }
    }

    #[tokio::test]
    async fn a_stored_plan_comes_back_byte_identical() {
        let (db, sub, by) = seeded().await;
        let stored = db.create_import_plan(new_plan(sub, by)).await.unwrap();
        let read = db
            .import_plans(&TenantScope::Global)
            .by_id(stored.id)
            .await
            .unwrap()
            .expect("stored");
        // The reviewed artifact must survive the round trip exactly; anything
        // else and "apply what was approved" is a claim we cannot make.
        assert_eq!(read.plan_json, r#"{"sites":[]}"#);
        assert_eq!(read.source_kind, ImportSource::Cpanel);
        assert!(!read.is_applied());
    }

    #[tokio::test]
    async fn only_the_first_claim_on_a_plan_succeeds() {
        let (db, sub, by) = seeded().await;
        let stored = db.create_import_plan(new_plan(sub, by)).await.unwrap();
        assert!(
            db.claim_import_plan(stored.id, Some("task-1"))
                .await
                .unwrap()
        );
        assert!(
            !db.claim_import_plan(stored.id, Some("task-2"))
                .await
                .unwrap(),
            "a second apply of the same plan must be refused, not duplicated"
        );
        let read = db
            .import_plans(&TenantScope::Global)
            .by_id(stored.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.applied_task_id.as_deref(), Some("task-1"));
    }

    #[tokio::test]
    async fn another_customers_plan_is_not_visible() {
        let (db, sub, by) = seeded().await;
        let stored = db.create_import_plan(new_plan(sub, by)).await.unwrap();
        let stranger = db
            .users(&TenantScope::Global)
            .create(crate::users::NewUser {
                role: Role::Customer,
                email: Email::parse("other@example.com").unwrap(),
                username: Username::parse("other").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();

        let scope = TenantScope::Customer {
            customer_id: stranger.id,
        };
        assert!(
            db.import_plans(&scope)
                .by_id(stored.id)
                .await
                .unwrap()
                .is_none(),
            "a plan outside the scope must read as absent, not as forbidden"
        );
        assert!(
            db.import_plans(&scope)
                .list(50, 0)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
