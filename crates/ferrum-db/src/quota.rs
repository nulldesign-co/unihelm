//! Disk quota state: per-subscription limits and XFS project id allocation
//! (spec §6.2, §6.3).
//!
//! The kernel enforces quotas; this module is the panel's book-keeping about
//! what it asked the kernel to enforce. Two invariants matter:
//!
//! 1. **A project id is never shared.** XFS accounts usage per project id, so
//!    two subscriptions behind one id would see each other's consumption and
//!    trip each other's limits. The `quota_projects` PRIMARY KEY enforces this
//!    at the storage layer; the allocator here only chooses candidates.
//! 2. **Ids are reused after deletion, not before.** The id space is not
//!    scarce, but leaking one id per deleted tenant forever means an
//!    installation that churns tenants walks its ids upward without bound —
//!    and stale ids linger in `xfs_quota report` output for operators to
//!    puzzle over. Allocation therefore takes the smallest free id at or
//!    above [`FIRST_PROJECT_ID`].

use ferrum_core::SubscriptionId;
use serde::Serialize;

use crate::{Db, DbError, Result, now, to_sql_time};

/// Where panel-allocated XFS project ids start. Everything below is reserved
/// for ids an operator may have assigned by hand before the panel arrived.
pub const FIRST_PROJECT_ID: i64 = 100;

/// One row of `quota_projects`: an XFS project id bound to a subscription.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct QuotaProject {
    pub project_id: i64,
    pub subscription_id: i64,
    pub path: String,
}

/// The limits stored on a subscription. `None` means no quota has been set —
/// deliberately distinct from zero, which would be "a quota of nothing".
#[derive(Debug, Clone, Copy, Serialize, sqlx::FromRow)]
pub struct QuotaLimits {
    pub quota_soft_mb: Option<i64>,
    pub quota_hard_mb: Option<i64>,
}

impl Db {
    /// The project id for a subscription, allocating one on first use.
    ///
    /// Repeated calls return the same id: the mapping is the durable record
    /// of what the kernel was told, so inventing a fresh id per call would
    /// orphan the accounting the previous id had accumulated.
    pub async fn quota_project_for(
        &self,
        subscription_id: SubscriptionId,
        path: &str,
    ) -> Result<QuotaProject> {
        if let Some(existing) = self.quota_project(subscription_id).await? {
            return Ok(existing);
        }

        // Two writers can compute the same candidate; the PRIMARY KEY turns
        // the loser's insert into a retry instead of a shared id. Bounded like
        // the linux-user retry in `create_subscription`: if eight attempts all
        // collide something is systematically wrong and looping forever would
        // only hide it.
        for _ in 0..8 {
            let result = sqlx::query_as::<_, QuotaProject>(
                // Smallest free id >= FIRST_PROJECT_ID. The seed row in the
                // UNION covers the empty-table case and the case where the
                // first id itself was freed by a deleted tenant.
                "INSERT INTO quota_projects (project_id, subscription_id, path, created_at)
                 SELECT MIN(candidate), ?1, ?2, ?3 FROM (
                     SELECT ?4 AS candidate
                     UNION ALL
                     SELECT project_id + 1 FROM quota_projects WHERE project_id >= ?4
                 )
                 WHERE candidate NOT IN (SELECT project_id FROM quota_projects)
                 RETURNING project_id, subscription_id, path",
            )
            .bind(subscription_id.get())
            .bind(path)
            .bind(to_sql_time(now()))
            .bind(FIRST_PROJECT_ID)
            .fetch_one(self.pool())
            .await;

            match result {
                Ok(row) => return Ok(row),
                Err(sqlx::Error::Database(e))
                    if e.message().contains("UNIQUE constraint failed") =>
                {
                    // Either another writer took our candidate id, or another
                    // call already allocated for this subscription. Re-check
                    // the mapping before retrying the id race.
                    if let Some(existing) = self.quota_project(subscription_id).await? {
                        return Ok(existing);
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(DbError::Conflict {
            what: "quota project id",
        })
    }

    /// The project id already allocated to a subscription, if any.
    pub async fn quota_project(
        &self,
        subscription_id: SubscriptionId,
    ) -> Result<Option<QuotaProject>> {
        let row = sqlx::query_as::<_, QuotaProject>(
            "SELECT project_id, subscription_id, path FROM quota_projects
             WHERE subscription_id = ?1",
        )
        .bind(subscription_id.get())
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// Record the limits the kernel was just told to enforce.
    ///
    /// Written *after* enforcement succeeds, so the database never claims a
    /// quota that is not actually live (the caller in `ferrum-ops` owns that
    /// ordering).
    pub async fn set_quota_limits(
        &self,
        subscription_id: SubscriptionId,
        soft_mb: i64,
        hard_mb: i64,
    ) -> Result<()> {
        let done = sqlx::query(
            "UPDATE subscriptions SET quota_soft_mb = ?2, quota_hard_mb = ?3, updated_at = ?4
             WHERE id = ?1",
        )
        .bind(subscription_id.get())
        .bind(soft_mb)
        .bind(hard_mb)
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        if done.rows_affected() == 0 {
            return Err(DbError::NotFound {
                what: "subscription",
            });
        }
        Ok(())
    }

    /// The stored limits for a subscription, or `None` if it does not exist.
    pub async fn quota_limits(
        &self,
        subscription_id: SubscriptionId,
    ) -> Result<Option<QuotaLimits>> {
        let row = sqlx::query_as::<_, QuotaLimits>(
            "SELECT quota_soft_mb, quota_hard_mb FROM subscriptions WHERE id = ?1",
        )
        .bind(subscription_id.get())
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::NewUser;
    use ferrum_core::{Email, Role, TenantScope, Username};

    async fn seed() -> (Db, Vec<SubscriptionId>) {
        let db = Db::open_memory().await.unwrap();
        let mut subs = Vec::new();
        for name in ["alice", "bobby", "carol"] {
            let user = db
                .users(&TenantScope::Global)
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
                .unwrap();
            subs.push(db.create_subscription(user.id).await.unwrap().id);
        }
        (db, subs)
    }

    #[tokio::test]
    async fn each_subscription_gets_its_own_project_id() {
        let (db, subs) = seed().await;
        let a = db.quota_project_for(subs[0], "/home/ft_a").await.unwrap();
        let b = db.quota_project_for(subs[1], "/home/ft_b").await.unwrap();
        let c = db.quota_project_for(subs[2], "/home/ft_c").await.unwrap();

        // Distinct ids: XFS accounts usage per id, so a shared id would let
        // one tenant's files count against another's limit.
        assert_eq!(a.project_id, FIRST_PROJECT_ID);
        assert_eq!(b.project_id, FIRST_PROJECT_ID + 1);
        assert_eq!(c.project_id, FIRST_PROJECT_ID + 2);
    }

    #[tokio::test]
    async fn allocation_is_idempotent_per_subscription() {
        let (db, subs) = seed().await;
        let first = db.quota_project_for(subs[0], "/home/ft_a").await.unwrap();
        let again = db.quota_project_for(subs[0], "/home/ft_a").await.unwrap();
        assert_eq!(first.project_id, again.project_id);
        // And only one row exists — the id is the durable record of what the
        // kernel was told, not a counter.
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM quota_projects")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    #[tokio::test]
    async fn a_deleted_tenants_project_id_is_reused_not_leaked() {
        let (db, subs) = seed().await;
        db.quota_project_for(subs[0], "/home/ft_a").await.unwrap();
        let b = db.quota_project_for(subs[1], "/home/ft_b").await.unwrap();
        db.quota_project_for(subs[2], "/home/ft_c").await.unwrap();

        // Deleting the subscription cascades the project row away.
        sqlx::query("DELETE FROM subscriptions WHERE id = ?1")
            .bind(subs[1].get())
            .execute(db.pool())
            .await
            .unwrap();
        assert!(db.quota_project(subs[1]).await.unwrap().is_none());

        // A new tenant takes the freed id — the smallest hole, not a fresh
        // number — so the id space does not creep upward as tenants churn.
        let user = db
            .users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Customer,
                email: Email::parse("dave@example.com").unwrap(),
                username: Username::parse("dave1").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let sub = db.create_subscription(user.id).await.unwrap();
        let reused = db.quota_project_for(sub.id, "/home/ft_d").await.unwrap();
        assert_eq!(reused.project_id, b.project_id);
    }

    #[tokio::test]
    async fn the_first_id_itself_is_reusable_after_deletion() {
        let (db, subs) = seed().await;
        let a = db.quota_project_for(subs[0], "/home/ft_a").await.unwrap();
        db.quota_project_for(subs[1], "/home/ft_b").await.unwrap();
        assert_eq!(a.project_id, FIRST_PROJECT_ID);

        sqlx::query("DELETE FROM subscriptions WHERE id = ?1")
            .bind(subs[0].get())
            .execute(db.pool())
            .await
            .unwrap();

        // The UNION seed row in the allocator exists for exactly this case:
        // without it the query only ever proposes successor ids and the very
        // first id would leak forever.
        let again = db.quota_project_for(subs[2], "/home/ft_c").await.unwrap();
        assert_eq!(again.project_id, FIRST_PROJECT_ID);
    }

    #[tokio::test]
    async fn limits_round_trip_and_absence_is_none_not_zero() {
        let (db, subs) = seed().await;
        let before = db.quota_limits(subs[0]).await.unwrap().unwrap();
        assert_eq!(before.quota_soft_mb, None);
        assert_eq!(before.quota_hard_mb, None);

        db.set_quota_limits(subs[0], 500, 550).await.unwrap();
        let after = db.quota_limits(subs[0]).await.unwrap().unwrap();
        assert_eq!(after.quota_soft_mb, Some(500));
        assert_eq!(after.quota_hard_mb, Some(550));

        // A subscription that does not exist is an error the caller can see,
        // not a silent no-op.
        let missing = SubscriptionId(9999);
        assert!(db.quota_limits(missing).await.unwrap().is_none());
        assert!(db.set_quota_limits(missing, 1, 1).await.is_err());
    }
}
