//! Plans: named bundles of limits and feature flags (spec §6.2).
//!
//! Ownership is two-tier: a plan with `owner_user_id = NULL` is admin-global —
//! every reseller can see it and assign it — while a reseller's own plans are
//! visible only to that reseller (and to the admin). Customers never manage
//! plans; the scoped repository shows them nothing beyond what is already
//! assigned to their own subscriptions.
//!
//! Enforcement lives where resources are created: `site.create` asks
//! [`Db::quota_site_count`] before inserting a row, and the database module
//! does the same for `max_dbs` on its side. There is deliberately no
//! "check quota" flag on the plan row itself — a subscription without a plan
//! is unlimited, which is the Phase 1 behavior unchanged.

use serde::Serialize;
use unihelm_core::{ErrorCode, PlanId, SubscriptionId, TenantScope, UnihelmError, UserId};

use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub id: PlanId,
    /// `None` = admin-global (spec §6.2).
    pub owner_user_id: Option<UserId>,
    pub name: String,
    pub max_sites: i64,
    pub max_dbs: i64,
    pub storage_mb: i64,
    pub can_ssh: bool,
    pub can_cron: bool,
    pub can_node_apps: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PlanRow {
    pub id: i64,
    pub owner_user_id: Option<i64>,
    pub name: String,
    pub max_sites: i64,
    pub max_dbs: i64,
    pub storage_mb: i64,
    pub can_ssh: i64,
    pub can_cron: i64,
    pub can_node_apps: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<PlanRow> for Plan {
    type Error = DbError;

    fn try_from(r: PlanRow) -> Result<Self> {
        Ok(Plan {
            id: PlanId(r.id),
            owner_user_id: r.owner_user_id.map(UserId),
            name: r.name,
            max_sites: r.max_sites,
            max_dbs: r.max_dbs,
            storage_mb: r.storage_mb,
            // The CHECK constraints keep these to 0/1; `!= 0` tolerates a
            // hand-edited database rather than refusing to load it.
            can_ssh: r.can_ssh != 0,
            can_cron: r.can_cron != 0,
            can_node_apps: r.can_node_apps != 0,
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NewPlan {
    pub owner_user_id: Option<UserId>,
    pub name: String,
    pub max_sites: i64,
    pub max_dbs: i64,
    pub storage_mb: i64,
    pub can_ssh: bool,
    pub can_cron: bool,
    pub can_node_apps: bool,
}

/// A partial update. Every field is optional; only what is set moves.
#[derive(Debug, Clone, Default)]
pub struct PlanUpdate {
    pub name: Option<String>,
    pub max_sites: Option<i64>,
    pub max_dbs: Option<i64>,
    pub storage_mb: Option<i64>,
    pub can_ssh: Option<bool>,
    pub can_cron: Option<bool>,
    pub can_node_apps: Option<bool>,
}

pub struct PlanRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn plans(&self, scope: &TenantScope) -> PlanRepo<'_> {
        PlanRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    /// The plan a subscription is on, if any. Global on purpose: quota
    /// enforcement runs inside operations that already resolved the
    /// subscription through the caller's scope.
    pub async fn plan_of_subscription(&self, id: SubscriptionId) -> Result<Option<Plan>> {
        let row = sqlx::query_as::<_, PlanRow>(
            "SELECT p.* FROM plans p
             JOIN subscriptions s ON s.plan_id = p.id
             WHERE s.id = ?1",
        )
        .bind(id.get())
        .fetch_optional(self.pool())
        .await?;
        row.map(Plan::try_from).transpose()
    }

    /// How many sites count against a subscription's `max_sites`.
    ///
    /// Failed sites are excluded: a failed create is retried by *reclaiming*
    /// its row (see `site.create`), so counting it would let one broken attempt
    /// eat a slot of the quota it never actually used.
    pub async fn quota_site_count(&self, id: SubscriptionId) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sites WHERE subscription_id = ?1 AND status != 'failed'",
        )
        .bind(id.get())
        .fetch_one(self.pool())
        .await?;
        Ok(count)
    }

    /// How many databases count against a subscription's `max_dbs`.
    ///
    /// Database users are not counted: `max_dbs` is a count of databases, and
    /// the panel routinely creates several users per database.
    pub async fn quota_db_count(&self, id: SubscriptionId) -> Result<i64> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM dbs WHERE subscription_id = ?1")
                .bind(id.get())
                .fetch_one(self.pool())
                .await?;
        Ok(count)
    }

    /// How many subscriptions are on a plan — the delete-refusal number.
    pub async fn subscriptions_on_plan(&self, id: PlanId) -> Result<i64> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM subscriptions WHERE plan_id = ?1")
                .bind(id.get())
                .fetch_one(self.pool())
                .await?;
        Ok(count)
    }

    /// Point a subscription at a plan.
    ///
    /// Global on purpose, like [`Db::set_subscription_status`]: the operation
    /// layer resolves both the subscription and the plan through the caller's
    /// scope first, and this only records the outcome. SQLite cannot enforce
    /// the foreign key here (the column predates the `plans` table), so this
    /// method is the seam every assignment must pass through.
    pub async fn assign_plan(&self, subscription: SubscriptionId, plan: PlanId) -> Result<()> {
        let affected =
            sqlx::query("UPDATE subscriptions SET plan_id = ?2, updated_at = ?3 WHERE id = ?1")
                .bind(subscription.get())
                .bind(plan.get())
                .bind(to_sql_time(now()))
                .execute(self.pool())
                .await?
                .rows_affected();
        if affected == 0 {
            return Err(DbError::NotFound {
                what: "subscription",
            });
        }
        Ok(())
    }
}

impl PlanRepo<'_> {
    /// Create a plan.
    ///
    /// The scope constrains the owner, not the other way round: a
    /// reseller-scoped repository writes the reseller's id whatever the caller
    /// passed, so a forged `owner_user_id` cannot plant a plan in somebody
    /// else's catalogue (or in the global one).
    pub async fn create(&self, new: NewPlan) -> Result<Plan> {
        let owner = match self.scope {
            ScopeFilter::All => new.owner_user_id,
            ScopeFilter::Reseller(reseller_id) => Some(UserId(reseller_id)),
            ScopeFilter::Customer(_) | ScopeFilter::Subscription { .. } => {
                return Err(DbError::Domain(UnihelmError::denied(
                    "customers cannot create plans",
                )));
            }
        };

        let ts = to_sql_time(now());
        let result = sqlx::query_as::<_, PlanRow>(
            "INSERT INTO plans
                 (owner_user_id, name, max_sites, max_dbs, storage_mb,
                  can_ssh, can_cron, can_node_apps, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             RETURNING *",
        )
        .bind(owner.map(UserId::get))
        .bind(&new.name)
        .bind(new.max_sites)
        .bind(new.max_dbs)
        .bind(new.storage_mb)
        .bind(i64::from(new.can_ssh))
        .bind(i64::from(new.can_cron))
        .bind(i64::from(new.can_node_apps))
        .bind(&ts)
        .fetch_one(self.db.pool())
        .await;

        match result {
            Ok(row) => Plan::try_from(row),
            Err(sqlx::Error::Database(e)) if e.message().contains("UNIQUE constraint failed") => {
                Err(DbError::Conflict { what: "plan name" })
            }
            Err(e) => Err(e.into()),
        }
    }

    /// A plan this scope may *see*: admins see everything, a reseller sees its
    /// own plans plus the admin-global ones, a customer sees only what is
    /// already assigned to one of their subscriptions.
    pub async fn by_id(&self, id: PlanId) -> Result<Option<Plan>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, PlanRow>("SELECT * FROM plans WHERE id = ?1")
                    .bind(id.get())
                    .fetch_optional(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, PlanRow>(
                    "SELECT * FROM plans
                     WHERE id = ?1 AND (owner_user_id = ?2 OR owner_user_id IS NULL)",
                )
                .bind(id.get())
                .bind(reseller_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, PlanRow>(
                    "SELECT p.* FROM plans p
                     WHERE p.id = ?1 AND EXISTS (
                         SELECT 1 FROM subscriptions s
                         WHERE s.plan_id = p.id AND s.customer_id = ?2
                     )",
                )
                .bind(id.get())
                .bind(customer_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, PlanRow>(
                    "SELECT p.* FROM plans p
                     JOIN subscriptions s ON s.plan_id = p.id
                     WHERE p.id = ?1 AND s.id = ?2",
                )
                .bind(id.get())
                .bind(subscription_id)
                .fetch_optional(self.db.pool())
                .await?
            }
        };
        row.map(Plan::try_from).transpose()
    }

    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<Plan>> {
        let limit = limit.clamp(1, 500);
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, PlanRow>(
                    "SELECT * FROM plans ORDER BY name ASC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, PlanRow>(
                    "SELECT * FROM plans
                     WHERE owner_user_id = ?1 OR owner_user_id IS NULL
                     ORDER BY name ASC LIMIT ?2 OFFSET ?3",
                )
                .bind(reseller_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, PlanRow>(
                    "SELECT DISTINCT p.* FROM plans p
                     JOIN subscriptions s ON s.plan_id = p.id
                     WHERE s.customer_id = ?1
                     ORDER BY p.name ASC LIMIT ?2 OFFSET ?3",
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
                sqlx::query_as::<_, PlanRow>(
                    "SELECT p.* FROM plans p
                     JOIN subscriptions s ON s.plan_id = p.id
                     WHERE s.id = ?1",
                )
                .bind(subscription_id)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(Plan::try_from).collect()
    }

    /// Update a plan this scope may *change* — a narrower set than what it may
    /// see: a reseller reads global plans but only the admin edits them.
    pub async fn update(&self, id: PlanId, update: PlanUpdate) -> Result<Plan> {
        self.require_mutable(id).await?;

        let result = sqlx::query(
            "UPDATE plans SET
                 name          = COALESCE(?2, name),
                 max_sites     = COALESCE(?3, max_sites),
                 max_dbs       = COALESCE(?4, max_dbs),
                 storage_mb    = COALESCE(?5, storage_mb),
                 can_ssh       = COALESCE(?6, can_ssh),
                 can_cron      = COALESCE(?7, can_cron),
                 can_node_apps = COALESCE(?8, can_node_apps),
                 updated_at    = ?9
             WHERE id = ?1",
        )
        .bind(id.get())
        .bind(update.name.as_deref())
        .bind(update.max_sites)
        .bind(update.max_dbs)
        .bind(update.storage_mb)
        .bind(update.can_ssh.map(i64::from))
        .bind(update.can_cron.map(i64::from))
        .bind(update.can_node_apps.map(i64::from))
        .bind(to_sql_time(now()))
        .execute(self.db.pool())
        .await;

        if let Err(sqlx::Error::Database(e)) = &result
            && e.message().contains("UNIQUE constraint failed")
        {
            return Err(DbError::Conflict { what: "plan name" });
        }
        result?;

        self.by_id(id)
            .await?
            .ok_or(DbError::NotFound { what: "plan" })
    }

    /// Delete a plan — refused while any subscription is still on it.
    ///
    /// The `NOT EXISTS` guard is in the DELETE itself, not a separate check, so
    /// an assignment that lands between "count is zero" and "delete" cannot
    /// leave a subscription pointing at a plan that no longer exists.
    pub async fn delete(&self, id: PlanId) -> Result<()> {
        self.require_mutable(id).await?;

        let affected = sqlx::query(
            "DELETE FROM plans WHERE id = ?1
             AND NOT EXISTS (SELECT 1 FROM subscriptions WHERE plan_id = ?1)",
        )
        .bind(id.get())
        .execute(self.db.pool())
        .await?
        .rows_affected();

        if affected == 0 {
            let in_use = self.db.subscriptions_on_plan(id).await?;
            return Err(DbError::Domain(UnihelmError::new(
                ErrorCode::DependentsExist,
                format!(
                    "{in_use} subscription(s) still use this plan; move them to \
                     another plan first"
                ),
            )));
        }
        Ok(())
    }

    /// Visible *and* editable in this scope, or the reason it is not.
    ///
    /// The distinction between the two errors is deliberate: a plan the caller
    /// cannot even see answers "not found" (its existence is not their
    /// business), while a global plan a reseller can see but not edit names
    /// the real refusal.
    async fn require_mutable(&self, id: PlanId) -> Result<Plan> {
        let plan = self
            .by_id(id)
            .await?
            .ok_or(DbError::NotFound { what: "plan" })?;
        match self.scope {
            ScopeFilter::All => Ok(plan),
            ScopeFilter::Reseller(reseller_id) => {
                if plan.owner_user_id == Some(UserId(reseller_id)) {
                    Ok(plan)
                } else {
                    Err(DbError::Domain(UnihelmError::denied(
                        "global plans are managed by the administrator",
                    )))
                }
            }
            ScopeFilter::Customer(_) | ScopeFilter::Subscription { .. } => Err(DbError::Domain(
                UnihelmError::denied("customers cannot modify plans"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::NewUser;
    use unihelm_core::{Domain, Email, Role, SiteId, Username};

    async fn db_with_users() -> (Db, UserId, UserId, UserId) {
        let db = Db::open_memory().await.unwrap();
        let mk = |name: &'static str, role: Role, reseller: Option<UserId>| NewUser {
            role,
            email: Email::parse(&format!("{name}@example.com")).unwrap(),
            username: Username::parse(name).unwrap(),
            password: "a-long-enough-password".into(),
            reseller_id: reseller,
            full_name: None,
            locale: "en".into(),
        };
        let global = TenantScope::Global;
        let reseller_a = db
            .users(&global)
            .create(mk("resellera", Role::Reseller, None))
            .await
            .unwrap();
        let reseller_b = db
            .users(&global)
            .create(mk("resellerb", Role::Reseller, None))
            .await
            .unwrap();
        let customer = db
            .users(&global)
            .create(mk("customer", Role::Customer, Some(reseller_a.id)))
            .await
            .unwrap();
        (db, reseller_a.id, reseller_b.id, customer.id)
    }

    fn plan(name: &str, max_sites: i64) -> NewPlan {
        NewPlan {
            owner_user_id: None,
            name: name.into(),
            max_sites,
            max_dbs: 1,
            storage_mb: 1024,
            can_ssh: false,
            can_cron: true,
            can_node_apps: false,
        }
    }

    #[tokio::test]
    async fn a_reseller_sees_its_own_plans_plus_global_ones_and_nobody_elses() {
        let (db, a, b, _) = db_with_users().await;
        let global_plan = db
            .plans(&TenantScope::Global)
            .create(plan("global", 10))
            .await
            .unwrap();
        let a_scope = TenantScope::Reseller { reseller_id: a };
        let b_scope = TenantScope::Reseller { reseller_id: b };
        let a_plan = db.plans(&a_scope).create(plan("mine", 5)).await.unwrap();
        let b_plan = db.plans(&b_scope).create(plan("theirs", 5)).await.unwrap();

        let visible = db.plans(&a_scope).list(100, 0).await.unwrap();
        let names: Vec<&str> = visible.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["global", "mine"]);

        assert!(db.plans(&a_scope).by_id(a_plan.id).await.unwrap().is_some());
        assert!(
            db.plans(&a_scope)
                .by_id(global_plan.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            db.plans(&a_scope).by_id(b_plan.id).await.unwrap().is_none(),
            "another reseller's catalogue must be invisible"
        );
    }

    #[tokio::test]
    async fn a_reseller_scoped_create_cannot_plant_a_plan_in_the_global_catalogue() {
        let (db, a, _, _) = db_with_users().await;
        let scope = TenantScope::Reseller { reseller_id: a };
        // The caller claims global ownership; the scope overrules it.
        let created = db
            .plans(&scope)
            .create(NewPlan {
                owner_user_id: None,
                ..plan("sneaky", 5)
            })
            .await
            .unwrap();
        assert_eq!(created.owner_user_id, Some(a));
    }

    #[tokio::test]
    async fn a_reseller_may_read_but_not_edit_or_delete_a_global_plan() {
        let (db, a, _, _) = db_with_users().await;
        let global_plan = db
            .plans(&TenantScope::Global)
            .create(plan("global", 10))
            .await
            .unwrap();
        let scope = TenantScope::Reseller { reseller_id: a };

        let err = db
            .plans(&scope)
            .update(
                global_plan.id,
                PlanUpdate {
                    max_sites: Some(999),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            DbError::Domain(ref e) if e.code == ErrorCode::PermissionDenied
        ));

        let err = db.plans(&scope).delete(global_plan.id).await.unwrap_err();
        assert!(matches!(
            err,
            DbError::Domain(ref e) if e.code == ErrorCode::PermissionDenied
        ));
    }

    #[tokio::test]
    async fn plan_names_are_unique_per_owner_including_the_global_owner() {
        let (db, a, _, _) = db_with_users().await;
        let global = TenantScope::Global;
        db.plans(&global).create(plan("starter", 1)).await.unwrap();
        assert!(matches!(
            db.plans(&global).create(plan("starter", 2)).await,
            Err(DbError::Conflict { .. })
        ));
        // The same name under a different owner is a different plan.
        let scope = TenantScope::Reseller { reseller_id: a };
        assert!(db.plans(&scope).create(plan("starter", 2)).await.is_ok());
    }

    #[tokio::test]
    async fn a_plan_with_subscriptions_on_it_cannot_be_deleted() {
        let (db, _, _, customer) = db_with_users().await;
        let global = TenantScope::Global;
        let p = db.plans(&global).create(plan("starter", 1)).await.unwrap();
        let sub = db.create_subscription(customer).await.unwrap();
        db.assign_plan(sub.id, p.id).await.unwrap();

        let err = db.plans(&global).delete(p.id).await.unwrap_err();
        assert!(
            matches!(err, DbError::Domain(ref e) if e.code == ErrorCode::DependentsExist),
            "got {err:?}"
        );

        // Unassigned (subscription removed from the plan), the delete goes through.
        sqlx::query("UPDATE subscriptions SET plan_id = NULL WHERE id = ?1")
            .bind(sub.id.get())
            .execute(db.pool())
            .await
            .unwrap();
        db.plans(&global).delete(p.id).await.unwrap();
        assert!(db.plans(&global).by_id(p.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_customer_sees_only_the_plan_assigned_to_their_subscription() {
        let (db, a, _, customer) = db_with_users().await;
        let global = TenantScope::Global;
        let assigned = db.plans(&global).create(plan("mine", 1)).await.unwrap();
        let other = db.plans(&global).create(plan("other", 1)).await.unwrap();
        let _ = a;

        let sub = db.create_subscription(customer).await.unwrap();
        db.assign_plan(sub.id, assigned.id).await.unwrap();

        let scope = TenantScope::Customer {
            customer_id: customer,
        };
        let visible = db.plans(&scope).list(100, 0).await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, assigned.id);
        assert!(db.plans(&scope).by_id(other.id).await.unwrap().is_none());

        // And a customer can mutate nothing, not even their own plan.
        let err = db.plans(&scope).delete(assigned.id).await.unwrap_err();
        assert!(matches!(
            err,
            DbError::Domain(ref e) if e.code == ErrorCode::PermissionDenied
        ));
    }

    #[tokio::test]
    async fn the_quota_count_ignores_failed_sites() {
        // A failed create is retried by reclaiming its row, so it must not eat
        // a quota slot it never used.
        let (db, _, _, customer) = db_with_users().await;
        let sub = db.create_subscription(customer).await.unwrap();

        let mk = |domain: &str| crate::NewSite {
            subscription_id: sub.id,
            domain: Domain::parse(domain).unwrap(),
            site_type: crate::SiteType::Static,
            php_version: None,
            root_dir: format!("/home/{}/sites/{domain}/public", sub.linux_user),
            proxy_port: None,
            redirect_target: None,
        };
        let ok = db.create_site(mk("ok.example.com")).await.unwrap();
        let failed = db.create_site(mk("bad.example.com")).await.unwrap();
        db.set_site_status(ok.id, crate::SiteStatus::Active)
            .await
            .unwrap();
        db.set_site_status(failed.id, crate::SiteStatus::Failed)
            .await
            .unwrap();

        assert_eq!(db.quota_site_count(sub.id).await.unwrap(), 1);
        let _: SiteId = ok.id; // typed, not a raw i64
    }

    #[tokio::test]
    async fn assigning_a_plan_records_it_on_the_subscription() {
        let (db, _, _, customer) = db_with_users().await;
        let global = TenantScope::Global;
        let p = db.plans(&global).create(plan("starter", 3)).await.unwrap();
        let sub = db.create_subscription(customer).await.unwrap();

        db.assign_plan(sub.id, p.id).await.unwrap();
        let found = db.plan_of_subscription(sub.id).await.unwrap().unwrap();
        assert_eq!(found.id, p.id);
        assert_eq!(db.subscriptions_on_plan(p.id).await.unwrap(), 1);

        // A subscription that does not exist is an error, not a silent no-op.
        assert!(matches!(
            db.assign_plan(SubscriptionId(9999), p.id).await,
            Err(DbError::NotFound { .. })
        ));
    }
}
