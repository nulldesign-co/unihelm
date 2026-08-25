//! Subscriptions: the unit that owns sites and maps to one Linux account.
//!
//! Plans and quotas are Phase 2. What exists here is the part Phase 1 genuinely
//! needs: a PHP-FPM pool has to run as *somebody*, and that somebody is the
//! subscription's Linux user.

use ferrum_core::{LinuxUser, SubscriptionId, TenantScope, UserId};
use serde::Serialize;

use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    Suspended,
    PendingDelete,
}

impl SubscriptionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            SubscriptionStatus::Active => "active",
            SubscriptionStatus::Suspended => "suspended",
            SubscriptionStatus::PendingDelete => "pending_delete",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "active" => SubscriptionStatus::Active,
            "suspended" => SubscriptionStatus::Suspended,
            "pending_delete" => SubscriptionStatus::PendingDelete,
            other => {
                return Err(DbError::Corrupt {
                    field: "subscriptions.status",
                    detail: format!("unknown status `{other}`"),
                });
            }
        })
    }

    /// A suspended subscription's sites are switched to a suspended page and its
    /// pools are stopped; nothing new may be created under it.
    pub const fn can_serve(self) -> bool {
        matches!(self, SubscriptionStatus::Active)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Subscription {
    pub id: SubscriptionId,
    pub customer_id: UserId,
    pub plan_id: Option<i64>,
    pub linux_user: String,
    pub home_dir: String,
    pub status: SubscriptionStatus,
    pub suspended_reason: Option<String>,
    /// When the current suspension began; the clock the delete grace period
    /// runs from (spec §6.4). `None` whenever the subscription is active.
    #[serde(with = "time::serde::rfc3339::option")]
    pub suspended_at: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubscriptionRow {
    pub id: i64,
    pub customer_id: i64,
    pub plan_id: Option<i64>,
    pub linux_user: String,
    pub home_dir: String,
    pub status: String,
    pub suspended_reason: Option<String>,
    pub suspended_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<SubscriptionRow> for Subscription {
    type Error = DbError;

    fn try_from(r: SubscriptionRow) -> Result<Self> {
        Ok(Subscription {
            id: SubscriptionId(r.id),
            customer_id: UserId(r.customer_id),
            plan_id: r.plan_id,
            linux_user: r.linux_user,
            home_dir: r.home_dir,
            status: SubscriptionStatus::parse(&r.status)?,
            suspended_reason: r.suspended_reason,
            suspended_at: r.suspended_at.as_deref().map(from_sql_time).transpose()?,
            created_at: from_sql_time(&r.created_at)?,
        })
    }
}

pub struct SubscriptionRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn subscriptions(&self, scope: &TenantScope) -> SubscriptionRepo<'_> {
        SubscriptionRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    /// Create a subscription with a freshly generated Linux account name.
    ///
    /// The name is derived from randomness rather than from the customer's
    /// details: a username that leaks who a tenant is shows up in `ps`, in file
    /// ownership, and in every other tenant's view of the process table.
    pub async fn create_subscription(&self, customer_id: UserId) -> Result<Subscription> {
        for _ in 0..8 {
            let candidate = generate_linux_user();
            let user = LinuxUser::parse(&candidate)?;
            let home = format!("/home/{}", user.as_str());
            let ts = to_sql_time(now());

            let result = sqlx::query_as::<_, SubscriptionRow>(
                "INSERT INTO subscriptions (customer_id, linux_user, home_dir, status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'active', ?4, ?4)
                 RETURNING *",
            )
            .bind(customer_id.get())
            .bind(user.as_str())
            .bind(&home)
            .bind(&ts)
            .fetch_one(self.pool())
            .await;

            match result {
                Ok(row) => return Subscription::try_from(row),
                // Astronomically unlikely, but a name collision must retry
                // rather than fail a customer's signup.
                Err(sqlx::Error::Database(e))
                    if e.message().contains("UNIQUE constraint failed") =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(DbError::Conflict {
            what: "linux user name",
        })
    }

    /// The subscription a Linux account belongs to.
    pub async fn subscription_by_linux_user(
        &self,
        linux_user: &str,
    ) -> Result<Option<Subscription>> {
        let row = sqlx::query_as::<_, SubscriptionRow>(
            "SELECT * FROM subscriptions WHERE linux_user = ?1",
        )
        .bind(linux_user)
        .fetch_optional(self.pool())
        .await?;
        row.map(Subscription::try_from).transpose()
    }

    /// The customer's first subscription, creating one if they have none.
    ///
    /// Phase 1 has no UI for managing subscriptions, so a site created by an
    /// admin lands in an implicit one. Phase 2 replaces this with a real
    /// provisioning flow; the shape of the row does not change.
    pub async fn default_subscription_for(&self, customer_id: UserId) -> Result<Subscription> {
        let existing = sqlx::query_as::<_, SubscriptionRow>(
            "SELECT * FROM subscriptions WHERE customer_id = ?1 AND status = 'active'
             ORDER BY id ASC LIMIT 1",
        )
        .bind(customer_id.get())
        .fetch_optional(self.pool())
        .await?;

        match existing {
            Some(row) => Subscription::try_from(row),
            None => self.create_subscription(customer_id).await,
        }
    }

    pub async fn set_subscription_status(
        &self,
        id: SubscriptionId,
        status: SubscriptionStatus,
        reason: Option<&str>,
    ) -> Result<()> {
        let ts = to_sql_time(now());
        // `suspended_at` follows the status (spec §6.4): stamped whenever the
        // subscription stops being active, cleared the moment it is again — so
        // a reinstated tenant never carries a stale suspension clock into a
        // later delete grace-period calculation.
        let suspended_at = match status {
            SubscriptionStatus::Active => None,
            SubscriptionStatus::Suspended | SubscriptionStatus::PendingDelete => Some(ts.clone()),
        };
        sqlx::query(
            "UPDATE subscriptions
             SET status = ?2, suspended_reason = ?3, suspended_at = ?4, updated_at = ?5
             WHERE id = ?1",
        )
        .bind(id.get())
        .bind(status.as_str())
        .bind(reason)
        .bind(suspended_at)
        .bind(&ts)
        .execute(self.pool())
        .await?;
        Ok(())
    }
}

impl SubscriptionRepo<'_> {
    pub async fn by_id(&self, id: SubscriptionId) -> Result<Option<Subscription>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, SubscriptionRow>("SELECT * FROM subscriptions WHERE id = ?1")
                    .bind(id.get())
                    .fetch_optional(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, SubscriptionRow>(
                    "SELECT s.* FROM subscriptions s
                     JOIN users u ON u.id = s.customer_id
                     WHERE s.id = ?1 AND u.reseller_id = ?2",
                )
                .bind(id.get())
                .bind(reseller_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, SubscriptionRow>(
                    "SELECT * FROM subscriptions WHERE id = ?1 AND customer_id = ?2",
                )
                .bind(id.get())
                .bind(customer_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, SubscriptionRow>(
                    "SELECT * FROM subscriptions WHERE id = ?1 AND id = ?2",
                )
                .bind(id.get())
                .bind(subscription_id)
                .fetch_optional(self.db.pool())
                .await?
            }
        };
        row.map(Subscription::try_from).transpose()
    }

    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<Subscription>> {
        let limit = limit.clamp(1, 500);
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, SubscriptionRow>(
                    "SELECT * FROM subscriptions ORDER BY id DESC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, SubscriptionRow>(
                    "SELECT s.* FROM subscriptions s
                     JOIN users u ON u.id = s.customer_id
                     WHERE u.reseller_id = ?1 ORDER BY s.id DESC LIMIT ?2 OFFSET ?3",
                )
                .bind(reseller_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, SubscriptionRow>(
                    "SELECT * FROM subscriptions WHERE customer_id = ?1
                     ORDER BY id DESC LIMIT ?2 OFFSET ?3",
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
                sqlx::query_as::<_, SubscriptionRow>("SELECT * FROM subscriptions WHERE id = ?1")
                    .bind(subscription_id)
                    .fetch_all(self.db.pool())
                    .await?
            }
        };
        rows.into_iter().map(Subscription::try_from).collect()
    }
}

/// `ft_` plus 8 random lowercase-alphanumeric characters.
///
/// Short enough for the 32-character Linux limit with room for suffixes, long
/// enough that guessing another tenant's account name is not a strategy.
fn generate_linux_user() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..8)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect();
    format!("ft_{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::NewUser;
    use ferrum_core::{Email, Role, Username};

    async fn seed() -> (Db, UserId, UserId) {
        let db = Db::open_memory().await.unwrap();
        let mk = |name: &'static str| NewUser {
            role: Role::Customer,
            email: Email::parse(&format!("{name}@example.com")).unwrap(),
            username: Username::parse(name).unwrap(),
            password: "a-long-enough-password".into(),
            reseller_id: None,
            full_name: None,
            locale: "en".into(),
        };
        let a = db
            .users(&TenantScope::Global)
            .create(mk("alice"))
            .await
            .unwrap();
        let b = db
            .users(&TenantScope::Global)
            .create(mk("bobby"))
            .await
            .unwrap();
        (db, a.id, b.id)
    }

    #[tokio::test]
    async fn a_subscription_gets_a_unique_opaque_linux_user() {
        let (db, alice, bobby) = seed().await;
        let a = db.create_subscription(alice).await.unwrap();
        let b = db.create_subscription(bobby).await.unwrap();

        assert_ne!(a.linux_user, b.linux_user);
        assert!(a.linux_user.starts_with("ft_"));
        assert_eq!(a.linux_user.len(), 11);
        // The account name must not reveal who the tenant is: it shows up in
        // `ps` and in file ownership for every other tenant to see.
        assert!(!a.linux_user.contains("alice"));
        assert_eq!(a.home_dir, format!("/home/{}", a.linux_user));
        // And it must survive the panel's own validation.
        assert!(LinuxUser::parse(&a.linux_user).is_ok());
    }

    #[tokio::test]
    async fn the_default_subscription_is_created_once_and_then_reused() {
        let (db, alice, _) = seed().await;
        let first = db.default_subscription_for(alice).await.unwrap();
        let second = db.default_subscription_for(alice).await.unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(
            db.subscriptions(&TenantScope::Global)
                .list(100, 0)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_suspended_subscription_is_not_reused_as_the_default() {
        let (db, alice, _) = seed().await;
        let first = db.default_subscription_for(alice).await.unwrap();
        db.set_subscription_status(first.id, SubscriptionStatus::Suspended, Some("unpaid"))
            .await
            .unwrap();

        let second = db.default_subscription_for(alice).await.unwrap();
        assert_ne!(second.id, first.id);
        assert!(second.status.can_serve());
    }

    #[tokio::test]
    async fn suspension_stamps_a_clock_and_reinstatement_clears_it() {
        // The delete grace period (spec §6.4) counts from `suspended_at`, so a
        // subscription that was suspended, reinstated and suspended again must
        // carry the *latest* suspension time and an active one must carry none.
        let (db, alice, _) = seed().await;
        let sub = db.create_subscription(alice).await.unwrap();
        assert!(sub.suspended_at.is_none());

        db.set_subscription_status(sub.id, SubscriptionStatus::Suspended, Some("unpaid"))
            .await
            .unwrap();
        let suspended = db
            .subscriptions(&TenantScope::Global)
            .by_id(sub.id)
            .await
            .unwrap()
            .unwrap();
        assert!(suspended.suspended_at.is_some());
        assert_eq!(suspended.suspended_reason.as_deref(), Some("unpaid"));

        db.set_subscription_status(sub.id, SubscriptionStatus::Active, None)
            .await
            .unwrap();
        let reinstated = db
            .subscriptions(&TenantScope::Global)
            .by_id(sub.id)
            .await
            .unwrap()
            .unwrap();
        assert!(reinstated.suspended_at.is_none(), "no stale clock");
        assert!(reinstated.suspended_reason.is_none());
    }

    #[tokio::test]
    async fn lookup_by_linux_user_is_how_the_agent_maps_a_pool_back_to_a_tenant() {
        let (db, alice, _) = seed().await;
        let sub = db.create_subscription(alice).await.unwrap();
        let found = db
            .subscription_by_linux_user(&sub.linux_user)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, sub.id);
        assert!(
            db.subscription_by_linux_user("ft_nobody1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn one_customer_cannot_see_another_customers_subscription() {
        let (db, alice, bobby) = seed().await;
        let mine = db.create_subscription(alice).await.unwrap();
        let theirs = db.create_subscription(bobby).await.unwrap();

        let scope = TenantScope::Customer { customer_id: alice };
        assert!(
            db.subscriptions(&scope)
                .by_id(mine.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            db.subscriptions(&scope)
                .by_id(theirs.id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db.subscriptions(&scope).list(100, 0).await.unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn a_reseller_sees_its_own_customers_subscriptions_only() {
        let db = Db::open_memory().await.unwrap();
        let mk = |name: &'static str, reseller: Option<UserId>, role: Role| NewUser {
            role,
            email: Email::parse(&format!("{name}@example.com")).unwrap(),
            username: Username::parse(name).unwrap(),
            password: "a-long-enough-password".into(),
            reseller_id: reseller,
            full_name: None,
            locale: "en".into(),
        };
        let global = TenantScope::Global;
        let reseller = db
            .users(&global)
            .create(mk("reseller", None, Role::Reseller))
            .await
            .unwrap();
        let mine = db
            .users(&global)
            .create(mk("mine", Some(reseller.id), Role::Customer))
            .await
            .unwrap();
        let theirs = db
            .users(&global)
            .create(mk("theirs", None, Role::Customer))
            .await
            .unwrap();

        let mine_sub = db.create_subscription(mine.id).await.unwrap();
        let theirs_sub = db.create_subscription(theirs.id).await.unwrap();

        let scope = TenantScope::Reseller {
            reseller_id: reseller.id,
        };
        assert!(
            db.subscriptions(&scope)
                .by_id(mine_sub.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            db.subscriptions(&scope)
                .by_id(theirs_sub.id)
                .await
                .unwrap()
                .is_none(),
            "a reseller must not reach a customer it does not own"
        );
        assert_eq!(
            db.subscriptions(&scope).list(100, 0).await.unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn a_customer_with_sites_cannot_be_deleted_out_from_under_them() {
        let (db, alice, _) = seed().await;
        db.create_subscription(alice).await.unwrap();
        // ON DELETE RESTRICT: removing the owner would orphan a Linux account
        // and a home directory full of somebody's files.
        let err = sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(alice.get())
            .execute(db.pool())
            .await;
        assert!(err.is_err());
    }
}
