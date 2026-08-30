//! The WordPress toolkit's inventory (spec §11.12).
//!
//! A `wp_installs` row is the panel's *bookkeeping* about an install, never its
//! state. WordPress's own truth is `wp-config.php` and the database behind it,
//! and WP-CLI can read every bit of it; duplicating any of that here would
//! create a second copy that drifts. So the row holds only what cannot be
//! re-derived: which site the install belongs to, where its files are, which
//! managed database backs it, and whether the operator asked for unattended
//! core updates.
//!
//! **Scoping goes through the site, always.** Every read here joins
//! `sites` → `subscriptions` (→ `users` for a reseller) exactly the way
//! [`crate::sites::SiteRepo`] does, so an install id that belongs to another
//! tenant is `Ok(None)` — indistinguishable from an id that does not exist.
//! There is no unscoped `by_id`; the only unscoped entry points are the
//! writers, which take an id the caller has already resolved through a scoped
//! read (the same contract [`Db::create_site`] and [`Db::create_node_app`]
//! use).

use serde::Serialize;
use unihelm_core::{SiteId, TenantScope};

use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// One WordPress installation the panel manages.
#[derive(Debug, Clone, Serialize)]
pub struct WpInstall {
    pub id: i64,
    pub site_id: SiteId,
    /// Absolute directory holding `wp-config.php`. Panel-derived, never
    /// caller-supplied.
    pub path: String,
    /// Last observed core version; `None` until something has looked.
    pub version: Option<String>,
    /// The managed database backing the install, if the panel created one.
    pub db_id: Option<i64>,
    pub auto_update: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WpInstallRow {
    pub id: i64,
    pub site_id: i64,
    pub path: String,
    pub version: Option<String>,
    pub db_id: Option<i64>,
    pub auto_update: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<WpInstallRow> for WpInstall {
    type Error = DbError;

    fn try_from(r: WpInstallRow) -> Result<Self> {
        Ok(WpInstall {
            id: r.id,
            site_id: SiteId(r.site_id),
            path: r.path,
            version: r.version,
            db_id: r.db_id,
            auto_update: r.auto_update != 0,
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

/// What recording a new install needs.
#[derive(Debug, Clone)]
pub struct NewWpInstall {
    pub site_id: SiteId,
    pub path: String,
    pub version: Option<String>,
    pub db_id: Option<i64>,
    pub auto_update: bool,
}

pub struct WpInstallRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn wp_installs(&self, scope: &TenantScope) -> WpInstallRepo<'_> {
        WpInstallRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    /// Record an install.
    ///
    /// Unscoped by design: the caller resolved `site_id` through their own
    /// scope to get here, and a second filter would only be able to disagree
    /// with the first. The UNIQUE index on `path` is what makes a concurrent
    /// double-install resolve to exactly one row.
    pub async fn create_wp_install(&self, new: NewWpInstall) -> Result<WpInstall> {
        let ts = to_sql_time(now());
        let result = sqlx::query_as::<_, WpInstallRow>(
            "INSERT INTO wp_installs
                 (site_id, path, version, db_id, auto_update, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             RETURNING *",
        )
        .bind(new.site_id.get())
        .bind(&new.path)
        .bind(&new.version)
        .bind(new.db_id)
        .bind(i64::from(new.auto_update))
        .bind(&ts)
        .fetch_one(self.pool())
        .await;

        match result {
            Ok(row) => WpInstall::try_from(row),
            Err(sqlx::Error::Database(e)) if e.message().contains("UNIQUE constraint failed") => {
                Err(DbError::Conflict {
                    what: "a WordPress install in that directory",
                })
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Cache the version WP-CLI just reported.
    ///
    /// Separate from [`Db::set_wp_auto_update`] because the two writes have
    /// different authors: this one is a side effect of *reading* the install,
    /// and must never touch a policy the operator set.
    pub async fn set_wp_version(&self, id: i64, version: &str) -> Result<()> {
        sqlx::query("UPDATE wp_installs SET version = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(id)
            .bind(version)
            .bind(to_sql_time(now()))
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Set the unattended-core-update policy for one install.
    pub async fn set_wp_auto_update(&self, id: i64, auto_update: bool) -> Result<()> {
        sqlx::query("UPDATE wp_installs SET auto_update = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(id)
            .bind(i64::from(auto_update))
            .bind(to_sql_time(now()))
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Every install with unattended updates switched on, across all tenants.
    ///
    /// Unscoped on purpose: its only caller is the scheduler, which acts as the
    /// system and is not a tenant (spec §11.12's "auto-update policy per site").
    pub async fn wp_installs_with_auto_update(&self) -> Result<Vec<WpInstall>> {
        let rows = sqlx::query_as::<_, WpInstallRow>(
            "SELECT * FROM wp_installs WHERE auto_update = 1 ORDER BY id ASC",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(WpInstall::try_from).collect()
    }
}

impl WpInstallRepo<'_> {
    /// One install, or `None` when it does not exist **or** is outside the
    /// caller's scope. The two are indistinguishable on purpose: a customer
    /// probing ids must not be able to tell which of the two they hit.
    pub async fn by_id(&self, id: i64) -> Result<Option<WpInstall>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, WpInstallRow>("SELECT * FROM wp_installs WHERE id = ?1")
                    .bind(id)
                    .fetch_optional(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, WpInstallRow>(
                    "SELECT w.* FROM wp_installs w
                     JOIN sites s ON s.id = w.site_id
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE w.id = ?1 AND u.reseller_id = ?2",
                )
                .bind(id)
                .bind(reseller_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, WpInstallRow>(
                    "SELECT w.* FROM wp_installs w
                     JOIN sites s ON s.id = w.site_id
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     WHERE w.id = ?1 AND sub.customer_id = ?2",
                )
                .bind(id)
                .bind(customer_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, WpInstallRow>(
                    "SELECT w.* FROM wp_installs w
                     JOIN sites s ON s.id = w.site_id
                     WHERE w.id = ?1 AND s.subscription_id = ?2",
                )
                .bind(id)
                .bind(subscription_id)
                .fetch_optional(self.db.pool())
                .await?
            }
        };
        row.map(WpInstall::try_from).transpose()
    }

    /// The install recorded for one site, if any. Scoped through the same
    /// joins as [`Self::by_id`], so naming another tenant's site id answers
    /// `None`.
    pub async fn by_site(&self, site_id: SiteId) -> Result<Option<WpInstall>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, WpInstallRow>("SELECT * FROM wp_installs WHERE site_id = ?1")
                    .bind(site_id.get())
                    .fetch_optional(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, WpInstallRow>(
                    "SELECT w.* FROM wp_installs w
                     JOIN sites s ON s.id = w.site_id
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE w.site_id = ?1 AND u.reseller_id = ?2",
                )
                .bind(site_id.get())
                .bind(reseller_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, WpInstallRow>(
                    "SELECT w.* FROM wp_installs w
                     JOIN sites s ON s.id = w.site_id
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     WHERE w.site_id = ?1 AND sub.customer_id = ?2",
                )
                .bind(site_id.get())
                .bind(customer_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, WpInstallRow>(
                    "SELECT w.* FROM wp_installs w
                     JOIN sites s ON s.id = w.site_id
                     WHERE w.site_id = ?1 AND s.subscription_id = ?2",
                )
                .bind(site_id.get())
                .bind(subscription_id)
                .fetch_optional(self.db.pool())
                .await?
            }
        };
        row.map(WpInstall::try_from).transpose()
    }

    /// Every install this scope can see, newest last.
    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<WpInstall>> {
        let limit = limit.clamp(1, 500);
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, WpInstallRow>(
                    "SELECT * FROM wp_installs ORDER BY id ASC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, WpInstallRow>(
                    "SELECT w.* FROM wp_installs w
                     JOIN sites s ON s.id = w.site_id
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE u.reseller_id = ?3
                     ORDER BY w.id ASC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .bind(reseller_id)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, WpInstallRow>(
                    "SELECT w.* FROM wp_installs w
                     JOIN sites s ON s.id = w.site_id
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     WHERE sub.customer_id = ?3
                     ORDER BY w.id ASC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .bind(customer_id)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, WpInstallRow>(
                    "SELECT w.* FROM wp_installs w
                     JOIN sites s ON s.id = w.site_id
                     WHERE s.subscription_id = ?3
                     ORDER BY w.id ASC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .bind(subscription_id)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(WpInstall::try_from).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sites::{NewSite, SiteType};
    use crate::users::NewUser;
    use unihelm_core::{Domain, Email, Role, SubscriptionId, UserId, Username};

    /// One reseller, two customers under it, a subscription and a site each,
    /// and a recorded WordPress install on each site.
    struct Fixture {
        db: Db,
        mine: i64,
        theirs: i64,
        my_site: SiteId,
        my_customer: UserId,
        my_subscription: SubscriptionId,
        my_reseller: UserId,
    }

    async fn user(db: &Db, name: &str, reseller: Option<UserId>, role: Role) -> UserId {
        db.users(&TenantScope::Global)
            .create(NewUser {
                role,
                email: Email::parse(&format!("{name}@example.com")).unwrap(),
                username: Username::parse(name).unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: reseller,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .expect("user created")
            .id
    }

    async fn fixture() -> Fixture {
        let db = Db::open_memory().await.unwrap();
        let reseller = user(&db, "reseller", None, Role::Reseller).await;
        let mine_user = user(&db, "mine", Some(reseller), Role::Customer).await;
        let theirs_user = user(&db, "theirs", Some(reseller), Role::Customer).await;

        let my_sub = db.create_subscription(mine_user).await.unwrap();
        let their_sub = db.create_subscription(theirs_user).await.unwrap();

        let my_site = site(&db, my_sub.id, "mine.example").await;
        let their_site = site(&db, their_sub.id, "theirs.example").await;

        let mine = record(&db, my_site, "/home/uh_mine/sites/mine.example/public").await;
        let theirs = record(
            &db,
            their_site,
            "/home/uh_theirs/sites/theirs.example/public",
        )
        .await;

        Fixture {
            db,
            mine,
            theirs,
            my_site,
            my_customer: mine_user,
            my_subscription: my_sub.id,
            my_reseller: reseller,
        }
    }

    async fn site(db: &Db, subscription_id: SubscriptionId, domain: &str) -> SiteId {
        db.create_site(NewSite {
            subscription_id,
            domain: Domain::parse(domain).unwrap(),
            site_type: SiteType::Static,
            php_version: None,
            root_dir: format!("/home/x/sites/{domain}/public"),
            proxy_port: None,
            redirect_target: None,
        })
        .await
        .expect("site created")
        .id
    }

    async fn record(db: &Db, site_id: SiteId, path: &str) -> i64 {
        db.create_wp_install(NewWpInstall {
            site_id,
            path: path.into(),
            version: None,
            db_id: None,
            auto_update: false,
        })
        .await
        .expect("install recorded")
        .id
    }

    /// The containment claim, stated as a test: an install id that exists but
    /// belongs to another customer answers exactly like one that never
    /// existed. `wp.*` turns both into `not_found`, so a caller enumerating
    /// ids learns nothing from the difference.
    #[tokio::test]
    async fn another_customers_install_is_indistinguishable_from_a_missing_one() {
        let f = fixture().await;
        let scope = TenantScope::Customer {
            customer_id: f.my_customer,
        };
        let repo = f.db.wp_installs(&scope);

        assert!(repo.by_id(f.mine).await.unwrap().is_some());
        assert!(repo.by_id(f.theirs).await.unwrap().is_none());
        assert!(repo.by_id(999_999).await.unwrap().is_none());
    }

    /// The same containment through the other lookup key: naming a site id is
    /// no way around naming an install id.
    #[tokio::test]
    async fn by_site_is_scoped_the_same_way_as_by_id() {
        let f = fixture().await;
        let theirs_site =
            f.db.wp_installs(&TenantScope::Global)
                .by_id(f.theirs)
                .await
                .unwrap()
                .unwrap()
                .site_id;

        let scope = TenantScope::Customer {
            customer_id: f.my_customer,
        };
        assert!(
            f.db.wp_installs(&scope)
                .by_site(f.my_site)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            f.db.wp_installs(&scope)
                .by_site(theirs_site)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_subscription_scope_sees_only_its_own_installs() {
        let f = fixture().await;
        let scope = TenantScope::Subscription {
            subscription_id: f.my_subscription,
            customer_id: f.my_customer,
        };
        let listed = f.db.wp_installs(&scope).list(100, 0).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, f.mine);
        assert!(
            f.db.wp_installs(&scope)
                .by_id(f.theirs)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A reseller sees both of their customers; an admin sees everybody. The
    /// reseller join is the one with three hops, so it gets its own assertion.
    #[tokio::test]
    async fn a_reseller_sees_both_of_their_customers_and_an_admin_sees_all() {
        let f = fixture().await;
        let reseller_view =
            f.db.wp_installs(&TenantScope::Reseller {
                reseller_id: f.my_reseller,
            })
            .list(100, 0)
            .await
            .unwrap();
        assert_eq!(reseller_view.len(), 2);

        let admin_view =
            f.db.wp_installs(&TenantScope::Global)
                .list(100, 0)
                .await
                .unwrap();
        assert_eq!(admin_view.len(), 2);
    }

    /// The path index is what stops two rows describing one `wp-config.php`,
    /// which would let two update policies fight over the same files.
    #[tokio::test]
    async fn a_second_install_in_the_same_directory_is_a_conflict() {
        let f = fixture().await;
        let err =
            f.db.create_wp_install(NewWpInstall {
                site_id: f.my_site,
                path: "/home/uh_mine/sites/mine.example/public".into(),
                version: None,
                db_id: None,
                auto_update: false,
            })
            .await
            .expect_err("the path is already taken");
        assert!(matches!(err, DbError::Conflict { .. }), "{err:?}");
    }

    /// `ON DELETE CASCADE` on `site_id`: an install row whose site is gone
    /// could no longer be scoped to anybody, so it must not survive.
    #[tokio::test]
    async fn deleting_a_site_takes_its_install_row_with_it() {
        let f = fixture().await;
        f.db.sites(&TenantScope::Global)
            .delete(f.my_site)
            .await
            .expect("site deleted");
        assert!(
            f.db.wp_installs(&TenantScope::Global)
                .by_id(f.mine)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Caching a version must not disturb the operator's update policy: the
    /// two writes have different authors and different lifetimes.
    #[tokio::test]
    async fn caching_a_version_leaves_the_auto_update_policy_alone() {
        let f = fixture().await;
        f.db.set_wp_auto_update(f.mine, true).await.unwrap();
        f.db.set_wp_version(f.mine, "6.8.2").await.unwrap();

        let row =
            f.db.wp_installs(&TenantScope::Global)
                .by_id(f.mine)
                .await
                .unwrap()
                .expect("still there");
        assert_eq!(row.version.as_deref(), Some("6.8.2"));
        assert!(row.auto_update);

        let scheduled = f.db.wp_installs_with_auto_update().await.unwrap();
        assert_eq!(scheduled.len(), 1);
        assert_eq!(scheduled[0].id, f.mine);
    }
}
