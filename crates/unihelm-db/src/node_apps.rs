//! Tenant Node.js applications and the port allocator (spec §11.6).
//!
//! The interesting part of this module is the **port allocator**, because it is
//! the one piece of state that is shared across every tenant on the server.
//!
//! Two invariants:
//!
//! 1. **A port is never handed out twice.** The reverse-proxy vhost names the
//!    port before the app has ever started, so "bind and see what you get" is
//!    not available to us; the number has to be decided up front. Two apps
//!    created concurrently must therefore not be able to compute the same
//!    answer — and `port INTEGER NOT NULL UNIQUE` means that even if they do,
//!    exactly one insert survives and the other retries. The allocation
//!    happens *inside* the INSERT for that reason, not as a read-then-write.
//! 2. **Ports are reused after deletion.** The range is 5001 wide, and a panel
//!    that leaked one number per deleted app would exhaust it after 5001
//!    create/delete cycles — on a box that might be hosting three apps.
//!    Allocation therefore takes the smallest free port in the range, which is
//!    the same shape as [`crate::quota`]'s XFS project ids and for the same
//!    reason.
//!
//! The one cost of reuse is that a port freshly freed can be handed to another
//! tenant while a stale client is still trying to reach it. That is a
//! connection to a local port on a machine both tenants already share, and the
//! app on the other end is a different HTTP server that will answer 404 — no
//! data crosses, and the alternative (never reusing) breaks the panel outright
//! once the range is walked.

use serde::{Deserialize, Serialize};
use unihelm_core::{AppName, SiteId, SubscriptionId, TenantPath, TenantScope};

use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// The tenant app port range (spec §11.6: "port auto-allocated" from a managed
/// range). Above the registered-service crowd, far below the ephemeral range
/// Linux allocates outbound sockets from (`net.ipv4.ip_local_port_range`
/// defaults to 32768–60999), so a tenant app and an outgoing connection can
/// never collide.
pub const APP_PORT_MIN: i64 = 20_000;
pub const APP_PORT_MAX: i64 = 25_000;

/// `NODE_ENV`, as an enum rather than a string: it is rendered into a systemd
/// `Environment=` line, and the set of values that mean anything to a Node
/// process is this small.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeEnv {
    /// The default: what a hosted app should almost always run as.
    #[default]
    Production,
    Development,
    Test,
}

impl NodeEnv {
    pub const fn as_str(self) -> &'static str {
        match self {
            NodeEnv::Production => "production",
            NodeEnv::Development => "development",
            NodeEnv::Test => "test",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "production" => NodeEnv::Production,
            "development" => NodeEnv::Development,
            "test" => NodeEnv::Test,
            other => {
                return Err(DbError::Corrupt {
                    field: "node_apps.node_env",
                    detail: format!("unknown NODE_ENV `{other}`"),
                });
            }
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeApp {
    pub id: i64,
    pub subscription_id: SubscriptionId,
    pub site_id: Option<SiteId>,
    pub name: String,
    pub entry: String,
    pub port: i64,
    pub node_env: NodeEnv,
    /// The runtime version this app is pinned to, e.g. `22.11.0`.
    ///
    /// `None` means whatever a bare `node` resolves to, which is what every app
    /// created before pinning existed means — and still the right default for
    /// somebody who has only one Node installed.
    pub runtime_version: Option<String>,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NodeAppRow {
    pub id: i64,
    pub subscription_id: i64,
    pub site_id: Option<i64>,
    pub name: String,
    pub entry: String,
    pub port: i64,
    pub node_env: String,
    pub runtime_version: Option<String>,
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<NodeAppRow> for NodeApp {
    type Error = DbError;

    fn try_from(r: NodeAppRow) -> Result<Self> {
        Ok(NodeApp {
            id: r.id,
            subscription_id: SubscriptionId(r.subscription_id),
            site_id: r.site_id.map(SiteId),
            name: r.name,
            entry: r.entry,
            port: r.port,
            node_env: NodeEnv::parse(&r.node_env)?,
            runtime_version: r.runtime_version,
            enabled: r.enabled != 0,
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

/// What is needed to create an app. The port is deliberately absent: it is
/// allocated by the insert, not chosen by a caller.
#[derive(Debug, Clone)]
pub struct NewNodeApp {
    pub subscription_id: SubscriptionId,
    pub name: AppName,
    pub entry: TenantPath,
    pub node_env: NodeEnv,
    /// Pin to a specific installed version, or `None` for the default one.
    pub runtime_version: Option<String>,
}

pub struct NodeAppRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn node_apps(&self, scope: &TenantScope) -> NodeAppRepo<'_> {
        NodeAppRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    /// Create an app, allocating it the smallest free port in the managed
    /// range.
    ///
    /// Not scoped: the caller has already resolved the subscription through
    /// their own scope (same contract as [`Db::create_site`]).
    pub async fn create_node_app(&self, new: NewNodeApp) -> Result<NodeApp> {
        self.create_node_app_in_range(new, APP_PORT_MIN, APP_PORT_MAX)
            .await
    }

    /// The same, over an explicit port range.
    ///
    /// A test seam: exercising exhaustion against the real 5001-wide range
    /// would mean inserting five thousand rows to assert one error message.
    /// The range is a parameter rather than a global so tests can run in
    /// parallel, each in its own slice of the space.
    pub async fn create_node_app_in_range(
        &self,
        new: NewNodeApp,
        min_port: i64,
        max_port: i64,
    ) -> Result<NodeApp> {
        let ts = to_sql_time(now());

        // Bounded retry, like `create_subscription`'s user-name loop: each
        // collision means another writer took the candidate between our SELECT
        // and our INSERT, and a handful of rounds settles any realistic race.
        // Looping forever would turn a systematic problem (a corrupted index,
        // say) into a hung task.
        for _ in 0..8 {
            let result = sqlx::query_as::<_, NodeAppRow>(
                // Smallest free port at or above `min_port`. The seed row in
                // the UNION covers both the empty table and the case where the
                // lowest port itself was freed by a deleted app.
                "INSERT INTO node_apps
                     (subscription_id, site_id, name, entry, port, node_env,
                      runtime_version, enabled, created_at, updated_at)
                 SELECT ?1, NULL, ?2, ?3, MIN(candidate), ?4, ?8, 1, ?5, ?5 FROM (
                     SELECT ?6 AS candidate
                     UNION ALL
                     SELECT port + 1 FROM node_apps WHERE port >= ?6
                 )
                 WHERE candidate NOT IN (SELECT port FROM node_apps)
                   AND candidate <= ?7
                 RETURNING *",
            )
            .bind(new.subscription_id.get())
            .bind(new.name.as_str())
            .bind(new.entry.as_str())
            .bind(new.node_env.as_str())
            .bind(&ts)
            .bind(min_port)
            .bind(max_port)
            .bind(new.runtime_version.as_deref())
            .fetch_one(self.pool())
            .await;

            match result {
                Ok(row) => return NodeApp::try_from(row),
                Err(sqlx::Error::Database(e)) => {
                    let message = e.message().to_string();

                    // An aggregate query without GROUP BY always yields one
                    // row, so a range with nothing free does not come back
                    // empty: `MIN()` of no rows is NULL, and NOT NULL turns
                    // that into this. Reporting it as a conflict is what makes
                    // exhaustion legible instead of "database error".
                    if message.contains("NOT NULL constraint failed: node_apps.port") {
                        return Err(DbError::Conflict {
                            what: "node app port (the managed range is exhausted)",
                        });
                    }
                    if message.contains("UNIQUE constraint failed") {
                        // Two writers computed the same port: retry, and let
                        // the second attempt see the first one's row. A name
                        // collision must NOT retry — it would spin eight times
                        // and then report a port problem for a name problem.
                        if message.contains("node_apps.port") {
                            continue;
                        }
                        return Err(DbError::Conflict {
                            what: "an app of that name",
                        });
                    }
                    return Err(sqlx::Error::Database(e).into());
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(DbError::Conflict {
            what: "node app port",
        })
    }

    /// Point an app at the reverse-proxy site published in front of it.
    pub async fn set_node_app_site(&self, id: i64, site_id: Option<SiteId>) -> Result<()> {
        sqlx::query("UPDATE node_apps SET site_id = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(id)
            .bind(site_id.map(|s| s.get()))
            .bind(to_sql_time(now()))
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// How many apps count against a subscription's plan (spec §6.2
    /// `nodejs_app_count`).
    pub async fn node_app_count(&self, subscription_id: SubscriptionId) -> Result<i64> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM node_apps WHERE subscription_id = ?1")
                .bind(subscription_id.get())
                .fetch_one(self.pool())
                .await?;
        Ok(count)
    }
}

impl NodeAppRepo<'_> {
    pub async fn by_id(&self, id: i64) -> Result<Option<NodeApp>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, NodeAppRow>("SELECT * FROM node_apps WHERE id = ?1")
                    .bind(id)
                    .fetch_optional(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, NodeAppRow>(
                    "SELECT a.* FROM node_apps a
                     JOIN subscriptions sub ON sub.id = a.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE a.id = ?1 AND u.reseller_id = ?2",
                )
                .bind(id)
                .bind(reseller_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, NodeAppRow>(
                    "SELECT a.* FROM node_apps a
                     JOIN subscriptions sub ON sub.id = a.subscription_id
                     WHERE a.id = ?1 AND sub.customer_id = ?2",
                )
                .bind(id)
                .bind(customer_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, NodeAppRow>(
                    "SELECT * FROM node_apps WHERE id = ?1 AND subscription_id = ?2",
                )
                .bind(id)
                .bind(subscription_id)
                .fetch_optional(self.db.pool())
                .await?
            }
        };
        row.map(NodeApp::try_from).transpose()
    }

    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<NodeApp>> {
        let limit = limit.clamp(1, 500);
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, NodeAppRow>(
                    "SELECT * FROM node_apps ORDER BY name ASC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, NodeAppRow>(
                    "SELECT a.* FROM node_apps a
                     JOIN subscriptions sub ON sub.id = a.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE u.reseller_id = ?1 ORDER BY a.name ASC LIMIT ?2 OFFSET ?3",
                )
                .bind(reseller_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, NodeAppRow>(
                    "SELECT a.* FROM node_apps a
                     JOIN subscriptions sub ON sub.id = a.subscription_id
                     WHERE sub.customer_id = ?1 ORDER BY a.name ASC LIMIT ?2 OFFSET ?3",
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
                sqlx::query_as::<_, NodeAppRow>(
                    "SELECT * FROM node_apps WHERE subscription_id = ?1
                     ORDER BY name ASC LIMIT ?2 OFFSET ?3",
                )
                .bind(subscription_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(NodeApp::try_from).collect()
    }

    /// Delete an app, returning the row that was removed.
    ///
    /// Scoped through [`Self::by_id`], so a tenant cannot delete an app they
    /// cannot see — and the port comes back to the allocator with the row.
    pub async fn delete(&self, id: i64) -> Result<NodeApp> {
        let app = self
            .by_id(id)
            .await?
            .ok_or(DbError::NotFound { what: "node app" })?;
        sqlx::query("DELETE FROM node_apps WHERE id = ?1")
            .bind(id)
            .execute(self.db.pool())
            .await?;
        Ok(app)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::NewUser;
    use unihelm_core::{Email, Role, UserId, Username};

    async fn seed() -> (Db, SubscriptionId, SubscriptionId, UserId, UserId) {
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
        let sa = db.create_subscription(a.id).await.unwrap();
        let sb = db.create_subscription(b.id).await.unwrap();
        (db, sa.id, sb.id, a.id, b.id)
    }

    fn app(sub: SubscriptionId, name: &str) -> NewNodeApp {
        NewNodeApp {
            subscription_id: sub,
            name: AppName::parse(name).unwrap(),
            entry: TenantPath::parse(&format!("apps/{name}/server.js")).unwrap(),
            node_env: NodeEnv::Production,
            runtime_version: None,
        }
    }

    #[tokio::test]
    async fn the_first_app_gets_the_bottom_of_the_range() {
        let (db, sub, ..) = seed().await;
        let created = db.create_node_app(app(sub, "blog")).await.unwrap();
        assert_eq!(created.port, APP_PORT_MIN);
        assert_eq!(created.node_env, NodeEnv::Production);
        assert!(
            created.enabled,
            "a new app is enabled; it is about to start"
        );
        assert!(created.site_id.is_none());
    }

    #[tokio::test]
    async fn ports_are_handed_out_in_order_and_never_twice() {
        // The vhost names the port before the app has run, so two apps sharing
        // one would mean one of them is permanently unreachable behind the
        // other's proxy.
        let (db, mine, theirs, ..) = seed().await;
        let a = db.create_node_app(app(mine, "one")).await.unwrap();
        let b = db.create_node_app(app(mine, "two")).await.unwrap();
        // Across tenants too: the range is server-wide, not per-subscription.
        let c = db.create_node_app(app(theirs, "one")).await.unwrap();

        assert_eq!(
            (a.port, b.port, c.port),
            (APP_PORT_MIN, APP_PORT_MIN + 1, APP_PORT_MIN + 2)
        );
    }

    #[tokio::test]
    async fn a_deleted_apps_port_is_handed_to_the_next_app() {
        // Without reuse, 5001 create/delete cycles exhaust the range on a box
        // that is hosting three apps.
        let (db, sub, ..) = seed().await;
        let first = db.create_node_app(app(sub, "one")).await.unwrap();
        let second = db.create_node_app(app(sub, "two")).await.unwrap();
        assert_eq!(second.port, first.port + 1);

        db.node_apps(&TenantScope::Global)
            .delete(first.id)
            .await
            .unwrap();

        let third = db.create_node_app(app(sub, "three")).await.unwrap();
        assert_eq!(
            third.port, first.port,
            "the freed port must come back to the allocator"
        );

        // And the still-live app keeps its own.
        let fourth = db.create_node_app(app(sub, "four")).await.unwrap();
        assert_eq!(fourth.port, second.port + 1);
    }

    #[tokio::test]
    async fn an_exhausted_range_is_refused_with_a_conflict_not_a_duplicate_port() {
        // Three ports, three apps, then no more. The failure has to be a clean
        // refusal: a fourth app quietly sharing port 20000 would look fine in
        // the panel and 502 in production.
        let (db, sub, ..) = seed().await;
        for (i, name) in ["one", "two", "three"].iter().enumerate() {
            let created = db
                .create_node_app_in_range(app(sub, name), 20_000, 20_002)
                .await
                .unwrap();
            assert_eq!(created.port, 20_000 + i as i64);
        }

        let err = db
            .create_node_app_in_range(app(sub, "four"), 20_000, 20_002)
            .await
            .unwrap_err();
        match err {
            DbError::Conflict { what } => assert!(what.contains("exhausted"), "{what}"),
            other => panic!("expected a conflict, got {other:?}"),
        }

        // Freeing one lets the next app in, so exhaustion is a state, not a
        // one-way door.
        let freed = db
            .node_apps(&TenantScope::Global)
            .list(10, 0)
            .await
            .unwrap()[0]
            .id;
        db.node_apps(&TenantScope::Global)
            .delete(freed)
            .await
            .unwrap();
        assert!(
            db.create_node_app_in_range(app(sub, "four"), 20_000, 20_002)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_port_outside_the_managed_range_cannot_be_stored_at_all() {
        // The CHECK is the second line of defence behind the allocator: an app
        // on port 22 or 443 would be a hosting incident, not a bug report.
        let (db, sub, ..) = seed().await;
        for port in [22, 443, 19_999, 25_001, 65_535] {
            let bad = sqlx::query(
                "INSERT INTO node_apps
                     (subscription_id, name, entry, port, node_env, created_at, updated_at)
                 VALUES (?1, 'x', 'apps/x/server.js', ?2, 'production',
                         '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            )
            .bind(sub.get())
            .bind(port)
            .execute(db.pool())
            .await;
            assert!(bad.is_err(), "port {port} must not be storable");
        }
    }

    #[tokio::test]
    async fn one_tenant_may_reuse_a_name_another_tenant_already_took() {
        let (db, mine, theirs, ..) = seed().await;
        db.create_node_app(app(mine, "blog")).await.unwrap();
        assert!(
            db.create_node_app(app(theirs, "blog")).await.is_ok(),
            "names are per tenant; the unit name carries the Linux user"
        );
    }

    #[tokio::test]
    async fn the_same_tenant_cannot_have_two_apps_of_one_name() {
        // The unit name is derived from (linux_user, name), so a duplicate
        // would be two rows fighting over one unit file.
        let (db, sub, ..) = seed().await;
        db.create_node_app(app(sub, "blog")).await.unwrap();
        let err = db.create_node_app(app(sub, "blog")).await.unwrap_err();
        match err {
            DbError::Conflict { what } => assert!(what.contains("name"), "{what}"),
            other => panic!("expected a name conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn one_tenant_can_neither_see_nor_delete_anothers_app() {
        let (db, mine, theirs, alice, _bobby) = seed().await;
        let victim = db.create_node_app(app(theirs, "victim")).await.unwrap();
        db.create_node_app(app(mine, "mine")).await.unwrap();

        let intruder = TenantScope::Customer { customer_id: alice };
        assert!(
            db.node_apps(&intruder)
                .by_id(victim.id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(db.node_apps(&intruder).list(100, 0).await.unwrap().len(), 1);
        assert!(matches!(
            db.node_apps(&intruder).delete(victim.id).await,
            Err(DbError::NotFound { .. })
        ));

        // Untouched, and still holding its port.
        assert!(
            db.node_apps(&TenantScope::Global)
                .by_id(victim.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn deleting_the_proxy_site_leaves_the_app_alive_and_unpublished() {
        // ON DELETE SET NULL, not CASCADE: removing the vhost unpublishes the
        // app; it must not delete the tenant's application.
        use crate::sites::{NewSite, SiteType};
        let (db, sub, ..) = seed().await;
        let created = db.create_node_app(app(sub, "blog")).await.unwrap();
        let site = db
            .create_site(NewSite {
                subscription_id: sub,
                domain: unihelm_core::Domain::parse("blog.example.com").unwrap(),
                site_type: SiteType::Proxy,
                php_version: None,
                root_dir: "/home/uh_x/apps/blog".into(),
                proxy_port: Some(created.port as u16),
                redirect_target: None,
            })
            .await
            .unwrap();
        db.set_node_app_site(created.id, Some(site.id))
            .await
            .unwrap();

        db.sites(&TenantScope::Global)
            .delete(site.id)
            .await
            .unwrap();

        let after = db
            .node_apps(&TenantScope::Global)
            .by_id(created.id)
            .await
            .unwrap()
            .expect("the app must survive its vhost");
        assert_eq!(after.site_id, None);
        assert_eq!(after.port, created.port);
    }

    #[tokio::test]
    async fn the_plan_counter_counts_only_this_subscriptions_apps() {
        let (db, mine, theirs, ..) = seed().await;
        db.create_node_app(app(mine, "one")).await.unwrap();
        db.create_node_app(app(mine, "two")).await.unwrap();
        db.create_node_app(app(theirs, "one")).await.unwrap();

        assert_eq!(db.node_app_count(mine).await.unwrap(), 2);
        assert_eq!(db.node_app_count(theirs).await.unwrap(), 1);
    }

    #[test]
    fn node_env_round_trips_and_refuses_anything_else() {
        for env in [NodeEnv::Production, NodeEnv::Development, NodeEnv::Test] {
            assert_eq!(NodeEnv::parse(env.as_str()).unwrap(), env);
        }
        assert!(NodeEnv::parse("prod").is_err());
        // It reaches a systemd Environment= line, so it can never be free text.
        assert!(serde_json::from_str::<NodeEnv>("\"production\"").is_ok());
        assert!(serde_json::from_str::<NodeEnv>("\"x\\nExecStart=/bin/sh\"").is_err());
    }
}
