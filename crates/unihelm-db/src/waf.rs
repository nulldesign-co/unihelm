//! Per-site WAF policy and the rule exclusion list (spec §11.9).
//!
//! These two tables are the entire input to the generated ModSecurity rules
//! file. Everything the panel writes into `/etc/unihelm/waf/main.conf` is a pure
//! function of what is here plus the pinned Core Rule Set, which is what makes
//! "why is rule 942100 not firing on that site" a question two SELECTs answer.
//!
//! Nothing here is tenant-scoped, for the same reason nothing in
//! [`crate::firewall`] is: ModSecurity is one host-wide engine, the operations
//! that write these rows require `Permission::ServerManage`, and inventing a
//! per-tenant view of a server-wide engine is how a customer ends up able to
//! switch off the rules protecting the box.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// What ModSecurity does with one site's traffic.
///
/// The three states are deliberately not a boolean plus a flag: "off",
/// "watching" and "enforcing" are three different answers to "what happens to
/// an attack right now", and an operator has to be able to see which one a
/// site is in without reading a second column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WafMode {
    /// ModSecurity is switched off for this site's traffic.
    Off,
    /// Rules run and log; nothing is blocked. Spec §11.9 asks for a log-only
    /// mode first, and this is it.
    Detect,
    /// The CRS anomaly score is enforced: matching requests get a 403.
    Block,
}

impl WafMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            WafMode::Off => "off",
            WafMode::Detect => "detect",
            WafMode::Block => "block",
        }
    }

    /// The `ctl:ruleEngine=` value this mode renders into.
    pub const fn rule_engine(self) -> &'static str {
        match self {
            WafMode::Off => "Off",
            WafMode::Detect => "DetectionOnly",
            WafMode::Block => "On",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "off" => Ok(WafMode::Off),
            "detect" => Ok(WafMode::Detect),
            "block" => Ok(WafMode::Block),
            other => Err(DbError::Corrupt {
                field: "waf_sites.mode",
                detail: format!("`{other}` is not a WAF mode"),
            }),
        }
    }
}

/// The CRS paranoia level: how aggressive the rule set is.
///
/// Bounded 1–4 by the schema *and* here, because an out-of-range value would
/// not fail loudly — it would set `tx.blocking_paranoia_level` to something no
/// CRS rule tests, which reads at runtime as "paranoia level 1" and would have
/// an operator believing a site is far better defended than it is.
pub const MIN_PARANOIA: i64 = 1;
pub const MAX_PARANOIA: i64 = 4;

/// The default level for a site that has not chosen one. Level 1 is the only
/// level that does not reject legitimate traffic on an application nobody has
/// tuned the rules against.
pub const DEFAULT_PARANOIA: i64 = 1;

/// One site's WAF policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WafSitePolicy {
    pub site_id: i64,
    pub mode: WafMode,
    pub paranoia_level: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// A rule the operator has decided not to run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WafExclusion {
    pub id: i64,
    /// `None` is server-wide.
    pub site_id: Option<i64>,
    pub rule_id: i64,
    pub reason: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// An exclusion on its way in, before it has an id or a timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewWafExclusion {
    #[serde(default)]
    pub site_id: Option<i64>,
    pub rule_id: i64,
    pub reason: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct WafSiteRow {
    site_id: i64,
    mode: String,
    paranoia_level: i64,
    updated_at: String,
}

impl TryFrom<WafSiteRow> for WafSitePolicy {
    type Error = DbError;

    fn try_from(r: WafSiteRow) -> Result<Self> {
        Ok(WafSitePolicy {
            site_id: r.site_id,
            mode: WafMode::parse(&r.mode)?,
            paranoia_level: r.paranoia_level,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct WafExclusionRow {
    id: i64,
    site_id: Option<i64>,
    rule_id: i64,
    reason: String,
    created_at: String,
}

impl TryFrom<WafExclusionRow> for WafExclusion {
    type Error = DbError;

    fn try_from(r: WafExclusionRow) -> Result<Self> {
        Ok(WafExclusion {
            id: r.id,
            site_id: r.site_id,
            rule_id: r.rule_id,
            reason: r.reason,
            created_at: from_sql_time(&r.created_at)?,
        })
    }
}

impl Db {
    /// Every site that has a policy of its own, ordered by site id so two
    /// renders of unchanged state produce byte-identical files — which is what
    /// lets the config engine skip the write and the nginx reload.
    pub async fn waf_site_policies(&self) -> Result<Vec<WafSitePolicy>> {
        let rows = sqlx::query_as::<_, WafSiteRow>(
            "SELECT site_id, mode, paranoia_level, updated_at \
             FROM waf_sites ORDER BY site_id",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(WafSitePolicy::try_from).collect()
    }

    pub async fn waf_site_policy(&self, site_id: i64) -> Result<Option<WafSitePolicy>> {
        let row = sqlx::query_as::<_, WafSiteRow>(
            "SELECT site_id, mode, paranoia_level, updated_at \
             FROM waf_sites WHERE site_id = ?1",
        )
        .bind(site_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(WafSitePolicy::try_from).transpose()
    }

    /// Set (or replace) one site's policy.
    ///
    /// An upsert rather than insert-or-update in the caller: two admins
    /// switching the same site on at once must end with one row and one policy,
    /// not with a unique-constraint error one of them has to interpret.
    pub async fn set_waf_site_policy(
        &self,
        site_id: i64,
        mode: WafMode,
        paranoia_level: i64,
    ) -> Result<WafSitePolicy> {
        if !(MIN_PARANOIA..=MAX_PARANOIA).contains(&paranoia_level) {
            return Err(DbError::Corrupt {
                field: "waf_sites.paranoia_level",
                detail: format!(
                    "paranoia level {paranoia_level} is outside {MIN_PARANOIA}–{MAX_PARANOIA}"
                ),
            });
        }
        let stamp = to_sql_time(now());
        sqlx::query(
            "INSERT INTO waf_sites (site_id, mode, paranoia_level, updated_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT (site_id) DO UPDATE SET \
               mode = excluded.mode, \
               paranoia_level = excluded.paranoia_level, \
               updated_at = excluded.updated_at",
        )
        .bind(site_id)
        .bind(mode.as_str())
        .bind(paranoia_level)
        .bind(&stamp)
        .execute(self.pool())
        .await?;

        self.waf_site_policy(site_id)
            .await?
            .ok_or_else(|| DbError::Corrupt {
                field: "waf_sites",
                detail: "the policy just written was not readable back".into(),
            })
    }

    /// Forget a site's policy, returning it to the server-wide default.
    pub async fn clear_waf_site_policy(&self, site_id: i64) -> Result<bool> {
        let done = sqlx::query("DELETE FROM waf_sites WHERE site_id = ?1")
            .bind(site_id)
            .execute(self.pool())
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Every exclusion, server-wide ones first. Ordered for the same
    /// byte-stability reason as [`Db::waf_site_policies`].
    pub async fn waf_exclusions(&self) -> Result<Vec<WafExclusion>> {
        let rows = sqlx::query_as::<_, WafExclusionRow>(
            "SELECT id, site_id, rule_id, reason, created_at FROM waf_exclusions \
             ORDER BY COALESCE(site_id, 0), rule_id",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(WafExclusion::try_from).collect()
    }

    /// Replace the whole exclusion list in one transaction.
    ///
    /// Wholesale replacement rather than add/remove verbs: the list is short,
    /// an operator edits it as a list, and a partial apply would leave the
    /// rendered rules file agreeing with neither the old list nor the new one.
    /// The transaction is what makes "the render always matches the table"
    /// true even if the process dies mid-write.
    ///
    /// Duplicate `(site_id, rule_id)` pairs in `wanted` are rejected by the
    /// unique index rather than silently collapsed — a caller who sent the same
    /// exclusion twice with two different reasons has a bug worth hearing about.
    pub async fn replace_waf_exclusions(
        &self,
        wanted: &[NewWafExclusion],
    ) -> Result<Vec<WafExclusion>> {
        let stamp = to_sql_time(now());
        let mut tx = self.pool().begin().await?;

        sqlx::query("DELETE FROM waf_exclusions")
            .execute(&mut *tx)
            .await?;

        for entry in wanted {
            sqlx::query(
                "INSERT INTO waf_exclusions (site_id, rule_id, reason, created_at) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(entry.site_id)
            .bind(entry.rule_id)
            .bind(&entry.reason)
            .bind(&stamp)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        self.waf_exclusions().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> Db {
        Db::open_memory().await.expect("in-memory database")
    }

    /// The WAF tables reference `sites`, so a policy needs a site to hang off.
    async fn a_site(db: &Db, domain: &str) -> i64 {
        use crate::{NewSite, SiteType};
        use unihelm_core::{Domain, Email, PhpVersion, Role, TenantScope, Username};

        let user = db
            .users(&TenantScope::Global)
            .create(crate::users::NewUser {
                role: Role::Customer,
                email: Email::parse(&format!("u-{domain}@example.com")).unwrap(),
                username: Username::parse(&domain.replace('.', "")).unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let sub = db.create_subscription(user.id).await.unwrap();
        db.create_site(NewSite {
            subscription_id: sub.id,
            domain: Domain::parse(domain).unwrap(),
            site_type: SiteType::Php,
            php_version: Some(PhpVersion::V83),
            root_dir: format!("/home/t/sites/{domain}/public"),
            proxy_port: None,
            redirect_target: None,
        })
        .await
        .unwrap()
        .id
        .get()
    }

    #[tokio::test]
    async fn a_sites_policy_is_replaced_not_duplicated_when_it_is_set_twice() {
        let db = db().await;
        let site = a_site(&db, "one.example.com").await;

        db.set_waf_site_policy(site, WafMode::Detect, 1)
            .await
            .unwrap();
        let second = db
            .set_waf_site_policy(site, WafMode::Block, 3)
            .await
            .unwrap();

        assert_eq!(second.mode, WafMode::Block);
        assert_eq!(second.paranoia_level, 3);
        assert_eq!(
            db.waf_site_policies().await.unwrap().len(),
            1,
            "two admins switching one site on must leave one policy, not two"
        );
    }

    #[tokio::test]
    async fn a_paranoia_level_outside_the_crs_range_is_refused_before_it_is_stored() {
        // The dangerous direction: a level CRS does not test reads at runtime
        // as level 1, so an operator would believe a site is defended at
        // level 9 while it runs the loosest rules there are.
        let db = db().await;
        let site = a_site(&db, "two.example.com").await;
        for level in [0, 5, 9, -1] {
            assert!(
                db.set_waf_site_policy(site, WafMode::Block, level)
                    .await
                    .is_err(),
                "paranoia level {level} must be refused"
            );
        }
        assert!(db.waf_site_policy(site).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn deleting_a_site_takes_its_waf_policy_and_exclusions_with_it() {
        // A policy for a site that no longer exists could only render into a
        // rule matching a hostname nothing serves — and a stale exclusion
        // would be a hole nobody could explain.
        let db = db().await;
        let site = a_site(&db, "gone.example.com").await;
        db.set_waf_site_policy(site, WafMode::Block, 2)
            .await
            .unwrap();
        db.replace_waf_exclusions(&[NewWafExclusion {
            site_id: Some(site),
            rule_id: 942100,
            reason: "the page editor posts SQL".into(),
        }])
        .await
        .unwrap();

        sqlx::query("DELETE FROM sites WHERE id = ?1")
            .bind(site)
            .execute(db.pool())
            .await
            .unwrap();

        assert!(db.waf_site_policies().await.unwrap().is_empty());
        assert!(db.waf_exclusions().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_same_server_wide_exclusion_cannot_be_stored_twice() {
        // Without the COALESCE in the unique index, NULL site_id values are
        // distinct from each other and this would store two rows — rendering
        // `SecRuleRemoveById 942100` twice.
        let db = db().await;
        let twice = [
            NewWafExclusion {
                site_id: None,
                rule_id: 942100,
                reason: "first".into(),
            },
            NewWafExclusion {
                site_id: None,
                rule_id: 942100,
                reason: "second".into(),
            },
        ];
        assert!(db.replace_waf_exclusions(&twice).await.is_err());
    }

    #[tokio::test]
    async fn a_failed_replacement_leaves_the_previous_exclusion_list_intact() {
        // The transaction is the point: a half-applied list would agree with
        // neither the old policy nor the new one, and the rendered rules file
        // would then disagree with the table it claims to be a render of.
        let db = db().await;
        db.replace_waf_exclusions(&[NewWafExclusion {
            site_id: None,
            rule_id: 920420,
            reason: "the API accepts text/plain uploads".into(),
        }])
        .await
        .unwrap();

        let bad = [
            NewWafExclusion {
                site_id: None,
                rule_id: 941100,
                reason: "ok".into(),
            },
            NewWafExclusion {
                site_id: None,
                rule_id: 941100,
                reason: "duplicate — the unique index rejects this".into(),
            },
        ];
        assert!(db.replace_waf_exclusions(&bad).await.is_err());

        let still = db.waf_exclusions().await.unwrap();
        assert_eq!(still.len(), 1);
        assert_eq!(still[0].rule_id, 920420);
    }

    #[tokio::test]
    async fn the_same_rule_can_be_excluded_server_wide_and_for_one_site() {
        // Different scopes are different exclusions; the unique index is on the
        // pair, not on the rule.
        let db = db().await;
        let site = a_site(&db, "three.example.com").await;
        let stored = db
            .replace_waf_exclusions(&[
                NewWafExclusion {
                    site_id: None,
                    rule_id: 942100,
                    reason: "server-wide".into(),
                },
                NewWafExclusion {
                    site_id: Some(site),
                    rule_id: 942100,
                    reason: "and for this site".into(),
                },
            ])
            .await
            .unwrap();
        assert_eq!(stored.len(), 2);
        // Server-wide first: the render emits them in this order.
        assert_eq!(stored[0].site_id, None);
    }

    #[tokio::test]
    async fn policies_and_exclusions_read_back_in_a_stable_order() {
        // Byte-stable renders are what let the config engine skip a write and
        // an nginx reload when nothing actually changed.
        let db = db().await;
        let a = a_site(&db, "a.example.com").await;
        let b = a_site(&db, "b.example.com").await;
        db.set_waf_site_policy(b, WafMode::Block, 2).await.unwrap();
        db.set_waf_site_policy(a, WafMode::Detect, 1).await.unwrap();

        let policies = db.waf_site_policies().await.unwrap();
        assert_eq!(policies[0].site_id, a.min(b));
        assert_eq!(policies[1].site_id, a.max(b));
    }
}
