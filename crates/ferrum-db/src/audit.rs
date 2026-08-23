//! The audit trail (spec §10.3, §12 rule 10).
//!
//! Every state-changing call writes a row here. Two details matter:
//! `actor_username` is denormalised so the trail survives the account being
//! renamed or deleted, and `impersonator_id` is always populated when an admin is
//! acting through "login as".

use ferrum_core::{SubscriptionId, TenantScope, UserId};

use crate::models::{AuditEntry, AuditRow};
use crate::scope::ScopeFilter;
use crate::{Db, Result, now, to_sql_time};

/// Keys that must never be written into `detail_json`.
///
/// Audit rows are read by support staff and exported; a password that lands here
/// outlives every other place it was scrubbed (spec §12 rule 6).
const REDACTED_KEYS: &[&str] = &[
    "password",
    "new_password",
    "old_password",
    "pass",
    "pass_hash",
    "secret",
    "token",
    "api_key",
    "private_key",
    "totp_secret",
    "credentials",
    "creds",
];

const REDACTED: &str = "[redacted]";

/// One entry to write.
#[derive(Debug, Clone)]
pub struct NewAuditEntry {
    pub actor_user_id: Option<UserId>,
    pub actor_username: String,
    pub impersonator_id: Option<UserId>,
    pub ip: Option<String>,
    /// Dotted action name, matching the operation where there is one:
    /// `auth.login`, `site.create`, `user.suspend`.
    pub action: String,
    /// What was acted on: a domain, a username, a unit name.
    pub target: Option<String>,
    pub detail: serde_json::Value,
    pub request_id: Option<String>,
    pub subscription_id: Option<SubscriptionId>,
}

pub struct AuditRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn audit(&self, scope: &TenantScope) -> AuditRepo<'_> {
        AuditRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    /// Write an audit row.
    ///
    /// Unscoped on purpose: the actor's scope was already checked by whatever is
    /// being audited, and refusing to record an action because of a scope check
    /// would be exactly backwards.
    pub async fn record_audit(&self, entry: NewAuditEntry) -> Result<i64> {
        let detail = redact(entry.detail);
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO audit_log (at, actor_user_id, actor_username, impersonator_id, ip,
                                    action, target, detail_json, request_id, subscription_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             RETURNING id",
        )
        .bind(to_sql_time(now()))
        .bind(entry.actor_user_id.map(|u| u.get()))
        .bind(&entry.actor_username)
        .bind(entry.impersonator_id.map(|u| u.get()))
        .bind(&entry.ip)
        .bind(&entry.action)
        .bind(&entry.target)
        .bind(serde_json::to_string(&detail).unwrap_or_else(|_| "{}".into()))
        .bind(&entry.request_id)
        .bind(entry.subscription_id.map(|s| s.get()))
        .fetch_one(self.pool())
        .await?;
        Ok(row.0)
    }

    /// Drop entries older than `days`. Default retention is 180 days (spec §10.3).
    pub async fn purge_audit(&self, days: i64) -> Result<u64> {
        let cutoff = to_sql_time(now() - time::Duration::days(days.max(1)));
        let result = sqlx::query("DELETE FROM audit_log WHERE at < ?1")
            .bind(cutoff)
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected())
    }
}

impl AuditRepo<'_> {
    /// Entries visible to this scope, newest first.
    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<AuditEntry>> {
        let limit = limit.clamp(1, 500);
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, AuditRow>(
                    "SELECT * FROM audit_log ORDER BY at DESC, id DESC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(user_id) | ScopeFilter::Customer(user_id) => {
                sqlx::query_as::<_, AuditRow>(
                    "SELECT * FROM audit_log WHERE actor_user_id = ?1
                     ORDER BY at DESC, id DESC LIMIT ?2 OFFSET ?3",
                )
                .bind(user_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, AuditRow>(
                    "SELECT * FROM audit_log WHERE subscription_id = ?1
                     ORDER BY at DESC, id DESC LIMIT ?2 OFFSET ?3",
                )
                .bind(subscription_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(AuditEntry::try_from).collect()
    }

    /// Filter by action prefix, for "show me every certificate renewal".
    pub async fn list_by_action(&self, action_prefix: &str, limit: i64) -> Result<Vec<AuditEntry>> {
        let limit = limit.clamp(1, 500);
        // `LIKE` with an escaped, bound pattern — the prefix is data, not SQL.
        let pattern = format!("{}%", action_prefix.replace('%', "\\%").replace('_', "\\_"));
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, AuditRow>(
                    "SELECT * FROM audit_log WHERE action LIKE ?1 ESCAPE '\\'
                     ORDER BY at DESC, id DESC LIMIT ?2",
                )
                .bind(&pattern)
                .bind(limit)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(user_id) | ScopeFilter::Customer(user_id) => sqlx::query_as::<
                _,
                AuditRow,
            >(
                "SELECT * FROM audit_log WHERE action LIKE ?1 ESCAPE '\\' AND actor_user_id = ?2
                     ORDER BY at DESC, id DESC LIMIT ?3",
            )
            .bind(&pattern)
            .bind(user_id)
            .bind(limit)
            .fetch_all(self.db.pool())
            .await?,
            ScopeFilter::Subscription {
                subscription_id, ..
            } => sqlx::query_as::<_, AuditRow>(
                "SELECT * FROM audit_log WHERE action LIKE ?1 ESCAPE '\\' AND subscription_id = ?2
                     ORDER BY at DESC, id DESC LIMIT ?3",
            )
            .bind(&pattern)
            .bind(subscription_id)
            .bind(limit)
            .fetch_all(self.db.pool())
            .await?,
        };
        rows.into_iter().map(AuditEntry::try_from).collect()
    }
}

/// Recursively replace the value of any sensitive-looking key.
fn redact(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| {
                    let lower = k.to_ascii_lowercase();
                    if REDACTED_KEYS.iter().any(|needle| lower.contains(needle)) {
                        (k, Value::String(REDACTED.into()))
                    } else {
                        (k, redact(v))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(redact).collect()),
        other => other,
    }
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

    fn entry(actor: UserId, username: &str, action: &str) -> NewAuditEntry {
        NewAuditEntry {
            actor_user_id: Some(actor),
            actor_username: username.into(),
            impersonator_id: None,
            ip: Some("10.0.0.1".into()),
            action: action.into(),
            target: Some("example.com".into()),
            detail: serde_json::json!({}),
            request_id: Some("req-1".into()),
            subscription_id: None,
        }
    }

    #[tokio::test]
    async fn entries_round_trip() {
        let (db, alice, _) = seed().await;
        db.record_audit(entry(alice, "alice", "site.create"))
            .await
            .unwrap();
        let list = db.audit(&TenantScope::Global).list(10, 0).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].action, "site.create");
        assert_eq!(list[0].actor_username, "alice");
        assert_eq!(list[0].ip.as_deref(), Some("10.0.0.1"));
    }

    #[tokio::test]
    async fn secrets_are_redacted_before_they_are_stored() {
        let (db, alice, _) = seed().await;
        let mut e = entry(alice, "alice", "user.create");
        e.detail = serde_json::json!({
            "username": "newuser",
            "password": "hunter2",
            "nested": { "api_key": "sk-live-xyz", "keep": "visible" },
            "list": [ { "totp_secret": "JBSWY3DP" } ],
        });
        db.record_audit(e).await.unwrap();

        let stored = db.audit(&TenantScope::Global).list(1, 0).await.unwrap();
        let d = &stored[0].detail;
        assert_eq!(d["password"], REDACTED);
        assert_eq!(d["nested"]["api_key"], REDACTED);
        assert_eq!(d["nested"]["keep"], "visible");
        assert_eq!(d["list"][0]["totp_secret"], REDACTED);
        assert_eq!(d["username"], "newuser");

        // And nothing sensitive survives anywhere in the raw column.
        let raw: (String,) = sqlx::query_as("SELECT detail_json FROM audit_log")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert!(!raw.0.contains("hunter2"));
        assert!(!raw.0.contains("sk-live-xyz"));
    }

    #[tokio::test]
    async fn impersonation_records_both_identities() {
        let (db, alice, bobby) = seed().await;
        let mut e = entry(alice, "alice", "auth.impersonate");
        e.impersonator_id = Some(bobby);
        db.record_audit(e).await.unwrap();
        let list = db.audit(&TenantScope::Global).list(1, 0).await.unwrap();
        assert_eq!(list[0].impersonator_id, Some(bobby));
        assert_eq!(list[0].actor_user_id, Some(alice));
    }

    #[tokio::test]
    async fn a_tenant_sees_only_its_own_trail() {
        let (db, alice, bobby) = seed().await;
        db.record_audit(entry(alice, "alice", "site.create"))
            .await
            .unwrap();
        db.record_audit(entry(bobby, "bobby", "site.delete"))
            .await
            .unwrap();

        let mine = db
            .audit(&TenantScope::Customer { customer_id: alice })
            .list(10, 0)
            .await
            .unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].actor_username, "alice");

        assert_eq!(
            db.audit(&TenantScope::Global)
                .list(10, 0)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn action_filter_treats_wildcards_as_literal_text() {
        let (db, alice, _) = seed().await;
        db.record_audit(entry(alice, "alice", "cert.renew"))
            .await
            .unwrap();
        db.record_audit(entry(alice, "alice", "site.create"))
            .await
            .unwrap();

        let repo = db.audit(&TenantScope::Global);
        assert_eq!(repo.list_by_action("cert.", 10).await.unwrap().len(), 1);
        assert_eq!(repo.list_by_action("site", 10).await.unwrap().len(), 1);
        // A user-supplied `%` must not turn into "match everything".
        assert_eq!(repo.list_by_action("%", 10).await.unwrap().len(), 0);
        assert_eq!(
            repo.list_by_action("_ert.renew", 10).await.unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn the_trail_survives_the_actor_being_deleted() {
        let (db, alice, _) = seed().await;
        db.record_audit(entry(alice, "alice", "site.create"))
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(alice.get())
            .execute(db.pool())
            .await
            .unwrap();

        let list = db.audit(&TenantScope::Global).list(10, 0).await.unwrap();
        assert_eq!(
            list.len(),
            1,
            "deleting an account must not erase what it did"
        );
        assert_eq!(list[0].actor_username, "alice");
        assert_eq!(list[0].actor_user_id, None);
    }

    #[tokio::test]
    async fn purge_respects_retention() {
        let (db, alice, _) = seed().await;
        db.record_audit(entry(alice, "alice", "site.create"))
            .await
            .unwrap();
        sqlx::query("UPDATE audit_log SET at = ?1")
            .bind(to_sql_time(now() - time::Duration::days(200)))
            .execute(db.pool())
            .await
            .unwrap();

        assert_eq!(db.purge_audit(180).await.unwrap(), 1);
        assert!(
            db.audit(&TenantScope::Global)
                .list(10, 0)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
