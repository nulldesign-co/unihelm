//! Firewall intent and Sentinel ban history (spec §11.9).
//!
//! Two tables, one philosophy: **the running firewall is the truth and this is
//! the panel's record of what it asked for.** `fw_rules` never says whether a
//! rule is live — `FwBackend::list_rules` answers that, and `fw.rules` reports
//! the difference between the two as drift. `sentinel_bans` never deletes a
//! row: a ban list that forgets cannot answer "why was my office cut off last
//! Tuesday", which is the question a brute-force defence generates most.
//!
//! Nothing here is tenant-scoped. The firewall is one host-wide resource; the
//! permission check (`Permission::FirewallManage`) lives in the operation
//! layer, and there is no per-tenant view of it to get wrong.

use serde::Serialize;
use time::OffsetDateTime;

use crate::{Db, Result, from_sql_time, now, to_sql_time};

/// One managed hole in the firewall, as the panel recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FwRuleRecord {
    pub id: i64,
    pub port: u16,
    /// `tcp` or `udp`; the CHECK constraint keeps anything else out.
    pub proto: String,
    /// `None` is "from anywhere".
    pub source: Option<String>,
    pub comment: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct FwRuleRow {
    id: i64,
    port: i64,
    proto: String,
    source: Option<String>,
    comment: String,
    created_at: String,
}

impl TryFrom<FwRuleRow> for FwRuleRecord {
    type Error = crate::DbError;

    fn try_from(r: FwRuleRow) -> Result<Self> {
        Ok(FwRuleRecord {
            id: r.id,
            // The column has a `BETWEEN 1 AND 65535` CHECK, so this only fires
            // on a database somebody edited by hand.
            port: u16::try_from(r.port).map_err(|_| crate::DbError::Corrupt {
                field: "fw_rules.port",
                detail: format!("`{}` is not a port number", r.port),
            })?,
            proto: r.proto,
            source: r.source,
            comment: r.comment,
            created_at: from_sql_time(&r.created_at)?,
        })
    }
}

/// One ban, live or historical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SentinelBan {
    pub id: i64,
    pub ip: String,
    pub reason: String,
    #[serde(with = "time::serde::rfc3339")]
    pub banned_at: OffsetDateTime,
    /// `None` is a permanent ban — only ever an operator's deliberate choice.
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub lifted_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SentinelBanRow {
    id: i64,
    ip: String,
    reason: String,
    banned_at: String,
    expires_at: Option<String>,
    lifted_at: Option<String>,
}

impl TryFrom<SentinelBanRow> for SentinelBan {
    type Error = crate::DbError;

    fn try_from(r: SentinelBanRow) -> Result<Self> {
        Ok(SentinelBan {
            id: r.id,
            ip: r.ip,
            reason: r.reason,
            banned_at: from_sql_time(&r.banned_at)?,
            expires_at: r.expires_at.as_deref().map(from_sql_time).transpose()?,
            lifted_at: r.lifted_at.as_deref().map(from_sql_time).transpose()?,
        })
    }
}

impl Db {
    // -- firewall rule intent ------------------------------------------------

    /// Record that the panel opened a port. Idempotent on
    /// `(port, proto, source)`: re-opening an existing rule refreshes its
    /// comment rather than accumulating duplicate records against the one live
    /// backend rule.
    pub async fn record_fw_rule(
        &self,
        port: u16,
        proto: &str,
        source: Option<&str>,
        comment: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO fw_rules (port, proto, source, comment, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (port, proto, COALESCE(source, '')) DO UPDATE SET comment = ?4",
        )
        .bind(i64::from(port))
        .bind(proto)
        .bind(source)
        .bind(comment)
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Forget a rule the panel closed. Returns how many records went away, so
    /// a caller can tell "closed a rule we knew about" from "closed a rule that
    /// only ever existed in the backend".
    pub async fn forget_fw_rule(
        &self,
        port: u16,
        proto: &str,
        source: Option<&str>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM fw_rules
             WHERE port = ?1 AND proto = ?2 AND COALESCE(source, '') = COALESCE(?3, '')",
        )
        .bind(i64::from(port))
        .bind(proto)
        .bind(source)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Every rule the panel believes it opened, oldest first.
    pub async fn fw_rules(&self) -> Result<Vec<FwRuleRecord>> {
        let rows: Vec<FwRuleRow> =
            sqlx::query_as("SELECT * FROM fw_rules ORDER BY port, proto, COALESCE(source, '')")
                .fetch_all(self.pool())
                .await?;
        rows.into_iter().map(FwRuleRecord::try_from).collect()
    }

    // -- Sentinel bans -------------------------------------------------------

    /// Open a ban record. Returns its id.
    ///
    /// A fresh row per ban even for a repeat offender: the history of *when*
    /// an address was banned is exactly what makes the list useful later.
    pub async fn record_ban(
        &self,
        ip: &str,
        reason: &str,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO sentinel_bans (ip, reason, banned_at, expires_at)
             VALUES (?1, ?2, ?3, ?4) RETURNING id",
        )
        .bind(ip)
        .bind(reason)
        .bind(to_sql_time(now()))
        .bind(expires_at.map(to_sql_time))
        .fetch_one(self.pool())
        .await?;
        Ok(row.0)
    }

    /// Close every still-standing ban for an address. Returns how many rows
    /// were closed — zero means the address was not banned by us, which the
    /// unban operation reports honestly rather than claiming success.
    pub async fn lift_bans_for(&self, ip: &str) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE sentinel_bans SET lifted_at = ?1 WHERE ip = ?2 AND lifted_at IS NULL",
        )
        .bind(to_sql_time(now()))
        .bind(ip)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Bans that have not been lifted, newest first — whether or not their TTL
    /// has passed. Expiry is the backend's job (ipset and nft sets expire their
    /// own entries); the reaper below closes the rows to match.
    pub async fn active_bans(&self) -> Result<Vec<SentinelBan>> {
        let rows: Vec<SentinelBanRow> = sqlx::query_as(
            "SELECT * FROM sentinel_bans WHERE lifted_at IS NULL ORDER BY banned_at DESC, id DESC",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(SentinelBan::try_from).collect()
    }

    /// The ban list for the UI: everything, newest first, including history.
    pub async fn recent_bans(&self, limit: i64) -> Result<Vec<SentinelBan>> {
        let limit = limit.clamp(1, 500);
        let rows: Vec<SentinelBanRow> =
            sqlx::query_as("SELECT * FROM sentinel_bans ORDER BY banned_at DESC, id DESC LIMIT ?1")
                .bind(limit)
                .fetch_all(self.pool())
                .await?;
        rows.into_iter().map(SentinelBan::try_from).collect()
    }

    /// Is this address under a ban that has not been lifted and has not
    /// expired? Used to keep the scanner from re-banning an address every
    /// minute for the same burst of failures.
    pub async fn is_banned(&self, ip: &str) -> Result<bool> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sentinel_bans
             WHERE ip = ?1 AND lifted_at IS NULL AND (expires_at IS NULL OR expires_at > ?2)",
        )
        .bind(ip)
        .bind(to_sql_time(now()))
        .fetch_one(self.pool())
        .await?;
        Ok(row.0 > 0)
    }

    /// Bans whose TTL has passed but whose row is still open.
    ///
    /// The firewall backends expire their own entries (ipset `timeout`, nft
    /// `flags timeout`), so this is bookkeeping catching up with the kernel,
    /// not the mechanism that ends a ban. The unban still runs for the ufw
    /// backend, which has no expiry of its own.
    pub async fn expired_bans(&self) -> Result<Vec<SentinelBan>> {
        let rows: Vec<SentinelBanRow> = sqlx::query_as(
            "SELECT * FROM sentinel_bans
             WHERE lifted_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?1
             ORDER BY expires_at",
        )
        .bind(to_sql_time(now()))
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(SentinelBan::try_from).collect()
    }

    /// Failed panel logins since `since`, as `(ip, count)`.
    ///
    /// The panel's own jail (spec §11.9 ships "default jails for sshd, panel
    /// login"): `login_attempts` is already written by the login route, so the
    /// scanner reads it rather than parsing the panel's own log.
    pub async fn failed_logins_since(&self, since: OffsetDateTime) -> Result<Vec<(String, i64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT ip, COUNT(*) FROM login_attempts
             WHERE success = 0 AND at >= ?1 GROUP BY ip",
        )
        .bind(to_sql_time(since))
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[tokio::test]
    async fn opening_the_same_port_twice_records_one_rule() {
        // The backend is idempotent (opening 443 twice is one hole), so the
        // panel's record of it must be too — otherwise the drift view would
        // show two panel rules against one backend rule forever.
        let db = Db::open_memory().await.unwrap();
        db.record_fw_rule(443, "tcp", None, "https").await.unwrap();
        db.record_fw_rule(443, "tcp", None, "https again")
            .await
            .unwrap();

        let rules = db.fw_rules().await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].comment, "https again");
    }

    #[tokio::test]
    async fn the_same_port_from_different_sources_are_different_rules() {
        let db = Db::open_memory().await.unwrap();
        db.record_fw_rule(3306, "tcp", None, "everyone")
            .await
            .unwrap();
        db.record_fw_rule(3306, "tcp", Some("10.0.0.0/8"), "office")
            .await
            .unwrap();
        db.record_fw_rule(3306, "udp", None, "why not")
            .await
            .unwrap();
        assert_eq!(db.fw_rules().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn forgetting_a_rule_matches_a_null_source_exactly() {
        // `source = NULL` never matches in SQL, so a naive DELETE would leave
        // "open to anywhere" records behind forever after every close.
        let db = Db::open_memory().await.unwrap();
        db.record_fw_rule(8080, "tcp", None, "app").await.unwrap();
        db.record_fw_rule(8080, "tcp", Some("203.0.113.0/24"), "office")
            .await
            .unwrap();

        assert_eq!(db.forget_fw_rule(8080, "tcp", None).await.unwrap(), 1);
        let left = db.fw_rules().await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].source.as_deref(), Some("203.0.113.0/24"));

        // Closing something we never recorded is not an error, it is a zero.
        assert_eq!(db.forget_fw_rule(9999, "tcp", None).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_lifted_ban_stays_in_the_history() {
        let db = Db::open_memory().await.unwrap();
        db.record_ban(
            "203.0.113.9",
            "6 ssh failures",
            Some(now() + Duration::hours(1)),
        )
        .await
        .unwrap();
        assert!(db.is_banned("203.0.113.9").await.unwrap());

        assert_eq!(db.lift_bans_for("203.0.113.9").await.unwrap(), 1);
        assert!(!db.is_banned("203.0.113.9").await.unwrap());
        assert!(db.active_bans().await.unwrap().is_empty());

        // But the record of what happened survives.
        let history = db.recent_bans(10).await.unwrap();
        assert_eq!(history.len(), 1);
        assert!(history[0].lifted_at.is_some());
    }

    #[tokio::test]
    async fn unbanning_an_address_we_never_banned_reports_zero() {
        let db = Db::open_memory().await.unwrap();
        assert_eq!(db.lift_bans_for("198.51.100.1").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn an_expired_ban_is_no_longer_in_force_and_shows_up_for_the_reaper() {
        let db = Db::open_memory().await.unwrap();
        let id = db
            .record_ban("203.0.113.9", "ssh", Some(now() - Duration::minutes(1)))
            .await
            .unwrap();

        // Its TTL passed, so it is not in force...
        assert!(!db.is_banned("203.0.113.9").await.unwrap());
        // ...but its row is still open, which is what the reaper closes.
        let expired = db.expired_bans().await.unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, id);

        db.lift_bans_for("203.0.113.9").await.unwrap();
        assert!(db.expired_bans().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_permanent_ban_never_expires() {
        let db = Db::open_memory().await.unwrap();
        db.record_ban("203.0.113.9", "manual", None).await.unwrap();
        assert!(db.is_banned("203.0.113.9").await.unwrap());
        assert!(
            db.expired_bans().await.unwrap().is_empty(),
            "a ban with no TTL must never be reaped"
        );
    }

    #[tokio::test]
    async fn failed_logins_are_counted_per_ip_inside_the_window() {
        let db = Db::open_memory().await.unwrap();
        for _ in 0..3 {
            db.record_login_attempt("203.0.113.9", "admin", false)
                .await
                .unwrap();
        }
        db.record_login_attempt("203.0.113.9", "admin", true)
            .await
            .unwrap();
        db.record_login_attempt("198.51.100.4", "admin", false)
            .await
            .unwrap();

        let counts = db
            .failed_logins_since(now() - Duration::minutes(10))
            .await
            .unwrap();
        let find = |ip: &str| counts.iter().find(|(a, _)| a == ip).map(|(_, n)| *n);
        // The successful login is not a failure and must not count towards a ban.
        assert_eq!(find("203.0.113.9"), Some(3));
        assert_eq!(find("198.51.100.4"), Some(1));

        // A window that starts in the future sees nothing.
        assert!(
            db.failed_logins_since(now() + Duration::minutes(1))
                .await
                .unwrap()
                .is_empty()
        );
    }
}
