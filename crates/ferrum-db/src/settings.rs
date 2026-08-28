//! Key/value panel settings (spec §9 `settings`).
//!
//! Values are JSON documents, read and written through serde, so a setting is a
//! typed struct in code and a readable blob in the database.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Db, DbError, Result, now, to_sql_time};

/// Setting keys the panel itself uses. Free-form keys are allowed for plugins
/// later, but core settings live here so a typo is a compile error.
pub mod keys {
    /// Panel display name, used in the UI and in notification templates.
    pub const PANEL_NAME: &str = "panel.name";
    /// Default locale for new accounts (`en` or `fa`).
    pub const DEFAULT_LOCALE: &str = "panel.default_locale";
    /// Audit retention in days.
    pub const AUDIT_RETENTION_DAYS: &str = "audit.retention_days";
    /// Whether admins must have 2FA enabled.
    pub const FORCE_ADMIN_2FA: &str = "security.force_admin_2fa";
    /// Schema-independent marker for "the installer finished".
    pub const SETUP_COMPLETE: &str = "setup.complete";

    // -- Sentinel, the built-in brute-force defence (spec §11.9) -------------
    //
    // Defaults live in `ferrum_ops::fwops::SentinelSettings`, not here, because
    // an *absent* key must read as the default: seeding rows at install time
    // would mean an upgrade could never change a default it had already
    // written into every database.

    /// Master switch. **Defaults to false** — a fresh install must never start
    /// banning addresses before its operator has told it which ones matter.
    pub const SENTINEL_ENABLED: &str = "sentinel.enabled";
    /// Failed SSH authentications within the window that earn a ban.
    pub const SENTINEL_SSH_THRESHOLD: &str = "sentinel.ssh_threshold";
    /// How far back each scan looks, in minutes.
    pub const SENTINEL_WINDOW_MINUTES: &str = "sentinel.window_minutes";
    /// How long a ban lasts, in minutes.
    pub const SENTINEL_BAN_MINUTES: &str = "sentinel.ban_minutes";
    /// Addresses and CIDRs Sentinel must never ban, on top of the built-in
    /// refusals (loopback, this host's own addresses, the caller's address).
    pub const SENTINEL_ALLOWLIST: &str = "sentinel.allowlist";

    /// This server's public IP addresses, as a JSON array of strings.
    ///
    /// The override `dns.check` consults first (spec §11.13). A server behind a
    /// NAT, a floating IP or a load balancer answers the internet on an address
    /// that appears on no local interface, so probing cannot find it and an
    /// operator has to say. Unset on a plain public VPS, where the interface
    /// addresses are already the right answer.
    pub const DNS_SERVER_ADDRESSES: &str = "dns.server_addresses";

    // -- ModSecurity WAF (spec §11.9) ---------------------------------------
    //
    // Same reasoning as Sentinel's keys: defaults live in `ferrum_ops::waf`
    // and an absent key reads as the default, so a later release can change a
    // default without migrating a value it once wrote into every database.

    /// Whether the panel has switched ModSecurity on for this server. False
    /// until an operator runs `waf.enable`, which is also the point at which
    /// the panel first checks whether a loadable module exists at all.
    pub const WAF_ENABLED: &str = "waf.enabled";
    /// The server-wide engine mode every site inherits without a policy of its
    /// own: `off`, `detect` or `block`. **`detect`** by default — spec §11.9
    /// asks for a log-only mode first, because a rule set that has never seen
    /// a site's traffic will have false positives and finding them in a log is
    /// cheaper than finding them in a support ticket.
    pub const WAF_DEFAULT_MODE: &str = "waf.default_mode";
    /// The CRS paranoia level a site inherits without one of its own.
    pub const WAF_DEFAULT_PARANOIA: &str = "waf.default_paranoia";
    /// The Core Rule Set release currently unpacked on disk. Written after a
    /// successful verified install, so a version mismatch against the pin in
    /// `ferrum_ops::waf` is visible without hashing the tree again.
    pub const WAF_CRS_VERSION: &str = "waf.crs_version";
}

impl Db {
    /// Read a setting, or `None` if it has never been written.
    pub async fn get_setting<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value_json FROM settings WHERE key = ?1")
                .bind(key)
                .fetch_optional(self.pool())
                .await?;

        match row {
            None => Ok(None),
            Some((json,)) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| DbError::Corrupt {
                    field: "settings.value_json",
                    detail: e.to_string(),
                }),
        }
    }

    /// Read a setting, falling back to `default` when unset **or unreadable**.
    ///
    /// A setting whose stored shape no longer matches the code should not stop
    /// the panel from booting; the fallback is logged loudly instead.
    pub async fn get_setting_or<T: DeserializeOwned>(&self, key: &str, default: T) -> T {
        match self.get_setting::<T>(key).await {
            Ok(Some(v)) => v,
            Ok(None) => default,
            Err(e) => {
                tracing::warn!(key, error = %e, "unreadable setting; using the default");
                default
            }
        }
    }

    pub async fn set_setting<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let json = serde_json::to_string(value).map_err(|e| DbError::Corrupt {
            field: "settings.value_json",
            detail: e.to_string(),
        })?;
        sqlx::query(
            "INSERT INTO settings (key, value_json, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (key) DO UPDATE SET value_json = ?2, updated_at = ?3",
        )
        .bind(key)
        .bind(json)
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn delete_setting(&self, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM settings WHERE key = ?1")
            .bind(key)
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Branding {
        name: String,
        accent: String,
    }

    #[tokio::test]
    async fn settings_round_trip_and_upsert() {
        let db = Db::open_memory().await.unwrap();
        assert_eq!(
            db.get_setting::<String>(keys::PANEL_NAME).await.unwrap(),
            None
        );

        db.set_setting(keys::PANEL_NAME, &"Ferrum".to_string())
            .await
            .unwrap();
        assert_eq!(
            db.get_setting::<String>(keys::PANEL_NAME).await.unwrap(),
            Some("Ferrum".to_string())
        );

        db.set_setting(keys::PANEL_NAME, &"Panel".to_string())
            .await
            .unwrap();
        assert_eq!(
            db.get_setting::<String>(keys::PANEL_NAME).await.unwrap(),
            Some("Panel".to_string())
        );
    }

    #[tokio::test]
    async fn structured_settings_work() {
        let db = Db::open_memory().await.unwrap();
        let b = Branding {
            name: "Acme Hosting".into(),
            accent: "#3b82f6".into(),
        };
        db.set_setting("branding", &b).await.unwrap();
        assert_eq!(
            db.get_setting::<Branding>("branding").await.unwrap(),
            Some(b)
        );
    }

    #[tokio::test]
    async fn a_setting_of_the_wrong_shape_falls_back_instead_of_breaking_boot() {
        let db = Db::open_memory().await.unwrap();
        db.set_setting(keys::AUDIT_RETENTION_DAYS, &"not a number".to_string())
            .await
            .unwrap();
        assert!(
            db.get_setting::<i64>(keys::AUDIT_RETENTION_DAYS)
                .await
                .is_err()
        );
        assert_eq!(
            db.get_setting_or(keys::AUDIT_RETENTION_DAYS, 180i64).await,
            180
        );
    }

    #[tokio::test]
    async fn delete_removes_the_key() {
        let db = Db::open_memory().await.unwrap();
        db.set_setting(keys::SETUP_COMPLETE, &true).await.unwrap();
        db.delete_setting(keys::SETUP_COMPLETE).await.unwrap();
        assert_eq!(
            db.get_setting::<bool>(keys::SETUP_COMPLETE).await.unwrap(),
            None
        );
    }
}
