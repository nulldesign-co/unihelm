//! The plugin registry (spec §6 plugin note, §14 Phase 6).
//!
//! One row per installed plugin. The row is the **routing authority**: the
//! agent decides which extension-point calls a plugin may receive by reading
//! `extensions_json` here, never by asking the running sidecar what it thinks
//! it provides. A plugin that could widen its own reach at runtime would have
//! turned the manifest into a suggestion.
//!
//! Everything the panel does with a plugin is server-wide and admin-only, so
//! there is no [`crate::scope::ScopeFilter`] in this module: the operations
//! above it require `server_manage`, which only an admin ever holds.

use serde::Serialize;

use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// How the payload was trusted at install time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSignature {
    /// A minisign signature over the archive verified against a trusted key.
    Minisign,
    /// Installed with `plugins.allow_unsigned` on. Recorded rather than
    /// forgotten: "how did this get here" is a question that gets asked months
    /// later, usually during an incident.
    Unsigned,
}

impl PluginSignature {
    pub const fn as_str(self) -> &'static str {
        match self {
            PluginSignature::Minisign => "minisign",
            PluginSignature::Unsigned => "unsigned",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "minisign" => Ok(PluginSignature::Minisign),
            "unsigned" => Ok(PluginSignature::Unsigned),
            other => Err(DbError::Corrupt {
                field: "plugins.signature",
                detail: format!("`{other}` is not a signature state"),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginRecord {
    pub slug: String,
    pub name: String,
    pub version: String,
    /// The manifest exactly as validated at install time.
    pub manifest: serde_json::Value,
    /// The extension points the agent will route to this plugin.
    pub extensions: Vec<String>,
    pub install_dir: String,
    pub run_user: String,
    pub signature: PluginSignature,
    pub enabled: bool,
    pub last_error: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub installed_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PluginRow {
    pub slug: String,
    pub name: String,
    pub version: String,
    pub manifest_json: String,
    pub extensions_json: String,
    pub install_dir: String,
    pub run_user: String,
    pub signature: String,
    pub enabled: i64,
    pub last_error: Option<String>,
    pub installed_at: String,
    pub updated_at: String,
}

impl TryFrom<PluginRow> for PluginRecord {
    type Error = DbError;

    fn try_from(r: PluginRow) -> Result<Self> {
        let manifest = serde_json::from_str(&r.manifest_json).map_err(|e| DbError::Corrupt {
            field: "plugins.manifest_json",
            detail: e.to_string(),
        })?;
        let extensions: Vec<String> =
            serde_json::from_str(&r.extensions_json).map_err(|e| DbError::Corrupt {
                field: "plugins.extensions_json",
                detail: e.to_string(),
            })?;
        Ok(PluginRecord {
            slug: r.slug,
            name: r.name,
            version: r.version,
            manifest,
            extensions,
            install_dir: r.install_dir,
            run_user: r.run_user,
            signature: PluginSignature::parse(&r.signature)?,
            enabled: r.enabled != 0,
            last_error: r.last_error,
            installed_at: from_sql_time(&r.installed_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

/// A plugin to record. Everything here has already been validated by
/// `ferrum_ops::plugin`; this module only stores it.
#[derive(Debug, Clone)]
pub struct NewPlugin {
    pub slug: String,
    pub name: String,
    pub version: String,
    pub manifest: serde_json::Value,
    pub extensions: Vec<String>,
    pub install_dir: String,
    pub run_user: String,
    pub signature: PluginSignature,
}

impl Db {
    /// Every installed plugin, newest first.
    pub async fn list_plugins(&self) -> Result<Vec<PluginRecord>> {
        let rows =
            sqlx::query_as::<_, PluginRow>("SELECT * FROM plugins ORDER BY installed_at DESC")
                .fetch_all(self.pool())
                .await?;
        rows.into_iter().map(PluginRecord::try_from).collect()
    }

    pub async fn plugin_by_slug(&self, slug: &str) -> Result<Option<PluginRecord>> {
        let row = sqlx::query_as::<_, PluginRow>("SELECT * FROM plugins WHERE slug = ?1")
            .bind(slug)
            .fetch_optional(self.pool())
            .await?;
        row.map(PluginRecord::try_from).transpose()
    }

    /// Record an installed plugin. **Disabled** — installing is not starting.
    ///
    /// Two verbs rather than one because they answer different questions: "is
    /// this code on the machine" and "is this code running". An install that
    /// started the sidecar would mean an operator who wanted to read the
    /// manifest first had no way to.
    pub async fn create_plugin(&self, new: NewPlugin) -> Result<PluginRecord> {
        let ts = to_sql_time(now());
        let manifest_json = serde_json::to_string(&new.manifest).map_err(|e| DbError::Corrupt {
            field: "plugins.manifest_json",
            detail: e.to_string(),
        })?;
        let extensions_json =
            serde_json::to_string(&new.extensions).map_err(|e| DbError::Corrupt {
                field: "plugins.extensions_json",
                detail: e.to_string(),
            })?;

        let row = sqlx::query_as::<_, PluginRow>(
            "INSERT INTO plugins
                 (slug, name, version, manifest_json, extensions_json, install_dir,
                  run_user, signature, enabled, last_error, installed_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, NULL, ?9, ?9)
             RETURNING *",
        )
        .bind(&new.slug)
        .bind(&new.name)
        .bind(&new.version)
        .bind(&manifest_json)
        .bind(&extensions_json)
        .bind(&new.install_dir)
        .bind(&new.run_user)
        .bind(new.signature.as_str())
        .bind(&ts)
        .fetch_one(self.pool())
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db) if db.is_unique_violation() => {
                DbError::Conflict { what: "plugin" }
            }
            other => DbError::Sqlx(other),
        })?;
        PluginRecord::try_from(row)
    }

    /// Turn a plugin on or off. Returns the row, or `NotFound`.
    pub async fn set_plugin_enabled(&self, slug: &str, enabled: bool) -> Result<PluginRecord> {
        let row = sqlx::query_as::<_, PluginRow>(
            "UPDATE plugins SET enabled = ?2, last_error = NULL, updated_at = ?3
             WHERE slug = ?1 RETURNING *",
        )
        .bind(slug)
        .bind(i64::from(enabled))
        .bind(to_sql_time(now()))
        .fetch_optional(self.pool())
        .await?;
        row.ok_or(DbError::NotFound { what: "plugin" })
            .and_then(PluginRecord::try_from)
    }

    /// Record why a plugin's sidecar last failed.
    pub async fn set_plugin_error(&self, slug: &str, error: &str) -> Result<()> {
        // Somebody else's daemon wrote this text. Bound it.
        let error: String = error.chars().take(500).collect();
        sqlx::query("UPDATE plugins SET last_error = ?2, updated_at = ?3 WHERE slug = ?1")
            .bind(slug)
            .bind(&error)
            .bind(to_sql_time(now()))
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn delete_plugin(&self, slug: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM plugins WHERE slug = ?1")
            .bind(slug)
            .execute(self.pool())
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound { what: "plugin" });
        }
        Ok(())
    }

    /// The plugins that should have a sidecar running.
    pub async fn enabled_plugins(&self) -> Result<Vec<PluginRecord>> {
        let rows =
            sqlx::query_as::<_, PluginRow>("SELECT * FROM plugins WHERE enabled = 1 ORDER BY slug")
                .fetch_all(self.pool())
                .await?;
        rows.into_iter().map(PluginRecord::try_from).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_plugin(slug: &str, extensions: &[&str]) -> NewPlugin {
        NewPlugin {
            slug: slug.into(),
            name: "Example provider".into(),
            version: "1.2.3".into(),
            manifest: serde_json::json!({ "slug": slug, "version": "1.2.3" }),
            extensions: extensions.iter().map(|e| (*e).to_string()).collect(),
            install_dir: format!("/var/lib/ferrum/plugins/{slug}"),
            run_user: format!("ferrum-plug-{slug}"),
            signature: PluginSignature::Minisign,
        }
    }

    #[tokio::test]
    async fn a_plugin_is_installed_disabled() {
        let db = Db::open_memory().await.unwrap();
        let p = db
            .create_plugin(new_plugin("acme-dns", &["dns_provider"]))
            .await
            .unwrap();
        assert!(
            !p.enabled,
            "installing must not start anything: enabling is a separate, audited decision"
        );
        assert!(db.enabled_plugins().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_same_slug_cannot_be_installed_twice() {
        let db = Db::open_memory().await.unwrap();
        db.create_plugin(new_plugin("acme-dns", &["dns_provider"]))
            .await
            .unwrap();
        assert!(matches!(
            db.create_plugin(new_plugin("acme-dns", &["notifier"]))
                .await,
            Err(DbError::Conflict { .. })
        ));
        // And the first row's declared extensions were not widened by the
        // attempt: the registry is the authority, and a second install is a
        // conflict rather than an upsert.
        let stored = db.plugin_by_slug("acme-dns").await.unwrap().unwrap();
        assert_eq!(stored.extensions, vec!["dns_provider".to_string()]);
    }

    #[tokio::test]
    async fn enabling_clears_a_previous_failure() {
        let db = Db::open_memory().await.unwrap();
        db.create_plugin(new_plugin("acme-dns", &["dns_provider"]))
            .await
            .unwrap();
        db.set_plugin_error("acme-dns", "sidecar exited immediately")
            .await
            .unwrap();
        let enabled = db.set_plugin_enabled("acme-dns", true).await.unwrap();
        assert!(enabled.enabled);
        assert_eq!(enabled.last_error, None);
        assert_eq!(db.enabled_plugins().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_missing_plugin_is_not_found_rather_than_silently_ignored() {
        let db = Db::open_memory().await.unwrap();
        assert!(matches!(
            db.set_plugin_enabled("nope", true).await,
            Err(DbError::NotFound { .. })
        ));
        assert!(matches!(
            db.delete_plugin("nope").await,
            Err(DbError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn a_hand_edited_signature_state_is_a_corrupt_row_not_a_default() {
        let db = Db::open_memory().await.unwrap();
        db.create_plugin(new_plugin("acme-dns", &["dns_provider"]))
            .await
            .unwrap();
        // The CHECK constraint is the first line of defence; this proves the
        // reader does not quietly fall back to `unsigned` if it is ever
        // bypassed (a restored database, a schema change).
        assert!(PluginSignature::parse("trust-me").is_err());
    }

    #[tokio::test]
    async fn a_long_sidecar_error_is_bounded_before_it_becomes_a_row() {
        let db = Db::open_memory().await.unwrap();
        db.create_plugin(new_plugin("acme-dns", &["dns_provider"]))
            .await
            .unwrap();
        db.set_plugin_error("acme-dns", &"x".repeat(10_000))
            .await
            .unwrap();
        let stored = db.plugin_by_slug("acme-dns").await.unwrap().unwrap();
        assert_eq!(stored.last_error.unwrap().chars().count(), 500);
    }
}
