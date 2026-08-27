//! Stored DNS provider credentials (spec §11.13).
//!
//! One row per (kind, label). The credential is sealed with the panel master
//! key before it arrives here and is never opened in this module — the only
//! thing this file knows about the secret is that it is an opaque string,
//! which is what keeps it out of a query log, a `Debug` line and a backup of
//! the panel database that somebody reads with `sqlite3`.

use serde::Serialize;

use crate::{Db, DbError, Result, now, to_sql_time};

/// Which provider a stored credential belongs to.
///
/// One variant on purpose (spec §11.13: "Cloudflare first, then generic
/// RFC2136, others"). The database CHECK constraint agrees, so adding a
/// provider is a migration and a review, not a string that slips through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsProviderKind {
    Cloudflare,
}

impl DnsProviderKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            DnsProviderKind::Cloudflare => "cloudflare",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "cloudflare" => Ok(DnsProviderKind::Cloudflare),
            other => Err(DbError::Corrupt {
                field: "dns_providers.kind",
                detail: format!("unknown provider `{other}`"),
            }),
        }
    }
}

/// A stored provider credential.
///
/// `credentials_sealed` is deliberately *not* `Serialize`d anywhere: this
/// struct is an internal record, and the operation layer projects it into its
/// own output type that has no credential field at all. A sealed value is still
/// a secret — publishing it hands an attacker everything but the master key.
#[derive(Debug, Clone)]
pub struct DnsProvider {
    pub id: i64,
    pub kind: DnsProviderKind,
    pub label: String,
    /// Still sealed. Open it with [`crate::MasterKey`].
    pub credentials_sealed: String,
}

#[derive(Debug, sqlx::FromRow)]
struct DnsProviderRow {
    id: i64,
    kind: String,
    label: String,
    credentials_sealed: String,
}

impl TryFrom<DnsProviderRow> for DnsProvider {
    type Error = DbError;

    fn try_from(r: DnsProviderRow) -> Result<Self> {
        Ok(DnsProvider {
            id: r.id,
            kind: DnsProviderKind::parse(&r.kind)?,
            label: r.label,
            credentials_sealed: r.credentials_sealed,
        })
    }
}

impl Db {
    /// Store or rotate a provider credential.
    ///
    /// Upsert on (kind, label) rather than insert: an operator re-running
    /// `dns.provider.set` after rotating a token in the Cloudflare dashboard is
    /// replacing a credential, and an append-only table would leave the old,
    /// now-revoked token behind for issuance to try first.
    pub async fn save_dns_provider(
        &self,
        kind: DnsProviderKind,
        label: &str,
        credentials_sealed: &str,
    ) -> Result<DnsProvider> {
        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, DnsProviderRow>(
            "INSERT INTO dns_providers (kind, label, credentials_sealed, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT (kind, label) DO UPDATE SET
                 credentials_sealed = ?3, updated_at = ?4
             RETURNING id, kind, label, credentials_sealed",
        )
        .bind(kind.as_str())
        .bind(label)
        .bind(credentials_sealed)
        .bind(&ts)
        .fetch_one(self.pool())
        .await?;
        DnsProvider::try_from(row)
    }

    /// Every stored credential for a provider, oldest first.
    ///
    /// Oldest first is the issuance order, and it is stable: a wildcard that
    /// issued through one token last month must not silently start using a
    /// different one because a row was added.
    pub async fn dns_providers(&self, kind: DnsProviderKind) -> Result<Vec<DnsProvider>> {
        let rows = sqlx::query_as::<_, DnsProviderRow>(
            "SELECT id, kind, label, credentials_sealed FROM dns_providers
             WHERE kind = ?1 ORDER BY id",
        )
        .bind(kind.as_str())
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(DnsProvider::try_from).collect()
    }

    /// Labels only, for the settings screen.
    ///
    /// A separate query rather than a projection of [`Db::dns_providers`] so
    /// that the read path the UI uses never loads a ciphertext into the web
    /// process's memory at all.
    pub async fn dns_provider_labels(&self, kind: DnsProviderKind) -> Result<Vec<String>> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT label FROM dns_providers WHERE kind = ?1 ORDER BY id")
                .bind(kind.as_str())
                .fetch_all(self.pool())
                .await?;
        Ok(rows.into_iter().map(|(label,)| label).collect())
    }

    pub async fn delete_dns_provider(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM dns_providers WHERE id = ?1")
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MasterKey;

    #[tokio::test]
    async fn a_provider_credential_round_trips_sealed() {
        let db = Db::open_memory().await.unwrap();
        let key = MasterKey::generate();
        let sealed = key.seal_str("cf-token-value").unwrap();

        let saved = db
            .save_dns_provider(DnsProviderKind::Cloudflare, "acme-corp", &sealed)
            .await
            .unwrap();
        assert_eq!(saved.label, "acme-corp");
        assert_eq!(saved.kind, DnsProviderKind::Cloudflare);

        let listed = db.dns_providers(DnsProviderKind::Cloudflare).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            key.open_str(&listed[0].credentials_sealed).unwrap(),
            "cf-token-value"
        );
    }

    #[tokio::test]
    async fn the_stored_column_never_holds_the_token_in_the_clear() {
        // The property the whole table exists for: a backup of the panel
        // database, read with `sqlite3`, must not yield a working credential.
        let db = Db::open_memory().await.unwrap();
        let key = MasterKey::generate();
        let sealed = key.seal_str("v1.0-super-secret-token").unwrap();
        db.save_dns_provider(DnsProviderKind::Cloudflare, "one", &sealed)
            .await
            .unwrap();

        let raw: (String,) = sqlx::query_as("SELECT credentials_sealed FROM dns_providers")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert!(!raw.0.contains("super-secret"));
        assert!(raw.0.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn setting_the_same_label_twice_rotates_rather_than_duplicates() {
        // An operator who rotates a token in the Cloudflare dashboard and
        // re-enters it must end up with one credential, not two — the older of
        // which is revoked and would be tried first.
        let db = Db::open_memory().await.unwrap();
        db.save_dns_provider(DnsProviderKind::Cloudflare, "same", "sealed-old")
            .await
            .unwrap();
        db.save_dns_provider(DnsProviderKind::Cloudflare, "same", "sealed-new")
            .await
            .unwrap();

        let listed = db.dns_providers(DnsProviderKind::Cloudflare).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].credentials_sealed, "sealed-new");
    }

    #[tokio::test]
    async fn two_labels_can_hold_two_zone_scoped_tokens() {
        // The reason the unique index is on (kind, label) and not on kind: a
        // token scoped to one zone cannot serve another, so a server hosting
        // two customers' domains needs two tokens.
        let db = Db::open_memory().await.unwrap();
        db.save_dns_provider(DnsProviderKind::Cloudflare, "customer-a", "sealed-a")
            .await
            .unwrap();
        db.save_dns_provider(DnsProviderKind::Cloudflare, "customer-b", "sealed-b")
            .await
            .unwrap();

        let labels = db
            .dns_provider_labels(DnsProviderKind::Cloudflare)
            .await
            .unwrap();
        assert_eq!(labels, vec!["customer-a", "customer-b"]);
    }

    #[tokio::test]
    async fn the_kind_column_refuses_a_provider_this_build_cannot_speak() {
        // The CHECK constraint, exercised: a future provider is a migration and
        // a review, not a string that slips into the table.
        let db = Db::open_memory().await.unwrap();
        let err = sqlx::query(
            "INSERT INTO dns_providers (kind, label, credentials_sealed, created_at, updated_at)
             VALUES ('route53', 'x', 'y', 'z', 'z')",
        )
        .execute(db.pool())
        .await
        .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("constraint"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_corrupt_kind_is_reported_rather_than_guessed() {
        let err = DnsProviderKind::parse("powerdns").unwrap_err();
        assert!(err.to_string().contains("powerdns"), "{err}");
    }
}
