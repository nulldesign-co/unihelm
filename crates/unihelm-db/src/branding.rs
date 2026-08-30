//! White-label branding, per reseller, with the panel default underneath
//! (spec §11.19).
//!
//! # Branding is data, not configuration
//!
//! Nothing in this module renders a file, and that is the whole design. Spec
//! §11.19's acceptance criterion is "switching branding requires no restart",
//! which is only free if branding never becomes a config file in the first
//! place: the panel name, the colour and the images are read out of SQLite on
//! the request that needs them. There is no `ApplyRequest`, no reload, and no
//! window in which the browser and the database disagree.
//!
//! # Inheritance is per field
//!
//! Every column is nullable and every NULL means "inherit from the panel
//! default" — row `reseller_id = 0`. A reseller who has uploaded a logo and
//! nothing else gets the panel's name, colour and support URL, and an operator
//! who later changes the panel's colour changes theirs with it. Partial
//! branding is the common case, so all-or-nothing inheritance would be the
//! wrong default (see [`Db::resolved_branding`]).
//!
//! # The assets are blobs, and they are raster images only
//!
//! Blobs in the panel database rather than files on disk for three reasons: it
//! survives a restore (§11.10 backs up this database), it is readable by the
//! *web* process, which is unprivileged and has no business in a directory the
//! agent writes, and it is bounded to three small images per reseller.
//!
//! The `content_type` column is constrained to five raster types. It records
//! what the panel *sniffed* from the bytes, never what an uploader claimed, and
//! SVG is not in the set — the reasoning lives with the sniffer in
//! `unihelm_ops::branding`, and the CHECK constraint is what makes it
//! unbypassable from any other code path.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// The sentinel row every other row falls back to.
///
/// Zero can never collide with a real account: `users.id` is
/// `INTEGER PRIMARY KEY AUTOINCREMENT`, so the first user is 1.
pub const PANEL_DEFAULT: i64 = 0;

/// Which image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Logo,
    Favicon,
    LoginBackground,
}

impl AssetKind {
    pub const ALL: [AssetKind; 3] = [
        AssetKind::Logo,
        AssetKind::Favicon,
        AssetKind::LoginBackground,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            AssetKind::Logo => "logo",
            AssetKind::Favicon => "favicon",
            AssetKind::LoginBackground => "login_background",
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "logo" => Ok(AssetKind::Logo),
            "favicon" => Ok(AssetKind::Favicon),
            "login_background" => Ok(AssetKind::LoginBackground),
            other => Err(DbError::Corrupt {
                field: "branding_assets.kind",
                detail: format!("`{other}` is not a branding asset kind"),
            }),
        }
    }
}

/// The image formats the panel will store and serve.
///
/// A closed enum rather than a string, so the `Content-Type` a browser sees is
/// chosen from this list by the type system and can never be a value that
/// arrived with an upload. Notably absent: `image/svg+xml`. An SVG is an XML
/// document that can carry `<script>`, event handlers and `<foreignObject>`
/// HTML, so serving one from the panel's own origin is script execution in the
/// panel's origin — see `unihelm_ops::branding::sniff_image`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageType {
    Png,
    Jpeg,
    Gif,
    Webp,
    Icon,
}

impl ImageType {
    pub const fn content_type(self) -> &'static str {
        match self {
            ImageType::Png => "image/png",
            ImageType::Jpeg => "image/jpeg",
            ImageType::Gif => "image/gif",
            ImageType::Webp => "image/webp",
            ImageType::Icon => "image/x-icon",
        }
    }

    pub fn parse(content_type: &str) -> Result<Self> {
        match content_type {
            "image/png" => Ok(ImageType::Png),
            "image/jpeg" => Ok(ImageType::Jpeg),
            "image/gif" => Ok(ImageType::Gif),
            "image/webp" => Ok(ImageType::Webp),
            "image/x-icon" => Ok(ImageType::Icon),
            other => Err(DbError::Corrupt {
                field: "branding_assets.content_type",
                detail: format!("`{other}` is not a stored image type"),
            }),
        }
    }
}

/// One reseller's stored branding, before inheritance is applied.
///
/// Every field is `Option` and every `None` means "inherit". Use
/// [`Db::resolved_branding`] to get the values a browser should actually see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Branding {
    pub reseller_id: i64,
    pub panel_name: Option<String>,
    pub support_url: Option<String>,
    pub primary_color: Option<String>,
    pub login_host: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// The values after inheritance: what the login page and the panel chrome use.
///
/// The asset flags say only *whether* an image exists, and for whom. They are
/// not URLs, because the URL is the web layer's business, and they are not
/// bytes, because this struct crosses the IPC boundary as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedBranding {
    /// Whose branding this is. Equal to [`PANEL_DEFAULT`] when the reseller
    /// has no row of their own, which is how a caller can tell "inherited
    /// everything" from "set everything to the same values".
    pub reseller_id: i64,
    pub panel_name: Option<String>,
    pub support_url: Option<String>,
    pub primary_color: Option<String>,
    /// For each asset kind that resolves to something, the reseller whose
    /// upload it is — the reseller themselves, or [`PANEL_DEFAULT`].
    pub assets: Vec<ResolvedAsset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedAsset {
    pub kind: AssetKind,
    pub owner_id: i64,
    pub content_type: &'static str,
    /// Hex sha256 of the bytes. The web layer serves it as an `ETag` so a
    /// browser that already has the logo does not refetch it on every visit to
    /// the login page.
    pub sha256: String,
    pub size_bytes: i64,
}

/// A stored image, bytes and all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandingAsset {
    pub reseller_id: i64,
    pub kind: AssetKind,
    pub image_type: ImageType,
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub updated_at: OffsetDateTime,
}

/// Branding on its way in. `None` fields are left as they are; use the
/// dedicated clear flags to set one back to "inherit".
#[derive(Debug, Clone, Default)]
pub struct BrandingUpdate {
    pub panel_name: Option<String>,
    pub support_url: Option<String>,
    pub primary_color: Option<String>,
    pub login_host: Option<String>,
    /// Field names to reset to NULL, i.e. back to inheriting.
    pub clear: Vec<BrandingField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrandingField {
    PanelName,
    SupportUrl,
    PrimaryColor,
    LoginHost,
}

#[derive(Debug, sqlx::FromRow)]
struct BrandingRow {
    reseller_id: i64,
    panel_name: Option<String>,
    support_url: Option<String>,
    primary_color: Option<String>,
    login_host: Option<String>,
    updated_at: String,
}

impl TryFrom<BrandingRow> for Branding {
    type Error = DbError;

    fn try_from(r: BrandingRow) -> Result<Self> {
        Ok(Branding {
            reseller_id: r.reseller_id,
            panel_name: r.panel_name,
            support_url: r.support_url,
            primary_color: r.primary_color,
            login_host: r.login_host,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AssetRow {
    reseller_id: i64,
    kind: String,
    content_type: String,
    bytes: Vec<u8>,
    sha256: String,
    updated_at: String,
}

#[derive(Debug, sqlx::FromRow)]
struct AssetMetaRow {
    reseller_id: i64,
    kind: String,
    content_type: String,
    sha256: String,
    size_bytes: i64,
}

const SELECT_BRANDING: &str = "SELECT reseller_id, panel_name, support_url, primary_color, \
     login_host, updated_at FROM branding WHERE reseller_id = ?1";

impl Db {
    /// One reseller's own row, without inheritance.
    pub async fn branding(&self, reseller_id: i64) -> Result<Option<Branding>> {
        let row = sqlx::query_as::<_, BrandingRow>(SELECT_BRANDING)
            .bind(reseller_id)
            .fetch_optional(self.pool())
            .await?;
        row.map(Branding::try_from).transpose()
    }

    /// Upsert one reseller's branding.
    ///
    /// Field-at-a-time: a `None` in the update leaves the stored value alone,
    /// and an entry in `clear` sets it to NULL. Two separate mechanisms
    /// because "do not change the name" and "go back to inheriting the name"
    /// are different intentions, and a single `Option<Option<String>>` in the
    /// wire format is a shape nobody gets right by accident.
    pub async fn save_branding(
        &self,
        reseller_id: i64,
        update: BrandingUpdate,
    ) -> Result<Branding> {
        let existing = self.branding(reseller_id).await?;

        let pick = |field: BrandingField, incoming: Option<String>, current: Option<String>| {
            if update.clear.contains(&field) {
                None
            } else {
                incoming.or(current)
            }
        };

        let (name, support, colour, host) = match existing {
            Some(b) => (
                pick(BrandingField::PanelName, update.panel_name, b.panel_name),
                pick(BrandingField::SupportUrl, update.support_url, b.support_url),
                pick(
                    BrandingField::PrimaryColor,
                    update.primary_color,
                    b.primary_color,
                ),
                pick(BrandingField::LoginHost, update.login_host, b.login_host),
            ),
            None => (
                pick(BrandingField::PanelName, update.panel_name, None),
                pick(BrandingField::SupportUrl, update.support_url, None),
                pick(BrandingField::PrimaryColor, update.primary_color, None),
                pick(BrandingField::LoginHost, update.login_host, None),
            ),
        };

        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, BrandingRow>(
            "INSERT INTO branding (reseller_id, panel_name, support_url, primary_color, \
                 login_host, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (reseller_id) DO UPDATE SET
                 panel_name = ?2, support_url = ?3, primary_color = ?4,
                 login_host = ?5, updated_at = ?6
             RETURNING reseller_id, panel_name, support_url, primary_color, login_host, updated_at",
        )
        .bind(reseller_id)
        .bind(&name)
        .bind(&support)
        .bind(&colour)
        .bind(&host)
        .bind(&ts)
        .fetch_one(self.pool())
        .await?;
        Branding::try_from(row)
    }

    /// The branding a reseller's users should actually see.
    ///
    /// Their own values where they have them, the panel default underneath,
    /// field by field — including the images.
    pub async fn resolved_branding(&self, reseller_id: i64) -> Result<ResolvedBranding> {
        let own = if reseller_id == PANEL_DEFAULT {
            None
        } else {
            self.branding(reseller_id).await?
        };
        let default = self.branding(PANEL_DEFAULT).await?;

        let inherit = |own: Option<String>, base: &Option<String>| own.or_else(|| base.clone());
        let (own_name, own_support, own_colour) = match &own {
            Some(b) => (
                b.panel_name.clone(),
                b.support_url.clone(),
                b.primary_color.clone(),
            ),
            None => (None, None, None),
        };
        let (base_name, base_support, base_colour) = match &default {
            Some(b) => (
                b.panel_name.clone(),
                b.support_url.clone(),
                b.primary_color.clone(),
            ),
            None => (None, None, None),
        };

        let mut assets = Vec::new();
        for meta in self.asset_metadata(reseller_id).await? {
            assets.push(meta);
        }

        Ok(ResolvedBranding {
            reseller_id: own.as_ref().map_or(PANEL_DEFAULT, |b| b.reseller_id),
            panel_name: inherit(own_name, &base_name),
            support_url: inherit(own_support, &base_support),
            primary_color: inherit(own_colour, &base_colour),
            assets,
        })
    }

    /// Which images resolve for a reseller, and whose they are.
    ///
    /// One query over both owners rather than two round trips per kind: three
    /// kinds times two owners would be six queries on the login page, which is
    /// the one page that must be fast before anybody is authenticated.
    async fn asset_metadata(&self, reseller_id: i64) -> Result<Vec<ResolvedAsset>> {
        let rows = sqlx::query_as::<_, AssetMetaRow>(
            "SELECT reseller_id, kind, content_type, sha256, size_bytes
             FROM branding_assets WHERE reseller_id IN (?1, ?2)",
        )
        .bind(reseller_id)
        .bind(PANEL_DEFAULT)
        .fetch_all(self.pool())
        .await?;

        let mut out: Vec<ResolvedAsset> = Vec::new();
        for row in rows {
            let kind = AssetKind::parse(&row.kind)?;
            let image = ImageType::parse(&row.content_type)?;
            let resolved = ResolvedAsset {
                kind,
                owner_id: row.reseller_id,
                content_type: image.content_type(),
                sha256: row.sha256,
                size_bytes: row.size_bytes,
            };
            match out.iter_mut().find(|a| a.kind == kind) {
                // The reseller's own upload wins over the panel default. Which
                // row arrived first is not something SQLite promises, so the
                // preference is decided here rather than by an ORDER BY.
                Some(existing) if existing.owner_id == PANEL_DEFAULT => *existing = resolved,
                Some(_) => {}
                None => out.push(resolved),
            }
        }
        out.sort_by_key(|a| a.kind);
        Ok(out)
    }

    /// Whose branding a hostname belongs to.
    ///
    /// The lookup behind `GET /api/branding`, the one endpoint that answers
    /// without a session. `host` is taken from the `Host` header, which is
    /// attacker-controlled — so this is an exact match against a stored value
    /// and nothing else. The worst a forged header can do is show the caller a
    /// different reseller's logo, which is public information the moment that
    /// reseller's own customers can see it.
    pub async fn branding_for_login_host(&self, host: &str) -> Result<Option<Branding>> {
        let normalized = normalize_login_host(host);
        if normalized.is_empty() {
            return Ok(None);
        }
        let row = sqlx::query_as::<_, BrandingRow>(
            "SELECT reseller_id, panel_name, support_url, primary_color, login_host, updated_at
             FROM branding WHERE login_host = ?1",
        )
        .bind(&normalized)
        .fetch_optional(self.pool())
        .await?;
        row.map(Branding::try_from).transpose()
    }

    /// Store or replace one image.
    pub async fn save_branding_asset(
        &self,
        reseller_id: i64,
        kind: AssetKind,
        image_type: ImageType,
        bytes: &[u8],
        sha256: &str,
    ) -> Result<()> {
        let ts = to_sql_time(now());
        sqlx::query(
            "INSERT INTO branding_assets (reseller_id, kind, content_type, bytes, sha256, \
                 size_bytes, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (reseller_id, kind) DO UPDATE SET
                 content_type = ?3, bytes = ?4, sha256 = ?5, size_bytes = ?6, updated_at = ?7",
        )
        .bind(reseller_id)
        .bind(kind.as_str())
        .bind(image_type.content_type())
        .bind(bytes)
        .bind(sha256)
        .bind(i64::try_from(bytes.len()).unwrap_or(i64::MAX))
        .bind(&ts)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn delete_branding_asset(&self, reseller_id: i64, kind: AssetKind) -> Result<bool> {
        let result =
            sqlx::query("DELETE FROM branding_assets WHERE reseller_id = ?1 AND kind = ?2")
                .bind(reseller_id)
                .bind(kind.as_str())
                .execute(self.pool())
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// One image's bytes, falling back to the panel default.
    ///
    /// The fallback is the point: a reseller who has set a name and a colour
    /// but no logo must still get *a* logo, and it has to be the panel's.
    pub async fn branding_asset(
        &self,
        reseller_id: i64,
        kind: AssetKind,
    ) -> Result<Option<BrandingAsset>> {
        for owner in [reseller_id, PANEL_DEFAULT] {
            let row = sqlx::query_as::<_, AssetRow>(
                "SELECT reseller_id, kind, content_type, bytes, sha256, updated_at
                 FROM branding_assets WHERE reseller_id = ?1 AND kind = ?2",
            )
            .bind(owner)
            .bind(kind.as_str())
            .fetch_optional(self.pool())
            .await?;
            if let Some(r) = row {
                return Ok(Some(BrandingAsset {
                    reseller_id: r.reseller_id,
                    kind: AssetKind::parse(&r.kind)?,
                    image_type: ImageType::parse(&r.content_type)?,
                    bytes: r.bytes,
                    sha256: r.sha256,
                    updated_at: from_sql_time(&r.updated_at)?,
                }));
            }
            if owner == PANEL_DEFAULT {
                break;
            }
        }
        Ok(None)
    }
}

/// Reduce a `Host` header to the form stored in `branding.login_host`.
///
/// Lowercased, port stripped, IPv6 brackets kept intact, trailing dot removed.
/// A hostname is case-insensitive and `panel.example.com:8443` is the same host
/// as `panel.example.com`; storing one spelling and comparing another would
/// silently mean "branding only works on the default port".
pub fn normalize_login_host(host: &str) -> String {
    let host = host.trim();
    // `[::1]:8443` — the colon that separates the port is the one after the
    // closing bracket, so a naive `split(':')` would cut an IPv6 literal in
    // half and store something that matches nothing.
    let without_port = if let Some(rest) = host.strip_prefix('[') {
        // `rest` starts one byte into `host`, and the slice must keep the
        // closing bracket: `+ 1` for the offset, `+ 1` for the bracket itself.
        match rest.find(']') {
            Some(end) => &host[..end + 2],
            None => host,
        }
    } else {
        host.split(':').next().unwrap_or(host)
    };
    without_port.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nfake";

    fn update(name: &str) -> BrandingUpdate {
        BrandingUpdate {
            panel_name: Some(name.to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_fresh_panel_resolves_to_nothing_rather_than_failing() {
        // The login page renders before anybody has configured anything.
        let db = Db::open_memory().await.unwrap();
        let resolved = db.resolved_branding(PANEL_DEFAULT).await.unwrap();
        assert_eq!(resolved.panel_name, None);
        assert!(resolved.assets.is_empty());
    }

    #[tokio::test]
    async fn a_reseller_inherits_each_unset_field_from_the_panel_default() {
        let db = Db::open_memory().await.unwrap();
        db.save_branding(
            PANEL_DEFAULT,
            BrandingUpdate {
                panel_name: Some("Unihelm".into()),
                primary_color: Some("#3b82f6".into()),
                support_url: Some("https://support.example".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        db.save_branding(7, update("Acme Hosting")).await.unwrap();

        let resolved = db.resolved_branding(7).await.unwrap();
        assert_eq!(resolved.panel_name.as_deref(), Some("Acme Hosting"));
        // Inherited, field by field — not all-or-nothing.
        assert_eq!(resolved.primary_color.as_deref(), Some("#3b82f6"));
        assert_eq!(
            resolved.support_url.as_deref(),
            Some("https://support.example")
        );
    }

    #[tokio::test]
    async fn clearing_a_field_goes_back_to_inheriting_rather_than_to_empty() {
        let db = Db::open_memory().await.unwrap();
        db.save_branding(PANEL_DEFAULT, update("Unihelm"))
            .await
            .unwrap();
        db.save_branding(7, update("Acme Hosting")).await.unwrap();
        db.save_branding(
            7,
            BrandingUpdate {
                clear: vec![BrandingField::PanelName],
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            db.resolved_branding(7).await.unwrap().panel_name.as_deref(),
            Some("Unihelm"),
        );
    }

    #[tokio::test]
    async fn an_update_that_mentions_no_field_changes_nothing() {
        // The shape a UI sends when only the logo was touched.
        let db = Db::open_memory().await.unwrap();
        db.save_branding(7, update("Acme Hosting")).await.unwrap();
        db.save_branding(7, BrandingUpdate::default())
            .await
            .unwrap();
        assert_eq!(
            db.branding(7).await.unwrap().unwrap().panel_name.as_deref(),
            Some("Acme Hosting"),
        );
    }

    #[tokio::test]
    async fn a_resellers_own_logo_wins_over_the_panel_default() {
        let db = Db::open_memory().await.unwrap();
        db.save_branding_asset(PANEL_DEFAULT, AssetKind::Logo, ImageType::Png, PNG, "aa")
            .await
            .unwrap();
        db.save_branding_asset(7, AssetKind::Logo, ImageType::Gif, b"GIF89a!", "bb")
            .await
            .unwrap();

        let asset = db
            .branding_asset(7, AssetKind::Logo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(asset.reseller_id, 7);
        assert_eq!(asset.image_type, ImageType::Gif);

        let resolved = db.resolved_branding(7).await.unwrap();
        let logo = resolved
            .assets
            .iter()
            .find(|a| a.kind == AssetKind::Logo)
            .unwrap();
        assert_eq!(logo.owner_id, 7);
    }

    #[tokio::test]
    async fn a_reseller_without_a_logo_falls_back_to_the_panels() {
        let db = Db::open_memory().await.unwrap();
        db.save_branding_asset(PANEL_DEFAULT, AssetKind::Logo, ImageType::Png, PNG, "aa")
            .await
            .unwrap();

        let asset = db
            .branding_asset(7, AssetKind::Logo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(asset.reseller_id, PANEL_DEFAULT);
        let resolved = db.resolved_branding(7).await.unwrap();
        assert_eq!(resolved.assets.len(), 1);
        assert_eq!(resolved.assets[0].owner_id, PANEL_DEFAULT);
    }

    #[tokio::test]
    async fn deleting_a_resellers_asset_uncovers_the_panel_default_again() {
        let db = Db::open_memory().await.unwrap();
        db.save_branding_asset(PANEL_DEFAULT, AssetKind::Logo, ImageType::Png, PNG, "aa")
            .await
            .unwrap();
        db.save_branding_asset(7, AssetKind::Logo, ImageType::Png, PNG, "bb")
            .await
            .unwrap();
        assert!(db.delete_branding_asset(7, AssetKind::Logo).await.unwrap());

        let asset = db
            .branding_asset(7, AssetKind::Logo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(asset.reseller_id, PANEL_DEFAULT);
    }

    #[tokio::test]
    async fn uploading_the_same_kind_twice_replaces_it_rather_than_accumulating() {
        let db = Db::open_memory().await.unwrap();
        db.save_branding_asset(7, AssetKind::Logo, ImageType::Png, PNG, "aa")
            .await
            .unwrap();
        db.save_branding_asset(7, AssetKind::Logo, ImageType::Gif, b"GIF89a!", "bb")
            .await
            .unwrap();
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM branding_assets")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    #[tokio::test]
    async fn a_login_host_resolves_to_its_reseller_whatever_port_the_browser_used() {
        let db = Db::open_memory().await.unwrap();
        db.save_branding(
            7,
            BrandingUpdate {
                login_host: Some("panel.acme.example".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        for header in [
            "panel.acme.example",
            "panel.acme.example:8443",
            "PANEL.Acme.Example",
            "panel.acme.example.",
        ] {
            let found = db.branding_for_login_host(header).await.unwrap();
            assert_eq!(found.map(|b| b.reseller_id), Some(7), "for {header:?}");
        }
    }

    #[tokio::test]
    async fn an_unknown_or_forged_host_header_resolves_to_nothing() {
        // The Host header is attacker-controlled. The only thing it may do is
        // select a public logo; an unmatched value must resolve to the panel
        // default rather than to an error or to the last row inserted.
        let db = Db::open_memory().await.unwrap();
        db.save_branding(
            7,
            BrandingUpdate {
                login_host: Some("panel.acme.example".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        for header in [
            "",
            "  ",
            "evil.example",
            "panel.acme.example.evil.test",
            "'",
        ] {
            assert!(
                db.branding_for_login_host(header).await.unwrap().is_none(),
                "{header:?} must not match",
            );
        }
    }

    #[tokio::test]
    async fn two_resellers_cannot_claim_the_same_login_host() {
        // Otherwise the pre-session lookup has two answers and picks one at
        // SQLite's discretion.
        let db = Db::open_memory().await.unwrap();
        db.save_branding(
            7,
            BrandingUpdate {
                login_host: Some("panel.acme.example".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let err = db
            .save_branding(
                8,
                BrandingUpdate {
                    login_host: Some("panel.acme.example".into()),
                    ..Default::default()
                },
            )
            .await;
        assert!(
            err.is_err(),
            "the unique index must reject the second claim"
        );
    }

    #[tokio::test]
    async fn a_colour_that_is_not_a_hex_triple_is_refused_by_the_schema() {
        // The value reaches a browser inside a CSS custom property. The
        // operation layer validates it too; this is the check that survives a
        // code path nobody thought of.
        let db = Db::open_memory().await.unwrap();
        for bad in ["red", "#fff", "#12345g", "#3b82f6; background:url(x)"] {
            let err = db
                .save_branding(
                    7,
                    BrandingUpdate {
                        primary_color: Some(bad.into()),
                        ..Default::default()
                    },
                )
                .await;
            assert!(err.is_err(), "{bad:?} must not be storable");
        }
        assert!(
            db.save_branding(
                7,
                BrandingUpdate {
                    primary_color: Some("#3b82f6".into()),
                    ..Default::default()
                },
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn a_content_type_outside_the_raster_set_is_refused_by_the_schema() {
        // The CHECK is the last line of defence for "no SVG": it holds even if
        // a future code path forgets to sniff.
        let db = Db::open_memory().await.unwrap();
        let err = sqlx::query(
            "INSERT INTO branding_assets (reseller_id, kind, content_type, bytes, sha256, \
                 size_bytes, updated_at)
             VALUES (7, 'logo', 'image/svg+xml', x'3c737667', 'aa', 4, '2026-01-01T00:00:00Z')",
        )
        .execute(db.pool())
        .await;
        assert!(err.is_err(), "image/svg+xml must not be storable");
    }

    #[test]
    fn an_ipv6_host_header_survives_normalisation() {
        assert_eq!(normalize_login_host("[::1]:8443"), "[::1]");
        assert_eq!(normalize_login_host("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(normalize_login_host("Example.COM:443"), "example.com");
        assert_eq!(normalize_login_host(" example.com. "), "example.com");
    }

    #[test]
    fn every_asset_kind_round_trips_through_its_column_value() {
        for kind in AssetKind::ALL {
            assert_eq!(AssetKind::parse(kind.as_str()).unwrap(), kind);
        }
        assert!(AssetKind::parse("banner").is_err());
    }

    #[test]
    fn no_image_type_maps_to_a_scriptable_content_type() {
        for t in [
            ImageType::Png,
            ImageType::Jpeg,
            ImageType::Gif,
            ImageType::Webp,
            ImageType::Icon,
        ] {
            let ct = t.content_type();
            assert!(ct.starts_with("image/"), "{ct}");
            assert!(
                !ct.contains("svg"),
                "{ct} would be scriptable in our origin"
            );
            assert!(!ct.contains("xml"), "{ct}");
            assert_eq!(ImageType::parse(ct).unwrap(), t);
        }
        assert!(ImageType::parse("image/svg+xml").is_err());
        assert!(ImageType::parse("text/html").is_err());
    }
}
