//! White-label branding (spec §11.19).
//!
//! # Branding is data, so it applies without a restart
//!
//! Nothing in this module renders a file, reloads a service or touches
//! `/etc`. Spec §11.19's acceptance criterion is "switching branding requires
//! no restart", and the cheapest way to guarantee that is never to make
//! branding configuration in the first place: the panel name, the colour and
//! the images are rows the next request reads. There is no window in which the
//! browser and the database disagree, and there is nothing to roll back.
//!
//! # SVG is refused, and it is also neutered
//!
//! An uploaded image is served back from the panel's own origin, so the format
//! question is a script-execution question. SVG is not an image format in the
//! sense that matters here: it is an XML document that may contain `<script>`,
//! `onload=` handlers, `<foreignObject>` with arbitrary HTML, and external
//! references. A logo an attacker could upload and then persuade an
//! administrator to open would run in the panel's origin with the
//! administrator's session cookie.
//!
//! **The choice made here is to refuse SVG entirely**, in [`sniff_image`], and
//! to serve what is accepted under a `Content-Security-Policy` that would
//! neuter it anyway. Both, not either:
//!
//! - refusing is the part that is provable. The accepted set is five raster
//!   formats, matched on their magic bytes, and the database `CHECK` constraint
//!   agrees, so no other code path can reintroduce SVG;
//! - the CSP is the part that survives a mistake. A polyglot file — valid PNG
//!   by its first eight bytes and valid HTML to a sniffing browser — is the
//!   attack that beats format checks, and `X-Content-Type-Options: nosniff`
//!   plus `default-src 'none'; sandbox` is what makes it inert. That header set
//!   lives with the route that serves the bytes.
//!
//! Refusing rather than sanitising is deliberate. Sanitising SVG is an
//! open-ended arms race against a parser differential; a hosting panel does not
//! need to win it to let somebody upload a logo.
//!
//! # Two fields are injection sites, not decoration
//!
//! `primary_color` is interpolated into a CSS custom property and
//! `support_url` into an anchor's `href`. A colour that is not exactly
//! `#rrggbb` would be a stylesheet injection; a URL with a `javascript:` scheme
//! would be script execution on click, in the panel's origin, on a page a
//! reseller's customer is looking at. Both are validated here, and the colour
//! is validated a second time by the schema.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unihelm_core::{ErrorCode, Permission, Result, Role, TenantScope, UnihelmError};
use unihelm_db::branding::PANEL_DEFAULT;
use unihelm_db::{AssetKind, BrandingField, BrandingUpdate, ImageType, ResolvedBranding};

use crate::registry::{Execution, OpContext, TypedOperation};

/// Per-kind upload ceilings, in bytes.
///
/// Chosen from what the asset is *for* rather than from a round number: a
/// favicon that is not tiny is a mistake, a header logo lives at a couple of
/// hundred pixels tall, and a login background is the one image that can
/// legitimately be a photograph. The bytes live in the panel database and are
/// served on the unauthenticated login page, so an unbounded upload would be
/// both a disk-growth and a bandwidth problem.
pub const fn max_bytes(kind: AssetKind) -> usize {
    match kind {
        AssetKind::Favicon => 64 * 1024,
        AssetKind::Logo => 512 * 1024,
        AssetKind::LoginBackground => 2 * 1024 * 1024,
    }
}

/// Largest pixel dimension any branding image may declare.
///
/// Read out of the file header where the format makes that cheap. A 40000 ×
/// 40000 PNG compresses to a few kilobytes and expands to gigabytes in the
/// browser that decodes it — a size cap alone does not catch that.
pub const MAX_DIMENSION: u32 = 8192;

// ---------------------------------------------------------------------------
// content sniffing
// ---------------------------------------------------------------------------

/// Decide what an upload actually is, from its bytes.
///
/// The filename and any client-supplied content type are ignored entirely —
/// they are the uploader's claim, and this is the panel's finding. Only the
/// five raster formats below are accepted; everything else, SVG loudly
/// included, is refused with a message that says why.
pub fn sniff_image(bytes: &[u8]) -> Result<ImageType> {
    let refuse = |detail: String| {
        Err::<ImageType, UnihelmError>(
            UnihelmError::new(ErrorCode::InvalidInput, detail).with_field("content_b64"),
        )
    };

    if bytes.len() < 12 {
        return refuse("that file is too small to be an image".into());
    }

    // Checked before the raster magics so the message can be specific. An SVG
    // may start with `<svg`, with an XML declaration, with a comment, or with
    // a byte-order mark — so the test is "does this look like markup at all",
    // not "does it start with <svg".
    if looks_like_markup(bytes) {
        return refuse(
            "that file is XML or HTML — most likely an SVG. Unihelm does not accept SVG for \
             branding: an SVG is a document that can carry scripts and event handlers, and it \
             would be served from the panel's own origin. Upload a PNG, JPEG, GIF, WebP or ICO."
                .into(),
        );
    }

    let image = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        ImageType::Png
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        ImageType::Jpeg
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        ImageType::Gif
    } else if bytes.starts_with(b"RIFF") && bytes[8..12] == *b"WEBP" {
        ImageType::Webp
    } else if bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        ImageType::Icon
    } else {
        return refuse(
            "that file is not a PNG, JPEG, GIF, WebP or ICO. The check is on the file's own \
             bytes, not on its name, so renaming it will not help."
                .into(),
        );
    };

    if let Some((width, height)) = dimensions(image, bytes)
        && (width > MAX_DIMENSION || height > MAX_DIMENSION)
    {
        return refuse(format!(
            "that image declares {width}×{height} pixels; the limit is {MAX_DIMENSION} on each \
             side. A very large image costs the browser that decodes it far more memory than \
             its file size suggests."
        ));
    }

    Ok(image)
}

/// Does this look like an XML or HTML document rather than a binary image?
///
/// Leading whitespace and a UTF-8 byte-order mark are skipped first, because
/// both are legal in front of an XML declaration and neither is legal at the
/// start of any format accepted here.
fn looks_like_markup(bytes: &[u8]) -> bool {
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let start = body
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(body.len());
    body.get(start) == Some(&b'<')
}

/// Pixel dimensions, where the header makes them cheap to read.
///
/// PNG and GIF only. JPEG needs a segment walk and WebP has three container
/// variants; neither is worth the parser, and the byte cap still bounds them.
/// Returning `None` means "not checked", never "fine".
fn dimensions(image: ImageType, bytes: &[u8]) -> Option<(u32, u32)> {
    match image {
        // IHDR is the first chunk and always at a fixed offset: 8 bytes of
        // signature, 4 of length, 4 of type, then width and height.
        ImageType::Png if bytes.len() >= 24 => {
            let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
            let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
            Some((width, height))
        }
        // The GIF logical screen descriptor, little-endian, right after the
        // six-byte signature.
        ImageType::Gif if bytes.len() >= 10 => {
            let width = u16::from_le_bytes(bytes[6..8].try_into().ok()?);
            let height = u16::from_le_bytes(bytes[8..10].try_into().ok()?);
            Some((u32::from(width), u32::from(height)))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// field validation
// ---------------------------------------------------------------------------

/// Accept `#rrggbb`, and nothing else.
///
/// Not `rgb()`, not a named colour, not three-digit shorthand. The value is
/// interpolated into a CSS custom property, so the grammar has to be one this
/// function can state completely — "anything a browser would accept as a
/// colour" is not such a grammar, and `#3b82f6; background: url(//evil)` is
/// what the difference looks like.
pub fn parse_colour(input: &str) -> Result<String> {
    let value = input.trim().to_ascii_lowercase();
    let ok = value.len() == 7
        && value.starts_with('#')
        && value[1..].chars().all(|c| c.is_ascii_hexdigit());
    if !ok {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "a colour must be exactly `#rrggbb` — six hexadecimal digits after a hash",
        )
        .with_field("primary_color"));
    }
    Ok(value)
}

/// Accept an `http:` or `https:` absolute URL.
///
/// The scheme allowlist is the whole point. This value becomes an anchor's
/// `href` on a page a reseller's customers see, so `javascript:`, `data:` and
/// `vbscript:` are script execution in the panel's origin, one click away.
/// Relative URLs are refused too: a support link that resolves inside the panel
/// is not a support link.
pub fn parse_support_url(input: &str) -> Result<String> {
    let value = input.trim();
    let invalid = |detail: &str| {
        UnihelmError::new(ErrorCode::InvalidInput, detail.to_string()).with_field("support_url")
    };
    if value.is_empty() || value.len() > 512 {
        return Err(invalid(
            "a support URL must be between 1 and 512 characters",
        ));
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(invalid(
            "a URL may not contain whitespace or control characters",
        ));
    }
    let lowered = value.to_ascii_lowercase();
    if !(lowered.starts_with("https://") || lowered.starts_with("http://")) {
        return Err(invalid(
            "a support URL must start with `https://` or `http://`. Any other scheme — \
             `javascript:` above all — would run as a link on the login page.",
        ));
    }
    // `https://` is eight characters; something has to follow it.
    if lowered.len() <= "https://".len() && lowered.starts_with("https://") {
        return Err(invalid("that URL has no host"));
    }
    if lowered
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .is_empty()
    {
        return Err(invalid("that URL has no host"));
    }
    Ok(value.to_string())
}

/// Accept a panel name.
///
/// React escapes it on render, so this is not an XSS boundary — it is a
/// "somebody pasted a novel into the field" boundary, plus the usual refusal of
/// control characters, which would otherwise show up in a `<title>` and in
/// notification subjects.
pub fn parse_panel_name(input: &str) -> Result<String> {
    let value = input.trim();
    if value.is_empty() || value.chars().count() > 64 {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "a panel name must be between 1 and 64 characters",
        )
        .with_field("panel_name"));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "a panel name may not contain control characters",
        )
        .with_field("panel_name"));
    }
    Ok(value.to_string())
}

/// Accept a login hostname.
///
/// Stored lowercase and without a port, because that is the form the
/// pre-session lookup compares a `Host` header against.
pub fn parse_login_host(input: &str) -> Result<String> {
    let value = unihelm_db::branding::normalize_login_host(input);
    let invalid = |detail: &str| {
        UnihelmError::new(ErrorCode::InvalidInput, detail.to_string()).with_field("login_host")
    };
    if value.is_empty() || value.len() > 253 {
        return Err(invalid("a login host must be between 1 and 253 characters"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    {
        return Err(invalid(
            "a login host may contain only letters, digits, dots and hyphens",
        ));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// who may brand what
// ---------------------------------------------------------------------------

/// Which branding row this caller is allowed to write.
///
/// An admin writes the panel default, or a named reseller's row when they say
/// so. A reseller writes their own row and nothing else — the id comes from
/// their authenticated scope, never from the request, so `reseller_id` in a
/// body they control cannot move the write onto somebody else's branding.
pub fn target_reseller(ctx: &OpContext, requested: Option<i64>) -> Result<i64> {
    match ctx.auth().acting_role {
        Role::Admin => Ok(requested.unwrap_or(PANEL_DEFAULT)),
        Role::Reseller => {
            let own = match ctx.scope() {
                TenantScope::Reseller { reseller_id } => reseller_id.get(),
                // A reseller whose scope is not a reseller scope is a state
                // that should not exist; refusing beats guessing.
                _ => {
                    return Err(UnihelmError::new(
                        ErrorCode::PermissionDenied,
                        "this account has no reseller scope to brand",
                    ));
                }
            };
            match requested {
                None => Ok(own),
                Some(id) if id == own => Ok(own),
                // Deliberately `not_found` rather than `permission_denied`:
                // the same answer another reseller's non-existent row would
                // give, so this cannot be used to enumerate resellers.
                Some(_) => Err(UnihelmError::not_found("branding")),
            }
        }
        Role::Customer => Err(UnihelmError::new(
            ErrorCode::PermissionDenied,
            "branding belongs to the panel operator and to resellers",
        )),
    }
}

// ---------------------------------------------------------------------------
// `branding.get`
// ---------------------------------------------------------------------------

/// `branding.get` — the stored branding for one owner, and what it resolves to.
pub struct Get;

#[derive(Debug, Deserialize)]
pub struct GetInput {
    /// Admin only. A reseller always reads their own.
    #[serde(default)]
    pub reseller_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct GetOutput {
    /// Whose branding this is.
    pub reseller_id: i64,
    /// The row as stored: a `None` field means "inherits".
    pub own: Option<unihelm_db::Branding>,
    /// What a browser would actually see, after inheritance.
    pub resolved: ResolvedBranding,
    /// Bytes each kind may be, so the UI can refuse a too-large file before
    /// spending a round trip on it.
    pub limits: Vec<AssetLimit>,
    /// The formats accepted, in the panel's words, so the UI does not keep its
    /// own copy of the list.
    pub accepted_formats: Vec<&'static str>,
    /// Why SVG is not in that list.
    pub svg_note: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AssetLimit {
    pub kind: AssetKind,
    pub max_bytes: usize,
}

const SVG_NOTE: &str = "SVG is refused. An SVG is an XML document that can carry scripts and event handlers, and a \
     branding image is served from the panel's own origin — so an SVG logo would be script \
     execution against whoever opened it. Uploads are identified by their bytes, not by their \
     filename.";

fn limits() -> Vec<AssetLimit> {
    AssetKind::ALL
        .into_iter()
        .map(|kind| AssetLimit {
            kind,
            max_bytes: max_bytes(kind),
        })
        .collect()
}

#[async_trait]
impl TypedOperation for Get {
    type Input = GetInput;
    type Output = GetOutput;

    const NAME: &'static str = "branding.get";
    // Not `ServerManage`: a reseller must be able to read and write their own
    // branding, and `UserManage` is the permission a reseller holds over the
    // accounts below them. An admin holds it too.
    const PERMISSION: Permission = Permission::UserManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let reseller_id = target_reseller(ctx, input.reseller_id)?;
        let db = ctx.db();
        Ok(GetOutput {
            reseller_id,
            own: db.branding(reseller_id).await.map_err(UnihelmError::from)?,
            resolved: db
                .resolved_branding(reseller_id)
                .await
                .map_err(UnihelmError::from)?,
            limits: limits(),
            accepted_formats: vec![
                "image/png",
                "image/jpeg",
                "image/gif",
                "image/webp",
                "image/x-icon",
            ],
            svg_note: SVG_NOTE,
        })
    }
}

// ---------------------------------------------------------------------------
// `branding.set`
// ---------------------------------------------------------------------------

/// What to do with one image.
///
/// An explicit three-state enum rather than `Option<Option<String>>`: "leave
/// the logo alone" and "go back to the panel's logo" are different intentions,
/// and a wire format that expresses the difference as a missing key versus a
/// null is one nobody gets right by accident.
#[derive(Debug, Default, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AssetChange {
    #[default]
    Keep,
    /// Remove this owner's image, uncovering the panel default underneath.
    Clear,
    /// Replace it. The bytes arrive base64-encoded inside the operation JSON,
    /// the same way file-manager content does (spec §11.7) — one transport for
    /// binary payloads rather than two.
    Set { content_b64: String },
}

#[derive(Debug, Deserialize)]
pub struct SetInput {
    #[serde(default)]
    pub reseller_id: Option<i64>,
    #[serde(default)]
    pub panel_name: Option<String>,
    #[serde(default)]
    pub support_url: Option<String>,
    #[serde(default)]
    pub primary_color: Option<String>,
    #[serde(default)]
    pub login_host: Option<String>,
    /// Fields to reset to "inherit".
    #[serde(default)]
    pub clear: Vec<BrandingField>,
    #[serde(default)]
    pub logo: AssetChange,
    #[serde(default)]
    pub favicon: AssetChange,
    #[serde(default)]
    pub login_background: AssetChange,
}

#[derive(Debug, Serialize)]
pub struct SetOutput {
    pub reseller_id: i64,
    pub resolved: ResolvedBranding,
    /// What happened to each image, so the caller does not have to diff two
    /// `resolved` snapshots to find out.
    pub assets: Vec<AssetOutcome>,
}

#[derive(Debug, Serialize)]
pub struct AssetOutcome {
    pub kind: AssetKind,
    pub action: &'static str,
    pub content_type: Option<&'static str>,
    pub size_bytes: Option<usize>,
}

/// `branding.set` — panel name, colour, support URL, login host and images.
pub struct Set;

#[async_trait]
impl TypedOperation for Set {
    type Input = SetInput;
    type Output = SetOutput;

    const NAME: &'static str = "branding.set";
    const PERMISSION: Permission = Permission::UserManage;
    // Immediate, and that is the feature. Branding is rows, not files: there
    // is nothing to render, nothing to validate and nothing to reload, which
    // is what makes spec §11.19's "no restart" free rather than careful.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let reseller_id = target_reseller(ctx, input.reseller_id)?;
        let db = ctx.db();

        let update = BrandingUpdate {
            panel_name: input
                .panel_name
                .as_deref()
                .map(parse_panel_name)
                .transpose()?,
            support_url: input
                .support_url
                .as_deref()
                .map(parse_support_url)
                .transpose()?,
            primary_color: input
                .primary_color
                .as_deref()
                .map(parse_colour)
                .transpose()?,
            login_host: input
                .login_host
                .as_deref()
                .map(parse_login_host)
                .transpose()?,
            clear: input.clear,
        };

        // Images first, then the row, then read back. If an image is refused
        // the text fields are untouched, which is the order that makes a
        // partial failure comprehensible: nothing changed.
        let mut assets = Vec::new();
        for (kind, change) in [
            (AssetKind::Logo, input.logo),
            (AssetKind::Favicon, input.favicon),
            (AssetKind::LoginBackground, input.login_background),
        ] {
            assets.push(apply_asset(ctx, reseller_id, kind, change).await?);
        }

        db.save_branding(reseller_id, update).await.map_err(|e| {
            // The one storage failure with a cause worth naming: two resellers
            // cannot own the same login host, and the raw constraint error
            // would say nothing useful.
            if e.to_string().contains("branding_login_host") {
                UnihelmError::new(
                    ErrorCode::Conflict,
                    "another reseller already uses that login host",
                )
                .with_field("login_host")
            } else {
                UnihelmError::from(e)
            }
        })?;

        Ok(SetOutput {
            reseller_id,
            resolved: db
                .resolved_branding(reseller_id)
                .await
                .map_err(UnihelmError::from)?,
            assets,
        })
    }
}

async fn apply_asset(
    ctx: &OpContext,
    reseller_id: i64,
    kind: AssetKind,
    change: AssetChange,
) -> Result<AssetOutcome> {
    match change {
        AssetChange::Keep => Ok(AssetOutcome {
            kind,
            action: "kept",
            content_type: None,
            size_bytes: None,
        }),
        AssetChange::Clear => {
            ctx.db()
                .delete_branding_asset(reseller_id, kind)
                .await
                .map_err(UnihelmError::from)?;
            Ok(AssetOutcome {
                kind,
                action: "cleared",
                content_type: None,
                size_bytes: None,
            })
        }
        AssetChange::Set { content_b64 } => {
            let bytes = decode_upload(kind, &content_b64)?;
            let image = sniff_image(&bytes)?;
            let digest = hex::encode(Sha256::digest(&bytes));
            ctx.db()
                .save_branding_asset(reseller_id, kind, image, &bytes, &digest)
                .await
                .map_err(UnihelmError::from)?;
            Ok(AssetOutcome {
                kind,
                action: "replaced",
                content_type: Some(image.content_type()),
                size_bytes: Some(bytes.len()),
            })
        }
    }
}

/// Decode an upload, refusing an over-large one *before* allocating it.
///
/// base64 inflates by 4/3, so the encoded length bounds the decoded length
/// exactly. Checking there means a caller cannot make the agent allocate
/// hundreds of megabytes to find out that the result is too big — the same
/// arithmetic the file manager's `checked_content_len` does, for the same
/// reason.
fn decode_upload(kind: AssetKind, content_b64: &str) -> Result<Vec<u8>> {
    let cap = max_bytes(kind);
    let encoded = content_b64.len();
    if encoded / 4 * 3 > cap {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "a {} may be at most {} KiB; that upload is larger",
                kind.as_str(),
                cap / 1024
            ),
        )
        .with_field("content_b64"));
    }
    let bytes = BASE64.decode(content_b64.as_bytes()).map_err(|e| {
        UnihelmError::new(
            ErrorCode::InvalidInput,
            format!("the image is not valid base64: {e}"),
        )
        .with_field("content_b64")
    })?;
    if bytes.len() > cap {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "a {} may be at most {} KiB; that one is {} KiB",
                kind.as_str(),
                cap / 1024,
                bytes.len() / 1024
            ),
        )
        .with_field("content_b64"));
    }
    if bytes.is_empty() {
        return Err(
            UnihelmError::new(ErrorCode::InvalidInput, "the image is empty")
                .with_field("content_b64"),
        );
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use unihelm_core::Role;

    // -- sniffing ----------------------------------------------------------

    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        out.extend_from_slice(&13u32.to_be_bytes());
        out.extend_from_slice(b"IHDR");
        out.extend_from_slice(&width.to_be_bytes());
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(&[8, 6, 0, 0, 0]);
        out
    }

    #[test]
    fn every_accepted_format_is_recognised_from_its_magic_bytes() {
        assert_eq!(sniff_image(&png(16, 16)).unwrap(), ImageType::Png);
        assert_eq!(
            sniff_image(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 16, b'J', b'F', b'I', b'F', 0, 1]).unwrap(),
            ImageType::Jpeg
        );
        assert_eq!(
            sniff_image(b"GIF89a\x10\x00\x10\x00\x00\x00").unwrap(),
            ImageType::Gif
        );
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&[0, 0, 0, 0]);
        webp.extend_from_slice(b"WEBPVP8 ");
        assert_eq!(sniff_image(&webp).unwrap(), ImageType::Webp);
        assert_eq!(
            sniff_image(&[0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0]).unwrap(),
            ImageType::Icon
        );
    }

    #[test]
    fn an_svg_is_refused_however_it_starts() {
        // The whole reason this function reads bytes and not filenames. Every
        // one of these is a legal way to begin an SVG document.
        for body in [
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>".to_vec(),
            b"<?xml version=\"1.0\"?><svg onload=\"alert(1)\"/>".to_vec(),
            b"  \n\t<svg/>                    ".to_vec(),
            b"<!-- a comment --><svg/>".to_vec(),
            {
                let mut bom = vec![0xEF, 0xBB, 0xBF];
                bom.extend_from_slice(b"<svg/>          ");
                bom
            },
        ] {
            let err = sniff_image(&body).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput);
            assert!(
                err.detail.contains("SVG"),
                "the refusal must say why: {}",
                err.detail
            );
        }
    }

    #[test]
    fn html_and_php_disguised_as_an_image_are_refused() {
        // A logo upload is a file-write primitive if the format check can be
        // talked out of its answer.
        for body in [
            b"<html><body><script>fetch('/api/auth/me')</script></body></html>".to_vec(),
            b"<?php system($_GET['c']); ?>                    ".to_vec(),
            b"GIF89a<?php system($_GET['c']); ?>".to_vec(),
        ] {
            let sniffed = sniff_image(&body);
            match sniffed {
                Err(e) => assert_eq!(e.code, ErrorCode::InvalidInput),
                // The GIF polyglot really is a GIF by its first six bytes.
                // That is exactly the case the serving headers exist for: it
                // is stored as image/gif and served with nosniff plus a CSP
                // that stops the browser ever treating it as a document.
                Ok(kind) => assert_eq!(kind, ImageType::Gif),
            }
        }
    }

    #[test]
    fn a_decompression_bomb_is_refused_on_its_declared_dimensions() {
        // 40000 × 40000 is a few kilobytes on disk and 6 GB in a decoder.
        let err = sniff_image(&png(40_000, 40_000)).unwrap_err();
        assert!(err.detail.contains("40000"), "{}", err.detail);
        assert!(sniff_image(&png(1024, 1024)).is_ok());
    }

    #[test]
    fn an_empty_or_truncated_upload_is_refused_rather_than_panicking() {
        for body in [vec![], vec![0u8], b"\x89PNG".to_vec(), b"RIFF1234".to_vec()] {
            assert!(sniff_image(&body).is_err(), "{body:?}");
        }
    }

    #[test]
    fn an_over_large_upload_is_refused_from_its_encoded_length_alone() {
        // Before allocating: the point is that a caller cannot make the agent
        // materialise the payload to learn it is too big.
        let huge = "A".repeat(max_bytes(AssetKind::Favicon) * 2);
        let err = decode_upload(AssetKind::Favicon, &huge).unwrap_err();
        assert!(err.detail.contains("KiB"), "{}", err.detail);
    }

    #[test]
    fn garbage_base64_is_invalid_input_not_an_internal_error() {
        let err = decode_upload(AssetKind::Logo, "@@@not base64@@@").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("content_b64"));
    }

    // -- field validation --------------------------------------------------

    #[test]
    fn a_colour_that_could_carry_css_is_refused() {
        for bad in [
            "#3b82f6; background: url(//evil.example/x)",
            "red",
            "#fff",
            "#3b82f",
            "rgb(1,2,3)",
            "",
            "#gggggg",
            "url(x)",
        ] {
            assert!(parse_colour(bad).is_err(), "{bad:?} must be refused");
        }
        assert_eq!(parse_colour("  #3B82F6 ").unwrap(), "#3b82f6");
    }

    #[test]
    fn a_support_url_with_a_scripting_scheme_is_refused() {
        // It becomes an href on the login page. `javascript:` there is script
        // execution in the panel's origin, one click away.
        for bad in [
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox",
            "//evil.example",
            "/support",
            "ftp://example.com",
            "https://",
            "",
            "https://exa mple.com",
        ] {
            assert!(parse_support_url(bad).is_err(), "{bad:?} must be refused");
        }
        assert_eq!(
            parse_support_url(" https://support.example.com/help ").unwrap(),
            "https://support.example.com/help"
        );
        assert!(parse_support_url("http://intranet.example/help").is_ok());
    }

    #[test]
    fn a_panel_name_is_bounded_and_free_of_control_characters() {
        assert!(parse_panel_name("").is_err());
        assert!(parse_panel_name(&"x".repeat(65)).is_err());
        assert!(parse_panel_name("Acme\u{0}Hosting").is_err());
        assert!(parse_panel_name("Acme\nHosting").is_err());
        // Persian is a first-class locale here, and 64 *characters* is not 64
        // bytes.
        assert_eq!(parse_panel_name(" میزبانی آکمه ").unwrap(), "میزبانی آکمه");
    }

    #[test]
    fn a_login_host_is_normalised_the_same_way_the_lookup_normalises_a_header() {
        assert_eq!(
            parse_login_host("Panel.Acme.Example:8443").unwrap(),
            "panel.acme.example"
        );
        assert!(parse_login_host("").is_err());
        assert!(parse_login_host("panel acme example").is_err());
        assert!(parse_login_host("panel.acme.example/../x").is_err());
    }

    // -- authorisation -----------------------------------------------------

    #[tokio::test]
    async fn a_reseller_cannot_write_another_resellers_branding() {
        // And gets `not_found`, not `permission_denied`: the second answer
        // would confirm that the other reseller exists.
        let (reg, _admin, _customer) = registry().await;
        let auth = auth_for(unihelm_core::UserId(7), Role::Reseller);
        let ctx = OpContext::new(reg.services().clone(), auth);
        assert_eq!(target_reseller(&ctx, None).unwrap(), 7);
        assert_eq!(target_reseller(&ctx, Some(7)).unwrap(), 7);
        let err = target_reseller(&ctx, Some(8)).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn an_admin_writes_the_panel_default_unless_they_name_a_reseller() {
        let (reg, admin, _customer) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        assert_eq!(target_reseller(&ctx, None).unwrap(), PANEL_DEFAULT);
        assert_eq!(target_reseller(&ctx, Some(9)).unwrap(), 9);
    }

    #[tokio::test]
    async fn a_customer_cannot_brand_anything() {
        let (reg, _admin, customer) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(customer, Role::Customer));
        assert_eq!(
            target_reseller(&ctx, None).unwrap_err().code,
            ErrorCode::PermissionDenied
        );
    }

    // -- the operations end to end ----------------------------------------

    #[tokio::test]
    async fn setting_branding_takes_effect_with_nothing_to_reload() {
        // Spec §11.19's acceptance criterion, as a test: the write and the
        // read are the whole mechanism.
        let (reg, admin, _) = registry().await;
        let out = reg
            .dispatch(
                "branding.set",
                &auth_for(admin, Role::Admin),
                serde_json::json!({
                    "panel_name": "Acme Hosting",
                    "primary_color": "#3B82F6",
                    "support_url": "https://support.acme.example",
                    "logo": { "action": "set", "content_b64": BASE64.encode(png(64, 64)) },
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["resolved"]["panel_name"], "Acme Hosting");
        assert_eq!(out["resolved"]["primary_color"], "#3b82f6");
        assert_eq!(out["assets"][0]["action"], "replaced");
        assert_eq!(out["assets"][0]["content_type"], "image/png");

        let read = reg
            .dispatch(
                "branding.get",
                &auth_for(admin, Role::Admin),
                serde_json::json!({}),
                None,
            )
            .await
            .unwrap();
        assert_eq!(read["resolved"]["panel_name"], "Acme Hosting");
        assert_eq!(read["resolved"]["assets"][0]["kind"], "logo");
    }

    #[tokio::test]
    async fn a_refused_logo_leaves_the_text_fields_untouched() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);
        reg.dispatch(
            "branding.set",
            &auth,
            serde_json::json!({ "panel_name": "Acme Hosting" }),
            None,
        )
        .await
        .unwrap();

        let err = reg
            .dispatch(
                "branding.set",
                &auth,
                serde_json::json!({
                    "panel_name": "Renamed",
                    "logo": { "action": "set", "content_b64": BASE64.encode("<svg/>            ") },
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);

        let read = reg
            .dispatch("branding.get", &auth, serde_json::json!({}), None)
            .await
            .unwrap();
        assert_eq!(
            read["resolved"]["panel_name"], "Acme Hosting",
            "a refused image must not half-apply the rest of the form"
        );
    }

    #[tokio::test]
    async fn no_operation_output_can_carry_image_bytes() {
        // The bytes are served by a dedicated route with its own headers; an
        // operation output that also carried them would be a second, unheadered
        // way to get at them.
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);
        let logo = BASE64.encode(png(8, 8));
        reg.dispatch(
            "branding.set",
            &auth,
            serde_json::json!({ "logo": { "action": "set", "content_b64": logo.clone() } }),
            None,
        )
        .await
        .unwrap();

        for op in ["branding.get", "branding.set"] {
            let out = reg
                .dispatch(op, &auth, serde_json::json!({}), None)
                .await
                .unwrap();
            let rendered = out.to_string();
            assert!(!rendered.contains(&logo[..32]), "{op} leaked image bytes");
            assert!(!rendered.contains("content_b64"), "{op}");
        }
    }

    #[tokio::test]
    async fn clearing_a_logo_uncovers_the_panel_default() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);
        reg.dispatch(
            "branding.set",
            &auth,
            serde_json::json!({ "logo": { "action": "set", "content_b64": BASE64.encode(png(8, 8)) } }),
            None,
        )
        .await
        .unwrap();
        reg.dispatch(
            "branding.set",
            &auth,
            serde_json::json!({ "reseller_id": 7, "logo": { "action": "set", "content_b64": BASE64.encode(png(9, 9)) } }),
            None,
        )
        .await
        .unwrap();

        let out = reg
            .dispatch(
                "branding.set",
                &auth,
                serde_json::json!({ "reseller_id": 7, "logo": { "action": "clear" } }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["assets"][0]["action"], "cleared");
        assert_eq!(out["resolved"]["assets"][0]["owner_id"], 0);
    }

    #[tokio::test]
    async fn a_customer_is_refused_by_the_registry_before_the_input_is_parsed() {
        let (reg, _, customer) = registry().await;
        let err = reg
            .dispatch(
                "branding.set",
                &auth_for(customer, Role::Customer),
                serde_json::json!({ "primary_color": "not a colour" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }
}
