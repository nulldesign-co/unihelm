//! White-label branding (spec §11.19).
//!
//! # The one endpoint that answers without a session
//!
//! `GET /api/branding` and `GET /api/branding/assets/{kind}` are public,
//! because the login page has to render the reseller's name, colour and logo
//! *before* anybody has logged in. That makes them the panel's only
//! unauthenticated read surface beyond `/healthz` and the login POST, so what
//! they expose is worth stating exactly:
//!
//! - a display name, a support URL, a hex colour, and which of the three images
//!   exist, with an ETag each;
//! - **nothing else**. No reseller id, no account count, no hostname list, no
//!   hint whether the requested host matched a reseller or fell through to the
//!   panel default. An unmatched `Host` header and a matched one produce
//!   responses of the same shape, so the endpoint cannot be used to enumerate
//!   which resellers exist.
//!
//! Both read straight from the panel database in *this* process rather than
//! crossing to the agent. That is not a shortcut: an agent operation needs an
//! `AuthContext`, and inventing an anonymous one to satisfy a public read is
//! precisely the shape that turns into a privilege hole. Branding is data with
//! no privileged component, so the unprivileged process reads it itself.
//!
//! # Which reseller's branding
//!
//! The `Host` header, matched exactly against `branding.login_host` (spec
//! §11.19's "custom login domain"). The header is attacker-controlled, so it is
//! used for nothing but selecting a row of public information: the worst a
//! forged one can do is show the caller a logo that a different reseller's own
//! customers already see.
//!
//! # Serving somebody's uploaded bytes
//!
//! Three headers carry the security of the asset route, and each is doing a
//! specific job:
//!
//! - **`Content-Type` comes from a closed enum**, never from the upload. The
//!   bytes were identified by their magic numbers in
//!   `ferrum_ops::branding::sniff_image`, which refuses SVG outright, and the
//!   database `CHECK` constraint agrees, so no stored row can name a document
//!   type.
//! - **`X-Content-Type-Options: nosniff`** stops a browser second-guessing
//!   that. It is set globally by the panel's security-header layer
//!   (`main::build_router`) and applies here too.
//! - **`Content-Disposition: attachment`** is the one that survives a polyglot.
//!   A file that is a valid GIF by its first six bytes and a valid HTML
//!   document to a lenient parser passes every format check there is; served as
//!   an attachment it can never *execute*, because a top-level navigation to it
//!   downloads rather than renders. Subresource loads ignore the header
//!   entirely, so `<img src>`, `<link rel="icon">` and CSS `url()` — the three
//!   ways branding is actually used — are unaffected.
//!
//! The panel's global CSP (`script-src 'self'` with no `unsafe-inline`) already
//! blocks inline script and event handlers in anything served from this origin,
//! and it is applied by an *overriding* layer, so this route deliberately does
//! not set a per-response policy that would be replaced anyway. The refusal to
//! store SVG at all is the guarantee; these headers are what makes a mistake
//! survivable.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ferrum_core::Permission;
use ferrum_db::audit::NewAuditEntry;
use ferrum_db::branding::{PANEL_DEFAULT, normalize_login_host};
use ferrum_db::{AssetKind, ResolvedBranding};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use utoipa::{IntoParams, ToSchema};

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// What the login page needs, and nothing more.
#[derive(Debug, Serialize, ToSchema)]
pub struct PublicBranding {
    /// The name to show. `null` means "use the product's own name", which the
    /// UI already has in its translations.
    pub panel_name: Option<String>,
    pub support_url: Option<String>,
    /// `#rrggbb`. Validated on the way in, so it is safe to put in a CSS
    /// custom property.
    pub primary_color: Option<String>,
    /// One entry per image that resolves. Absent kinds simply are not listed.
    pub assets: Vec<PublicAsset>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PublicAsset {
    /// `logo`, `favicon` or `login_background`.
    pub kind: String,
    /// Where to fetch it. The URL carries no owner id — the asset route
    /// resolves the same way this one did, from the `Host` header.
    pub url: String,
    pub content_type: String,
    /// The bytes' sha256, also served as the `ETag`, so a client can tell a
    /// changed logo from an unchanged one without fetching it.
    pub etag: String,
}

/// Resolve the `Host` header to an owner id.
///
/// Falls back to the panel default for an unknown host, a missing header, or
/// anything that does not parse. Never errors: this runs on the login page, and
/// a panel that will not render its login form because a proxy sent an odd
/// `Host` is worse than one showing the default logo.
async fn owner_for_host(state: &SharedState, headers: &HeaderMap) -> i64 {
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(normalize_login_host)
    else {
        return PANEL_DEFAULT;
    };
    match state.db.branding_for_login_host(&host).await {
        Ok(Some(branding)) => branding.reseller_id,
        Ok(None) => PANEL_DEFAULT,
        Err(e) => {
            tracing::warn!(error = %e, "branding lookup failed; falling back to the panel default");
            PANEL_DEFAULT
        }
    }
}

fn public_view(resolved: ResolvedBranding) -> PublicBranding {
    PublicBranding {
        panel_name: resolved.panel_name,
        support_url: resolved.support_url,
        primary_color: resolved.primary_color,
        assets: resolved
            .assets
            .into_iter()
            .map(|a| PublicAsset {
                kind: a.kind.as_str().to_string(),
                url: format!("/api/branding/assets/{}", a.kind.as_str()),
                content_type: a.content_type.to_string(),
                etag: a.sha256,
            })
            .collect(),
    }
}

/// The branding this hostname's login page should use.
///
/// **Public on purpose** — it is the one endpoint that must answer without a
/// session, because the login page renders before there is one. It exposes a
/// name, a support URL, a colour and the URLs of up to three images; no
/// identifiers, no counts, and no way to tell a matched host from an unmatched
/// one.
#[utoipa::path(
    get,
    path = "/api/branding",
    tag = "branding",
    security(()),
    responses(
        (status = 200, description = "Panel name, support URL, primary colour and the resolved image URLs", body = PublicBranding),
    ),
)]
pub async fn public_get(State(state): State<SharedState>, headers: HeaderMap) -> Json<PublicBranding> {
    let owner = owner_for_host(&state, &headers).await;
    match state.db.resolved_branding(owner).await {
        Ok(resolved) => Json(public_view(resolved)),
        Err(e) => {
            // An unbranded login page is a working login page; a 500 here is
            // a panel nobody can log into.
            tracing::warn!(error = %e, "branding could not be read; serving the product default");
            Json(PublicBranding {
                panel_name: None,
                support_url: None,
                primary_color: None,
                assets: Vec::new(),
            })
        }
    }
}

/// One branding image.
///
/// **Public**, for the same reason as above, and served with the header set
/// described in this module's docs: a `Content-Type` chosen from a closed enum,
/// the panel's global `nosniff`, and `Content-Disposition: attachment` so a
/// polyglot can never be navigated to as a document.
#[utoipa::path(
    get,
    path = "/api/branding/assets/{kind}",
    tag = "branding",
    security(()),
    params(("kind" = String, Path, description = "`logo`, `favicon` or `login_background`")),
    responses(
        (status = 200, description = "The image bytes", content_type = "image/png"),
        (status = 304, description = "The caller's `If-None-Match` still matches"),
        (status = 400, description = "`invalid_input`: not an asset kind", body = ApiErrorBody),
        (status = 404, description = "`not_found`: neither this owner nor the panel default has one", body = ApiErrorBody),
    ),
)]
pub async fn asset(
    State(state): State<SharedState>,
    Path(kind): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let kind = AssetKind::parse(&kind).map_err(|_| {
        ApiError::code(
            ferrum_core::ErrorCode::InvalidInput,
            "not a branding asset kind",
        )
    })?;
    let owner = owner_for_host(&state, &headers).await;
    let asset = state
        .db
        .branding_asset(owner, kind)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("branding asset"))?;

    let etag = format!("\"{}\"", asset.sha256);
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|presented| presented.split(',').any(|t| t.trim() == etag))
    {
        return Ok(StatusCode::NOT_MODIFIED.into_response());
    }

    Ok((
        [
            // From the closed `ImageType` enum, never from the upload.
            (header::CONTENT_TYPE, asset.image_type.content_type().to_string()),
            // See the module docs: this is what stops an image/HTML polyglot
            // ever being *rendered* as a document in the panel's origin.
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", kind.as_str()),
            ),
            // Revalidate every time. Branding is data and applies with no
            // restart (spec §11.19); a cached logo that outlives the change
            // would undo that from the browser's side. The ETag makes the
            // revalidation a 304 rather than a refetch.
            (header::CACHE_CONTROL, "no-cache".to_string()),
            (header::ETAG, etag),
        ],
        asset.bytes,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// the authenticated half
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SettingsQuery {
    /// Admin only: read another reseller's branding. A reseller always reads
    /// their own, and naming somebody else's gets `not_found` — the same answer
    /// a non-existent one gives, so this cannot enumerate resellers.
    #[serde(default)]
    pub reseller_id: Option<i64>,
}

/// The stored branding row, what it resolves to, and the upload limits.
#[utoipa::path(
    get,
    path = "/api/branding/settings",
    tag = "branding",
    security(("session_cookie" = [])),
    params(SettingsQuery),
    responses(
        (status = 200, description = "The owner's own row (nulls mean `inherits`), the resolved values, the per-kind byte limits and the accepted formats", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `user_manage`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: another reseller's branding", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn settings_get(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<SettingsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::UserManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "branding.get",
        json!({ "reseller_id": q.reseller_id }),
    )
    .await?;
    Ok(Json(data))
}

/// What to do with one image.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AssetChange {
    /// Leave it alone.
    Keep,
    /// Remove this owner's image, uncovering the panel default underneath.
    Clear,
    /// Replace it. Base64, the same transport the file manager uses for binary
    /// content (spec §11.7). Identified by its magic bytes, not its name;
    /// **SVG is refused**.
    Set { content_b64: String },
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BrandingRequest {
    #[serde(default)]
    pub reseller_id: Option<i64>,
    /// 1–64 characters. Omit to leave unchanged; list it in `clear` to go back
    /// to inheriting.
    #[serde(default)]
    pub panel_name: Option<String>,
    /// `https://` or `http://` only. Any other scheme — `javascript:` above
    /// all — is refused, because this becomes an anchor's `href` on the login
    /// page.
    #[serde(default)]
    pub support_url: Option<String>,
    /// Exactly `#rrggbb`. It reaches the browser inside a CSS custom property.
    #[serde(default)]
    pub primary_color: Option<String>,
    /// The hostname whose login page shows this branding.
    #[serde(default)]
    pub login_host: Option<String>,
    /// Fields to reset to "inherit": `panel_name`, `support_url`,
    /// `primary_color`, `login_host`.
    #[serde(default)]
    pub clear: Vec<String>,
    #[serde(default)]
    pub logo: Option<AssetChange>,
    #[serde(default)]
    pub favicon: Option<AssetChange>,
    #[serde(default)]
    pub login_background: Option<AssetChange>,
}

/// Set branding.
///
/// 200, not 202: branding is rows, not files. There is nothing to render,
/// validate or reload, which is exactly what makes spec §11.19's "switching
/// branding requires no restart" free rather than careful — the next request
/// reads the new values.
#[utoipa::path(
    put,
    path = "/api/branding/settings",
    tag = "branding",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = BrandingRequest,
    responses(
        (status = 200, description = "The resolved branding after the change, and what happened to each image", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: a bad colour, a non-http support URL, an oversized upload, or a file that is not one of the accepted raster formats", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: another reseller's branding", body = ApiErrorBody),
        (status = 409, description = "`conflict`: another reseller already uses that login host", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn settings_set(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<BrandingRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::UserManage)
        .map_err(ApiError::from)?;

    // The fields, never the image bytes: an audit row carrying a megabyte of
    // base64 per upload would make the audit log unusable and unexportable.
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: "branding.set".into(),
            target: body.reseller_id.map(|id| id.to_string()),
            detail: json!({
                "panel_name": body.panel_name,
                "support_url": body.support_url,
                "primary_color": body.primary_color,
                "login_host": body.login_host,
                "clear": body.clear,
                "images": image_actions(&body),
            }),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;

    let mut input = json!({
        "reseller_id": body.reseller_id,
        "panel_name": body.panel_name,
        "support_url": body.support_url,
        "primary_color": body.primary_color,
        "login_host": body.login_host,
        "clear": body.clear,
    });
    for (field, change) in [
        ("logo", body.logo),
        ("favicon", body.favicon),
        ("login_background", body.login_background),
    ] {
        if let Some(change) = change {
            input[field] = match change {
                AssetChange::Keep => json!({ "action": "keep" }),
                AssetChange::Clear => json!({ "action": "clear" }),
                AssetChange::Set { content_b64 } => {
                    json!({ "action": "set", "content_b64": content_b64 })
                }
            };
        }
    }

    let data = ops::invoke_now(&state, &current.auth, "branding.set", input).await?;
    Ok(Json(data))
}

/// Which images a request touches, for the audit row — the verb only.
fn image_actions(body: &BrandingRequest) -> serde_json::Value {
    let name = |change: &Option<AssetChange>| match change {
        None | Some(AssetChange::Keep) => "kept",
        Some(AssetChange::Clear) => "cleared",
        Some(AssetChange::Set { .. }) => "replaced",
    };
    json!({
        "logo": name(&body.logo),
        "favicon": name(&body.favicon),
        "login_background": name(&body.login_background),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use ferrum_core::config::FerrumConfig;
    use ferrum_db::{Db, ImageType};
    use std::sync::Arc;
    use tower::ServiceExt as _;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nnot really, but the bytes never leave the database";

    async fn state() -> SharedState {
        let db = Db::open_memory().await.expect("in-memory panel database");
        Arc::new(crate::state::AppState::new(db, FerrumConfig::default()))
    }

    /// A request through the *whole* API router, with no session and no CSRF
    /// token — which is the property being tested.
    async fn anonymous(state: &SharedState, uri: &str, host: &str) -> axum::response::Response {
        let request = Request::builder()
            .uri(uri)
            .header(header::HOST, host)
            .body(Body::empty())
            .expect("a valid test request");
        crate::routes::api()
            .with_state(state.clone())
            .oneshot(request)
            .await
            .expect("the router answers")
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("a bounded body");
        serde_json::from_slice(&bytes).expect("JSON")
    }

    #[tokio::test]
    async fn the_whole_api_router_builds_with_branding_split_across_public_and_protected() {
        // `Router::merge` panics on a path registered twice with the same
        // method, and branding is the one area that lives in both halves. If
        // this ever regresses the panel does not start at all, so it is worth
        // a test that does nothing but construct the router.
        let router: axum::Router = crate::routes::api().with_state(state().await);
        let _ = router;
    }

    #[tokio::test]
    async fn branding_answers_without_a_session_because_the_login_page_needs_it() {
        let state = state().await;
        state
            .db
            .save_branding(
                ferrum_db::branding::PANEL_DEFAULT,
                ferrum_db::BrandingUpdate {
                    panel_name: Some("Acme Hosting".into()),
                    primary_color: Some("#3b82f6".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let response = anonymous(&state, "/api/branding", "panel.example").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["panel_name"], "Acme Hosting");
        assert_eq!(body["primary_color"], "#3b82f6");
    }

    #[tokio::test]
    async fn the_public_payload_exposes_nothing_but_branding() {
        // The panel's only unauthenticated read surface beyond /healthz. An
        // identifier here would let anybody enumerate resellers.
        let state = state().await;
        state
            .db
            .save_branding(
                7,
                ferrum_db::BrandingUpdate {
                    panel_name: Some("Acme".into()),
                    login_host: Some("panel.acme.example".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let body = body_json(anonymous(&state, "/api/branding", "panel.acme.example").await).await;
        let mut keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["assets", "panel_name", "primary_color", "support_url"],
            "the public shape grew a field; check it is not an identifier"
        );
        let rendered = body.to_string();
        assert!(!rendered.contains("reseller"), "{rendered}");
        assert!(!rendered.contains("owner_id"), "{rendered}");
    }

    #[tokio::test]
    async fn a_forged_host_header_gets_the_panel_default_and_the_same_shape() {
        // The Host header is attacker-controlled. A different response shape
        // for a matched host would make it an existence oracle.
        let state = state().await;
        state
            .db
            .save_branding(
                7,
                ferrum_db::BrandingUpdate {
                    panel_name: Some("Acme".into()),
                    login_host: Some("panel.acme.example".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let matched = body_json(anonymous(&state, "/api/branding", "panel.acme.example").await).await;
        let forged = body_json(anonymous(&state, "/api/branding", "evil.example").await).await;
        assert_eq!(matched["panel_name"], "Acme");
        assert_eq!(forged["panel_name"], serde_json::Value::Null);
        let keys = |v: &serde_json::Value| {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };
        assert_eq!(keys(&matched), keys(&forged));
    }

    #[tokio::test]
    async fn an_unbranded_panel_still_answers_so_the_login_page_renders() {
        let state = state().await;
        let response = anonymous(&state, "/api/branding", "panel.example").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["panel_name"], serde_json::Value::Null);
        assert!(body["assets"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_asset_is_served_as_an_attachment_with_a_type_from_the_stored_enum() {
        // `Content-Disposition: attachment` is what stops an image/HTML
        // polyglot ever being *rendered* as a document in the panel's origin,
        // and it is ignored for the subresource loads branding actually uses.
        let state = state().await;
        state
            .db
            .save_branding_asset(
                ferrum_db::branding::PANEL_DEFAULT,
                AssetKind::Logo,
                ImageType::Png,
                PNG,
                "abc123",
            )
            .await
            .unwrap();

        let response = anonymous(&state, "/api/branding/assets/logo", "panel.example").await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers[header::CONTENT_TYPE], "image/png");
        assert!(
            headers[header::CONTENT_DISPOSITION]
                .to_str()
                .unwrap()
                .starts_with("attachment;"),
        );
        assert_eq!(headers[header::ETAG], "\"abc123\"");
        assert_eq!(headers[header::CACHE_CONTROL], "no-cache");
    }

    #[tokio::test]
    async fn an_unchanged_asset_answers_304_rather_than_resending_the_bytes() {
        let state = state().await;
        state
            .db
            .save_branding_asset(
                ferrum_db::branding::PANEL_DEFAULT,
                AssetKind::Logo,
                ImageType::Png,
                PNG,
                "abc123",
            )
            .await
            .unwrap();

        let request = Request::builder()
            .uri("/api/branding/assets/logo")
            .header(header::HOST, "panel.example")
            .header(header::IF_NONE_MATCH, "\"abc123\"")
            .body(Body::empty())
            .unwrap();
        let response = crate::routes::api()
            .with_state(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn an_asset_kind_that_is_not_one_of_the_three_is_refused() {
        let state = state().await;
        for kind in ["script", "..%2f..%2fetc%2fpasswd", "LOGO"] {
            let response =
                anonymous(&state, &format!("/api/branding/assets/{kind}"), "panel.example").await;
            assert_ne!(response.status(), StatusCode::OK, "{kind}");
        }
    }

    #[tokio::test]
    async fn a_missing_asset_is_a_404_not_an_empty_200() {
        let state = state().await;
        let response = anonymous(&state, "/api/branding/assets/logo", "panel.example").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_authenticated_half_still_needs_a_session() {
        // Publishing the read must not have made the write public too.
        let state = state().await;
        let response = anonymous(&state, "/api/branding/settings", "panel.example").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // -- request shaping ---------------------------------------------------

    fn request_body(value: serde_json::Value) -> BrandingRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    #[test]
    fn the_audit_row_records_the_verb_for_each_image_and_never_the_bytes() {
        // A megabyte of base64 per upload would make the audit log unusable
        // and unexportable, which is how an audit log stops being read.
        let body = request_body(json!({
            "logo": { "action": "set", "content_b64": "QUFBQUFBQUFBQQ==" },
            "favicon": { "action": "clear" },
        }));
        let detail = image_actions(&body);
        assert_eq!(detail["logo"], "replaced");
        assert_eq!(detail["favicon"], "cleared");
        assert_eq!(detail["login_background"], "kept");
        assert!(!detail.to_string().contains("QUFB"));
    }

    #[test]
    fn a_colour_this_layer_does_not_recognise_is_passed_through_for_the_agent_to_refuse() {
        // The agent owns the grammar; a second copy here would drift from it.
        let body = request_body(json!({ "primary_color": "#3b82f6; background: url(x)" }));
        assert_eq!(
            body.primary_color.as_deref(),
            Some("#3b82f6; background: url(x)")
        );
    }
}
