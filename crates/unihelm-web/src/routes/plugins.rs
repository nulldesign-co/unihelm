//! The plugins API (spec §6 plugin note, §14 Phase 6, §13).
//!
//! A thin bridge onto the `plugin.*` operations in `unihelm_ops::plugin`. Every
//! decision that matters — manifest validation, signature verification, the
//! digest table, the dedicated account, the hardened unit — is in the agent,
//! where it can be enforced rather than merely asked for. Two things are
//! decided here:
//!
//! 1. **Install is a task; everything else is immediate.** Hashing a payload,
//!    creating an account and writing a unit is past the 300 ms round-trip
//!    budget, and the verification steps are exactly what an operator wants to
//!    read afterwards — so `POST /api/plugins` answers 202 with a task id and
//!    the task log carries "signature verified", "N files match their
//!    digests", "installed, disabled".
//!
//! 2. **The audit row records the staging path.** "Where did this code come
//!    from" is the first question anybody asks about a plugin, and by the time
//!    it is asked the staging directory is usually gone. The path is not a
//!    secret and it is the only durable answer.

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use unihelm_core::Permission;
use unihelm_db::audit::NewAuditEntry;
use utoipa::ToSchema;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// Installed plugins and this build's extension-point catalogue.
#[utoipa::path(
    get,
    path = "/api/plugins",
    tag = "plugins",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Installed plugins (slug, name, version, declared extension points, install directory, the account the sidecar runs as, how it was signed, whether it is enabled, last error), plus `extension_points`, the plugin `api_version`, whether `allow_unsigned` is on, and how many trusted signing keys are configured", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn list(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "plugin.list", json!({})).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct InstallRequest {
    /// Absolute path to a staged plugin tree containing `plugin.toml` and,
    /// unless `plugins.allow_unsigned` is on, `plugin.toml.minisig`.
    ///
    /// The panel does not fetch plugins; staging is the operator's step. A path
    /// under `/home` is refused, because a tree a tenant can rewrite between
    /// verification and install would make the signature check theatre.
    #[schema(example = "/opt/unihelm-plugins/acme-dns")]
    pub source: String,
}

/// Verify and install a plugin, leaving it **disabled**.
///
/// Installing is not starting. The sidecar's unit is written but not enabled,
/// so an operator can read the manifest the panel accepted before any of that
/// code runs. See `docs/plugins.md` for the manifest contract and the trust
/// model.
#[utoipa::path(
    post,
    path = "/api/plugins",
    tag = "plugins",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = InstallRequest,
    responses(
        (status = 202, description = "Accepted: a task id whose log carries each verification step", body = serde_json::Value),
        (status = 400, description = "`invalid_input` / `invalid_path`: a malformed manifest, an entry point that leaves the tree, or a source path that is not absolute", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_manage`; also the answer for an unsigned plugin while `plugins.allow_unsigned` is off, for a signature from an untrusted key, and for a payload that does not match its digests / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no `plugin.toml` at that path", body = ApiErrorBody),
        (status = 409, description = "`conflict`: that slug is already installed — remove it first, there is no in-place upgrade", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn install(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<InstallRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let input = json!({ "source": body.source });
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "plugin.install",
        &body.source,
        &input,
    )
    .await?;
    ops::invoke(&state, &current.auth, "plugin.install", input).await
}

/// Start a plugin's sidecar and begin routing its declared extension points.
#[utoipa::path(
    post,
    path = "/api/plugins/{slug}/enable",
    tag = "plugins",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("slug" = String, Path, description = "Plugin slug")),
    responses(
        (status = 200, description = "The plugin row and the sidecar unit's state", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a plugin slug", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such plugin", body = ApiErrorBody),
        (status = 500, description = "`service_action_failed`: the sidecar would not start", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn enable(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    set_state(state, peer, headers, slug, current, true).await
}

/// Stop a plugin's sidecar and stop routing to it.
#[utoipa::path(
    post,
    path = "/api/plugins/{slug}/disable",
    tag = "plugins",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("slug" = String, Path, description = "Plugin slug")),
    responses(
        (status = 200, description = "The plugin row and the sidecar unit's state. The panel stops routing even if systemd could not stop the unit — and says so", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a plugin slug", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such plugin", body = ApiErrorBody),
        (status = 500, description = "`service_action_failed`: the unit did not stop", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn disable(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    set_state(state, peer, headers, slug, current, false).await
}

async fn set_state(
    state: SharedState,
    peer: SocketAddr,
    headers: HeaderMap,
    slug: String,
    current: CurrentUser,
    enable: bool,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let op = if enable {
        "plugin.enable"
    } else {
        "plugin.disable"
    };
    let input = json!({ "slug": slug });
    audit(&state, &current, &headers, &peer, op, &slug, &input).await?;
    let data = ops::invoke_now(&state, &current.auth, op, input).await?;
    Ok(Json(data))
}

/// Stop a plugin, remove its unit and its installed tree, and forget it.
///
/// The dedicated system account is deliberately left behind; the response names
/// it. Deleting a system account that might still own a file somewhere is how a
/// uid gets recycled onto files nobody meant to hand over.
#[utoipa::path(
    delete,
    path = "/api/plugins/{slug}",
    tag = "plugins",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("slug" = String, Path, description = "Plugin slug")),
    responses(
        (status = 202, description = "Accepted: a task id. The result names the account left behind", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a plugin slug", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such plugin", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn remove(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let input = json!({ "slug": slug });
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "plugin.remove",
        &slug,
        &input,
    )
    .await?;
    ops::invoke(&state, &current.auth, "plugin.remove", input).await
}

async fn audit(
    state: &SharedState,
    current: &CurrentUser,
    headers: &HeaderMap,
    peer: &SocketAddr,
    action: &str,
    target: &str,
    detail: &serde_json::Value,
) -> ApiResult<()> {
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(peer), headers)),
            action: action.to_string(),
            target: Some(target.to_string()),
            detail: detail.clone(),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;
    Ok(())
}
