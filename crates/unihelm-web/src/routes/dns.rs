//! The DNS API (spec §11.13, §11.5).
//!
//! Thin, like every route module: permission check, an audit row for the
//! mutations, then the operation. The agent re-checks every permission against
//! the same tables (spec §12 rule 4), so the interesting decisions — which
//! credential administers a name, how long to wait for propagation, when a TXT
//! record is removed — live in `unihelm_ops::dns` and not here.
//!
//! What this layer *is* responsible for is the direction the Cloudflare API
//! token travels. It goes in through `PUT /api/dns/provider` and is sealed with
//! the master key before it is stored; it never comes back out. There is no
//! route here that reads a credential, `ProviderSetOutput` has no field that
//! could carry one, and the audit row written below records the *label* and the
//! zone count, never the token. A GET that returned a stored token — even to an
//! admin, even over TLS — would put it in a browser cache, a proxy log and the
//! reviewer's screenshot, which is why one does not exist.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use unihelm_core::Permission;
use unihelm_db::audit::NewAuditEntry;
use utoipa::{IntoParams, ToSchema};

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CheckQuery {
    /// The domain to look up. Validated as a `Domain` in the agent, so a
    /// non-domain comes back as `invalid_input` on the `domain` field rather
    /// than as a resolver error.
    pub domain: String,
}

/// Is a domain pointed at this server?
///
/// `SiteRead`, not a DNS permission: this reads public DNS and compares it with
/// addresses the server already answers on. It reveals nothing a `dig` from any
/// shell would not, it touches no stored credential, and the customer about to
/// point a domain at their site is exactly who needs the answer (spec §11.13).
///
/// The result is advisory. `matches_server: false` with `proxied_hint: true` is
/// a correct, working Cloudflare-proxied setup, not a fault — `advice` carries
/// the sentence so the UI does not keep a second copy of that decision table.
#[utoipa::path(
    get,
    path = "/api/dns/check",
    tag = "dns",
    security(("session_cookie" = [])),
    params(CheckQuery),
    responses(
        (status = 200, description = "A/AAAA records for the domain and its www form, this server's addresses, and an advisory sentence", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a domain", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `site.read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn check(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<CheckQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::SiteRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "dns.check",
        json!({ "domain": q.domain }),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ProviderRequest {
    /// `cloudflare` — the only provider this build speaks (spec §11.13).
    pub kind: String,
    /// The operator's own name for this credential. It is the only handle they
    /// get on a value they can never read back.
    pub label: String,
    /// A **Cloudflare API Token**, scoped to `Zone:Read` + `Zone:DNS:Edit` on
    /// the zones the panel will manage. Never a Global API Key: that credential
    /// authenticates every action on every zone in the account, including
    /// billing, and cannot be scoped down.
    ///
    /// Verified against Cloudflare before it is stored, then sealed with the
    /// panel master key. It is not returned by this endpoint or any other.
    pub token: String,
}

/// Store or rotate the Cloudflare API token wildcard issuance uses.
///
/// `PUT` rather than `POST` because it is an upsert keyed on `(kind, label)`:
/// re-sending the same label with a fresh token rotates that credential in
/// place. An operator who has just rotated a token in the Cloudflare dashboard
/// must not end up with two rows, the older of which is revoked and would be
/// tried first.
///
/// `ServerManage` — admin only, and deliberately not the reseller-held DNS
/// permission. This credential is server-wide: every tenant's wildcard issuance
/// runs through whatever token is stored here, so anyone who can replace it can
/// redirect the panel's DNS writes into a Cloudflare account they control.
#[utoipa::path(
    put,
    path = "/api/dns/provider",
    tag = "dns",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = ProviderRequest,
    responses(
        (status = 200, description = "The credential's label, Cloudflare's verdict on the token, and the zones it administers. Never the token.", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: empty or over-long label", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.manage`, or Cloudflare rejected the token / it can see no zones", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`, or the Cloudflare API is unreachable", body = ApiErrorBody),
    ),
)]
pub async fn provider_set(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<ProviderRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    // The label and the kind, never the token. An audit trail that recorded the
    // credential would defeat the sealing three lines later, and audit rows are
    // exactly what gets exported when somebody is debugging.
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: "dns.provider.set".into(),
            target: Some(body.label.clone()),
            detail: json!({ "kind": body.kind }),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;

    let data = ops::invoke_now(
        &state,
        &current.auth,
        "dns.provider.set",
        json!({
            "kind": body.kind,
            "label": body.label,
            "token": body.token,
        }),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct IssueWildcardRequest {
    /// Use the staging directory. Its root is not publicly trusted, so this is
    /// for proving the DNS-01 flow works without spending rate-limit budget,
    /// not for a live site.
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub contact_email: Option<String>,
}

/// Request a wildcard certificate for a site over DNS-01.
///
/// Covers both `example.com` and `*.example.com` in one certificate. A
/// `*.example.com` certificate does not match `example.com` — a wildcard covers
/// exactly one label — so a wildcard-only certificate leaves the apex broken,
/// which is the single most common wildcard mistake.
///
/// 202 and a task id: the CA validates through public DNS, so this waits on a
/// zone the panel does not own and takes minutes rather than the ~300 ms an
/// immediate operation is allowed.
#[utoipa::path(
    post,
    path = "/api/sites/{id}/certificate-wildcard",
    tag = "certificates",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Site id")),
    request_body = IssueWildcardRequest,
    responses(
        (status = 202, description = "Issuance queued; poll the task", body = ops::TaskAccepted),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope, or no stored credential administers its zone", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn issue_wildcard(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(site_id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<IssueWildcardRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::SiteManage)
        .map_err(ApiError::from)?;

    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: "cert.issue_wildcard".into(),
            target: Some(site_id.to_string()),
            detail: json!({ "staging": body.staging }),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;

    ops::invoke(
        &state,
        &current.auth,
        "cert.issue_wildcard",
        json!({
            "site_id": site_id,
            "staging": body.staging,
            "contact_email": body.contact_email,
        }),
    )
    .await
}
