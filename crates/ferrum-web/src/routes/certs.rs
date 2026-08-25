//! The certificates API (spec §11.5).

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use ferrum_core::Permission;
use ferrum_db::audit::NewAuditEntry;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use utoipa::ToSchema;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// Every certificate the caller's scope can see.
#[utoipa::path(
    get,
    path = "/api/certificates",
    tag = "certificates",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Certificate rows with expiry and renewal state", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `site.read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn list(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::SiteRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "cert.list", json!({})).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct IssueRequest {
    /// Use the staging directory. Its root is not publicly trusted, so this is
    /// for proving the flow works, not for a live site.
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub contact_email: Option<String>,
}

/// Request a Let's Encrypt certificate for a site (HTTP-01).
#[utoipa::path(
    post,
    path = "/api/sites/{id}/certificate",
    tag = "certificates",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Site id")),
    request_body = IssueRequest,
    responses(
        (status = 202, description = "Issuance queued; poll the task", body = ops::TaskAccepted),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn issue(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(site_id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<IssueRequest>,
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
            action: "cert.issue".into(),
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
        "cert.issue",
        json!({
            "site_id": site_id,
            "staging": body.staging,
            "contact_email": body.contact_email,
        }),
    )
    .await
}
