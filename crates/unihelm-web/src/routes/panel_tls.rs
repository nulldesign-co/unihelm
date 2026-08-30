//! The panel's own TLS (spec §11.5): a domain and a Let's Encrypt
//! certificate for the panel itself, instead of a hand-written reverse proxy.
//!
//! Admin-only in both directions. The status read is served straight from the
//! panel database — the settings key and the NULL-site certificate row —
//! because it must keep answering when the agent is down: "why is my panel's
//! certificate expired" is exactly the question someone asks mid-outage.

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use unihelm_core::Permission;
use unihelm_db::CertStatus;
use unihelm_db::audit::NewAuditEntry;
use utoipa::ToSchema;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

#[derive(Debug, Deserialize, ToSchema)]
pub struct IssueRequest {
    /// Must already resolve to this server, or the HTTP-01 challenge fails.
    pub domain: String,
    #[serde(default)]
    pub contact_email: Option<String>,
    /// Use the staging directory — proves the flow without spending
    /// rate-limit budget, but its root is not publicly trusted.
    #[serde(default)]
    pub staging: bool,
}

/// `POST /api/server/panel-tls` — issue the panel's certificate. Long
/// operation, so the answer is 202 with a task id.
#[utoipa::path(
    post,
    path = "/api/server/panel-tls",
    tag = "server",
    request_body = IssueRequest,
    security(("session_cookie" = []), ("csrf_header" = [])),
    responses(
        (status = 202, description = "Issuance queued; poll the task", body = super::ops::TaskAccepted),
        (status = 400, description = "`invalid_domain` / `invalid_input`", body = crate::error::ApiErrorBody),
        (status = 403, description = "`permission_denied`", body = crate::error::ApiErrorBody),
    ),
)]
pub async fn issue(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<IssueRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    // The agent validates these again — it does not trust us — but parsing
    // here means the user gets the field highlighted instead of a task that
    // fails a second later.
    let domain = unihelm_core::Domain::parse(&body.domain)
        .map_err(|e| ApiError::new(e.with_field("domain")))?;
    let contact_email = body
        .contact_email
        .as_deref()
        .map(|raw| {
            unihelm_core::Email::parse(raw)
                .map_err(|e| ApiError::new(e.with_field("contact_email")))
        })
        .transpose()?;

    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: "panel.tls.issue".into(),
            target: Some(domain.as_str().to_string()),
            detail: json!({ "staging": body.staging }),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;

    ops::invoke(
        &state,
        &current.auth,
        "panel.tls.issue",
        json!({
            "domain": domain.as_str(),
            "contact_email": contact_email.map(|e| e.as_str().to_string()),
            "staging": body.staging,
        }),
    )
    .await
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StatusResponse {
    /// The domain the panel is (or is being) served on; absent until the
    /// first `panel.tls.issue`.
    pub domain: Option<String>,
    /// Status of the panel's certificate row: the active one when it exists,
    /// otherwise the newest attempt — so a failed issuance is visible here.
    #[schema(value_type = Option<String>, example = "active")]
    pub certificate_status: Option<CertStatus>,
    /// Days until the certificate expires; negative once it has passed.
    pub days_remaining: Option<i64>,
    /// Why the last issuance or renewal failed, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// `GET /api/server/panel-tls` — the panel's domain and certificate health.
#[utoipa::path(
    get,
    path = "/api/server/panel-tls",
    tag = "server",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Domain and certificate health", body = StatusResponse),
        (status = 403, description = "`permission_denied`", body = crate::error::ApiErrorBody),
    ),
)]
pub async fn status(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<StatusResponse>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let domain: Option<String> = state
        .db
        .get_setting(unihelm_db::panel::DOMAIN_KEY)
        .await
        .map_err(ApiError::from)?;
    let certificate = state.db.panel_certificate().await.map_err(ApiError::from)?;

    Ok(Json(StatusResponse {
        domain,
        certificate_status: certificate.as_ref().map(|c| c.status),
        days_remaining: certificate.as_ref().and_then(|c| c.days_remaining()),
        last_error: certificate.and_then(|c| c.last_error),
    }))
}
