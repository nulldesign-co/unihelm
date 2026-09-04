//! The Stack Manager API (spec §11.1).

use axum::Json;
use axum::extract::{ConnectInfo, State};
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

/// What the panel can install, and what it already has.
#[utoipa::path(
    get,
    path = "/api/stack",
    tag = "stack",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Installed and installable components, per the agent", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn status(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "stack.status", json!({})).await?;
    Ok(Json(data))
}

/// A catalogue slug and one of its versions.
///
/// This used to be an enum with four variants, and the comment beside it said
/// the web layer re-states the whitelist so an unknown component dies before it
/// crosses the IPC boundary. That was true and it was also why the panel could
/// install four things: the list lived in three places — here, the CLI, and the
/// agent — and all three had to be edited in step.
///
/// The whitelist has not gone away, it has moved to where it is data:
/// `unihelm_ops::catalogue`. The agent looks the pair up there and refuses
/// anything absent, so nothing reaches a package manager that is not in that
/// table. What this layer no longer does is keep a second copy that can drift
/// from it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ComponentRequest {
    /// Any slug the catalogue offers: `nginx`, `php`, `mariadb`, `redis`, …
    pub component: String,
    /// Which version. Omitted means the catalogue's recommended one.
    #[serde(default)]
    pub version: Option<String>,
}

impl ComponentRequest {
    fn as_input(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("component".into(), json!(self.component));
        if let Some(v) = &self.version {
            m.insert("version".into(), json!(v));
        }
        serde_json::Value::Object(m)
    }

    /// What the audit row records.
    fn describe(&self) -> String {
        match &self.version {
            Some(v) => format!("{} {v}", self.component),
            None => self.component.clone(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct InstallRequest {
    #[serde(flatten)]
    pub component: ComponentRequest,
}

/// Install a stack component.
#[utoipa::path(
    post,
    path = "/api/stack/install",
    tag = "stack",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = InstallRequest,
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
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
        .require(Permission::StackManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        Some(&peer),
        "stack.install",
        &body.component.describe(),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "stack.install",
        body.component.as_input(),
    )
    .await
}

/// Remove a stack component.
#[utoipa::path(
    post,
    path = "/api/stack/remove",
    tag = "stack",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = InstallRequest,
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 409, description = "`dependents_exist`: sites still use this component", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn remove(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<InstallRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::StackManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        Some(&peer),
        "stack.remove",
        &body.component.describe(),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "stack.remove",
        body.component.as_input(),
    )
    .await
}

/// Record the intent before the work starts.
///
/// Auditing after the fact loses the record when the agent is unreachable — and
/// "somebody tried to remove nginx while the agent was down" is exactly the
/// entry an incident review wants (spec §12 rule 10).
async fn audit(
    state: &SharedState,
    current: &CurrentUser,
    headers: &HeaderMap,
    peer: Option<&SocketAddr>,
    action: &str,
    target: &str,
) -> ApiResult<()> {
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(peer, headers)),
            action: action.to_string(),
            target: Some(target.to_string()),
            detail: json!({}),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: None,
        })
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

/// What the panel runs in containers, and whether each is up.
#[utoipa::path(
    get,
    path = "/api/engines",
    tag = "stack",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Every containerised engine and its state", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn engines(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "engine.status", json!({})).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EngineRemoveRequest {
    pub component: String,
    #[serde(default)]
    pub version: Option<String>,
    /// Delete the data volume as well. This destroys the databases in it.
    #[serde(default)]
    pub delete_data: bool,
}

/// Stop and remove an engine's container.
#[utoipa::path(
    post,
    path = "/api/engines/remove",
    tag = "stack",
    request_body = EngineRemoveRequest,
    security(("session_cookie" = [], "csrf_header" = [])),
    responses(
        (status = 202, description = "Queued; poll the task", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such engine container", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn engine_remove(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<EngineRemoveRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::StackManage)
        .map_err(ApiError::from)?;

    // Audited whether or not the data goes: removing the container is what makes
    // an application stop being able to connect, and "who did that" is the
    // question asked afterwards.
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: "engine.remove".into(),
            target: Some(body.component.clone()),
            detail: json!({ "delete_data": body.delete_data }),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;

    ops::invoke(
        &state,
        &current.auth,
        "engine.remove",
        json!({
            "component": body.component,
            "version": body.version,
            "delete_data": body.delete_data,
        }),
    )
    .await
}
