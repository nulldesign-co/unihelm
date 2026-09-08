//! Server status: metrics and managed services (spec §11.11, §11.1).

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use serde::Serialize;
use serde_json::json;
use unihelm_core::Permission;
use unihelm_db::audit::NewAuditEntry;
use utoipa::ToSchema;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// The units the dashboard shows. Sent to the agent as `ManagedUnit` values, so
/// this list can never turn into "read the status of any unit you like".
fn dashboard_units() -> Vec<serde_json::Value> {
    vec![
        json!({ "unit": "nginx" }),
        json!({ "unit": "maria_db" }),
        json!({ "unit": "postgre_sql" }),
        json!({ "unit": "kv_store" }),
        json!({ "unit": "docker" }),
        json!({ "unit": "unihelm_agentd" }),
    ]
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Overview {
    /// Whether the agent answered. The rest of the payload is absent when it did
    /// not, rather than silently stale.
    pub agent_online: bool,
    pub panel_version: &'static str,
    pub panel_uptime_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_error: Option<String>,
}

/// Everything the dashboard needs in one round trip.
#[utoipa::path(
    get,
    path = "/api/server/overview",
    tag = "server",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Metrics and system facts; partial when the agent is unreachable", body = Overview),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.read`", body = ApiErrorBody),
    ),
)]
pub async fn overview(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<Overview>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;

    let mut overview = Overview {
        agent_online: false,
        panel_version: env!("CARGO_PKG_VERSION"),
        panel_uptime_seconds: state.uptime_seconds(),
        metrics: None,
        system: None,
        agent_error: None,
    };

    let metrics = state
        .agent
        .call_ok(
            "metrics.snapshot",
            &current.auth,
            json!({ "include_panel_footprint": true, "web_pid": std::process::id() }),
        )
        .await;

    match metrics {
        Ok(data) => {
            overview.agent_online = true;
            overview.metrics = Some(data);
        }
        Err(e) => {
            // The panel being unable to reach its agent is worth showing plainly.
            // It is also not an error page: the sites are still being served.
            overview.agent_error = Some(e.detail.clone());
            return Ok(Json(overview));
        }
    }

    if let Ok(system) = state
        .agent
        .call_ok("sys.ping", &current.auth, json!({}))
        .await
    {
        overview.system = Some(system);
    }

    Ok(Json(overview))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServicesResponse {
    pub services: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_error: Option<String>,
}

/// Status of every service the panel manages.
#[utoipa::path(
    get,
    path = "/api/server/services",
    tag = "server",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "One entry per managed unit", body = ServicesResponse),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.read`", body = ApiErrorBody),
    ),
)]
pub async fn services(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<ServicesResponse>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;

    let mut services = Vec::new();
    let mut agent_error = None;

    for unit in dashboard_units() {
        match state
            .agent
            .call_ok("svc.status", &current.auth, json!({ "unit": unit }))
            .await
        {
            Ok(status) => services.push(status),
            Err(e) => {
                // One unreachable agent means none of the rest will work either;
                // report once instead of six times.
                agent_error = Some(e.detail);
                break;
            }
        }
    }

    Ok(Json(ServicesResponse {
        services,
        agent_error,
    }))
}

/// Whether this machine is running code it has already replaced.
///
/// `ServerRead`, for the same reason the posture scan is: the person who needs
/// to know a kernel patch is installed but not running is the person watching
/// the dashboard, and gating it behind the permission to restart the server
/// would keep it from them.
#[utoipa::path(
    get,
    path = "/api/server/reboot",
    tag = "server",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Whether a restart is pending, the packages that asked for one when the system named them, and what a restart would stop. A machine where the check could not run reports `unknown` rather than a clean result.", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn reboot_status(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "server.reboot.status", json!({})).await?;
    Ok(Json(data))
}

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct RebootRequest {
    /// This machine's hostname, retyped. The agent refuses without it.
    pub confirm_hostname: String,
}

/// Restart the machine.
///
/// Immediate rather than a task, deliberately: the agent goes down with the
/// machine, so a task row would be reconciled as failed on the way back up —
/// the panel reporting a failure for the one operation that worked.
#[utoipa::path(
    post,
    path = "/api/server/reboot",
    tag = "server",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = RebootRequest,
    responses(
        (status = 200, description = "The restart is scheduled. The answer names the sites that stop and says plainly that the panel cannot report the machine coming back, because it goes down with it.", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: the hostname was not retyped correctly", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`: needs `server_manage`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn reboot(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<RebootRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let input = json!({ "confirm_hostname": body.confirm_hostname });
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "server.reboot",
        "server",
        &input,
    )
    .await?;
    let data = ops::invoke_now(&state, &current.auth, "server.reboot", input).await?;
    Ok(Json(data))
}

/// The audit row for a restart.
///
/// Every route file here keeps its own, because what belongs in `detail`
/// differs per surface. There is exactly one field and it is not a secret: the
/// hostname the operator retyped. "Who restarted this server, and when" is the
/// question this row exists to answer, and it is written **before** the machine
/// goes down — after would never happen.
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
