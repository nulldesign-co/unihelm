//! Server status: metrics and managed services (spec §11.11, §11.1).

use axum::Json;
use axum::extract::State;
use ferrum_core::Permission;
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiErrorBody, ApiResult};
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
        json!({ "unit": "ferrum_agentd" }),
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
