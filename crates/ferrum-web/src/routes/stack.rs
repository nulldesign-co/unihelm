//! The Stack Manager API (spec §11.1).

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
use ferrum_core::{Permission, PhpVersion};
use ferrum_db::audit::NewAuditEntry;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// What the panel can install, and what it already has.
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

#[derive(Debug, Deserialize)]
#[serde(tag = "component", rename_all = "snake_case")]
pub enum ComponentRequest {
    Nginx,
    Php { version: PhpVersion },
    // The database engines (spec §11.4). Mirrors `StackComponent` in
    // ferrum-ops: the web layer re-states the whitelist so a request for an
    // unknown component dies here, before it ever crosses the IPC boundary.
    Mariadb,
    Postgres,
}

impl ComponentRequest {
    fn as_input(&self) -> serde_json::Value {
        match self {
            ComponentRequest::Nginx => json!({ "component": "nginx" }),
            ComponentRequest::Php { version } => {
                json!({ "component": "php", "version": version.as_str() })
            }
            ComponentRequest::Mariadb => json!({ "component": "mariadb" }),
            ComponentRequest::Postgres => json!({ "component": "postgres" }),
        }
    }

    fn describe(&self) -> String {
        match self {
            ComponentRequest::Nginx => "nginx".into(),
            ComponentRequest::Php { version } => format!("php{}", version.as_str()),
            ComponentRequest::Mariadb => "mariadb".into(),
            ComponentRequest::Postgres => "postgres".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct InstallRequest {
    #[serde(flatten)]
    pub component: ComponentRequest,
}

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
