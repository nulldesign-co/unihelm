//! Database tooling endpoints (spec §11.4).
//!
//! Today this is Adminer only. The endpoints report and toggle the loopback
//! deployment; they do **not** proxy to it. Until the panel grows an
//! authenticated reverse proxy for the Adminer port, the returned URL is
//! reachable from the server itself and nowhere else — that boundary is
//! documented at the top of `ferrum_ops::adminer` and is the reason these
//! endpoints are admin-only (`ServerManage`) rather than `DbManage`.

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
use ferrum_core::Permission;
use ferrum_db::audit::NewAuditEntry;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// Is Adminer enabled, and on which loopback URL.
pub async fn adminer_status(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "db.adminer.status", json!({})).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize)]
pub struct AdminerToggle {
    pub enable: bool,
}

/// Enable or disable Adminer. Both directions are tasks (202 + task id): the
/// enable downloads and verifies a release, and both reload services.
pub async fn adminer_set(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<AdminerToggle>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let op = if body.enable {
        "db.adminer.enable"
    } else {
        "db.adminer.disable"
    };

    // Intent recorded before the work starts, same reasoning as the stack
    // routes: an attempt made while the agent is down is exactly the audit
    // entry an incident review wants (spec §12 rule 10).
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: op.to_string(),
            target: Some("adminer".to_string()),
            detail: json!({}),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: None,
        })
        .await
        .map_err(ApiError::from)?;

    ops::invoke(&state, &current.auth, op, json!({})).await
}
