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
    /// `host` or `container`, for an entry that offers both.
    ///
    /// The Stack page has posted this since containers landed and this struct
    /// had nowhere to put it, so serde dropped it and every install followed the
    /// catalogue's default — a container for every database and cache. An
    /// operator who picked "on the server" got one anyway and was told nothing.
    /// Left a `String` for the same reason `component` is one: the agent looks
    /// it up in the catalogue and refuses what that entry does not offer, and a
    /// second copy of the rule here is a second copy that can drift.
    #[serde(default)]
    pub runtime: Option<String>,
}

impl ComponentRequest {
    fn as_input(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("component".into(), json!(self.component));
        if let Some(v) = &self.version {
            m.insert("version".into(), json!(v));
        }
        // Only when it was asked for. Absent has to stay absent across this
        // boundary: the agent answers "the operator said nothing" with the
        // catalogue's default, and filling one in here would take that decision
        // away from the one place that is allowed to make it.
        if let Some(r) = &self.runtime {
            m.insert("runtime".into(), json!(r));
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

    /// The rest of the decision, beside the target.
    ///
    /// "Installed MariaDB" and "installed MariaDB on the host" are different
    /// decisions with different consequences for the machine, and only one of
    /// them is answerable afterwards from the slug alone.
    fn audit_detail(&self) -> serde_json::Value {
        match &self.runtime {
            Some(r) => json!({ "runtime": r }),
            // Not `"runtime": null`: the row would then claim the operator was
            // asked and declined to answer, when the field simply was not sent.
            None => json!({}),
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
        body.component.audit_detail(),
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
        body.component.audit_detail(),
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

/// Which installed component's service to act on.
///
/// No `runtime`: `stack.start` and `stack.stop` act on a systemd unit, and a
/// container has none. `version` still matters, because `php8.3-fpm` and
/// `php8.4-fpm` are two services on one machine.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ServiceRequest {
    /// A catalogue slug whose service the panel is allowed to name: `nginx`,
    /// `apache`, `php`, `mariadb`, `redis`, `docker`. Anything else is refused
    /// by the agent, which holds the list.
    pub component: String,
    /// Which version, for the entries that run several services at once.
    #[serde(default)]
    pub version: Option<String>,
    /// The component's own slug, said back, for a stop that takes something
    /// else down with it. The agent prices the stop, refuses, and its refusal
    /// names the string to send — so the second click is an operator agreeing
    /// to a stated cost rather than repeating a click that failed.
    #[serde(default)]
    pub confirm: Option<String>,
}

impl ServiceRequest {
    fn as_input(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("component".into(), json!(self.component));
        if let Some(v) = &self.version {
            m.insert("version".into(), json!(v));
        }
        if let Some(confirm) = &self.confirm {
            m.insert("confirm".into(), json!(confirm));
        }
        serde_json::Value::Object(m)
    }

    fn describe(&self) -> String {
        match &self.version {
            Some(v) => format!("{} {v}", self.component),
            None => self.component.clone(),
        }
    }
}

/// Start the service an installed component ships.
#[utoipa::path(
    post,
    path = "/api/stack/start",
    tag = "stack",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = ServiceRequest,
    responses(
        (status = 200, description = "The unit's state afterwards", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`: needs `server.manage`", body = ApiErrorBody),
        (status = 501, description = "`not_implemented`: the panel does not name this component's unit", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn start(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<ServiceRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    service_action(&state, peer, &headers, &current, "stack.start", &body).await
}

/// Stop the service an installed component ships.
#[utoipa::path(
    post,
    path = "/api/stack/stop",
    tag = "stack",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = ServiceRequest,
    responses(
        (status = 200, description = "The unit's state afterwards", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`: needs `server.manage`", body = ApiErrorBody),
        // The refusal that matters: stopping the web server this machine serves
        // with while sites are still up. It arrives here rather than in a task
        // log, because the operation is immediate — the operator reads the
        // sentence in the same click that asked the question.
        (status = 409, description = "`dependents_exist`: it serves this machine's sites", body = ApiErrorBody),
        (status = 501, description = "`not_implemented`: the panel does not name this component's unit", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn stop(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<ServiceRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    service_action(&state, peer, &headers, &current, "stack.stop", &body).await
}

/// The half both share: authorise, record the intent, then ask the agent.
///
/// `invoke_now` rather than `invoke`, because both operations are immediate and
/// a task id arriving here would be a bug rather than an outcome — the whole
/// point of the fast lane is that a package install running for four minutes is
/// not why a stop button does nothing.
async fn service_action(
    state: &SharedState,
    peer: SocketAddr,
    headers: &HeaderMap,
    current: &CurrentUser,
    op: &str,
    body: &ServiceRequest,
) -> ApiResult<Json<serde_json::Value>> {
    // `server.manage` is the permission that covers service state, and it is
    // what `svc.action` already requires for the identical act. Reaching it
    // through the Stack page must not make it cheaper to do.
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    // Before the work, like every other stack change. Stopping the web server
    // takes every site on the machine offline, and "who did that" is the first
    // question anybody asks afterwards — including when the agent was down and
    // the stop never happened at all.
    audit(
        state,
        current,
        headers,
        Some(&peer),
        op,
        &body.describe(),
        json!({}),
    )
    .await?;

    let data = ops::invoke_now(state, &current.auth, op, body.as_input()).await?;
    Ok(Json(data))
}

/// Which web server to move this machine to.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SwitchWebServer {
    /// `nginx` or `apache`.
    pub target: String,
    /// Switch even though some sites are configured for something the target
    /// cannot do. Without it the switch refuses and lists every one.
    #[serde(default)]
    pub accept_gaps: bool,
}

/// Move every site on this server to another web server.
#[utoipa::path(
    post,
    path = "/api/stack/webserver",
    tag = "stack",
    request_body = SwitchWebServer,
    security(("session_cookie" = [], "csrf_header" = [])),
    responses(
        // A task. Every refusal the operation makes — not installed, sites would
        // lose a control, this build cannot write that layout — reaches the
        // caller through the task, not through this call. Documenting 400, 409
        // and 501 here said the opposite, and a client written against that
        // list would wait for a rejection that never arrives. `GET
        // /api/stack/webserver/gaps` is what answers before the work starts.
        (status = 202, description = "Queued; poll the task for the outcome", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `stack.manage`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn switch_webserver(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<SwitchWebServer>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::StackManage)
        .map_err(ApiError::from)?;

    // Audited before the work, like every other stack change: this one moves
    // what serves every site on the machine, so "who asked for this" is the
    // first question anybody will have afterwards.
    audit(
        &state,
        &current,
        &headers,
        Some(&peer),
        "webserver.switch",
        // With the flag, because "switched to Apache" and "switched to Apache
        // knowing three sites would lose rate limiting" are different decisions
        // and only one of them is answerable afterwards from the target alone.
        &if body.accept_gaps {
            format!("{} (accepting gaps)", body.target)
        } else {
            body.target.clone()
        },
        json!({ "accept_gaps": body.accept_gaps }),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "webserver.switch",
        json!({ "target": body.target, "accept_gaps": body.accept_gaps }),
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
    detail: serde_json::Value,
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
            detail,
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

/// What switching would cost, before anything is done.
#[utoipa::path(
    get,
    path = "/api/stack/webserver/gaps",
    tag = "stack",
    params(("target" = Option<String>, Query, description = "`nginx` or `apache`; absent means the server serving now")),
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "The sites and features a switch would cost", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a web server this panel serves with", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn webserver_gaps(
    State(state): State<SharedState>,
    current: CurrentUser,
    axum::extract::Query(query): axum::extract::Query<WebServerTarget>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    // Not audited: it reads and changes nothing. The switch that follows is.
    let mut args = serde_json::Map::new();
    if let Some(target) = &query.target {
        args.insert("target".into(), json!(target));
    }
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "webserver.gaps",
        serde_json::Value::Object(args),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub struct WebServerTarget {
    /// Absent means the server serving right now — which is how a page asks
    /// "what does this machine show as set and not actually apply".
    #[serde(default)]
    pub target: Option<String>,
}
