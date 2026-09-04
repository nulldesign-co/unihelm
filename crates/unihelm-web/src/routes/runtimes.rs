//! Language runtimes, Docker's inventory, and the vhosts already on the machine.
//!
//! Three read surfaces and one install, grouped because they answer the same
//! question from different angles: what is on this server that the panel did not
//! put there? A panel installed onto a machine that has been serving sites for
//! years is otherwise blind to all of it, and shows an empty list to somebody
//! looking at twelve live sites.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use unihelm_core::Permission;
use utoipa::ToSchema;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// Every language runtime on this server, with each installed version.
#[utoipa::path(
    get,
    path = "/api/runtimes",
    tag = "runtimes",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Installed runtimes and versions", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.read`", body = ApiErrorBody),
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
    let data = ops::invoke_now(&state, &current.auth, "runtime.list", json!({})).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct InstallRuntime {
    /// A Node major line: 20, 22, 24.
    pub major: u32,
}

/// Install a Node major line from NodeSource.
#[utoipa::path(
    post,
    path = "/api/runtimes/install",
    tag = "runtimes",
    request_body = InstallRuntime,
    security(("session_cookie" = [], "csrf_header" = [])),
    responses(
        (status = 202, description = "Queued; poll the task", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a line anyone ships", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `stack.manage`", body = ApiErrorBody),
        (status = 501, description = "`not_implemented`: no NodeSource repository for this distribution", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn install(
    State(state): State<SharedState>,
    current: CurrentUser,
    Json(body): Json<InstallRuntime>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::StackManage)
        .map_err(ApiError::from)?;
    // A task, not an immediate call: this runs apt, which takes minutes and
    // streams its output into the task log the page shows.
    ops::invoke(
        &state,
        &current.auth,
        "runtime.install",
        json!({ "major": body.major }),
    )
    .await
}

/// Docker's containers, images and volumes.
#[utoipa::path(
    get,
    path = "/api/server/docker",
    tag = "server",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Docker's inventory, or why there is none", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    // A machine with no Docker is a 200 with `installed: false`, not an error:
    // "Docker is not here" is an answer the page renders, and a 503 would send
    // it down the agent-unreachable path instead.
    let data = ops::invoke_now(&state, &current.auth, "docker.list", json!({})).await?;
    Ok(Json(data))
}

/// Sites already served by nginx that the panel did not create.
#[utoipa::path(
    get,
    path = "/api/sites/discover",
    tag = "sites",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Hand-written vhosts found on the machine", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn discover(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    // `server.read` rather than `site.manage`: this reports the whole machine's
    // nginx configuration, including vhosts belonging to nobody in the panel, so
    // it is not a tenant-scoped read and must not be reachable as one.
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "sites.discover", json!({})).await?;
    Ok(Json(data))
}

// ---------------------------------------------------------------------------
// driving a container that is already there
// ---------------------------------------------------------------------------

/// One shape for the four operations that take only a container.
///
/// `server_manage` on all of them: most of these containers were not created by
/// this panel, and one of them may be an nginx serving somebody's production
/// site. Reading the list is a `server_read`; stopping something is not.
async fn container_action(
    state: &SharedState,
    current: &CurrentUser,
    op: &'static str,
    container: &str,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    ops::invoke(
        &state.clone(),
        &current.auth,
        op,
        json!({ "container": container }),
    )
    .await
}

/// Start a container.
#[utoipa::path(
    post,
    path = "/api/server/docker/containers/{id}/start",
    tag = "server",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = String, Path, description = "Container id or name")),
    responses(
        (status = 200, description = "Start a container", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a container reference", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such container", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_start(
    State(state): State<SharedState>,
    current: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    container_action(&state, &current, "docker.start", &id).await
}

/// Stop a container.
#[utoipa::path(
    post,
    path = "/api/server/docker/containers/{id}/stop",
    tag = "server",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = String, Path, description = "Container id or name")),
    responses(
        (status = 200, description = "Stop a container", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a container reference", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such container", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_stop(
    State(state): State<SharedState>,
    current: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    container_action(&state, &current, "docker.stop", &id).await
}

/// Restart a container.
#[utoipa::path(
    post,
    path = "/api/server/docker/containers/{id}/restart",
    tag = "server",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = String, Path, description = "Container id or name")),
    responses(
        (status = 200, description = "Restart a container", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a container reference", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such container", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_restart(
    State(state): State<SharedState>,
    current: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    container_action(&state, &current, "docker.restart", &id).await
}

/// Delete a container and its writable layer. A running one is refused.
#[utoipa::path(
    delete,
    path = "/api/server/docker/containers/{id}",
    tag = "server",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = String, Path, description = "Container id or name")),
    responses(
        (status = 200, description = "Removed", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such container", body = ApiErrorBody),
        (status = 409, description = "`conflict`: it is running — stop it first", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_remove(
    State(state): State<SharedState>,
    current: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    container_action(&state, &current, "docker.remove", &id).await
}

#[derive(Debug, Deserialize)]
pub struct LogLines {
    pub lines: Option<u32>,
}

/// The last lines a container wrote, both streams merged.
#[utoipa::path(
    get,
    path = "/api/server/docker/containers/{id}/logs",
    tag = "server",
    security(("session_cookie" = [])),
    params(
        ("id" = String, Path, description = "Container id or name"),
        ("lines" = Option<u32>, Query, description = "How many lines; 200 by default"),
    ),
    responses(
        (status = 200, description = "The tail of the container's output", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.read`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such container", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_logs(
    State(state): State<SharedState>,
    current: CurrentUser,
    Path(id): Path<String>,
    Query(q): Query<LogLines>,
) -> ApiResult<Json<serde_json::Value>> {
    // Reading, so `server_read` — the same permission the list needs.
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;

    let mut input = json!({ "container": id });
    if let Some(lines) = q.lines {
        input["lines"] = json!(lines);
    }
    let data = ops::invoke_now(&state, &current.auth, "docker.logs", input).await?;
    Ok(Json(data))
}

/// Create and start a container from an image.
#[utoipa::path(
    post,
    path = "/api/server/docker/containers",
    tag = "server",
    security(("session_cookie" = [], "csrf_header" = [])),
    responses(
        (status = 202, description = "Queued; poll the task", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not an image, a name, a port, or a named volume", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 409, description = "`conflict`: a container of that name exists", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_create(
    State(state): State<SharedState>,
    current: CurrentUser,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    // Forwarded as sent. Every field is validated by the operation's own typed
    // input — the image reference, the volume names, the environment keys — and
    // a second copy of those rules here would be a second thing to keep in step,
    // which is the mistake the stack whitelist made three times over.
    ops::invoke(&state, &current.auth, "docker.create", body).await
}
