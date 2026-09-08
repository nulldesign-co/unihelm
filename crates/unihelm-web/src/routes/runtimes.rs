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

/// What to install.
///
/// Every field is optional because the operation behind this takes them that
/// way: `runtime` defaults to Node, `version` and `major` are two spellings of
/// the same choice, and Go and Ruby have exactly one version that lands on
/// `$PATH` so they name neither.
#[derive(Debug, Deserialize, ToSchema)]
pub struct InstallRuntime {
    /// `node`, `python`, `go` or `ruby`. Absent means Node.
    #[serde(default)]
    pub runtime: Option<String>,
    /// The version, as `runtime.list` spells it: `22`, `3.12`.
    #[serde(default)]
    pub version: Option<String>,
    /// A Node major line: 20, 22, 24. The older spelling of `version`.
    #[serde(default)]
    pub major: Option<u32>,
}

/// Install a language runtime from a signed repository.
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
        (status = 501, description = "`not_implemented`: no signed repository for this distribution", body = ApiErrorBody),
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
        install_args(&body),
    )
    .await
}

/// The request, as the operation spells it.
///
/// Its own function so the forwarding can be asserted. The bug it replaces was
/// a handler that declared one required `major` and then rebuilt the request
/// from that field alone: a caller asking for Python 3.12 was rejected by serde
/// before the operation ever saw it, and the only shape that could reach the
/// agent was a Node line. Nothing here decides whether a runtime or a version is
/// installable — `runtime.install` does, and duplicating that judgement is how
/// the two drifted apart in the first place.
fn install_args(body: &InstallRuntime) -> serde_json::Value {
    let mut args = serde_json::Map::new();
    if let Some(runtime) = &body.runtime {
        args.insert("runtime".into(), json!(runtime));
    }
    if let Some(version) = &body.version {
        args.insert("version".into(), json!(version));
    }
    if let Some(major) = body.major {
        args.insert("major".into(), json!(major));
    }
    serde_json::Value::Object(args)
}

/// Which installed version a bare command name resolves to.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetRuntimeDefault {
    /// Only `php` has a default this panel can move.
    pub runtime: String,
    /// The version to point at, as `runtime.list` reports it.
    pub version: String,
}

/// Point a bare command name at one installed version.
#[utoipa::path(
    post,
    path = "/api/runtimes/default",
    tag = "runtimes",
    request_body = SetRuntimeDefault,
    security(("session_cookie" = [], "csrf_header" = [])),
    responses(
        (status = 200, description = "What the bare name resolves to now", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `stack.manage`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: not installed, or not registered with update-alternatives", body = ApiErrorBody),
        (status = 501, description = "`not_implemented`: this runtime has no default to move", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn set_default(
    State(state): State<SharedState>,
    current: CurrentUser,
    Json(body): Json<SetRuntimeDefault>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::StackManage)
        .map_err(ApiError::from)?;
    // Immediate: it is one `update-alternatives --set`, and a task for it would
    // mean a spinner and a poll for something already finished.
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "runtime.default.set",
        json!({ "runtime": body.runtime, "version": body.version }),
    )
    .await?;
    Ok(Json(data))
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

// ---------------------------------------------------------------------------
// Images and volumes
// ---------------------------------------------------------------------------

/// Which image to pull or remove.
///
/// **In a body, not in the path**, and that is not a style choice: an image
/// reference is `ghcr.io/owner/app:v1` — slashes and colons — and a path
/// parameter carrying one is a percent-encoding problem at every client that
/// ever calls it. A volume name has no such trouble and stays in the path
/// below, where it reads as the resource it is.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ImageRequest {
    /// `nginx`, `redis:7`, `ghcr.io/owner/app:v1`. Validated by the operation.
    pub image: String,
}

/// Fetch an image, or confirm the tag is already at this digest.
#[utoipa::path(
    post,
    path = "/api/server/docker/images/pull",
    tag = "server",
    request_body = ImageRequest,
    security(("session_cookie" = [], "csrf_header" = [])),
    responses(
        (status = 202, description = "Queued; poll the task", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not an image reference", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_image_pull(
    State(state): State<SharedState>,
    current: CurrentUser,
    Json(body): Json<ImageRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    // A task: a pull is minutes on the uplink a cheap VPS actually has, and the
    // operator should watch it rather than a spinner.
    ops::invoke(
        &state,
        &current.auth,
        "docker.image.pull",
        json!({ "image": body.image }),
    )
    .await
}

/// Delete an image. One a container still needs is refused, with the container
/// named.
#[utoipa::path(
    post,
    path = "/api/server/docker/images/remove",
    tag = "server",
    request_body = ImageRequest,
    security(("session_cookie" = [], "csrf_header" = [])),
    responses(
        (status = 200, description = "Removed, with Docker's untagged and deleted lines", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not an image reference", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such image", body = ApiErrorBody),
        (status = 409, description = "`dependents_exist`: a container is built on it", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_image_remove(
    State(state): State<SharedState>,
    current: CurrentUser,
    Json(body): Json<ImageRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    // Immediate, so the refusal naming the container reaches the page that
    // asked rather than a task log the operator has to go and open.
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "docker.image.remove",
        json!({ "image": body.image }),
    )
    .await?;
    Ok(Json(data))
}

/// Whether to delete or only to list.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct PruneRequest {
    /// List what would go and delete nothing. Absent means delete.
    #[serde(default)]
    pub dry_run: bool,
}

/// Reclaim the disk that dangling image layers eat.
#[utoipa::path(
    post,
    path = "/api/server/docker/images/prune",
    tag = "server",
    request_body = PruneRequest,
    security(("session_cookie" = [], "csrf_header" = [])),
    responses(
        (status = 202, description = "Queued; the task reports what went and how much came back", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_image_prune(
    State(state): State<SharedState>,
    current: CurrentUser,
    Json(body): Json<PruneRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    // A task: deleting tens of gigabytes of layers off a slow disk is minutes,
    // and the list of what went belongs in a log that outlives the page.
    ops::invoke(
        &state,
        &current.auth,
        "docker.image.prune",
        json!({ "dry_run": body.dry_run }),
    )
    .await
}

/// Delete a volume. One a container references, or one holding an engine's
/// databases, is refused.
#[utoipa::path(
    delete,
    path = "/api/server/docker/volumes/{name}",
    tag = "server",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("name" = String, Path, description = "Volume name")),
    responses(
        (status = 200, description = "Removed", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a volume name", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such volume", body = ApiErrorBody),
        (status = 409, description = "`conflict` / `dependents_exist`: it holds an engine's data, or a container mounts it", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_volume_remove(
    State(state): State<SharedState>,
    current: CurrentUser,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    // Immediate, for the reason the image removal is: both refusals name what
    // is in the way, and a refusal an operator has to poll for is a refusal
    // they will read as a failed request.
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "docker.volume.remove",
        json!({ "volume": name }),
    )
    .await?;
    Ok(Json(data))
}

// ---------------------------------------------------------------------------
// The container templates
// ---------------------------------------------------------------------------

/// The curated container templates the panel ships.
#[utoipa::path(
    get,
    path = "/api/server/docker/templates",
    tag = "server",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Every template, with its pinned image, ports and volumes", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_templates(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    // `server_read`, the same as the inventory this list appears beside: the
    // catalogue is compiled in and says nothing about this machine.
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "docker.template.list", json!({})).await?;
    Ok(Json(data))
}

/// What to call the container a template is being filled in for.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PrepareTemplate {
    /// The container name. The template's own suggestion when absent.
    #[serde(default)]
    pub name: Option<String>,
}

/// Fill in one template for this machine.
///
/// **A POST for something that changes nothing on the server**, deliberately.
/// The answer carries a freshly generated password for the templates that need
/// one, so it must not sit in a URL, in a proxy's cache or in a browser's
/// history — and it must not be reachable without the CSRF header, because the
/// only thing it is for is the create form behind it.
#[utoipa::path(
    post,
    path = "/api/server/docker/templates/{id}/prepare",
    tag = "server",
    request_body = PrepareTemplate,
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = String, Path, description = "Template id, as the list prints it")),
    responses(
        (status = 200, description = "A draft `docker.create` accepts, with generated secrets filled in", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a container name", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no template of that id", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn docker_template_prepare(
    State(state): State<SharedState>,
    current: CurrentUser,
    Path(id): Path<String>,
    Json(body): Json<PrepareTemplate>,
) -> ApiResult<Json<serde_json::Value>> {
    // `server_manage`, not `server_read`. The draft is a credential, and the
    // only operation that can spend it is `docker.create`, which needs this. A
    // reader handed one could not use it, so handing them one would be giving
    // away a secret for nothing.
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    // Immediate: this reads one `docker ps` and answers. The task is the create
    // that follows, and a draft the operator has to poll for is a form that
    // fills itself in some seconds after they asked for it.
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "docker.template.prepare",
        prepare_args(&id, &body),
    )
    .await?;
    Ok(Json(data))
}

/// The request, as the operation spells it.
///
/// Its own function so the forwarding can be asserted, exactly like
/// [`install_args`]. The template id comes from the path and the name from the
/// body, and neither is checked here: `docker.template.prepare` refuses an id
/// it does not have by listing the ones it does, and parses the name through
/// the same `ContainerRef` grammar `docker.create` will. A second copy of
/// either rule in this file would be a second thing to keep in step.
fn prepare_args(id: &str, body: &PrepareTemplate) -> serde_json::Value {
    let mut args = serde_json::Map::new();
    args.insert("template".into(), json!(id));
    // Omitted rather than sent as null when the operator did not type one, so
    // the operation's own default — the template's suggested name — is the only
    // place that decides what an unnamed container is called.
    if let Some(name) = &body.name {
        args.insert("name".into(), json!(name));
    }
    serde_json::Value::Object(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the Runtimes page sends, which the previous handler could not
    /// parse at all: it required `major`, so every Python, Go and Ruby install
    /// — and every Node install, which the page spells as a version too — came
    /// back 400 without reaching the agent.
    #[test]
    fn the_body_the_panel_sends_reaches_the_operation_intact() {
        for (body, expected) in [
            (
                json!({ "runtime": "python", "version": "3.12" }),
                json!({ "runtime": "python", "version": "3.12" }),
            ),
            (
                json!({ "runtime": "node", "version": "22" }),
                json!({ "runtime": "node", "version": "22" }),
            ),
            // Go and Ruby have exactly one version that lands on `$PATH`, so
            // the page sends no version and the operation picks.
            (json!({ "runtime": "go" }), json!({ "runtime": "go" })),
            // The older spelling, still accepted: an API client written against
            // the previous handler keeps working.
            (json!({ "major": 22 }), json!({ "major": 22 })),
        ] {
            let asked: InstallRuntime = serde_json::from_value(body.clone()).unwrap_or_else(|e| {
                panic!("{body} is what the panel sends and it did not parse: {e}")
            });
            assert_eq!(install_args(&asked), expected, "from {body}");
        }
    }

    /// An empty body is the operation's decision to refuse or default, not this
    /// handler's. Inventing a runtime here would mean two places deciding what
    /// "install" means with nothing keeping them in step.
    #[test]
    fn an_empty_body_is_forwarded_empty_rather_than_guessed_at() {
        let asked: InstallRuntime = serde_json::from_value(json!({})).unwrap();
        assert_eq!(install_args(&asked), json!({}));
    }

    /// Why the image endpoints take their reference in a body while the volume
    /// endpoint keeps its name in the path.
    ///
    /// An image reference carries slashes and colons — `ghcr.io/owner/app:v1`
    /// is one token with four of them — so a path parameter holding one has to
    /// be percent-encoded by every client that ever calls it, and a client that
    /// forgets does not get an error: it addresses a different route. A volume
    /// name has no such characters, so it stays where it reads as the resource
    /// it is.
    #[test]
    fn a_registry_qualified_image_reaches_the_handler_whole() {
        for reference in [
            "nginx",
            "redis:7",
            "ghcr.io/owner/app:v1",
            "registry.example.com:5000/team/app@sha256:aaaa",
        ] {
            let asked: ImageRequest = serde_json::from_value(json!({ "image": reference }))
                .unwrap_or_else(|e| panic!("`{reference}` is what the page sends: {e}"));
            assert_eq!(asked.image, reference);
        }
    }

    /// The template id lives in the path and the name in the body, and both
    /// have to reach the operation under the names it reads them by. The bug
    /// this guards against is the one `install_args` replaced: a handler that
    /// rebuilt the request from one field and dropped the rest, which failed as
    /// a 400 the page could not explain.
    #[test]
    fn a_template_and_the_name_the_operator_typed_both_reach_the_operation() {
        let named: PrepareTemplate = serde_json::from_value(json!({ "name": "kuma" })).unwrap();
        assert_eq!(
            prepare_args("uptime-kuma", &named),
            json!({ "template": "uptime-kuma", "name": "kuma" })
        );
    }

    /// An unnamed draft is the template's suggestion, and only the operation
    /// knows what that is. Sending `null` would work today and would stop the
    /// moment anything in the chain read a present key as an answer.
    #[test]
    fn a_draft_with_no_name_omits_the_field_rather_than_sending_a_null() {
        let bare: PrepareTemplate = serde_json::from_value(json!({})).unwrap();
        assert_eq!(
            prepare_args("grafana", &bare),
            json!({ "template": "grafana" })
        );
    }

    /// A prune with no body is a prune, not a listing. An operator who pressed
    /// the button and got a list back would reasonably believe the disk had
    /// been reclaimed, which is the panel reporting something that did not
    /// happen.
    #[test]
    fn a_prune_defaults_to_deleting_rather_than_listing() {
        let bare: PruneRequest = serde_json::from_value(json!({})).unwrap();
        assert!(!bare.dry_run);
        let asked: PruneRequest = serde_json::from_value(json!({ "dry_run": true })).unwrap();
        assert!(asked.dry_run);
    }
}
