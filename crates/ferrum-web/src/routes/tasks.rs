//! Reading tasks and their logs (spec §11.17).

use axum::Json;
use axum::extract::{Path, Query, State};
use ferrum_core::TaskId;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::state::SharedState;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListResponse {
    /// Task rows. The shape is `ferrum_db::models::Task`'s serialization; it is
    /// deliberately not re-modelled here, so the schema stays honest when the
    /// model grows a column.
    #[schema(value_type = Vec<Object>)]
    pub tasks: Vec<ferrum_db::models::Task>,
    /// Drives the badge on the task drawer.
    pub active: i64,
}

/// Recent tasks in this caller's tenant scope, newest first.
#[utoipa::path(
    get,
    path = "/api/tasks",
    tag = "tasks",
    security(("session_cookie" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Task rows plus the number still running", body = ListResponse),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
    ),
)]
pub async fn list(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<ListResponse>> {
    let repo = state.db.tasks(&current.auth.tenant_scope);
    let tasks = repo
        .list(q.limit, q.offset.max(0))
        .await
        .map_err(ApiError::from)?;
    let active = repo.count_active().await.map_err(ApiError::from)?;
    Ok(Json(ListResponse { tasks, active }))
}

/// One task's current state.
#[utoipa::path(
    get,
    path = "/api/tasks/{id}",
    tag = "tasks",
    security(("session_cookie" = [])),
    params(("id" = String, Path, description = "Task id (UUID)")),
    responses(
        (status = 200, description = "The task row (`ferrum_db::models::Task`)", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a UUID", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: also the answer for another tenant's task", body = ApiErrorBody),
    ),
)]
pub async fn detail(
    State(state): State<SharedState>,
    current: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<ferrum_db::models::Task>> {
    let id = parse_task_id(&id)?;
    let task = state
        .db
        .tasks(&current.auth.tenant_scope)
        .by_id(id)
        .await
        .map_err(ApiError::from)?
        // A task in another tenant is "not found", not "forbidden": whether it
        // exists is itself information.
        .ok_or_else(|| ApiError::not_found("task"))?;
    Ok(Json(task))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogQuery {
    /// Resume point, so a reconnecting drawer does not re-render the whole log.
    #[serde(default)]
    pub after_seq: i64,
    #[serde(default = "default_log_limit")]
    pub limit: i64,
}

fn default_log_limit() -> i64 {
    1000
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LogsResponse {
    /// `ferrum_db::models::TaskLogLine` rows, in sequence order.
    #[schema(value_type = Vec<Object>)]
    pub lines: Vec<ferrum_db::models::TaskLogLine>,
}

/// A task's log lines, resumable via `after_seq`.
#[utoipa::path(
    get,
    path = "/api/tasks/{id}/logs",
    tag = "tasks",
    security(("session_cookie" = [])),
    params(("id" = String, Path, description = "Task id (UUID)"), LogQuery),
    responses(
        (status = 200, description = "Log lines after the requested sequence number", body = LogsResponse),
        (status = 400, description = "`invalid_input`: not a UUID", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
    ),
)]
pub async fn logs(
    State(state): State<SharedState>,
    current: CurrentUser,
    Path(id): Path<String>,
    Query(q): Query<LogQuery>,
) -> ApiResult<Json<LogsResponse>> {
    let id = parse_task_id(&id)?;
    let lines = state
        .db
        .tasks(&current.auth.tenant_scope)
        .logs(id, q.after_seq.max(0), q.limit)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(LogsResponse { lines }))
}

fn parse_task_id(raw: &str) -> ApiResult<TaskId> {
    raw.parse::<TaskId>().map_err(|_| {
        ApiError::code(
            ferrum_core::ErrorCode::InvalidInput,
            "task id must be a UUID",
        )
    })
}
