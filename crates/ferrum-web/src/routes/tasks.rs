//! Reading tasks and their logs (spec §11.17).

use axum::Json;
use axum::extract::{Path, Query, State};
use ferrum_core::TaskId;
use serde::{Deserialize, Serialize};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub tasks: Vec<ferrum_db::models::Task>,
    /// Drives the badge on the task drawer.
    pub active: i64,
}

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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Serialize)]
pub struct LogsResponse {
    pub lines: Vec<ferrum_db::models::TaskLogLine>,
}

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
