//! Tasks: history, logs, cancel and retry (spec §11.17).
//!
//! "This is how users *see* the panel working — transparency is the antidote to
//! aaPanel's opaque hangs." Two decisions here follow from that sentence:
//!
//! * **Retry re-runs, it does not resurrect.** A retried task is a *new* task
//!   with the same op and the same input, so the failed one keeps its logs and
//!   its reason and the history still says what happened. Rewriting the old row
//!   would erase the evidence the page exists to show.
//! * **Cancel is scoped here before it is sent.** The agent's `CancelTask`
//!   control frame carries no tenant scope — it is the panel user's own socket
//!   — so this file resolves the task through the caller's scope *first*, and a
//!   task the caller cannot see is `not_found` rather than cancelled.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use ferrum_core::{ErrorCode, Permission, TaskId};
use ferrum_db::audit::NewAuditEntry;
use ferrum_db::models::TaskStatus;
use ferrum_db::tasks::TaskFilter;
use ferrum_ipc::frame::ControlKind;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use utoipa::{IntoParams, ToSchema};

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Exactly one operation name, e.g. `site.create`. Compared, never
    /// interpolated.
    #[serde(default)]
    pub op: Option<String>,
    /// `queued`, `running`, `ok`, `failed` or `cancelled`.
    #[serde(default)]
    pub status: Option<String>,
    /// RFC 3339. Inclusive.
    #[serde(default)]
    pub since: Option<String>,
    /// RFC 3339. Inclusive.
    #[serde(default)]
    pub until: Option<String>,
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
    /// Every op name present in this caller's history, so the filter control
    /// only offers choices that would match something.
    pub ops: Vec<String>,
}

/// Recent tasks in this caller's tenant scope, newest first.
#[utoipa::path(
    get,
    path = "/api/tasks",
    tag = "tasks",
    security(("session_cookie" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Task rows, the number still running, and the op names available as filters", body = ListResponse),
        (status = 400, description = "`invalid_input`: an unknown `status`, or a `since`/`until` that is not RFC 3339", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
    ),
)]
pub async fn list(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<ListResponse>> {
    let repo = state.db.tasks(&current.auth.tenant_scope);
    let filter = TaskFilter {
        op: q.op.filter(|op| !op.is_empty()),
        status: match q.status.as_deref().filter(|s| !s.is_empty()) {
            None => None,
            Some(raw) => Some(TaskStatus::parse(raw).map_err(|_| {
                ApiError::code(
                    ErrorCode::InvalidInput,
                    "status must be queued, running, ok, failed or cancelled",
                )
            })?),
        },
        since: parse_time(q.since.as_deref(), "since")?,
        until: parse_time(q.until.as_deref(), "until")?,
    };
    let tasks = repo
        .list_filtered(&filter, q.limit, q.offset.max(0))
        .await
        .map_err(ApiError::from)?;
    let active = repo.count_active().await.map_err(ApiError::from)?;
    let ops = repo.distinct_ops().await.map_err(ApiError::from)?;
    Ok(Json(ListResponse { tasks, active, ops }))
}

/// An RFC 3339 instant from a query string, or a named error.
fn parse_time(raw: Option<&str>, field: &'static str) -> ApiResult<Option<time::OffsetDateTime>> {
    let Some(raw) = raw.filter(|r| !r.is_empty()) else {
        return Ok(None);
    };
    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .map(Some)
        .map_err(|_| {
            ApiError::code(
                ErrorCode::InvalidInput,
                format!("`{field}` must be an RFC 3339 timestamp"),
            )
        })
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

/// Ask the agent to stop a task.
///
/// The scope check happens here and the answer for another tenant's task is
/// `not_found`: the agent's cancel frame has no tenant scope of its own, so
/// this is the only place that containment can be applied.
#[utoipa::path(
    post,
    path = "/api/tasks/{id}/cancel",
    tag = "tasks",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = String, Path, description = "Task id (UUID)")),
    responses(
        (status = 200, description = "The cancellation was sent; watch the task's state for the outcome", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a UUID", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `task_cancel` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: also the answer for another tenant's task", body = ApiErrorBody),
        (status = 409, description = "`task_not_cancellable`: the task did not opt in, or has already finished", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn cancel(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::TaskCancel)
        .map_err(ApiError::from)?;
    let id = parse_task_id(&id)?;
    let task = visible_task(&state, &current, id).await?;

    // Refused here as well as in the database, so the UI gets the real reason
    // rather than a cancel that silently does nothing.
    if !task.cancellable {
        return Err(ApiError::code(
            ErrorCode::TaskNotCancellable,
            "this task cannot be cancelled",
        ));
    }
    if task.status.is_terminal() {
        return Err(ApiError::code(
            ErrorCode::TaskNotCancellable,
            "this task has already finished",
        ));
    }

    audit(&state, &current, &headers, &peer, "task.cancel", &task).await?;
    state
        .agent
        .control(ControlKind::CancelTask { task_id: id })
        .await
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({ "task_id": id, "requested": true })))
}

/// Run a finished task's operation again.
///
/// A *new* task, with the same op and the same input. The original keeps its
/// row, its logs and its failure reason — a history that quietly mutates is not
/// a history, and "what did we try, and what did it say" is the question this
/// page exists to answer.
///
/// The agent re-checks the caller's permission for the operation being retried,
/// so a retry can never do something the caller could not have asked for
/// directly today, whatever they were allowed to do when the task first ran.
#[utoipa::path(
    post,
    path = "/api/tasks/{id}/retry",
    tag = "tasks",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = String, Path, description = "Task id (UUID)")),
    responses(
        (status = 200, description = "The operation answered immediately", body = serde_json::Value),
        (status = 202, description = "A new task was accepted; its id is in the body", body = crate::routes::ops::TaskAccepted),
        (status = 400, description = "`invalid_input`: not a UUID", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: the caller may not run that operation / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: also the answer for another tenant's task", body = ApiErrorBody),
        (status = 409, description = "`conflict`: the task has not finished yet", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn retry(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let id = parse_task_id(&id)?;
    let task = visible_task(&state, &current, id).await?;

    // Retrying something still in flight would run it twice concurrently,
    // which for a non-idempotent op is the worst possible outcome.
    if !task.status.is_terminal() {
        return Err(ApiError::code(
            ErrorCode::Conflict,
            "this task has not finished yet",
        ));
    }

    audit(&state, &current, &headers, &peer, "task.retry", &task).await?;
    ops::invoke(&state, &current.auth, &task.op, task.input.clone()).await
}

/// A task this caller may see, or `not_found`.
async fn visible_task(
    state: &SharedState,
    current: &CurrentUser,
    id: TaskId,
) -> ApiResult<ferrum_db::models::Task> {
    state
        .db
        .tasks(&current.auth.tenant_scope)
        .by_id(id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("task"))
}

async fn audit(
    state: &SharedState,
    current: &CurrentUser,
    headers: &HeaderMap,
    peer: &SocketAddr,
    action: &str,
    task: &ferrum_db::models::Task,
) -> ApiResult<()> {
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(peer), headers)),
            action: action.to_string(),
            target: Some(task.id.to_string()),
            // The op, not the input: the input was already audited when the
            // task was created, and repeating it here would duplicate whatever
            // the redactor had to work on.
            detail: serde_json::json!({ "op": task.op, "status": task.status.as_str() }),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: task.subscription_id,
        })
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

fn parse_task_id(raw: &str) -> ApiResult<TaskId> {
    raw.parse::<TaskId>().map_err(|_| {
        ApiError::code(
            ferrum_core::ErrorCode::InvalidInput,
            "task id must be a UUID",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_date_filter_must_be_rfc_3339_or_it_is_a_named_error() {
        // A silently-ignored bad filter shows the user a list that is not what
        // they asked for, which on a history page reads as data loss.
        assert!(parse_time(None, "since").unwrap().is_none());
        assert!(parse_time(Some(""), "since").unwrap().is_none());
        assert!(parse_time(Some("2026-08-28T00:00:00Z"), "since").unwrap().is_some());

        let err = parse_time(Some("yesterday"), "since").unwrap_err();
        assert_eq!(err.inner.code, ErrorCode::InvalidInput);
        assert!(err.inner.detail.contains("since"));
    }

    #[test]
    fn a_task_id_must_be_a_uuid() {
        assert!(parse_task_id("not-a-uuid").is_err());
        assert!(parse_task_id(&uuid::Uuid::new_v4().to_string()).is_ok());
    }
}
