//! The bridge from an HTTP request to an agent operation.
//!
//! Every route that does privileged work goes through here, so the mapping from
//! "the agent accepted this as a task" to "202 with a task id" is written once
//! and behaves the same everywhere.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ferrum_core::AuthContext;
use ferrum_ipc::frame::ResponseBody;
use serde::Serialize;

use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;

/// A long-running operation's receipt.
#[derive(Debug, Serialize)]
pub struct TaskAccepted {
    pub task_id: String,
    /// Where to watch it. The UI opens the task drawer on this.
    pub task_url: String,
}

/// Call an operation and turn its verdict into a response.
///
/// Immediate operations answer 200 with their data. Anything the agent turned
/// into a task answers **202** with the task id — the distinction matters,
/// because a client that treats "accepted" as "done" will refresh a list before
/// the work has happened and conclude nothing occurred.
pub async fn invoke(
    state: &SharedState,
    auth: &AuthContext,
    op: &str,
    input: serde_json::Value,
) -> ApiResult<Response> {
    match state.agent.call(op, auth, input).await? {
        ResponseBody::Ok { data } => Ok((StatusCode::OK, Json(data)).into_response()),
        ResponseBody::Err { error } => {
            Err(ApiError::new(error).with_request_id(auth.request_id.clone()))
        }
        ResponseBody::Task { task_id } => Ok((
            StatusCode::ACCEPTED,
            Json(TaskAccepted {
                task_id: task_id.to_string(),
                task_url: format!("/api/tasks/{task_id}"),
            }),
        )
            .into_response()),
    }
}

/// Call an operation that must answer immediately.
///
/// Used by the read paths, where a task id would be a bug rather than a
/// legitimate outcome.
pub async fn invoke_now(
    state: &SharedState,
    auth: &AuthContext,
    op: &str,
    input: serde_json::Value,
) -> ApiResult<serde_json::Value> {
    match state.agent.call(op, auth, input).await? {
        ResponseBody::Ok { data } => Ok(data),
        ResponseBody::Err { error } => {
            Err(ApiError::new(error).with_request_id(auth.request_id.clone()))
        }
        ResponseBody::Task { task_id } => Err(ApiError::code(
            ferrum_core::ErrorCode::Internal,
            format!("`{op}` unexpectedly became task {task_id}"),
        )),
    }
}
