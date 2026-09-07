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
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use unihelm_core::{ErrorCode, Permission, TaskId};
use unihelm_db::audit::NewAuditEntry;
use unihelm_db::models::TaskStatus;
use unihelm_db::tasks::TaskFilter;
use unihelm_ipc::frame::ControlKind;
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
    /// Task rows: `unihelm_db::models::Task`'s serialization, plus `subject`.
    /// The row itself is deliberately not re-modelled here, so the schema stays
    /// honest when the model grows a column.
    #[schema(value_type = Vec<Object>)]
    pub tasks: Vec<TaskView>,
    /// Drives the badge on the task drawer.
    pub active: i64,
    /// Every op name present in this caller's history, so the filter control
    /// only offers choices that would match something.
    pub ops: Vec<String>,
}

/// A task row as the panel receives it: the stored row, plus the short subject
/// derived from its input by [`task_subject`].
///
/// Flattened rather than nested, so adding the subject did not move every other
/// field of a row the UI already reads.
#[derive(Debug, Serialize)]
pub struct TaskView {
    #[serde(flatten)]
    pub task: unihelm_db::models::Task,
    /// What the task acted on, when the panel can name it. Omitted rather than
    /// guessed — see [`task_subject`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

impl TaskView {
    fn new(task: unihelm_db::models::Task) -> Self {
        let subject = task_subject(&task.op, &task.input);
        Self { task, subject }
    }
}

/// Longest subject a row will carry. A history row is one line beside the op
/// name and the timestamp; a tenant path can be far longer than that.
const SUBJECT_MAX: usize = 60;

/// A short, human name for *what* a task acted on: `php 8.3`, `shop.example.com`.
///
/// Ten rows reading `stack.install` are the same three words ten times, and
/// "which install was that" is the question the history page exists to answer.
///
/// Derived here rather than by handing the browser the task's `input`: that
/// column is stored exactly as the caller sent it, unredacted, so a page that
/// rendered it would put whatever anybody typed — a relay password, an SFTP
/// password — on screen next to the op name.
///
/// Only fields that *name* the thing are read: a domain, a catalogue slug, a
/// container, an archive. An operation whose input carries nothing but row ids
/// gets `None`, and the row goes on showing its op name alone. That is the
/// honest answer: `site 12` is not a name anybody chose, and a subject invented
/// from a field that merely happens to be a string would be the panel telling
/// the operator what a task was when it does not know.
fn task_subject(op: &str, input: &serde_json::Value) -> Option<String> {
    match op {
        // These three take a flattened `StackComponent` — `{"component": "php",
        // "version": "8.3"}`. The version is the whole difference between two
        // PHP installs, so it belongs in the subject when one was asked for.
        "stack.install" | "stack.remove" | "engine.remove" => named_version(input, "component"),
        "runtime.install" => named_version(input, "runtime"),
        "site.create" | "panel.tls.issue" => text(input, "domain"),
        "app.create" | "docker.create" => text(input, "name"),
        "docker.image.pull" => text(input, "image"),
        // The WordPress site's own title, which is what the operator typed into
        // the install form and how they will recognise the install.
        "wp.install" => text(input, "title"),
        "wp.plugin.update" => single_plugin(input),
        "fs.compress" | "fs.extract" => text(input, "archive"),
        "plugin.install" => text(input, "source"),
        "plugin.remove" => text(input, "slug"),
        "webserver.switch" => text(input, "target"),
        // The relay host. Its neighbouring `password` field is exactly why the
        // browser is not handed this object to pick a subject out of itself.
        "mail.relay.set" => text(input, "host"),
        _ => None,
    }
}

/// `<name> <version>`, or the bare name when the caller expressed no preference.
fn named_version(input: &serde_json::Value, name_key: &str) -> Option<String> {
    let name = text(input, name_key)?;
    Some(match text(input, "version") {
        Some(version) => format!("{name} {version}"),
        None => name,
    })
}

/// The one plugin slug a `wp.plugin.update` names, if it names exactly one.
///
/// An empty list means "everything with an update available" and a longer one
/// has no single subject; both are honestly nameless rather than half-named.
fn single_plugin(input: &serde_json::Value) -> Option<String> {
    let [only] = input.get("plugins")?.as_array()?.as_slice() else {
        return None;
    };
    clean(only.as_str()?)
}

/// One string field of the input, trimmed to something a row can hold.
fn text(input: &serde_json::Value, key: &str) -> Option<String> {
    clean(input.get(key)?.as_str()?)
}

/// A row-sized, single-line form of a raw input value.
///
/// Newlines and control characters become spaces: the value reaches the DOM as
/// text, and a subject that wrapped over three lines would push the rest of the
/// history off the screen. An over-long one is cut with an ellipsis so the row
/// says it was cut rather than pretending the short form is the whole name.
fn clean(raw: &str) -> Option<String> {
    let collapsed = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>();
    let mut value = collapsed.split_whitespace().collect::<Vec<_>>().join(" ");
    if value.is_empty() {
        return None;
    }
    if value.chars().count() > SUBJECT_MAX {
        value = value.chars().take(SUBJECT_MAX - 1).collect();
        value.push('…');
    }
    Some(value)
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
        .map_err(ApiError::from)?
        .into_iter()
        .map(TaskView::new)
        .collect();
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
        (status = 200, description = "The task row (`unihelm_db::models::Task`, plus `subject`)", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a UUID", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: also the answer for another tenant's task", body = ApiErrorBody),
    ),
)]
pub async fn detail(
    State(state): State<SharedState>,
    current: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<TaskView>> {
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
    // The same subject the list carries: one row rendered two ways, described
    // two ways, is how the drawer and the history page drift apart.
    Ok(Json(TaskView::new(task)))
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
    /// `unihelm_db::models::TaskLogLine` rows, in sequence order.
    #[schema(value_type = Vec<Object>)]
    pub lines: Vec<unihelm_db::models::TaskLogLine>,
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
    Ok(Json(
        serde_json::json!({ "task_id": id, "requested": true }),
    ))
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
) -> ApiResult<unihelm_db::models::Task> {
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
    task: &unihelm_db::models::Task,
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
            unihelm_core::ErrorCode::InvalidInput,
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
        assert!(
            parse_time(Some("2026-08-28T00:00:00Z"), "since")
                .unwrap()
                .is_some()
        );

        let err = parse_time(Some("yesterday"), "since").unwrap_err();
        assert_eq!(err.inner.code, ErrorCode::InvalidInput);
        assert!(err.inner.detail.contains("since"));
    }

    #[test]
    fn a_task_id_must_be_a_uuid() {
        assert!(parse_task_id("not-a-uuid").is_err());
        assert!(parse_task_id(&uuid::Uuid::new_v4().to_string()).is_ok());
    }

    #[test]
    fn a_stack_operation_is_named_by_its_component_and_version() {
        // Ten `stack.install` rows were ten identical lines. The version is the
        // difference between two PHP installs, so it is part of the name.
        assert_eq!(
            task_subject(
                "stack.install",
                &serde_json::json!({ "component": "php", "version": "8.3" }),
            )
            .as_deref(),
            Some("php 8.3"),
        );
        assert_eq!(
            task_subject("stack.remove", &serde_json::json!({ "component": "redis" })).as_deref(),
            Some("redis"),
        );
        assert_eq!(
            task_subject(
                "runtime.install",
                &serde_json::json!({ "runtime": "node", "version": "22" }),
            )
            .as_deref(),
            Some("node 22"),
        );
    }

    #[test]
    fn a_site_operation_is_named_by_its_domain() {
        assert_eq!(
            task_subject(
                "site.create",
                &serde_json::json!({ "domain": "shop.example.com", "site_type": "php" }),
            )
            .as_deref(),
            Some("shop.example.com"),
        );
    }

    #[test]
    fn an_operation_the_derivation_does_not_know_is_left_unnamed() {
        // The row then shows the op name it has always shown. A subject the
        // panel had to invent would be worse than no subject at all.
        assert_eq!(task_subject("some.future.op", &serde_json::json!({})), None);
        // Known op, but the input carries only row ids: still nameless. `site
        // 12` is not a name anybody chose.
        assert_eq!(
            task_subject("site.update", &serde_json::json!({ "site_id": 12 })),
            None,
        );
        // Known op, naming field missing or the wrong shape.
        assert_eq!(task_subject("site.create", &serde_json::json!({})), None);
        assert_eq!(
            task_subject("site.create", &serde_json::json!({ "domain": 12 })),
            None,
        );
        assert_eq!(
            task_subject("site.create", &serde_json::json!({ "domain": "   " })),
            None,
        );
    }

    #[test]
    fn a_plugin_update_is_named_only_when_it_names_one_plugin() {
        // Empty means "everything with an update available" and a longer list
        // has no single subject; naming one of several would be a lie about
        // what ran.
        assert_eq!(
            task_subject(
                "wp.plugin.update",
                &serde_json::json!({ "install_id": 3, "plugins": ["akismet"] }),
            )
            .as_deref(),
            Some("akismet"),
        );
        assert_eq!(
            task_subject(
                "wp.plugin.update",
                &serde_json::json!({ "install_id": 3, "plugins": [] }),
            ),
            None,
        );
        assert_eq!(
            task_subject(
                "wp.plugin.update",
                &serde_json::json!({ "install_id": 3, "plugins": ["akismet", "jetpack"] }),
            ),
            None,
        );
    }

    #[test]
    fn a_subject_is_one_line_and_fits_a_row() {
        // It lands in a table cell as text: a newline in a WordPress title
        // would push the rest of the history down the page.
        assert_eq!(
            task_subject(
                "wp.install",
                &serde_json::json!({ "title": "My\nblog\tabout  things" }),
            )
            .as_deref(),
            Some("My blog about things"),
        );

        let long = "a".repeat(200);
        let cut = task_subject("fs.compress", &serde_json::json!({ "archive": long }))
            .expect("a long archive path is still a name");
        assert_eq!(cut.chars().count(), SUBJECT_MAX);
        // Cut, and saying so — a silently shortened path reads as the whole one.
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn the_row_carries_the_subject_beside_the_fields_the_ui_already_reads() {
        // Flattened, not nested: adding the subject must not move `op` or
        // `status` out from under the pages that read them.
        let view = TaskView {
            task: unihelm_db::models::Task {
                id: TaskId(uuid::Uuid::new_v4()),
                op: "stack.install".to_string(),
                input: serde_json::json!({ "component": "php", "version": "8.3" }),
                actor_user_id: None,
                subscription_id: None,
                status: TaskStatus::Ok,
                progress: 100,
                error_code: None,
                error_detail: None,
                cancellable: false,
                idempotent: true,
                request_id: None,
                created_at: time::OffsetDateTime::UNIX_EPOCH,
                started_at: None,
                finished_at: None,
            },
            subject: Some("php 8.3".to_string()),
        };

        let json = serde_json::to_value(&view).expect("a task row serialises");
        assert_eq!(json["op"], "stack.install");
        assert_eq!(json["subject"], "php 8.3");
    }
}
