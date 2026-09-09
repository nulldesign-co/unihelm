//! The process table: what is running, and the one thing that can be done to it
//! (spec §11.11; issue 46).
//!
//! Two routes, and the split between them is the point. `GET` is a monitor and
//! needs `server_read`, the same permission as the dashboard it explains: an
//! operator watching a machine sit at 96% has to be able to see *what* is at
//! 96%. `POST /kill` takes something off the machine and needs `server_manage`,
//! like stopping a service.
//!
//! Neither permission is the tenant boundary, and the 0.8.0 review found out the
//! hard way that this file read as though it were. `server_read` is a
//! `Role::Reseller` default and a reseller is a tenant with peers on the same
//! box, so until `unihelm_ops::processes` started refusing any scope narrower
//! than the whole machine, `GET /api/processes` handed one reseller every other
//! tenant's verbatim command lines — passwords on argv included — their Linux
//! accounts and their subscription ids. The refusal is `tenant_scope_violation`,
//! it comes from the operation, and the sidebar link is not a gate: the answer
//! has to be no at the endpoint whether or not a page offers the button.
//!
//! Neither route makes a judgement of its own. Which processes may be signalled
//! is decided in `unihelm_ops::processes`, on the machine, from the uid and the
//! cgroup it read there — this file could not re-derive any of it from an HTTP
//! request, and a second opinion here would only be a weaker one that disagrees.
//!
//! What this file does own is `web_pid`. The agent has no reliable way to
//! identify the web process (`metrics.snapshot` takes the same field for the
//! same reason), so it is passed on both routes: with it, the process serving
//! this very page is refused by pid even on a development install that runs
//! outside systemd, where the unit rule has nothing to match.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::HeaderMap;
use serde::Deserialize;
use serde_json::json;
use unihelm_core::Permission;
use unihelm_db::audit::NewAuditEntry;
use utoipa::{IntoParams, ToSchema};

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// `cpu` (default) or `memory`.
    #[serde(default)]
    pub sort: Option<String>,
    /// How many rows; the agent clamps it to 200.
    #[serde(default)]
    pub limit: Option<usize>,
    /// Substring of the command, its arguments, the owning account or the unit.
    /// The agent applies it to the whole machine before it sorts and cuts.
    #[serde(default)]
    pub search: Option<String>,
}

/// What is running, what it is using, and whose it is.
///
/// The answer carries `refresh_seconds` — the interval the agent expects to be
/// asked again on. The page reads that rather than choosing for itself, so a
/// client cannot poll faster than the CPU counters underneath it change.
#[utoipa::path(
    get,
    path = "/api/processes",
    tag = "processes",
    security(("session_cookie" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Processes, busiest first, with the CPU window they were measured over, the interval to poll on, and — on any process the panel would refuse to signal — the reason it would refuse", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_read`; or `tenant_scope_violation`: the process table is the whole machine's, so only an account scoped to the whole machine is shown it", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn list(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;

    let data = ops::invoke_now(&state, &current.auth, "process.list", list_input(&q)).await?;
    Ok(Json(data))
}

/// What `process.list` is asked for. Separate from the handler so the one
/// judgement in it — that the panel names its own web process — is testable
/// without an agent behind it.
///
/// An absent query field is **omitted**, not sent as `null`. `sort` on the
/// operation is an enum with a serde default, and a default fills in for a
/// missing key rather than for an explicit null: sending `"sort": null` would
/// turn "no preference" into a parse failure the operator reads as a broken
/// page.
fn list_input(q: &ListQuery) -> serde_json::Value {
    let mut input = serde_json::Map::new();
    input.insert("web_pid".into(), json!(std::process::id()));
    if let Some(sort) = &q.sort {
        input.insert("sort".into(), json!(sort));
    }
    if let Some(limit) = q.limit {
        input.insert("limit".into(), json!(limit));
    }
    if let Some(search) = &q.search {
        input.insert("search".into(), json!(search));
    }
    serde_json::Value::Object(input)
}

/// A kill, with the process it means named back.
#[derive(Debug, Deserialize, ToSchema)]
pub struct KillRequest {
    pub pid: u32,
    /// The command the operator was shown for this pid, as they were shown it.
    ///
    /// Sent from the confirmation dialog, not from the row: pids are recycled,
    /// and the agent refuses unless this and `confirm_user` still describe the
    /// process behind that pid. That check is what makes a stale list a refusal
    /// instead of a kill.
    pub confirm_command: String,
    /// The owning account the operator was shown. `""` for a uid with no
    /// `passwd` entry, which is what the row shows too.
    pub confirm_user: String,
    /// `term` (default) or `kill`.
    #[serde(default)]
    pub signal: Option<String>,
}

/// Send a signal to one process.
///
/// The answer says what was **sent**, never that the process exited: a signal
/// is a request to the kernel, and SIGTERM in particular is a request to the
/// process, which may ignore it.
#[utoipa::path(
    post,
    path = "/api/processes/kill",
    tag = "processes",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = KillRequest,
    responses(
        (status = 200, description = "The signal was sent. The note says what that does and does not mean.", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: the pid is not a single process, or the command and owner no longer match the process behind it", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`: needs `server_manage`; or `tenant_scope_violation`: the pid namespace is the whole machine's", body = ApiErrorBody),
        (status = 404, description = "`not_found`: nothing is running under that pid", body = ApiErrorBody),
        (status = 409, description = "`conflict`: the process belongs to init, to the panel, or to a system account, and the reason names which", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn kill(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<KillRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    // Written before the signal, and it records what was *asked for* — the pid
    // with the command and owner the operator was looking at when they asked.
    // A row written afterwards would be missing exactly the attempts worth
    // auditing: the ones the agent refused.
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: "process.kill".to_string(),
            target: Some(format!("pid {}", body.pid)),
            detail: json!({
                "pid": body.pid,
                "command": body.confirm_command,
                "user": body.confirm_user,
                "signal": body.signal,
            }),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;

    let data = ops::invoke_now(&state, &current.auth, "process.kill", kill_input(&body)).await?;
    Ok(Json(data))
}

/// What `process.kill` is asked for.
///
/// Every field is passed through as the operator gave it. The agent compares
/// `confirm_command` and `confirm_user` against the live process, so anything
/// this normalised or dropped would turn a refusal back into a kill of whatever
/// now holds that pid.
fn kill_input(body: &KillRequest) -> serde_json::Value {
    let mut input = serde_json::Map::new();
    input.insert("pid".into(), json!(body.pid));
    input.insert("confirm_command".into(), json!(body.confirm_command));
    input.insert("confirm_user".into(), json!(body.confirm_user));
    input.insert("web_pid".into(), json!(std::process::id()));
    // Omitted rather than null when the caller named no signal, for the reason
    // `list_input` omits its own: the operation's default is SIGTERM, and a
    // null would be a parse error instead of that default.
    if let Some(signal) = &body.signal {
        input.insert("signal".into(), json!(signal));
    }
    serde_json::Value::Object(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The confirmation is the whole safety property of the kill, and it is the
    /// one thing this file could break without the agent noticing: the agent
    /// compares what it is sent against the live process, so a route that
    /// "helpfully" normalised or dropped either field would turn a refusal back
    /// into a kill of whatever now holds that pid.
    #[test]
    fn the_confirmation_the_operator_typed_reaches_the_agent_unchanged() {
        let body: KillRequest = serde_json::from_value(json!({
            "pid": 4123,
            "confirm_command": "php-fpm",
            "confirm_user": "uh_abc123",
            "signal": "kill",
        }))
        .expect("the request shape parses");

        let sent = kill_input(&body);
        assert_eq!(sent["pid"], json!(4123));
        assert_eq!(sent["confirm_command"], json!("php-fpm"));
        assert_eq!(sent["confirm_user"], json!("uh_abc123"));
        assert_eq!(sent["signal"], json!("kill"));
    }

    /// A uid with no `passwd` entry is shown as an empty owner, and the empty
    /// string is what the agent compares against. Dropping the key would make
    /// the agent read the field as missing and refuse a kill the operator
    /// confirmed correctly.
    #[test]
    fn an_owner_with_no_passwd_entry_is_still_sent_as_a_confirmation() {
        let body: KillRequest = serde_json::from_value(json!({
            "pid": 4123,
            "confirm_command": "php-fpm",
            "confirm_user": "",
        }))
        .expect("the request shape parses");

        let sent = kill_input(&body);
        assert_eq!(sent["confirm_user"], json!(""));
        assert!(sent.get("confirm_user").is_some());
        // No signal named leaves the key out entirely, so the operation's own
        // default applies. A `null` there is a parse error, not a default.
        assert!(sent.get("signal").is_none());
    }

    /// Both routes name the web process, which is how the page serving the
    /// request is refused by pid on an install that runs outside systemd.
    #[test]
    fn both_routes_tell_the_agent_which_process_is_the_panel() {
        let body: KillRequest = serde_json::from_value(json!({
            "pid": 4123,
            "confirm_command": "php",
            "confirm_user": "uh_abc123",
        }))
        .expect("the request shape parses");

        assert_eq!(kill_input(&body)["web_pid"], json!(std::process::id()));

        let listing = list_input(&ListQuery {
            sort: None,
            limit: None,
            search: None,
        });
        assert_eq!(listing["web_pid"], json!(std::process::id()));
        // A query field nobody supplied is left out, so the operation's own
        // default decides. Sending `null` for `sort` would be a parse failure
        // rather than "busiest first".
        for absent in ["sort", "limit", "search"] {
            assert!(listing.get(absent).is_none(), "{absent} should be omitted");
        }
    }
}
