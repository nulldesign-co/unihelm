//! The cron API (spec §11.8, §13).
//!
//! A thin bridge onto the `cron.*` operations in `ferrum_ops::cron`. The agent
//! re-derives the permission from the database and re-validates the schedule
//! and the command (spec §5.2 rule 4), so nothing here is load-bearing for
//! security on its own. Three things are nevertheless decided in this file:
//!
//! 1. **The upsert is split into two verbs.** `cron.set` creates *or* updates
//!    depending on whether it was given an `id`, which is right for an
//!    operation and wrong for a URL: a `POST /api/cron` that silently updated
//!    an existing row because a client echoed an id back would be a surprise.
//!    So `POST /api/cron` never carries an id and `PUT /api/cron/{id}` always
//!    does — the id comes from the path, and a body that disagrees cannot.
//!
//! 2. **The audit row records the schedule and the command in full.** Unlike a
//!    Node app's environment (see `apps.rs`), a cron command is not a place
//!    secrets belong — it is a command line visible in `ps` to anyone on the
//!    box the moment it runs — and "what did they schedule" is precisely the
//!    question an audit log exists to answer.
//!
//! 3. **`enabled` is omitted when the client did not send it**, so the agent's
//!    `#[serde(default)]` (which is `true`) decides, rather than this file
//!    guessing and the two drifting apart.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use ferrum_core::Permission;
use ferrum_db::audit::NewAuditEntry;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use utoipa::{IntoParams, ToSchema};

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// Narrow to one subscription. An id outside the caller's tenant scope is
    /// `not_found`, not an empty list.
    #[serde(default)]
    pub subscription_id: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// List the cron jobs this caller's tenant scope can see.
#[utoipa::path(
    get,
    path = "/api/cron",
    tag = "cron",
    security(("session_cookie" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Job rows (schedule, command, enabled, last apply error) plus `max_jobs_per_subscription`, tenant-scoped by the agent", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `cron_manage`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such subscription in this tenant's scope", body = ApiErrorBody),
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
        .require(Permission::CronManage)
        .map_err(ApiError::from)?;

    let mut input = json!({ "limit": q.limit, "offset": q.offset });
    if let Some(id) = q.subscription_id {
        input
            .as_object_mut()
            .expect("just built as an object")
            .insert("subscription_id".into(), json!(id));
    }
    let data = ops::invoke_now(&state, &current.auth, "cron.list", input).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRequest {
    /// Five whitespace-separated fields: minute hour day-of-month month
    /// day-of-week. Numbers, `a-b` ranges, `*/n` or `a-b/n` steps and
    /// comma-separated lists. `@reboot` and the other `@` aliases are refused.
    #[schema(example = "*/15 * * * *")]
    pub schedule: String,
    /// The command line cron hands to the tenant's shell, as the tenant. At
    /// most 1024 characters, and no control characters at all.
    #[schema(example = "/usr/bin/php /home/ft_ab12cd34/cron.php")]
    pub command: String,
    /// Which subscription owns it. Defaults to the caller's own.
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// A disabled job keeps its row and renders into the crontab as a comment.
    /// Absent means enabled.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Create a cron job and re-install the subscription's crontab.
#[utoipa::path(
    post,
    path = "/api/cron",
    tag = "cron",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = CreateRequest,
    responses(
        (status = 200, description = "The created job, how many jobs the installed crontab schedules, and the Linux account it was installed for", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: the `schedule` or `command` field is named in the error", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid` / `plan_feature_disabled`: the target plan has no `can_cron` / `account_suspended`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such subscription in this tenant's scope", body = ApiErrorBody),
        (status = 409, description = "`conflict`: the account already has a crontab Ferrum did not write, or is at its job limit", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<CreateRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::CronManage)
        .map_err(ApiError::from)?;

    let input = set_input(None, &body);
    audit(&state, &current, &headers, &peer, "cron.set", "new", &input).await?;
    let data = ops::invoke_now(&state, &current.auth, "cron.set", input).await?;
    Ok(Json(data))
}

/// Replace a cron job's schedule, command and enabled flag.
///
/// The id comes from the path. A job cannot be moved between subscriptions, so
/// there is no `subscription_id` to send here: the job's own subscription is
/// whichever one it already belongs to.
#[utoipa::path(
    put,
    path = "/api/cron/{id}",
    tag = "cron",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Cron job id")),
    request_body = CreateRequest,
    responses(
        (status = 200, description = "The updated job and the re-installed crontab's job count", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: the `schedule` or `command` field is named in the error", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid` / `plan_feature_disabled` / `account_suspended`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such job in this tenant's scope", body = ApiErrorBody),
        (status = 409, description = "`conflict`: the account has a crontab Ferrum did not write", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn update(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<CreateRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::CronManage)
        .map_err(ApiError::from)?;

    let input = set_input(Some(id), &body);
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "cron.set",
        &id.to_string(),
        &input,
    )
    .await?;
    let data = ops::invoke_now(&state, &current.auth, "cron.set", input).await?;
    Ok(Json(data))
}

/// Delete a cron job and re-install the subscription's crontab without it.
#[utoipa::path(
    delete,
    path = "/api/cron/{id}",
    tag = "cron",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Cron job id")),
    responses(
        (status = 200, description = "The removed job's id and how many jobs remain scheduled", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such job in this tenant's scope", body = ApiErrorBody),
        (status = 409, description = "`conflict`: the account has a crontab Ferrum did not write", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn delete(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::CronManage)
        .map_err(ApiError::from)?;

    let input = json!({ "id": id });
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "cron.delete",
        &id.to_string(),
        &input,
    )
    .await?;
    let data = ops::invoke_now(&state, &current.auth, "cron.delete", input).await?;
    Ok(Json(data))
}

/// Build the `cron.set` input.
///
/// Split out from the handlers so the two rules this file owns are testable
/// without an agent: the id comes from the path (never from the body), and an
/// unsent `enabled` is *absent* rather than `null` — `SetInput::enabled` is a
/// plain `bool` behind `#[serde(default)]`, so a `null` would be a
/// deserialization error in the agent where an absent key means "enabled".
///
/// The schedule and the command are deliberately **not** parsed here. Unlike
/// `Domain` or `TenantPath` they are not newtypes with an edge parser, and a
/// second copy of the cron grammar in the web process is a second copy that
/// can disagree with the one that matters. The agent's refusal already names
/// the field, which is what the form needs.
fn set_input(id: Option<i64>, body: &CreateRequest) -> serde_json::Value {
    let mut input = json!({
        "schedule": body.schedule,
        "command": body.command,
    });
    let object = input.as_object_mut().expect("just built as an object");
    if let Some(id) = id {
        object.insert("id".into(), json!(id));
    } else if let Some(subscription_id) = body.subscription_id {
        // Only on create: an update takes the job's existing subscription, and
        // sending one here is how a client asks to move a job — which the agent
        // refuses. Dropping it silently on the update path keeps a client that
        // round-trips a job object from tripping over that.
        object.insert("subscription_id".into(), json!(subscription_id));
    }
    if let Some(enabled) = body.enabled {
        object.insert("enabled".into(), json!(enabled));
    }
    input
}

async fn audit(
    state: &SharedState,
    current: &CurrentUser,
    headers: &HeaderMap,
    peer: &SocketAddr,
    action: &str,
    target: &str,
    detail: &serde_json::Value,
) -> ApiResult<()> {
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(peer), headers)),
            action: action.to_string(),
            target: Some(target.to_string()),
            detail: detail.clone(),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(value: serde_json::Value) -> CreateRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    /// The rule this module owns: on an update the id is the path's, so a body
    /// that carries a different one cannot reach the operation.
    #[test]
    fn the_id_comes_from_the_path_and_a_body_cannot_override_it() {
        let body = request(json!({
            "schedule": "0 3 * * *",
            "command": "backup.sh",
            "subscription_id": 99,
        }));

        let update = set_input(Some(7), &body);
        assert_eq!(update["id"], json!(7));
        assert!(
            !update.as_object().unwrap().contains_key("subscription_id"),
            "an update must not try to move the job: {update}"
        );

        let create = set_input(None, &body);
        assert!(!create.as_object().unwrap().contains_key("id"), "{create}");
        assert_eq!(create["subscription_id"], json!(99));
    }

    /// `SetInput::enabled` is a bare `bool` behind `#[serde(default)]`, so an
    /// explicit `null` is a deserialization error in the agent where an absent
    /// key is simply "enabled".
    #[test]
    fn an_unset_enabled_flag_sends_no_key_at_all() {
        let body = request(json!({ "schedule": "0 3 * * *", "command": "backup.sh" }));
        let input = set_input(None, &body);
        let object = input.as_object().expect("object");
        assert!(!object.contains_key("enabled"), "{input}");
        assert!(!object.contains_key("subscription_id"), "{input}");

        let disabled = request(json!({
            "schedule": "0 3 * * *",
            "command": "backup.sh",
            "enabled": false,
        }));
        assert_eq!(set_input(None, &disabled)["enabled"], json!(false));
    }

    /// The schedule and the command reach the agent byte for byte, including
    /// the hostile shapes: this file must not "helpfully" strip a newline and
    /// turn an attack into a valid-looking job. The agent is where they are
    /// refused, and it refuses them by naming the field.
    #[test]
    fn a_hostile_command_is_passed_through_untouched_for_the_agent_to_refuse() {
        let payload = "backup.sh\n* * * * * /tmp/backdoor";
        let body = request(json!({ "schedule": "@reboot", "command": payload }));
        let input = set_input(None, &body);
        assert_eq!(input["command"], json!(payload));
        assert_eq!(input["schedule"], json!("@reboot"));
    }
}
