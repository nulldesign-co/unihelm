//! The backups API (spec §11.10).
//!
//! Thin over `unihelm_ops::backup`, like every route module — the agent
//! re-derives the permission and re-validates every field (spec §5.2 rule 4),
//! so nothing here is the last line of defence. Three things are nevertheless
//! decided in this file:
//!
//! 1. **Repository creation answers 200, not 202.** `backup.repo.init` is an
//!    *immediate* operation because its response carries the show-once
//!    repository password, and a task discards its output while persisting its
//!    input — which for this operation is the S3 secret access key. The
//!    architecture note is in `unihelm_ops::backup::RepoInit`; the consequence
//!    here is that a client must read the body of the 200 and never poll a
//!    task for it.
//!
//! 2. **The audit rows record labels and ids, never secrets.** Creating a
//!    repository is audited by its label, kind and location — not its
//!    credentials, and not the generated password (spec §12 rule 6). The audit
//!    log is browsable by anybody holding `audit_read`, so a secret that
//!    reaches it is a secret published to every operator.
//!
//! 3. **The two list endpoints read the database directly**, as `tasks.rs`
//!    does, because `Db::backups(scope)` is already tenant-scoped: a customer
//!    sees their own subscription's runs and schedules and a panel-scope row —
//!    whose `subscription_id` is NULL — is invisible to them. The repository
//!    list is the exception and is administrator-only, since deciding where
//!    backups go is an administrator's job; `BackupRepo` deliberately has no
//!    field for either sealed column, so even that list carries no credential.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use unihelm_core::{ErrorCode, Permission, TenantScope};
use unihelm_db::audit::NewAuditEntry;
use utoipa::{IntoParams, ToSchema};

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// Refuse anything narrower than the whole server.
///
/// The mirror of `unihelm_ops::backup::require_global`, applied here as well so
/// a reseller or a customer holding `backup_manage` gets a 403 straight away
/// rather than a round trip to the agent for an answer that was already
/// decided. The agent's copy is the one that is trusted.
fn require_admin(current: &CurrentUser, what: &str) -> ApiResult<()> {
    if matches!(current.auth.tenant_scope, TenantScope::Global) {
        return Ok(());
    }
    Err(ApiError::code(
        ErrorCode::PermissionDenied,
        format!("{what} is an administrator operation"),
    ))
}

// ---------------------------------------------------------------------------
// repositories
// ---------------------------------------------------------------------------

/// The backup repositories this panel knows about.
///
/// Administrator-only. Rows carry the location and whether credentials are
/// stored — never the credentials themselves, and never the repository
/// password: `unihelm_db::BackupRepo` has no field for either.
#[utoipa::path(
    get,
    path = "/api/backups/repos",
    tag = "backups",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Repository rows, without any sealed value", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `backup_manage` and administrator scope", body = ApiErrorBody),
    ),
)]
pub async fn repos_list(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::BackupManage)
        .map_err(ApiError::from)?;
    require_admin(&current, "listing backup repositories")?;

    let repos = state.db.backup_repos().await.map_err(ApiError::from)?;
    Ok(Json(json!({ "repos": repos })))
}

/// S3 credentials, as the request spells them.
#[derive(Debug, Deserialize, ToSchema)]
pub struct S3CredentialsRequest {
    #[schema(example = "AKIAEXAMPLE")]
    pub access_key_id: String,
    /// Sealed under the master key before it is stored, and never returned.
    pub secret_access_key: String,
    #[serde(default)]
    #[schema(example = "us-east-1")]
    pub region: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RepoInitRequest {
    /// `local` or `s3`.
    #[schema(example = "s3")]
    pub kind: String,
    /// What the operator calls it; unique across the panel.
    #[schema(example = "nightly-offsite")]
    pub label: String,
    /// An absolute path for `local`; `endpoint/bucket[/prefix]` for `s3`.
    #[schema(example = "s3.example.com/unihelm-backups")]
    pub path_or_url: String,
    /// Required for `s3`, refused for `local`.
    #[serde(default)]
    pub s3: Option<S3CredentialsRequest>,
}

/// Create a repository: `restic init`, a generated password, sealed storage.
///
/// **The response body carries the repository password, once.** It cannot be
/// asked for again — an operation that could reveal it later would turn a
/// stolen session into every backup this panel has ever taken. Store it off
/// this server together with `/etc/unihelm/secret.key`; without both, a
/// panel-scope backup cannot be restored after the panel is lost. See
/// `docs/operations.md` under `backup.repo.init`.
#[utoipa::path(
    post,
    path = "/api/backups/repos",
    tag = "backups",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = RepoInitRequest,
    responses(
        (status = 200, description = "Created. The body contains the show-once repository password", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: bad location, label or credentials", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 409, description = "`already_exists`: that label is taken", body = ApiErrorBody),
        (status = 500, description = "`command_failed`: restic could not initialise the repository", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn repos_create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<RepoInitRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::BackupManage)
        .map_err(ApiError::from)?;
    require_admin(&current, "creating a backup repository")?;

    let mut input = json!({
        "kind": body.kind,
        "label": body.label,
        "path_or_url": body.path_or_url,
    });
    if let Some(s3) = &body.s3 {
        input["s3"] = json!({
            "access_key_id": s3.access_key_id,
            "secret_access_key": s3.secret_access_key,
            "region": s3.region,
        });
    }

    // What was created, never what it was created with: the secret access key
    // is in the request body a line above, and an audit row is read by every
    // operator holding `audit_read` (spec §12 rule 6).
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "backup.repo.init",
        &body.label,
        json!({
            "kind": body.kind,
            "path_or_url": body.path_or_url,
            "has_credentials": body.s3.is_some(),
        }),
    )
    .await?;

    ops::invoke(&state, &current.auth, "backup.repo.init", input).await
}

/// Forget a repository. Nothing inside it is deleted.
///
/// Refused while any run references it: that history is the panel's only record
/// of which snapshots exist.
#[utoipa::path(
    delete,
    path = "/api/backups/repos/{id}",
    tag = "backups",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Repository id")),
    responses(
        (status = 200, description = "Forgotten. The snapshots are untouched", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such repository", body = ApiErrorBody),
        (status = 409, description = "`already_exists`: runs are recorded against it", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn repos_delete(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(repo_id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::BackupManage)
        .map_err(ApiError::from)?;
    require_admin(&current, "deleting a backup repository")?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "backup.repo.delete",
        &repo_id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "backup.repo.delete",
        json!({ "repo_id": repo_id }),
    )
    .await
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SnapshotsQuery {
    /// Narrow to one subscription's snapshots. A scoped caller must supply it
    /// and is narrowed to their own regardless.
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

/// The snapshots in a repository, from `restic snapshots --json`.
#[utoipa::path(
    get,
    path = "/api/backups/repos/{id}/snapshots",
    tag = "backups",
    security(("session_cookie" = [])),
    params(("id" = i64, Path, description = "Repository id"), SnapshotsQuery),
    responses(
        (status = 200, description = "Snapshot ids, times, paths and tags", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: a scoped caller named no subscription", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `backup_manage`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such repository, or not this tenant's", body = ApiErrorBody),
        (status = 500, description = "`command_failed`: restic could not read the repository", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn snapshots(
    State(state): State<SharedState>,
    Path(repo_id): Path<i64>,
    current: CurrentUser,
    Query(q): Query<SnapshotsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::BackupManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "backup.list",
        json!({ "repo_id": repo_id, "subscription_id": q.subscription_id }),
    )
    .await?;
    Ok(Json(data))
}

// ---------------------------------------------------------------------------
// schedules
// ---------------------------------------------------------------------------

/// The backup schedules this caller can see.
///
/// Tenant-scoped by `Db::backups(scope)`: a customer sees the schedules for
/// their own subscriptions, and a panel-scope schedule — which covers every
/// tenant's data — only ever appears to an administrator.
#[utoipa::path(
    get,
    path = "/api/backups/schedules",
    tag = "backups",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Schedule rows in this caller's tenant scope", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `backup_manage`", body = ApiErrorBody),
    ),
)]
pub async fn schedules_list(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::BackupManage)
        .map_err(ApiError::from)?;
    let schedules = state
        .db
        .backups(&current.auth.tenant_scope)
        .schedules()
        .await
        .map_err(ApiError::from)?;
    Ok(Json(json!({ "schedules": schedules })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ScheduleRequest {
    pub repo_id: i64,
    /// `panel` or `subscription`.
    #[schema(example = "subscription")]
    pub scope: String,
    /// Required for `subscription` scope, refused for `panel`.
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// Five fields: `minute hour day-of-month month day-of-week`.
    #[schema(example = "0 3 * * *")]
    pub cron: String,
    #[serde(default)]
    pub keep_daily: Option<i64>,
    #[serde(default)]
    pub keep_weekly: Option<i64>,
    #[serde(default)]
    pub keep_monthly: Option<i64>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Create a schedule: when a scope is backed up, and how much history is kept.
///
/// Administrator-only, and that is what grants a tenant access to a repository
/// at all — `backup.run` lets a scoped caller write only into a repository some
/// administrator already pointed a schedule for their subscription at.
#[utoipa::path(
    post,
    path = "/api/backups/schedules",
    tag = "backups",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = ScheduleRequest,
    responses(
        (status = 200, description = "The created schedule", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: unreadable cron expression, or a scope and subject that disagree", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such repository or subscription", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn schedules_create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<ScheduleRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::BackupManage)
        .map_err(ApiError::from)?;
    require_admin(&current, "setting a backup schedule")?;

    let input = schedule_input(&body);

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "backup.schedule.set",
        &body.repo_id.to_string(),
        input.clone(),
    )
    .await?;

    ops::invoke(&state, &current.auth, "backup.schedule.set", input).await
}

/// Build the `backup.schedule.set` input, omitting the keys the caller left
/// out.
///
/// Absent, not `null`: the retention fields are `#[serde(default = "…")]`
/// non-optional integers in the agent, so an explicit `null` fails
/// deserialization there where an absent key takes the documented default.
/// Split out from the handler so that rule is testable without an agent.
fn schedule_input(body: &ScheduleRequest) -> serde_json::Value {
    let mut input = json!({
        "repo_id": body.repo_id,
        "scope": body.scope,
        "cron": body.cron,
    });
    let object = input.as_object_mut().expect("just built as an object");
    if let Some(id) = body.subscription_id {
        object.insert("subscription_id".into(), json!(id));
    }
    for (key, value) in [
        ("keep_daily", body.keep_daily),
        ("keep_weekly", body.keep_weekly),
        ("keep_monthly", body.keep_monthly),
    ] {
        if let Some(n) = value {
            object.insert(key.into(), json!(n));
        }
    }
    if let Some(enabled) = body.enabled {
        object.insert("enabled".into(), json!(enabled));
    }
    input
}

/// Delete a schedule. The runs it already made keep their history.
#[utoipa::path(
    delete,
    path = "/api/backups/schedules/{id}",
    tag = "backups",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Schedule id")),
    responses(
        (status = 200, description = "Deleted; past runs keep their rows", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such schedule", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn schedules_delete(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(schedule_id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::BackupManage)
        .map_err(ApiError::from)?;
    require_admin(&current, "deleting a backup schedule")?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "backup.schedule.delete",
        &schedule_id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "backup.schedule.delete",
        json!({ "schedule_id": schedule_id }),
    )
    .await
}

// ---------------------------------------------------------------------------
// runs and restores
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RunsQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Backup history, newest first, in this caller's tenant scope.
///
/// Failures are rows here too. A history that recorded only successes could not
/// answer "when did this stop working", which is the question a backup history
/// exists to answer (spec §11.10).
#[utoipa::path(
    get,
    path = "/api/backups/runs",
    tag = "backups",
    security(("session_cookie" = [])),
    params(RunsQuery),
    responses(
        (status = 200, description = "Run rows: status, snapshot id, bytes and the failure text", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `backup_manage`", body = ApiErrorBody),
    ),
)]
pub async fn runs_list(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<RunsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::BackupManage)
        .map_err(ApiError::from)?;
    // The repository clamps the limit to 1..=500 and floors the offset at zero,
    // so a hostile page size is bounded there rather than here.
    let runs = state
        .db
        .backups(&current.auth.tenant_scope)
        .runs(q.limit.unwrap_or(50), q.offset.unwrap_or(0))
        .await
        .map_err(ApiError::from)?;
    Ok(Json(json!({ "runs": runs })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RunRequest {
    pub repo_id: i64,
    /// `panel` or `subscription`.
    #[schema(example = "subscription")]
    pub scope: String,
    /// Required for `subscription` scope, refused for `panel`.
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

/// Take a backup now.
///
/// A task: a real backup is measured in minutes or hours, and restic's output
/// streams into the task log line by line. Panel scope writes a consistent copy
/// of the panel database (`VACUUM INTO`, never a copy of the live WAL file),
/// `/etc/unihelm` and the state directory; subscription scope writes the tenant
/// home.
#[utoipa::path(
    post,
    path = "/api/backups/runs",
    tag = "backups",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = RunRequest,
    responses(
        (status = 202, description = "Queued; poll the task for restic's output", body = ops::TaskAccepted),
        (status = 400, description = "`invalid_input`: a scope and subject that disagree", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: panel scope is administrator-only", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such repository or subscription in this caller's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn runs_create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<RunRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::BackupManage)
        .map_err(ApiError::from)?;

    let input = json!({
        "repo_id": body.repo_id,
        "scope": body.scope,
        "subscription_id": body.subscription_id,
    });

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "backup.run",
        &body.repo_id.to_string(),
        input.clone(),
    )
    .await?;

    ops::invoke(&state, &current.auth, "backup.run", input).await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RestoreRequest {
    pub repo_id: i64,
    /// A restic snapshot id (8–64 hex characters), or `latest`.
    #[schema(example = "aabbccdd")]
    pub snapshot_id: String,
}

/// Restore a snapshot into a staging directory.
///
/// Administrator-only, and it touches **nothing live**: the files land in a
/// fresh 0700 directory under the state directory and the response says where.
/// Restoring in place is deliberately not implemented — see
/// `docs/operations.md` under `backup.restore`.
#[utoipa::path(
    post,
    path = "/api/backups/restores",
    tag = "backups",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = RestoreRequest,
    responses(
        (status = 202, description = "Queued; the finished task names the staging directory", body = ops::TaskAccepted),
        (status = 400, description = "`invalid_input`: that is not a snapshot id", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such repository", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn restores_create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<RestoreRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::BackupManage)
        .map_err(ApiError::from)?;
    require_admin(&current, "restoring from a backup")?;

    let input = json!({
        "repo_id": body.repo_id,
        "snapshot_id": body.snapshot_id,
    });

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "backup.restore",
        &body.snapshot_id,
        input.clone(),
    )
    .await?;

    ops::invoke(&state, &current.auth, "backup.restore", input).await
}

/// Record who asked for what, before the work starts.
///
/// Before, not after: an audit trail that only records the operations that
/// succeeded is an audit trail with a hole exactly where an investigation
/// looks.
#[allow(clippy::too_many_arguments)]
async fn audit(
    state: &SharedState,
    current: &CurrentUser,
    headers: &HeaderMap,
    peer: &SocketAddr,
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
            ip: Some(client_ip(Some(peer), headers)),
            action: action.to_string(),
            target: Some(target.to_string()),
            detail,
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

    fn request(value: serde_json::Value) -> ScheduleRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    #[test]
    fn a_retention_field_the_caller_omitted_is_absent_rather_than_null() {
        // `keep_daily` and friends are non-optional integers behind
        // `#[serde(default = "…")]` in `unihelm_ops::backup::ScheduleSetInput`.
        // An explicit `null` is a deserialization error there; an absent key is
        // the documented default. Sending `null` would turn "I did not choose"
        // into a 400.
        let input = schedule_input(&request(json!({
            "repo_id": 1,
            "scope": "panel",
            "cron": "0 3 * * *",
        })));
        let object = input.as_object().unwrap();
        for key in [
            "keep_daily",
            "keep_weekly",
            "keep_monthly",
            "enabled",
            "subscription_id",
        ] {
            assert!(
                !object.contains_key(key),
                "`{key}` must be absent, not null"
            );
        }
        assert_eq!(object["cron"], json!("0 3 * * *"));
    }

    #[test]
    fn a_retention_field_the_caller_chose_is_sent_through_untouched() {
        let input = schedule_input(&request(json!({
            "repo_id": 7,
            "scope": "subscription",
            "subscription_id": 3,
            "cron": "30 2 * * 0",
            "keep_daily": 0,
            "enabled": false,
        })));
        assert_eq!(input["subscription_id"], json!(3));
        // Zero is a real policy ("keep no dailies"), so it must survive the
        // Option unwrapping rather than being read as "unset".
        assert_eq!(input["keep_daily"], json!(0));
        assert_eq!(input["enabled"], json!(false));
        assert!(input.as_object().unwrap().get("keep_weekly").is_none());
    }
}
