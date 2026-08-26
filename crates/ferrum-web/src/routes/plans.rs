//! The plans and suspension API (spec §6.2, §6.4).
//!
//! Thin by design, like every route module: permission check, audit row, then
//! the operation — the agent re-validates everything anyway (spec §12 rule 4),
//! so the interesting logic lives in `ferrum_ops::plan`, not here.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
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
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// The plans this caller may see: all of them for an admin, own plus
/// admin-global for a reseller.
#[utoipa::path(
    get,
    path = "/api/plans",
    tag = "plans",
    security(("session_cookie" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Plan rows with their subscription counts", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `plan_manage`", body = ApiErrorBody),
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
        .require(Permission::PlanManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "plan.list",
        json!({ "limit": q.limit, "offset": q.offset }),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRequest {
    pub name: String,
    pub max_sites: u32,
    pub max_dbs: u32,
    pub storage_mb: u32,
    #[serde(default)]
    pub can_ssh: bool,
    #[serde(default = "default_true")]
    pub can_cron: bool,
    #[serde(default)]
    pub can_node_apps: bool,
}

fn default_true() -> bool {
    true
}

/// Create a plan. An admin's plan is global; a reseller's belongs to them —
/// ownership comes from who is asking, never from the request body.
#[utoipa::path(
    post,
    path = "/api/plans",
    tag = "plans",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = CreateRequest,
    responses(
        (status = 200, description = "The created plan", body = serde_json::Value),
        (status = 400, description = "`invalid_input`", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 409, description = "`already_exists`: a plan of that name", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<CreateRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::PlanManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "plan.create",
        &body.name,
        json!({ "max_sites": body.max_sites, "max_dbs": body.max_dbs }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "plan.create",
        json!({
            "name": body.name,
            "max_sites": body.max_sites,
            "max_dbs": body.max_dbs,
            "storage_mb": body.storage_mb,
            "can_ssh": body.can_ssh,
            "can_cron": body.can_cron,
            "can_node_apps": body.can_node_apps,
        }),
    )
    .await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub max_sites: Option<u32>,
    #[serde(default)]
    pub max_dbs: Option<u32>,
    #[serde(default)]
    pub storage_mb: Option<u32>,
    #[serde(default)]
    pub can_ssh: Option<bool>,
    #[serde(default)]
    pub can_cron: Option<bool>,
    #[serde(default)]
    pub can_node_apps: Option<bool>,
}

/// Change a plan's limits or flags. Absent fields are left alone. Resellers
/// may edit only their own plans; global ones answer `permission_denied`.
#[utoipa::path(
    patch,
    path = "/api/plans/{id}",
    tag = "plans",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Plan id")),
    request_body = UpdateRequest,
    responses(
        (status = 200, description = "The updated plan", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such plan in this scope", body = ApiErrorBody),
        (status = 409, description = "`already_exists`: the new name is taken", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn update(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<UpdateRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::PlanManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "plan.update",
        &id.to_string(),
        json!({}),
    )
    .await?;

    let mut input = json!({ "plan_id": id });
    let object = input.as_object_mut().expect("just built as an object");
    macro_rules! put {
        ($field:ident) => {
            if let Some(v) = body.$field {
                object.insert(stringify!($field).into(), json!(v));
            }
        };
    }
    put!(name);
    put!(max_sites);
    put!(max_dbs);
    put!(storage_mb);
    put!(can_ssh);
    put!(can_cron);
    put!(can_node_apps);

    ops::invoke(&state, &current.auth, "plan.update", input).await
}

/// Delete a plan. Refused with `dependents_exist` while any subscription is
/// still on it.
#[utoipa::path(
    delete,
    path = "/api/plans/{id}",
    tag = "plans",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Plan id")),
    responses(
        (status = 200, description = "Deleted", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such plan in this scope", body = ApiErrorBody),
        (status = 409, description = "`dependents_exist`: subscriptions still use it", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn delete(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::PlanManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "plan.delete",
        &id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(&state, &current.auth, "plan.delete", json!({ "plan_id": id })).await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignRequest {
    pub subscription_id: i64,
}

/// Put a subscription on a plan. Both must be visible in the caller's scope.
#[utoipa::path(
    post,
    path = "/api/plans/{id}/assign",
    tag = "plans",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Plan id")),
    request_body = AssignRequest,
    responses(
        (status = 200, description = "Assigned; `over_limit` flags an over-quota downgrade", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: plan or subscription outside this scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn assign(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<AssignRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::PlanManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "plan.assign",
        &id.to_string(),
        json!({ "subscription_id": body.subscription_id }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "plan.assign",
        json!({ "plan_id": id, "subscription_id": body.subscription_id }),
    )
    .await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SuspendRequest {
    /// Shown to the tenant in the panel; required, because "suspended for no
    /// recorded reason" helps nobody.
    pub reason: String,
}

/// Suspend a subscription: block anything new, switch its sites to the
/// maintenance page. Reversible with unsuspend (spec §6.4).
#[utoipa::path(
    post,
    path = "/api/subscriptions/{id}/suspend",
    tag = "subscriptions",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Subscription id")),
    request_body = SuspendRequest,
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 400, description = "`invalid_input`: a usable reason is required", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such subscription in this scope", body = ApiErrorBody),
        (status = 409, description = "`conflict`: scheduled for deletion", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn suspend(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<SuspendRequest>,
) -> ApiResult<Response> {
    // UserManage, not PlanManage: suspension governs an account's service, not
    // the plan catalogue (and a customer holds neither, so they cannot
    // unsuspend themselves).
    current
        .auth
        .require(Permission::UserManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "subscription.suspend",
        &id.to_string(),
        json!({ "reason": body.reason }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "subscription.suspend",
        json!({ "subscription_id": id, "reason": body.reason }),
    )
    .await
}

/// Reinstate a suspended subscription; its sites render from their own stored
/// settings again.
#[utoipa::path(
    post,
    path = "/api/subscriptions/{id}/unsuspend",
    tag = "subscriptions",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Subscription id")),
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such subscription in this scope", body = ApiErrorBody),
        (status = 409, description = "`conflict`: scheduled for deletion", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn unsuspend(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::UserManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "subscription.unsuspend",
        &id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "subscription.unsuspend",
        json!({ "subscription_id": id }),
    )
    .await
}

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
