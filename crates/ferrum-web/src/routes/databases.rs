//! The databases API (spec §11.4).
//!
//! Everything here is a thin bridge to the `db.*` operations; the agent
//! re-validates every input and re-checks every permission (spec §5.2 rule 4).
//! One rule is enforced *here* as well: request bodies never carry passwords —
//! the agent generates them and the JSON response is the only place one ever
//! appears. Audit entries therefore record names and engines, never `detail`
//! fields that could hold credential material.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use ferrum_core::Permission;
use ferrum_db::audit::NewAuditEntry;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

pub async fn list(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::DbManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "db.list",
        json!({ "limit": q.limit, "offset": q.offset }),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub name: String,
    pub engine: String,
    #[serde(default)]
    pub subscription_id: Option<i64>,
    #[serde(default)]
    pub owner: Option<String>,
}

pub async fn create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<CreateRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::DbManage)
        .map_err(ApiError::from)?;

    // The agent validates this too, but rejecting it here gives the user
    // `FER-1202` with the field highlighted instead of a round trip.
    let name = ferrum_core::DbName::parse(&body.name)
        .map_err(|e| ApiError::new(e.with_field("name")))?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "db.create",
        name.as_str(),
        json!({ "engine": body.engine, "owner": body.owner }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "db.create",
        json!({
            "name": name.as_str(),
            "engine": body.engine,
            "subscription_id": body.subscription_id,
            "owner": body.owner,
        }),
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct DropQuery {
    /// The database's name, retyped — the agent refuses without it.
    pub confirm_name: String,
}

pub async fn drop(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<DropQuery>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::DbManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "db.drop",
        &id.to_string(),
        json!({ "confirm_name": q.confirm_name }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "db.drop",
        json!({ "database_id": id, "confirm_name": q.confirm_name }),
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct UserCreateRequest {
    pub username: String,
    pub engine: String,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

/// The response carries the generated password exactly once. It is never in
/// the request, the audit row or a task log — see the ops module docs.
pub async fn user_create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<UserCreateRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::DbManage)
        .map_err(ApiError::from)?;

    let username = ferrum_core::DbName::parse(&body.username)
        .map_err(|e| ApiError::new(e.with_field("username")))?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "db.user.create",
        username.as_str(),
        json!({ "engine": body.engine }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "db.user.create",
        json!({
            "username": username.as_str(),
            "engine": body.engine,
            "subscription_id": body.subscription_id,
        }),
    )
    .await
}

pub async fn user_drop(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(username): Path<String>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::DbManage)
        .map_err(ApiError::from)?;

    let username = ferrum_core::DbName::parse(&username)
        .map_err(|e| ApiError::new(e.with_field("username")))?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "db.user.drop",
        username.as_str(),
        json!({}),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "db.user.drop",
        json!({ "username": username.as_str() }),
    )
    .await
}

/// Reset a database user's password. The new one rides the response, once.
pub async fn user_password(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(username): Path<String>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::DbManage)
        .map_err(ApiError::from)?;

    let username = ferrum_core::DbName::parse(&username)
        .map_err(|e| ApiError::new(e.with_field("username")))?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "db.user.password",
        username.as_str(),
        json!({}),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "db.user.password",
        json!({ "username": username.as_str() }),
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct GrantRequest {
    pub database: String,
    pub username: String,
}

pub async fn grant(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<GrantRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::DbManage)
        .map_err(ApiError::from)?;

    let database = ferrum_core::DbName::parse(&body.database)
        .map_err(|e| ApiError::new(e.with_field("database")))?;
    let username = ferrum_core::DbName::parse(&body.username)
        .map_err(|e| ApiError::new(e.with_field("username")))?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "db.grant",
        database.as_str(),
        json!({ "username": username.as_str() }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "db.grant",
        json!({ "database": database.as_str(), "username": username.as_str() }),
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
