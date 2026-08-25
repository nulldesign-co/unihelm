//! The sites API (spec §11.2).

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use ferrum_core::{Permission, PhpVersion};
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

/// List the sites this caller's tenant scope can see.
#[utoipa::path(
    get,
    path = "/api/sites",
    tag = "sites",
    security(("session_cookie" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Site rows, tenant-scoped by the agent", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `site.read`", body = ApiErrorBody),
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
        .require(Permission::SiteRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "site.list",
        json!({ "limit": q.limit, "offset": q.offset }),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRequest {
    pub domain: String,
    /// `php`, `static`, …
    #[serde(default = "default_type")]
    pub site_type: String,
    #[serde(default)]
    #[schema(value_type = Option<String>, example = "8.3")]
    pub php_version: Option<PhpVersion>,
    #[serde(default)]
    pub with_www: bool,
    #[serde(default)]
    pub subscription_id: Option<i64>,
    #[serde(default)]
    pub proxy_port: Option<u16>,
    #[serde(default)]
    pub redirect_target: Option<String>,
}

fn default_type() -> String {
    "php".into()
}

/// Create a site.
#[utoipa::path(
    post,
    path = "/api/sites",
    tag = "sites",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = CreateRequest,
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 400, description = "`invalid_domain`", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 409, description = "`domain_already_exists`", body = ApiErrorBody),
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
        .require(Permission::SiteManage)
        .map_err(ApiError::from)?;

    // The agent validates this too — it has to, because it does not trust us —
    // but rejecting it here means the user gets `FER-1201` with the field
    // highlighted instead of a task that fails a second later.
    let domain = ferrum_core::Domain::parse(&body.domain)
        .map_err(|e| ApiError::new(e.with_field("domain")))?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "site.create",
        domain.as_str(),
        json!({
            "site_type": body.site_type,
            "php_version": body.php_version.map(|v| v.as_str()),
        }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "site.create",
        json!({
            "domain": domain.as_str(),
            "site_type": body.site_type,
            "php_version": body.php_version.map(|v| v.as_str()),
            "with_www": body.with_www,
            "subscription_id": body.subscription_id,
            "proxy_port": body.proxy_port,
            "redirect_target": body.redirect_target,
        }),
    )
    .await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRequest {
    #[serde(default)]
    #[schema(value_type = Option<String>, example = "8.3")]
    pub php_version: Option<PhpVersion>,
    #[serde(default)]
    pub force_https: Option<bool>,
    #[serde(default)]
    pub http3: Option<bool>,
    #[serde(default)]
    pub maintenance_mode: Option<bool>,
    #[serde(default)]
    pub client_max_body_size: Option<String>,
    /// `Some(None)` clears the snippet; absent leaves it alone.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub custom_nginx_snippet: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub php_ini_overrides: Option<Option<String>>,
    #[serde(default)]
    pub rate_limit_enabled: Option<bool>,
}

/// Distinguish "field absent" from "field set to null".
///
/// Without this, clearing a custom snippet and leaving it alone look identical
/// on the wire.
fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

/// Change a site's settings. Absent fields are left alone.
#[utoipa::path(
    patch,
    path = "/api/sites/{id}",
    tag = "sites",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Site id")),
    request_body = UpdateRequest,
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope", body = ApiErrorBody),
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
        .require(Permission::SiteManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "site.update",
        &id.to_string(),
        json!({}),
    )
    .await?;

    let mut input = json!({ "site_id": id });
    let object = input.as_object_mut().expect("just built as an object");
    macro_rules! put {
        ($field:ident) => {
            if let Some(v) = body.$field {
                object.insert(stringify!($field).into(), json!(v));
            }
        };
    }
    put!(force_https);
    put!(http3);
    put!(maintenance_mode);
    put!(rate_limit_enabled);
    if let Some(v) = body.php_version {
        object.insert("php_version".into(), json!(v.as_str()));
    }
    if let Some(v) = body.client_max_body_size {
        object.insert("client_max_body_size".into(), json!(v));
    }
    if let Some(v) = body.custom_nginx_snippet {
        object.insert("custom_nginx_snippet".into(), json!(v));
    }
    if let Some(v) = body.php_ini_overrides {
        object.insert("php_ini_overrides".into(), json!(v));
    }

    ops::invoke(&state, &current.auth, "site.update", input).await
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DeleteQuery {
    /// Also remove the site's files. Off unless asked for explicitly.
    #[serde(default)]
    pub purge_files: bool,
}

/// Delete a site, optionally purging its files.
#[utoipa::path(
    delete,
    path = "/api/sites/{id}",
    tag = "sites",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Site id"), DeleteQuery),
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn delete(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(q): Query<DeleteQuery>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::SiteManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "site.delete",
        &id.to_string(),
        json!({ "purge_files": q.purge_files }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "site.delete",
        json!({ "site_id": id, "purge_files": q.purge_files }),
    )
    .await
}

/// Has somebody edited this site's generated vhost?
#[utoipa::path(
    get,
    path = "/api/sites/{id}/drift",
    tag = "sites",
    security(("session_cookie" = [])),
    params(("id" = i64, Path, description = "Site id")),
    responses(
        (status = 200, description = "Drift verdict for the site's rendered config", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `site.read`", body = ApiErrorBody),
        (status = 404, description = "`not_found`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn drift(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::SiteRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "site.drift",
        json!({ "site_id": id }),
    )
    .await?;
    Ok(Json(data))
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
