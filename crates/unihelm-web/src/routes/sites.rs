//! The sites API (spec §11.2).

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use unihelm_core::{Permission, PhpVersion};
use unihelm_db::audit::NewAuditEntry;
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
    // but rejecting it here means the user gets `UNI-1201` with the field
    // highlighted instead of a task that fails a second later.
    let domain = unihelm_core::Domain::parse(&body.domain)
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
    #[schema(value_type = Option<String>, example = "redirect_to_www")]
    pub www_policy: Option<String>,
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
    if let Some(v) = body.www_policy {
        object.insert("www_policy".into(), json!(v));
    }
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct AliasRequest {
    /// The extra name this site should answer to, e.g. `www.example.com`.
    pub domain: String,
}

/// Attach another domain to an existing site.
///
/// There is no `redirect` field although the column exists: nothing renders it
/// into a vhost, and the panel does not accept settings it cannot honour — see
/// `site.alias.add` and the `www_policy` refusal next to it.
#[utoipa::path(
    post,
    path = "/api/sites/{id}/aliases",
    tag = "sites",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Site id")),
    request_body = AliasRequest,
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 400, description = "`invalid_domain`", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope", body = ApiErrorBody),
        (status = 409, description = "`domain_already_exists`, or the site is not ready for one", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn alias_add(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<AliasRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::SiteManage)
        .map_err(ApiError::from)?;

    // Parsed here for the same reason `create` parses: the agent checks it
    // again because it does not trust us, but a bad name gets `UNI-1201` with
    // the field highlighted instead of a task that fails a second later.
    let domain = unihelm_core::Domain::parse(&body.domain)
        .map_err(|e| ApiError::new(e.with_field("domain")))?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "site.alias.add",
        &id.to_string(),
        json!({ "domain": domain.as_str() }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "site.alias.add",
        alias_input(id, &domain),
    )
    .await
}

/// Detach a domain from a site.
///
/// The alias travels in the path rather than a body: a `DELETE` with a body is
/// awkward for every client, and the name is the identity of the thing being
/// removed. It is parsed as a domain before it goes anywhere, so a path segment
/// that is not one is a 400 rather than a task.
#[utoipa::path(
    delete,
    path = "/api/sites/{id}/aliases/{alias}",
    tag = "sites",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(
        ("id" = i64, Path, description = "Site id"),
        ("alias" = String, Path, description = "The alias to detach"),
    ),
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 400, description = "`invalid_domain`", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site, or the name is not one of its aliases", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn alias_remove(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((id, alias)): Path<(i64, String)>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::SiteManage)
        .map_err(ApiError::from)?;

    let domain =
        unihelm_core::Domain::parse(&alias).map_err(|e| ApiError::new(e.with_field("domain")))?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "site.alias.remove",
        &id.to_string(),
        json!({ "domain": domain.as_str() }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "site.alias.remove",
        alias_input(id, &domain),
    )
    .await
}

/// The operation input both alias routes send.
///
/// The id is the path's and the domain is the normalised parse, never the raw
/// string the client sent: `Shop.Example.COM.` and `shop.example.com` name one
/// alias, and sending both spellings to the agent would make the remove miss
/// the row the add wrote.
fn alias_input(id: i64, domain: &unihelm_core::Domain) -> serde_json::Value {
    json!({ "site_id": id, "domain": domain.as_str() })
}

/// Run a site's provisioning again, for one that never finished.
#[utoipa::path(
    post,
    path = "/api/sites/{id}/reprovision",
    tag = "sites",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Site id")),
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope", body = ApiErrorBody),
        (status = 409, description = "`conflict`: a provisioning task is already running", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn reprovision(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
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
        "site.reprovision",
        &id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "site.reprovision",
        json!({ "site_id": id }),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule this module owns for the alias routes: the site id is the
    /// path's, and the name that travels is the *normalised* domain.
    ///
    /// `site_aliases.domain` stores what the agent was given, and the removal
    /// matches on it exactly. Forwarding the raw string would let
    /// `Shop.Example.COM.` be attached as one spelling and then be unfindable
    /// under the one the panel shows — a remove button that reports success and
    /// detaches nothing, or a 404 on a name the page is displaying.
    #[test]
    fn an_alias_reaches_the_agent_normalised_and_under_the_paths_site_id() {
        let domain = unihelm_core::Domain::parse("  Shop.Example.COM. ").expect("a real domain");
        let input = alias_input(7, &domain);

        assert_eq!(input["site_id"], json!(7));
        assert_eq!(input["domain"], json!("shop.example.com"));
        assert_eq!(
            input.as_object().map(|o| o.len()),
            Some(2),
            "nothing else belongs in an alias request: {input}"
        );
    }

    /// The body carries the name and nothing else. `redirect` is deliberately
    /// absent: no template renders it, and a stored setting nothing honours is
    /// the defect `site.update` refuses `www_policy` for.
    #[test]
    fn an_alias_request_carries_only_the_domain() {
        let body: AliasRequest =
            serde_json::from_value(json!({ "domain": "www.example.com", "redirect": true }))
                .expect("the request shape parses");
        assert_eq!(body.domain, "www.example.com");

        let domain = unihelm_core::Domain::parse(&body.domain).expect("a real domain");
        let input = alias_input(1, &domain);
        assert!(
            !input.as_object().expect("object").contains_key("redirect"),
            "a flag the vhost cannot render must not reach the agent: {input}"
        );
    }

    /// The names a client can put in a path segment that are not domains. Each
    /// has to be a 400 with the field named, not a task that fails later — and
    /// `..` and an absolute path are the two that would otherwise reach the
    /// agent as a `domain`.
    #[test]
    fn a_path_segment_that_is_not_a_domain_never_becomes_an_alias() {
        for bad in [
            "",
            "..",
            "/etc/nginx",
            "localhost",
            "192.0.2.1",
            "a b.example",
        ] {
            assert!(
                unihelm_core::Domain::parse(bad).is_err(),
                "accepted `{bad}` as an alias"
            );
        }
    }
}
