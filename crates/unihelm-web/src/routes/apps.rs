//! The Node applications API (spec §11.10, §13).
//!
//! A thin bridge onto the `app.*` operations in `unihelm_ops::nodeapp`. The
//! agent re-derives the permission from the database and re-validates every
//! field (spec §5.2 rule 4), so nothing here is load-bearing for security on
//! its own. Three things are nevertheless decided in this file, and each is
//! decided here for a reason:
//!
//! 1. **Newtypes are parsed at the edge.** `AppName`, `TenantPath` and `Domain`
//!    are parsed before the operation is called so a typo comes back as
//!    `FER-1201` with `field` set — which the form can highlight — instead of a
//!    202, a task, and a failure a second later in the task drawer.
//!
//! 2. **The audit row records environment variable *names*, never values.** An
//!    app's environment is where a tenant puts `DATABASE_URL` and
//!    `STRIPE_SECRET_KEY`; the audit log is built to be browsed by anyone with
//!    `audit_read` (spec §12 rule 6). Names alone answer the question an audit
//!    row exists to answer — "what changed" — without turning the log into a
//!    credential store.
//!
//! 3. **Absent optional fields are omitted from the operation input, not sent
//!    as `null`.** `CreateInput::node_env` is a `#[serde(default)]` *enum*, not
//!    an `Option`: an explicit `null` fails deserialization in the agent where
//!    an absent key takes the default. Building the JSON key by key is what
//!    keeps "the user did not choose" and "the user chose nothing" the same
//!    request.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
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
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// List the Node applications this caller's tenant scope can see.
#[utoipa::path(
    get,
    path = "/api/apps",
    tag = "apps",
    security(("session_cookie" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "App rows with their systemd unit state and port, tenant-scoped by the agent", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `node_apps`", body = ApiErrorBody),
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
        .require(Permission::NodeApps)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "app.list",
        json!({ "limit": q.limit, "offset": q.offset }),
    )
    .await?;
    Ok(Json(data))
}

/// One environment variable, as the API spells it.
///
/// A list of pairs rather than a map, matching `nodeapp::EnvVar` exactly:
/// systemd's `Environment=` lines are order-sensitive, and a map could not
/// express the duplicate key the agent deliberately refuses.
#[derive(Debug, Deserialize, ToSchema)]
pub struct EnvVarRequest {
    #[schema(example = "DATABASE_URL")]
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRequest {
    /// `[a-z0-9][a-z0-9_-]{0,31}` — also the second half of the unit name.
    #[schema(example = "blog")]
    pub name: String,
    /// Tenant-home-relative path to the JavaScript entry point.
    #[schema(example = "apps/blog/server.js")]
    pub entry: String,
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// `PORT` and `NODE_ENV` are the panel's; the agent refuses either here.
    #[serde(default)]
    pub env: Vec<EnvVarRequest>,
    /// `production` (the default), `development` or `test`.
    #[serde(default)]
    #[schema(example = "production")]
    pub node_env: Option<String>,
    /// Per-app `MemoryMax`, inside the tenant slice's own ceiling.
    #[serde(default)]
    pub memory_mb: Option<u32>,
    /// Publish the app behind this domain as a reverse-proxy site.
    #[serde(default)]
    pub proxy_domain: Option<String>,
}

/// Create a Node application: a port, a directory, a systemd unit, and
/// optionally a reverse-proxy vhost in front of it.
#[utoipa::path(
    post,
    path = "/api/apps",
    tag = "apps",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = CreateRequest,
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 400, description = "`invalid_input` / `invalid_path` / `invalid_domain`", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid` / `plan_feature_disabled`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: Node.js is not installed on this server", body = ApiErrorBody),
        (status = 409, description = "`already_exists`: this subscription already has an app by that name", body = ApiErrorBody),
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
        .require(Permission::NodeApps)
        .map_err(ApiError::from)?;

    let input = create_input(&body)?;

    // Publishing creates a *site*, so it needs the site permission too. The
    // agent enforces this as well (`nodeapp::Create` calls
    // `require(SiteManage)`); doing it here means a caller who may run apps but
    // not manage domains gets a 403 rather than a task id for work that will
    // refuse itself.
    if body.proxy_domain.is_some() {
        current
            .auth
            .require(Permission::SiteManage)
            .map_err(ApiError::from)?;
    }

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "app.create",
        input["name"].as_str().unwrap_or_default(),
        create_audit_detail(&body),
    )
    .await?;

    ops::invoke(&state, &current.auth, "app.create", input).await
}

/// Turn a validated request into the `app.create` input.
///
/// Split out from the handler so the omission rules above are testable without
/// an agent: every optional key is either present with a value or absent
/// entirely, and `node_env` in particular must never be sent as `null`.
fn create_input(body: &CreateRequest) -> ApiResult<serde_json::Value> {
    // Parsed here for the field-highlighted error; the agent parses these same
    // newtypes again on the way in, and its copy is the one that is trusted.
    let name = unihelm_core::AppName::parse(&body.name)
        .map_err(|e| ApiError::new(e.with_field("name")))?;
    let entry = unihelm_core::TenantPath::parse(&body.entry)
        .map_err(|e| ApiError::new(e.with_field("entry")))?;

    let mut input = json!({
        "name": name.as_str(),
        "entry": entry.as_str(),
        "env": body
            .env
            .iter()
            .map(|v| json!({ "key": v.key, "value": v.value }))
            .collect::<Vec<_>>(),
    });
    let object = input.as_object_mut().expect("just built as an object");

    if let Some(id) = body.subscription_id {
        object.insert("subscription_id".into(), json!(id));
    }
    if let Some(mb) = body.memory_mb {
        object.insert("memory_mb".into(), json!(mb));
    }
    // `NodeEnv` is a plain enum behind `#[serde(default)]`, so an explicit
    // `null` would be a deserialization error in the agent where an absent key
    // is simply "production".
    if let Some(node_env) = &body.node_env {
        object.insert("node_env".into(), json!(node_env));
    }
    if let Some(domain) = &body.proxy_domain {
        let domain = unihelm_core::Domain::parse(domain)
            .map_err(|e| ApiError::new(e.with_field("proxy_domain")))?;
        object.insert("proxy_domain".into(), json!(domain.as_str()));
    }

    Ok(input)
}

/// What the audit log records about a create.
///
/// The environment is reduced to its **names**. An app's environment is where
/// database passwords and API tokens live, and an audit row is read by every
/// operator with `audit_read`; recording `env_keys` answers "what was set"
/// without making the audit log a place secrets accumulate (spec §12 rule 6).
fn create_audit_detail(body: &CreateRequest) -> serde_json::Value {
    json!({
        "entry": body.entry,
        "node_env": body.node_env,
        "memory_mb": body.memory_mb,
        "proxy_domain": body.proxy_domain,
        "subscription_id": body.subscription_id,
        "env_keys": body.env.iter().map(|v| v.key.as_str()).collect::<Vec<_>>(),
    })
}

/// Delete an application: stop it, disable it, remove its unit and free its
/// port. Any proxy site in front of it is left standing.
#[utoipa::path(
    delete,
    path = "/api/apps/{id}",
    tag = "apps",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "App id")),
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such app in this tenant's scope", body = ApiErrorBody),
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
        .require(Permission::NodeApps)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "app.delete",
        &id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(&state, &current.auth, "app.delete", json!({ "app_id": id })).await
}

/// Restart an application's systemd unit.
#[utoipa::path(
    post,
    path = "/api/apps/{id}/restart",
    tag = "apps",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "App id")),
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such app, or its unit file is missing", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn restart(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::NodeApps)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "app.restart",
        &id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "app.restart",
        json!({ "app_id": id }),
    )
    .await
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogsQuery {
    /// How many journal lines to tail. The agent clamps to 1..=2000; omitted
    /// means 200.
    #[serde(default)]
    pub lines: Option<u32>,
}

/// Tail an application's journal.
///
/// The unit whose journal is read is derived by the agent from a row the
/// caller's scope could see — this request names an app id, never a unit — so
/// there is no spelling of it that reaches another service's logs.
#[utoipa::path(
    get,
    path = "/api/apps/{id}/logs",
    tag = "apps",
    security(("session_cookie" = [])),
    params(("id" = i64, Path, description = "App id"), LogsQuery),
    responses(
        (status = 200, description = "The unit name and its last `lines` journal lines", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `node_apps`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such app in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn logs(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    Query(q): Query<LogsQuery>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::NodeApps)
        .map_err(ApiError::from)?;

    let mut input = json!({ "app_id": id });
    // `LogsInput::lines` is `Option<u32>`, so a `null` would be harmless — but
    // omitting it keeps every input this module builds to the same rule.
    if let Some(lines) = q.lines {
        input
            .as_object_mut()
            .expect("just built as an object")
            .insert("lines".into(), json!(lines));
    }

    let data = ops::invoke_now(&state, &current.auth, "app.logs", input).await?;
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
    use unihelm_core::ErrorCode;

    fn request(value: serde_json::Value) -> CreateRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    /// The one piece of judgement this module owns rather than delegates.
    ///
    /// A Node app's environment is exactly where `DATABASE_URL` and an API key
    /// go, and the audit log is browsable by anybody holding `audit_read`
    /// (spec §12 rule 6) — so a value must never reach it, even though the
    /// value is perfectly legitimate input to the operation itself.
    #[test]
    fn a_create_audit_row_records_environment_names_and_never_their_values() {
        let body = request(json!({
            "name": "blog",
            "entry": "apps/blog/server.js",
            "env": [
                { "key": "DATABASE_URL", "value": "postgres://app:hunter2@localhost/blog" },
                { "key": "STRIPE_SECRET_KEY", "value": "sk_live_TOPSECRET" },
            ],
        }));

        let rendered =
            serde_json::to_string(&create_audit_detail(&body)).expect("detail serializes");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("sk_live_TOPSECRET"), "{rendered}");
        assert!(!rendered.contains("postgres://"), "{rendered}");
        assert!(rendered.contains("DATABASE_URL"), "{rendered}");
        assert!(rendered.contains("STRIPE_SECRET_KEY"), "{rendered}");
    }

    /// …while the operation input still carries them, because that is the
    /// whole point of declaring an environment. The two assertions belong
    /// together: an audit-only redaction that also blanked the real input
    /// would be a silently broken feature rather than a leak.
    #[test]
    fn the_operation_input_still_carries_the_environment_values() {
        let body = request(json!({
            "name": "blog",
            "entry": "apps/blog/server.js",
            "env": [{ "key": "DATABASE_URL", "value": "postgres://localhost/blog" }],
        }));
        let input = create_input(&body).expect("a valid request builds an input");
        assert_eq!(input["env"][0]["key"], json!("DATABASE_URL"));
        assert_eq!(input["env"][0]["value"], json!("postgres://localhost/blog"));
    }

    /// `CreateInput::node_env` is a bare enum behind `#[serde(default)]`, so an
    /// explicit `null` is a deserialization error in the agent — "the user did
    /// not pick an environment" has to arrive as an absent key.
    #[test]
    fn an_unchosen_node_env_sends_no_key_at_all() {
        let body = request(json!({ "name": "blog", "entry": "apps/blog/server.js" }));
        let input = create_input(&body).expect("a valid request builds an input");
        let object = input.as_object().expect("object");

        assert!(!object.contains_key("node_env"), "{input}");
        for absent in ["memory_mb", "subscription_id", "proxy_domain"] {
            assert!(
                !object.contains_key(absent),
                "`{absent}` must be absent, not null: {input}"
            );
        }

        let chosen = request(json!({
            "name": "blog",
            "entry": "apps/blog/server.js",
            "node_env": "development",
        }));
        let input = create_input(&chosen).expect("a valid request builds an input");
        assert_eq!(input["node_env"], json!("development"));
    }

    /// The newtypes are parsed at the edge so the form can highlight the field.
    /// The traversal payloads are the hostile half: they never become a
    /// `TenantPath` at all, here or in the agent.
    #[test]
    fn a_bad_name_or_entry_is_refused_with_the_field_named() {
        for bad_name in ["", "-leading", "UPPER CASE", &"a".repeat(33)] {
            let body = request(json!({ "name": bad_name, "entry": "apps/x/server.js" }));
            let err = create_input(&body).expect_err("expected a refusal");
            assert_eq!(err.inner.code, ErrorCode::InvalidInput, "{bad_name:?}");
            assert_eq!(err.inner.field.as_deref(), Some("name"), "{bad_name:?}");
        }

        for hostile in ["../../etc/passwd", "/etc/passwd", "apps/x\0/server.js"] {
            let body = request(json!({ "name": "blog", "entry": hostile }));
            let err = create_input(&body).expect_err("expected a refusal");
            assert_eq!(err.inner.field.as_deref(), Some("entry"), "{hostile:?}");
        }

        let body = request(json!({
            "name": "blog",
            "entry": "apps/blog/server.js",
            "proxy_domain": "-not.a.domain",
        }));
        let err = create_input(&body).expect_err("expected a refusal");
        assert_eq!(err.inner.field.as_deref(), Some("proxy_domain"));
    }

    /// `AppName::parse` lowercases and trims; sending the raw string instead
    /// would make the audit target and the created row disagree.
    #[test]
    fn the_name_that_reaches_the_operation_is_the_parsed_one() {
        let body = request(json!({ "name": "  Blog  ", "entry": "apps/blog/server.js" }));
        let input = create_input(&body).expect("a valid request builds an input");
        assert_eq!(input["name"], json!("blog"));
    }
}
