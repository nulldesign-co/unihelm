//! The migration importer API (spec §11.15, §13).
//!
//! A thin bridge onto the `import.*` operations in `ferrum_ops::importer`. The
//! agent re-derives the permission, re-validates the source path and re-reads
//! the stored plan, so nothing here is load-bearing for security on its own.
//! Three things are nevertheless decided in this file:
//!
//! 1. **Planning is a POST even though it changes nothing on the server.** It
//!    reads an operator-named path, takes minutes, and writes a plan row — so
//!    it is a task with a body and an audit entry, not a cacheable GET with a
//!    filesystem path in the query string.
//! 2. **The plan id comes from the URL, never from a body.** `POST
//!    /api/imports/{id}/apply` cannot be pointed at a different plan by a field
//!    that disagrees with the path, because there is no such field.
//! 3. **`import.apply` answers 202 and the *outcome* is read back from the
//!    plan.** A task's return value never reaches the caller (the response is
//!    a task id), so what actually happened is stored on the plan row and
//!    served by `GET /api/imports/{id}`. That is the endpoint to poll once the
//!    task finishes.

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

/// Which source to read, and where it is.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SourceBody {
    /// A cPanel `cpmove` / full-backup tarball already on this server.
    Cpanel {
        #[schema(example = "/root/cpmove-bob.tar.gz")]
        path: String,
    },
    /// An aaPanel installation root. `/www` on a stock install.
    Aapanel {
        #[serde(default)]
        #[schema(example = "/www")]
        root: Option<String>,
    },
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PlanRequest {
    pub source: SourceBody,
    /// The subscription every imported site and database will belong to.
    pub subscription_id: i64,
    /// PHP version for imported PHP sites whose own version is unknown or is
    /// one Ferrum does not offer.
    #[serde(default)]
    #[schema(example = "8.3")]
    pub php_version: Option<String>,
}

/// Read a cPanel backup or an aaPanel installation and produce the import plan.
///
/// **Nothing is created.** The response is a task; when it finishes, the plan is
/// readable at `GET /api/imports` and `GET /api/imports/{id}`, and its id is
/// what `POST /api/imports/{id}/apply` takes. The plan lists what maps *and*
/// what does not — mail, DNS zones, certificates, cron, FTP accounts — with a
/// reason for each.
#[utoipa::path(
    post,
    path = "/api/imports",
    tag = "imports",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = PlanRequest,
    responses(
        (status = 202, description = "Queued; poll the task, then read the plan", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 400, description = "`invalid_path`: the source path is relative, contains `..` or holds a NUL; `invalid_input`: the archive is not a readable cpmove, or has more than one top-level directory", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_manage` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such source path, or no such subscription", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<PlanRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let input = plan_input(&body)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "import.plan",
        &body.subscription_id.to_string(),
        // The source path is the whole point of the audit row: "who pointed the
        // importer at what, and when".
        json!({ "source": source_label(&body.source) }),
    )
    .await?;

    ops::invoke(&state, &current.auth, "import.plan", input).await
}

/// Turn a validated request into the `import.plan` input.
///
/// Split out from the handler so the shape is testable without an agent. The
/// agent parses these values again — its copy is the one that is trusted — but
/// a bad PHP version is worth naming here, where the field name can be attached
/// to the error.
fn plan_input(body: &PlanRequest) -> ApiResult<serde_json::Value> {
    let source = match &body.source {
        SourceBody::Cpanel { path } => json!({ "kind": "cpanel", "path": path }),
        SourceBody::Aapanel { root } => match root {
            // `root` is `#[serde(default)]` on the agent side, so an explicit
            // `null` would be a deserialization error where an absent key takes
            // `/www`.
            Some(root) => json!({ "kind": "aapanel", "root": root }),
            None => json!({ "kind": "aapanel" }),
        },
    };

    let mut input = json!({
        "source": source,
        "subscription_id": body.subscription_id,
    });
    if let Some(version) = &body.php_version {
        let parsed = ferrum_core::PhpVersion::parse(version)
            .map_err(|e| ApiError::new(e.with_field("php_version")))?;
        input
            .as_object_mut()
            .expect("just built as an object")
            .insert("php_version".into(), json!(parsed.as_str()));
    }
    Ok(input)
}

/// What the audit row records about a source: its kind and its path. Never the
/// contents — the plan itself is stored, and the audit log is not the place to
/// duplicate somebody else's account layout.
fn source_label(source: &SourceBody) -> String {
    match source {
        SourceBody::Cpanel { path } => format!("cpanel:{path}"),
        SourceBody::Aapanel { root } => {
            format!("aapanel:{}", root.as_deref().unwrap_or("/www"))
        }
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// How many plans to return. Clamped to 200 by the agent.
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Recent import plans, newest first, without their full documents.
#[utoipa::path(
    get,
    path = "/api/imports",
    tag = "imports",
    security(("session_cookie" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Each plan's id, source, totals, and whether it has been applied", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_manage`", body = ApiErrorBody),
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
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let mut input = json!({});
    let object = input.as_object_mut().expect("just built as an object");
    if let Some(limit) = q.limit {
        object.insert("limit".into(), json!(limit));
    }
    if let Some(offset) = q.offset {
        object.insert("offset".into(), json!(offset));
    }

    let data = ops::invoke_now(&state, &current.auth, "import.list", input).await?;
    Ok(Json(data))
}

/// One plan in full: the mapping, the unmapped list, and — once it has been
/// applied — what each step actually did.
#[utoipa::path(
    get,
    path = "/api/imports/{id}",
    tag = "imports",
    security(("session_cookie" = [])),
    params(("id" = i64, Path, description = "Plan id")),
    responses(
        (status = 200, description = "The stored plan document and its outcome", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_manage`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such plan in this caller's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn detail(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let data = ops::invoke_now(
        &state,
        &current.auth,
        "import.list",
        json!({ "plan_id": id }),
    )
    .await?;
    Ok(Json(data))
}

/// Execute a stored plan.
///
/// The plan is executed **as stored**: the source is re-opened only for payload
/// bytes, and only after its SHA-256 still matches the plan's. A plan that was
/// already applied is refused (`409`) rather than applied twice — make a fresh
/// plan instead. Poll `GET /api/imports/{id}` once the task finishes to see
/// what each step did.
#[utoipa::path(
    post,
    path = "/api/imports/{id}/apply",
    tag = "imports",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Plan id")),
    responses(
        (status = 202, description = "Queued; poll the task, then re-read the plan for its outcome", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_manage` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such plan, or its source is no longer on disk", body = ApiErrorBody),
        (status = 409, description = "`already_exists`: the plan was already applied; `conflict`: the source has changed since the plan was made, or another apply holds it", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn apply(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "import.apply",
        &id.to_string(),
        json!({ "plan_id": id }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "import.apply",
        json!({ "plan_id": id }),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_core::ErrorCode;

    fn request(value: serde_json::Value) -> PlanRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    #[test]
    fn an_absent_aapanel_root_is_omitted_rather_than_sent_as_null() {
        // The agent's field is `#[serde(default)]`; an explicit `null` would
        // fail deserialization there where an absent key means `/www`.
        let input = plan_input(&request(json!({
            "source": { "kind": "aapanel" },
            "subscription_id": 3,
        })))
        .unwrap();
        assert_eq!(input["source"]["kind"], "aapanel");
        assert!(
            input["source"].get("root").is_none(),
            "an absent root must not be sent at all: {input}"
        );
        assert!(input.get("php_version").is_none());
    }

    #[test]
    fn a_php_version_is_validated_at_the_edge_with_its_field_named() {
        let err = plan_input(&request(json!({
            "source": { "kind": "cpanel", "path": "/root/x.tar.gz" },
            "subscription_id": 1,
            "php_version": "5.6",
        })))
        .unwrap_err();
        assert_eq!(err.inner.code, ErrorCode::InvalidPhpVersion);
        assert_eq!(err.inner.field.as_deref(), Some("php_version"));

        let ok = plan_input(&request(json!({
            "source": { "kind": "cpanel", "path": "/root/x.tar.gz" },
            "subscription_id": 1,
            "php_version": "8.3",
        })))
        .unwrap();
        assert_eq!(ok["php_version"], "8.3");
        assert_eq!(ok["source"]["path"], "/root/x.tar.gz");
    }

    #[test]
    fn a_source_kind_this_build_has_no_importer_for_is_refused_at_the_edge() {
        assert!(
            serde_json::from_value::<PlanRequest>(json!({
                "source": { "kind": "plesk", "path": "/root/x.tar.gz" },
                "subscription_id": 1,
            }))
            .is_err()
        );
    }

    #[test]
    fn the_audit_row_records_the_source_but_never_its_contents() {
        assert_eq!(
            source_label(&SourceBody::Cpanel {
                path: "/root/cpmove-bob.tar.gz".into()
            }),
            "cpanel:/root/cpmove-bob.tar.gz"
        );
        assert_eq!(
            source_label(&SourceBody::Aapanel { root: None }),
            "aapanel:/www"
        );
    }
}
