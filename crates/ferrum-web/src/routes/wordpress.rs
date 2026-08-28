//! The WordPress toolkit API (spec §11.12, §13).
//!
//! A thin bridge onto the `wp.*` operations in `ferrum_ops::wordpress`. The
//! agent re-derives the permission from the database, re-resolves the site and
//! the install through the caller's tenant scope, and re-validates every
//! WP-CLI argument (spec §5.2 rule 4), so nothing here is load-bearing for
//! security on its own. Three things are nevertheless decided in this file:
//!
//! 1. **The audit row records the WP-CLI *group*, never the arguments.** A
//!    passthrough call is exactly where `wp option update` carries an API token
//!    and `wp user update --user_pass=…` carries a password, and an audit row
//!    is browsable by anyone holding `audit_read` (spec §12 rule 6). "Who ran
//!    a `user` command against install 7, and when" is the question an audit
//!    log exists to answer; the argument values are not part of it.
//!
//! 2. **The install id comes from the path, never from a body.** `POST
//!    /api/wordpress/{id}/cli` cannot be pointed at another installation by a
//!    body field that disagrees with the URL, because there is no such field.
//!
//! 3. **Absent optional fields are omitted, not sent as `null`.**
//!    `InstallInput::locale` is a `#[serde(default)]` newtype, not an
//!    `Option`: an explicit `null` fails deserialization in the agent where an
//!    absent key takes `en_US`.

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
pub struct DetectQuery {
    /// The site to look at. Outside the caller's tenant scope this is
    /// `not_found`, never a hint that the site exists.
    pub site_id: i64,
    /// Look in a subdirectory of the document root instead of the root itself.
    #[serde(default)]
    pub subdirectory: Option<String>,
}

/// Is there a WordPress on this site, and what does the panel know about it?
#[utoipa::path(
    get,
    path = "/api/wordpress",
    tag = "wordpress",
    security(("session_cookie" = [])),
    params(DetectQuery),
    responses(
        (status = 200, description = "Whether wp-config.php and wp-load.php are present, the install row if the panel has one, the core version WP-CLI reports, and the pinned WP-CLI version with its pin provenance", body = serde_json::Value),
        (status = 400, description = "`invalid_path`: the site's document root is not inside its tenant home", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `site_manage`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn detect(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<DetectQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::SiteManage)
        .map_err(ApiError::from)?;

    let mut input = json!({ "site_id": q.site_id });
    if let Some(sub) = &q.subdirectory {
        let parsed = ferrum_core::TenantPath::parse(sub)
            .map_err(|e| ApiError::new(e.with_field("subdirectory")))?;
        input
            .as_object_mut()
            .expect("just built as an object")
            .insert("subdirectory".into(), json!(parsed.as_str()));
    }

    let data = ops::invoke_now(&state, &current.auth, "wp.detect", input).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct InstallRequest {
    pub site_id: i64,
    /// Install into a subdirectory of the document root, e.g. `blog`.
    #[serde(default)]
    pub subdirectory: Option<String>,
    /// `en_US` when omitted. `fa_IR` is a first-class case (spec §11.12).
    #[serde(default)]
    #[schema(example = "fa_IR")]
    pub locale: Option<String>,
    /// The site title WordPress shows. May be Unicode; may not contain control
    /// characters or shell metacharacters.
    #[schema(example = "وبلاگ من")]
    pub title: String,
    /// The WordPress administrator's login name.
    #[schema(example = "siteadmin")]
    pub admin_user: String,
    #[schema(example = "admin@example.com")]
    pub admin_email: String,
    /// Turn on unattended core updates for this install.
    #[serde(default)]
    pub auto_update: bool,
}

/// Install WordPress: create a database and user, download core, write
/// `wp-config.php` with fresh CSPRNG salts, and run the installer.
///
/// **No password is returned.** The database password is written into
/// `wp-config.php` and can be rotated with `db.user.password`; the WordPress
/// administrator password is generated, used once and discarded. Both choices
/// are deliberate — a task's input is stored verbatim and its log is kept, so
/// neither is a place a credential may travel.
#[utoipa::path(
    post,
    path = "/api/wordpress",
    tag = "wordpress",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = InstallRequest,
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 400, description = "`invalid_input` / `invalid_path`: the offending field is named", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope, or no PHP is installed", body = ApiErrorBody),
        (status = 409, description = "`already_exists`: this site already has a WordPress, or the directory already holds a wp-config.php", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn install(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<InstallRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::SiteManage)
        .map_err(ApiError::from)?;

    let input = install_input(&body)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "wp.install",
        &body.site_id.to_string(),
        json!({
            "subdirectory": body.subdirectory,
            "locale": body.locale,
            "admin_user": body.admin_user,
            "auto_update": body.auto_update,
        }),
    )
    .await?;

    ops::invoke(&state, &current.auth, "wp.install", input).await
}

/// Turn a validated request into the `wp.install` input.
///
/// Split out from the handler so the omission rules are testable without an
/// agent: every optional key is either present with a value or absent
/// entirely, and `locale` in particular must never be sent as `null`.
fn install_input(body: &InstallRequest) -> ApiResult<serde_json::Value> {
    // Parsed at the edge for the field-highlighted error; the agent parses the
    // same newtypes again on the way in, and its copy is the one that is
    // trusted.
    let email = ferrum_core::Email::parse(&body.admin_email)
        .map_err(|e| ApiError::new(e.with_field("admin_email")))?;
    let admin_user = ferrum_core::Username::parse(&body.admin_user)
        .map_err(|e| ApiError::new(e.with_field("admin_user")))?;

    let mut input = json!({
        "site_id": body.site_id,
        "title": body.title,
        "admin_user": admin_user.as_str(),
        "admin_email": email.as_str(),
        "auto_update": body.auto_update,
    });
    let object = input.as_object_mut().expect("just built as an object");

    if let Some(sub) = &body.subdirectory {
        let parsed = ferrum_core::TenantPath::parse(sub)
            .map_err(|e| ApiError::new(e.with_field("subdirectory")))?;
        object.insert("subdirectory".into(), json!(parsed.as_str()));
    }
    // `InstallInput::locale` is a newtype behind `#[serde(default)]`, so an
    // explicit `null` would be a deserialization error in the agent where an
    // absent key is simply `en_US`.
    if let Some(locale) = &body.locale {
        object.insert("locale".into(), json!(locale));
    }
    Ok(input)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRequest {
    /// Update to a specific core version instead of the latest.
    #[serde(default)]
    #[schema(example = "6.8.2")]
    pub version: Option<String>,
    /// Also run `wp core update-db`, which is what WordPress itself prompts
    /// for after a core update. Absent means yes.
    #[serde(default)]
    pub update_db: Option<bool>,
}

/// Update WordPress core for one installation.
#[utoipa::path(
    post,
    path = "/api/wordpress/{id}/update",
    tag = "wordpress",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Install id")),
    request_body = UpdateRequest,
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: `version` is not a WordPress version", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such installation in this tenant's scope", body = ApiErrorBody),
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

    let mut input = json!({ "install_id": id });
    let object = input.as_object_mut().expect("just built as an object");
    if let Some(version) = &body.version {
        object.insert("version".into(), json!(version));
    }
    if let Some(update_db) = body.update_db {
        object.insert("update_db".into(), json!(update_db));
    }

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "wp.update",
        &id.to_string(),
        json!({ "version": body.version, "update_db": body.update_db }),
    )
    .await?;

    ops::invoke(&state, &current.auth, "wp.update", input).await
}

/// List an installation's plugins, with the update each one has waiting.
#[utoipa::path(
    get,
    path = "/api/wordpress/{id}/plugins",
    tag = "wordpress",
    security(("session_cookie" = [])),
    params(("id" = i64, Path, description = "Install id")),
    responses(
        (status = 200, description = "`wp plugin list --format=json`, passed through unmodelled", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `site_manage`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such installation in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn plugins(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::SiteManage)
        .map_err(ApiError::from)?;

    let data = ops::invoke_now(
        &state,
        &current.auth,
        "wp.plugin.list",
        json!({ "install_id": id }),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PluginUpdateRequest {
    /// Plugin slugs. An empty list means every plugin with an update waiting.
    #[serde(default)]
    #[schema(example = json!(["woocommerce", "wp-super-cache"]))]
    pub plugins: Vec<String>,
}

/// Update named plugins, or every plugin with an update available.
#[utoipa::path(
    post,
    path = "/api/wordpress/{id}/plugins/update",
    tag = "wordpress",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Install id")),
    request_body = PluginUpdateRequest,
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: a slug is not a slug", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such installation in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn plugins_update(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<PluginUpdateRequest>,
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
        "wp.plugin.update",
        &id.to_string(),
        json!({ "plugins": body.plugins }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "wp.plugin.update",
        json!({ "install_id": id, "plugins": body.plugins }),
    )
    .await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CliRequest {
    /// One of `core`, `plugin`, `theme`, `option`, `user`, `db`, `cache`,
    /// `rewrite`. Anything else is refused by the agent's enum before the
    /// operation body runs.
    #[schema(example = "option")]
    pub subcommand: String,
    /// Everything after the group. Each argument must be ASCII, free of
    /// control characters and shell metacharacters, and must not be one of the
    /// flags the panel reserves (`--path`, `--require`, `--exec`, `--ssh`,
    /// `--http`, `--prompt`, `--context`).
    #[serde(default)]
    #[schema(example = json!(["get", "blogname"]))]
    pub args: Vec<String>,
}

/// Run a restricted WP-CLI command against one installation.
///
/// This is not a shell. The command group is a closed enum, every argument is
/// validated, `--path` is decided by the panel and cannot be overridden, and
/// the whole thing runs as the tenant's Linux account through a
/// privilege-dropping helper. A non-zero WP-CLI exit is returned as data —
/// `wp option get missing_key` exits 1, and turning that into an API error
/// would make half of WP-CLI unusable.
#[utoipa::path(
    post,
    path = "/api/wordpress/{id}/cli",
    tag = "wordpress",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Install id")),
    request_body = CliRequest,
    responses(
        (status = 200, description = "The exact argv WP-CLI received, its exit status, stdout and stderr", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: the subcommand is not in the allowlist, or an argument was refused", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such installation in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn cli(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<CliRequest>,
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
        "wp.cli",
        &id.to_string(),
        cli_audit_detail(&body),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "wp.cli",
        json!({
            "install_id": id,
            "subcommand": body.subcommand,
            "args": body.args,
        }),
    )
    .await
}

/// What the audit log records about a passthrough call.
///
/// The group and the argument *count*, never the values. `wp option update
/// some_api_key sk_live_…` and `wp user update admin --user_pass=…` are both
/// ordinary, legitimate uses of this endpoint, and an audit row is read by
/// every operator holding `audit_read` (spec §12 rule 6). The count is enough
/// to see that a call happened and roughly how large it was.
fn cli_audit_detail(body: &CliRequest) -> serde_json::Value {
    json!({
        "subcommand": body.subcommand,
        "arg_count": body.args.len(),
    })
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

    fn cli_request(value: serde_json::Value) -> CliRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    fn install_request(value: serde_json::Value) -> InstallRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    /// The one piece of judgement this module owns rather than delegates.
    ///
    /// A WP-CLI passthrough is exactly where a password or an API token
    /// appears as an ordinary argument, and the audit log is browsable by
    /// anybody holding `audit_read` (spec §12 rule 6) — so no argument value
    /// may reach it, even though every one of them is legitimate input to the
    /// operation itself.
    #[test]
    fn a_cli_audit_row_records_the_group_and_never_the_argument_values() {
        let body = cli_request(json!({
            "subcommand": "user",
            "args": ["update", "admin", "--user_pass=hunter2"],
        }));
        let rendered = serde_json::to_string(&cli_audit_detail(&body)).expect("serializes");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("admin"), "{rendered}");
        assert!(rendered.contains("user"), "{rendered}");
        assert!(rendered.contains("\"arg_count\":3"), "{rendered}");

        let secret = cli_request(json!({
            "subcommand": "option",
            "args": ["update", "stripe_key", "sk_live_TOPSECRET"],
        }));
        let rendered = serde_json::to_string(&cli_audit_detail(&secret)).expect("serializes");
        assert!(!rendered.contains("sk_live_TOPSECRET"), "{rendered}");
    }

    /// `InstallInput::locale` is a newtype behind `#[serde(default)]`, so an
    /// explicit `null` is a deserialization error in the agent — "the user did
    /// not pick a locale" has to arrive as an absent key.
    #[test]
    fn an_unchosen_locale_or_subdirectory_sends_no_key_at_all() {
        let body = install_request(json!({
            "site_id": 4,
            "title": "My Blog",
            "admin_user": "siteadmin",
            "admin_email": "admin@example.com",
        }));
        let input = install_input(&body).expect("a valid request builds an input");
        let object = input.as_object().expect("object");
        for absent in ["locale", "subdirectory"] {
            assert!(
                !object.contains_key(absent),
                "`{absent}` must be absent, not null: {input}"
            );
        }

        let chosen = install_request(json!({
            "site_id": 4,
            "title": "وبلاگ من",
            "admin_user": "siteadmin",
            "admin_email": "admin@example.com",
            "locale": "fa_IR",
            "subdirectory": "blog",
        }));
        let input = install_input(&chosen).expect("a valid request builds an input");
        assert_eq!(input["locale"], json!("fa_IR"));
        assert_eq!(input["subdirectory"], json!("blog"));
        assert_eq!(input["title"], json!("وبلاگ من"));
    }

    /// The newtypes are parsed at the edge so a form can highlight the field.
    /// The traversal payloads are the hostile half: they never become a
    /// `TenantPath` at all, here or in the agent.
    #[test]
    fn a_bad_email_user_or_subdirectory_is_refused_with_the_field_named() {
        let body = install_request(json!({
            "site_id": 1,
            "title": "T",
            "admin_user": "siteadmin",
            "admin_email": "not-an-email",
        }));
        let err = install_input(&body).expect_err("expected a refusal");
        assert_eq!(err.inner.field.as_deref(), Some("admin_email"));

        let body = install_request(json!({
            "site_id": 1,
            "title": "T",
            "admin_user": "not a username!",
            "admin_email": "admin@example.com",
        }));
        let err = install_input(&body).expect_err("expected a refusal");
        assert_eq!(err.inner.field.as_deref(), Some("admin_user"));

        for hostile in ["../../etc", "/etc/passwd", "blog\0/x"] {
            let body = install_request(json!({
                "site_id": 1,
                "title": "T",
                "admin_user": "siteadmin",
                "admin_email": "admin@example.com",
                "subdirectory": hostile,
            }));
            let err = install_input(&body).expect_err("expected a refusal for {hostile:?}");
            assert_eq!(err.inner.code, ErrorCode::InvalidPath, "{hostile:?}");
            assert_eq!(
                err.inner.field.as_deref(),
                Some("subdirectory"),
                "{hostile:?}"
            );
        }
    }

    /// `Username::parse` normalises; sending the raw string instead would make
    /// the audit target and the created WordPress account disagree.
    #[test]
    fn the_admin_user_that_reaches_the_operation_is_the_parsed_one() {
        let body = install_request(json!({
            "site_id": 1,
            "title": "T",
            "admin_user": "  SiteAdmin  ",
            "admin_email": "admin@example.com",
        }));
        let input = install_input(&body).expect("a valid request builds an input");
        assert_eq!(
            input["admin_user"],
            json!(ferrum_core::Username::parse("SiteAdmin").unwrap().as_str())
        );
    }
}
