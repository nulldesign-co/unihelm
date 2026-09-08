//! Deploying a site from a Git repository (spec §11.2, §13).
//!
//! A thin bridge onto the `git.*` operations in `unihelm_ops::git`. The agent
//! re-derives the permission, re-resolves the site through the caller's tenant
//! scope, and re-parses the repository URL and the branch name, so nothing here
//! is load-bearing for security. Two things are nevertheless decided in this
//! file:
//!
//! 1. **The site id comes from the path, never from a body.** `POST
//!    /api/sites/{id}/git/pull` cannot be aimed at another site by a body field
//!    that disagrees with the URL, because there is no such field.
//!
//! 2. **An audit row never carries a credential.** The audit row is written
//!    *before* the operation runs — which is right, because a call that fails
//!    still happened — and it is readable by anybody holding `audit_read`
//!    (spec §12 rule 6). The agent refuses a repository URL with a username or
//!    token in it, but that refusal comes one round trip too late to keep the
//!    token out of the row, so [`redact_credentials`] takes the userinfo out on
//!    the way past. It is not a second copy of the validation rules — the
//!    request is forwarded verbatim and the agent still decides.

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use unihelm_core::Permission;
use unihelm_db::audit::NewAuditEntry;
use utoipa::ToSchema;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// What the panel knows about this site's repository, and what is actually in
/// its document root.
#[utoipa::path(
    get,
    path = "/api/sites/{id}/git",
    tag = "git",
    security(("session_cookie" = [])),
    params(("id" = i64, Path, description = "Site id")),
    responses(
        (status = 200, description = "The attachment if there is one, whether git is installed, what state the document root is in, and the checkout's branch, commit and uncommitted changes", body = serde_json::Value),
        (status = 400, description = "`invalid_path`: the site's document root is not inside its tenant home", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `site_read`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn status(
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
        "git.status",
        json!({ "site_id": id }),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AttachRequest {
    /// A public HTTPS repository URL. SSH addresses and URLs carrying a
    /// username or token are refused by the agent, with the reason.
    #[schema(example = "https://github.com/owner/project.git")]
    pub repository: String,
    /// The branch to deploy. Omitted or empty means the repository's default
    /// branch, and the first clone records which branch that turned out to be.
    #[serde(default)]
    #[schema(example = "main")]
    pub branch: Option<String>,
}

/// Record which repository and branch this site deploys from.
///
/// Writes nothing to disk: it is the panel's note of what to clone or pull.
/// Attaching a *different* repository forgets the commit the old one deployed,
/// because that commit no longer describes anything.
#[utoipa::path(
    post,
    path = "/api/sites/{id}/git",
    tag = "git",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Site id")),
    request_body = AttachRequest,
    responses(
        (status = 200, description = "The stored attachment, and the repository it replaced if it replaced one", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: the repository is not a public https:// URL, or the branch name is not usable — the offending field is named", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn attach(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<AttachRequest>,
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
        "git.attach",
        &id.to_string(),
        json!({
            "repository": redact_credentials(&body.repository),
            "branch": body.branch,
        }),
    )
    .await?;

    ops::invoke(&state, &current.auth, "git.attach", attach_input(id, &body)).await
}

/// Turn a validated request into the `git.attach` input.
///
/// Split out from the handler so the omission rule is testable without an
/// agent: `branch` is a `#[serde(default)] Option<String>` on the operation, and
/// an absent key means "the repository's default branch". Sending the key with
/// an empty string would work too — the agent treats blank as absent — but a
/// body that says nothing about the branch should reach the agent saying
/// nothing about the branch.
fn attach_input(site_id: i64, body: &AttachRequest) -> serde_json::Value {
    let mut input = serde_json::Map::new();
    input.insert("site_id".into(), json!(site_id));
    input.insert("repository".into(), json!(body.repository));
    if let Some(branch) = body.branch.as_deref().filter(|b| !b.trim().is_empty()) {
        input.insert("branch".into(), json!(branch));
    }
    serde_json::Value::Object(input)
}

/// Forget the repository. The checkout and the site's files stay where they
/// are — this removes the panel's note, not the code.
#[utoipa::path(
    delete,
    path = "/api/sites/{id}/git",
    tag = "git",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Site id")),
    responses(
        (status = 200, description = "Whether there was an attachment to remove, and which repository it named", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn detach(
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
        "git.detach",
        &id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "git.detach",
        json!({ "site_id": id }),
    )
    .await
}

/// Clone the attached repository into the site's document root.
///
/// Refused when the document root already holds a checkout, or files the panel
/// did not put there — the only file it will replace is the holding page
/// `site.create` wrote.
#[utoipa::path(
    post,
    path = "/api/sites/{id}/git/clone",
    tag = "git",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Site id")),
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`, or `permission_denied` from git when the repository is private", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site, no repository attached, no such repository or branch, or no document root yet", body = ApiErrorBody),
        (status = 409, description = "`conflict`: the document root already holds a checkout or somebody's files", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn clone(
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
        "git.clone",
        &id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(&state, &current.auth, "git.clone", json!({ "site_id": id })).await
}

/// Deploy: fetch the attached branch and fast-forward the checkout onto it.
///
/// Refused when the working tree has uncommitted changes to tracked files, and
/// refused when the histories have diverged. Nothing here ever discards a
/// commit.
#[utoipa::path(
    post,
    path = "/api/sites/{id}/git/pull",
    tag = "git",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Site id")),
    responses(
        (status = 202, description = "Queued; poll the task", body = ops::TaskAccepted),
        (status = 200, description = "Finished immediately", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site, or no repository attached", body = ApiErrorBody),
        (status = 409, description = "`conflict`: there is no checkout, it points at another repository, it has uncommitted changes, or it cannot be fast-forwarded", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn pull(
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
        "git.pull",
        &id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(&state, &current.auth, "git.pull", json!({ "site_id": id })).await
}

/// Replace any userinfo in a repository URL with `***`.
///
/// The agent refuses such a URL outright, so this is not a fallback for it —
/// it is what keeps a token out of the audit row that is written before the
/// agent ever sees the request. Both spellings git accepts are covered:
/// `https://user:token@host/path` and the scp-like `user@host:path`.
fn redact_credentials(raw: &str) -> String {
    let (scheme, rest) = match raw.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), raw),
    };
    // Everything before the first `/` is the authority; a `@` inside it
    // separates the credential from the host.
    let end = rest.find('/').unwrap_or(rest.len());
    match rest[..end].rsplit_once('@') {
        Some((_, host)) => format!("{scheme}***@{host}{}", &rest[end..]),
        None => raw.to_string(),
    }
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

    fn attach_request(value: serde_json::Value) -> AttachRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    /// The one piece of judgement this module owns rather than delegates.
    ///
    /// The audit row is written before the agent has refused anything, and it
    /// is readable by anybody holding `audit_read` — so a token that arrives in
    /// a repository URL must not survive the trip into it.
    #[test]
    fn a_repository_url_carrying_a_credential_is_redacted_before_the_audit_row() {
        for (raw, expected) in [
            (
                "https://user:ghp_secrettoken@github.com/o/p.git",
                "https://***@github.com/o/p.git",
            ),
            (
                "https://ghp_secrettoken@github.com/o/p.git",
                "https://***@github.com/o/p.git",
            ),
            ("git@github.com:o/p.git", "***@github.com:o/p.git"),
        ] {
            let redacted = redact_credentials(raw);
            assert_eq!(redacted, expected, "{raw}");
            assert!(!redacted.contains("ghp_secrettoken"), "{raw}");
        }
    }

    #[test]
    fn an_ordinary_repository_url_reaches_the_audit_row_unchanged() {
        for url in [
            "https://github.com/owner/project.git",
            "https://gitlab.example.com:8443/group/project",
        ] {
            assert_eq!(redact_credentials(url), url);
        }
    }

    /// An explicit `null` branch would fail deserialization in the agent where
    /// an absent key means "the repository's default branch"; a blank one from
    /// an untouched form field means the same thing and must not travel as a
    /// branch named "".
    #[test]
    fn a_blank_branch_is_omitted_rather_than_sent_as_a_branch_name() {
        for blank in [json!(""), json!("   "), serde_json::Value::Null] {
            let body = attach_request(json!({
                "repository": "https://github.com/o/p.git",
                "branch": blank,
            }));
            let input = attach_input(7, &body);
            assert!(input.get("branch").is_none(), "{input}");
            assert_eq!(input["site_id"], json!(7));
        }

        let body = attach_request(json!({
            "repository": "https://github.com/o/p.git",
            "branch": "release/2026",
        }));
        assert_eq!(attach_input(7, &body)["branch"], json!("release/2026"));
    }

    /// The site id is a path parameter and there is no body field that could
    /// disagree with it.
    #[test]
    fn the_site_id_comes_from_the_path_and_a_body_cannot_override_it() {
        let body = attach_request(json!({
            "repository": "https://github.com/o/p.git",
            "site_id": 99,
        }));
        assert_eq!(attach_input(7, &body)["site_id"], json!(7));
    }
}
