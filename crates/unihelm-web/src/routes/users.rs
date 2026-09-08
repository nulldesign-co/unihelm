//! Panel accounts, and the one credential a signed-in account changes itself
//! (spec §6.1, §12 rule 7).
//!
//! Two halves that look alike and are not.
//!
//! # Managing other people's accounts
//!
//! `GET/POST /api/users`, `/api/users/{id}/role`, `/api/users/{id}/status` and
//! `DELETE /api/users/{id}` are the usual thin wrappers: check the permission,
//! write the audit row, hand it to `unihelm_ops::users`, which re-derives the
//! caller's rights against the database before it does anything (spec §12
//! rule 4). Every refusal that matters — the last administrator, your own
//! account, an account that still owns subscriptions — lives there, so the CLI
//! gets it too.
//!
//! # Changing your own password
//!
//! `POST /api/account/password` is answered **in this process**, and that is a
//! decision rather than a shortcut.
//!
//! It is not privileged work: two rows of the panel's own database and nothing
//! on the host. And an operation has to declare the one `Permission` its caller
//! must hold, while there is no permission that means *your own account* — a
//! customer holds neither `user_manage` nor anything that could honestly stand
//! for it. Filing this under a permission every role happens to have would put
//! a false claim in the audit trail and in `docs/operations.md`. Meanwhile the
//! two things it needs are both here: the session table and the argon2 budget.
//! So it sits beside login and logout, which are answered here for the same
//! reasons.
//!
//! Four rules hold it up, and each has a way it goes wrong:
//!
//! 1. **The current password is required**, from everybody, the admin included.
//!    Without it a stolen session is a stolen account: whoever has the cookie
//!    sets a password of their own and the owner is locked out of their own
//!    panel. It is verified with [`verify_or_burn_under_budget`] — a blocking
//!    thread under [`PASSWORD_VERIFY_PERMITS`] — because argon2id at 19 MiB run
//!    inline parks an async worker for a third of a second.
//!
//! 2. **The new one is hashed exactly once, in the one place that hashes.**
//!    `UserRepo::set_password` runs the policy and then
//!    `unihelm_db::password::hash_password`, which is the same function and the
//!    same parameters the login path verifies against. A second configuration
//!    here would be a second thing to keep in step, and the way that fails is
//!    silent — a hash the login path can still read but at a cost nobody meant.
//!    The store runs under a permit from the same budget, so a password change
//!    cannot be a way to spend argon2 the login endpoint is being kept from.
//!
//! 3. **Every other session ends.** Somebody changing their password usually
//!    believes another person has the old one, and a session does not consult
//!    the hash — `auth.rs` even extends the cookie on every request, so an
//!    intruder's session would never age out. Every session is revoked and this
//!    request is issued a fresh one on the way out, which is why the response
//!    carries a new CSRF token and a new cookie: rotating the credential
//!    rotates the session that proved it.
//!
//! 4. **Nothing here ever writes a password down.** Not in a log line, not in
//!    an audit `detail`, not in a response. `unihelm_db::audit` would redact a
//!    `password` key on the way in; this module does not rely on that, and puts
//!    none there in the first place.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use unihelm_core::{ErrorCode, Permission};
use unihelm_db::audit::NewAuditEntry;
use unihelm_db::password;
use unihelm_db::sessions::DEFAULT_TTL;
use utoipa::{IntoParams, ToSchema};

use crate::auth::{
    CurrentUser, PASSWORD_VERIFY_PERMITS, client_ip, cookie_secure, session_cookie,
    tenant_scope_for, verify_or_burn_under_budget,
};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// The accounts this caller may see: the whole panel for an admin, itself and
/// the accounts beneath it for a reseller.
#[utoipa::path(
    get,
    path = "/api/users",
    tag = "users",
    params(ListQuery),
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Accounts in the caller's scope, each with the counts that would block deleting it", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `user_manage`", body = ApiErrorBody),
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
        .require(Permission::UserManage)
        .map_err(ApiError::from)?;
    Ok(Json(
        ops::invoke_now(
            &state,
            &current.auth,
            "user.list",
            json!({ "limit": q.limit, "offset": q.offset }),
        )
        .await?,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRequest {
    pub username: String,
    pub email: String,
    /// `admin`, `reseller` or `customer`. A reseller may only send `customer`.
    pub role: String,
    /// The account's first password. At least 12 characters; the operator hands
    /// it over out of band, and the panel never shows it again.
    pub password: String,
    #[serde(default)]
    pub full_name: Option<String>,
}

/// Create an account. Whose it is comes from who is asking, never from the body.
#[utoipa::path(
    post,
    path = "/api/users",
    tag = "users",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = CreateRequest,
    responses(
        (status = 200, description = "The account that was created", body = serde_json::Value),
        (status = 400, description = "`invalid_username` / `invalid_input` / `password_too_weak`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `user_manage`, and a reseller may only create customers", body = ApiErrorBody),
        (status = 409, description = "`already_exists`: that username or email is taken", body = ApiErrorBody),
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
        .require(Permission::UserManage)
        .map_err(ApiError::from)?;

    // The role and the username, never the password: an audit row outlives
    // every other place a credential is scrubbed (spec §12 rule 6).
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "user.create",
        &body.username,
        json!({ "role": body.role, "email": body.email }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "user.create",
        json!({
            "username": body.username,
            "email": body.email,
            "role": body.role,
            "password": body.password,
            "full_name": body.full_name,
        }),
    )
    .await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RoleRequest {
    pub role: String,
}

/// Change an account's role. Ends that account's sessions.
#[utoipa::path(
    post,
    path = "/api/users/{id}/role",
    tag = "users",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "The account")),
    request_body = RoleRequest,
    responses(
        (status = 200, description = "The account, and how many of its sessions ended", body = serde_json::Value),
        (status = 403, description = "`permission_denied`: not your own account, and a reseller may only manage customers", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such account in this scope", body = ApiErrorBody),
        (status = 409, description = "`dependents_exist`: this is the only administrator who can sign in", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn set_role(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<RoleRequest>,
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
        "user.role.set",
        &id.to_string(),
        json!({ "role": body.role }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "user.role.set",
        json!({ "user_id": id, "role": body.role }),
    )
    .await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct StatusRequest {
    /// `active` or `suspended`.
    pub status: String,
}

/// Suspend an account or let it back in. Suspending ends its sessions.
#[utoipa::path(
    post,
    path = "/api/users/{id}/status",
    tag = "users",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "The account")),
    request_body = StatusRequest,
    responses(
        (status = 200, description = "The account, and how many of its sessions ended", body = serde_json::Value),
        (status = 403, description = "`permission_denied`: you cannot suspend the account you are signed in as", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such account in this scope", body = ApiErrorBody),
        (status = 409, description = "`dependents_exist`: this is the only administrator who can sign in", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn set_status(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<StatusRequest>,
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
        "user.status.set",
        &id.to_string(),
        json!({ "status": body.status }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "user.status.set",
        json!({ "user_id": id, "status": body.status }),
    )
    .await
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DeleteQuery {
    /// The account's username, retyped. The agent refuses without it — an id
    /// in a URL is not something an operator can check by eye.
    pub confirm_username: String,
}

/// Delete an account. Refused while it still owns anything.
#[utoipa::path(
    delete,
    path = "/api/users/{id}",
    tag = "users",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "The account"), DeleteQuery),
    responses(
        (status = 200, description = "What was deleted, and what went with it", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: the confirmation did not match the account's username", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: you cannot delete the account you are signed in as", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such account in this scope", body = ApiErrorBody),
        (status = 409, description = "`dependents_exist`: the only administrator, or the account still owns subscriptions, plans or customers", body = ApiErrorBody),
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
        .require(Permission::UserManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "user.delete",
        &id.to_string(),
        json!({ "confirm_username": q.confirm_username }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "user.delete",
        json!({ "user_id": id, "confirm_username": q.confirm_username }),
    )
    .await
}

// ---------------------------------------------------------------------------
// Your own password
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    /// The password on the account right now. Required from everybody.
    pub current_password: String,
    /// The replacement. At least 12 characters (`unihelm_db::password`).
    pub new_password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChangePasswordResponse {
    /// Other devices that were signed out. This session is not counted: it was
    /// revoked with the rest and re-issued on this response.
    pub sessions_ended: u64,
    /// The CSRF token of the session this response carries, because the old one
    /// went with the old session. A client must store it in place of the
    /// previous one or its next write is refused.
    pub csrf_token: String,
}

/// Change the password of the account you are signed in as.
#[utoipa::path(
    post,
    path = "/api/account/password",
    tag = "auth",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Changed. Every other session is signed out, and this one is replaced — the new cookie and CSRF token ride on this response", body = ChangePasswordResponse),
        (status = 400, description = "`password_too_weak`, or `invalid_input` when the new password is the one already in use", body = ApiErrorBody),
        (status = 401, description = "`invalid_credentials`: the current password is wrong. Nothing changed", body = ApiErrorBody),
        (status = 429, description = "`rate_limited`: the panel is already checking as many passwords as it will at once", body = ApiErrorBody),
    ),
)]
pub async fn change_password(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    current: CurrentUser,
    Json(body): Json<ChangePasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    let request_id = current.auth.request_id.clone();

    // Checked before anything expensive: a password that cannot be stored is
    // not worth an argon2 verification, and the caller gets the message on the
    // field it belongs to rather than after the round trip.
    password::check_strength(&body.new_password)
        .map_err(|e| ApiError::new(e).with_request_id(request_id.clone()))?;

    // Refused rather than performed. Changing a password to itself would sign
    // every other device out and rotate this session for no change at all —
    // which reads as "it worked" and is the shape of a lie.
    if body.new_password == body.current_password {
        return Err(ApiError::code(
            ErrorCode::InvalidInput,
            "the new password is the one already on this account. Nothing was changed, and \
             no sessions were signed out.",
        )
        .with_request_id(request_id));
    }

    // Blocking thread, inside the panel's hashing budget. Deliberately not
    // recorded as a failed *login*: those budgets exist to blunt anonymous
    // guessing at `/api/auth/login`, and spending one from here would let an
    // operator who mistypes their own password five times lock themselves out
    // of signing in at all. What bounds guessing here is the budget itself —
    // this endpoint needs a live session and a CSRF token, and it will never
    // check more than PASSWORD_VERIFY_PERMITS passwords at once.
    let correct = verify_or_burn_under_budget(
        &state.password_verifications,
        Some(current.user.pass_hash.clone()),
        body.current_password,
    )
    .await
    .map_err(|e| e.with_request_id(request_id.clone()))?;

    if !correct {
        tracing::warn!(
            user = %current.user.username,
            ip = %client_ip(Some(&peer), &headers),
            "a password change was refused: the current password did not match"
        );
        audit(
            &state,
            &current,
            &headers,
            &peer,
            "auth.password_change_refused",
            current.user.username.as_str(),
            json!({ "reason": "current password did not match" }),
        )
        .await?;
        return Err(ApiError::code(
            ErrorCode::InvalidCredentials,
            "that is not the password on this account, so nothing was changed. The current \
             password is required even when you are already signed in — otherwise a stolen \
             session would be enough to take the account.",
        )
        .with_request_id(request_id));
    }

    {
        // The hash itself happens inside `set_password`, which is the one
        // function in the tree that hashes a password. Holding a permit across
        // it is what keeps this endpoint from spending argon2 the login path is
        // being rationed out of. `acquire`, not `try_acquire`: this caller has
        // already proved the current password at the cost of a permit, and
        // throwing that away to answer 429 would send them back to retype both
        // fields.
        let _permit = state.password_verifications.acquire().await.map_err(|e| {
            ApiError::new(unihelm_core::UnihelmError::internal(format!(
                "the panel's password budget is closed ({e}); nothing was changed"
            )))
        })?;
        state
            .db
            .users(&tenant_scope_for(&current.user))
            .set_password(current.user.id, &body.new_password)
            .await
            .map_err(ApiError::from)?;
    }

    // Every session, this one included — then a fresh one on the way out. The
    // point of changing a password is that whoever had the old one stops being
    // signed in, and a session never re-reads the hash.
    let revoked = state
        .db
        .revoke_all_sessions(current.user.id)
        .await
        .map_err(ApiError::from)?;
    let issued = state
        .db
        .create_session(
            current.user.id,
            Some(&client_ip(Some(&peer), &headers)),
            headers.get("user-agent").and_then(|v| v.to_str().ok()),
            DEFAULT_TTL,
            current.session.impersonator_id,
        )
        .await
        .map_err(ApiError::from)?;

    // This session was among the revoked and has just been replaced, so it is
    // not one of the devices that got signed out.
    let sessions_ended = revoked.saturating_sub(1);
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "auth.password_change",
        current.user.username.as_str(),
        json!({ "sessions_ended": sessions_ended }),
    )
    .await?;

    let secure = cookie_secure(state.config.panel.secure_cookies, &headers, Some(&peer));
    let jar = jar.add(session_cookie(issued.token, secure, DEFAULT_TTL));
    Ok((
        jar,
        Json(ChangePasswordResponse {
            sessions_ended,
            csrf_token: issued.csrf,
        }),
    ))
}

/// One audit row, written before the work rather than after it.
///
/// The same helper every route module keeps: an attempt that fails still has to
/// be in the trail, because "who tried to delete this account" is exactly the
/// question asked afterwards.
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

/// A reminder in the type system rather than in prose: if the budget constant
/// ever became zero, `acquire` above would wait forever and a password change
/// would hang instead of failing.
const _: () = assert!(PASSWORD_VERIFY_PERMITS > 0);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::connect_info::ConnectInfo;
    use std::sync::Arc;
    use unihelm_core::{Email, Role, TenantScope, UnihelmConfig, Username};
    use unihelm_db::Db;
    use unihelm_db::users::NewUser;

    const CURRENT: &str = "the-old-password";

    /// A panel with one admin, and a live session for them.
    async fn signed_in() -> (SharedState, CurrentUser, String) {
        let db = Db::open_memory().await.unwrap();
        let user = db
            .users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Admin,
                email: Email::parse("admin@example.com").unwrap(),
                username: Username::parse("admin").unwrap(),
                password: CURRENT.into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let issued = db
            .create_session(user.id, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();

        let state: SharedState =
            Arc::new(crate::state::AppState::new(db, UnihelmConfig::default()));
        let auth = unihelm_core::AuthContext::from_role(
            user.id,
            user.role,
            TenantScope::Global,
            "req-test",
        );
        let current = CurrentUser {
            user,
            session: issued.session,
            auth,
        };
        (state, current, issued.token)
    }

    fn peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:40000".parse().unwrap())
    }

    async fn change(
        state: &SharedState,
        current: &CurrentUser,
        currently: &str,
        new: &str,
    ) -> ApiResult<axum::response::Response> {
        // The handler consumes its extractors, so each call gets its own copy
        // of the caller. Cloning `CurrentUser` is not worth an impl for one
        // test module.
        let again = CurrentUser {
            user: current.user.clone(),
            session: current.session.clone(),
            auth: current.auth.clone(),
        };
        change_password(
            State(state.clone()),
            peer(),
            HeaderMap::new(),
            CookieJar::new(),
            again,
            Json(ChangePasswordRequest {
                current_password: currently.into(),
                new_password: new.into(),
            }),
        )
        .await
        .map(axum::response::IntoResponse::into_response)
    }

    #[tokio::test]
    async fn the_current_password_is_required_and_a_wrong_one_changes_nothing() {
        let (state, current, token) = signed_in().await;

        let err = change(&state, &current, "not-the-password", "a-brand-new-password")
            .await
            .expect_err("a wrong current password must be refused");
        assert_eq!(err.inner.code, ErrorCode::InvalidCredentials);

        let after = state
            .db
            .find_user_for_login("admin")
            .await
            .unwrap()
            .unwrap();
        assert!(
            password::verify_password(CURRENT, &after.pass_hash),
            "the stored password must be untouched"
        );
        assert!(
            state.db.lookup_session(&token).await.unwrap().is_some(),
            "a refused change must not sign anybody out"
        );
    }

    #[tokio::test]
    async fn a_change_stores_the_new_password_under_the_login_paths_own_hashing() {
        let (state, current, _) = signed_in().await;
        change(&state, &current, CURRENT, "a-brand-new-password")
            .await
            .expect("the change is accepted");

        let after = state
            .db
            .find_user_for_login("admin")
            .await
            .unwrap()
            .unwrap();
        assert!(password::verify_password(
            "a-brand-new-password",
            &after.pass_hash
        ));
        assert!(!password::verify_password(CURRENT, &after.pass_hash));
        // The same argon2id parameters `unihelm_db::password` verifies with. A
        // second configuration here would still log in, at a cost nobody chose.
        assert!(after.pass_hash.starts_with("$argon2id$"));
        assert!(after.pass_hash.contains("m=19456"), "{}", after.pass_hash);
    }

    #[tokio::test]
    async fn a_change_signs_out_every_other_device_and_replaces_this_session() {
        let (state, current, token) = signed_in().await;
        let elsewhere = state
            .db
            .create_session(current.user.id, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();

        change(&state, &current, CURRENT, "a-brand-new-password")
            .await
            .expect("the change is accepted");

        assert!(
            state
                .db
                .lookup_session(&elsewhere.token)
                .await
                .unwrap()
                .is_none(),
            "the whole point of changing a password is that the other session stops"
        );
        assert!(
            state.db.lookup_session(&token).await.unwrap().is_none(),
            "the session that proved the old password is rotated with it"
        );
        // One session is left: the replacement this response carried.
        assert_eq!(
            state.db.list_sessions(current.user.id).await.unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn a_password_that_fails_the_policy_is_refused_before_anything_changes() {
        let (state, current, token) = signed_in().await;
        let err = change(&state, &current, CURRENT, "short")
            .await
            .expect_err("the policy refuses it");
        assert_eq!(err.inner.code, ErrorCode::PasswordTooWeak);

        let after = state
            .db
            .find_user_for_login("admin")
            .await
            .unwrap()
            .unwrap();
        assert!(password::verify_password(CURRENT, &after.pass_hash));
        assert!(state.db.lookup_session(&token).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn setting_the_password_to_the_one_in_use_is_refused_rather_than_reported_as_done() {
        let (state, current, token) = signed_in().await;
        let err = change(&state, &current, CURRENT, CURRENT)
            .await
            .expect_err("a change that changes nothing is not a change");
        assert_eq!(err.inner.code, ErrorCode::InvalidInput);
        assert!(
            state.db.lookup_session(&token).await.unwrap().is_some(),
            "nobody should be signed out over a no-op"
        );
    }
}
