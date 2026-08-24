//! Login, logout, and "who am I".

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum_extra::extract::cookie::CookieJar;
use ferrum_core::{ErrorCode, Permission};
use ferrum_db::audit::NewAuditEntry;
use ferrum_db::sessions::DEFAULT_TTL;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::auth::{
    CurrentUser, check_rate_limits, clearing_cookie, client_ip, cookie_secure, request_id,
    session_cookie, verify_or_burn,
};
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    // TODO(scope): a `totp_code` field joins this struct with the 2FA work.
    // Adding it before anything can verify it would be a field that silently
    // does nothing.
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user: UserView,
    /// The token that must accompany every state-changing request.
    pub csrf_token: String,
}

/// The public shape of an account.
///
/// A separate struct from [`ferrum_db::models::User`] on purpose: the model
/// carries `pass_hash` and `totp_secret`, and the way to guarantee those never
/// reach a response is for the response type not to have them (spec §12 rule 6).
#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub role: &'static str,
    pub full_name: Option<String>,
    pub locale: String,
    pub permissions: Vec<&'static str>,
    pub is_impersonated: bool,
}

impl UserView {
    fn from(user: &ferrum_db::models::User, impersonated: bool) -> Self {
        Self {
            id: user.id.get(),
            username: user.username.as_str().to_string(),
            email: user.email.as_str().to_string(),
            role: user.role.as_str(),
            full_name: user.full_name.clone(),
            locale: user.locale.clone(),
            permissions: user
                .effective_permissions()
                .into_iter()
                .map(Permission::as_str)
                .collect(),
            is_impersonated: impersonated,
        }
    }
}

pub async fn login(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> ApiResult<impl IntoResponse> {
    let request_id = request_id(&headers);
    let ip = client_ip(Some(&peer), &headers);
    let username = body.username.trim().to_ascii_lowercase();

    check_rate_limits(&state.db, &ip, &username).await?;

    let user = state
        .db
        .find_user_for_login(&username)
        .await
        .map_err(ApiError::from)?;
    let password_ok = verify_or_burn(user.as_ref(), &body.password);

    let Some(user) = user.filter(|_| password_ok) else {
        state
            .db
            .record_login_attempt(&ip, &username, false)
            .await
            .map_err(ApiError::from)?;
        // One message for "no such account" and "wrong password": the difference
        // is not the client's business.
        return Err(ApiError::code(
            ErrorCode::InvalidCredentials,
            "incorrect username or password",
        )
        .with_request_id(request_id));
    };

    if !user.status.can_log_in() {
        state
            .db
            .record_login_attempt(&ip, &username, false)
            .await
            .map_err(ApiError::from)?;
        return Err(
            ApiError::code(ErrorCode::AccountSuspended, "this account is not active")
                .with_request_id(request_id),
        );
    }

    if user.totp_enabled {
        // TODO(scope): TOTP verification lands with the 2FA work. Nothing in the
        // panel can set this flag yet, and refusing is the safe direction if it
        // is somehow set — never "log them in anyway".
        state
            .db
            .record_login_attempt(&ip, &username, false)
            .await
            .map_err(ApiError::from)?;
        return Err(ApiError::code(
            ErrorCode::NotImplemented,
            "this account requires two-factor authentication, which this build cannot verify",
        )
        .with_request_id(request_id));
    }

    let issued = state
        .db
        .create_session(
            user.id,
            Some(&ip),
            headers.get("user-agent").and_then(|v| v.to_str().ok()),
            DEFAULT_TTL,
            None,
        )
        .await
        .map_err(ApiError::from)?;

    state
        .db
        .record_login_attempt(&ip, &username, true)
        .await
        .map_err(ApiError::from)?;
    let _ = state
        .db
        .users(&crate::auth::tenant_scope_for(&user))
        .record_login(user.id)
        .await;

    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(user.id),
            actor_username: user.username.as_str().to_string(),
            impersonator_id: None,
            ip: Some(ip),
            action: "auth.login".into(),
            target: None,
            detail: serde_json::json!({ "user_agent": headers.get("user-agent").and_then(|v| v.to_str().ok()) }),
            request_id: Some(request_id),
            subscription_id: None,
        })
        .await
        .map_err(ApiError::from)?;

    let secure = cookie_secure(state.config.panel.secure_cookies, &headers, Some(&peer));
    let jar = jar.add(session_cookie(issued.token, secure, DEFAULT_TTL));
    Ok((
        jar,
        Json(LoginResponse {
            user: UserView::from(&user, false),
            csrf_token: issued.csrf,
        }),
    ))
}

pub async fn logout(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    current: CurrentUser,
) -> ApiResult<impl IntoResponse> {
    state
        .db
        .revoke_session(&current.session.id)
        .await
        .map_err(ApiError::from)?;

    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: "auth.logout".into(),
            target: None,
            detail: serde_json::json!({}),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: None,
        })
        .await
        .map_err(ApiError::from)?;

    let secure = cookie_secure(state.config.panel.secure_cookies, &headers, Some(&peer));
    let jar = jar.add(clearing_cookie(secure));
    Ok((jar, Json(serde_json::json!({ "ok": true }))))
}

/// The current session's account, used by the UI on every page load.
pub async fn me(current: CurrentUser) -> Json<LoginResponse> {
    Json(LoginResponse {
        user: UserView::from(&current.user, current.session.impersonator_id.is_some()),
        // Returned again so a reloaded tab can restore its CSRF token without a
        // second round trip.
        csrf_token: current.session.csrf.clone(),
    })
}
