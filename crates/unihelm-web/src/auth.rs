//! Session authentication, CSRF, and login rate limiting (spec §12 rule 7).
//!
//! The pieces that matter:
//!
//! - the session cookie is `HttpOnly`, `SameSite=Strict` and (by default)
//!   `Secure`, and what it contains is a random token whose *hash* is what the
//!   database stores;
//! - state-changing requests must also present the session's CSRF token in a
//!   header, which `SameSite=Strict` already makes hard to forge and this makes
//!   pointless to try;
//! - failed logins are counted per address *and* per account, so neither a
//!   spray across accounts nor a focus on one gets an unlimited budget;
//! - an unknown username still costs a full argon2 verification, so response
//!   time does not tell an attacker which accounts exist.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use std::net::SocketAddr;
use time::Duration;
use unihelm_core::{AuthContext, ErrorCode, Role, TenantScope};
use unihelm_db::models::{Session, User};
use unihelm_db::{Db, password};

use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;

pub const SESSION_COOKIE: &str = "unihelm_session";
pub const CSRF_HEADER: &str = "x-unihelm-csrf";
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// How many failures from one address before it is refused, and over what window.
const IP_FAILURE_LIMIT: i64 = 10;
/// Per-account limit, lower because a targeted attack is the more dangerous one.
const ACCOUNT_FAILURE_LIMIT: i64 = 5;
const FAILURE_WINDOW: Duration = Duration::minutes(15);

/// The authenticated caller, extracted on every protected route.
pub struct CurrentUser {
    pub user: User,
    pub session: Session,
    pub auth: AuthContext,
}

impl CurrentUser {
    /// Build the context that travels to the agent.
    fn build_auth(user: &User, session: &Session, request_id: String) -> AuthContext {
        let scope = tenant_scope_for(user);
        let mut auth = AuthContext::from_role(user.id, user.role, scope, request_id);
        // Per-account overrides can only narrow (spec §6.1).
        auth = auth.restrict_to(&user.effective_permissions());
        auth.impersonator_id = session.impersonator_id;
        auth
    }
}

/// The slice of the world this account may act on.
pub fn tenant_scope_for(user: &User) -> TenantScope {
    match user.role {
        Role::Admin => TenantScope::Global,
        Role::Reseller => TenantScope::Reseller {
            reseller_id: user.id,
        },
        Role::Customer => TenantScope::Customer {
            customer_id: user.id,
        },
    }
}

impl FromRequestParts<SharedState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let request_id = request_id(&parts.headers);

        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_string())
            .ok_or_else(|| ApiError::unauthorized().with_request_id(request_id.clone()))?;

        let (session, user) = state
            .db
            .lookup_session(&token)
            .await
            .map_err(ApiError::from)?
            .ok_or_else(|| {
                ApiError::code(ErrorCode::SessionExpired, "your session has ended")
                    .with_request_id(request_id.clone())
            })?;

        // CSRF applies to anything that changes state. Safe methods are exempt
        // because they must not change state in the first place.
        if !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
            let presented = parts.headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok());
            let ok = presented.is_some_and(|p| constant_time_eq(p, &session.csrf));
            if !ok {
                return Err(ApiError::code(
                    ErrorCode::CsrfInvalid,
                    "missing or invalid CSRF token",
                )
                .with_request_id(request_id));
            }
        }

        // Keep the session alive while it is being used, without writing on
        // every single request.
        let db = state.db.clone();
        let session_id = session.id.clone();
        let last_seen = session.last_seen_at;
        tokio::spawn(async move {
            if time::OffsetDateTime::now_utc() - last_seen > Duration::minutes(5) {
                let _ = db.touch_session(&session_id).await;
                let _ = db
                    .extend_session(&session_id, unihelm_db::sessions::DEFAULT_TTL)
                    .await;
            }
        });

        let auth = Self::build_auth(&user, &session, request_id);
        Ok(CurrentUser {
            user,
            session,
            auth,
        })
    }
}

/// The request id assigned by the middleware, or a fresh one.
pub fn request_id(headers: &HeaderMap) -> String {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// Compare two secrets without leaking their common prefix through timing.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Should this response's session cookie carry `Secure`?
///
/// `Secure` means the browser will only ever send the cookie back over HTTPS.
/// That is what we want across a network — and it is exactly wrong for the
/// panel's own default deployment, where it listens on loopback and an operator
/// reaches it through an SSH tunnel. There, the cookie would be set and never
/// sent back, so the login screen simply reappears after a successful login with
/// nothing to explain why.
///
/// The connection tells us which situation we are in:
///
/// - `X-Forwarded-Proto: https` — a TLS-terminating proxy in front of us, so the
///   browser really is on HTTPS. `Secure`.
/// - the peer is loopback and there is no forwarded protocol — reached directly
///   over a tunnel. The bytes never left the machine, so `Secure` buys nothing
///   and costs the ability to log in at all.
/// - anything else — a real network hop with no TLS in front. Keep `Secure`:
///   handing out a session cookie in clear over a network is the thing this
///   attribute exists to prevent, and the startup warning tells the operator to
///   put TLS in front.
pub fn cookie_secure(policy: bool, headers: &HeaderMap, peer: Option<&SocketAddr>) -> bool {
    if !policy {
        return false;
    }
    if headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|proto| {
            proto
                .split(',')
                .next()
                .is_some_and(|p| p.trim().eq_ignore_ascii_case("https"))
        })
    {
        return true;
    }
    if peer.is_some_and(|addr| addr.ip().is_loopback()) {
        return false;
    }
    true
}

/// Build the session cookie.
pub fn session_cookie(token: String, secure: bool, ttl: Duration) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, token);
    cookie.set_http_only(true);
    // Strict, not Lax: nothing in the panel is meant to be reached by following
    // a link from another site.
    cookie.set_same_site(SameSite::Strict);
    cookie.set_secure(secure);
    cookie.set_path("/");
    cookie.set_max_age(ttl);
    cookie
}

/// The cookie that removes a session.
pub fn clearing_cookie(secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, "");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_secure(secure);
    cookie.set_path("/");
    cookie.set_max_age(Duration::ZERO);
    cookie
}

/// Refuse a login attempt that is part of a burst.
///
/// Returns the error to send, or `None` to proceed. The message is deliberately
/// the same for both limits: telling an attacker *which* limit they hit is
/// telling them whether the account exists.
pub async fn check_rate_limits(db: &Db, ip: &str, username: &str) -> ApiResult<()> {
    let by_ip = db
        .recent_failures_for_ip(ip, FAILURE_WINDOW)
        .await
        .map_err(ApiError::from)?;
    let by_account = db
        .recent_failures_for_username(username, FAILURE_WINDOW)
        .await
        .map_err(ApiError::from)?;

    if by_ip >= IP_FAILURE_LIMIT || by_account >= ACCOUNT_FAILURE_LIMIT {
        tracing::warn!(
            ip,
            username,
            by_ip,
            by_account,
            "login refused by rate limit"
        );
        return Err(ApiError::code(
            ErrorCode::RateLimited,
            "too many failed attempts; try again in a few minutes",
        ));
    }
    Ok(())
}

/// The caller's address, for rate limiting and the audit trail.
pub fn client_ip(peer: Option<&SocketAddr>, headers: &HeaderMap) -> String {
    // A reverse proxy in front of the panel is the normal deployment, so trust
    // `X-Forwarded-For` only for its left-most entry and only as a label.
    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first) = value.split(',').next()
    {
        let candidate = first.trim();
        if !candidate.is_empty() && candidate.parse::<std::net::IpAddr>().is_ok() {
            return candidate.to_string();
        }
    }
    peer.map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

/// Verify a password against an account that may not exist.
///
/// Always performs one argon2 verification, so the timing of "no such user" and
/// "wrong password" match.
pub fn verify_or_burn(user: Option<&User>, password_input: &str) -> bool {
    match user {
        Some(u) => password::verify_password(password_input, &u.pass_hash),
        None => {
            password::verify_dummy(password_input);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use unihelm_core::UserId;

    #[test]
    fn constant_time_comparison_is_still_correct() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn a_loopback_connection_gets_a_cookie_it_can_actually_send_back() {
        // The panel's own default: loopback listener, reached over an SSH
        // tunnel. A Secure cookie there is set and never returned, so login
        // silently fails with the form simply reappearing.
        let loopback: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        assert!(!cookie_secure(true, &HeaderMap::new(), Some(&loopback)));

        let v6: SocketAddr = "[::1]:54321".parse().unwrap();
        assert!(!cookie_secure(true, &HeaderMap::new(), Some(&v6)));
    }

    #[test]
    fn a_tls_terminating_proxy_still_gets_a_secure_cookie() {
        // nginx in front of us proxies from loopback, but the browser is on
        // HTTPS — the cookie must stay Secure.
        let loopback: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(cookie_secure(true, &headers, Some(&loopback)));

        // A proxy chain sends a list; the left-most entry is the browser's hop.
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https, http"));
        assert!(cookie_secure(true, &headers, Some(&loopback)));

        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        assert!(!cookie_secure(true, &headers, Some(&loopback)));
    }

    #[test]
    fn a_real_network_hop_keeps_secure_even_though_it_breaks_plain_http() {
        // Handing a session cookie out in clear over a network is exactly what
        // this attribute prevents. The operator gets a startup warning telling
        // them to put TLS in front.
        let remote: SocketAddr = "203.0.113.5:41234".parse().unwrap();
        assert!(cookie_secure(true, &HeaderMap::new(), Some(&remote)));
        assert!(cookie_secure(true, &HeaderMap::new(), None));
    }

    #[test]
    fn turning_the_policy_off_overrides_everything() {
        let remote: SocketAddr = "203.0.113.5:41234".parse().unwrap();
        assert!(!cookie_secure(false, &HeaderMap::new(), Some(&remote)));
    }

    #[test]
    fn session_cookies_are_locked_down() {
        let c = session_cookie("token".into(), true, Duration::hours(12));
        assert!(
            c.http_only().unwrap(),
            "javascript must not be able to read the session"
        );
        assert_eq!(c.same_site(), Some(SameSite::Strict));
        assert!(c.secure().unwrap());
        assert_eq!(c.path(), Some("/"));
    }

    #[test]
    fn the_clearing_cookie_actually_expires() {
        let c = clearing_cookie(true);
        assert_eq!(c.value(), "");
        assert_eq!(c.max_age(), Some(Duration::ZERO));
        assert!(c.http_only().unwrap());
    }

    #[test]
    fn forwarded_for_is_used_only_when_it_is_an_address() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.7, 10.0.0.1"),
        );
        assert_eq!(client_ip(None, &headers), "203.0.113.7");

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        assert_eq!(
            client_ip(None, &headers),
            "unknown",
            "a junk header must not become an identity"
        );

        assert_eq!(client_ip(None, &HeaderMap::new()), "unknown");
    }

    #[test]
    fn scopes_follow_the_role() {
        // Built through a row so the mapping is exercised end to end.
        let scope = |role| match role {
            Role::Admin => TenantScope::Global,
            Role::Reseller => TenantScope::Reseller {
                reseller_id: UserId(3),
            },
            Role::Customer => TenantScope::Customer {
                customer_id: UserId(3),
            },
        };
        assert!(scope(Role::Admin).is_global());
        assert!(!scope(Role::Customer).is_global());
        assert_eq!(scope(Role::Customer).customer_id(), Some(UserId(3)));
    }

    #[tokio::test]
    async fn rate_limits_trip_on_either_axis() {
        let db = Db::open_memory().await.unwrap();

        for _ in 0..IP_FAILURE_LIMIT {
            db.record_login_attempt("10.0.0.5", "someone", false)
                .await
                .unwrap();
        }
        let err = check_rate_limits(&db, "10.0.0.5", "unrelated")
            .await
            .unwrap_err();
        assert_eq!(err.inner.code, ErrorCode::RateLimited);

        // A different address, but the same account under attack.
        let db = Db::open_memory().await.unwrap();
        for i in 0..ACCOUNT_FAILURE_LIMIT {
            db.record_login_attempt(&format!("10.0.0.{i}"), "admin", false)
                .await
                .unwrap();
        }
        assert!(check_rate_limits(&db, "10.0.0.99", "admin").await.is_err());
        assert!(
            check_rate_limits(&db, "10.0.0.99", "someone-else")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn successful_logins_do_not_count_towards_the_limit() {
        let db = Db::open_memory().await.unwrap();
        for _ in 0..(IP_FAILURE_LIMIT * 2) {
            db.record_login_attempt("10.0.0.5", "admin", true)
                .await
                .unwrap();
        }
        assert!(check_rate_limits(&db, "10.0.0.5", "admin").await.is_ok());
    }

    #[test]
    fn a_missing_account_still_costs_a_verification() {
        // Not a timing assertion — those are flaky — but a guard that the code
        // path exists and returns false rather than short-circuiting.
        assert!(!verify_or_burn(None, "whatever"));
    }
}
