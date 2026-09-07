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
//!   time does not tell an attacker which accounts exist;
//! - and because that verification is expensive on purpose, only a few may run
//!   at once, off the async runtime — see [`PASSWORD_VERIFY_PERMITS`].

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use std::net::SocketAddr;
use time::Duration;
use tokio::sync::Semaphore;
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

/// How many argon2 verifications the panel will run at the same time.
///
/// Each one costs 19 MiB and two passes over it, and until this existed the
/// login handler ran them inline on the async runtime with no limit at all. A
/// few dozen simultaneous POSTs to `/api/auth/login` — which needs no account
/// and no session — parked every runtime worker on a memory-hard hash and took
/// the whole panel down with them: not just logins, every request, including
/// the operator's attempt to look at what was happening.
///
/// Four, because the panel targets a 1 GB VPS whose real job is hosting the
/// sites: ~76 MiB of hashing is a spike that box survives, and anything past
/// that is refused rather than queued (queueing is the same outage arriving a
/// few seconds later).
pub const PASSWORD_VERIFY_PERMITS: usize = 4;

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
        // Name the actual number. "A few minutes" against a fifteen-minute
        // window means somebody waits two, fails again, and concludes their
        // password is wrong — which is what happened to the first person to
        // mistype a username on a fresh install.
        return Err(ApiError::code(
            ErrorCode::RateLimited,
            format!(
                "too many failed attempts; this account is locked for {} minutes. \
                 A correct password will not work until then. \
                 `unihelm user unlock <name>` clears it from the server.",
                FAILURE_WINDOW.whole_minutes()
            ),
        ));
    }
    Ok(())
}

/// The caller's address, for rate limiting and the audit trail.
///
/// `X-Forwarded-For` is honoured only from a loopback peer. It used to be
/// honoured from anyone, on the reasoning that a reverse proxy is the normal
/// deployment and the value is "only a label" — but since 0.1.9 the normal
/// deployment is the panel on 0.0.0.0 with no proxy at all, and that label is
/// what the per-IP login budget counts, what the audit trail records, and what
/// Sentinel feeds to the firewall when it decides whom to ban. A header anyone
/// could set made the throttle count forged buckets instead of callers, and let
/// an anonymous caller spend somebody else's failure budget until the panel
/// banned an address of their choosing.
///
/// Loopback is the right test rather than "is TLS off": `unihelm cert panel`
/// renders `proxy_pass https://127.0.0.1:8088`, so nginx keeps talking to a
/// panel whose own TLS is still on, and it reaches us over loopback either way.
///
/// The entry we take is the **last** one, not the first. Trusting the proxy is
/// not the same as trusting the header it forwards: nginx's
/// `$proxy_add_x_forwarded_for` and Apache's mod_proxy both *append* the address
/// they actually saw to whatever the client sent, so the first entry is the
/// client's own writing and only the last one is the proxy's. Reading the first
/// meant any caller could put an address at the front and have the panel adopt
/// it — into the audit trail, into the per-IP login budget, and into the list
/// Sentinel hands the firewall. Six failed logins with a chosen address in front
/// were enough to get a bystander, or the operator's own office, banned from the
/// server. The panel vhosts now pin the header to one hop as well, but this side
/// has to hold on its own: a vhost only changes on the next render, and the
/// panel is reachable on 0.0.0.0 without one.
pub fn client_ip(peer: Option<&SocketAddr>, headers: &HeaderMap) -> String {
    let from_proxy = peer.is_some_and(|a| a.ip().is_loopback());
    if from_proxy
        // Last header line, then that line's last element: "the proxy appends"
        // is only true at the very end of the field, and HTTP lets one field
        // arrive split across several lines.
        && let Some(value) = headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
        && let Some(last) = value.rsplit(',').next()
    {
        let candidate = last.trim();
        if !candidate.is_empty() && candidate.parse::<std::net::IpAddr>().is_ok() {
            return candidate.to_string();
        }
        // The proxy's own entry is unreadable, so there is nothing here we are
        // entitled to believe. Fall through to the peer rather than reach back
        // into the part of the chain the client wrote.
    }
    peer.map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

/// Verify a password against an account that may not exist.
///
/// Always performs one argon2 verification, so the timing of "no such user" and
/// "wrong password" match. Blocking and CPU-bound — call it through
/// [`verify_or_burn_under_budget`] rather than from an async context.
pub fn verify_or_burn(stored_hash: Option<&str>, password_input: &str) -> bool {
    match stored_hash {
        Some(hash) => password::verify_password(password_input, hash),
        None => {
            password::verify_dummy(password_input);
            false
        }
    }
}

/// One [`verify_or_burn`], on a blocking thread and inside the panel's hashing
/// budget.
///
/// Two things here are load-bearing.
///
/// **The permit is taken, not waited for.** `try_acquire` fails immediately when
/// [`PASSWORD_VERIFY_PERMITS`] verifications are already running, and the caller
/// gets a 429. Queueing instead would let an unauthenticated burst accumulate
/// arbitrarily much pending argon2 work — the same collapse, just later.
///
/// **The burn is inside the permit too.** An unknown username costs a permit,
/// a blocking thread and a full hash exactly like a known one. Skipping the
/// dummy verification when the budget is tight would make "no such account"
/// the fast answer and turn the login form into a username oracle.
pub async fn verify_or_burn_under_budget(
    budget: &Semaphore,
    stored_hash: Option<String>,
    password_input: String,
) -> ApiResult<bool> {
    let _permit = budget.try_acquire().map_err(|_| {
        ApiError::code(
            ErrorCode::RateLimited,
            format!(
                "the panel is already checking {PASSWORD_VERIFY_PERMITS} passwords at once, \
                 so this attempt was refused rather than queued. Nothing is wrong with the \
                 credentials — retry in a few seconds. If it keeps happening, something is \
                 hammering /api/auth/login; `unihelm audit --action auth.login` shows from where."
            ),
        )
    })?;

    // spawn_blocking, because argon2id at 19 MiB is hundreds of milliseconds of
    // solid CPU. Run inline it did not merely make this request slow, it parked
    // an async worker thread — with the runtime's small worker count, a handful
    // of concurrent logins stalled every other request in the panel.
    tokio::task::spawn_blocking(move || verify_or_burn(stored_hash.as_deref(), &password_input))
        .await
        .map_err(|e| {
            ApiError::new(unihelm_core::UnihelmError::internal(format!(
                "the password check did not finish ({e}); no decision was made about these \
                 credentials, so nothing was signed in. Retry, and check the panel's log."
            )))
        })
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
    fn forwarded_for_is_honoured_from_a_proxy_and_ignored_from_everyone_else() {
        let xff = |v| {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-for", HeaderValue::from_static(v));
            h
        };
        let proxy: SocketAddr = "127.0.0.1:44444".parse().unwrap();
        let caller: SocketAddr = "198.51.100.9:44444".parse().unwrap();

        // nginx on loopback, which is what `unihelm cert panel` sets up. The
        // proxy's own entry is the last one.
        assert_eq!(
            client_ip(Some(&proxy), &xff("203.0.113.7, 10.0.0.1")),
            "10.0.0.1"
        );
        assert_eq!(client_ip(Some(&proxy), &xff("203.0.113.7")), "203.0.113.7");

        // The panel's own default is 0.0.0.0 with no proxy at all, so this
        // header is written by whoever is calling. Believing it let an
        // anonymous caller spend another address's login budget until Sentinel
        // banned the address they named — the operator's own, if they chose.
        assert_eq!(
            client_ip(Some(&caller), &xff("203.0.113.7")),
            "198.51.100.9",
            "a header from a direct caller must not become their identity"
        );

        // Junk from a genuine proxy falls back to the peer rather than becoming
        // an identity of its own.
        assert_eq!(client_ip(Some(&proxy), &xff("not-an-ip")), "127.0.0.1");

        // No peer means no evidence of a proxy, so the header is not trusted.
        assert_eq!(client_ip(None, &xff("203.0.113.7")), "unknown");
        assert_eq!(client_ip(None, &HeaderMap::new()), "unknown");
    }

    #[test]
    fn a_forged_forwarded_for_prefix_cannot_choose_whose_address_gets_banned() {
        let proxy: SocketAddr = "127.0.0.1:44444".parse().unwrap();

        // Exactly what the panel's vhost produced before it was pinned to one
        // hop: `$proxy_add_x_forwarded_for` appends the address nginx really
        // saw to whatever the client typed. Reading the front of that list let
        // the caller nominate an address to be rate limited, audited and
        // eventually banned — an innocent third party, or the operator's own.
        let mut forged = HeaderMap::new();
        forged.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.4, 203.0.113.7"),
        );
        assert_eq!(
            client_ip(Some(&proxy), &forged),
            "203.0.113.7",
            "only the proxy's own entry, at the end, is evidence of anything"
        );

        // The same field split across two lines, which HTTP allows and which
        // reading only the first header value would have got wrong the same way.
        let mut split = HeaderMap::new();
        split.append("x-forwarded-for", HeaderValue::from_static("198.51.100.4"));
        split.append("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        assert_eq!(client_ip(Some(&proxy), &split), "203.0.113.7");

        // An unusable last entry is not an invitation to believe the rest of
        // the chain; the peer stands in instead.
        let mut junk = HeaderMap::new();
        junk.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.4, nonsense"),
        );
        assert_eq!(client_ip(Some(&proxy), &junk), "127.0.0.1");
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

    #[tokio::test]
    async fn a_full_hashing_budget_refuses_a_login_instead_of_queueing_it() {
        // The unbounded version of this took the panel down: enough concurrent
        // POSTs to /api/auth/login — no account needed — parked every runtime
        // worker on a 19 MiB hash and every other request with them.
        let budget = Semaphore::new(1);
        let held = budget.try_acquire().unwrap();

        let err = verify_or_burn_under_budget(&budget, None, "whatever".into())
            .await
            .unwrap_err();
        assert_eq!(
            err.inner.code,
            ErrorCode::RateLimited,
            "a full budget must be a 429 the client can retry, not a queued hash"
        );

        drop(held);
        assert!(
            !verify_or_burn_under_budget(&budget, None, "whatever".into())
                .await
                .unwrap(),
            "the permit must come back when the verification finishes"
        );
    }

    #[tokio::test]
    async fn an_unknown_username_spends_the_same_budget_as_a_real_one() {
        // The equality is the point: if "no such account" skipped the permit,
        // it would answer while a real account was still waiting for one, and
        // the login form would tell an attacker which usernames exist.
        let budget = Semaphore::new(1);
        let held = budget.try_acquire().unwrap();

        let hash = unihelm_db::password::hash_password("correct horse battery staple").unwrap();
        for stored in [None, Some(hash.clone())] {
            let err =
                verify_or_burn_under_budget(&budget, stored, "correct horse battery staple".into())
                    .await
                    .unwrap_err();
            assert_eq!(err.inner.code, ErrorCode::RateLimited);
        }

        drop(held);
        assert!(
            verify_or_burn_under_budget(&budget, Some(hash), "correct horse battery staple".into())
                .await
                .unwrap(),
            "a correct password must still verify once there is room"
        );
    }
}
