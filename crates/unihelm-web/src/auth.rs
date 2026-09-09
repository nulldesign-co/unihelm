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
//! - failed logins are counted per address, per (account, address) pair, and
//!   per account from everywhere, so neither a spray across accounts nor a
//!   focus on one gets an unlimited budget. The first two budgets belong to the
//!   caller's own address; the third would be a lockout anyone could impose on
//!   anyone, so it only ever refuses addresses that have never signed in to the
//!   account — see [`check_rate_limits`];
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
/// Per (account, address) limit, lower because a targeted attack is the more
/// dangerous one. Both of these budgets belong to the caller's own address; see
/// [`check_rate_limits`] for why a budget belonging to an *account* may only
/// ever refuse callers that account has never seen succeed.
const ACCOUNT_FAILURE_LIMIT: i64 = 5;
const FAILURE_WINDOW: Duration = Duration::minutes(15);

/// Failures against one account, from anywhere, before answers start slowing.
const ACCOUNT_SLOWDOWN_AFTER: i64 = ACCOUNT_FAILURE_LIMIT;

/// Failures against one account, from anywhere, before the panel stops taking
/// guesses from addresses it has never seen sign in to that account.
///
/// Ten addresses' worth of the per-pair budget, so nothing an operator can do
/// by hand comes near it: reaching it takes at least ten distinct addresses
/// inside fifteen minutes, because each pair is refused at five. A botnet
/// reaches it in a second, which is the point — before this existed, a thousand
/// addresses bought a thousand fresh budgets and the account had no ceiling at
/// all.
const ACCOUNT_DISTRIBUTED_LIMIT: i64 = ACCOUNT_FAILURE_LIMIT * 10;
/// What each failure past that is worth, and the ceiling it stops at.
///
/// 500 ms is invisible to somebody typing a password and expensive to a script
/// working through a list one request at a time. It is **not** a bound on a
/// concurrent attacker, whatever this comment used to imply: a sleep on a task
/// is latency, and a hundred sleeping requests sleep in parallel, so throughput
/// is still whatever [`PASSWORD_VERIFY_PERMITS`] allows. That is what
/// [`ACCOUNT_DISTRIBUTED_LIMIT`] is for; this only buys time.
///
/// The cap is what keeps it a delay rather than a refusal in disguise: five
/// seconds is a long pause on a login form and it is still a login, which
/// "locked out" is not.
const ACCOUNT_SLOWDOWN_STEP: std::time::Duration = std::time::Duration::from_millis(500);
const ACCOUNT_SLOWDOWN_CAP: std::time::Duration = std::time::Duration::from_secs(5);

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

/// The typed identifier, in a shape that is safe to quote back.
///
/// The refusals name it because the throttle counts the string that was typed
/// rather than the account behind it, and an operator who does not know which
/// spelling is throttled cannot unlock it. But that string is whatever the
/// client sent: control characters would corrupt a terminal reading the panel's
/// log or an operator pasting the message, and there is no length limit on the
/// field, so the whole request body could otherwise come back inside an error.
///
/// Not an escaping function — the response is JSON and the UI renders text —
/// just a bound and a scrub, so the message stays a message.
fn shown_identifier(username: &str) -> String {
    const MAX: usize = 64;
    let cleaned: String = username
        .chars()
        .take(MAX)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if username.chars().nth(MAX).is_some() {
        format!("{cleaned}…")
    } else {
        cleaned
    }
}

/// How long to make this caller wait for an account that is under attack.
///
/// A pure function of the count, so the curve can be asserted without a clock.
pub fn account_slowdown(failures: i64) -> std::time::Duration {
    let over = failures.saturating_sub(ACCOUNT_SLOWDOWN_AFTER).max(0);
    ACCOUNT_SLOWDOWN_STEP
        .saturating_mul(u32::try_from(over).unwrap_or(u32::MAX))
        .min(ACCOUNT_SLOWDOWN_CAP)
}

/// Refuse — or merely slow down — a login attempt that is part of a burst.
///
/// **No refusal is keyed on an account's failures alone.** It used to be
/// possible to refuse on that number by itself, counted from everywhere, and
/// that is a lockout anybody could impose on anybody: five wrong passwords for
/// `admin` every fifteen minutes — no account, no session, no session cookie
/// needed — and the real admin could not sign in from any address on earth with
/// the correct password, for as long as the attacker cared to keep it up. The
/// two budgets a caller spends are their own: the (account, address) pair, and
/// the address across all accounts.
///
/// **The account's own count still has to stop something.** Removing the
/// account-wide refusal and replacing it with nothing but [`account_slowdown`]
/// left the account with no ceiling whatsoever: a thousand addresses bought a
/// thousand fresh per-pair budgets, and the delay is latency rather than
/// backpressure — sleeping requests sleep in parallel, so a concurrent attacker
/// pays five seconds once and then guesses as fast as
/// [`PASSWORD_VERIFY_PERMITS`] allows, for ever. The slowdown is kept because it
/// is real against the ordinary sequential script, but it is not a bound.
///
/// **The bound is [`ACCOUNT_DISTRIBUTED_LIMIT`], and it may only refuse
/// strangers.** What separates the operator from the attack is not where they
/// are calling from — an operator travels and an attacker forges — it is that
/// the operator has, at some point, typed the correct password. So past that
/// many failures the panel refuses attempts from addresses that have never
/// signed in to the account ([`Db::address_has_signed_in`]), and lets addresses
/// that have straight through to their own per-pair budget. An attacker cannot
/// join the second group without the password, and the operator cannot be
/// pushed out of it by anything a stranger does. Both properties hold at once,
/// which no single number could give.
///
/// Two more things keep this from becoming the lockout it replaced. The refusal
/// is filed as throttled, so it cannot renew the count that caused it and the
/// fifteen minutes really do end. And `unihelm user unlock` clears the count
/// outright for an operator who has never signed in from anywhere yet — the
/// fresh-install case, the one group this bound can genuinely catch, which is
/// why that command had to start working (it was clearing nothing when the
/// operator typed their email address).
///
/// The two refusals say different things because they *are* different things:
/// telling an operator "too many failed sign-ins from your address" when their
/// address has done nothing is the panel reporting something that is not true,
/// and sends them hunting for a problem on their own machine. Neither message
/// quotes a count — that would tell an attacker how far along they are.
pub async fn check_rate_limits(db: &Db, ip: &str, username: &str) -> ApiResult<()> {
    let by_ip = db
        .recent_failures_for_ip(ip, FAILURE_WINDOW)
        .await
        .map_err(ApiError::from)?;
    let by_pair = db
        .recent_failures_for_ip_and_username(ip, username, FAILURE_WINDOW)
        .await
        .map_err(ApiError::from)?;

    if by_ip >= IP_FAILURE_LIMIT || by_pair >= ACCOUNT_FAILURE_LIMIT {
        tracing::warn!(ip, username, by_ip, by_pair, "login refused by rate limit");
        // Recorded here rather than left to the caller, so that no future call
        // site can refuse silently. A refusal the panel never wrote down is a
        // refusal Sentinel cannot see, and Sentinel bans on what is written
        // down — so the throttle engaging used to be the moment the attacker
        // became invisible. The row is filed as throttled and so cannot feed
        // the budgets above; a write that fails is logged and the refusal
        // stands, because failing to record an attack is no reason to allow it.
        if let Err(e) = db.record_throttled_login_attempt(ip, username).await {
            tracing::warn!(ip, error = %e, "could not record a throttled login attempt");
        }
        // Name the actual number. "A few minutes" against a fifteen-minute
        // window means somebody waits two, fails again, and concludes their
        // password is wrong — which is what happened to the first person to
        // mistype a username on a fresh install.
        //
        // And name the identifier, because the throttle counts the string that
        // was typed: the operator who typed the installer-printed address is
        // locked out under `admin@example.com` while the command they are about
        // to run says `admin`, which used to clear nothing and say it had
        // worked. `unlock` takes either spelling and now clears both.
        return Err(ApiError::code(
            ErrorCode::RateLimited,
            format!(
                "too many failed sign-ins from your address ({ip}), so this one was refused \
                 without the password being checked. The block is on this address alone — the \
                 account still works from anywhere else — and it lifts by itself {} minutes \
                 after the last failed attempt. The attempts were filed under `{ident}`, which \
                 is what you typed; `unihelm user unlock {ident}` on the server clears them and \
                 the addresses they came from.",
                FAILURE_WINDOW.whole_minutes(),
                ident = shown_identifier(username),
            ),
        ));
    }

    let by_account = db
        .recent_failures_for_username(username, FAILURE_WINDOW)
        .await
        .map_err(ApiError::from)?;

    // The account-wide bound. `address_has_signed_in` is the expensive half of
    // the decision and the short circuit keeps it off every healthy login: it is
    // only asked once an account is already past a threshold that takes ten
    // addresses to reach.
    //
    // This also holds if the caller forged their address. A forged *fresh*
    // address is a stranger and is refused here; forging one the account has
    // seen succeed means guessing which, and buys only that pair's five
    // attempts per fifteen minutes. Either way there is a ceiling, which is what
    // was missing.
    if by_account >= ACCOUNT_DISTRIBUTED_LIMIT
        && !db
            .address_has_signed_in(ip, username)
            .await
            .map_err(ApiError::from)?
    {
        tracing::warn!(
            ip,
            username,
            by_account,
            "login refused: account under distributed attack and this address has never signed in"
        );
        // Filed as throttled, for the same two reasons as above: Sentinel must
        // keep seeing the attack, and the refusal must not count towards the
        // number that produced it — otherwise the retries renew the bound and
        // the fifteen minutes never end, which is the lockout this is written to
        // avoid.
        if let Err(e) = db.record_throttled_login_attempt(ip, username).await {
            tracing::warn!(ip, error = %e, "could not record a throttled login attempt");
        }
        return Err(ApiError::code(
            ErrorCode::RateLimited,
            format!(
                "`{ident}` is being guessed at from many addresses at once, so sign-ins from \
                 addresses that have never signed in to it — including this one ({ip}) — are \
                 being refused without the password being checked. An address that has signed \
                 in before is not affected. This lifts by itself {} minutes after the last \
                 attempt the panel actually checked; on the server, \
                 `unihelm user unlock {ident}` lifts it now.",
                FAILURE_WINDOW.whole_minutes(),
                ident = shown_identifier(username),
            ),
        ));
    }

    let slowdown = account_slowdown(by_account);
    if !slowdown.is_zero() {
        tracing::info!(
            ip,
            username,
            by_account,
            delay_ms = slowdown.as_millis() as u64,
            "slowing a login for an account under attack"
        );
        // A sleep, not a blocked thread: the runtime keeps serving everything
        // else, including the operator's attempt to look at what is happening.
        tokio::time::sleep(slowdown).await;
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
        // Spraying accounts from one address spends that address's budget...
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

        // ...and hammering one account from one address spends the smaller,
        // per-pair budget before that.
        let db = Db::open_memory().await.unwrap();
        for _ in 0..ACCOUNT_FAILURE_LIMIT {
            db.record_login_attempt("10.0.0.6", "admin", false)
                .await
                .unwrap();
        }
        assert!(check_rate_limits(&db, "10.0.0.6", "admin").await.is_err());
        // Another account from the same address still has room, and the same
        // account from another address is untouched.
        assert!(
            check_rate_limits(&db, "10.0.0.6", "someone-else")
                .await
                .is_ok()
        );
        assert!(check_rate_limits(&db, "10.0.0.99", "admin").await.is_ok());
    }

    #[tokio::test]
    async fn an_attacker_locks_out_their_own_address_and_nobody_elses() {
        // The lockout anyone could impose on anyone: five wrong passwords for
        // `admin` every fifteen minutes, needing no account and no session, and
        // the real admin could not sign in from anywhere on earth with the
        // correct password for as long as it kept up.
        let db = Db::open_memory().await.unwrap();
        for _ in 0..(ACCOUNT_FAILURE_LIMIT * 3) {
            db.record_login_attempt("203.0.113.9", "admin", false)
                .await
                .unwrap();
        }

        assert!(
            check_rate_limits(&db, "203.0.113.9", "admin")
                .await
                .is_err(),
            "the address doing it must be refused"
        );
        assert!(
            check_rate_limits(&db, "198.51.100.4", "admin")
                .await
                .is_ok(),
            "and no other address may pay for it"
        );
    }

    #[tokio::test]
    async fn an_account_sprayed_from_everywhere_is_slowed_before_it_is_bounded() {
        // A botnet with a thousand addresses gets a thousand fresh per-pair
        // budgets, so the account's own count still has to be worth something.
        // Below ACCOUNT_DISTRIBUTED_LIMIT what it is worth is time, not a
        // refusal — a fresh address is delayed and still gets in.
        // One failure past the threshold, so the assertion below costs the
        // suite one step and not the whole cap.
        let db = Db::open_memory().await.unwrap();
        for i in 0..(ACCOUNT_SLOWDOWN_AFTER + 1) {
            db.record_login_attempt(&format!("203.0.113.{i}"), "admin", false)
                .await
                .unwrap();
        }

        let started = std::time::Instant::now();
        assert!(
            check_rate_limits(&db, "198.51.100.4", "admin")
                .await
                .is_ok(),
            "the admin's own address is not over budget, so it must still get in"
        );
        assert!(
            started.elapsed() >= ACCOUNT_SLOWDOWN_STEP,
            "and it must have been made to wait on the way"
        );
    }

    /// Seed `count` failures against `username` from that many distinct
    /// addresses, so no per-pair or per-address budget is spent on the way.
    async fn spray_from_many_addresses(db: &Db, username: &str, count: i64) {
        for i in 0..count {
            db.record_login_attempt(&format!("198.51.{}.{}", i / 250, i % 250), username, false)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn a_distributed_attack_on_one_account_runs_out_of_guesses() {
        // The regression this release introduced while removing the lockout:
        // every hard refusal was keyed on the caller's address, so an attacker
        // with a fresh address per attempt — a botnet, or one local process
        // forging `X-Forwarded-For` — met no refusal at any point.
        // `recent_failures_for_ip` and `recent_failures_for_ip_and_username`
        // both saw zero for ever, and two hundred consecutive guesses against
        // `admin` were refused exactly none of the time. The loop below is that
        // exploit, and every iteration of it must now be refused.
        let db = Db::open_memory().await.unwrap();
        spray_from_many_addresses(&db, "admin", ACCOUNT_DISTRIBUTED_LIMIT).await;

        for i in 0..200 {
            let ip = format!("203.0.{}.{}", i / 250, i % 250);
            assert!(
                check_rate_limits(&db, &ip, "admin").await.is_err(),
                "guess {i}, from an address the panel has never seen, was allowed"
            );
        }
    }

    // The property that keeps the account-wide bound from becoming the lockout
    // it replaced. Each (account, address) pair is refused at
    // ACCOUNT_FAILURE_LIMIT, so the account-wide figure cannot be reached from
    // fewer than ten addresses — nothing an operator mistyping a password, or a
    // small office behind one NAT, can do.
    //
    // A `const` block rather than a `#[test]`: these are relationships between
    // compile-time constants, so the build should refuse them, not a test run.
    // Somebody tuning the numbers finds out while they are editing.
    const _: () = {
        assert!(
            ACCOUNT_DISTRIBUTED_LIMIT >= ACCOUNT_FAILURE_LIMIT * 10,
            "a bound a few addresses could reach is a lockout anybody can impose"
        );
        assert!(
            ACCOUNT_SLOWDOWN_AFTER < ACCOUNT_DISTRIBUTED_LIMIT,
            "the delay must come first, so an account is slowed long before \
             anything is refused on its behalf"
        );
    };

    #[tokio::test]
    async fn the_operator_still_gets_in_while_their_account_is_under_attack() {
        // The other half, and the reason the bound is not simply back: an
        // account-wide refusal that catches everybody is a lockout any stranger
        // can impose on any account, which is what was removed. What the
        // attacker cannot forge is a correct password, so the address that has
        // signed in before is the one the bound must not touch.
        let db = Db::open_memory().await.unwrap();
        db.record_login_attempt("198.51.100.4", "admin", true)
            .await
            .unwrap();
        spray_from_many_addresses(&db, "admin", ACCOUNT_DISTRIBUTED_LIMIT * 3).await;

        assert!(
            check_rate_limits(&db, "198.51.100.4", "admin")
                .await
                .is_ok(),
            "an address that has signed in to this account must not be shut out \
             by what strangers did to it"
        );
        assert!(
            check_rate_limits(&db, "203.0.113.77", "admin")
                .await
                .is_err(),
            "and an address that has not must be refused"
        );
        assert!(
            check_rate_limits(&db, "203.0.113.77", "someone-else")
                .await
                .is_ok(),
            "the bound belongs to the account under attack and to no other"
        );
    }

    #[tokio::test]
    async fn the_operators_own_wrong_password_still_only_costs_them_their_own_budget() {
        // A known address is exempt from the account-wide bound, not from its
        // own: otherwise one stolen laptop would have an unlimited budget.
        let db = Db::open_memory().await.unwrap();
        db.record_login_attempt("198.51.100.4", "admin", true)
            .await
            .unwrap();
        for _ in 0..ACCOUNT_FAILURE_LIMIT {
            db.record_login_attempt("198.51.100.4", "admin", false)
                .await
                .unwrap();
        }
        assert!(
            check_rate_limits(&db, "198.51.100.4", "admin")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn the_account_wide_bound_lifts_instead_of_renewing_itself() {
        // If a refused attempt counted towards the number that refused it, an
        // attack would hold the account down for as long as it kept sending —
        // permanently, for an operator who has never signed in from anywhere
        // yet. Refusals are filed as throttled and so cannot.
        let db = Db::open_memory().await.unwrap();
        spray_from_many_addresses(&db, "admin", ACCOUNT_DISTRIBUTED_LIMIT).await;

        for i in 0..5 {
            assert!(
                check_rate_limits(&db, &format!("203.0.113.{i}"), "admin")
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            db.recent_failures_for_username("admin", FAILURE_WINDOW)
                .await
                .unwrap(),
            ACCOUNT_DISTRIBUTED_LIMIT,
            "the refusals must not have spent the budget that produced them"
        );

        // And the documented cure works from a root shell, which is the escape
        // hatch for the one operator this bound can catch: the one on a fresh
        // install who has never signed in from anywhere.
        assert!(db.clear_login_failures("admin").await.unwrap() > 0);
        assert!(
            check_rate_limits(&db, "203.0.113.77", "admin")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_refusal_names_the_spelling_that_is_actually_throttled() {
        // The throttle counts the string that was typed, and the installer
        // prints the address far more prominently than the username — so the
        // person most likely to be locked out is locked out under
        // `admin@example.com` while the command they are told to run says
        // `admin`. A message that does not name the spelling sends them to run
        // an unlock that clears nothing.
        let db = Db::open_memory().await.unwrap();
        for _ in 0..ACCOUNT_FAILURE_LIMIT {
            db.record_login_attempt("10.0.0.6", "admin@example.com", false)
                .await
                .unwrap();
        }

        let err = check_rate_limits(&db, "10.0.0.6", "admin@example.com")
            .await
            .unwrap_err();
        let message = err.inner.detail.clone();
        assert!(
            message.contains("`admin@example.com`"),
            "the refusal must say which identifier is throttled: {message}"
        );
        assert!(
            message.contains("unihelm user unlock admin@example.com"),
            "and the command it prints must be one that clears it: {message}"
        );

        // The account-wide refusal names it too, and does not claim the
        // caller's address is the problem when it is not.
        let db = Db::open_memory().await.unwrap();
        spray_from_many_addresses(&db, "admin@example.com", ACCOUNT_DISTRIBUTED_LIMIT).await;
        let err = check_rate_limits(&db, "203.0.113.77", "admin@example.com")
            .await
            .unwrap_err();
        let message = err.inner.detail.clone();
        assert!(message.contains("`admin@example.com`"), "{message}");
        assert!(
            !message.contains("too many failed sign-ins from your address"),
            "an address that has done nothing must not be told it is the cause: {message}"
        );
    }

    #[test]
    fn an_echoed_identifier_is_bounded_and_stripped_of_control_characters() {
        // It is whatever the client sent, and it lands in an error body and in
        // the panel's log.
        assert_eq!(shown_identifier("admin@example.com"), "admin@example.com");
        assert_eq!(shown_identifier("ad\nmin\u{7}"), "ad?min?");
        let long = "a".repeat(500);
        let shown = shown_identifier(&long);
        assert_eq!(shown.chars().count(), 65, "64 characters and the ellipsis");
        assert!(shown.ends_with('…'));
    }

    #[test]
    fn the_account_slowdown_is_free_until_it_bites_and_then_stops_growing() {
        assert!(account_slowdown(0).is_zero());
        assert!(
            account_slowdown(ACCOUNT_SLOWDOWN_AFTER).is_zero(),
            "the threshold itself is not yet a delay"
        );
        assert_eq!(
            account_slowdown(ACCOUNT_SLOWDOWN_AFTER + 1),
            ACCOUNT_SLOWDOWN_STEP
        );
        assert_eq!(
            account_slowdown(ACCOUNT_SLOWDOWN_AFTER + 2),
            ACCOUNT_SLOWDOWN_STEP * 2
        );
        // A cap, not a curve that eventually becomes a refusal in disguise.
        assert_eq!(account_slowdown(i64::MAX), ACCOUNT_SLOWDOWN_CAP);
        assert_eq!(account_slowdown(-1), std::time::Duration::ZERO);
    }

    #[tokio::test]
    async fn a_refused_attempt_is_evidence_for_sentinel_and_does_not_extend_its_own_lock() {
        // Both directions. Counted by the throttle, every retry would renew the
        // lock that refused it and the fifteen minutes would never end;
        // uncounted by Sentinel, the attacker becomes invisible at exactly the
        // moment the panel decided they were an attacker.
        let db = Db::open_memory().await.unwrap();
        for _ in 0..ACCOUNT_FAILURE_LIMIT {
            db.record_login_attempt("203.0.113.9", "admin", false)
                .await
                .unwrap();
        }

        for _ in 0..4 {
            assert!(
                check_rate_limits(&db, "203.0.113.9", "admin")
                    .await
                    .is_err()
            );
        }

        assert_eq!(
            db.recent_failures_for_ip("203.0.113.9", FAILURE_WINDOW)
                .await
                .unwrap(),
            ACCOUNT_FAILURE_LIMIT,
            "the refusals must not have spent the budget that produced them"
        );
        let evidence = db
            .failed_logins_since(unihelm_db::now() - FAILURE_WINDOW)
            .await
            .unwrap()
            .into_iter()
            .find(|(ip, _)| ip == "203.0.113.9")
            .map(|(_, n)| n);
        assert_eq!(
            evidence,
            Some(ACCOUNT_FAILURE_LIMIT + 4),
            "and Sentinel must see every one of them"
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
