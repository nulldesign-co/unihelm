//! Browser sessions (spec §12 rule 7).
//!
//! The cookie value never reaches the database: we store its SHA-256, so a stolen
//! backup is not a set of live logins. The raw token is returned exactly once, at
//! creation, and cannot be recovered afterwards.

use time::Duration;
use unihelm_core::UserId;

use crate::models::{Session, SessionRow, User, UserRow};
use crate::{Db, DbError, Result, from_sql_time, now, password, to_sql_time};

/// Default session lifetime. Long enough for a working day, short enough that a
/// forgotten laptop is not a standing invitation.
pub const DEFAULT_TTL: Duration = Duration::hours(12);

/// What a refused attempt is filed under in `login_attempts.username`.
///
/// `login_attempts` has four columns and the one query that must keep seeing
/// these rows — [`Db::failed_logins_since`], which is Sentinel's evidence —
/// reads `ip` and `success` only. So `username` is where the distinction goes:
/// the row still names the account the attempt was aimed at, prefixed, and the
/// throttle counters filter on that prefix. A `throttled` column would say the
/// same thing more plainly, and is the shape to move to the next time this
/// table is migrated; migrations here are forward-only and their numbers are
/// allocated in `docs/wave1-contracts.md`, so it is not a change to make in
/// passing.
///
/// The prefix is not a secret and does not need to be: [`account_label`] strips
/// it off everything a caller supplies, so no client can file its own attempt
/// under it however it spells its username.
const THROTTLED_LABEL_PREFIX: &str = "throttled:";

/// The account label a caller-supplied username is filed under.
///
/// Stripping repeatedly rather than once, because a single strip would leave
/// `throttled:throttled:admin` still wearing the marker.
fn account_label(username: &str) -> &str {
    let mut label = username;
    while let Some(rest) = label.strip_prefix(THROTTLED_LABEL_PREFIX) {
        label = rest;
    }
    label
}

/// The `LIKE` pattern that matches every throttled row and nothing else.
///
/// The prefix carries no `%` or `_` of its own, so it needs no `ESCAPE` clause.
fn throttled_like_pattern() -> String {
    format!("{THROTTLED_LABEL_PREFIX}%")
}

/// A freshly minted session. `token` is the cookie value and is never stored.
#[derive(Debug, Clone)]
pub struct IssuedSession {
    pub token: String,
    pub csrf: String,
    pub session: Session,
}

impl Db {
    /// Issue a session for an authenticated user.
    pub async fn create_session(
        &self,
        user_id: UserId,
        ip: Option<&str>,
        user_agent: Option<&str>,
        ttl: Duration,
        impersonator_id: Option<UserId>,
    ) -> Result<IssuedSession> {
        let token = password::generate_token();
        let id = password::token_digest(&token);
        let csrf = password::generate_token();
        let created = now();
        let expires = created + ttl;

        let row = sqlx::query_as::<_, SessionRow>(
            "INSERT INTO sessions (id, user_id, csrf, ip, user_agent, impersonator_id,
                                   created_at, last_seen_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8)
             RETURNING *",
        )
        .bind(&id)
        .bind(user_id.get())
        .bind(&csrf)
        .bind(ip)
        .bind(user_agent)
        .bind(impersonator_id.map(|i| i.get()))
        .bind(to_sql_time(created))
        .bind(to_sql_time(expires))
        .fetch_one(self.pool())
        .await?;

        Ok(IssuedSession {
            token,
            csrf,
            session: Session::try_from(row)?,
        })
    }

    /// Resolve a cookie value to its session and user.
    ///
    /// Returns `None` for anything not currently usable — unknown, expired,
    /// revoked, or belonging to an account that may no longer log in — so callers
    /// cannot forget one of those checks.
    pub async fn lookup_session(&self, token: &str) -> Result<Option<(Session, User)>> {
        let id = password::token_digest(token);

        let Some(session_row) =
            sqlx::query_as::<_, SessionRow>("SELECT * FROM sessions WHERE id = ?1")
                .bind(&id)
                .fetch_optional(self.pool())
                .await?
        else {
            return Ok(None);
        };

        let session = Session::try_from(session_row)?;
        if !session.is_valid_at(now()) {
            return Ok(None);
        }

        let Some(user_row) = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?1")
            .bind(session.user_id.get())
            .fetch_optional(self.pool())
            .await?
        else {
            return Ok(None);
        };

        let user = User::try_from(user_row)?;
        if !user.status.can_log_in() {
            return Ok(None);
        }

        Ok(Some((session, user)))
    }

    /// Slide the last-seen timestamp. Cheap enough to call per request.
    pub async fn touch_session(&self, session_id: &str) -> Result<()> {
        sqlx::query("UPDATE sessions SET last_seen_at = ?2 WHERE id = ?1")
            .bind(session_id)
            .bind(to_sql_time(now()))
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Extend a session's expiry — used on activity so an active user is not
    /// logged out mid-task.
    pub async fn extend_session(&self, session_id: &str, ttl: Duration) -> Result<()> {
        sqlx::query("UPDATE sessions SET expires_at = ?2 WHERE id = ?1 AND revoked = 0")
            .bind(session_id)
            .bind(to_sql_time(now() + ttl))
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn revoke_session(&self, session_id: &str) -> Result<()> {
        sqlx::query("UPDATE sessions SET revoked = 1 WHERE id = ?1")
            .bind(session_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Revoke every session for an account — password change, suspension, or the
    /// "sign out everywhere" button.
    pub async fn revoke_all_sessions(&self, user_id: UserId) -> Result<u64> {
        let result =
            sqlx::query("UPDATE sessions SET revoked = 1 WHERE user_id = ?1 AND revoked = 0")
                .bind(user_id.get())
                .execute(self.pool())
                .await?;
        Ok(result.rows_affected())
    }

    /// The device list shown in account settings.
    pub async fn list_sessions(&self, user_id: UserId) -> Result<Vec<Session>> {
        let rows = sqlx::query_as::<_, SessionRow>(
            "SELECT * FROM sessions WHERE user_id = ?1 AND revoked = 0 ORDER BY last_seen_at DESC",
        )
        .bind(user_id.get())
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(Session::try_from).collect()
    }

    /// Delete sessions that expired more than a day ago. Run by the scheduler.
    pub async fn purge_expired_sessions(&self) -> Result<u64> {
        let cutoff = to_sql_time(now() - Duration::days(1));
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < ?1")
            .bind(cutoff)
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected())
    }

    /// Record a login attempt for rate limiting (spec §11.9).
    pub async fn record_login_attempt(
        &self,
        ip: &str,
        username: &str,
        success: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO login_attempts (at, ip, username, success) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(to_sql_time(now()))
        .bind(ip)
        // Never the raw string. The login route records whatever the client
        // typed, so without this a caller could file its own attempt under the
        // throttled label and buy itself an unlimited budget.
        .bind(account_label(username))
        .bind(i64::from(success))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Record an attempt the panel refused *without checking the password*.
    ///
    /// It is a failure to Sentinel and not a failure to the throttle, and both
    /// halves are load-bearing. Until this existed the login route returned on
    /// the throttle's error before recording anything, so the moment the
    /// throttle engaged the attacker's address stopped accumulating evidence
    /// and Sentinel — which bans on recorded failures — went blind exactly when
    /// there was most to see.
    ///
    /// The row therefore carries the real address and `success = 0`, which is
    /// all [`Db::failed_logins_since`] asks for, and is filed under
    /// [`THROTTLED_LABEL_PREFIX`] rather than the account it named, which is
    /// what keeps [`Db::recent_failures_for_ip`] and its siblings from counting
    /// it. Counting it there would make the refusal renew the lock that caused
    /// it, on every retry, for as long as the attempts kept coming.
    pub async fn record_throttled_login_attempt(&self, ip: &str, username: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO login_attempts (at, ip, username, success) VALUES (?1, ?2, ?3, 0)",
        )
        .bind(to_sql_time(now()))
        .bind(ip)
        .bind(format!(
            "{THROTTLED_LABEL_PREFIX}{}",
            account_label(username)
        ))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Failed attempts from one address inside `window`, throttled ones aside.
    pub async fn recent_failures_for_ip(&self, ip: &str, window: Duration) -> Result<i64> {
        let since = to_sql_time(now() - window);
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM login_attempts
             WHERE ip = ?1 AND success = 0 AND at >= ?2 AND username NOT LIKE ?3",
        )
        .bind(ip)
        .bind(since)
        .bind(throttled_like_pattern())
        .fetch_one(self.pool())
        .await?;
        Ok(row.0)
    }

    /// Failed attempts against one account *from one address* inside `window`.
    ///
    /// This pair, rather than the account alone, is what may earn a refusal.
    /// Counting an account's failures from everywhere and refusing on the total
    /// meant five wrong passwords for `admin` every fifteen minutes — which
    /// needs no account and no session — held the real admin out from every
    /// address on earth, indefinitely, with the correct password.
    pub async fn recent_failures_for_ip_and_username(
        &self,
        ip: &str,
        username: &str,
        window: Duration,
    ) -> Result<i64> {
        let since = to_sql_time(now() - window);
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM login_attempts
             WHERE ip = ?1 AND username = ?2 AND success = 0 AND at >= ?3",
        )
        .bind(ip)
        // Throttled rows are filed under a label no `account_label` can return,
        // so this equality excludes them without a second predicate.
        .bind(account_label(username))
        .bind(since)
        .fetch_one(self.pool())
        .await?;
        Ok(row.0)
    }

    /// Forget an account's failed logins, and the failures from the addresses
    /// they came from.
    ///
    /// The throttle is what locks somebody out, and until this existed there was
    /// no way to lift it — not even from a root shell on the server. Resetting
    /// the password does not help, because the count is on attempts rather than
    /// on the credential. Fifteen minutes of waiting was the only cure, and the
    /// message did not say fifteen.
    ///
    /// The IP rows go too: whoever is locked out has usually spent some of that
    /// budget as well, and clearing only half leaves them still refused for a
    /// reason the command said it had fixed. That second pass is also what
    /// takes the throttled rows those addresses left behind, which the first
    /// pass cannot see because they are filed under a different label.
    pub async fn clear_login_failures(&self, username: &str) -> Result<u64> {
        let account = account_label(username);
        let ips = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT ip FROM login_attempts WHERE username = ?1 AND success = 0",
        )
        .bind(account)
        .fetch_all(self.pool())
        .await?;

        let mut cleared = sqlx::query("DELETE FROM login_attempts WHERE username = ?1")
            .bind(account)
            .execute(self.pool())
            .await?
            .rows_affected();

        for ip in ips {
            cleared += sqlx::query("DELETE FROM login_attempts WHERE ip = ?1 AND success = 0")
                .bind(&ip)
                .execute(self.pool())
                .await?
                .rows_affected();
        }
        Ok(cleared)
    }

    /// Failed attempts against one account, from anywhere, inside `window`.
    ///
    /// A signal about the account rather than about a caller: anyone on the
    /// internet can raise it for any account, so what the panel does with it
    /// must never be a refusal (see `unihelm_web::auth::check_rate_limits`).
    pub async fn recent_failures_for_username(
        &self,
        username: &str,
        window: Duration,
    ) -> Result<i64> {
        let since = to_sql_time(now() - window);
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM login_attempts WHERE username = ?1 AND success = 0 AND at >= ?2",
        )
        .bind(account_label(username))
        .bind(since)
        .fetch_one(self.pool())
        .await?;
        Ok(row.0)
    }

    /// Drop login history older than `keep`.
    pub async fn purge_login_attempts(&self, keep: Duration) -> Result<u64> {
        let cutoff = to_sql_time(now() - keep);
        let result = sqlx::query("DELETE FROM login_attempts WHERE at < ?1")
            .bind(cutoff)
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected())
    }

    /// Force a session's expiry, for tests and for administrative revocation.
    pub async fn expire_session_at(
        &self,
        session_id: &str,
        at: time::OffsetDateTime,
    ) -> Result<()> {
        sqlx::query("UPDATE sessions SET expires_at = ?2 WHERE id = ?1")
            .bind(session_id)
            .bind(to_sql_time(at))
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

/// Parse a stored expiry, for callers that only have the row.
pub fn parse_expiry(s: &str) -> Result<time::OffsetDateTime> {
    from_sql_time(s).map_err(|_| DbError::Corrupt {
        field: "sessions.expires_at",
        detail: s.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UserStatus;
    use crate::users::NewUser;
    use unihelm_core::{Email, Role, TenantScope, Username};

    async fn seed() -> (Db, UserId) {
        let db = Db::open_memory().await.unwrap();
        let u = db
            .users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Admin,
                email: Email::parse("admin@example.com").unwrap(),
                username: Username::parse("admin").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        (db, u.id)
    }

    #[tokio::test]
    async fn the_raw_token_is_never_stored() {
        let (db, uid) = seed().await;
        let issued = db
            .create_session(uid, Some("10.0.0.1"), None, DEFAULT_TTL, None)
            .await
            .unwrap();

        assert_ne!(issued.session.id, issued.token);
        assert_eq!(issued.session.id, password::token_digest(&issued.token));

        let stored: Vec<String> = sqlx::query_as::<_, (String,)>("SELECT id FROM sessions")
            .fetch_all(db.pool())
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.0)
            .collect();
        assert!(
            !stored.contains(&issued.token),
            "the cookie value must not be in the database"
        );
    }

    #[tokio::test]
    async fn lookup_resolves_a_valid_token() {
        let (db, uid) = seed().await;
        let issued = db
            .create_session(uid, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();

        let (session, user) = db.lookup_session(&issued.token).await.unwrap().unwrap();
        assert_eq!(session.user_id, uid);
        assert_eq!(user.id, uid);

        assert!(
            db.lookup_session("not-a-real-token")
                .await
                .unwrap()
                .is_none()
        );
        // The digest is not a valid token either.
        assert!(
            db.lookup_session(&issued.session.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn expired_sessions_do_not_resolve() {
        let (db, uid) = seed().await;
        let issued = db
            .create_session(uid, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();
        db.expire_session_at(&issued.session.id, now() - Duration::seconds(1))
            .await
            .unwrap();
        assert!(db.lookup_session(&issued.token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoked_sessions_do_not_resolve() {
        let (db, uid) = seed().await;
        let issued = db
            .create_session(uid, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();
        db.revoke_session(&issued.session.id).await.unwrap();
        assert!(db.lookup_session(&issued.token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn suspending_an_account_invalidates_its_live_sessions() {
        let (db, uid) = seed().await;
        let issued = db
            .create_session(uid, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();
        assert!(db.lookup_session(&issued.token).await.unwrap().is_some());

        db.users(&TenantScope::Global)
            .set_status(uid, UserStatus::Suspended)
            .await
            .unwrap();
        assert!(
            db.lookup_session(&issued.token).await.unwrap().is_none(),
            "a suspended account must not keep working through an existing cookie"
        );
    }

    #[tokio::test]
    async fn revoke_all_signs_out_every_device() {
        let (db, uid) = seed().await;
        let a = db
            .create_session(uid, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();
        let b = db
            .create_session(uid, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();
        assert_eq!(db.list_sessions(uid).await.unwrap().len(), 2);

        assert_eq!(db.revoke_all_sessions(uid).await.unwrap(), 2);
        assert!(db.lookup_session(&a.token).await.unwrap().is_none());
        assert!(db.lookup_session(&b.token).await.unwrap().is_none());
        assert!(db.list_sessions(uid).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn every_session_gets_its_own_csrf_token() {
        let (db, uid) = seed().await;
        let a = db
            .create_session(uid, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();
        let b = db
            .create_session(uid, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();
        assert_ne!(a.csrf, b.csrf);
        assert_ne!(a.token, b.token);
    }

    #[tokio::test]
    async fn purge_removes_only_long_expired_rows() {
        let (db, uid) = seed().await;
        let live = db
            .create_session(uid, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();
        let stale = db
            .create_session(uid, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();
        db.expire_session_at(&stale.session.id, now() - Duration::days(2))
            .await
            .unwrap();

        assert_eq!(db.purge_expired_sessions().await.unwrap(), 1);
        assert!(db.lookup_session(&live.token).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn login_attempts_are_counted_per_ip_and_per_account() {
        let (db, _) = seed().await;
        for _ in 0..3 {
            db.record_login_attempt("10.0.0.9", "admin", false)
                .await
                .unwrap();
        }
        db.record_login_attempt("10.0.0.9", "admin", true)
            .await
            .unwrap();
        db.record_login_attempt("10.0.0.10", "admin", false)
            .await
            .unwrap();

        assert_eq!(
            db.recent_failures_for_ip("10.0.0.9", Duration::minutes(15))
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            db.recent_failures_for_ip("10.0.0.10", Duration::minutes(15))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            db.recent_failures_for_username("admin", Duration::minutes(15))
                .await
                .unwrap(),
            4,
            "account lockout counts failures from every address"
        );
        // Attempts older than the window are not counted. Timestamps are
        // second-granular, so backdate rather than relying on a zero-length window.
        sqlx::query("UPDATE login_attempts SET at = ?1 WHERE ip = '10.0.0.10'")
            .bind(to_sql_time(now() - Duration::hours(1)))
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(
            db.recent_failures_for_ip("10.0.0.10", Duration::minutes(15))
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            db.recent_failures_for_ip("10.0.0.10", Duration::hours(2))
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn failures_are_counted_per_account_and_address_pair() {
        // The pair is what may earn a refusal, so it must not pick up the
        // failures the same account collected from somewhere else.
        let (db, _) = seed().await;
        for _ in 0..4 {
            db.record_login_attempt("10.0.0.9", "admin", false)
                .await
                .unwrap();
        }
        db.record_login_attempt("10.0.0.10", "admin", false)
            .await
            .unwrap();

        let window = Duration::minutes(15);
        assert_eq!(
            db.recent_failures_for_ip_and_username("10.0.0.9", "admin", window)
                .await
                .unwrap(),
            4
        );
        assert_eq!(
            db.recent_failures_for_ip_and_username("10.0.0.10", "admin", window)
                .await
                .unwrap(),
            1,
            "an address must only answer for what it did itself"
        );
        assert_eq!(
            db.recent_failures_for_ip_and_username("10.0.0.11", "admin", window)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn a_throttled_attempt_is_evidence_for_sentinel_and_not_for_the_throttle() {
        // Both directions, because getting either one backwards is a bug with
        // teeth: counted by the throttle, every refusal renews the lock that
        // caused it; invisible to Sentinel, the defence goes blind the moment
        // the throttle engages, which is when there is most to see.
        let (db, _) = seed().await;
        for _ in 0..2 {
            db.record_login_attempt("10.0.0.9", "admin", false)
                .await
                .unwrap();
        }
        db.record_throttled_login_attempt("10.0.0.9", "admin")
            .await
            .unwrap();
        db.record_throttled_login_attempt("10.0.0.9", "admin")
            .await
            .unwrap();

        let window = Duration::minutes(15);
        assert_eq!(
            db.recent_failures_for_ip("10.0.0.9", window).await.unwrap(),
            2,
            "a refusal must not spend the budget that produced it"
        );
        assert_eq!(
            db.recent_failures_for_ip_and_username("10.0.0.9", "admin", window)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            db.recent_failures_for_username("admin", window)
                .await
                .unwrap(),
            2
        );

        let evidence = db
            .failed_logins_since(now() - window)
            .await
            .unwrap()
            .into_iter()
            .find(|(ip, _)| ip == "10.0.0.9")
            .map(|(_, n)| n);
        assert_eq!(
            evidence,
            Some(4),
            "Sentinel counts what the attacker actually did, refusals included"
        );
    }

    #[tokio::test]
    async fn a_caller_cannot_file_its_own_attempt_as_throttled() {
        // The login route records whatever the client typed. If that string
        // could wear the throttled label, an attacker would spell their
        // username `throttled:admin` and buy an unlimited budget.
        let (db, _) = seed().await;
        for _ in 0..3 {
            db.record_login_attempt("10.0.0.9", "throttled:admin", false)
                .await
                .unwrap();
        }

        let window = Duration::minutes(15);
        assert_eq!(
            db.recent_failures_for_ip("10.0.0.9", window).await.unwrap(),
            3
        );
        assert_eq!(
            db.recent_failures_for_username("admin", window)
                .await
                .unwrap(),
            3,
            "the marker is stripped, so the attempts land on the account they named"
        );
        assert_eq!(
            db.recent_failures_for_ip_and_username("10.0.0.9", "throttled:admin", window)
                .await
                .unwrap(),
            3,
            "and the same stripping makes the query find them again"
        );
    }

    #[tokio::test]
    async fn unlocking_an_account_also_clears_the_refusals_it_collected() {
        // The refusals hold no lock of their own, but leaving them behind
        // leaves Sentinel holding evidence against an operator the command just
        // said it had unlocked.
        let (db, _) = seed().await;
        for _ in 0..5 {
            db.record_login_attempt("10.0.0.9", "admin", false)
                .await
                .unwrap();
        }
        db.record_throttled_login_attempt("10.0.0.9", "admin")
            .await
            .unwrap();

        assert_eq!(db.clear_login_failures("admin").await.unwrap(), 6);
        assert!(
            db.failed_logins_since(now() - Duration::minutes(15))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn impersonation_is_recorded_on_the_session() {
        let (db, uid) = seed().await;
        let issued = db
            .create_session(uid, None, None, DEFAULT_TTL, Some(UserId(1)))
            .await
            .unwrap();
        let (session, _) = db.lookup_session(&issued.token).await.unwrap().unwrap();
        assert_eq!(session.impersonator_id, Some(UserId(1)));
    }
}
