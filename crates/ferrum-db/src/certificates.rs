//! Certificates and their renewal state (spec §11.5).
//!
//! The row here is metadata only. The key and chain live on disk under
//! `cert_dir`, owned by root and readable by nginx — putting a private key in
//! the panel database would put it in every backup of the panel database.

use ferrum_core::{SiteId, TenantScope};
use serde::Serialize;
use time::Duration;

use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertKind {
    /// Issued by Let's Encrypt (or another ACME CA).
    Le,
    /// Uploaded by the operator.
    Custom,
    /// Generated locally, for the catch-all server and for a panel that has no
    /// domain pointed at it yet.
    SelfSigned,
}

impl CertKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            CertKind::Le => "le",
            CertKind::Custom => "custom",
            CertKind::SelfSigned => "self_signed",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "le" => CertKind::Le,
            "custom" => CertKind::Custom,
            "self_signed" => CertKind::SelfSigned,
            other => {
                return Err(DbError::Corrupt {
                    field: "certificates.kind",
                    detail: format!("unknown kind `{other}`"),
                });
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    Pending,
    Active,
    /// A newer certificate for the same site has taken over.
    ///
    /// Kept rather than deleted so the history of what was served when is still
    /// there, but excluded from renewal — otherwise every re-issue would add
    /// another certificate that the scheduler dutifully renews for ever,
    /// multiplying ACME orders for one domain (found on a live server: one site
    /// had three "active" certificates for the same name).
    Superseded,
    Expired,
    Failed,
    Revoked,
}

impl CertStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            CertStatus::Pending => "pending",
            CertStatus::Active => "active",
            CertStatus::Superseded => "superseded",
            CertStatus::Expired => "expired",
            CertStatus::Failed => "failed",
            CertStatus::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "pending" => CertStatus::Pending,
            "active" => CertStatus::Active,
            "superseded" => CertStatus::Superseded,
            "expired" => CertStatus::Expired,
            "failed" => CertStatus::Failed,
            "revoked" => CertStatus::Revoked,
            other => {
                return Err(DbError::Corrupt {
                    field: "certificates.status",
                    detail: format!("unknown status `{other}`"),
                });
            }
        })
    }

    /// Is this certificate the one nginx should be serving?
    pub const fn is_usable(self) -> bool {
        matches!(self, CertStatus::Active)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Certificate {
    pub id: i64,
    pub site_id: Option<SiteId>,
    pub kind: CertKind,
    pub domains: Vec<String>,
    pub issuer: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub not_before: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub not_after: Option<time::OffsetDateTime>,
    pub auto_renew: bool,
    pub status: CertStatus,
    pub last_error: Option<String>,
    pub failure_count: i64,
    pub cert_dir: String,
}

impl Certificate {
    /// Days until expiry, negative once it has passed.
    pub fn days_remaining(&self) -> Option<i64> {
        self.not_after.map(|t| (t - now()).whole_days())
    }

    /// Should the scheduler try to renew this now?
    ///
    /// Thirty days is the conventional threshold for a 90-day certificate; the
    /// failure backoff is what keeps a broken vhost from burning Let's Encrypt's
    /// five-failures-per-hour budget.
    pub fn due_for_renewal(&self) -> bool {
        if !self.auto_renew || self.kind != CertKind::Le {
            return false;
        }
        match self.days_remaining() {
            None => false,
            Some(days) => days <= 30,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CertificateRow {
    pub id: i64,
    pub site_id: Option<i64>,
    pub kind: String,
    pub domains_json: String,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub auto_renew: i64,
    pub status: String,
    pub last_error: Option<String>,
    pub failure_count: i64,
    pub cert_dir: String,
    pub issued_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<CertificateRow> for Certificate {
    type Error = DbError;

    fn try_from(r: CertificateRow) -> Result<Self> {
        Ok(Certificate {
            id: r.id,
            site_id: r.site_id.map(SiteId),
            kind: CertKind::parse(&r.kind)?,
            domains: serde_json::from_str(&r.domains_json).map_err(|e| DbError::Corrupt {
                field: "certificates.domains_json",
                detail: e.to_string(),
            })?,
            issuer: r.issuer,
            not_before: r.not_before.as_deref().map(from_sql_time).transpose()?,
            not_after: r.not_after.as_deref().map(from_sql_time).transpose()?,
            auto_renew: r.auto_renew != 0,
            status: CertStatus::parse(&r.status)?,
            last_error: r.last_error,
            failure_count: r.failure_count,
            cert_dir: r.cert_dir,
        })
    }
}

impl Db {
    /// Record an intent to obtain a certificate. The row exists before the
    /// issuance is attempted, so a failure has somewhere to be reported.
    pub async fn create_certificate(
        &self,
        site_id: Option<SiteId>,
        kind: CertKind,
        domains: &[String],
        cert_dir: &str,
    ) -> Result<Certificate> {
        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, CertificateRow>(
            "INSERT INTO certificates (site_id, kind, domains_json, cert_dir, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?5)
             RETURNING *",
        )
        .bind(site_id.map(|s| s.get()))
        .bind(kind.as_str())
        .bind(serde_json::to_string(domains).expect("a list of strings always serialises"))
        .bind(cert_dir)
        .bind(&ts)
        .fetch_one(self.pool())
        .await?;
        Certificate::try_from(row)
    }

    /// Mark a certificate issued, clear any previous failure, and retire whatever
    /// it replaces.
    ///
    /// The retiring half is not cosmetic. Each issuance inserts a new row, so
    /// without it a site that has been re-issued three times has three rows the
    /// renewal scheduler considers live and renews separately — three ACME
    /// orders for one domain, every cycle, against a CA that rate-limits by
    /// domain. This was found on a live server, not in a test.
    ///
    /// Both statements share one transaction: a crash between them would
    /// otherwise leave either two active certificates or none.
    pub async fn certificate_issued(
        &self,
        id: i64,
        issuer: &str,
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> Result<()> {
        let ts = to_sql_time(now());
        let mut tx = self.begin().await?;

        sqlx::query(
            "UPDATE certificates
             SET status = 'active', issuer = ?2, not_before = ?3, not_after = ?4,
                 issued_at = ?5, last_error = NULL, failure_count = 0,
                 next_attempt_at = NULL, updated_at = ?5
             WHERE id = ?1",
        )
        .bind(id)
        .bind(issuer)
        .bind(to_sql_time(not_before))
        .bind(to_sql_time(not_after))
        .bind(&ts)
        .execute(&mut *tx)
        .await?;

        // Only rows for the same site. A certificate with no site is the panel's
        // own, and there is exactly one of those.
        sqlx::query(
            "UPDATE certificates
             SET status = 'superseded', updated_at = ?2
             WHERE id != ?1
               AND site_id IS NOT NULL
               AND site_id = (SELECT site_id FROM certificates WHERE id = ?1)
               AND status IN ('active', 'pending', 'expired')",
        )
        .bind(id)
        .bind(&ts)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Record a failure without discarding a certificate that is still valid.
    ///
    /// A renewal failing must never take the currently-served certificate down —
    /// that would turn "renewal is broken" into "the site is broken" a month
    /// early (spec §11.5 AC).
    pub async fn certificate_failed(&self, id: i64, error: &str) -> Result<()> {
        let ts = to_sql_time(now());
        sqlx::query(
            "UPDATE certificates
             SET last_error = ?2,
                 failure_count = failure_count + 1,
                 status = CASE WHEN status = 'active' THEN 'active' ELSE 'failed' END,
                 updated_at = ?3
             WHERE id = ?1",
        )
        .bind(id)
        .bind(truncate(error, 2000))
        .bind(&ts)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn set_certificate_auto_renew(&self, id: i64, auto_renew: bool) -> Result<()> {
        sqlx::query("UPDATE certificates SET auto_renew = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(id)
            .bind(i64::from(auto_renew))
            .bind(to_sql_time(now()))
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// The certificate a site should currently be serving.
    pub async fn active_certificate_for_site(
        &self,
        site_id: SiteId,
    ) -> Result<Option<Certificate>> {
        let row = sqlx::query_as::<_, CertificateRow>(
            "SELECT * FROM certificates
             WHERE site_id = ?1 AND status = 'active'
             ORDER BY not_after DESC LIMIT 1",
        )
        .bind(site_id.get())
        .fetch_optional(self.pool())
        .await?;
        row.map(Certificate::try_from).transpose()
    }

    /// Certificates the renewal scheduler should look at.
    ///
    /// Ordered by expiry so the most urgent goes first, and bounded so one
    /// scheduler tick cannot try to renew a thousand certificates at once.
    ///
    /// Four filters, each of which exists because leaving it out breaks
    /// something real:
    ///
    /// * `auto_renew` — the operator turned it off on purpose.
    /// * `kind = 'le'` — we cannot renew a certificate we did not issue.
    /// * `status` — a superseded row is history, not work (see
    ///   [`Db::certificate_issued`]); an expired one is the most urgent case
    ///   there is, so it stays in.
    /// * `next_attempt_at` — a failing certificate must wait out its backoff.
    ///   Let's Encrypt allows five failed validations per identifier per hour,
    ///   so a site with a broken DNS record retrying every tick would spend the
    ///   whole server's budget by itself.
    pub async fn certificates_to_renew(
        &self,
        within: Duration,
        limit: i64,
    ) -> Result<Vec<Certificate>> {
        let cutoff = to_sql_time(now() + within);
        let ts = to_sql_time(now());
        let rows = sqlx::query_as::<_, CertificateRow>(
            "SELECT * FROM certificates
             WHERE auto_renew = 1
               AND kind = 'le'
               AND status IN ('active', 'expired')
               AND not_after IS NOT NULL
               AND not_after <= ?1
               AND (next_attempt_at IS NULL OR next_attempt_at <= ?2)
             ORDER BY not_after ASC
             LIMIT ?3",
        )
        .bind(cutoff)
        .bind(ts)
        .bind(limit.clamp(1, 200))
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(Certificate::try_from).collect()
    }

    /// Hold a certificate back until `at`, after a failed renewal.
    pub async fn set_certificate_next_attempt(
        &self,
        id: i64,
        at: time::OffsetDateTime,
    ) -> Result<()> {
        sqlx::query("UPDATE certificates SET next_attempt_at = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(id)
            .bind(to_sql_time(at))
            .bind(to_sql_time(now()))
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Mark every certificate whose expiry has passed, so the UI stops claiming
    /// they are active.
    pub async fn expire_stale_certificates(&self) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE certificates SET status = 'expired', updated_at = ?1
             WHERE status = 'active' AND not_after IS NOT NULL AND not_after < ?1",
        )
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Certificates visible to a scope, for the UI.
    pub async fn certificates_for(&self, scope: &TenantScope) -> Result<Vec<Certificate>> {
        let sites = self.sites(scope).list(500, 0).await?;
        if sites.is_empty() {
            return Ok(Vec::new());
        }
        // A small `IN (…)` built from integers we produced ourselves — never
        // from anything a caller supplied.
        let ids: Vec<String> = sites.iter().map(|s| s.id.get().to_string()).collect();
        let sql = format!(
            "SELECT * FROM certificates WHERE site_id IN ({}) ORDER BY not_after ASC",
            ids.join(",")
        );
        let rows = sqlx::query_as::<_, CertificateRow>(&sql)
            .fetch_all(self.pool())
            .await?;
        rows.into_iter().map(Certificate::try_from).collect()
    }
}

/// The panel's ACME account for one directory (spec §11.5).
///
/// The credential contains the account's private key, so it is sealed with the
/// master key before it is stored and never leaves the agent in the clear.
#[derive(Debug, Clone)]
pub struct AcmeAccount {
    pub id: i64,
    pub directory_url: String,
    pub contact_email: String,
    /// Still sealed. Open it with [`crate::MasterKey`].
    pub credentials_sealed: String,
}

impl Db {
    /// The stored account for a directory, if we have registered with it.
    ///
    /// Scoped by directory URL on purpose: a staging credential is useless
    /// against production, and crossing them produces an authentication failure
    /// that reads like a bug in the client.
    pub async fn acme_account(&self, directory_url: &str) -> Result<Option<AcmeAccount>> {
        let row: Option<(i64, String, String, String)> = sqlx::query_as(
            "SELECT id, directory_url, contact_email, credentials_encrypted
             FROM acme_accounts WHERE directory_url = ?1",
        )
        .bind(directory_url)
        .fetch_optional(self.pool())
        .await?;

        Ok(row.map(
            |(id, directory_url, contact_email, credentials_sealed)| AcmeAccount {
                id,
                directory_url,
                contact_email,
                credentials_sealed,
            },
        ))
    }

    /// Store a newly registered account.
    pub async fn save_acme_account(
        &self,
        directory_url: &str,
        contact_email: &str,
        credentials_sealed: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO acme_accounts (directory_url, contact_email, credentials_encrypted, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (directory_url) DO UPDATE SET
                 contact_email = ?2, credentials_encrypted = ?3",
        )
        .bind(directory_url)
        .bind(contact_email)
        .bind(credentials_sealed)
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(())
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sites::{NewSite, SiteType};
    use crate::users::NewUser;
    use ferrum_core::{Domain, Email, PhpVersion, Role, Username};

    async fn seed() -> (Db, SiteId) {
        let db = Db::open_memory().await.unwrap();
        let user = db
            .users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Customer,
                email: Email::parse("a@example.com").unwrap(),
                username: Username::parse("alice").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let sub = db.create_subscription(user.id).await.unwrap();
        let site = db
            .create_site(NewSite {
                subscription_id: sub.id,
                domain: Domain::parse("example.com").unwrap(),
                site_type: SiteType::Php,
                php_version: Some(PhpVersion::V83),
                root_dir: "/home/x/sites/example.com/public".into(),
                proxy_port: None,
                redirect_target: None,
            })
            .await
            .unwrap();
        (db, site.id)
    }

    /// A second site, so a test can prove one site's issuance leaves another
    /// alone.
    async fn seed_site(db: &Db, domain: &str) -> SiteId {
        let user = db
            .users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Customer,
                email: Email::parse(&format!("u-{domain}@example.com")).unwrap(),
                username: Username::parse(&domain.replace('.', "")).unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let sub = db.create_subscription(user.id).await.unwrap();
        db.create_site(NewSite {
            subscription_id: sub.id,
            domain: Domain::parse(domain).unwrap(),
            site_type: SiteType::Php,
            php_version: Some(PhpVersion::V83),
            root_dir: format!("/home/y/sites/{domain}/public"),
            proxy_port: None,
            redirect_target: None,
        })
        .await
        .unwrap()
        .id
    }

    async fn issue(db: &Db, id: i64, days: i64) {
        db.certificate_issued(
            id,
            "Let's Encrypt",
            now() - Duration::days(90 - days),
            now() + Duration::days(days),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_certificate_starts_pending_so_a_failure_has_somewhere_to_land() {
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(
                Some(site),
                CertKind::Le,
                &["example.com".into()],
                "/certs/example.com",
            )
            .await
            .unwrap();
        assert_eq!(cert.status, CertStatus::Pending);
        assert!(cert.auto_renew);
        assert_eq!(cert.domains, vec!["example.com".to_string()]);
        assert!(!cert.status.is_usable());
    }

    #[tokio::test]
    async fn issuance_makes_it_the_active_certificate_for_the_site() {
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(
                Some(site),
                CertKind::Le,
                &["example.com".into()],
                "/certs/example.com",
            )
            .await
            .unwrap();
        issue(&db, cert.id, 89).await;

        let active = db.active_certificate_for_site(site).await.unwrap().unwrap();
        assert_eq!(active.id, cert.id);
        assert_eq!(active.status, CertStatus::Active);
        assert_eq!(active.days_remaining(), Some(89));
        assert!(!active.due_for_renewal(), "89 days out is not due");
    }

    #[tokio::test]
    async fn a_renewal_failure_does_not_take_a_working_certificate_down() {
        // Spec §11.5 AC: the failure path must not break the currently served
        // certificate. Getting this wrong turns "renewal is broken" into "the
        // site is broken" a month early.
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(
                Some(site),
                CertKind::Le,
                &["example.com".into()],
                "/certs/example.com",
            )
            .await
            .unwrap();
        issue(&db, cert.id, 20).await;

        db.certificate_failed(
            cert.id,
            "Connection refused fetching http://example.com/.well-known/...",
        )
        .await
        .unwrap();

        let still = db.active_certificate_for_site(site).await.unwrap().unwrap();
        assert_eq!(
            still.status,
            CertStatus::Active,
            "the served certificate must stay active"
        );
        assert_eq!(still.failure_count, 1);
        assert!(still.last_error.unwrap().contains("Connection refused"));
    }

    #[tokio::test]
    async fn a_first_issuance_failure_is_recorded_as_failed() {
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(
                Some(site),
                CertKind::Le,
                &["example.com".into()],
                "/certs/example.com",
            )
            .await
            .unwrap();
        db.certificate_failed(cert.id, "DNS problem: NXDOMAIN")
            .await
            .unwrap();

        let certs = db.certificates_for(&TenantScope::Global).await.unwrap();
        assert_eq!(certs[0].status, CertStatus::Failed);
        assert!(
            db.active_certificate_for_site(site)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_successful_renewal_clears_the_failure_history() {
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(
                Some(site),
                CertKind::Le,
                &["example.com".into()],
                "/certs/example.com",
            )
            .await
            .unwrap();
        db.certificate_failed(cert.id, "rate limited")
            .await
            .unwrap();
        db.certificate_failed(cert.id, "rate limited")
            .await
            .unwrap();
        issue(&db, cert.id, 89).await;

        let after = db.active_certificate_for_site(site).await.unwrap().unwrap();
        assert_eq!(after.failure_count, 0, "backoff must reset once it works");
        assert!(after.last_error.is_none());
    }

    #[tokio::test]
    async fn renewal_is_due_at_thirty_days_and_not_before() {
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(
                Some(site),
                CertKind::Le,
                &["example.com".into()],
                "/certs/example.com",
            )
            .await
            .unwrap();

        issue(&db, cert.id, 31).await;
        assert!(
            !db.active_certificate_for_site(site)
                .await
                .unwrap()
                .unwrap()
                .due_for_renewal()
        );

        issue(&db, cert.id, 29).await;
        assert!(
            db.active_certificate_for_site(site)
                .await
                .unwrap()
                .unwrap()
                .due_for_renewal()
        );

        let due = db
            .certificates_to_renew(Duration::days(30), 10)
            .await
            .unwrap();
        assert_eq!(due.len(), 1);
    }

    #[tokio::test]
    async fn issuing_again_retires_the_certificate_it_replaces() {
        // Found on a live server: one site, three rows, all "active". The
        // scheduler would have renewed each of them separately for ever.
        let (db, site) = seed().await;
        let mut ids = Vec::new();
        for _ in 0..3 {
            let c = db
                .create_certificate(
                    Some(site),
                    CertKind::Le,
                    &["example.com".into()],
                    "/certs/example.com",
                )
                .await
                .unwrap();
            issue(&db, c.id, 20).await;
            ids.push(c.id);
        }

        let due = db.certificates_to_renew(Duration::days(30), 10).await.unwrap();
        assert_eq!(due.len(), 1, "one site must produce one renewal, not three");
        assert_eq!(due[0].id, *ids.last().unwrap(), "the newest is the one served");

        let all = db.certificates_for(&TenantScope::Global).await.unwrap();
        assert_eq!(all.len(), 3, "the older rows are retired, not deleted");
        assert_eq!(
            all.iter().filter(|c| c.status == CertStatus::Superseded).count(),
            2
        );
    }

    #[tokio::test]
    async fn one_site_being_reissued_does_not_disturb_another() {
        let (db, site) = seed().await;
        let other = seed_site(&db, "other.example").await;
        let keep = db
            .create_certificate(Some(other), CertKind::Le, &["other.example".into()], "/certs/o")
            .await
            .unwrap();
        issue(&db, keep.id, 20).await;

        let mine = db
            .create_certificate(Some(site), CertKind::Le, &["example.com".into()], "/certs/e")
            .await
            .unwrap();
        issue(&db, mine.id, 20).await;

        let statuses: Vec<_> = db
            .certificates_for(&TenantScope::Global)
            .await
            .unwrap()
            .into_iter()
            .map(|c| (c.id, c.status))
            .collect();
        assert!(statuses.contains(&(keep.id, CertStatus::Active)), "{statuses:?}");
        assert!(statuses.contains(&(mine.id, CertStatus::Active)), "{statuses:?}");
    }

    #[tokio::test]
    async fn a_certificate_in_its_backoff_window_is_not_retried() {
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(Some(site), CertKind::Le, &["example.com".into()], "/certs/e")
            .await
            .unwrap();
        issue(&db, cert.id, 10).await;
        assert_eq!(db.certificates_to_renew(Duration::days(30), 10).await.unwrap().len(), 1);

        db.set_certificate_next_attempt(cert.id, now() + Duration::hours(1)).await.unwrap();
        assert!(db.certificates_to_renew(Duration::days(30), 10).await.unwrap().is_empty());

        // And a successful issuance clears the hold, so the next cycle is normal.
        issue(&db, cert.id, 90).await;
        db.set_certificate_next_attempt(cert.id, now() - Duration::minutes(1)).await.unwrap();
        issue(&db, cert.id, 10).await;
        assert_eq!(db.certificates_to_renew(Duration::days(30), 10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_expired_certificate_is_still_offered_for_renewal() {
        // Past its expiry is the most urgent case there is, not a reason to
        // stop trying.
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(Some(site), CertKind::Le, &["example.com".into()], "/certs/e")
            .await
            .unwrap();
        issue(&db, cert.id, -5).await;
        db.expire_stale_certificates().await.unwrap();
        assert_eq!(db.certificates_to_renew(Duration::days(30), 10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn turning_auto_renew_off_takes_it_out_of_the_scheduler() {
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(
                Some(site),
                CertKind::Le,
                &["example.com".into()],
                "/certs/example.com",
            )
            .await
            .unwrap();
        issue(&db, cert.id, 5).await;
        assert_eq!(
            db.certificates_to_renew(Duration::days(30), 10)
                .await
                .unwrap()
                .len(),
            1
        );

        db.set_certificate_auto_renew(cert.id, false).await.unwrap();
        assert!(
            db.certificates_to_renew(Duration::days(30), 10)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            !db.active_certificate_for_site(site)
                .await
                .unwrap()
                .unwrap()
                .due_for_renewal()
        );
    }

    #[tokio::test]
    async fn an_uploaded_certificate_is_never_auto_renewed() {
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(
                Some(site),
                CertKind::Custom,
                &["example.com".into()],
                "/certs/x",
            )
            .await
            .unwrap();
        issue(&db, cert.id, 5).await;
        let active = db.active_certificate_for_site(site).await.unwrap().unwrap();
        assert!(
            !active.due_for_renewal(),
            "we cannot renew a certificate we did not issue"
        );
        assert!(
            db.certificates_to_renew(Duration::days(30), 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_expired_certificate_stops_claiming_to_be_active() {
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(
                Some(site),
                CertKind::Le,
                &["example.com".into()],
                "/certs/example.com",
            )
            .await
            .unwrap();
        issue(&db, cert.id, -1).await;

        assert_eq!(db.expire_stale_certificates().await.unwrap(), 1);
        assert!(
            db.active_certificate_for_site(site)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn deleting_a_site_deletes_its_certificates() {
        let (db, site) = seed().await;
        db.create_certificate(
            Some(site),
            CertKind::Le,
            &["example.com".into()],
            "/certs/example.com",
        )
        .await
        .unwrap();
        db.sites(&TenantScope::Global).delete(site).await.unwrap();

        let remaining: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM certificates")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(remaining.0, 0);
    }

    #[tokio::test]
    async fn an_acme_account_is_stored_sealed_and_scoped_to_its_directory() {
        let (db, _) = seed().await;
        let key = crate::MasterKey::generate();
        let sealed = key.seal_str("{\"account\":\"private key\"}").unwrap();

        db.save_acme_account(
            "https://acme-v02.api.letsencrypt.org/directory",
            "a@b.com",
            &sealed,
        )
        .await
        .unwrap();

        // A staging credential must not be found for production.
        assert!(
            db.acme_account("https://acme-staging-v02.api.letsencrypt.org/directory")
                .await
                .unwrap()
                .is_none()
        );

        let found = db
            .acme_account("https://acme-v02.api.letsencrypt.org/directory")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.contact_email, "a@b.com");
        assert!(!found.credentials_sealed.contains("private key"));
        assert_eq!(
            key.open_str(&found.credentials_sealed).unwrap(),
            "{\"account\":\"private key\"}"
        );
    }

    #[tokio::test]
    async fn re_registering_replaces_the_stored_credential() {
        let (db, _) = seed().await;
        let url = "https://acme-v02.api.letsencrypt.org/directory";
        db.save_acme_account(url, "old@example.com", "aaaa")
            .await
            .unwrap();
        db.save_acme_account(url, "new@example.com", "bbbb")
            .await
            .unwrap();

        let found = db.acme_account(url).await.unwrap().unwrap();
        assert_eq!(found.contact_email, "new@example.com");
        assert_eq!(found.credentials_sealed, "bbbb");
    }

    #[tokio::test]
    async fn a_very_long_error_is_truncated_rather_than_stored_whole() {
        let (db, site) = seed().await;
        let cert = db
            .create_certificate(
                Some(site),
                CertKind::Le,
                &["example.com".into()],
                "/certs/example.com",
            )
            .await
            .unwrap();
        db.certificate_failed(cert.id, &"é".repeat(5000))
            .await
            .unwrap();

        let certs = db.certificates_for(&TenantScope::Global).await.unwrap();
        assert!(certs[0].last_error.as_ref().unwrap().len() <= 2000);
    }
}
