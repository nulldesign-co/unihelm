//! The panel's own certificate rows (spec §11.5 "panel's own cert management").
//!
//! The panel's certificate is an ordinary `certificates` row with one
//! difference: `site_id` is NULL, because the panel is not a site. That NULL is
//! why this module exists — SQL's `site_id = NULL` matches nothing, so every
//! per-site query in `certificates.rs` silently steps around the panel's row,
//! and the two places that matters (finding the row, retiring its predecessor)
//! need their own queries.

use crate::certificates::{Certificate, CertificateRow};
use crate::{Db, Result, now, to_sql_time};

/// Settings key: the domain the panel is served on (`panel.tls.issue` writes
/// it, the status endpoint and the renewal scheduler read it). Stored as a
/// plain JSON string, e.g. `"panel.example.com"`.
pub const DOMAIN_KEY: &str = "panel.domain";

impl Db {
    /// The panel's own certificate: the active one when it exists, otherwise
    /// the newest attempt — so a status endpoint shows "issuance failed"
    /// rather than nothing while the working certificate, if any, still wins.
    ///
    /// Self-signed rows are excluded on purpose: the fallback certificate a
    /// fresh panel serves is not something to report as "the panel's
    /// certificate" or to renew.
    pub async fn panel_certificate(&self) -> Result<Option<Certificate>> {
        let row = sqlx::query_as::<_, CertificateRow>(
            "SELECT * FROM certificates
             WHERE site_id IS NULL AND kind != 'self_signed'
             ORDER BY CASE WHEN status = 'active' THEN 0 ELSE 1 END, id DESC
             LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await?;
        row.map(Certificate::try_from).transpose()
    }

    /// Retire every panel certificate except `keep_id`.
    ///
    /// [`Db::certificate_issued`] supersedes replaced rows *by site id*, and
    /// deliberately skips rows whose `site_id` is NULL — it cannot tell the
    /// panel's certificate from any other site-less row. Without this call,
    /// every panel renewal would leave one more "active" NULL-site row behind,
    /// and the scheduler would renew each of them separately for ever: the
    /// same duplicate-order bug the per-site supersede fixed on a live server,
    /// reintroduced through the panel path.
    pub async fn supersede_panel_certificates(&self, keep_id: i64) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE certificates
             SET status = 'superseded', updated_at = ?2
             WHERE id != ?1
               AND site_id IS NULL
               AND kind != 'self_signed'
               AND status IN ('active', 'pending', 'expired')",
        )
        .bind(keep_id)
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::{CertKind, CertStatus};
    use ferrum_core::{Domain, TenantScope};
    use time::Duration;

    /// A NULL-site certificate, issued `days` from expiry.
    async fn panel_cert(db: &Db, days: i64) -> Certificate {
        let cert = db
            .create_certificate(
                None,
                CertKind::Le,
                &["panel.example.com".into()],
                "/certs/panel.example.com",
            )
            .await
            .unwrap();
        db.certificate_issued(
            cert.id,
            "Let's Encrypt",
            now() - Duration::days(90 - days),
            now() + Duration::days(days),
        )
        .await
        .unwrap();
        cert
    }

    #[tokio::test]
    async fn a_certificate_with_no_site_is_offered_for_renewal() {
        // The scheduler's query must not treat `site_id IS NULL` as "not
        // mine": the panel's own certificate expires like any other, and a
        // renewal query that skips it means the panel silently loses HTTPS
        // ninety days after install (spec §11.5).
        let db = Db::open_memory().await.unwrap();
        let cert = panel_cert(&db, 10).await;

        let due = db
            .certificates_to_renew(Duration::days(30), 10)
            .await
            .unwrap();
        assert_eq!(due.len(), 1, "the panel certificate must be offered");
        assert_eq!(due[0].id, cert.id);
        assert!(due[0].site_id.is_none());
    }

    #[tokio::test]
    async fn issuing_again_leaves_a_duplicate_unless_the_panel_supersede_runs() {
        // Documents *why* `supersede_panel_certificates` exists: the per-site
        // supersede inside `certificate_issued` matches rows by site id, and
        // NULL never equals NULL in SQL, so the old panel row survives...
        let db = Db::open_memory().await.unwrap();
        let old = panel_cert(&db, 10).await;
        let new = panel_cert(&db, 90).await;

        let due = db
            .certificates_to_renew(Duration::days(30), 10)
            .await
            .unwrap();
        assert_eq!(
            due.len(),
            1,
            "without the explicit supersede the stale row would still be renewed"
        );
        assert_eq!(due[0].id, old.id);

        // ...and the explicit supersede is what retires it.
        db.supersede_panel_certificates(new.id).await.unwrap();
        let due = db
            .certificates_to_renew(Duration::days(30), 10)
            .await
            .unwrap();
        assert!(
            due.is_empty(),
            "the retired row must not be renewed: {due:?}"
        );

        let current = db.panel_certificate().await.unwrap().unwrap();
        assert_eq!(current.id, new.id);
        assert_eq!(current.status, CertStatus::Active);
    }

    #[tokio::test]
    async fn the_panel_supersede_never_touches_a_site_certificate() {
        // The panel path retires only NULL-site rows; a customer's certificate
        // being demoted because the *panel* renewed would be a cross-tenant
        // side effect nobody could debug.
        let db = Db::open_memory().await.unwrap();
        let site = seed_site(&db).await;
        let site_cert = db
            .create_certificate(
                Some(site),
                CertKind::Le,
                &["example.com".into()],
                "/certs/example.com",
            )
            .await
            .unwrap();
        db.certificate_issued(
            site_cert.id,
            "Let's Encrypt",
            now(),
            now() + Duration::days(60),
        )
        .await
        .unwrap();

        let panel = panel_cert(&db, 90).await;
        db.supersede_panel_certificates(panel.id).await.unwrap();

        let still = db.active_certificate_for_site(site).await.unwrap().unwrap();
        assert_eq!(still.id, site_cert.id);
        assert_eq!(still.status, CertStatus::Active);
    }

    #[tokio::test]
    async fn the_active_row_wins_over_a_newer_failed_attempt() {
        // A renewal that fails inserts a newer, failed row. The status
        // endpoint must keep reporting the certificate that is actually being
        // served, not the latest attempt.
        let db = Db::open_memory().await.unwrap();
        let active = panel_cert(&db, 20).await;

        let retry = db
            .create_certificate(
                None,
                CertKind::Le,
                &["panel.example.com".into()],
                "/certs/panel.example.com",
            )
            .await
            .unwrap();
        db.certificate_failed(retry.id, "DNS problem: NXDOMAIN")
            .await
            .unwrap();

        let current = db.panel_certificate().await.unwrap().unwrap();
        assert_eq!(current.id, active.id);
        assert_eq!(current.status, CertStatus::Active);
    }

    #[tokio::test]
    async fn with_no_active_row_the_newest_attempt_carries_the_error() {
        // First issuance failed: the endpoint should be able to say *why*
        // there is no certificate yet.
        let db = Db::open_memory().await.unwrap();
        let attempt = db
            .create_certificate(
                None,
                CertKind::Le,
                &["panel.example.com".into()],
                "/certs/panel.example.com",
            )
            .await
            .unwrap();
        db.certificate_failed(attempt.id, "Connection refused")
            .await
            .unwrap();

        let current = db.panel_certificate().await.unwrap().unwrap();
        assert_eq!(current.status, CertStatus::Failed);
        assert!(current.last_error.unwrap().contains("Connection refused"));
    }

    #[tokio::test]
    async fn a_site_certificate_is_never_mistaken_for_the_panels() {
        let db = Db::open_memory().await.unwrap();
        let site = seed_site(&db).await;
        db.create_certificate(
            Some(site),
            CertKind::Le,
            &["example.com".into()],
            "/certs/example.com",
        )
        .await
        .unwrap();

        assert!(db.panel_certificate().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_panel_domain_setting_round_trips() {
        // The operation stores a validated `Domain`; the web process reads a
        // plain `String`. Both sides go through the same JSON value, and this
        // is the test that keeps them agreeing on its shape.
        let db = Db::open_memory().await.unwrap();
        assert_eq!(db.get_setting::<String>(DOMAIN_KEY).await.unwrap(), None);

        let domain = Domain::parse("panel.example.com").unwrap();
        db.set_setting(DOMAIN_KEY, &domain).await.unwrap();
        assert_eq!(
            db.get_setting::<String>(DOMAIN_KEY).await.unwrap(),
            Some("panel.example.com".to_string())
        );

        // Re-pointing the panel overwrites rather than duplicates.
        let moved = Domain::parse("panel2.example.com").unwrap();
        db.set_setting(DOMAIN_KEY, &moved).await.unwrap();
        assert_eq!(
            db.get_setting::<String>(DOMAIN_KEY).await.unwrap(),
            Some("panel2.example.com".to_string())
        );
    }

    /// A site to prove panel queries leave site certificates alone.
    async fn seed_site(db: &Db) -> ferrum_core::SiteId {
        use crate::sites::{NewSite, SiteType};
        use crate::users::NewUser;
        use ferrum_core::{Email, PhpVersion, Role, Username};

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
        db.create_site(NewSite {
            subscription_id: sub.id,
            domain: Domain::parse("example.com").unwrap(),
            site_type: SiteType::Php,
            php_version: Some(PhpVersion::V83),
            root_dir: "/home/x/sites/example.com/public".into(),
            proxy_port: None,
            redirect_target: None,
        })
        .await
        .unwrap()
        .id
    }
}
