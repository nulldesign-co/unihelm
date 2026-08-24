//! Certificate issuance and renewal (spec §11.5).

use async_trait::async_trait;
use ferrum_config::paths;
use ferrum_core::{ErrorCode, FerrumError, Permission, Result, SiteId};
use ferrum_db::{CertKind, Certificate};
use serde::{Deserialize, Serialize};

use crate::acme::{self, Directory};
use crate::registry::{Execution, OpContext, TypedOperation};

/// `cert.list` — what certificates exist and when they expire.
pub struct List;

#[derive(Debug, Deserialize)]
pub struct ListInput {}

#[derive(Debug, Serialize)]
pub struct CertView {
    #[serde(flatten)]
    pub certificate: Certificate,
    pub days_remaining: Option<i64>,
    pub due_for_renewal: bool,
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub certificates: Vec<CertView>,
}

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "cert.list";
    const PERMISSION: Permission = Permission::SiteRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let certificates = ctx
            .db()
            .certificates_for(ctx.scope())
            .await
            .map_err(FerrumError::from)?;
        Ok(ListOutput {
            certificates: certificates
                .into_iter()
                .map(|c| CertView {
                    days_remaining: c.days_remaining(),
                    due_for_renewal: c.due_for_renewal(),
                    certificate: c,
                })
                .collect(),
        })
    }
}

/// `cert.issue` — obtain a Let's Encrypt certificate for a site and put it live.
pub struct Issue;

#[derive(Debug, Deserialize)]
pub struct IssueInput {
    pub site_id: i64,
    /// Use the staging directory. Its root is not publicly trusted, so a staging
    /// certificate must never be installed on a live site — but it is the right
    /// way to prove the flow works without spending rate-limit budget.
    #[serde(default)]
    pub staging: bool,
    /// Contact address for expiry warnings from the CA.
    #[serde(default)]
    pub contact_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IssueOutput {
    pub certificate_id: i64,
    pub domains: Vec<String>,
    pub issuer: String,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: time::OffsetDateTime,
    pub days_valid: i64,
}

#[async_trait]
impl TypedOperation for Issue {
    type Input = IssueInput;
    type Output = IssueOutput;

    const NAME: &'static str = "cert.issue";
    const PERMISSION: Permission = Permission::SiteManage;
    // Minutes: the CA has to fetch a challenge from the public internet, and
    // that waits on DNS the panel does not control.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: false,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db().clone();
        let site_id = SiteId(input.site_id);

        let site = db
            .sites(ctx.scope())
            .by_id(site_id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("site"))?;

        // Every name the site answers to goes in the certificate, or the alias
        // gets a name-mismatch warning in every browser.
        let names = db
            .sites(ctx.scope())
            .server_names(site_id)
            .await
            .map_err(FerrumError::from)?;

        let directory = if input.staging {
            Directory::Staging
        } else {
            Directory::Production
        };
        let contact = input
            .contact_email
            .clone()
            .unwrap_or_else(|| format!("admin@{}", site.domain));

        ctx.log(format!(
            "requesting a certificate for {} from {}",
            names.join(", "),
            if input.staging {
                "the staging directory"
            } else {
                "Let's Encrypt"
            }
        ));

        // The row before the attempt, so a failure has somewhere to be recorded
        // and the UI can explain why the site still has no certificate.
        let cert_dir = paths::cert_dir(&site.domain);
        let record = db
            .create_certificate(
                Some(site_id),
                CertKind::Le,
                &names,
                &cert_dir.to_string_lossy(),
            )
            .await
            .map_err(FerrumError::from)?;

        let outcome = obtain(ctx, &names, &contact, directory).await;

        let issued = match outcome {
            Ok(issued) => issued,
            Err(e) => {
                let _ = db.certificate_failed(record.id, &e.detail).await;
                return Err(e);
            }
        };

        // Files first, then the row, then the vhost: nginx must never be
        // pointed at a certificate that is not on disk yet.
        acme::write_certificate(&cert_dir, &issued)?;
        ctx.log(format!("certificate written to {}", cert_dir.display()));

        db.certificate_issued(
            record.id,
            &issued.issuer,
            issued.not_before,
            issued.not_after,
        )
        .await
        .map_err(FerrumError::from)?;

        // Re-render the vhost, which now finds a certificate and turns TLS on.
        let subscription = db
            .subscriptions(&ferrum_core::TenantScope::Global)
            .by_id(site.subscription_id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::internal("the site's subscription is missing"))?;
        let linux_user = ferrum_core::LinuxUser::parse(&subscription.linux_user)?;
        crate::site::render_vhost(ctx, &site, &linux_user).await?;

        // nginx holds certificates in memory from the moment it loads them, so
        // replacing the files on disk changes nothing until it is told to look
        // again. And the vhost text does not change on a renewal — same paths,
        // same options — so the config engine correctly reports "nothing to do"
        // and skips the reload. Without this line every renewal would appear to
        // succeed while the expiring certificate stayed live, which is the
        // failure that only shows up ninety days later.
        {
            use ferrum_config::apply::Reloader;
            let reloader = crate::services::UnitReloader::nginx(ctx.distro());
            reloader.reload().await.map_err(|e| {
                FerrumError::new(
                    ErrorCode::ConfigRollback,
                    format!("the certificate is on disk but nginx would not reload: {e}"),
                )
            })?;
            ctx.log("nginx reloaded onto the new certificate");
        }

        let days_valid = (issued.not_after - ferrum_db::now()).whole_days();
        ctx.log(format!("{} is now served over HTTPS", site.domain));

        Ok(IssueOutput {
            certificate_id: record.id,
            domains: names,
            issuer: issued.issuer,
            not_after: issued.not_after,
            days_valid,
        })
    }
}

/// Register or restore the ACME account, then run the order.
async fn obtain(
    ctx: &OpContext,
    names: &[String],
    contact: &str,
    directory: Directory,
) -> Result<acme::Issued> {
    acme::install_crypto_provider();

    let db = ctx.db();
    let key = ctx.master_key();

    let stored = db
        .acme_account(directory.url())
        .await
        .map_err(FerrumError::from)?;
    let opened = match &stored {
        Some(account) => Some(key.open_str(&account.credentials_sealed).map_err(|e| {
            FerrumError::internal(format!(
                "the stored ACME credential could not be decrypted ({e}). \
                 If /etc/ferrum/secret.key was replaced, delete the acme_accounts row \
                 and the panel will register again."
            ))
        })?),
        None => None,
    };

    let (account, fresh) =
        acme::load_or_register(opened.as_deref(), directory, Some(contact)).await?;

    if let Some(credential) = fresh {
        let sealed = key.seal_str(&credential).map_err(FerrumError::from)?;
        db.save_acme_account(directory.url(), contact, &sealed)
            .await
            .map_err(FerrumError::from)?;
        ctx.log("registered a new ACME account");
    }

    // The webroot the catch-all and every site vhost serve
    // `/.well-known/acme-challenge/` from.
    let webroot = paths::acme_webroot();
    std::fs::create_dir_all(&webroot).map_err(|e| {
        FerrumError::internal(format!("could not create {}: {e}", webroot.display()))
    })?;

    let log = |line: &str| ctx.log(line);
    acme::issue_http01(&account, &webroot, names, &log).await
}

/// Certificates the scheduler should renew now.
///
/// Kept here rather than in the scheduler so the policy — thirty days, with a
/// backoff after repeated failures — lives next to the issuance it drives.
pub fn renewal_backoff(failure_count: i64) -> time::Duration {
    // Let's Encrypt allows five failed validations per identifier per hour.
    // Doubling from fifteen minutes never puts more than four attempts in an
    // hour, and the cap means a permanently broken site retries daily rather
    // than never.
    let minutes = 15i64.saturating_mul(1 << failure_count.clamp(0, 8));
    time::Duration::minutes(minutes.min(24 * 60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_renewal_backoff_grows_and_then_stops() {
        assert_eq!(renewal_backoff(0), time::Duration::minutes(15));
        assert_eq!(renewal_backoff(1), time::Duration::minutes(30));
        assert_eq!(renewal_backoff(3), time::Duration::minutes(120));
        // Capped at a day, so a permanently broken site retries daily rather
        // than never or constantly.
        assert_eq!(renewal_backoff(20), time::Duration::hours(24));
        assert!(renewal_backoff(6) <= time::Duration::hours(24));
    }

    #[test]
    fn the_backoff_never_burns_the_hourly_failure_budget() {
        // Five failed validations per identifier per hour. Even from the first
        // failure the interval is fifteen minutes, so at most four attempts land
        // in any hour.
        let attempts_per_hour = 60 / renewal_backoff(0).whole_minutes();
        assert!(
            attempts_per_hour <= 4,
            "{attempts_per_hour} attempts per hour is too many"
        );
    }

    #[tokio::test]
    async fn issuing_for_a_site_in_another_tenant_is_not_found() {
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let (reg, _admin, customer) = registry().await;
        let err = reg
            .dispatch(
                "cert.issue",
                &auth_for(customer, Role::Customer),
                serde_json::json!({ "site_id": 999 }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }
}
