//! Bridging `ferrum-config`'s apply engine to the real services.
//!
//! The engine knows *when* to validate and reload; these types know *how* on
//! this particular machine. Keeping them apart is what lets the whole config
//! contract be tested against fakes without a running nginx.

use std::sync::Arc;

use async_trait::async_trait;
use ferrum_config::apply::{NewRevision, Reloader, RevisionStore, StoredRevision, Validator};
use ferrum_core::PhpVersion;
use ferrum_db::Db;
use ferrum_distro::svc::{ManagedUnit, SvcAction};
use ferrum_distro::{Cmd, Distro};

/// `nginx -t`.
pub struct NginxValidator;

#[async_trait]
impl Validator for NginxValidator {
    fn name(&self) -> &'static str {
        "nginx -t"
    }

    async fn validate(&self) -> Result<(), String> {
        // nginx writes its verdict to stderr on both success and failure, and
        // that text — file and line number included — is exactly what a user
        // needs to see when their custom snippet is wrong.
        match Cmd::new("nginx").arg("-t").run().await {
            Ok(out) if out.success() => Ok(()),
            Ok(out) => Err(out.failure_text()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// A validator that always passes, for machines where nginx is not installed
/// yet — writing the catch-all vhost before the package lands is legitimate.
pub struct SkipValidation;

#[async_trait]
impl Validator for SkipValidation {
    fn name(&self) -> &'static str {
        "no validator"
    }
    async fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

/// `php-fpmX -t`, which checks the whole pool tree for that version.
pub struct FpmValidator {
    binary: String,
}

impl FpmValidator {
    pub fn new(distro: &Distro, version: PhpVersion) -> Self {
        Self {
            binary: ferrum_config::paths::fpm_binary(distro.info.family, version),
        }
    }
}

#[async_trait]
impl Validator for FpmValidator {
    fn name(&self) -> &'static str {
        "php-fpm -t"
    }

    async fn validate(&self) -> Result<(), String> {
        match Cmd::new(&self.binary).arg("-t").run().await {
            Ok(out) if out.success() => Ok(()),
            Ok(out) => Err(out.failure_text()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// `mariadbd --help --verbose`, which parses the whole configuration and exits.
///
/// MariaDB has no dedicated config-test flag. This is the documented stand-in:
/// it reads every file and drop-in and fails on a bad option, without touching
/// the data directory or binding a port — so a typo in a managed drop-in is
/// caught before the restart instead of by it.
pub struct MariaDbValidator;

#[async_trait]
impl Validator for MariaDbValidator {
    fn name(&self) -> &'static str {
        "mariadbd --help --verbose"
    }

    async fn validate(&self) -> Result<(), String> {
        match Cmd::new("mariadbd")
            .args(["--help", "--verbose"])
            .run()
            .await
        {
            Ok(out) if out.success() => Ok(()),
            Ok(out) => Err(out.failure_text()),
            // Not installed yet: the config engine writes the drop-in before
            // the first start on a fresh install, and a validator that fails
            // for "the binary is missing" would block that.
            Err(e) => {
                tracing::debug!(error = %e, "mariadbd not runnable; skipping validation");
                Ok(())
            }
        }
    }
}

/// Reload a managed unit.
pub struct UnitReloader {
    distro: Distro,
    unit: ManagedUnit,
    /// Reload where the service supports it, restart where it does not.
    action: SvcAction,
}

impl UnitReloader {
    /// nginx reloads without dropping a connection, which is why every site
    /// change is a reload and not a restart.
    pub fn nginx(distro: &Distro) -> Self {
        Self {
            distro: distro.clone(),
            unit: ManagedUnit::Nginx,
            action: SvcAction::Reload,
        }
    }

    /// MariaDB has no reload that re-reads `bind-address`: the listener is
    /// bound at start-up, so making it loopback-only means a restart.
    pub fn mariadb(distro: &Distro) -> Self {
        Self {
            distro: distro.clone(),
            unit: ManagedUnit::MariaDb,
            action: SvcAction::Restart,
        }
    }

    pub fn fpm(distro: &Distro, version: PhpVersion) -> Self {
        Self {
            distro: distro.clone(),
            unit: ManagedUnit::PhpFpm { version },
            // php-fpm's reload (SIGUSR2) re-reads pool files and drains workers
            // gracefully, so an in-flight request is not killed mid-response.
            action: SvcAction::Reload,
        }
    }
}

#[async_trait]
impl Reloader for UnitReloader {
    fn name(&self) -> &'static str {
        "systemd unit"
    }

    async fn reload(&self) -> Result<(), String> {
        let family = self.distro.info.family;
        let unit = self.unit.unit_name(family);

        // Reloading a unit that is not running is not a failure — a fresh
        // install writes its first vhost before nginx has ever started.
        let status = self
            .distro
            .svc
            .status(&unit)
            .await
            .map_err(|e| e.to_string())?;
        if !status.is_installed() || !status.is_active() {
            tracing::debug!(unit = %unit, "not running; nothing to reload");
            return Ok(());
        }

        self.distro
            .svc
            .action(&unit, self.action)
            .await
            .map_err(|e| e.to_string())
    }
}

/// A reloader that does nothing, for the same reason [`SkipValidation`] exists.
pub struct NoReload;

#[async_trait]
impl Reloader for NoReload {
    fn name(&self) -> &'static str {
        "none"
    }
    async fn reload(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Stores config revisions in the panel database (spec §10.4 rule 5).
pub struct DbRevisions {
    db: Db,
}

impl DbRevisions {
    pub fn new(db: Db) -> Arc<Self> {
        Arc::new(Self { db })
    }
}

#[async_trait]
impl RevisionStore for DbRevisions {
    async fn record(&self, revision: NewRevision) -> Result<i64, String> {
        self.db
            .record_revision(
                &revision.path,
                &revision.sha256,
                &revision.content,
                revision.rendered_by_task.as_deref(),
            )
            .await
            .map_err(|e| e.to_string())
    }

    async fn active(&self, path: &str) -> Result<Option<StoredRevision>, String> {
        let found = self
            .db
            .active_revision(path)
            .await
            .map_err(|e| e.to_string())?;
        Ok(found.map(|r| StoredRevision {
            id: r.id,
            path: r.path,
            sha256: r.sha256,
            content: r.content.unwrap_or_default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_distro::Family;

    #[tokio::test]
    async fn reloading_a_service_that_is_not_running_is_not_a_failure() {
        // A fresh install writes the catch-all vhost before nginx has ever
        // started; failing there would make the first install look broken.
        let distro = Distro::mock();
        let reloader = UnitReloader::nginx(&distro);
        assert!(reloader.reload().await.is_ok());
    }

    #[tokio::test]
    async fn reloading_a_running_service_issues_a_reload_not_a_restart() {
        let (distro, recorder) = ferrum_distro::mock::mock_distro_with_recorder(Family::Debian);
        let unit = ManagedUnit::Nginx.unit_name(Family::Debian);
        distro.svc.action(&unit, SvcAction::Start).await.unwrap();

        UnitReloader::nginx(&distro).reload().await.unwrap();

        let actions = &recorder.lock().unwrap().service_actions;
        assert!(
            actions
                .iter()
                .any(|(u, a)| u == "nginx.service" && *a == SvcAction::Reload),
            "nginx must be reloaded, not restarted: dropping every connection to \
             activate a vhost is exactly what a panel must not do — got {actions:?}"
        );
        assert!(!actions.iter().any(|(_, a)| *a == SvcAction::Restart));
    }

    #[tokio::test]
    async fn the_fpm_validator_uses_the_right_binary_per_family() {
        let debian = Distro::mock();
        let validator = FpmValidator::new(&debian, PhpVersion::V83);
        assert_eq!(validator.binary, "php-fpm8.3");

        let (rhel, _) = ferrum_distro::mock::mock_distro_with_recorder(Family::Rhel);
        let validator = FpmValidator::new(&rhel, PhpVersion::V83);
        assert!(
            validator.binary.contains("/opt/remi/php83/"),
            "{}",
            validator.binary
        );
    }

    #[tokio::test]
    async fn revisions_round_trip_through_the_database() {
        let db = Db::open_memory().await.unwrap();
        let store = DbRevisions::new(db);

        let id = store
            .record(NewRevision {
                path: "/etc/nginx/ferrum.d/site-a.conf".into(),
                sha256: "abc".into(),
                content: "server {}".into(),
                rendered_by_task: Some("task-1".into()),
            })
            .await
            .unwrap();

        let active = store
            .active("/etc/nginx/ferrum.d/site-a.conf")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.id, id);
        assert_eq!(active.content, "server {}");
        assert!(
            store
                .active("/etc/nginx/ferrum.d/nothing.conf")
                .await
                .unwrap()
                .is_none()
        );
    }
}
