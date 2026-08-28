//! The Stack Manager (spec §11.1): installing nginx and PHP from upstream.
//!
//! A base install ships the panel binary and nothing else. Everything the server
//! actually serves with arrives through here, on demand, from the vendor's own
//! repository — which is what keeps a fresh install small enough for a 1 GB VPS
//! and makes security updates the vendor's job.

use std::time::Duration;

use async_trait::async_trait;
use ferrum_config::apply::ApplyRequest;
use ferrum_config::managed::ManagedFile;
use ferrum_config::paths;
use ferrum_core::{ErrorCode, FerrumError, Permission, PhpVersion, Result};
use ferrum_db::ComponentStatus;
use ferrum_distro::fw::{PortRule, Proto};
use ferrum_distro::repos::{MARIADB_SERIES, POSTGRES_MAJOR};
use ferrum_distro::svc::ManagedUnit;
use ferrum_distro::{Cmd, Distro, Family, PackageName};
use serde::{Deserialize, Serialize};

use crate::php::{PhpExt, packages_for};
use crate::registry::{Execution, OpContext, TypedOperation};
use crate::services::{NginxValidator, NoReload, SkipValidation, UnitReloader};

/// A component the Stack Manager can install.
///
/// Typed, so an API caller cannot ask the panel to `apt install` something of
/// their choosing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "component", rename_all = "snake_case")]
pub enum StackComponent {
    Nginx,
    Php {
        version: PhpVersion,
    },
    /// MariaDB, the default database engine (spec §11.4).
    Mariadb,
    /// PostgreSQL from PGDG (spec §11.4).
    Postgres,
}

impl StackComponent {
    /// Stable key for the `stack_components` table.
    pub fn slug(self) -> String {
        match self {
            StackComponent::Nginx => "nginx".into(),
            StackComponent::Php { version } => format!("php{}", version.as_str()),
            StackComponent::Mariadb => "mariadb".into(),
            StackComponent::Postgres => "postgres".into(),
        }
    }

    pub fn display_name(self) -> String {
        match self {
            StackComponent::Nginx => "Nginx".into(),
            StackComponent::Php { version } => format!("PHP {}", version.as_str()),
            // The version the panel would install is part of the offer the UI
            // makes, not an implementation detail — show it.
            StackComponent::Mariadb => format!("MariaDB {MARIADB_SERIES}"),
            StackComponent::Postgres => format!("PostgreSQL {POSTGRES_MAJOR}"),
        }
    }

    /// The repository this component comes from.
    fn repo(self, distro: &Distro) -> Result<ferrum_distro::ResolvedRepo> {
        let info = &distro.info;
        let resolved = match self {
            StackComponent::Nginx => ferrum_distro::repos::nginx(info),
            StackComponent::Php { .. } => ferrum_distro::repos::php(info),
            StackComponent::Mariadb => ferrum_distro::repos::mariadb(info, MARIADB_SERIES),
            StackComponent::Postgres => ferrum_distro::repos::pgdg(info),
        };
        resolved.map_err(|e| FerrumError::new(ErrorCode::UnsupportedDistro, e))
    }

    fn packages(self, distro: &Distro, extensions: &[PhpExt]) -> Result<Vec<PackageName>> {
        match self {
            StackComponent::Nginx => parse_packages(&["nginx"]),
            StackComponent::Php { version } => {
                packages_for(distro.info.family, version, extensions)
            }
            StackComponent::Mariadb => match distro.info.family {
                // Package names verified against the live 11.8 repository
                // indexes on both families.
                //
                // The `*-compat` pair is listed explicitly because nothing
                // depends on it: since 11.x the binaries are `mariadb` /
                // `mariadbd`, and the compat packages are what still provides
                // the `mysql`/`mysqld` entry points that most applications,
                // scripts and health checks actually invoke.
                Family::Debian => parse_packages(&[
                    "mariadb-server",
                    "mariadb-client",
                    "mariadb-backup",
                    "mariadb-server-compat",
                    "mariadb-client-compat",
                ]),
                // Capital M, deliberately: MariaDB plc names its own RPMs
                // `MariaDB-*` precisely so they stay distinct from Red Hat's
                // lowercase `mariadb-*` AppStream packages. Asking dnf for the
                // lowercase names here would install the distribution's older
                // build instead of the repository we just pinned.
                Family::Rhel => parse_packages(&[
                    "MariaDB-server",
                    "MariaDB-client",
                    "MariaDB-backup",
                    "MariaDB-server-compat",
                    "MariaDB-client-compat",
                ]),
            },
            StackComponent::Postgres => match distro.info.family {
                // PGDG apt selects the major by package name; `postgresql-17`
                // pulls the server, `postgresql-client-17` the tools.
                Family::Debian => parse_packages(&[
                    &format!("postgresql-{POSTGRES_MAJOR}"),
                    &format!("postgresql-client-{POSTGRES_MAJOR}"),
                ]),
                // PGDG rpm naming: `postgresql17-server` is the daemon,
                // `postgresql17` the client, `-contrib` the standard extension
                // set (pg_stat_statements et al.) a hosting box wants anyway.
                Family::Rhel => parse_packages(&[
                    &format!("postgresql{POSTGRES_MAJOR}-server"),
                    &format!("postgresql{POSTGRES_MAJOR}"),
                    &format!("postgresql{POSTGRES_MAJOR}-contrib"),
                ]),
            },
        }
    }

    fn unit(self) -> ManagedUnit {
        match self {
            StackComponent::Nginx => ManagedUnit::Nginx,
            StackComponent::Php { version } => ManagedUnit::PhpFpm { version },
            StackComponent::Mariadb => ManagedUnit::MariaDb,
            StackComponent::Postgres => ManagedUnit::PostgreSql,
        }
    }
}

fn parse_packages(names: &[&str]) -> Result<Vec<PackageName>> {
    names
        .iter()
        .map(|n| {
            PackageName::parse(n)
                .map_err(|e| FerrumError::new(ErrorCode::InvalidInput, e.to_string()))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// stack.status
// ---------------------------------------------------------------------------

/// `stack.status` — what is installed, and what the panel could install.
pub struct Status;

#[derive(Debug, Deserialize)]
pub struct StatusInput {}

#[derive(Debug, Serialize)]
pub struct ComponentView {
    pub slug: String,
    pub display_name: String,
    pub status: String,
    pub installed_version: Option<String>,
    pub last_error: Option<String>,
    /// The service's own view, which can disagree with ours if somebody removed
    /// a package by hand.
    pub unit_state: String,
    pub unit_active: bool,
}

#[derive(Debug, Serialize)]
pub struct StatusOutput {
    pub components: Vec<ComponentView>,
    /// Repository pins that have not been independently corroborated yet.
    pub unverified_pins: &'static [&'static str],
}

#[async_trait]
impl TypedOperation for Status {
    type Input = StatusInput;
    type Output = StatusOutput;

    const NAME: &'static str = "stack.status";
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let distro = ctx.distro();
        let recorded = ctx.db().components().await.map_err(FerrumError::from)?;

        let mut candidates = vec![StackComponent::Nginx];
        candidates.extend(
            PhpVersion::ALL
                .iter()
                .map(|&version| StackComponent::Php { version }),
        );
        // The database engines (spec §11.4) — listed after the web stack, the
        // order the UI presents them in.
        candidates.push(StackComponent::Mariadb);
        candidates.push(StackComponent::Postgres);

        let mut components = Vec::new();
        for candidate in candidates {
            let slug = candidate.slug();
            let row = recorded.iter().find(|c| c.slug == slug);

            // Ask systemd as well as the database: a package removed by hand
            // should show up as a disagreement, not as a lie.
            let unit = candidate.unit().unit_name(distro.info.family);
            let unit_status = distro.svc.status(&unit).await.ok();

            components.push(ComponentView {
                slug,
                display_name: candidate.display_name(),
                status: row
                    .map(|c| c.status.as_str().to_string())
                    .unwrap_or_else(|| ComponentStatus::Absent.as_str().to_string()),
                installed_version: row.and_then(|c| c.installed_version.clone()),
                last_error: row.and_then(|c| c.last_error.clone()),
                unit_state: unit_status
                    .as_ref()
                    .map(|s| format!("{:?}", s.state).to_lowercase())
                    .unwrap_or_else(|| "unknown".into()),
                unit_active: unit_status.map(|s| s.is_active()).unwrap_or(false),
            });
        }

        Ok(StatusOutput {
            components,
            unverified_pins: ferrum_distro::repos::UNVERIFIED_PINS,
        })
    }
}

// ---------------------------------------------------------------------------
// stack.install
// ---------------------------------------------------------------------------

/// `stack.install` — add the repository, install the packages, start the service.
pub struct Install;

#[derive(Debug, Deserialize)]
pub struct InstallInput {
    #[serde(flatten)]
    pub component: StackComponent,
    /// Extensions to install alongside a PHP version. Empty means the default
    /// set that mainstream applications assume.
    #[serde(default)]
    pub extensions: Vec<PhpExt>,
}

#[derive(Debug, Serialize)]
pub struct InstallOutput {
    pub slug: String,
    pub installed_version: Option<String>,
    pub packages: Vec<String>,
}

#[async_trait]
impl TypedOperation for Install {
    type Input = InstallInput;
    type Output = InstallOutput;

    const NAME: &'static str = "stack.install";
    const PERMISSION: Permission = Permission::StackManage;
    // Minutes, not milliseconds. Streams the package manager's output so the
    // user can see it working rather than watching a spinner.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let component = input.component;
        let slug = component.slug();
        let db = ctx.db().clone();

        let task_id = ctx.task_id().map(|t| t.to_string()).unwrap_or_default();
        if !db
            .claim_component(&slug, ComponentStatus::Installing, &task_id)
            .await
            .map_err(FerrumError::from)?
        {
            return Err(FerrumError::new(
                ErrorCode::Conflict,
                format!(
                    "{} is already being installed or removed",
                    component.display_name()
                ),
            ));
        }

        let outcome = install_component(ctx, component, &input.extensions).await;

        match &outcome {
            Ok(out) => {
                db.component_installed(&slug, out.installed_version.as_deref())
                    .await
                    .map_err(FerrumError::from)?;
            }
            Err(e) => {
                // Record before returning, so the UI can explain a failure that
                // happened while nobody was watching.
                let _ = db.component_failed(&slug, &e.detail).await;
            }
        }

        outcome
    }
}

async fn install_component(
    ctx: &OpContext,
    component: StackComponent,
    extensions: &[PhpExt],
) -> Result<InstallOutput> {
    let distro = ctx.distro().clone();
    let log = ctx.log_sink();

    // 1. The repository, with its key verified against the pin.
    let repo = component.repo(&distro)?;
    ctx.log(format!(
        "adding {} ({})",
        repo.definition.display_name, repo.definition.base_url
    ));
    if repo.provenance == ferrum_distro::Provenance::SingleSource {
        ctx.log(format!(
            "note: this repository's key pin comes from a single source ({}); \
             verify it against the vendor before relying on it in production",
            repo.source
        ));
    }

    // Whatever this repository's packages depend on, first. Doing it after would
    // mean the install fails on a missing library with an error that never names
    // the archive it lives in.
    for prerequisite in &repo.prerequisites {
        distro.pkg.ensure_prerequisite(prerequisite, log).await?;
    }

    let key = fetch_key(&repo.definition.gpg_key_url).await?;
    ctx.log(format!("fetched {} bytes of key material", key.len()));
    distro
        .pkg
        .add_repo(&repo.definition, &key, &repo.options, log)
        .await?;

    // 2. The packages.
    let extensions = if extensions.is_empty() {
        PhpExt::DEFAULT
    } else {
        extensions
    };
    let packages = component.packages(&distro, extensions)?;
    ctx.log(format!(
        "installing {}",
        packages
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    ));
    distro.pkg.install(&packages, log).await?;

    // 3. Anything the component needs before it can usefully start.
    if component == StackComponent::Nginx {
        bootstrap_nginx(ctx).await?;
    }
    // A database the panel installed is a database the panel is answerable for.
    if component == StackComponent::Mariadb {
        crate::harden::mariadb(ctx).await?;
    }
    if let StackComponent::Php { version } = component {
        // Before it starts, so the stock `www` pool never gets to spawn a
        // single worker as the web server user.
        crate::fpm::retire_and_log(ctx, version).await;
    }
    if component == StackComponent::Postgres {
        // On EL the versioned unit refuses to start until initdb has run;
        // Debian's postgresql-common already created the cluster in postinst.
        bootstrap_postgres(ctx).await?;
    }
    if component == StackComponent::Mariadb && distro.info.family == Family::Rhel {
        // `MariaDB-server` only *recommends* the SELinux policy package, and
        // weak-dependency installation can be disabled host-wide. On an
        // enforcing host a missing policy surfaces later as mysterious
        // `mysqld_safe` denials — say so now, in the task log, where the
        // operator will actually look. Warn, never fail: a lab VM with SELinux
        // permissive is not a broken install.
        warn_if_mysql_selinux_missing(ctx).await;
    }

    // 4. Start it, and make it come back after a reboot.
    let unit = component.unit().unit_name(distro.info.family);
    distro.svc.enable(&unit, true).await?;
    ctx.log(format!("{unit} enabled and started"));

    // 4b. For a database, "started" is not "ready": both engines accept the
    // systemd start-up notification before they accept connections on a slow
    // first boot (InnoDB initialisation, crash recovery). Handing the operator
    // a component marked installed that refuses connections would make every
    // follow-up step (create database, create user) fail confusingly.
    wait_until_ready(ctx, component).await?;

    // 5. Report the version actually installed, not the one we asked for.
    let installed_version = distro
        .pkg
        .query(&packages[0])
        .await
        .ok()
        .and_then(|s| s.installed_version);

    Ok(InstallOutput {
        slug: component.slug(),
        installed_version,
        packages: packages.iter().map(|p| p.as_str().to_string()).collect(),
    })
}

/// Everything nginx needs before it is worth starting.
///
/// The include hook, a default server, and a certificate for it — an nginx with
/// no `default_server` serves whichever vhost it parsed first to a request for
/// an unknown host, which is how one customer's site answers for another's
/// domain.
pub async fn bootstrap_nginx(ctx: &OpContext) -> Result<()> {
    let engine = ctx.config();

    // A self-signed certificate for the catch-all. It is not meant to be
    // trusted; it exists so TLS on the default server is *something*.
    let default_certs = paths::default_cert_dir();
    if !crate::tls::certificate_present(&default_certs) {
        crate::tls::write_self_signed(&default_certs, &[])?;
        ctx.log("generated a self-signed certificate for the default server");
    }

    // The ACME webroot has to exist before the first challenge, and nginx's
    // *workers* have to be able to reach it at request time.
    //
    // This is not the same as reading a certificate: nginx opens those as root
    // during a reload, before dropping privileges. A challenge file is fetched
    // by a worker running as `nginx`, and `/var/lib/ferrum` is 0750 ferrum:ferrum
    // — so without this the CA gets a 404 and nginx logs
    // `stat() failed (13: Permission denied)` where nobody looks.
    //
    // `o+x` grants traversal, not listing. `panel.db` (0640) and private keys
    // (0600) stay unreadable to everyone else either way.
    let challenge_dir = paths::acme_webroot().join(".well-known/acme-challenge");
    std::fs::create_dir_all(&challenge_dir)
        .map_err(|e| FerrumError::internal(format!("could not create the ACME webroot: {e}")))?;
    make_traversable(&[paths::data_dir(), paths::state_dir()])?;
    set_mode(&paths::acme_webroot(), 0o755)?;
    set_mode(&challenge_dir, 0o755)?;

    std::fs::create_dir_all(paths::site_log_root())
        .map_err(|e| FerrumError::internal(format!("could not create the log directory: {e}")))?;

    // The include hook. Written with no validator: nginx may not be running yet,
    // and `nginx -t` on a tree that does not include this file cannot test it.
    engine
        .apply(ApplyRequest {
            file: ManagedFile::nginx(paths::nginx_hook()),
            template: "nginx/ferrum.conf",
            context: serde_json::json!({ "nginx_dir": paths::nginx_dir() }),
            service: "nginx",
            validator: &SkipValidation,
            reloader: &NoReload,
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;

    // The default server. Now nginx -t can see the whole tree.
    engine
        .apply(ApplyRequest {
            file: ManagedFile::nginx(paths::nginx_catchall()),
            template: "nginx/catchall.conf",
            context: serde_json::json!({
                "acme_webroot": paths::acme_webroot(),
                "default_cert": default_certs.join("fullchain.pem"),
                "default_key": default_certs.join("privkey.pem"),
                // HTTP/3 needs UDP/443 open; enabling it by default would make
                // the panel depend on a firewall change nobody made.
                "http3": false,
            }),
            service: "nginx",
            validator: &NginxValidator,
            reloader: &UnitReloader::nginx(ctx.distro()),
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;

    ctx.log("default server configured");

    // The web ports. An nginx that is running but unreachable is the single
    // most confusing state a new panel can be in, and it is what the operator
    // gets on a distro image that ships firewalld enabled with only SSH open.
    open_web_ports(ctx).await;

    Ok(())
}

/// Open 80 and 443, if there is a firewall to open them in.
///
/// Deliberately never fatal. A firewall that refuses the change must not undo an
/// otherwise-successful nginx install, and a host with no firewall at all is not
/// an error — the ports are already reachable there. Either way the task log
/// says exactly what happened, because "why can I not reach my site" is
/// answered by that line.
async fn open_web_ports(ctx: &OpContext) {
    let fw = &ctx.distro().fw;

    match fw.is_active().await {
        Ok(true) => {}
        Ok(false) => {
            ctx.log(format!(
                "no active firewall ({}); ports 80 and 443 need no change",
                fw.name()
            ));
            return;
        }
        Err(e) => {
            ctx.log(format!(
                "could not query the firewall ({e}); leaving it alone"
            ));
            return;
        }
    }

    for (port, what) in [(80u16, "http"), (443, "https")] {
        let rule = PortRule::anywhere(port, Proto::Tcp, what);
        match fw.open_port(&rule).await {
            Ok(()) => ctx.log(format!("opened {port}/tcp in {}", fw.name())),
            Err(e) => ctx.log(format!(
                "could not open {port}/tcp in {}: {e} — the site will not be \
                 reachable from outside until this port is open",
                fw.name()
            )),
        }
    }
}

/// What PostgreSQL needs before its unit can start.
///
/// On the RHEL family the PGDG packages install binaries and a unit but **no
/// data directory** — `postgresql-17.service` exits immediately with
/// "Directory /var/lib/pgsql/17/data is missing or empty" until initdb has run.
/// PGDG ships a setup script for exactly this, and its argv is the documented
/// install step: `/usr/pgsql-17/bin/postgresql-17-setup initdb`.
///
/// On the Debian family there is nothing to do: postgresql-common's postinst
/// creates and starts the default `main` cluster during package installation.
async fn bootstrap_postgres(ctx: &OpContext) -> Result<()> {
    if ctx.distro().info.family != Family::Rhel {
        ctx.log("postgresql-common created the default cluster during package install");
        return Ok(());
    }

    // The marker initdb itself writes. Present means a previous install (or the
    // operator) already initialised this directory — running initdb again would
    // fail on the non-empty directory, and must not, because reinstalling a
    // component is idempotent (spec §11.1).
    let marker = format!("/var/lib/pgsql/{POSTGRES_MAJOR}/data/PG_VERSION");
    if std::path::Path::new(&marker).exists() {
        ctx.log("data directory already initialised; skipping initdb");
        return Ok(());
    }

    ctx.log("initialising the PostgreSQL data directory");
    Cmd::new(format!(
        "/usr/pgsql-{POSTGRES_MAJOR}/bin/postgresql-{POSTGRES_MAJOR}-setup"
    ))
    .arg("initdb")
    .run_checked()
    .await
    .map_err(FerrumError::from)?;
    ctx.log("initdb complete");
    Ok(())
}

/// Warn when the SELinux policy for MariaDB did not come along. Never fatal.
async fn warn_if_mysql_selinux_missing(ctx: &OpContext) {
    // `rpm -q` exits non-zero for "not installed"; that is data here, not an
    // error, so `run` rather than `run_checked`.
    match Cmd::new("rpm").args(["-q", "mysql-selinux"]).run().await {
        Ok(out) if out.success() => {
            ctx.log(format!("SELinux policy present: {}", out.trimmed_stdout()));
        }
        _ => ctx.log(
            "warning: mysql-selinux is not installed — on an SELinux-enforcing host, \
             MariaDB may be denied access to its own files. Install it from the \
             distribution's repositories.",
        ),
    }
}

/// One readiness attempt for a database component. `None` for components whose
/// systemd "active" already means "serving" (nginx, php-fpm).
///
/// Both probes run as root over the local socket and need no credentials:
/// MariaDB's root account authenticates via `unix_socket` on a fresh install,
/// and `pg_isready` only sends an empty startup packet.
fn readiness_probe(component: StackComponent, family: Family) -> Option<Cmd> {
    match component {
        StackComponent::Mariadb => Some(
            // `--no-defaults` first (it must be the first argument to any
            // MySQL-family tool): the probe must not be steered by an
            // /etc/my.cnf or ~/.my.cnf an operator left behind.
            Cmd::new("mariadb").args([
                "--no-defaults",
                "--protocol=socket",
                "--user=root",
                "--connect-timeout=3",
                "--execute",
                "SELECT 1",
            ]),
        ),
        StackComponent::Postgres => Some(match family {
            // Debian's postgresql-client-common puts a version-routing
            // `pg_isready` on PATH; PGDG on EL installs only versioned paths.
            Family::Debian => Cmd::new("pg_isready").arg("--quiet"),
            Family::Rhel => {
                Cmd::new(format!("/usr/pgsql-{POSTGRES_MAJOR}/bin/pg_isready")).arg("--quiet")
            }
        }),
        StackComponent::Nginx | StackComponent::Php { .. } => None,
    }
}

/// Poll a component's readiness probe until it answers, with bounded backoff.
///
/// The schedule (500 ms doubling, capped at 5 s, 12 attempts) allows roughly
/// 45 seconds — generous enough for InnoDB's first-boot initialisation on a
/// 1 GB VPS, small enough that a genuinely broken service fails the task while
/// somebody is still watching it.
async fn wait_until_ready(ctx: &OpContext, component: StackComponent) -> Result<()> {
    const ATTEMPTS: u32 = 12;
    let Some(probe) = readiness_probe(component, ctx.distro().info.family) else {
        return Ok(());
    };

    let mut delay = Duration::from_millis(500);
    let mut last_failure = String::new();
    for attempt in 1..=ATTEMPTS {
        match probe.run().await {
            Ok(out) if out.success() => {
                ctx.log(format!(
                    "{} is accepting connections (attempt {attempt})",
                    component.display_name()
                ));
                return Ok(());
            }
            Ok(out) => last_failure = out.failure_text(),
            // A missing binary or spawn failure is as retryable as a refused
            // connection here — and if it persists, the final error says why.
            Err(e) => last_failure = e.to_string(),
        }
        if attempt < ATTEMPTS {
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(5));
        }
    }

    Err(FerrumError::new(
        ErrorCode::ServiceActionFailed,
        format!(
            "{} started but never became ready to accept connections: {last_failure}",
            component.display_name()
        ),
    ))
}

// ---------------------------------------------------------------------------
// stack.remove
// ---------------------------------------------------------------------------

/// `stack.remove` — remove a component, refusing while anything depends on it.
pub struct Remove;

#[derive(Debug, Deserialize)]
pub struct RemoveInput {
    #[serde(flatten)]
    pub component: StackComponent,
}

#[derive(Debug, Serialize)]
pub struct RemoveOutput {
    pub slug: String,
}

#[async_trait]
impl TypedOperation for Remove {
    type Input = RemoveInput;
    type Output = RemoveOutput;

    const NAME: &'static str = "stack.remove";
    const PERMISSION: Permission = Permission::StackManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let component = input.component;
        let slug = component.slug();
        let db = ctx.db().clone();

        // Removing PHP 8.3 while sites are running on it takes those sites down
        // (spec §11.1). Refuse and say which ones.
        if let StackComponent::Php { version } = component {
            let dependents: Vec<String> = db
                .all_sites()
                .await
                .map_err(FerrumError::from)?
                .into_iter()
                .filter(|s| s.php_version == Some(version))
                .map(|s| s.domain)
                .collect();

            if !dependents.is_empty() {
                return Err(FerrumError::new(
                    ErrorCode::DependentsExist,
                    format!(
                        "{} sites still use PHP {}: {}. Move them to another version first.",
                        dependents.len(),
                        version.as_str(),
                        dependents.join(", ")
                    ),
                ));
            }
        }

        if component == StackComponent::Nginx {
            let site_count = db.all_sites().await.map_err(FerrumError::from)?.len();
            if site_count > 0 {
                return Err(FerrumError::new(
                    ErrorCode::DependentsExist,
                    format!(
                        "{site_count} sites are still configured; removing nginx would take them all offline"
                    ),
                ));
            }
        }

        let task_id = ctx.task_id().map(|t| t.to_string()).unwrap_or_default();
        if !db
            .claim_component(&slug, ComponentStatus::Removing, &task_id)
            .await
            .map_err(FerrumError::from)?
        {
            return Err(FerrumError::new(
                ErrorCode::Conflict,
                format!(
                    "{} is already being installed or removed",
                    component.display_name()
                ),
            ));
        }

        let distro = ctx.distro().clone();
        let unit = component.unit().unit_name(distro.info.family);
        let _ = distro.svc.disable(&unit, true).await;

        let packages = component.packages(&distro, PhpExt::DEFAULT)?;
        let outcome = distro.pkg.remove(&packages, ctx.log_sink()).await;

        match outcome {
            Ok(_) => {
                db.component_removed(&slug)
                    .await
                    .map_err(FerrumError::from)?;
                Ok(RemoveOutput { slug })
            }
            Err(e) => {
                let _ = db.component_failed(&slug, &e.to_string()).await;
                Err(e.into())
            }
        }
    }
}

/// Add the execute bit for "other" so a service running as another account can
/// traverse into a subdirectory, without being able to list what is there.
fn make_traversable(dirs: &[std::path::PathBuf]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    for dir in dirs {
        let Ok(metadata) = std::fs::metadata(dir) else {
            continue;
        };
        let mode = metadata.permissions().mode() & 0o7777;
        if mode & 0o001 == 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode | 0o001)).map_err(
                |e| FerrumError::internal(format!("could not chmod {}: {e}", dir.display())),
            )?;
        }
    }
    Ok(())
}

fn set_mode(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| FerrumError::internal(format!("could not chmod {}: {e}", path.display())))
}

/// Download a repository's signing key.
///
/// Bounded and short-timeout: this runs inside a task the user is watching, and
/// a vendor whose key server is down should produce a clear failure rather than
/// a hung install.
async fn fetch_key(url: &str) -> Result<Vec<u8>> {
    /// No vendor's keyring is anywhere near this large.
    const MAX_KEY_BYTES: usize = 1024 * 1024;

    if !url.starts_with("https://") {
        return Err(FerrumError::internal(format!(
            "refusing to fetch a key over `{url}`"
        )));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("ferrum/", env!("CARGO_PKG_VERSION")))
        // A redirect to http:// would silently drop the transport security we
        // are relying on to bootstrap trust.
        .https_only(true)
        .build()
        .map_err(|e| FerrumError::internal(format!("could not build an HTTP client: {e}")))?;

    let response = client.get(url).send().await.map_err(|e| {
        FerrumError::new(
            ErrorCode::PackageBackendFailed,
            format!("could not fetch the signing key from {url}: {e}"),
        )
    })?;

    if !response.status().is_success() {
        return Err(FerrumError::new(
            ErrorCode::PackageBackendFailed,
            format!("{url} returned {}", response.status()),
        ));
    }

    let bytes = response.bytes().await.map_err(|e| {
        FerrumError::new(
            ErrorCode::PackageBackendFailed,
            format!("could not read {url}: {e}"),
        )
    })?;

    if bytes.len() > MAX_KEY_BYTES {
        return Err(FerrumError::new(
            ErrorCode::PackageBackendFailed,
            format!("{url} served {} bytes, which is not a keyring", bytes.len()),
        ));
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_is_granted_without_granting_a_listing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("state");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o750)).unwrap();

        make_traversable(std::slice::from_ref(&target)).unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o751,
            "expected traverse-only for other, got {mode:o}"
        );
        assert_eq!(
            mode & 0o004,
            0,
            "`other` must not be able to list the directory"
        );
    }

    #[test]
    fn making_a_directory_traversable_twice_changes_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("state");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        make_traversable(std::slice::from_ref(&target)).unwrap();
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn component_slugs_are_stable_and_distinct() {
        assert_eq!(StackComponent::Nginx.slug(), "nginx");
        assert_eq!(
            StackComponent::Php {
                version: PhpVersion::V83
            }
            .slug(),
            "php8.3"
        );

        assert_eq!(StackComponent::Mariadb.slug(), "mariadb");
        assert_eq!(StackComponent::Postgres.slug(), "postgres");

        let mut slugs: Vec<String> = PhpVersion::ALL
            .iter()
            .map(|&version| StackComponent::Php { version }.slug())
            .collect();
        slugs.push(StackComponent::Nginx.slug());
        slugs.push(StackComponent::Mariadb.slug());
        slugs.push(StackComponent::Postgres.slug());
        let unique: std::collections::HashSet<_> = slugs.iter().collect();
        assert_eq!(
            unique.len(),
            slugs.len(),
            "slugs must not collide: {slugs:?}"
        );
    }

    #[test]
    fn a_component_cannot_be_an_arbitrary_package() {
        // The whole point of the enum: no API caller can ask the panel to
        // `apt install` something of their choosing.
        assert!(serde_json::from_str::<StackComponent>(r#"{"component":"nginx"}"#).is_ok());
        assert!(
            serde_json::from_str::<StackComponent>(r#"{"component":"php","version":"8.3"}"#)
                .is_ok()
        );
        assert!(serde_json::from_str::<StackComponent>(r#"{"component":"mariadb"}"#).is_ok());
        assert!(serde_json::from_str::<StackComponent>(r#"{"component":"postgres"}"#).is_ok());
        for bad in [
            r#"{"component":"backdoor"}"#,
            r#"{"component":"php","version":"9.9"}"#,
            r#""nginx; rm -rf /""#,
        ] {
            assert!(
                serde_json::from_str::<StackComponent>(bad).is_err(),
                "{bad} should not parse"
            );
        }
    }

    #[test]
    fn nginx_installs_exactly_one_package() {
        let distro = Distro::mock();
        let packages = StackComponent::Nginx.packages(&distro, &[]).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].as_str(), "nginx");
    }

    #[test]
    fn php_pulls_its_family_specific_package_set() {
        let debian = Distro::mock();
        let packages = StackComponent::Php {
            version: PhpVersion::V83,
        }
        .packages(&debian, PhpExt::DEFAULT)
        .unwrap();
        assert!(packages.iter().any(|p| p.as_str() == "php8.3-fpm"));
        assert!(packages.iter().any(|p| p.as_str() == "php8.3-curl"));

        let (rhel, _) = ferrum_distro::mock::mock_distro_with_recorder(ferrum_distro::Family::Rhel);
        let packages = StackComponent::Php {
            version: PhpVersion::V83,
        }
        .packages(&rhel, PhpExt::DEFAULT)
        .unwrap();
        assert!(packages.iter().any(|p| p.as_str() == "php83-php-fpm"));
        assert!(
            !packages.iter().any(|p| p.as_str().contains("curl")),
            "Remi has no curl package; asking for one fails the transaction"
        );
    }

    #[test]
    fn every_component_resolves_a_pinned_repository_on_both_families() {
        for family in [ferrum_distro::Family::Debian, ferrum_distro::Family::Rhel] {
            let (distro, _) = ferrum_distro::mock::mock_distro_with_recorder(family);
            for component in [
                StackComponent::Nginx,
                StackComponent::Php {
                    version: PhpVersion::V83,
                },
                StackComponent::Mariadb,
                StackComponent::Postgres,
            ] {
                let repo = component.repo(&distro).unwrap();
                assert!(!repo.definition.accepted_fingerprints.is_empty());
                repo.definition.validate().unwrap();
            }
        }
    }

    #[test]
    fn mariadb_packages_are_capital_m_on_el_and_include_the_compat_pair() {
        // Lowercase names on EL would resolve to the distribution's own
        // AppStream build, not the pinned vendor repository.
        let (rhel, _) = ferrum_distro::mock::mock_distro_with_recorder(ferrum_distro::Family::Rhel);
        let names: Vec<String> = StackComponent::Mariadb
            .packages(&rhel, &[])
            .unwrap()
            .iter()
            .map(|p| p.as_str().to_string())
            .collect();
        assert!(names.contains(&"MariaDB-server".to_string()), "{names:?}");
        assert!(names.contains(&"MariaDB-backup".to_string()));
        // The `mysql`/`mysqld` entry points live only here; nothing pulls them
        // in as a dependency.
        assert!(names.contains(&"MariaDB-server-compat".to_string()));
        assert!(names.contains(&"MariaDB-client-compat".to_string()));
        assert!(
            !names.iter().any(|n| n.starts_with("mariadb-")),
            "no lowercase names on EL: {names:?}"
        );

        let debian = Distro::mock();
        let names: Vec<String> = StackComponent::Mariadb
            .packages(&debian, &[])
            .unwrap()
            .iter()
            .map(|p| p.as_str().to_string())
            .collect();
        assert!(names.contains(&"mariadb-server".to_string()));
        assert!(names.contains(&"mariadb-server-compat".to_string()));
        assert!(names.contains(&"mariadb-client-compat".to_string()));
        assert!(
            !names.iter().any(|n| n.starts_with("MariaDB-")),
            "no capital names on Debian: {names:?}"
        );
    }

    #[test]
    fn postgres_packages_follow_each_familys_naming() {
        let debian = Distro::mock();
        let names: Vec<String> = StackComponent::Postgres
            .packages(&debian, &[])
            .unwrap()
            .iter()
            .map(|p| p.as_str().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                format!("postgresql-{POSTGRES_MAJOR}"),
                format!("postgresql-client-{POSTGRES_MAJOR}")
            ]
        );

        let (rhel, _) = ferrum_distro::mock::mock_distro_with_recorder(ferrum_distro::Family::Rhel);
        let names: Vec<String> = StackComponent::Postgres
            .packages(&rhel, &[])
            .unwrap()
            .iter()
            .map(|p| p.as_str().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                format!("postgresql{POSTGRES_MAJOR}-server"),
                format!("postgresql{POSTGRES_MAJOR}"),
                format!("postgresql{POSTGRES_MAJOR}-contrib")
            ]
        );
    }

    #[test]
    fn database_components_resolve_the_units_the_vendor_packages_ship() {
        assert_eq!(
            StackComponent::Mariadb
                .unit()
                .unit_name(Family::Debian)
                .as_str(),
            "mariadb.service"
        );
        assert_eq!(
            StackComponent::Mariadb
                .unit()
                .unit_name(Family::Rhel)
                .as_str(),
            "mariadb.service"
        );
        // PGDG on EL has no umbrella unit — only the versioned one exists.
        assert_eq!(
            StackComponent::Postgres
                .unit()
                .unit_name(Family::Debian)
                .as_str(),
            "postgresql.service"
        );
        assert_eq!(
            StackComponent::Postgres
                .unit()
                .unit_name(Family::Rhel)
                .as_str(),
            format!("postgresql-{POSTGRES_MAJOR}.service")
        );
    }

    #[test]
    fn readiness_probes_exist_only_for_the_database_engines() {
        // For nginx and php-fpm, systemd "active" already means "serving".
        assert!(readiness_probe(StackComponent::Nginx, Family::Debian).is_none());
        assert!(
            readiness_probe(
                StackComponent::Php {
                    version: PhpVersion::V83
                },
                Family::Rhel
            )
            .is_none()
        );

        let mariadb = readiness_probe(StackComponent::Mariadb, Family::Debian)
            .unwrap()
            .display();
        // `--no-defaults` must be the first argument or the client ignores it —
        // and then an operator's stray ~/.my.cnf can steer the probe.
        assert!(mariadb.starts_with("mariadb --no-defaults"), "{mariadb}");
        assert!(mariadb.contains("SELECT 1"));
        assert!(mariadb.contains("--protocol=socket"));

        let deb = readiness_probe(StackComponent::Postgres, Family::Debian)
            .unwrap()
            .display();
        assert_eq!(deb, "pg_isready --quiet");
        // PGDG on EL installs no `pg_isready` on PATH; only the versioned
        // directory exists.
        let el = readiness_probe(StackComponent::Postgres, Family::Rhel)
            .unwrap()
            .display();
        assert_eq!(
            el,
            format!("/usr/pgsql-{POSTGRES_MAJOR}/bin/pg_isready --quiet")
        );
    }

    #[tokio::test]
    async fn a_key_is_never_fetched_over_plain_http() {
        // Bootstrapping trust over an unauthenticated transport is not
        // bootstrapping trust.
        let err = fetch_key("http://example.com/key.gpg").await.unwrap_err();
        assert!(err.detail.contains("refusing to fetch"));
    }
}
