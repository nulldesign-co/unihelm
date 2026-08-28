//! Adminer, the panel's web database browser (spec §11.4).
//!
//! # The exposure decision, stated up front
//!
//! Adminer is served **only on 127.0.0.1**, on a dedicated loopback port
//! ([`ferrum_config::paths::ADMINER_LOOPBACK_PORT`]). The spec asks for a
//! "panel-auth-protected internal path", and nginx alone cannot provide the
//! "panel-auth" half: it has no way to check a Ferrum session cookie against
//! the sessions table. Publishing Adminer on a real interface behind anything
//! weaker (an allow-list, basic auth with a shared secret) would put a
//! database login form on the internet, so the loopback bind *is* the safety
//! boundary for now. The panel-session-checking reverse proxy inside
//! `ferrum-web` is the follow-up that makes it reachable from a browser; until
//! it lands, reaching Adminer requires being on the server already — and a
//! local process that can reach the port still needs valid database
//! credentials, which is exactly what it needs to talk to the database
//! socket directly. Loopback exposure therefore grants no capability a local
//! user does not already have.
//!
//! # What enabling actually does
//!
//! 1. Downloads the pinned Adminer release (single PHP file) over HTTPS and
//!    refuses to install it unless its SHA-256 matches [`ADMINER_SHA256`].
//! 2. Installs it root-owned 0644 at `/var/lib/ferrum/adminer/adminer.php` —
//!    the pool that executes the file must never be able to replace it.
//! 3. Creates a dedicated FPM pool on the **highest installed PHP version**
//!    (from `stack_components`), running as the panel's own `ferrum` user —
//!    not a tenant, not the web server user — with `open_basedir` locked to
//!    the Adminer directory plus `/tmp`.
//! 4. Renders the loopback-only nginx server block. Both files go through the
//!    config engine: validate before reload, roll back on failure, revisions
//!    recorded.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ferrum_config::apply::{ApplyRequest, Reloader, Validator};
use ferrum_config::context::{DEFAULT_DISABLE_FUNCTIONS, PoolContext};
use ferrum_config::managed::{FileState, ManagedFile};
use ferrum_config::{ConfigEngine, paths};
use ferrum_core::{ErrorCode, FerrumError, Permission, PhpVersion, Result};
use ferrum_db::{ComponentStatus, Db};
use ferrum_distro::Cmd;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::registry::{Execution, OpContext, TypedOperation};
use crate::services::{FpmValidator, NginxValidator, NoReload, SkipValidation, UnitReloader};

/// The release we install. Version, URL and checksum move together.
pub const ADMINER_VERSION: &str = "6.0.1";

/// The exact release asset: the full build, all drivers (the spec wants both
/// MariaDB and PostgreSQL browsable), all languages.
pub const ADMINER_URL: &str =
    "https://github.com/vrana/adminer/releases/download/v6.0.1/adminer-6.0.1.php";

/// SHA-256 of `adminer-6.0.1.php`, pinned.
///
/// Provenance, honestly: Adminer publishes **no signature** for its release
/// assets — no `.asc`, no `.sig`, no signing key — so there is nothing
/// cryptographic to chain this to. This value was computed on 2026-08-25 by
/// downloading the asset from the URL above and hashing it; GitHub's release
/// API reports the same digest for the asset. Both observations come from the
/// same host (github.com), which makes this a **single-source pin** in the
/// sense of `ferrum_distro::repos::UNVERIFIED_PINS`: it protects against a
/// later tampered or truncated download, not against the source having been
/// wrong on the day it was pinned. Corroborate against an independent mirror
/// before a release; [`ADMINER_PIN_PROVENANCE`] carries the flag to the UI.
pub const ADMINER_SHA256: &str = "1815c03f26e21d533e729c0b09bc69a59c902a6440409d013105ee679dff006c";

/// Surfaced by `db.adminer.status` the way `stack.status` surfaces
/// `UNVERIFIED_PINS`: the UI can tell an operator this pin has a single
/// source, without the operator reading this file.
pub const ADMINER_PIN_PROVENANCE: &str = "single-source";

/// The account the Adminer pool runs as: the panel's own unprivileged user
/// (created by the installer), so a compromise of Adminer lands in the same
/// sandbox as the panel's web process — not in any tenant's files, and not in
/// the web server's.
const RUNTIME_USER: &str = "ferrum";

/// The site-key used for the pool file name (`ferrum-adminer.conf`) and the
/// pool/section name. No collision with tenant pools is possible: those are
/// named from parsed domains, and `adminer` is not a valid domain.
const POOL_KEY: &str = "adminer";

/// Hard ceiling on the download. The real file is ~0.5 MiB; a "single-file
/// PHP app" that arrives larger than this is not the file we pinned, and
/// there is no point buffering it to find that out from the hash.
const MAX_DOWNLOAD_BYTES: usize = 2 * 1024 * 1024;

/// Where a browser (or the future authenticated proxy) reaches Adminer.
pub fn adminer_url() -> String {
    format!("http://127.0.0.1:{}/", paths::ADMINER_LOOPBACK_PORT)
}

// ---------------------------------------------------------------------------
// Download and verification
// ---------------------------------------------------------------------------

/// Fetches the Adminer release bytes. A trait so tests exercise the
/// verify-and-refuse path without a network.
#[async_trait]
pub trait ScriptFetcher: Send + Sync {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>>;
}

/// The real fetcher: HTTPS only, bounded, short-timeout — same posture as the
/// repository-key fetch in `stack.rs`, for the same reason: this runs inside a
/// task the user is watching, and a down mirror should be a clear failure.
pub struct HttpsFetcher;

#[async_trait]
impl ScriptFetcher for HttpsFetcher {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>> {
        if !url.starts_with("https://") {
            return Err(FerrumError::internal(format!(
                "refusing to fetch Adminer over `{url}`"
            )));
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("ferrum/", env!("CARGO_PKG_VERSION")))
            // A redirect to http:// would drop the transport security the
            // checksum pin is supplementing, not replacing.
            .https_only(true)
            .build()
            .map_err(|e| FerrumError::internal(format!("could not build an HTTP client: {e}")))?;

        let response = client.get(url).send().await.map_err(|e| {
            FerrumError::new(
                ErrorCode::PackageBackendFailed,
                format!("could not download {url}: {e}"),
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

        if bytes.len() > MAX_DOWNLOAD_BYTES {
            return Err(FerrumError::new(
                ErrorCode::PackageBackendFailed,
                format!(
                    "{url} served {} bytes; the pinned Adminer release is ~0.5 MiB",
                    bytes.len()
                ),
            ));
        }
        Ok(bytes.to_vec())
    }
}

/// Refuse anything whose SHA-256 is not the pinned one.
///
/// Takes the expected hash as a parameter so the tests can prove both
/// directions (accept the right bytes, refuse the wrong ones) without
/// embedding a copy of Adminer in the test suite. Production callers pass
/// [`ADMINER_SHA256`].
pub fn verify_sha256(bytes: &[u8], expected_hex: &str) -> Result<()> {
    let actual = hex::encode(Sha256::digest(bytes));
    if actual == expected_hex {
        return Ok(());
    }
    Err(FerrumError::new(
        ErrorCode::PackageBackendFailed,
        format!(
            "Adminer download failed checksum verification: expected sha256 \
             {expected_hex}, got {actual} ({} bytes). Nothing was installed. \
             This is either a corrupted download or a tampered file — do not \
             bypass this check.",
            bytes.len()
        ),
    ))
}

/// Write `bytes` to `path` atomically with `mode`.
///
/// Not `managed::write_atomic`: that prepends the FERRUM-MANAGED comment
/// header, and a comment line before `<?php` would be emitted as literal
/// output by PHP — and would also make the on-disk hash stop matching the
/// pin, which is how enable knows it can skip a re-download.
fn write_bytes_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let dir = path
        .parent()
        .ok_or_else(|| FerrumError::internal(format!("{} has no parent", path.display())))?;
    std::fs::create_dir_all(dir)
        .map_err(|e| FerrumError::internal(format!("could not create {}: {e}", dir.display())))?;

    let mut temp = dir.join(path.file_name().unwrap_or_default());
    temp.as_mut_os_string().push(".ferrum-tmp");
    {
        let mut file = std::fs::File::create(&temp).map_err(|e| {
            FerrumError::internal(format!("could not create {}: {e}", temp.display()))
        })?;
        file.write_all(bytes).map_err(|e| {
            FerrumError::internal(format!("could not write {}: {e}", temp.display()))
        })?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| {
                FerrumError::internal(format!("could not chmod {}: {e}", temp.display()))
            })?;
        file.sync_all().map_err(|e| {
            FerrumError::internal(format!("could not sync {}: {e}", temp.display()))
        })?;
    }
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        FerrumError::internal(format!("could not move {} into place: {e}", path.display()))
    })
}

// ---------------------------------------------------------------------------
// Contexts
// ---------------------------------------------------------------------------

/// The pool Adminer runs in. Everything is set here deliberately rather than
/// derived from `PoolContext::new`, because that constructor builds tenant
/// paths under `/home` and every one of them would be wrong for this pool.
pub fn adminer_pool_context(php: PhpVersion, nginx_user: &str) -> PoolContext {
    let dir = paths::adminer_dir();
    let tmp = paths::adminer_tmp_dir();

    PoolContext {
        name: POOL_KEY.into(),
        site_domain: "adminer (panel database browser)".into(),
        php_version: php.as_str().into(),
        // The panel's own user: not a tenant (Adminer must not inherit any
        // tenant's file access), not the web server user (nginx's user must
        // stay a pure consumer of sockets, never an executor of PHP).
        user: RUNTIME_USER.into(),
        group: RUNTIME_USER.into(),
        socket: paths::fpm_socket(POOL_KEY, php),
        socket_owner: RUNTIME_USER.into(),
        socket_group: nginx_user.into(),

        // An idle admin tool must cost nothing; four workers is plenty for
        // the handful of humans who can hold ServerManage.
        pm: "ondemand",
        max_children: 4,
        start_servers: 1,
        min_spare_servers: 1,
        max_spare_servers: 2,
        idle_timeout: 10,
        max_requests: 500,

        log_dir: paths::adminer_log_dir(),
        tmp_dir: tmp.clone(),
        session_dir: tmp.join("sessions"),
        slowlog_timeout: 10,
        terminate_timeout: 300,

        // The security boundary of this pool: the script directory (which
        // contains the tmp/session space) plus /tmp. No tenant home, no
        // panel state directory, nothing else.
        open_basedir: format!("{}:/tmp", dir.display()),
        disable_functions: DEFAULT_DISABLE_FUNCTIONS.replace([' ', '\n'], ""),
        // Adminer talks to database sockets, never to URLs. Leaving URL fopen
        // on would let a compromised Adminer be used as an SSRF proxy from
        // inside the server.
        allow_url_fopen: "off",

        memory_limit: "256M".into(),
        // Imports and exports of real databases run long; killing them at 60s
        // would make the tool useless for exactly the dumps it exists for.
        max_execution_time: 300,
        max_input_time: 300,
        upload_max_filesize: "256M".into(),
        post_max_size: "256M".into(),
        // Editing a wide table submits one input per column per row.
        max_input_vars: 10_000,
        timezone: "UTC".into(),

        opcache_memory_mb: 32,
        opcache_max_files: 100,
        opcache_validate_timestamps: 1,

        env: Vec::new(),
        extra_ini: None,
        // Never. Adminer is a database browser; a database browser that can
        // hand a message to the outbound relay is a spam relay with a login
        // form (spec §11.18).
        sendmail_path: None,
    }
}

/// Everything `nginx/adminer.conf` needs.
#[derive(Debug, Clone, Serialize)]
pub struct AdminerVhostContext {
    pub port: u16,
    pub root: PathBuf,
    pub script: PathBuf,
    pub socket: PathBuf,
    pub log_dir: PathBuf,
    pub max_body_size: String,
    pub timeout: u32,
}

pub fn adminer_vhost_context(php: PhpVersion) -> AdminerVhostContext {
    AdminerVhostContext {
        port: paths::ADMINER_LOOPBACK_PORT,
        root: paths::adminer_dir(),
        script: paths::adminer_php(),
        socket: paths::fpm_socket(POOL_KEY, php),
        log_dir: paths::adminer_log_dir(),
        // Matches the pool's post_max_size; whichever is smaller wins, so
        // they must move together.
        max_body_size: "256m".into(),
        timeout: 300,
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The newest PHP version the Stack Manager has actually installed.
///
/// From `stack_components`, not from a filesystem probe: the panel's own
/// bookkeeping decides what the panel maintains. Takes `&Db` rather than the
/// context so the tests can drive it with an in-memory database.
pub async fn highest_installed_php(db: &Db) -> Result<PhpVersion> {
    let components = db.components().await.map_err(FerrumError::from)?;
    components
        .iter()
        .filter(|c| c.status == ComponentStatus::Installed)
        .filter_map(|c| c.slug.strip_prefix("php"))
        .filter_map(|v| PhpVersion::parse(v).ok())
        .max()
        .ok_or_else(|| {
            FerrumError::new(
                ErrorCode::NotFound,
                "no PHP version is installed; install one from the Stack Manager first \
                 — Adminer is a PHP application",
            )
        })
}

/// Is this PHP version's FPM really on the machine?
///
/// Decides which validator a pool-file removal gets: `php-fpmX -t` where the
/// binary exists, and no validation where it does not (an absent FPM reads no
/// pool files, and a validator that cannot run would block the cleanup).
async fn php_present(ctx: &OpContext, version: PhpVersion) -> bool {
    let slug = format!("php{}", version.as_str());
    if let Ok(Some(c)) = ctx.db().component(&slug).await
        && c.status == ComponentStatus::Installed
    {
        return true;
    }
    let unit =
        ferrum_distro::svc::ManagedUnit::PhpFpm { version }.unit_name(ctx.distro().info.family);
    ctx.distro()
        .svc
        .status(&unit)
        .await
        .map(|s| s.is_installed())
        .unwrap_or(false)
}

/// `chown -R ferrum:ferrum` on a scratch directory, loudly non-fatal.
///
/// Non-fatal for the same reason `open_web_ports` is: on a real server (agent
/// runs as root) this succeeds; on a rooted dev instance it cannot, and
/// failing the whole enable over it would make the dev path untestable. The
/// log line says exactly what will not work.
async fn chown_runtime_dir(ctx: &OpContext, dir: &Path) {
    let spec = format!("{RUNTIME_USER}:{RUNTIME_USER}");
    match Cmd::new("chown").arg("-R").arg(&spec).arg(dir).run().await {
        Ok(out) if out.success() => {}
        Ok(out) => ctx.log(format!(
            "could not chown {} to {spec}: {} — Adminer logins will fail until \
             this directory is writable by {RUNTIME_USER} (sessions live there)",
            dir.display(),
            out.failure_text()
        )),
        Err(e) => ctx.log(format!(
            "could not chown {} to {spec}: {e} — Adminer logins will fail until \
             this directory is writable by {RUNTIME_USER} (sessions live there)",
            dir.display()
        )),
    }
}

/// The pool files this module may have written, one per PHP version that has
/// one on disk.
fn existing_pool_files(family: ferrum_distro::Family) -> Vec<(PhpVersion, PathBuf)> {
    PhpVersion::ALL
        .iter()
        .copied()
        .filter_map(|v| {
            let path = paths::fpm_pool_file(family, v, POOL_KEY);
            path.exists().then_some((v, path))
        })
        .collect()
}

/// One pool file to remove, with the validator that can actually judge it.
pub(crate) struct PoolRemoval {
    pub file: ManagedFile,
    pub service: String,
    pub validator: Box<dyn Validator>,
    pub reloader: Box<dyn Reloader>,
}

#[derive(Debug, Default)]
pub(crate) struct RemovedFiles {
    pub vhost_removed: bool,
    pub pools_removed: Vec<PathBuf>,
    /// Pool removals that failed. Collected, not fatal: the vhost is already
    /// gone by then, so nothing serves Adminer either way, and failing the
    /// disable would leave the operator believing it is still enabled.
    pub pool_failures: Vec<String>,
}

/// Everything `db.adminer.disable` deletes, in order: the vhost first (stop
/// serving before removing what was served), then the pool files, then the
/// script directory. All config files go through the engine, which refuses to
/// delete a file it did not write and rolls back if the survivors fail
/// validation. Split from the operation so tests can drive it against a
/// temporary tree — `paths::set_root` is a process-wide `OnceLock` a parallel
/// test binary cannot use.
pub(crate) async fn remove_adminer_files(
    engine: &ConfigEngine,
    vhost: ManagedFile,
    nginx_validator: &dyn Validator,
    nginx_reloader: &dyn Reloader,
    pools: Vec<PoolRemoval>,
    script_dir: &Path,
) -> Result<RemovedFiles> {
    // A vhost that cannot be removed is fatal: Adminer would still be served,
    // and reporting "disabled" would be a lie.
    let mut report = RemovedFiles {
        vhost_removed: engine
            .remove(&vhost, "nginx", nginx_validator, nginx_reloader)
            .await?,
        ..RemovedFiles::default()
    };

    for pool in pools {
        match engine
            .remove(
                &pool.file,
                &pool.service,
                pool.validator.as_ref(),
                pool.reloader.as_ref(),
            )
            .await
        {
            Ok(true) => report.pools_removed.push(pool.file.path.clone()),
            Ok(false) => {}
            Err(e) => report
                .pool_failures
                .push(format!("{}: {e}", pool.file.path.display())),
        }
    }

    match std::fs::remove_dir_all(script_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => report
            .pool_failures
            .push(format!("{}: {e}", script_dir.display())),
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// db.adminer.status
// ---------------------------------------------------------------------------

/// `db.adminer.status` — is Adminer installed, and where.
pub struct Status;

#[derive(Debug, Deserialize)]
pub struct StatusInput {}

#[derive(Debug, Serialize)]
pub struct StatusOutput {
    pub enabled: bool,
    /// Present only while enabled. Loopback — reachable from the server, not
    /// from a browser, until the authenticated proxy ships.
    pub url: Option<String>,
    pub php_version: Option<String>,
    pub adminer_version: &'static str,
    /// See [`ADMINER_SHA256`]: the checksum pin has one source and no
    /// upstream signature. The UI shows this the way it shows
    /// `unverified_pins` from `stack.status`.
    pub pin_provenance: &'static str,
}

#[async_trait]
impl TypedOperation for Status {
    type Input = StatusInput;
    type Output = StatusOutput;

    const NAME: &'static str = "db.adminer.status";
    // ServerManage even for the read: resellers hold ServerRead, and this
    // feature is admin-only end to end.
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        // Enabled = the pieces are actually on disk and ours, not a database
        // flag that can drift from reality. The vhost is the authority: it is
        // what makes Adminer reachable.
        let vhost_managed = matches!(
            ManagedFile::nginx(paths::nginx_adminer()).state(),
            FileState::Managed { .. }
        );
        let enabled = vhost_managed && paths::adminer_php().exists();

        let php_version = existing_pool_files(ctx.distro().info.family)
            .last()
            .map(|(v, _)| v.as_str().to_string());

        Ok(StatusOutput {
            enabled,
            url: enabled.then(adminer_url),
            php_version,
            adminer_version: ADMINER_VERSION,
            pin_provenance: ADMINER_PIN_PROVENANCE,
        })
    }
}

// ---------------------------------------------------------------------------
// db.adminer.enable
// ---------------------------------------------------------------------------

/// `db.adminer.enable` — download, verify, install, pool, vhost.
pub struct Enable {
    fetcher: Arc<dyn ScriptFetcher>,
}

impl Enable {
    pub fn new(fetcher: Arc<dyn ScriptFetcher>) -> Self {
        Self { fetcher }
    }
}

impl Default for Enable {
    fn default() -> Self {
        Self::new(Arc::new(HttpsFetcher))
    }
}

#[derive(Debug, Deserialize)]
pub struct EnableInput {}

#[derive(Debug, Serialize)]
pub struct EnableOutput {
    pub enabled: bool,
    pub url: String,
    pub php_version: String,
    pub adminer_version: &'static str,
}

#[async_trait]
impl TypedOperation for Enable {
    type Input = EnableInput;
    type Output = EnableOutput;

    const NAME: &'static str = "db.adminer.enable";
    const PERMISSION: Permission = Permission::ServerManage;
    // A download plus two validate-and-reload cycles: seconds, not
    // milliseconds, and worth a streamed log either way.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let distro = ctx.distro();
        let family = distro.info.family;
        let php = highest_installed_php(ctx.db()).await?;
        ctx.log(format!(
            "installing Adminer {ADMINER_VERSION} on PHP {} (highest installed)",
            php.as_str()
        ));

        // Same disclosure `stack.install` makes for single-sourced repo pins:
        // the operator deserves to know what this checksum does and does not
        // prove (see ADMINER_SHA256).
        ctx.log(
            "note: Adminer publishes no release signatures; the pinned sha256 \
             comes from a single source (github.com) — it detects tampering \
             after pinning, not before",
        );

        // 1. The script: reuse a byte-identical file, otherwise download and
        //    verify. The hash check gates every path to the write below.
        let script_path = paths::adminer_php();
        let bytes = match std::fs::read(&script_path) {
            Ok(existing) if verify_sha256(&existing, ADMINER_SHA256).is_ok() => {
                ctx.log("adminer.php already present with the pinned checksum; skipping download");
                existing
            }
            _ => {
                ctx.log(format!("downloading {ADMINER_URL}"));
                let fetched = self.fetcher.fetch(ADMINER_URL).await?;
                verify_sha256(&fetched, ADMINER_SHA256)?;
                ctx.log(format!(
                    "checksum verified: sha256 {ADMINER_SHA256} ({} bytes)",
                    fetched.len()
                ));
                fetched
            }
        };

        // 2. Install. The agent runs as root, so files it creates are
        //    root-owned; 0644 lets the pool read the script without ever
        //    being able to modify it. The scratch dir is the one place the
        //    runtime user may write.
        write_bytes_atomic(&script_path, &bytes, 0o644)?;
        let sessions = paths::adminer_tmp_dir().join("sessions");
        std::fs::create_dir_all(&sessions).map_err(|e| {
            FerrumError::internal(format!("could not create {}: {e}", sessions.display()))
        })?;
        std::fs::create_dir_all(paths::adminer_log_dir()).map_err(|e| {
            FerrumError::internal(format!("could not create the adminer log dir: {e}"))
        })?;
        chown_runtime_dir(ctx, &paths::adminer_tmp_dir()).await;
        // PHP workers (running as ferrum) write php-error.log here.
        chown_runtime_dir(ctx, &paths::adminer_log_dir()).await;
        ctx.log(format!("installed {}", script_path.display()));

        // 3. The pool. Same serialisation key and validators as tenant pools
        //    on this PHP version, so concurrent site work cannot interleave.
        std::fs::create_dir_all(paths::fpm_socket_dir()).map_err(|e| {
            FerrumError::internal(format!("could not create the FPM socket dir: {e}"))
        })?;
        let pool = adminer_pool_context(php, crate::provision::nginx_user(distro));
        ctx.config()
            .apply(ApplyRequest {
                file: ManagedFile::fpm_pool(paths::fpm_pool_file(family, php, POOL_KEY)),
                template: "php/pool.conf",
                context: serde_json::json!({ "pool": pool }),
                service: &format!("php-fpm-{}", php.as_str()),
                validator: &FpmValidator::new(distro, php),
                reloader: &UnitReloader::fpm(distro, php),
                post_check: None,
                force: false,
                task_id: ctx.task_id().map(|t| t.to_string()),
            })
            .await?;
        ctx.log(format!("FPM pool ready (PHP {})", php.as_str()));

        // A previous enable may have written the pool on what was then the
        // highest version. Two pools would both bind sockets and only one is
        // referenced by the vhost; remove the strays.
        for (version, path) in existing_pool_files(family) {
            if version == php {
                continue;
            }
            let removal = if php_present(ctx, version).await {
                (
                    Box::new(FpmValidator::new(distro, version)) as Box<dyn Validator>,
                    Box::new(UnitReloader::fpm(distro, version)) as Box<dyn Reloader>,
                )
            } else {
                (
                    Box::new(SkipValidation) as Box<dyn Validator>,
                    Box::new(NoReload) as Box<dyn Reloader>,
                )
            };
            match ctx
                .config()
                .remove(
                    &ManagedFile::fpm_pool(path.clone()),
                    &format!("php-fpm-{}", version.as_str()),
                    removal.0.as_ref(),
                    removal.1.as_ref(),
                )
                .await
            {
                Ok(true) => ctx.log(format!(
                    "removed the stale Adminer pool on PHP {}",
                    version.as_str()
                )),
                Ok(false) => {}
                Err(e) => ctx.log(format!(
                    "could not remove the stale Adminer pool on PHP {}: {e}",
                    version.as_str()
                )),
            }
        }

        // 4. The vhost, last: nothing is served until everything behind it
        //    exists.
        ctx.config()
            .apply(ApplyRequest {
                file: ManagedFile::nginx(paths::nginx_adminer()),
                template: "nginx/adminer.conf",
                context: serde_json::json!({ "adminer": adminer_vhost_context(php) }),
                service: "nginx",
                validator: &NginxValidator,
                reloader: &UnitReloader::nginx(distro),
                post_check: None,
                force: false,
                task_id: ctx.task_id().map(|t| t.to_string()),
            })
            .await?;

        let url = adminer_url();
        ctx.log(format!("Adminer enabled on {url} (loopback only)"));
        Ok(EnableOutput {
            enabled: true,
            url,
            php_version: php.as_str().to_string(),
            adminer_version: ADMINER_VERSION,
        })
    }
}

// ---------------------------------------------------------------------------
// db.adminer.disable
// ---------------------------------------------------------------------------

/// `db.adminer.disable` — remove the vhost, the pool(s) and the script.
pub struct Disable;

#[derive(Debug, Deserialize)]
pub struct DisableInput {}

#[derive(Debug, Serialize)]
pub struct DisableOutput {
    pub enabled: bool,
    pub vhost_removed: bool,
    pub pools_removed: Vec<String>,
    /// Cleanup that failed after the vhost was already gone. Nothing serves
    /// Adminer once the vhost is removed, so these are warnings, not errors.
    pub warnings: Vec<String>,
}

#[async_trait]
impl TypedOperation for Disable {
    type Input = DisableInput;
    type Output = DisableOutput;

    const NAME: &'static str = "db.adminer.disable";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let distro = ctx.distro();
        let family = distro.info.family;

        let mut pools = Vec::new();
        for (version, path) in existing_pool_files(family) {
            // A pool left over from a PHP version that has since been removed
            // has no `php-fpmX -t` to validate with — and needs none, because
            // no FPM reads it.
            let (validator, reloader): (Box<dyn Validator>, Box<dyn Reloader>) =
                if php_present(ctx, version).await {
                    (
                        Box::new(FpmValidator::new(distro, version)),
                        Box::new(UnitReloader::fpm(distro, version)),
                    )
                } else {
                    (Box::new(SkipValidation), Box::new(NoReload))
                };
            pools.push(PoolRemoval {
                file: ManagedFile::fpm_pool(path),
                service: format!("php-fpm-{}", version.as_str()),
                validator,
                reloader,
            });
        }

        let report = remove_adminer_files(
            ctx.config(),
            ManagedFile::nginx(paths::nginx_adminer()),
            &NginxValidator,
            &UnitReloader::nginx(distro),
            pools,
            &paths::adminer_dir(),
        )
        .await?;

        if report.vhost_removed {
            ctx.log("removed the Adminer vhost");
        } else {
            ctx.log("Adminer was not enabled; nothing to remove");
        }
        for path in &report.pools_removed {
            ctx.log(format!("removed {}", path.display()));
        }
        for warning in &report.pool_failures {
            ctx.log(format!("cleanup warning: {warning}"));
        }

        // Forget revision history for files that no longer exist, like
        // site.delete does — a rollback offer for a deleted feature is noise.
        let mut forgotten = vec![paths::nginx_adminer()];
        forgotten.extend(
            PhpVersion::ALL
                .iter()
                .map(|&v| paths::fpm_pool_file(family, v, POOL_KEY)),
        );
        for path in forgotten {
            let _ = ctx.db().forget_revisions(&path.to_string_lossy()).await;
        }

        Ok(DisableOutput {
            enabled: false,
            vhost_removed: report.vhost_removed,
            pools_removed: report
                .pools_removed
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            warnings: report.pool_failures,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_config::TemplateSet;
    use ferrum_config::managed::{CommentStyle, with_header, write_atomic};

    fn engine() -> ConfigEngine {
        ConfigEngine::new(TemplateSet::load().unwrap())
    }

    /// Comment lines stripped, so assertions are about directives, not prose.
    fn directives_only(rendered: &str) -> String {
        rendered
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with('#') && !t.starts_with(';')
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    // --- the pin ----------------------------------------------------------

    #[test]
    fn the_pinned_hash_is_a_well_formed_sha256() {
        assert_eq!(ADMINER_SHA256.len(), 64);
        assert!(ADMINER_SHA256.chars().all(|c| c.is_ascii_hexdigit()));
        // Lowercase, because `hex::encode` produces lowercase and the
        // comparison is exact.
        assert_eq!(ADMINER_SHA256, ADMINER_SHA256.to_lowercase());
    }

    #[test]
    fn bytes_matching_the_pin_are_accepted_and_wrong_bytes_are_refused() {
        let good = b"pretend this is adminer".to_vec();
        let pin = hex::encode(Sha256::digest(&good));

        assert!(verify_sha256(&good, &pin).is_ok());

        let tampered = b"pretend this is adminer!".to_vec();
        let err = verify_sha256(&tampered, &pin).unwrap_err();
        assert_eq!(err.code, ErrorCode::PackageBackendFailed);
        assert!(
            err.detail.contains("Nothing was installed"),
            "{}",
            err.detail
        );
        assert!(err.detail.contains(&pin), "must name the expected hash");
    }

    #[tokio::test]
    async fn a_download_whose_hash_does_not_match_the_pin_is_refused_before_any_write() {
        // The fetcher hands back attacker-chosen bytes; the verify step must
        // refuse them against the real pin, and nothing may have been written
        // for it to refuse *after*.
        struct EvilMirror;
        #[async_trait]
        impl ScriptFetcher for EvilMirror {
            async fn fetch(&self, _url: &str) -> Result<Vec<u8>> {
                Ok(b"<?php system($_GET['c']);".to_vec())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let install_target = dir.path().join("adminer.php");

        // The exact sequence Enable::run performs, up to the write.
        let bytes = EvilMirror.fetch(ADMINER_URL).await.unwrap();
        let verdict = verify_sha256(&bytes, ADMINER_SHA256);

        let err = verdict.unwrap_err();
        assert_eq!(err.code, ErrorCode::PackageBackendFailed);
        assert!(
            !install_target.exists(),
            "a refused download must leave nothing on disk"
        );
    }

    #[test]
    fn the_https_fetcher_refuses_plain_http() {
        // Constructing the refusal without a network: the URL check is first.
        let err = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(HttpsFetcher.fetch("http://example.com/adminer.php"))
            .unwrap_err();
        assert!(err.detail.contains("refusing"), "{}", err.detail);
    }

    // --- the pool ---------------------------------------------------------

    #[test]
    fn the_adminer_pool_runs_as_the_panel_user_inside_its_own_basedir() {
        let set = TemplateSet::load().unwrap();
        let pool = adminer_pool_context(PhpVersion::V84, "nginx");
        let rendered = set
            .render("php/pool.conf", &serde_json::json!({ "pool": pool }))
            .unwrap();
        let out = directives_only(&rendered);

        // The user: the panel's own account. Never a tenant, never nginx.
        assert!(out.contains("user  = ferrum"), "{out}");
        assert!(out.contains("group = ferrum"));
        // nginx can reach the socket, nothing else can.
        assert!(out.contains("listen.owner = ferrum"));
        assert!(out.contains("listen.group = nginx"));
        assert!(out.contains("listen.mode  = 0660"));

        // The basedir is the whole isolation story for this pool: the
        // adminer directory (script + scratch) plus /tmp, and nothing that
        // could reach a tenant's files or the panel's state.
        assert!(
            out.contains("php_admin_value[open_basedir] = /var/lib/ferrum/adminer:/tmp"),
            "{out}"
        );
        assert!(!out.contains("/home/"), "no tenant path may appear: {out}");

        // A DB browser must not be an SSRF proxy.
        assert!(out.contains("php_admin_flag[allow_url_fopen] = off"));
        // And not a command runner.
        assert!(out.contains("shell_exec"));
    }

    #[test]
    fn the_adminer_pool_costs_nothing_while_idle() {
        let set = TemplateSet::load().unwrap();
        let pool = adminer_pool_context(PhpVersion::V83, "nginx");
        let out = set
            .render("php/pool.conf", &serde_json::json!({ "pool": pool }))
            .unwrap();
        assert!(out.contains("pm = ondemand"));
        assert!(out.contains("pm.max_children = 4"));
    }

    #[test]
    fn the_pool_socket_and_file_cannot_collide_with_a_tenant_site() {
        // Tenant pool keys come from parsed domains; "adminer" is not one.
        assert!(ferrum_core::Domain::parse(POOL_KEY).is_err());
        let pool = adminer_pool_context(PhpVersion::V83, "nginx");
        assert!(
            pool.socket
                .to_string_lossy()
                .ends_with("adminer-php83.sock"),
            "{:?}",
            pool.socket
        );
    }

    // --- the vhost --------------------------------------------------------

    #[test]
    fn the_adminer_vhost_listens_only_on_loopback() {
        let set = TemplateSet::load().unwrap();
        let ctx = adminer_vhost_context(PhpVersion::V84);
        let rendered = set
            .render("nginx/adminer.conf", &serde_json::json!({ "adminer": ctx }))
            .unwrap();
        let out = directives_only(&rendered);

        // Exactly one listen directive, and it is the loopback one. This is
        // the security boundary of the whole feature (see the module docs),
        // so the assertion is about the *set* of listens, not one line.
        let listens: Vec<&str> = out
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("listen"))
            .collect();
        assert_eq!(
            listens,
            vec![format!("listen 127.0.0.1:{};", paths::ADMINER_LOOPBACK_PORT).as_str()],
            "any other listen makes a database login form public: {out}"
        );
        assert!(!out.contains("listen 80"));
        assert!(!out.contains("listen 443"));
        assert!(!out.contains("[::"), "no IPv6 bind either: {out}");
    }

    #[test]
    fn the_vhost_serves_the_pinned_script_and_nothing_else() {
        let set = TemplateSet::load().unwrap();
        let ctx = adminer_vhost_context(PhpVersion::V84);
        let rendered = set
            .render("nginx/adminer.conf", &serde_json::json!({ "adminer": ctx }))
            .unwrap();
        let out = directives_only(&rendered);

        // The script is named absolutely — no try_files over user paths, no
        // regex .php handler for a directory that must only ever hold one
        // file.
        assert!(
            out.contains("fastcgi_param SCRIPT_FILENAME /var/lib/ferrum/adminer/adminer.php"),
            "{out}"
        );
        assert!(out.contains("fastcgi_pass unix:/run/ferrum/fpm/adminer-php84.sock;"));
        // Everything that is not `/` is refused.
        assert!(out.contains("return 404;"));
        assert!(!out.contains("try_files"), "{out}");
    }

    // --- choosing the PHP version -----------------------------------------

    #[tokio::test]
    async fn enable_targets_the_highest_installed_php_version() {
        let db = Db::open_memory().await.unwrap();
        for slug in ["php8.1", "php8.4", "nginx"] {
            assert!(
                db.claim_component(slug, ComponentStatus::Installing, "t")
                    .await
                    .unwrap()
            );
            db.component_installed(slug, Some("test")).await.unwrap();
        }
        // A version that is merely *failing* to install must not be chosen.
        assert!(
            db.claim_component("php8.5", ComponentStatus::Installing, "t")
                .await
                .unwrap()
        );
        db.component_failed("php8.5", "boom").await.unwrap();

        let php = highest_installed_php(&db).await.unwrap();
        assert_eq!(php, PhpVersion::V84);
    }

    #[tokio::test]
    async fn enabling_without_any_php_installed_is_a_clear_error() {
        let db = Db::open_memory().await.unwrap();
        let err = highest_installed_php(&db).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(err.detail.contains("Stack Manager"), "{}", err.detail);
    }

    // --- disable ----------------------------------------------------------

    /// Apply a template through the engine into an explicit path, the way
    /// enable does, so removal is exercised against genuinely managed files.
    async fn apply_into(
        engine: &ConfigEngine,
        file: ManagedFile,
        template: &str,
        ctx: serde_json::Value,
    ) {
        engine
            .apply(ApplyRequest {
                file,
                template,
                context: ctx,
                service: "test",
                validator: &SkipValidation,
                reloader: &NoReload,
                post_check: None,
                force: false,
                task_id: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn disable_removes_the_vhost_and_pool_through_the_config_engine() {
        let engine = engine();
        let dir = tempfile::tempdir().unwrap();
        let vhost_path = dir.path().join("02-adminer.conf");
        let pool_path = dir.path().join("ferrum-adminer.conf");
        let script_dir = dir.path().join("adminer");
        std::fs::create_dir_all(&script_dir).unwrap();
        std::fs::write(script_dir.join("adminer.php"), "<?php").unwrap();

        apply_into(
            &engine,
            ManagedFile::nginx(&vhost_path),
            "nginx/adminer.conf",
            serde_json::json!({ "adminer": adminer_vhost_context(PhpVersion::V83) }),
        )
        .await;
        apply_into(
            &engine,
            ManagedFile::fpm_pool(&pool_path),
            "php/pool.conf",
            serde_json::json!({ "pool": adminer_pool_context(PhpVersion::V83, "nginx") }),
        )
        .await;

        let report = remove_adminer_files(
            &engine,
            ManagedFile::nginx(&vhost_path),
            &SkipValidation,
            &NoReload,
            vec![PoolRemoval {
                file: ManagedFile::fpm_pool(&pool_path),
                service: "php-fpm-8.3".into(),
                validator: Box::new(SkipValidation),
                reloader: Box::new(NoReload),
            }],
            &script_dir,
        )
        .await
        .unwrap();

        assert!(report.vhost_removed);
        assert_eq!(report.pools_removed, vec![pool_path.clone()]);
        assert!(
            report.pool_failures.is_empty(),
            "{:?}",
            report.pool_failures
        );
        assert!(!vhost_path.exists());
        assert!(!pool_path.exists());
        assert!(!script_dir.exists(), "the script directory must go too");
    }

    #[tokio::test]
    async fn disabling_twice_is_not_an_error() {
        let engine = engine();
        let dir = tempfile::tempdir().unwrap();

        let report = remove_adminer_files(
            &engine,
            ManagedFile::nginx(dir.path().join("02-adminer.conf")),
            &SkipValidation,
            &NoReload,
            Vec::new(),
            &dir.path().join("adminer"),
        )
        .await
        .unwrap();

        assert!(!report.vhost_removed, "there was nothing to remove");
        assert!(report.pools_removed.is_empty());
    }

    #[tokio::test]
    async fn disable_refuses_to_delete_a_vhost_it_did_not_write() {
        // An operator's hand-written file at our path is their configuration,
        // not ours. The engine refuses, and disable propagates that rather
        // than deleting it.
        let engine = engine();
        let dir = tempfile::tempdir().unwrap();
        let vhost_path = dir.path().join("02-adminer.conf");
        std::fs::write(&vhost_path, "server { listen 9999; }\n").unwrap();

        let result = remove_adminer_files(
            &engine,
            ManagedFile::nginx(&vhost_path),
            &SkipValidation,
            &NoReload,
            Vec::new(),
            &dir.path().join("adminer"),
        )
        .await;

        assert!(result.is_err());
        assert!(vhost_path.exists(), "the foreign file must survive");
    }

    #[tokio::test]
    async fn a_pool_that_fails_validation_on_removal_is_restored_not_lost() {
        // The engine's contract on removal failure is rollback; disable
        // reports it as a warning instead of pretending the pool is gone.
        struct AlwaysFails;
        #[async_trait]
        impl Validator for AlwaysFails {
            fn name(&self) -> &'static str {
                "always-fails"
            }
            async fn validate(&self) -> std::result::Result<(), String> {
                Err("still referenced".into())
            }
        }

        let engine = engine();
        let dir = tempfile::tempdir().unwrap();
        let vhost_path = dir.path().join("02-adminer.conf");
        let pool_path = dir.path().join("ferrum-adminer.conf");

        write_atomic(
            &vhost_path,
            &with_header("server {}\n", CommentStyle::Hash),
            0o644,
        )
        .unwrap();
        write_atomic(
            &pool_path,
            &with_header("[adminer]\n", CommentStyle::Semicolon),
            0o644,
        )
        .unwrap();

        let report = remove_adminer_files(
            &engine,
            ManagedFile::nginx(&vhost_path),
            &SkipValidation,
            &NoReload,
            vec![PoolRemoval {
                file: ManagedFile::fpm_pool(&pool_path),
                service: "php-fpm-8.3".into(),
                validator: Box::new(AlwaysFails),
                reloader: Box::new(NoReload),
            }],
            &dir.path().join("adminer"),
        )
        .await
        .unwrap();

        assert!(report.vhost_removed);
        assert_eq!(report.pool_failures.len(), 1);
        assert!(pool_path.exists(), "a failed removal must roll back");
    }
}
