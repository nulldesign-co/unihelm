//! Where a PHP version runs, and who is told when its pools change.
//!
//! Two jobs, and they are the same job seen from two ends.
//!
//! The older one is retiring the distribution's stock `www.conf` pool, which is
//! below and unchanged in what it decides.
//!
//! The new one is step three of `docs/design/containerised-runtimes.md`: a PHP
//! version now runs either as host packages with a systemd unit, or as one
//! container holding one master and every pool of that version. Creating and
//! running that container is [`crate::fpmcontainer`]'s. **This module is the
//! part that answers "which of the two is this version?" and routes.**
//!
//! ## The safety rule, and the default that carries it
//!
//! **A version already installed on the host stays on the host.** Sites are
//! serving through it, and there is only one 8.3 on a machine — a host 8.3 and a
//! container 8.3 would write pools into different places while claiming the same
//! sockets and the same sites.
//!
//! So [`PhpRuntime::of`] answers [`PhpRuntime::Host`] for **every version that
//! has no container record**, and a record is only ever written by an explicit
//! containerised install ([`crate::fpmcontainer::install`], which refuses
//! outright when the host already owns the version).
//!
//! That default cannot be the other way round, and not merely as a matter of
//! taste. Every machine this build lands on already has its PHP on the host and
//! an empty registry, because the registry did not exist until now. A default of
//! `Container` would send every pool write on every one of those servers at a
//! container that is not there — the pool file on disk, the master that is
//! actually serving never told, the site left on its old configuration or on
//! none, and the panel reporting success. Absence has to mean host, because
//! absence is exactly what every existing server looks like.
//!
//! ## What routing means in practice
//!
//! Three questions had a hard-coded answer before this, and each of them is now
//! asked of the version:
//!
//! - **Who validates a pool file?** `php-fpm8.3 -t` on the host. That binary
//!   does not exist for a containerised version, so the host validator would
//!   fail every pool write with an error about a missing program rather than
//!   about the pool. See [`validator`].
//! - **Who is reloaded?** `systemctl reload php8.3-fpm`, or `SIGUSR2` to the
//!   container's master. See [`reloader`].
//! - **Is the version even installed?** The `stack_components` row and the unit,
//!   or the container. See [`require_installed`].
//!
//! The pool files themselves do not change: `site::render_pool` writes the same
//! content to the same path, and the container bind-mounts that directory.
//! Neither do the vhosts — nginx, Apache and LiteSpeed all reach one socket in
//! `paths::fpm_socket_dir`, and nothing in `templates/nginx` is touched here.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;

use unihelm_config::apply::{Reloader, Validator};
use unihelm_config::paths;
use unihelm_core::{ErrorCode, PhpVersion, Result, UnihelmError};
use unihelm_db::{ComponentStatus, Db};
use unihelm_distro::Family;
use unihelm_distro::svc::ManagedUnit;

use crate::fpmcontainer::{self, FpmRegistry};
use crate::registry::OpContext;

// ===========================================================================
// Retiring the distribution's stock pool
// ===========================================================================
//
// Both families ship a `www.conf` pool that runs as the web server's own user
// (`apache` on Remi, `www-data` on Sury) with no `open_basedir`. On a live
// AlmaLinux box the panel installed PHP 8.3, created a properly isolated pool
// for the tenant — and left five `pool www` workers running as `apache`
// alongside it.
//
// Two reasons that has to go, in increasing order of seriousness:
//
// 1. Five idle workers is 150 MB on a machine where the whole panel is
//    budgeted 50 MB (spec §13).
// 2. It is a tenant-isolation hole one config mistake wide. Remi's pool socket
//    is reachable by nginx by design, so a vhost pointed at the wrong socket —
//    by a bug, by a hand edit, by an imported config — runs that tenant's PHP
//    as `apache`, outside their `open_basedir`, with read access to every
//    other tenant's files. The panel's isolation story is only as good as the
//    absence of a second, unisolated way in.
//
// The stock file is moved aside rather than edited: `paths` is explicit that
// Unihelm never edits a distro's own config, and a rename is something an
// operator can undo with one `mv`. An operator who wants the pool back can say
// so in the file itself — see [`KEEP_MARKER`].

/// The suffix we move the stock pool to. PHP-FPM only reads `*.conf`, so a file
/// ending in anything else is inert while staying exactly where the operator
/// would look for it.
const DISABLED_SUFFIX: &str = ".unihelm-disabled";

/// An operator who genuinely wants the stock pool puts this anywhere in
/// `www.conf` and Unihelm leaves it alone from then on.
///
/// It lives in the file rather than in the panel's settings because that is
/// where the next person to wonder "why is there a pool running as apache" will
/// be looking.
pub const KEEP_MARKER: &str = "unihelm: keep";

/// What we did, so the caller can log something true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockPool {
    /// There was no stock pool to begin with.
    Absent,
    /// Moved aside just now.
    Retired,
    /// A package upgrade put it back; removed, because the copy we took the
    /// first time is still there.
    RemovedDuplicate,
    /// The operator asked us to leave it.
    KeptOnRequest,
    /// Left in place because it is the only pool there is.
    ///
    /// FPM refuses to start with no pool at all, so retiring the last one does
    /// not harden a server — it takes every PHP site on it offline. On a machine
    /// where PHP was serving sites before the panel arrived, that is exactly what
    /// happened: `www.conf` moved aside, `php-fpm` failed with "No pool defined",
    /// and the sites answered 502.
    ///
    /// A containerised version has the same constraint for the same reason, and
    /// [`crate::fpmcontainer::ReloadPlan`] makes the same judgement about it: a
    /// master with no pools is stopped and left stopped rather than signalled
    /// into a crash loop.
    KeptAsOnlyPool,
}

/// Where the distribution's stock pool lives for a PHP version.
pub fn stock_pool_path(family: Family, version: PhpVersion) -> PathBuf {
    paths::fpm_pool_dir(family, version).join("www.conf")
}

/// Move the stock pool out of the way, if it is there and wanted gone.
///
/// Idempotent, and safe to call on every install and every site creation: a
/// package upgrade restores `www.conf`, so "we did this once at install time"
/// is not a state that stays true.
pub fn retire_stock_pool(family: Family, version: PhpVersion) -> Result<StockPool> {
    retire_stock_pool_in(&paths::fpm_pool_dir(family, version))
}

/// The same, against an explicit pool directory.
///
/// Split out so the tests can work in a temporary directory: `paths::set_root`
/// is a process-wide `OnceLock`, which a parallel test binary cannot use to give
/// each test its own tree.
pub fn retire_stock_pool_in(pool_dir: &Path) -> Result<StockPool> {
    let stock = pool_dir.join("www.conf");
    let disabled = pool_dir.join(format!("www.conf{DISABLED_SUFFIX}"));

    if !stock.exists() {
        return Ok(StockPool::Absent);
    }

    if pool_is_marked_keep(&stock) {
        return Ok(StockPool::KeptOnRequest);
    }

    // Never leave FPM with nothing to run.
    //
    // The point of retiring the stock pool is that it runs as the web server
    // user with no open_basedir, and every site Unihelm creates gets its own
    // pool instead. Until at least one of those exists, moving this one aside
    // stops FPM dead — and a stopped FPM is not a hardened server, it is a
    // server whose PHP sites all return 502. It is retired on the next site
    // creation, which is when there is something to take over from it.
    if !another_pool_exists(pool_dir) {
        return Ok(StockPool::KeptAsOnlyPool);
    }

    if disabled.exists() {
        // A copy is already preserved. The file that just reappeared is the
        // package's pristine default — rpm and dpkg leave a `.rpmnew`/`.dpkg-dist`
        // instead of overwriting anything an admin edited, so nothing of theirs
        // is in this one.
        std::fs::remove_file(&stock).map_err(|e| {
            UnihelmError::internal(format!(
                "could not remove the restored stock pool {}: {e}",
                stock.display()
            ))
        })?;
        return Ok(StockPool::RemovedDuplicate);
    }

    std::fs::rename(&stock, &disabled).map_err(|e| {
        UnihelmError::internal(format!(
            "could not move the stock pool {} aside: {e}",
            stock.display()
        ))
    })?;
    Ok(StockPool::Retired)
}

/// Whether any pool other than the stock `www.conf` is configured.
///
/// FPM includes `*.conf` from the pool directory, so that glob is the question:
/// a `.unihelm-disabled` file is not matched by it and does not count.
fn another_pool_exists(pool_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(pool_dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let path = e.path();
        path.extension().is_some_and(|x| x == "conf")
            && path.file_name().is_some_and(|n| n != "www.conf")
    })
}

fn pool_is_marked_keep(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|text| text.contains(KEEP_MARKER))
        .unwrap_or(false)
}

impl StockPool {
    /// Did this change the config on disk?
    ///
    /// The answer decides whether FPM has to be told. Removing a pool file
    /// changes nothing until the master process re-reads its config: on the live
    /// box the file went away and five workers kept running as `apache`, because
    /// the site's own pool was unchanged and so the config engine — correctly —
    /// skipped the reload. Same shape as the nginx certificate bug: the thing
    /// that changed was not the thing being watched.
    pub const fn changed_disk(self) -> bool {
        matches!(self, StockPool::Retired | StockPool::RemovedDuplicate)
    }
}

/// Retire the stock pool, say what happened in the task log, and reload FPM if
/// anything actually moved.
///
/// Never fatal: a stock pool we could not move is a wasted 150 MB and a latent
/// isolation risk, both of which are worth a loud line in the log and neither of
/// which is worth failing an otherwise-good PHP install over.
pub async fn retire_and_log(ctx: &OpContext, version: PhpVersion) {
    let php = version.as_str();

    let outcome = retire_stock_pool(ctx.distro().info.family, version);
    match &outcome {
        Ok(StockPool::Absent) => return,
        Ok(StockPool::Retired) => ctx.log(format!(
            "disabled the stock PHP {php} `www` pool (it runs as the web server \
             user with no open_basedir); moved to www.conf{DISABLED_SUFFIX}"
        )),
        Ok(StockPool::RemovedDuplicate) => ctx.log(format!(
            "a package upgrade restored the stock PHP {php} `www` pool; removed \
             it again (the original is still at www.conf{DISABLED_SUFFIX})"
        )),
        Ok(StockPool::KeptAsOnlyPool) => {
            ctx.log(format!(
                "leaving the stock PHP {php} `www` pool in place — it is the only \
                 pool configured, and FPM will not start without one. It runs as \
                 the web server user without open_basedir, so anything served \
                 through it is not isolated; it is retired automatically once a \
                 site of your own has a pool to take over from it."
            ));
            return;
        }
        Ok(StockPool::KeptOnRequest) => {
            ctx.log(format!(
                "leaving the stock PHP {php} `www` pool alone — it is marked \
                 `{KEEP_MARKER}`. It runs as the web server user without \
                 open_basedir, so nothing served through it is isolated."
            ));
            return;
        }
        Err(e) => {
            ctx.log(format!(
                "could not disable the stock PHP {php} `www` pool: {e}. It runs \
                 as the web server user without open_basedir; disable it by hand."
            ));
            return;
        }
    }

    if !outcome.map(StockPool::changed_disk).unwrap_or(false) {
        return;
    }

    // Through the router, not straight at systemd. On a machine where this
    // version is a container there is no unit to reload, and the master still
    // holding the retired `www` workers is inside the container — signalling
    // nothing would leave those workers running as the web-server user with the
    // panel reporting that they were gone.
    let reloaded = match reloader(ctx, version).await {
        Ok(reloader) => reloader.reload().await,
        Err(e) => Err(e.detail),
    };
    match reloaded {
        Ok(()) => ctx.log(format!(
            "reloaded PHP {php} FPM; the `www` workers are gone"
        )),
        Err(e) => ctx.log(format!(
            "moved the stock PHP {php} pool aside but could not reload FPM ({e}); \
             its workers keep running until the next restart"
        )),
    }
}

// ===========================================================================
// Which of the two ways this version runs
// ===========================================================================

/// How a PHP version is installed on this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhpRuntime {
    /// Packages and a systemd unit on this machine.
    Host,
    /// One container holding one master and every pool of this version —
    /// [`crate::fpmcontainer`].
    Container,
}

impl PhpRuntime {
    pub const fn as_str(self) -> &'static str {
        match self {
            PhpRuntime::Host => "host",
            PhpRuntime::Container => "container",
        }
    }

    /// The mode of one version, read from records already in hand.
    ///
    /// **The default lives here and nowhere else: no record means host.** It is
    /// a lookup in [`crate::fpmcontainer`]'s registry rather than a second store
    /// of the same fact, because two places that have to agree about which
    /// master serves a site are one place with a race in it.
    pub fn of(registry: &FpmRegistry, version: PhpVersion) -> Self {
        match registry.contains_key(version.as_str()) {
            true => PhpRuntime::Container,
            false => PhpRuntime::Host,
        }
    }
}

/// Where this version runs on this server.
pub async fn runtime_of(db: &Db, version: PhpVersion) -> Result<PhpRuntime> {
    Ok(PhpRuntime::of(&fpmcontainer::registry(db).await?, version))
}

// ===========================================================================
// Routing: who validates, who is reloaded
// ===========================================================================

/// The validator for this version's pool files.
///
/// `php-fpm8.3 -t` on the host; the same test inside the master otherwise. The
/// difference is not cosmetic: [`crate::services::FpmValidator`] runs
/// `paths::fpm_binary`, which on a machine where 8.3 is a container is a program
/// that was never installed — so every pool write for that version would fail
/// with "no such file or directory" and an operator would go looking for a
/// broken pool that is perfectly fine.
pub async fn validator<'a>(
    ctx: &'a OpContext,
    version: PhpVersion,
) -> Result<Box<dyn Validator + 'a>> {
    match runtime_of(ctx.db(), version).await? {
        PhpRuntime::Host => Ok(Box::new(crate::services::FpmValidator::new(
            ctx.distro(),
            version,
        ))),
        PhpRuntime::Container => Ok(Box::new(ContainerValidator { ctx, version })),
    }
}

/// Who is told that a pool file changed.
///
/// **The one function this step exists to provide.** Everything that writes or
/// removes a pool goes through it instead of naming `UnitReloader::fpm`, because
/// naming the unit is exactly the assumption that stops being true.
///
/// The returned reloader borrows the context rather than owning one, so no
/// caller has to produce an `OpContext` by value to get at it — the config
/// engine takes `&dyn Reloader` for the length of one `apply`, which is well
/// inside the borrow.
pub async fn reloader<'a>(
    ctx: &'a OpContext,
    version: PhpVersion,
) -> Result<Box<dyn Reloader + 'a>> {
    match runtime_of(ctx.db(), version).await? {
        PhpRuntime::Host => Ok(Box::new(crate::services::UnitReloader::fpm(
            ctx.distro(),
            version,
        ))),
        PhpRuntime::Container => Ok(Box::new(ContainerReloader { ctx, version })),
    }
}

/// `SIGUSR2` to the version's master, with the whole decision —
/// signal, start, or stop because the last pool has gone — left where it
/// belongs, in [`crate::fpmcontainer::reload`].
struct ContainerReloader<'a> {
    ctx: &'a OpContext,
    version: PhpVersion,
}

#[async_trait]
impl Reloader for ContainerReloader<'_> {
    fn name(&self) -> &'static str {
        "php-fpm container"
    }

    async fn reload(&self) -> std::result::Result<(), String> {
        match fpmcontainer::reload(self.ctx, self.version).await {
            Ok(plan) => reload_outcome(self.version, plan),
            Err(e) => Err(e.detail),
        }
    }
}

/// Whether a reload plan actually reached a master, in words.
///
/// Split out pure because the case it exists for is the one that is easy to get
/// wrong and impossible to see: [`fpmcontainer::ReloadPlan::NotOurs`] means the
/// container is **not on the machine**, and it is a perfectly ordinary answer
/// for a version this panel does not containerise. But this reloader is only
/// ever built for a version the registry says *is* a container, so here it means
/// the master vanished from under us — `docker rm` outside the panel, a daemon
/// that never came back.
///
/// Reporting that as a successful reload is the failure this whole step is
/// about: `mail.relay.set` rewrites every site's pool without asking whether PHP
/// is up, and it would write a hundred pool files nothing reads and report a
/// hundred successes while every one of those sites answered 502. An `Err` makes
/// the config engine put the file back and say why, and the two callers that
/// must not fail over this — `retire_and_log` and `site::remove_pool` — already
/// turn it into a log line rather than an error.
fn reload_outcome(
    version: PhpVersion,
    plan: fpmcontainer::ReloadPlan,
) -> std::result::Result<(), String> {
    let php = version.as_str();
    match plan {
        fpmcontainer::ReloadPlan::NotOurs => Err(format!(
            "PHP {php} runs in a container on this server and `{container}` is not on the \
             machine, so nothing read this pool file and every PHP {php} site answers 502. \
             Reinstall PHP {php} from the Stack page; your pool files, your sites and their \
             files are untouched.",
            container = fpmcontainer::container_name(version),
        )),
        fpmcontainer::ReloadPlan::Signal
        | fpmcontainer::ReloadPlan::Start
        | fpmcontainer::ReloadPlan::StopUntilThereIsAPool => Ok(()),
    }
}

/// `php-fpm -t` inside the running master.
struct ContainerValidator<'a> {
    ctx: &'a OpContext,
    version: PhpVersion,
}

#[async_trait]
impl Validator for ContainerValidator<'_> {
    fn name(&self) -> &'static str {
        "php-fpm -t (container)"
    }

    async fn validate(&self) -> std::result::Result<(), String> {
        let container = fpmcontainer::container_name(self.version);
        let docker = unihelm_distro::exec::resolve_program("docker")
            .map_err(|_| {
                format!(
                    "PHP {} runs in a container on this server and Docker is not \
                     installed, so its pool files cannot be checked.",
                    self.version.as_str()
                )
            })?
            .to_string_lossy()
            .into_owned();

        // A stopped master is not a failed validation, and this is the one place
        // this validator is deliberately softer than the host's. A version with
        // no pools is *stopped on purpose* — that is what
        // `fpmcontainer::ReloadPlan::StopUntilThereIsAPool` decides — so the very
        // first pool of a version is always written against a master that is
        // down. Refusing there would make it impossible to create the site that
        // starts it. The reload that follows starts the master and reports
        // whether it came up, with `docker logs` named in the sentence, so a pool
        // that will not parse is still caught and still explained.
        let status = fpmcontainer::status(self.ctx, self.version)
            .await
            .map_err(|e| e.detail)?;
        if !status.running {
            return Ok(());
        }

        let argv = [
            "exec".to_string(),
            container,
            "php-fpm".to_string(),
            "-t".to_string(),
        ];
        match unihelm_distro::Cmd::new(&docker)
            .args(argv)
            .timeout(VALIDATE_BUDGET)
            .run()
            .await
        {
            // FPM writes its verdict to stderr on success and on failure alike,
            // and that text — the file and the line — is what a user needs to
            // see. Paraphrasing it helps nobody.
            Ok(out) if out.success() => Ok(()),
            Ok(out) => Err(out.failure_text()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// `php-fpm -t` parses a pool tree and exits. Docker is either quick or wedged,
/// and this runs on a page somebody is waiting for.
const VALIDATE_BUDGET: Duration = Duration::from_secs(20);

// ===========================================================================
// The refusal in the other direction
// ===========================================================================

/// Refuse to install host packages for a version that already runs in a
/// container here.
///
/// [`crate::fpmcontainer::refuse_when_the_host_already_runs_this_version`] holds
/// the direction that matters most — a serving host version is never moved. This
/// is its mirror, and it is not symmetry for its own sake: the case it catches is
/// a container install that failed part way, leaving a record and a pool
/// directory, and an operator "fixing" it by installing the packages. That would
/// put a second master on the same pool directory and the same sockets, which is
/// the collision the whole step exists to prevent, arrived at from the side
/// nobody is watching.
pub async fn refuse_a_host_install_of_a_containerised_version(
    ctx: &OpContext,
    version: PhpVersion,
) -> Result<()> {
    let registry = fpmcontainer::registry(ctx.db()).await?;
    let Some(record) = registry.get(version.as_str()) else {
        return Ok(());
    };
    Err(host_install_refused(version, record))
}

/// The sentence, split from the lookup so it can be tested — and because the
/// sentence is the deliverable: "conflict" alone sends somebody to remove the
/// wrong thing.
///
/// The directory comes off the record rather than being recomputed. The two are
/// the same path today, but only the record knows which one the master is
/// actually bind-mounted to, and an operator sent to the wrong directory —
/// Debian's `/etc/php/8.3/fpm/pool.d` on a Remi box that keeps its pools in
/// `/etc/opt/remi/php83/php-fpm.d` — finds nothing there and concludes the panel
/// is confused about its own state.
fn host_install_refused(version: PhpVersion, record: &fpmcontainer::FpmRecord) -> UnihelmError {
    let php = version.as_str();
    UnihelmError::new(
        ErrorCode::Conflict,
        format!(
            "PHP {php} already runs in a container on this server (`{container}`), and it \
             holds the pool files in {pool_dir} and the sockets in {socket_dir} that host \
             packages would claim. There is only one PHP {php}: installing both would \
             leave two masters fighting over the same sites, and whichever started last \
             would win while the other's sites answered 502. Remove the containerised PHP \
             {php} from the Stack Manager first if this server is meant to run it as \
             packages — its sites are down between the two, so do it in a window where \
             that is acceptable.",
            container = record.container,
            pool_dir = record.pool_dir,
            socket_dir = paths::fpm_socket_dir().display(),
        ),
    )
    .with_field("version")
}

// ===========================================================================
// Why this version is not serving
// ===========================================================================

/// What the panel can say about one PHP version without anybody having to read
/// an nginx error log.
///
/// The state this exists for: the site row is `active`, the vhost is right, the
/// pool file is right, and the only thing wrong is a master nobody can see. Today
/// that is a 502 with nothing in the panel explaining it. This is the sentence
/// that explains it, in both modes — because "the FPM service is stopped" was
/// already an unexplained 502 on the host before any of this.
#[derive(Debug, Clone, Serialize)]
pub struct Availability {
    pub version: String,
    pub runtime: PhpRuntime,
    /// Whether this version exists on the server at all.
    pub installed: bool,
    /// Whether something can actually answer a request right now.
    pub serving: bool,
    /// The container, for a version that has one.
    pub container: Option<String>,
    /// What is wrong and what to do about it, in one sentence. `None` when
    /// nothing is.
    pub problem: Option<String>,
}

impl Availability {
    /// The sentence a task log should carry, if any.
    ///
    /// It is simply "whatever is wrong", and that is the point of it being its
    /// own function: gating the log on `!serving` looks harmless and drops
    /// exactly the sentence hardest to discover any other way. A master that is
    /// up with three of its five sockets missing *is* serving — two of its sites
    /// are 502ing, and that is the state [`container_problem`] was written to
    /// stop the panel calling perfect health.
    pub fn advice(&self) -> Option<&str> {
        self.problem.as_deref()
    }
}

/// Ask the machine what is true about a version.
pub async fn availability(ctx: &OpContext, version: PhpVersion) -> Result<Availability> {
    let php = version.as_str().to_string();

    if runtime_of(ctx.db(), version).await? == PhpRuntime::Host {
        let installed = host_has_php(ctx, version).await;
        let unit = ManagedUnit::PhpFpm { version }.unit_name(ctx.distro().info.family);
        let active = ctx
            .distro()
            .svc
            .status(&unit)
            .await
            .map(|s| s.is_active())
            .unwrap_or(false);
        return Ok(Availability {
            problem: host_problem(version, installed, active, unit.as_str()),
            version: php,
            runtime: PhpRuntime::Host,
            installed,
            serving: installed && active,
            container: None,
        });
    }

    let status = fpmcontainer::status(ctx, version).await?;
    Ok(Availability {
        problem: container_problem(version, &status),
        version: php,
        runtime: PhpRuntime::Container,
        installed: status.present,
        // A master with no pools is stopped on purpose and is not a fault; it is
        // also not serving, and saying otherwise would be the panel reporting
        // health about a version nothing can reach.
        serving: status.running && status.restarts == 0,
        container: Some(status.container),
    })
}

/// The host's own version of the silent 502.
fn host_problem(version: PhpVersion, installed: bool, active: bool, unit: &str) -> Option<String> {
    let php = version.as_str();
    match (installed, active) {
        (false, _) => Some(format!(
            "PHP {php} is not installed on this server. Install it from the Stack Manager; \
             until then every site on PHP {php} answers 502."
        )),
        (true, false) => Some(format!(
            "PHP {php} is installed on this server but `{unit}` is not running, so every \
             site on PHP {php} answers 502. Start it from the Services page or with \
             `systemctl start {unit}`; `systemctl status {unit}` says why it stopped."
        )),
        (true, true) => None,
    }
}

/// The sentence for a containerised version that cannot serve.
///
/// Pure, so the words can be tested without a Docker daemon — and the words are
/// as much the deliverable as the routing is. Each names the container, says what
/// a visitor is seeing, and ends with the thing to run.
///
/// The order is by how badly the operator is being misled: a master that is not
/// there at all, then one that is down, then one that `docker ps` calls healthy
/// while it crash-loops, then one that is up while some of its pools have no
/// socket — which is the case that used to be reported as perfect health.
fn container_problem(version: PhpVersion, status: &fpmcontainer::FpmStatus) -> Option<String> {
    let php = version.as_str();
    let container = &status.container;

    if !status.present {
        return Some(format!(
            "PHP {php} runs in a container on this server, and `{container}` is not on the \
             machine — it was removed outside the panel. Every PHP {php} site answers 502 \
             until it is back. Reinstall PHP {php} from the Stack page; your pool files, \
             your sites and their files are untouched."
        ));
    }

    if !status.running {
        // Stopped with no pools is the ordinary resting state of a version
        // nothing uses yet, and calling that a fault would put a red mark on a
        // perfectly healthy server. Stopped *with* pools is an outage.
        if status.pools == 0 {
            return Some(format!(
                "PHP {php} is installed in `{container}` and is stopped because no site \
                 uses it yet — PHP-FPM cannot run with no pool at all. It starts by itself \
                 with the first PHP {php} site."
            ));
        }
        return Some(format!(
            "PHP {php} runs in a container on this server and `{container}` is {state}, so \
             all {pools} site(s) on PHP {php} answer 502. Start it from the Stack page or \
             with `docker start {container}`; `docker logs {container}` says why it \
             stopped.",
            state = status.status,
            pools = status.pools,
        ));
    }

    if status.restarts > 0 {
        return Some(format!(
            "PHP {php}'s master `{container}` is up, but it has been restarted \
             {n} time(s): it is crashing and being put back, so PHP {php} sites answer 502 \
             between restarts. `docker logs {container}` says why — a pool file that will \
             not parse is the usual cause, and it names the line.",
            n = status.restarts,
        ));
    }

    if status.sockets_ready < status.pools {
        return Some(format!(
            "PHP {php}'s master `{container}` is running, but only {ready} of its {pools} \
             pools have a socket the web server can open — the other {missing} answer 502 \
             while the panel reports the version as healthy. `docker logs {container}` \
             names the pool it could not start.",
            ready = status.sockets_ready,
            pools = status.pools,
            missing = status.pools.saturating_sub(status.sockets_ready),
        ));
    }

    None
}

/// Whether this machine has host PHP for a version.
///
/// The panel's row and the machine's own unit, either one being enough — the
/// same pair, for the same reason, as
/// [`crate::fpmcontainer::refuse_when_the_host_already_runs_this_version`]: the
/// row covers an install the panel made, and the unit covers PHP that was here
/// before the panel was.
async fn host_has_php(ctx: &OpContext, version: PhpVersion) -> bool {
    let slug = format!("php{}", version.as_str());
    if let Ok(Some(row)) = ctx.db().component(&slug).await
        && row.status == ComponentStatus::Installed
    {
        return true;
    }
    let unit = ManagedUnit::PhpFpm { version }.unit_name(ctx.distro().info.family);
    ctx.distro()
        .svc
        .status(&unit)
        .await
        .map(|s| s.is_installed())
        .unwrap_or(false)
}

/// Refuse to put a site on a PHP version that is not on this server, and say out
/// loud when it is there but not serving.
///
/// The gate `site.create` and `site.update` need, replacing a check that asked
/// only about host packages and would therefore have called a containerised
/// version "not installed".
///
/// It refuses only what is genuinely absent. A master that is merely down is not
/// a reason to reject a site: a containerised version with no pools yet is
/// *always* down — that is what
/// [`crate::fpmcontainer::ReloadPlan::StopUntilThereIsAPool`] decides — and the
/// pool this very request is about to write is what starts it. So the rest goes
/// into the task log through [`Availability::problem`], which is where the
/// operator is already looking when their new site 502s.
pub async fn require_installed(ctx: &OpContext, version: PhpVersion) -> Result<()> {
    let found = availability(ctx, version).await?;
    if !found.installed {
        return Err(UnihelmError::new(
            ErrorCode::NotFound,
            found.problem.unwrap_or_else(|| {
                format!(
                    "PHP {} is not installed. Install it from the Stack Manager first.",
                    version.as_str()
                )
            }),
        )
        .with_field("php_version"));
    }
    if let Some(problem) = found.advice() {
        ctx.log(problem);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pool {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Pool {
        /// A pool directory that already holds a site's own pool.
        ///
        /// Which is the state every one of these tests means: the stock pool is
        /// only retired when something else can serve, because FPM will not
        /// start with no pool at all. `bare()` is for the tests about *that*.
        fn new() -> Self {
            let pool = Self::bare();
            std::fs::write(pool.path.join("uh_tenant.conf"), "[uh_tenant]\n").unwrap();
            pool
        }

        /// Nothing but whatever the test writes itself.
        fn bare() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().to_path_buf();
            Self { _dir: dir, path }
        }

        fn stock(&self) -> PathBuf {
            self.path.join("www.conf")
        }

        fn disabled(&self) -> PathBuf {
            self.path.join(format!("www.conf{DISABLED_SUFFIX}"))
        }

        fn write_stock(&self, body: &str) {
            std::fs::write(self.stock(), body).unwrap();
        }

        fn retire(&self) -> StockPool {
            retire_stock_pool_in(&self.path).unwrap()
        }
    }

    #[test]
    fn a_stock_pool_is_moved_aside_and_the_move_is_reversible() {
        let pool = Pool::new();
        pool.write_stock("[www]\nuser = apache\n");

        assert_eq!(pool.retire(), StockPool::Retired);
        assert!(!pool.stock().exists());

        // Still there, still readable, still exactly what it was — one `mv` from
        // being back.
        assert_eq!(
            std::fs::read_to_string(pool.disabled()).unwrap(),
            "[www]\nuser = apache\n"
        );
    }

    #[test]
    fn running_twice_is_not_an_error_and_does_not_lose_the_backup() {
        let pool = Pool::new();
        pool.write_stock("original\n");
        pool.retire();

        assert_eq!(pool.retire(), StockPool::Absent);
        assert_eq!(
            std::fs::read_to_string(pool.disabled()).unwrap(),
            "original\n"
        );
    }

    #[test]
    fn a_pool_restored_by_a_package_upgrade_is_retired_again() {
        // The reason this runs on every site creation and not once at install:
        // `dnf upgrade php83-php-fpm` puts www.conf back, and five workers as
        // `apache` reappear with it.
        let pool = Pool::new();
        pool.write_stock("original\n");
        pool.retire();

        pool.write_stock("pristine default from the package\n");
        assert_eq!(pool.retire(), StockPool::RemovedDuplicate);
        assert!(!pool.stock().exists());
        assert_eq!(
            std::fs::read_to_string(pool.disabled()).unwrap(),
            "original\n",
            "the first copy is the one that might carry an operator's edits"
        );
    }

    #[test]
    fn an_operator_can_ask_for_the_stock_pool_to_be_left_alone() {
        let pool = Pool::new();
        pool.write_stock("[www]\n; unihelm: keep - I need this\n");

        assert_eq!(pool.retire(), StockPool::KeptOnRequest);
        assert!(pool.stock().exists(), "an explicit opt-out must survive");
        // And it stays opted out, however many times we look at it.
        assert_eq!(pool.retire(), StockPool::KeptOnRequest);
    }

    #[test]
    fn a_system_that_never_had_one_is_not_a_failure() {
        let pool = Pool::new();
        assert_eq!(pool.retire(), StockPool::Absent);
    }

    #[test]
    fn the_real_path_is_the_one_php_fpm_reads() {
        // A typo here would move nothing and report success.
        assert!(
            stock_pool_path(Family::Rhel, PhpVersion::V83)
                .ends_with("etc/opt/remi/php83/php-fpm.d/www.conf"),
            "{:?}",
            stock_pool_path(Family::Rhel, PhpVersion::V83)
        );
        assert!(
            stock_pool_path(Family::Debian, PhpVersion::V83)
                .ends_with("etc/php/8.3/fpm/pool.d/www.conf"),
            "{:?}",
            stock_pool_path(Family::Debian, PhpVersion::V83)
        );
    }
}
#[cfg(test)]
mod only_pool_tests {
    use super::*;

    fn pool_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// The stock pool is the only one: leave it.
    ///
    /// This is a live server that had PHP before the panel arrived. Retiring
    /// `www.conf` left FPM with no pool at all, so it failed to start with "No
    /// pool defined" and every PHP site on the machine answered 502. A stopped
    /// FPM is not a hardened server.
    #[test]
    fn the_last_pool_is_never_retired() {
        let dir = pool_dir();
        std::fs::write(dir.path().join("www.conf"), "[www]\n").unwrap();

        assert_eq!(
            retire_stock_pool_in(dir.path()).unwrap(),
            StockPool::KeptAsOnlyPool
        );
        assert!(
            dir.path().join("www.conf").exists(),
            "the only pool was moved aside; FPM cannot start"
        );
    }

    /// Once a site has a pool of its own, the stock one goes as designed.
    #[test]
    fn the_stock_pool_retires_once_something_can_take_over() {
        let dir = pool_dir();
        std::fs::write(dir.path().join("www.conf"), "[www]\n").unwrap();
        std::fs::write(dir.path().join("uh_abc123.conf"), "[uh_abc123]\n").unwrap();

        assert_eq!(
            retire_stock_pool_in(dir.path()).unwrap(),
            StockPool::Retired
        );
        assert!(!dir.path().join("www.conf").exists());
        assert!(
            dir.path()
                .join(format!("www.conf{DISABLED_SUFFIX}"))
                .exists()
        );
    }

    /// An already-disabled copy is not a pool FPM can run, so it does not count
    /// as "something else is configured".
    #[test]
    fn a_disabled_copy_does_not_count_as_another_pool() {
        let dir = pool_dir();
        std::fs::write(dir.path().join("www.conf"), "[www]\n").unwrap();
        std::fs::write(
            dir.path().join(format!("old.conf{DISABLED_SUFFIX}")),
            "[old]\n",
        )
        .unwrap();

        assert_eq!(
            retire_stock_pool_in(dir.path()).unwrap(),
            StockPool::KeptAsOnlyPool,
            "FPM does not include .unihelm-disabled files"
        );
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;
    use crate::fpmcontainer::{FpmRecord, FpmStatus};
    use unihelm_distro::svc::UnitState;

    fn record(version: &str) -> FpmRecord {
        FpmRecord {
            version: version.to_string(),
            image: format!("php:{version}-fpm"),
            container: format!("unihelm-php-{version}"),
            pool_dir: format!("/etc/php/{version}/fpm/pool.d"),
        }
    }

    fn status(
        present: bool,
        running: bool,
        restarts: i64,
        pools: usize,
        ready: usize,
    ) -> FpmStatus {
        FpmStatus {
            version: "8.3".to_string(),
            container: "unihelm-php-8.3".to_string(),
            image: "php:8.3-fpm".to_string(),
            state: UnitState::Unknown,
            present,
            running,
            status: if running { "running" } else { "exited" }.to_string(),
            restarts,
            pools,
            sockets_ready: ready,
        }
    }

    // -----------------------------------------------------------------------
    // The default, which is the whole safety story
    // -----------------------------------------------------------------------

    /// **The rule this step is built around.** Every machine this build lands on
    /// has its PHP on the host and an empty registry — the registry did not
    /// exist until now — and every one of those versions must keep being served
    /// by the master that is serving it. A default of `Container` would send
    /// every pool write on every existing server at something that is not there.
    #[test]
    fn a_version_with_no_record_runs_on_the_host() {
        let empty = FpmRegistry::new();
        for &version in PhpVersion::ALL {
            assert_eq!(
                PhpRuntime::of(&empty, version),
                PhpRuntime::Host,
                "PHP {} read as a container on a server with no records at all",
                version.as_str()
            );
        }
    }

    /// And a record moves exactly one version. 8.3 and 8.4 are separate masters
    /// over separate pool directories, so containerising one says nothing about
    /// the other — least of all about one that is serving.
    #[test]
    fn only_the_recorded_version_becomes_a_container() {
        let mut registry = FpmRegistry::new();
        registry.insert("8.3".to_string(), record("8.3"));

        assert_eq!(
            PhpRuntime::of(&registry, PhpVersion::V83),
            PhpRuntime::Container
        );
        for &untouched in &[PhpVersion::V74, PhpVersion::V82, PhpVersion::V84] {
            assert_eq!(
                PhpRuntime::of(&registry, untouched),
                PhpRuntime::Host,
                "PHP {} moved because PHP 8.3 was containerised",
                untouched.as_str()
            );
        }
    }

    /// The registry is keyed the way the panel spells a version everywhere else.
    /// A key of `83` would read as "no record" and quietly route a containerised
    /// version at systemd.
    #[test]
    fn the_record_is_found_by_the_version_the_panel_writes() {
        let mut registry = FpmRegistry::new();
        registry.insert(PhpVersion::V83.as_str().to_string(), record("8.3"));
        assert_eq!(
            PhpRuntime::of(&registry, PhpVersion::V83),
            PhpRuntime::Container
        );
    }

    // -----------------------------------------------------------------------
    // The refusal in the other direction
    // -----------------------------------------------------------------------

    /// Installing host packages over a containerised version is the same
    /// collision arrived at from the side nobody watches, and the refusal has to
    /// say what to do — "conflict" alone sends somebody to remove the wrong
    /// thing.
    #[test]
    fn host_packages_are_refused_for_a_version_that_is_already_a_container() {
        let e = host_install_refused(PhpVersion::V83, &record("8.3"));
        assert_eq!(e.code, ErrorCode::Conflict);
        assert!(e.detail.contains("unihelm-php-8.3"), "{}", e.detail);
        assert!(e.detail.contains("two masters"), "{}", e.detail);
        assert!(
            e.detail.contains("Remove the containerised PHP 8.3"),
            "{}",
            e.detail
        );
        // The outage is stated rather than discovered.
        assert!(e.detail.contains("sites are down"), "{}", e.detail);
    }

    /// And it names the directory **this** machine keeps pools in. Recomputing
    /// it for one family sends every Remi operator to a Debian path that does
    /// not exist on their server, which reads as the panel not knowing where its
    /// own files are.
    #[test]
    fn the_refusal_names_the_pool_directory_this_server_actually_uses() {
        let remi = FpmRecord {
            pool_dir: paths::fpm_pool_dir(Family::Rhel, PhpVersion::V83)
                .display()
                .to_string(),
            ..record("8.3")
        };
        let e = host_install_refused(PhpVersion::V83, &remi);
        assert!(
            e.detail.contains("/etc/opt/remi/php83/php-fpm.d"),
            "{}",
            e.detail
        );
        assert!(
            !e.detail.contains("/etc/php/8.3/fpm"),
            "a Debian path on a Remi box: {}",
            e.detail
        );
    }

    // -----------------------------------------------------------------------
    // A reload that reached nothing is not a reload
    // -----------------------------------------------------------------------

    /// The registry says this version is a container and the container is not
    /// there. Calling that a successful reload leaves the pool file on disk with
    /// nothing reading it and the panel reporting success — which is the exact
    /// shape of the outage this step exists to prevent, and `mail.relay.set`
    /// rewrites every site's pool without asking whether PHP is up.
    #[test]
    fn a_reload_that_found_no_container_is_a_failure_not_a_success() {
        let e = reload_outcome(PhpVersion::V83, fpmcontainer::ReloadPlan::NotOurs)
            .expect_err("a master that is not on the machine did not read this pool");
        assert!(e.contains("unihelm-php-8.3"), "{e}");
        assert!(e.contains("502"), "{e}");
        assert!(e.contains("Reinstall PHP 8.3"), "{e}");
    }

    /// And a master that was signalled, started, or deliberately stopped for
    /// having no pools left did read the change — none of those is an error, and
    /// the last one least of all: it is what removing a version's final site
    /// does every time.
    #[test]
    fn a_master_that_was_reached_is_not_reported_as_a_failure() {
        for plan in [
            fpmcontainer::ReloadPlan::Signal,
            fpmcontainer::ReloadPlan::Start,
            fpmcontainer::ReloadPlan::StopUntilThereIsAPool,
        ] {
            assert!(
                reload_outcome(PhpVersion::V83, plan).is_ok(),
                "{plan:?} reached the master and was called a failure"
            );
        }
    }

    // -----------------------------------------------------------------------
    // The sentence has to survive as far as the log
    // -----------------------------------------------------------------------

    /// A running master with sites whose sockets are missing is *serving* — some
    /// of it is. Gating the log line on `serving` would drop the one sentence
    /// nobody can reconstruct from the panel, on the one state the panel used to
    /// call healthy.
    #[test]
    fn a_partly_serving_version_still_says_what_is_wrong() {
        let partial = status(true, true, 0, 5, 3);
        let found = Availability {
            version: "8.3".to_string(),
            runtime: PhpRuntime::Container,
            installed: true,
            serving: true,
            container: Some(partial.container.clone()),
            problem: container_problem(PhpVersion::V83, &partial),
        };
        assert!(
            found
                .advice()
                .is_some_and(|s| s.contains("3 of its 5 pools")),
            "{:?}",
            found.advice()
        );
    }

    /// And a healthy version puts nothing in the log, so a line that does appear
    /// means something.
    #[test]
    fn a_healthy_version_has_nothing_to_say() {
        let found = Availability {
            version: "8.3".to_string(),
            runtime: PhpRuntime::Container,
            installed: true,
            serving: true,
            container: Some("unihelm-php-8.3".to_string()),
            problem: container_problem(PhpVersion::V83, &status(true, true, 0, 4, 4)),
        };
        assert!(found.advice().is_none());
    }

    // -----------------------------------------------------------------------
    // A better answer than a bare 502
    // -----------------------------------------------------------------------

    /// The thing this step owed the operator. Today a missing FPM is a 502 with
    /// nothing in the panel explaining it; each of these says what is down, what
    /// a visitor is seeing, and the command that fixes it.
    #[test]
    fn a_container_that_cannot_serve_is_explained_in_words() {
        let gone = container_problem(PhpVersion::V83, &status(false, false, 0, 3, 0))
            .expect("a container that is not there is a problem");
        assert!(gone.contains("removed outside the panel"), "{gone}");
        assert!(gone.contains("untouched"), "{gone}");

        let stopped = container_problem(PhpVersion::V83, &status(true, false, 0, 3, 0))
            .expect("a stopped master with sites on it is a problem");
        assert!(stopped.contains("502"), "{stopped}");
        assert!(stopped.contains("3 site(s)"), "{stopped}");
        assert!(
            stopped.contains("docker start unihelm-php-8.3"),
            "{stopped}"
        );

        let looping = container_problem(PhpVersion::V83, &status(true, true, 4, 3, 3))
            .expect("a crash loop is a problem, however healthy `docker ps` looks");
        assert!(looping.contains("restarted 4"), "{looping}");
        assert!(looping.contains("docker logs unihelm-php-8.3"), "{looping}");
    }

    /// The case the panel used to report as perfect health: the master is up,
    /// and two of its five sites have no socket for nginx to open.
    #[test]
    fn a_running_master_with_unreachable_pools_is_not_called_healthy() {
        let partial = container_problem(PhpVersion::V83, &status(true, true, 0, 5, 3))
            .expect("three of five sockets is not health");
        assert!(partial.contains("3 of its 5 pools"), "{partial}");
        assert!(partial.contains("other 2"), "{partial}");
    }

    /// A version nobody uses yet is stopped **on purpose** — FPM cannot run with
    /// no pool — and marking that as a fault would put a red light on a server
    /// where nothing is wrong.
    #[test]
    fn a_version_with_no_sites_is_not_reported_as_broken() {
        let idle = container_problem(PhpVersion::V83, &status(true, false, 0, 0, 0))
            .expect("it is worth a sentence, just not an alarming one");
        assert!(idle.contains("no site"), "{idle}");
        assert!(idle.contains("starts by itself"), "{idle}");
        assert!(!idle.contains("502"), "{idle}");
    }

    /// And a healthy master says nothing at all, so the sentences above mean
    /// something when they do appear.
    #[test]
    fn a_healthy_container_has_nothing_to_explain() {
        assert!(container_problem(PhpVersion::V83, &status(true, true, 0, 4, 4)).is_none());
    }

    /// The host has the same silent failure — installed, service stopped, every
    /// site 502 — and before this it had no sentence either.
    #[test]
    fn a_stopped_host_service_is_explained_too() {
        let stopped = host_problem(PhpVersion::V83, true, false, "php8.3-fpm.service")
            .expect("an installed but stopped FPM is a problem");
        assert!(stopped.contains("502"), "{stopped}");
        assert!(
            stopped.contains("systemctl start php8.3-fpm.service"),
            "{stopped}"
        );

        assert!(host_problem(PhpVersion::V83, true, true, "php8.3-fpm.service").is_none());
        assert!(
            host_problem(PhpVersion::V83, false, false, "php8.3-fpm.service")
                .expect("not installed is a problem")
                .contains("not installed")
        );
    }
}
