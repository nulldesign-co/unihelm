//! Running one PHP version's FPM master as one container.
//!
//! Step three of `docs/design/containerised-runtimes.md`, and the last one
//! because it is the one that can take a running server offline. Step one was
//! [`crate::engine`] (databases and caches) and step two [`crate::appcontainer`]
//! (one container per application); this file is deliberately shaped like both —
//! resolve an image from the catalogue, name a container deterministically, read
//! the state back rather than trusting an exit status, and never let a removal
//! touch anything the panel did not create.
//!
//! ## The unit of migration is the version, not the site
//!
//! One FPM master holds one pool per site. Move PHP 8.3 into a container and
//! every 8.3 site moves with it, together, because there is only one 8.3. That
//! is unlike [`crate::appcontainer`], where each application was independent and
//! could be moved on its own.
//!
//! It follows that a host 8.3 and a container 8.3 cannot both exist. They would
//! write their pool files into different places while both claiming the same
//! sockets and the same sites, and whichever master started last would own
//! `/run/unihelm/fpm`: the other's sites answer 502 with every page in the panel
//! reporting health. So:
//!
//! **A PHP version already installed on the host stays on the host.** Nothing in
//! this module moves one across — see
//! [`refuse_when_the_host_already_runs_this_version`], which is called before
//! anything is pulled or created. A version installed fresh as a container is a
//! container, and that is the only way one comes to exist. Moving an existing
//! version is a deliberate act with a visible outage window; this file refuses
//! it and says what to do instead, exactly as step two refused to containerise a
//! Go application rather than inventing a way.
//!
//! ## The two mechanisms that make it work
//!
//! **uids must agree.** `uh_abc123` is uid 1007 on the host, and the pool inside
//! the container must run as 1007 or every file PHP writes into that tenant's
//! home belongs to somebody else. The container does not create accounts: the
//! host's `/etc/passwd` and `/etc/group` come in read-only and the pools name
//! the accounts they already name. That is also what makes `listen.group = nginx`
//! resolve inside the container — see [`SocketVerdict`].
//!
//! **The socket directory is the contract.** [`paths::fpm_socket_dir`] is
//! bind-mounted in, so `fastcgi_pass unix:/run/unihelm/fpm/<site>-php83.sock` in
//! a vhost reaches the pool without knowing anything changed. The comment on
//! that function is worth reading before touching this file: when the directory
//! is missing, every PHP site 502s while the panel reports healthy.
//!
//! **The web server is not part of this.** nginx, Apache and LiteSpeed all reach
//! the same socket and only their directive differs, which is already their
//! business. Nothing in `templates/nginx` is touched by this file, and nothing
//! should be.
//!
//! ## The four hazards, and what this file does about each
//!
//! 1. **A pool must not be lost.** The pool directory is *bind-mounted*, so the
//!    files the panel writes are the files the master reads. Nothing is copied
//!    in — a copy goes stale the moment a site is created — and the mount is
//!    read-only, because the panel writes pools and the container only reads
//!    them.
//! 2. **Removing the container must not remove the pools or the sockets.**
//!    [`remove_argv`] carries neither `-v` nor `-f`, and nothing in this file
//!    deletes a path (`nothing_here_deletes_a_pool_or_a_socket` asserts that
//!    against the source text). The pools are configuration the panel owns; the
//!    sockets FPM unlinks and recreates itself.
//! 3. **FPM will not start with no pool at all.** That is the bug that took a
//!    production site offline: retiring the only pool left the master with
//!    nothing to run, it would not start, and the site answered 502. So a
//!    version whose pool directory is empty is **installed and left stopped**,
//!    not started and not failed — see [`ReloadPlan`]. The first site of that
//!    version starts it; the last site leaving stops it again, rather than
//!    signalling a master that would then die and restart-loop.
//! 4. **The socket must be reachable by the web server's user.** It is created
//!    inside the container with the pool's uid and read from outside by nginx.
//!    The pool file already says `listen.owner`, `listen.group` and
//!    `listen.mode = 0660`; what this module has to supply is the ability to
//!    *apply* them — the `/etc/group` mount so the group name resolves, and
//!    `CAP_CHOWN`/`CAP_FOWNER` so a root master may chown and chmod the socket
//!    it made. [`check_socket`] then reads back what was actually produced,
//!    because the only trustworthy answer about a socket's group is the one the
//!    kernel gives.
//!
//! ## The one thing that changes for a site, which the caller must say out loud
//!
//! A container has its own network namespace, so `127.0.0.1` inside it is the
//! container and not the host. A PHP application configured against
//! `127.0.0.1:3306` — which is where [`crate::engine`] publishes a containerised
//! database — will not connect, and `localhost` for MySQL is a unix socket path
//! that is not in the image either. The host is reachable as
//! [`HOST_ALIAS`], which [`run_argv`] maps explicitly, and that is the sentence
//! the UI has to show beside a containerised PHP version. It is the same
//! sentence [`crate::appcontainer`] already needed, and it is one more reason
//! hazard-free operation means *new* sites on a containerised version rather
//! than moving old ones.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use unihelm_config::paths;
use unihelm_core::{ErrorCode, PhpVersion, Result, UnihelmError};
use unihelm_db::{ComponentStatus, Db};
use unihelm_distro::Family;
use unihelm_distro::svc::{ManagedUnit, UnitState};

use crate::catalogue;
use crate::docker::{ContainerRef, ImageRef};
use crate::registry::OpContext;

/// Docker's own client, not the daemon socket — the same choice, for the same
/// reason, as [`crate::docker`], [`crate::engine`] and [`crate::appcontainer`].
const DOCKER: &str = "docker";

/// The catalogue entry every version here comes off.
const PHP_SLUG: &str = "php";

/// Where the official image reads its pool files from.
///
/// The one asymmetric mount in this file. Everything else is bind-mounted at the
/// path it already has, so an absolute path in a log line or an error message
/// names a file the operator can open on the host; the pool directory cannot be,
/// because the host's is a distribution layout (`/etc/php/8.3/fpm/pool.d` on
/// Debian, `/etc/opt/remi/php83/php-fpm.d` on RHEL) and the image's is neither.
///
/// Mounting over it also hides the image's own `www.conf` and `zz-docker.conf`,
/// which is wanted twice over: `www.conf` is the unisolated stock pool
/// [`crate::fpm`] exists to retire, and hiding it means it is never there in the
/// first place. The cost is the rest of `zz-docker.conf` — see [`COMMAND`].
const IMAGE_POOL_DIR: &str = "/usr/local/etc/php-fpm.d";

/// The name the host answers to from inside the container.
///
/// [`crate::appcontainer::HOST_ALIAS`]'s value and its reasoning: a *name*
/// rather than an address, because the bridge subnet is Docker's to choose.
const HOST_ALIAS: &str = "host.docker.internal";

/// What the image is asked to run, and every word of it is load bearing.
///
/// - `--nodaemonize`. The official image puts `daemonize = no` in
///   `zz-docker.conf`, which lives in the pool directory this module mounts over
///   — so without this flag the master forks, PID 1 exits, and the container
///   stops a moment after `docker run` reported success. Passing it on the argv
///   makes it a property of this file rather than of a file we hide.
/// - `--force-stderr`. FPM's early errors — a pool that names an account the
///   container cannot resolve, a socket directory it cannot write — otherwise go
///   to a log file *inside* the container, so `docker logs` is empty and the
///   operator is told only that PHP "did not start". This is what puts the
///   reason in [`log_tail`], and therefore in the error message.
const COMMAND: &[&str] = &["php-fpm", "--nodaemonize", "--force-stderr"];

/// Capabilities the master keeps, having dropped everything else.
///
/// The master **runs as root inside the container**, and must: a pool names a
/// user, and only root can become somebody else. Copying
/// [`crate::appcontainer`]'s `--user` here would produce a master that logs
/// "user directive ignored" and runs every tenant's code as one account — every
/// site on that version sharing one uid, which is the isolation boundary gone.
///
/// So the boundary is drawn with capabilities instead, and this set is exactly
/// what an FPM master does:
///
/// - `SETUID` / `SETGID` — become the pool's account. Without these no pool
///   starts.
/// - `CHOWN` — `listen.owner` and `listen.group` on the socket it just created.
/// - `FOWNER` — `listen.mode` on that socket *after* the chown, when it is no
///   longer root's to chmod. Getting this wrong leaves a socket nginx cannot
///   open, which is a 502 with nothing in any log to explain it.
/// - `KILL` — signal its own workers, which are a different uid by then. Root
///   without `CAP_KILL` cannot signal another user's process, so a graceful
///   worker shutdown and `pm.process_idle_timeout` both quietly stop working.
/// - `DAC_OVERRIDE` — open per-site log files under [`paths::site_log_root`],
///   which provisioning creates root-owned and 0750.
///
/// Everything a host FPM holds and never uses is gone: `SYS_ADMIN`, `NET_ADMIN`,
/// `NET_RAW`, `MKNOD`, `SYS_PTRACE`, `SYS_CHROOT`, the audit capabilities. This
/// is strictly tighter than the master running on the host today.
const KEPT_CAPABILITIES: &[&str] = &[
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "KILL",
    "SETGID",
    "SETUID",
];

/// How FPM is asked to stop, and it is not the default.
///
/// `docker stop` sends `SIGTERM`, which is FPM's *immediate* terminate: workers
/// are killed where they stand. `SIGQUIT` is its graceful stop — workers finish
/// the request they are serving and then exit. One master holds every site on
/// this version, so the difference is not one dropped request, it is every
/// in-flight request on every 8.3 site at once.
const STOP_SIGNAL: &str = "SIGQUIT";

/// How a running master is told to re-read its pools.
///
/// The host path signals a reload through `UnitReloader::fpm`, whose
/// `SvcAction::Reload` is `systemctl reload php8.3-fpm` — and systemd's reload
/// for FPM is `SIGUSR2`, which re-reads the whole configuration (the pool
/// directory glob included) and drains workers gracefully. This is that same
/// signal, delivered the only way there is to a container.
const RELOAD_SIGNAL: &str = "SIGUSR2";

/// How long an image is given to arrive. [`crate::engine`]'s number and its
/// reasoning: a killed pull does not retry, it throws away the layers it had.
const PULL_BUDGET: Duration = Duration::from_secs(15 * 60);

/// A lifecycle command's budget. A stop takes the full grace period plus the
/// drain, and the IPC layer's own timeout is 30s.
const ACTION_BUDGET: Duration = Duration::from_secs(25);

/// A read — an inspect or a log tail. Docker is either quick or wedged.
const READ_BUDGET: Duration = Duration::from_secs(10);

/// How long the master is given to exit on [`STOP_SIGNAL`] before Docker
/// SIGKILLs it. Longer than Docker's default ten seconds on purpose: the point
/// of `SIGQUIT` is that a request in flight gets to finish, and the pool
/// template allows a request 120 seconds before it terminates one itself.
const GRACE_SECONDS: u32 = 30;

/// How long every pool is given to have its socket on the host.
///
/// FPM binds its sockets during start-up, before it forks a single worker, so a
/// healthy master is answering in well under a second. The budget is generous
/// against a loaded box rather than against FPM, and short enough that a master
/// which is *not* going to come up still fails while somebody is watching —
/// `stack::wait_until_ready`'s number, for that reason.
const SERVING_BUDGET: Duration = Duration::from_secs(45);

/// Lines of the master's own log carried into a failure message.
const LOG_LINES: u32 = 30;

// ---------------------------------------------------------------------------
// Identity: the image, the container
// ---------------------------------------------------------------------------

/// The image one PHP version runs on: `php:8.3-fpm`.
///
/// **Pure**, for [`crate::appcontainer::plan_image`]'s reason: a caller decides
/// whether a version *can* be a container before touching the machine, and
/// certainly before looking for a PHP interpreter on a host that is not meant to
/// have one.
///
/// The tag is the catalogue's version verbatim, which is the whole promise of
/// the Stack page: 8.3 on the page means `php:8.3-fpm` here, never a floating
/// `latest` that would turn a restart into a major-version upgrade landing on
/// somebody's production sites.
pub fn image_name(version: PhpVersion) -> String {
    format!("{PHP_SLUG}:{}-fpm", version.as_str())
}

/// The container one PHP version runs in: `unihelm-php-8.3`.
///
/// Derived rather than stored, so resolving it twice can never produce two
/// containers — and one per version, never one per site, because one master
/// already multiplexes every site of that version.
pub fn container_name(version: PhpVersion) -> String {
    format!("unihelm-{PHP_SLUG}-{}", version.as_str())
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// One PHP version resolved into everything needed to run its FPM master.
///
/// Every string that reaches an argv below is built here, out of
/// [`PhpVersion`], [`Family`] and [`paths`] — there is no field a caller can put
/// a flag in, which is the property [`crate::docker`] refuses to give up and
/// this file inherits.
#[derive(Debug, Clone)]
pub struct FpmContainer {
    version: PhpVersion,
    container: ContainerRef,
    image: ImageRef,
    /// The panel's own pool directory for this version, on the host. **The
    /// files the panel writes are the files the master reads**; nothing is
    /// copied.
    pool_dir: PathBuf,
    /// [`paths::fpm_socket_dir`] — the contract with the web server.
    socket_dir: PathBuf,
    /// Where the sites are.
    home_root: PathBuf,
    /// Where each pool's `access.log`, `slowlog` and `error_log` are opened.
    /// Not one of the four mounts the design names, and the master will not
    /// start without it: FPM opens those files before it accepts a request, and
    /// a pool whose log directory is not there fails the whole master.
    log_root: PathBuf,
}

impl FpmContainer {
    /// Resolve a PHP version into a container plan.
    ///
    /// `family` decides only where the *host* keeps pool files, because that is
    /// where `site::render_pool` writes them and this module's job is to run
    /// what the panel wrote — not to invent a second location that would divide
    /// a version's pools across two directories.
    pub fn plan(family: Family, version: PhpVersion) -> Result<Self> {
        // Through the catalogue, so a version this panel does not offer cannot
        // become a pull that fails minutes later with a message about a
        // manifest.
        if catalogue::version(PHP_SLUG, version.as_str()).is_none() {
            return Err(UnihelmError::new(
                ErrorCode::InvalidPhpVersion,
                format!(
                    "PHP {} is not a version this panel offers, so there is no \
                     `php:{}-fpm` image to run it from.",
                    version.as_str(),
                    version.as_str()
                ),
            )
            .with_field("version"));
        }

        Ok(Self {
            version,
            container: ContainerRef::parse(&container_name(version))?,
            image: ImageRef::parse(&image_name(version))?,
            pool_dir: paths::fpm_pool_dir(family, version),
            socket_dir: paths::fpm_socket_dir(),
            home_root: paths::home_root(),
            log_root: paths::site_log_root(),
        })
    }

    pub fn version(&self) -> PhpVersion {
        self.version
    }

    pub fn container(&self) -> &ContainerRef {
        &self.container
    }

    pub fn image(&self) -> &ImageRef {
        &self.image
    }

    /// The directory the panel writes pool files into and the container reads
    /// them from. **Never written by this module.**
    pub fn pool_dir(&self) -> &Path {
        &self.pool_dir
    }

    pub fn socket_dir(&self) -> &Path {
        &self.socket_dir
    }

    /// What to call this in a sentence somebody reads.
    pub fn label(&self) -> String {
        format!("PHP {} FPM", self.version.as_str())
    }

    /// What is configured to run inside it, read off the mounted directory.
    pub fn pools(&self) -> PoolSet {
        PoolSet::read(&self.pool_dir)
    }
}

// ---------------------------------------------------------------------------
// What is in the pool directory
// ---------------------------------------------------------------------------

/// One pool file, and the socket it claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    pub file: PathBuf,
    /// The unix socket from its `listen` line, or `None` for a pool that
    /// listens on TCP — which the panel never writes but an imported
    /// configuration may.
    pub socket: Option<PathBuf>,
}

/// Everything FPM would run for one version.
///
/// Read from the directory rather than from the database on purpose: the
/// directory *is* the configuration, the master reads exactly it, and a count
/// taken from a table would disagree with reality the first time somebody
/// dropped a file in by hand — which is how "FPM will not start" becomes "the
/// panel is broken".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolSet {
    pub pools: Vec<Pool>,
}

impl PoolSet {
    pub fn read(dir: &Path) -> Self {
        let Ok(entries) = std::fs::read_dir(dir) else {
            // A directory that is not there holds no pools, which is the same
            // answer as an empty one and leads to the same decision.
            return Self::default();
        };

        let mut pools: Vec<Pool> = entries
            .flatten()
            .map(|e| e.path())
            // FPM includes `*.conf` and nothing else, so `.unihelm-disabled` —
            // the suffix [`crate::fpm`] retires the stock pool with — is
            // correctly invisible here too.
            .filter(|p| p.extension().is_some_and(|x| x == "conf"))
            .filter_map(|path| {
                let body = std::fs::read_to_string(&path).ok()?;
                pool_in(&body).then(|| Pool {
                    socket: listen_socket(&body),
                    file: path,
                })
            })
            .collect();

        // Stable, so two calls in a row describe the same server.
        pools.sort_by(|a, b| a.file.cmp(&b.file));
        Self { pools }
    }

    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pools.len()
    }

    /// The sockets that must appear on the host for this version to be serving.
    pub fn sockets(&self) -> Vec<&Path> {
        self.pools
            .iter()
            .filter_map(|p| p.socket.as_deref())
            .collect()
    }
}

/// Whether a file declares a pool, as opposed to only global settings.
///
/// This is the exact question "will FPM start?" turns on. `[global]` is
/// configuration *about* the master; any other section is a pool, and a master
/// with none of the latter exits with "No pool defined".
fn pool_in(body: &str) -> bool {
    body.lines().map(str::trim).any(|line| {
        line.starts_with('[') && line.ends_with(']') && !line.eq_ignore_ascii_case("[global]")
    })
}

/// The `listen` value, when it is a unix socket path.
///
/// Read out of the file rather than recomputed from
/// [`paths::fpm_socket`], because the file is what the master obeys: a pool
/// somebody edited by hand, or one written by an older build with a different
/// naming scheme, would otherwise be checked against a socket that never
/// existed and reported as a failure to start.
///
/// `listen.owner`, `listen.group`, `listen.mode` and `listen.backlog` sit
/// directly above it in the template, so the key is compared whole.
fn listen_socket(body: &str) -> Option<PathBuf> {
    body.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with(';') || line.starts_with('#') {
            return None;
        }
        let (key, value) = line.split_once('=')?;
        if key.trim() != "listen" {
            return None;
        }
        // An ini comment may follow the value. No socket this panel writes can
        // contain a semicolon, so cutting at one cannot truncate a real path.
        let value = value.split(';').next().unwrap_or_default().trim();
        value.starts_with('/').then(|| PathBuf::from(value))
    })
}

/// Pools whose socket the container could not possibly create.
///
/// FPM binds every pool's socket while starting and **fails the whole master**
/// if one of them will not bind, so a single pool naming a directory that is not
/// mounted takes down every other site on the version rather than only its own.
///
/// The case is not hypothetical: it is where the refusal in
/// [`host_owns_it_error`] sends an operator. Removing the distribution's PHP
/// without purging it leaves the package's own `www.conf` behind in
/// [`paths::fpm_pool_dir`], listening on `/run/php/php8.3-fpm.sock` — a
/// directory the image does not have and this module does not mount. Installing
/// the version as a container then binds that file in and the master never
/// starts, which is the same outage as the original bug arrived at from the
/// other side.
///
/// Only unix sockets are judged. A pool listening on TCP binds nothing on the
/// filesystem: nothing is published so nothing off the box can reach it, but it
/// does not stop the master, and refusing an install over one would be inventing
/// a failure.
fn sockets_the_container_cannot_create<'a>(
    plan: &FpmContainer,
    pools: &'a PoolSet,
) -> Vec<&'a Pool> {
    pools
        .pools
        .iter()
        .filter(|pool| {
            pool.socket.as_deref().is_some_and(|socket| {
                !socket.starts_with(&plan.socket_dir) && !socket.starts_with(&plan.home_root)
            })
        })
        .collect()
}

/// The refusal for one such pool, naming the file rather than the symptom.
///
/// `docker logs` would eventually say "unable to bind listening socket", but by
/// then the version is installed, the master is crash-looping and the operator
/// is reading Docker output to find out that one leftover file from a package
/// they removed is holding every site down.
fn a_pool_this_container_cannot_run(plan: &FpmContainer, pool: &Pool) -> UnihelmError {
    let php = plan.version.as_str();
    UnihelmError::new(
        ErrorCode::Conflict,
        format!(
            "{file} asks PHP {php} to listen on {socket}, which is not inside {sockets} or \
             {homes} — the only directories this container can see. FPM binds every pool's \
             socket while it starts and fails the whole master if one of them will not \
             bind, so this single file would stop every PHP {php} site on this server, not \
             just its own. It is almost always the distribution's own `www.conf`, left in \
             {pool_dir} by removing the host PHP {php} without purging it. Move it aside or \
             delete it — the panel retires such a pool by renaming it \
             `www.conf.unihelm-disabled`, which FPM does not include — and install PHP \
             {php} again.",
            file = pool.file.display(),
            socket = pool
                .socket
                .as_deref()
                .unwrap_or(Path::new("(no socket)"))
                .display(),
            sockets = plan.socket_dir.display(),
            homes = plan.home_root.display(),
            pool_dir = plan.pool_dir.display(),
        ),
    )
    .with_field("version")
}

// ---------------------------------------------------------------------------
// The argv
// ---------------------------------------------------------------------------

fn pull_argv(image: &ImageRef) -> Vec<String> {
    vec!["pull".to_string(), image.as_str().to_string()]
}

/// The whole `docker run`.
///
/// **No published port appears here, and none may.** This master speaks over a
/// unix socket in a shared directory; publishing a port would put a PHP
/// interpreter on the network, and Docker's DNAT rule is inserted ahead of
/// `INPUT`, so it would answer the internet whatever ufw had been told.
/// `nothing_is_published` holds that against the argv.
fn run_argv(plan: &FpmContainer) -> Vec<String> {
    let mut argv = vec![
        "run".to_string(),
        "--detach".to_string(),
        "--name".to_string(),
        plan.container.as_str().to_string(),
        // The containerised form of `systemctl enable`: PHP must be back after a
        // reboot. `unless-stopped` rather than `always`, and that distinction
        // carries weight here — a version this module stopped for having no
        // pools (hazard 3) must stay stopped when the daemon restarts, or it
        // would come back, find nothing to run, and restart-loop.
        "--restart".to_string(),
        "unless-stopped".to_string(),
        // Graceful. See [`STOP_SIGNAL`].
        "--stop-signal".to_string(),
        STOP_SIGNAL.to_string(),
        // **The pools**, read-only. Bind-mounted rather than copied so the files
        // the panel writes are the files the master reads; read-only because the
        // panel owns them and the master only ever reads them, which also means
        // nothing inside the container can rewrite a pool into one that runs as
        // another tenant.
        "--volume".to_string(),
        format!("{}:{IMAGE_POOL_DIR}:ro", plan.pool_dir.display()),
        // **The contract with the web server.** Read-write: this is where FPM
        // creates the sockets nginx connects to, and the same directory on both
        // sides so the vhost's `fastcgi_pass` needs no translating.
        "--volume".to_string(),
        format!("{0}:{0}", plan.socket_dir.display()),
        // **The host's accounts**, read-only, which is what makes uid 1007
        // inside mean `uh_abc123` outside — and what makes `listen.group = nginx`
        // resolve to the gid nginx actually runs as. Read-only is not decoration:
        // a writable bind of the host's passwd inside a container running
        // tenant-authored code is the whole machine.
        "--volume".to_string(),
        "/etc/passwd:/etc/passwd:ro".to_string(),
        "--volume".to_string(),
        "/etc/group:/etc/group:ro".to_string(),
        // **The sites.** One master serves every tenant on this version, so it
        // is the home root and not one home — a per-tenant mount would mean
        // recreating the container, and therefore an outage for every site on
        // the version, each time a tenant was created. The boundary does not
        // move: it is the pool's uid and `open_basedir`, exactly as on the host.
        "--volume".to_string(),
        format!("{0}:{0}", plan.home_root.display()),
        // Per-site logs. FPM opens `access.log` and `slowlog` while starting, so
        // a missing directory here is not a missing log, it is a master that
        // will not start.
        "--volume".to_string(),
        format!("{0}:{0}", plan.log_root.display()),
        // 127.0.0.1 inside a container is the container. A site talking to a
        // containerised database needs a name for the host, and this is Docker's
        // own.
        "--add-host".to_string(),
        format!("{HOST_ALIAS}:host-gateway"),
        // A setuid binary inside the image would otherwise be a way for a worker
        // that has already dropped to a tenant uid to climb back out.
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        // Everything, then back what an FPM master actually is. See
        // [`KEPT_CAPABILITIES`] — and note there is no `--user`, deliberately.
        "--cap-drop".to_string(),
        "ALL".to_string(),
    ];

    for capability in KEPT_CAPABILITIES {
        argv.push("--cap-add".to_string());
        argv.push((*capability).to_string());
    }

    // No `--memory`, and that is a decision rather than an omission. A pool
    // already carries its tenant's ceiling — `pm.max_children` sized from their
    // plan, times `memory_limit` — so a container-wide ceiling would add
    // nothing except a new way to fail: the kernel's OOM killer takes the
    // largest process in the cgroup, which is the master, and every site on the
    // version goes down together to punish one of them.
    //
    // No `--cgroup-parent` either: a tenant slice cannot hold a process tree
    // that serves every tenant, and on the host this master is in `system.slice`
    // for the same reason.

    argv.push(plan.image.as_str().to_string());
    argv.extend(COMMAND.iter().map(|c| (*c).to_string()));
    argv
}

/// Stop, gracefully. `-t` is how long Docker waits after [`STOP_SIGNAL`] before
/// it stops being graceful.
fn stop_argv(container: &ContainerRef) -> Vec<String> {
    vec![
        "stop".to_string(),
        "-t".to_string(),
        GRACE_SECONDS.to_string(),
        container.as_str().to_string(),
    ]
}

fn start_argv(container: &ContainerRef) -> Vec<String> {
    vec!["start".to_string(), container.as_str().to_string()]
}

/// Tell the running master to re-read its pools.
///
/// A signal and **not** `docker restart`, which is the single most important
/// line in this file for anybody with sites on the box. One master holds every
/// site on this version, so restarting it because one site was added or changed
/// is an outage for all of the others; `SIGUSR2` re-reads the pool directory and
/// drains workers, so nothing in flight is dropped. It is the same signal
/// `systemctl reload php8.3-fpm` sends on the host path.
fn reload_argv(container: &ContainerRef) -> Vec<String> {
    vec![
        "kill".to_string(),
        "--signal".to_string(),
        RELOAD_SIGNAL.to_string(),
        container.as_str().to_string(),
    ]
}

/// Bare `rm`, and both omissions are load bearing.
///
/// No `--force`, which is a SIGKILL to a master serving requests. No
/// `--volumes`: there are no volumes here, only bind mounts of the panel's pool
/// files, the tenants' sites and the socket directory — a flag meaning "and
/// delete the data" has no business on the argv that removes a PHP version.
fn remove_argv(container: &ContainerRef) -> Vec<String> {
    vec!["rm".to_string(), container.as_str().to_string()]
}

fn logs_argv(container: &ContainerRef, tail: u32) -> Vec<String> {
    vec![
        "logs".to_string(),
        "--tail".to_string(),
        tail.to_string(),
        container.as_str().to_string(),
    ]
}

/// `{{.State.Running}}` is what decisions are made from; the rest is why.
///
/// `RestartCount` is the field that catches a master which starts, finds a pool
/// it cannot honour, dies, and is put back by the restart policy — "running" by
/// the time anything asks.
const INSPECT_FORMAT: &str = concat!(
    "{{.State.Running}}\t{{.State.Status}}\t{{.State.ExitCode}}\t{{.RestartCount}}",
    "\t{{.Id}}"
);

fn inspect_argv(container: &ContainerRef) -> Vec<String> {
    vec![
        "inspect".to_string(),
        // Without `--type container`, `docker inspect` will happily answer about
        // an *image* of the same name — and `php:8.3-fpm` is an image that
        // exists.
        "--type".to_string(),
        "container".to_string(),
        "--format".to_string(),
        INSPECT_FORMAT.to_string(),
        container.as_str().to_string(),
    ]
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// What Docker says about one version's master.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerState {
    pub present: bool,
    pub running: bool,
    /// Docker's own word: `running`, `exited`, `created`, `restarting`.
    pub status: String,
    pub exit_code: i64,
    /// Non-zero on a running container is a crash loop, not health.
    pub restarts: i64,
    pub id: String,
}

impl ContainerState {
    fn absent() -> Self {
        Self {
            present: false,
            running: false,
            status: "not on this server".to_string(),
            exit_code: 0,
            restarts: 0,
            id: String::new(),
        }
    }

    fn healthy(&self, baseline: i64) -> bool {
        self.running && self.restarts <= baseline
    }

    /// The same state in systemd's vocabulary, so the Stack page renders a
    /// containerised PHP version through the one status renderer it already has
    /// for a host one. [`crate::appcontainer::ContainerState::unit_state`]'s
    /// mapping, including its one opinion: a running container that has been
    /// restarted is a failure, because a crash loop is what an operator most
    /// needs to see and `docker ps` calls it `Up 2 seconds` for as long as it
    /// goes on.
    fn unit_state(&self) -> UnitState {
        if !self.present {
            return UnitState::NotFound;
        }
        match self.status.as_str() {
            "running" if self.restarts > 0 => UnitState::Failed,
            "running" => UnitState::Active,
            "restarting" => UnitState::Activating,
            "removing" => UnitState::Deactivating,
            "created" | "paused" => UnitState::Inactive,
            // A master stopped on purpose — which this module does when a
            // version has no pools — exited zero.
            "exited" if self.exit_code == 0 => UnitState::Inactive,
            "exited" | "dead" => UnitState::Failed,
            _ => UnitState::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// The registry: which versions are containers
// ---------------------------------------------------------------------------

/// Where the panel remembers which PHP versions it runs as containers.
///
/// One JSON document in `settings`, for [`crate::engine::ENGINES_SETTING`]'s
/// reason: this step owns no migration. A `php_runtimes` table keyed on the
/// version is the right home and is noted for the migration that follows.
///
/// It matters more here than it did for engines, because it is what
/// `site::render_pool` has to consult to know whether a pool change should be
/// signalled to a systemd unit or to a container — and getting *that* wrong is a
/// pool written and never read.
pub const FPM_CONTAINERS_SETTING: &str = "php.containers";

/// One PHP version the panel runs as a container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FpmRecord {
    /// `8.3`.
    pub version: String,
    /// `php:8.3-fpm`.
    pub image: String,
    /// `unihelm-php-8.3`, which is the identity.
    pub container: String,
    /// The host directory bind-mounted in, recorded so an operator reading the
    /// registry can see where the pools this master runs actually are.
    pub pool_dir: String,
}

/// Every containerised PHP version, keyed by dotted version.
pub type FpmRegistry = std::collections::BTreeMap<String, FpmRecord>;

/// Read the registry.
///
/// A document that will not parse is an **error**, never an empty registry.
/// Defaulting here and writing a fresh map over it would tell every later site
/// change that PHP is on the host, and pools would be written and signalled to a
/// systemd unit that does not exist while the container serving those sites
/// never heard about them.
pub async fn registry(db: &Db) -> Result<FpmRegistry> {
    match db.get_setting::<FpmRegistry>(FPM_CONTAINERS_SETTING).await {
        Ok(Some(found)) => Ok(found),
        Ok(None) => Ok(FpmRegistry::new()),
        Err(e) => Err(UnihelmError::internal(format!(
            "the record of which PHP versions run in containers \
             (`{FPM_CONTAINERS_SETTING}`) could not be read: {e}. Until it can, the panel \
             cannot tell whether a pool change should reach a container or a service, so \
             it is refusing rather than guessing."
        ))),
    }
}

/// Whether this PHP version is served by a container on this machine.
///
/// **The question `site::render_pool` has to ask** before it picks a reloader.
pub async fn is_containerised(db: &Db, version: PhpVersion) -> Result<bool> {
    Ok(registry(db).await?.contains_key(version.as_str()))
}

/// Add or replace one record, against whatever the registry holds **now**.
///
/// Re-read rather than the caller's copy written back, for
/// [`crate::engine`]'s reason: an install reads it, then pulls an image, which
/// is minutes on a slow link, and writing that stale map back would erase a
/// record another install wrote in between.
async fn record_version(db: &Db, record: FpmRecord) -> Result<()> {
    let mut registry = registry(db).await?;
    registry.insert(record.version.clone(), record);
    save_registry(db, &registry).await
}

async fn forget_version(db: &Db, version: PhpVersion) -> Result<()> {
    let mut registry = registry(db).await?;
    registry.remove(version.as_str());
    save_registry(db, &registry).await
}

async fn save_registry(db: &Db, registry: &FpmRegistry) -> Result<()> {
    db.set_setting(FPM_CONTAINERS_SETTING, registry)
        .await
        .map_err(UnihelmError::from)
}

// ---------------------------------------------------------------------------
// One or the other, per version
// ---------------------------------------------------------------------------

/// Whether the host owns this PHP version.
///
/// Split out pure so the rule can be read and tested without a machine. Three
/// sources, because no one of them answers on every machine:
///
/// - **the unit**, which is the machine's own answer and therefore covers a PHP
///   somebody installed with apt before this panel existed — the case where
///   there are sites serving that the panel has never heard of;
/// - **the interpreter**, `paths::fpm_binary`, which answers the same question
///   without going near systemd. It is here because the unit lookup is a command
///   that can fail, and a failed lookup reads as "no unit": that fail-open is
///   the one direction this rule must not fail in, since the cost of a false
///   positive is an operator told to remove a PHP they may not have and the cost
///   of a false negative is two masters fighting over one socket directory;
/// - **the row**, which covers an install this panel made whose service is
///   momentarily not there, mid-upgrade or on a box that is still booting.
///
/// The row is the only one of the three that is waived, and it has to be:
/// `stack.install` writes `php8.3` → `Installed` for a **container** install as
/// well as a host one, so on its own the row cannot tell them apart. Left
/// unwaived it refuses the panel's own second install of a version it already
/// runs in a container — a repair, or a retry after a failed pull — with a
/// sentence telling the operator to remove host packages that are not there. The
/// two machine answers are never waived, so a version that is genuinely on the
/// host is still refused even while it carries a container record.
const fn host_owns_this_version(
    unit_installed: bool,
    binary_present: bool,
    row_installed: bool,
    already_a_container: bool,
) -> bool {
    if unit_installed || binary_present {
        return true;
    }
    row_installed && !already_a_container
}

/// Refuse to run a PHP version in a container when this server already runs it
/// on the host.
///
/// **The safety rule of this whole step**, and it is a refusal rather than a
/// migration on purpose. Moving a version means: stop the host master, which
/// takes every site on that version offline; start a container that must find
/// the same pools, resolve the same accounts and recreate the same sockets; and
/// have nginx reconnect. Every one of those steps can fail on a machine this
/// panel has never seen, and the failure is a production site answering 502 with
/// the panel reporting success — which has already happened once on this
/// project, for a smaller reason. So it is not attempted here. Step two took the
/// same decision about Go applications and was right to.
///
/// Called before anything is pulled, created or written.
pub async fn refuse_when_the_host_already_runs_this_version(
    ctx: &OpContext,
    version: PhpVersion,
) -> Result<()> {
    let distro = ctx.distro();
    let unit = ManagedUnit::PhpFpm { version };
    let unit_name = unit.unit_name(distro.info.family);

    let unit_installed = distro
        .svc
        .status(&unit_name)
        .await
        .map(|s| s.is_installed())
        .unwrap_or(false);

    // Asked of the filesystem rather than of a service manager, so a `systemctl`
    // that will not answer cannot turn a host install into "nothing here".
    let binary_present =
        unihelm_distro::exec::program_available(&paths::fpm_binary(distro.info.family, version));

    let row_installed = ctx
        .db()
        .component(&format!("{PHP_SLUG}{}", version.as_str()))
        .await
        .map_err(UnihelmError::from)?
        .is_some_and(|row| row.status == ComponentStatus::Installed);

    let already_a_container = is_containerised(ctx.db(), version).await?;

    if !host_owns_this_version(
        unit_installed,
        binary_present,
        row_installed,
        already_a_container,
    ) {
        return Ok(());
    }
    Err(host_owns_it_error(version, &unit_name.to_string()))
}

/// The refusal, in words that say what to do instead.
///
/// Separate from the lookup so the sentence is testable, and because the
/// sentence is the deliverable: an operator who reads "conflict" and nothing
/// else will go and remove the wrong thing.
fn host_owns_it_error(version: PhpVersion, unit: &str) -> UnihelmError {
    let php = version.as_str();
    UnihelmError::new(
        ErrorCode::Conflict,
        format!(
            "PHP {php} is already installed on this server as host packages (`{unit}`), and \
             it stays there. There is only one PHP {php}: a container of it would write its \
             pool files somewhere else while claiming the same sockets in {socket_dir} and \
             the same sites, so whichever master started last would own them and every site \
             on the other would answer 502. The panel will not move a version that is \
             serving. Install a PHP version this server does not already have — that one \
             becomes a container — and point sites at it; or, if PHP {php} itself must \
             become a container, remove the host PHP {php} from the Stack Manager first, \
             during a window where its sites may be down, and install it again.",
            socket_dir = paths::fpm_socket_dir().display(),
        ),
    )
    .with_field("version")
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// What `php.install` produced.
#[derive(Debug, Clone, Serialize)]
pub struct InstallOutput {
    pub version: String,
    pub container: String,
    pub image: String,
    pub pool_dir: String,
    /// How many pools this version has. Zero is the ordinary state of a version
    /// installed before any site names it.
    pub pools: usize,
    /// False when there were no pools to run — see [`ReloadPlan`]. Not a
    /// failure, and the caller must say so rather than reporting an install that
    /// did not work.
    pub running: bool,
}

/// Install a PHP version as a container: pull the image, create the master, and
/// start it if there is anything for it to run.
///
/// The order matters and is [`crate::engine::install_container`]'s: refuse
/// before pulling, pull before replacing, replace before starting. Taking a
/// serving master down and then spending a quarter of an hour on a download is
/// an outage bought for nothing, and bought again if the download fails.
pub async fn install(ctx: &OpContext, version: PhpVersion) -> Result<InstallOutput> {
    refuse_when_the_host_already_runs_this_version(ctx, version).await?;

    let plan = FpmContainer::plan(ctx.distro().info.family, version)?;
    let docker = docker_program()?;

    prepare_mount_sources(ctx, &plan)?;

    // Before the pull, because a refusal that costs nothing should not first
    // cost a quarter of an hour of download. Read again after the run for the
    // start decision, rather than carried down: a site can be created while an
    // image is arriving.
    let found_now = plan.pools();
    if let Some(stray) = sockets_the_container_cannot_create(&plan, &found_now).first() {
        return Err(a_pool_this_container_cannot_run(&plan, stray));
    }

    ctx.log(format!("docker pull {}", plan.image.as_str()));
    run_checked(&docker, &pull_argv(&plan.image), PULL_BUDGET).await?;

    // The name is the identity, so a container already holding it is this same
    // version — an interrupted install, or one being put back — rather than
    // somebody else's container to work around. `docker run` would refuse the
    // name. Nothing is lost by replacing it: the pools and the sockets are
    // outside.
    let existing = state(&docker, &plan.container).await?;
    if existing.present {
        ctx.log(format!(
            "{} already exists; replacing it — the pool files in {} are untouched.{}",
            plan.container,
            plan.pool_dir.display(),
            if existing.running {
                format!(
                    " It is running, so every PHP {} site on this server stops being served \
                     from the stop below until the new master has its sockets back.",
                    version.as_str()
                )
            } else {
                String::new()
            }
        ));
        take_down(ctx, &docker, &plan.container).await?;
    }

    ctx.log(format!(
        "docker run {} as {} — pools from {}, sockets in {}",
        plan.image.as_str(),
        plan.container,
        plan.pool_dir.display(),
        plan.socket_dir.display()
    ));
    run_checked(&docker, &run_argv(&plan), ACTION_BUDGET).await?;

    // Recorded **before** the wait. Without the record, `site::render_pool`
    // would go on signalling a systemd unit that is not there, so a version
    // whose readiness check merely timed out would end up with pools nothing
    // ever reads — and the container is already on the machine either way.
    record_version(
        ctx.db(),
        FpmRecord {
            version: version.as_str().to_string(),
            image: plan.image.as_str().to_string(),
            container: plan.container.as_str().to_string(),
            pool_dir: plan.pool_dir.display().to_string(),
        },
    )
    .await?;

    let pools = plan.pools();
    let running = match ReloadPlan::decide(true, true, pools.len()) {
        // A brand new version has no sites yet, and **FPM will not start with no
        // pool at all**. Starting it anyway is the bug that took a site offline:
        // the master exits with "No pool defined", the restart policy puts it
        // back, and an install that did everything right is reported as broken.
        // So it is stopped, and said out loud. The first site of this version
        // starts it (see [`reload`]).
        ReloadPlan::StopUntilThereIsAPool => {
            ctx.log(format!(
                "PHP {} has no site pools yet, so its FPM master is installed and left \
                 stopped — FPM will not start with no pool at all. It starts by itself \
                 when the first site on PHP {} is created.",
                version.as_str(),
                version.as_str()
            ));
            take_down(ctx, &docker, &plan.container).await?;
            false
        }
        _ => {
            wait_until_serving(ctx, &docker, &plan, &pools).await?;
            true
        }
    };

    Ok(InstallOutput {
        version: version.as_str().to_string(),
        container: plan.container.as_str().to_string(),
        image: plan.image.as_str().to_string(),
        pool_dir: plan.pool_dir.display().to_string(),
        pools: pools.len(),
        running,
    })
}

/// What a pool change means for the master, decided from three facts.
///
/// A type rather than a chain of `if`s because the interesting case is the one
/// that is easy to miss: **the pool that just went away was the last one.**
/// Signalling the master then makes it re-read its configuration, find nothing
/// to run, exit — and the restart policy puts it straight back into a crash
/// loop. It has to be stopped instead, which is the same judgement
/// [`crate::fpm::StockPool::KeptAsOnlyPool`] makes on the host: a master with no
/// pool is not a hardened server, it is a server whose PHP sites all 502.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadPlan {
    /// This version is not a container on this machine. Nothing to do, and not
    /// an error — the host path is somebody else's to signal.
    NotOurs,
    /// There are pools and the master is up: signal it.
    Signal,
    /// There are pools and the master is down: start it.
    Start,
    /// There are no pools. Stop it if it is up, and leave it stopped.
    StopUntilThereIsAPool,
}

impl ReloadPlan {
    const fn decide(present: bool, running: bool, pools: usize) -> Self {
        if !present {
            return Self::NotOurs;
        }
        if pools == 0 {
            return Self::StopUntilThereIsAPool;
        }
        if running { Self::Signal } else { Self::Start }
    }
}

/// Make a pool change reach the master. **The equivalent of
/// `UnitReloader::fpm`.**
///
/// Called after `site::render_pool` writes or removes a pool file. Idempotent,
/// and never fatal for the reason the host path is not: a pool on disk that the
/// master has not read yet is a site that is not serving, which is worth a loud
/// line and a retry rather than a failed site creation that leaves half a site
/// behind.
pub async fn reload(ctx: &OpContext, version: PhpVersion) -> Result<ReloadPlan> {
    let plan = FpmContainer::plan(ctx.distro().info.family, version)?;
    let docker = docker_program()?;
    let found = state(&docker, &plan.container).await?;
    // Only when a master is up, because that is the only case where the answer
    // decides whether it keeps running. See [`pool_dir_must_be_readable`].
    if found.running {
        pool_dir_must_be_readable(&plan.pool_dir)?;
    }
    let pools = plan.pools();
    let decision = ReloadPlan::decide(found.present, found.running, pools.len());

    match decision {
        ReloadPlan::NotOurs => {
            // "Not ours" is only true when the panel does not record this
            // version as a container. When it does and the container is gone —
            // removed by hand, or by a prune — returning quietly is the worst
            // outcome in this file: the pool is written, nothing ever reads it,
            // the site answers 502, and every page in the panel says the site
            // was created. The caller rolls the pool file back on an error,
            // which is the honest end of the operation.
            if is_containerised(ctx.db(), version).await? {
                return Err(the_container_has_gone_missing(&plan, pools.len()));
            }
            tracing::debug!(
                version = version.as_str(),
                "no FPM container; nothing to reload"
            );
        }
        ReloadPlan::Signal => {
            ctx.log(format!(
                "docker kill --signal {RELOAD_SIGNAL} {} — {} pool(s), no restart and no \
                 dropped request",
                plan.container,
                pools.len()
            ));
            run_checked(&docker, &reload_argv(&plan.container), ACTION_BUDGET).await?;
            wait_until_serving(ctx, &docker, &plan, &pools).await?;
        }
        ReloadPlan::Start => {
            ctx.log(format!(
                "starting {} — PHP {} now has {} pool(s) to run",
                plan.container,
                version.as_str(),
                pools.len()
            ));
            run_checked(&docker, &start_argv(&plan.container), ACTION_BUDGET).await?;
            wait_until_serving(ctx, &docker, &plan, &pools).await?;
        }
        ReloadPlan::StopUntilThereIsAPool => {
            if found.running {
                ctx.log(format!(
                    "PHP {} has no pools left, so {} is being stopped rather than reloaded \
                     — a master told to re-read an empty pool directory exits with \"No \
                     pool defined\" and is then restarted into a loop. It starts again \
                     with the next PHP {} site.",
                    version.as_str(),
                    plan.container,
                    version.as_str()
                ));
                run_checked(&docker, &stop_argv(&plan.container), ACTION_BUDGET).await?;
            }
        }
    }
    Ok(decision)
}

/// The registry says this version is a container and the container is not on
/// the machine.
///
/// Split out so the sentence is testable, and because the sentence has to name
/// the two ways back: the pools are still there, so either the container is put
/// back or the version stops being a container. Silence here is a site that is
/// configured, reported as created, and answering 502.
fn the_container_has_gone_missing(plan: &FpmContainer, pools: usize) -> UnihelmError {
    let php = plan.version.as_str();
    UnihelmError::new(
        ErrorCode::NotFound,
        format!(
            "PHP {php} runs in a container on this server, but `{container}` is not on the \
             machine — it has been removed outside the panel. The {pools} pool file(s) in \
             {pool_dir} are still there and are still what a master would read, but nothing \
             is reading them, so every PHP {php} site answers 502. Install PHP {php} again \
             from the Stack Manager to put the container back; the pool files are kept and \
             the sites come back with it.",
            container = plan.container,
            pool_dir = plan.pool_dir.display(),
        ),
    )
}

/// A pool directory the panel cannot read is not an empty pool directory.
///
/// [`PoolSet::read`] answers "no pools" to both, and "no pools" is what stops a
/// master — so an unreadable directory would take every site on the version
/// offline on the strength of one failed `read_dir`. A *missing* directory is
/// still genuinely no pools: that is the ordinary state of a version nobody has
/// made a site on, and stopping a master over it is the decision hazard 3 wants.
fn pool_dir_must_be_readable(dir: &Path) -> Result<()> {
    match std::fs::read_dir(dir) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(UnihelmError::internal(format!(
            "{} could not be read ({e}), so the panel cannot tell whether this PHP version \
             still has pools. It is refusing rather than reading an unreadable directory as \
             an empty one and stopping a master that is serving sites.",
            dir.display()
        ))),
    }
}

/// Stop a version's master. Every site on that version stops being served, which
/// is the caller's to say.
pub async fn stop(ctx: &OpContext, version: PhpVersion) -> Result<()> {
    let plan = FpmContainer::plan(ctx.distro().info.family, version)?;
    let docker = docker_program()?;
    let found = state(&docker, &plan.container).await?;
    if !found.running {
        ctx.log(format!(
            "{} is not running; nothing to stop",
            plan.container
        ));
        return Ok(());
    }
    let pools = plan.pools();
    ctx.log(format!(
        "docker stop {} ({STOP_SIGNAL}, up to {GRACE_SECONDS}s to drain) — {} site(s) on \
         PHP {} stop being served",
        plan.container,
        pools.len(),
        version.as_str()
    ));
    run_checked(&docker, &stop_argv(&plan.container), ACTION_BUDGET)
        .await
        .map(|_| ())
}

/// What `php.remove` produced.
#[derive(Debug, Clone, Serialize)]
pub struct RemoveOutput {
    pub version: String,
    pub container: String,
    /// Still on disk, still the panel's. Named so the reply can say so.
    pub pool_dir_kept: String,
    /// How many pools were left behind — which is how many sites stop working
    /// until they are pointed at another version.
    pub pools_kept: usize,
}

/// Take a version's master off the machine. **The pools and the sockets stay.**
///
/// The pool files are configuration the panel wrote and still owns: a site still
/// names this version, and deleting its pool here would mean that reinstalling
/// the version brought back a master with nothing to run. The sockets are FPM's
/// own — it unlinks them as it stops and creates them again when it starts — so
/// they are not this module's to remove either. Nothing in this file deletes a
/// path.
///
/// Idempotent. A container that is not there is not a failed removal.
pub async fn remove(ctx: &OpContext, version: PhpVersion) -> Result<RemoveOutput> {
    let plan = FpmContainer::plan(ctx.distro().info.family, version)?;
    let docker = docker_program()?;
    let pools = plan.pools();
    let found = state(&docker, &plan.container).await?;

    if found.present {
        if !pools.is_empty() {
            ctx.log(format!(
                "removing {} while {} site pool(s) still name PHP {} — those sites stop \
                 being served until they are moved to another PHP version. Their pool \
                 files in {} are kept.",
                plan.container,
                pools.len(),
                version.as_str(),
                plan.pool_dir.display()
            ));
        }
        take_down(ctx, &docker, &plan.container).await?;
    } else {
        ctx.log(format!(
            "{} is not on this server; nothing to remove",
            plan.container
        ));
    }

    // The record goes only once the container is gone, so a removal that failed
    // half way leaves the panel still knowing this version is a container — and
    // therefore still signalling the right thing.
    forget_version(ctx.db(), version).await?;

    Ok(RemoveOutput {
        version: version.as_str().to_string(),
        container: plan.container.as_str().to_string(),
        pool_dir_kept: plan.pool_dir.display().to_string(),
        pools_kept: pools.len(),
    })
}

/// What one containerised PHP version is doing.
#[derive(Debug, Clone, Serialize)]
pub struct FpmStatus {
    pub version: String,
    pub container: String,
    pub image: String,
    /// systemd's vocabulary, so the Stack page renders this through the status
    /// renderer it already has.
    pub state: UnitState,
    pub present: bool,
    pub running: bool,
    /// Docker's own word, for a caller that wants to be specific.
    pub status: String,
    pub restarts: i64,
    /// Pools configured for this version.
    pub pools: usize,
    /// Of those, how many have a socket the web server can see. Fewer than
    /// `pools` on a running master means sites that 502 — which is exactly the
    /// state the panel used to report as healthy.
    pub sockets_ready: usize,
}

/// `php.status` for one version.
pub async fn status(ctx: &OpContext, version: PhpVersion) -> Result<FpmStatus> {
    let plan = FpmContainer::plan(ctx.distro().info.family, version)?;
    let docker = docker_program()?;
    let found = state(&docker, &plan.container).await?;
    let pools = plan.pools();
    let web_group = crate::provision::nginx_user(ctx.distro());

    let sockets_ready = pools
        .sockets()
        .into_iter()
        .filter(|path| matches!(check_socket(path, web_group), SocketVerdict::Reachable))
        .count();

    Ok(FpmStatus {
        version: version.as_str().to_string(),
        container: plan.container.as_str().to_string(),
        image: plan.image.as_str().to_string(),
        state: found.unit_state(),
        present: found.present,
        running: found.running,
        status: found.status.clone(),
        restarts: found.restarts,
        pools: pools.len(),
        sockets_ready,
    })
}

/// Stop if running, then remove. Used by [`install`]'s replace and by
/// [`remove`].
async fn take_down(ctx: &OpContext, docker: &str, container: &ContainerRef) -> Result<()> {
    if state(docker, container).await?.running {
        ctx.log(format!("docker stop {container}"));
        run_checked(docker, &stop_argv(container), ACTION_BUDGET).await?;
    }
    ctx.log(format!("docker rm {container}"));
    run_checked(docker, &remove_argv(container), ACTION_BUDGET).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Readiness: the socket, not the container
// ---------------------------------------------------------------------------

/// What the host can tell about a pool's socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketVerdict {
    /// It is there, it is a socket, and the web server's group can open it.
    Reachable,
    /// Nothing at that path.
    Missing,
    /// Something is there, and it is not a socket.
    NotASocket,
    /// It exists but nginx cannot open it, with the reason in the sentence.
    Unreachable(String),
}

/// Read back what the container actually produced.
///
/// The mode and the group are stated in the pool file, and stating them is not
/// the same as achieving them: inside the container the master has to resolve
/// the *name* `nginx` to a gid and then chown a socket to it, which works only
/// because `/etc/group` is bind-mounted and only because `CAP_CHOWN` survived
/// the cap-drop. If either were missing the socket would come out root-owned or
/// 0600 and every PHP site would 502 with the container reporting "running" —
/// the failure this whole file is written around. So the kernel is asked instead
/// of the template being trusted.
///
/// A socket whose group does not match is reported rather than repaired.
/// Chowning it from here would paper over a container that is misconfigured and
/// would be undone by the master the next time it recreated the socket.
fn check_socket(path: &Path, web_group: &str) -> SocketVerdict {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let Ok(md) = std::fs::metadata(path) else {
        return SocketVerdict::Missing;
    };
    if !md.file_type().is_socket() {
        return SocketVerdict::NotASocket;
    }

    let mode = md.mode() & 0o777;
    let gid = md.gid();

    // Read and write, because FastCGI is a conversation.
    const GROUP_RW: u32 = 0o060;
    if mode & GROUP_RW != GROUP_RW {
        return SocketVerdict::Unreachable(format!(
            "{} is mode {mode:04o}, so the `{web_group}` group cannot open it — the pool \
             asks for 0660 and the master could not apply it",
            path.display()
        ));
    }

    match group_gid(web_group) {
        // The host has no such group. Not this module's failure to report on:
        // the pool file names it, the web server runs as it, and provisioning
        // creates it — saying more here would be guessing.
        None => SocketVerdict::Reachable,
        Some(want) if want == gid => SocketVerdict::Reachable,
        Some(want) => SocketVerdict::Unreachable(format!(
            "{} belongs to group {gid}, but the web server runs as `{web_group}` (group \
             {want}), so it cannot open the socket. Inside the container the group name \
             did not resolve to the host's gid — check that /etc/group is still \
             bind-mounted read-only into the container",
            path.display()
        )),
    }
}

/// Wait until every pool of this version is actually answering.
///
/// Three gates, in this order, because they fail for different reasons and the
/// operator needs to know which:
///
/// 1. **The container stayed up.** `docker run`, `docker start` and
///    `docker kill -s USR2` all report success the instant Docker accepts them;
///    a master that finds a pool it cannot honour is dead a moment later and
///    `--restart unless-stopped` has it "running" again by the time anything
///    asks, so the restart counter is watched against a baseline taken here.
/// 2. **Every pool's socket exists on the host side of the bind mount.** This is
///    the path nginx will take, and it is the only check that proves the mount
///    is still the same directory the web server looks in. It is also the one
///    that catches the reboot failure [`paths::fpm_socket_dir`] warns about: if
///    `/run/unihelm/fpm` is deleted and recreated under a running container, the
///    master keeps writing into an unlinked directory and nothing appears here.
/// 3. **The socket is reachable by the web server's group.** See
///    [`check_socket`].
async fn wait_until_serving(
    ctx: &OpContext,
    docker: &str,
    plan: &FpmContainer,
    pools: &PoolSet,
) -> Result<()> {
    let web_group = crate::provision::nginx_user(ctx.distro());
    let baseline = state(docker, &plan.container).await?.restarts;
    let deadline = tokio::time::Instant::now() + SERVING_BUDGET;
    let mut delay = Duration::from_millis(200);
    // Declared without a value on purpose: the only way out of the loop below
    // that reads it is one that has just written it, so an initial string would
    // be a sentence nothing can ever print — and a plausible-looking one is
    // worse than none, because it would eventually be printed by a refactor and
    // believed.
    let mut last: String;

    loop {
        let found = state(docker, &plan.container).await?;
        if !found.healthy(baseline) {
            return Err(did_not_stay_up(docker, plan, &found).await);
        }
        match first_problem(pools, web_group) {
            None => {
                ctx.log(format!(
                    "{} is serving {} pool(s); their sockets are in {}",
                    plan.label(),
                    pools.len(),
                    plan.socket_dir.display()
                ));
                return Ok(());
            }
            Some(why) => last = why,
        }
        if tokio::time::Instant::now() + delay >= deadline {
            break;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(2));
    }

    // One last look, so a master that died in the final second is reported as
    // dead rather than as quiet.
    let found = state(docker, &plan.container).await?;
    if !found.healthy(baseline) {
        return Err(did_not_stay_up(docker, plan, &found).await);
    }

    Err(UnihelmError::new(
        ErrorCode::ServiceActionFailed,
        format!(
            "{} is running, but its sockets never became usable: {last}. Every site on PHP \
             {} answers 502 until they are. If {} was deleted and recreated after the \
             container started — which is what happens when the tmpfiles entry recreates \
             it on a reboot — the master is writing into a directory nothing else can see, \
             and `docker restart {}` puts it back. This is the end of its log:\n{}",
            plan.label(),
            plan.version.as_str(),
            plan.socket_dir.display(),
            plan.container,
            log_tail(docker, &plan.container).await
        ),
    ))
}

/// The first pool whose socket is not usable, in words worth showing.
fn first_problem(pools: &PoolSet, web_group: &str) -> Option<String> {
    pools
        .sockets()
        .into_iter()
        .find_map(|path| match check_socket(path, web_group) {
            SocketVerdict::Reachable => None,
            SocketVerdict::Missing => Some(format!(
                "{} has not appeared — the pool that asks for it either did not start or \
                 is writing somewhere the host cannot see",
                path.display()
            )),
            SocketVerdict::NotASocket => Some(format!(
                "{} exists but is not a socket; something else is using that name",
                path.display()
            )),
            SocketVerdict::Unreachable(why) => Some(why),
        })
}

/// The error for a master that did not survive, carrying the only thing that
/// helps: what it said on its way out. `--force-stderr` in [`COMMAND`] is what
/// puts anything in there at all.
async fn did_not_stay_up(
    docker: &str,
    plan: &FpmContainer,
    found: &ContainerState,
) -> UnihelmError {
    let what = if found.restarts > 0 {
        format!("started and then died {} time(s) in a row", found.restarts)
    } else {
        format!("exited immediately with status {}", found.exit_code)
    };
    UnihelmError::new(
        ErrorCode::ServiceActionFailed,
        format!(
            "{} {what}. Every site on PHP {} is down while it is. The container is `{}` and \
             this is the end of its log:\n{}",
            plan.label(),
            plan.version.as_str(),
            plan.container,
            log_tail(docker, &plan.container).await
        ),
    )
}

/// The end of the master's log.
///
/// Both streams concatenated rather than interleaved by timestamp the way
/// [`crate::appcontainer`] has to: `--force-stderr` puts everything FPM says on
/// one stream, so there are no two orders to reconcile.
async fn log_tail(docker: &str, container: &ContainerRef) -> String {
    match run_raw(docker, &logs_argv(container, LOG_LINES), READ_BUDGET).await {
        Ok(out) => {
            let text = format!("{}\n{}", out.stdout.trim_end(), out.stderr.trim_end());
            let text = text.trim();
            if text.is_empty() {
                format!("(nothing; `docker logs {container}` is empty)")
            } else {
                text.to_string()
            }
        }
        Err(e) => format!("(its log could not be read: {e})"),
    }
}

// ---------------------------------------------------------------------------
// Reloading is routed from `fpm`, not from here
// ---------------------------------------------------------------------------
//
// There is deliberately no `Reloader` implementation in this file. `fpm::reloader`
// hands the config engine either `services::UnitReloader::fpm` or a wrapper
// around [`reload`], choosing on the version's runtime — and a second reloader
// here would be a second place that had to agree with it about when a pool
// change reaches a container. Two things that must agree are one thing.

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// Make sure every bind-mount source is a real directory before Docker sees it.
///
/// Two failures, both of them somebody's server:
///
/// - **Missing.** Docker creates a missing bind source itself, as root, and
///   silently. For the pool directory that is nearly harmless and is done here
///   anyway so it is the panel that made it; for the socket directory it would
///   hide the very condition [`paths::fpm_socket_dir`] warns about.
/// - **A symlink.** Docker resolves the path on the host before mounting it, so
///   a link is a mount of somewhere else. The pool directory is root's, but the
///   check is uniform because a rule with an exception is a rule nobody applies.
fn prepare_mount_sources(ctx: &OpContext, plan: &FpmContainer) -> Result<()> {
    for dir in [&plan.pool_dir, &plan.socket_dir, &plan.log_root] {
        if !dir.exists() {
            ctx.log(format!("creating {}", dir.display()));
            std::fs::create_dir_all(dir).map_err(|e| {
                UnihelmError::internal(format!("could not create {}: {e}", dir.display()))
            })?;
        }
    }
    for dir in [
        &plan.pool_dir,
        &plan.socket_dir,
        &plan.log_root,
        &plan.home_root,
    ] {
        check_bind_source(dir)?;
    }
    Ok(())
}

fn check_bind_source(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(md) if md.file_type().is_symlink() => Err(UnihelmError::new(
            ErrorCode::InvalidPath,
            format!(
                "{} is a symlink; refusing to mount through it into a container",
                dir.display()
            ),
        )),
        Ok(md) if md.is_dir() => Ok(()),
        Ok(_) => Err(UnihelmError::new(
            ErrorCode::InvalidPath,
            format!("{} exists but is not a directory", dir.display()),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(UnihelmError::new(
            ErrorCode::NotFound,
            format!(
                "{} does not exist, so there is nothing to bind-mount into the PHP \
                 container.",
                dir.display()
            ),
        )),
        Err(e) => Err(UnihelmError::internal(format!(
            "could not inspect {}: {e}",
            dir.display()
        ))),
    }
}

/// The `docker` binary, or the reason there is nothing to run PHP in.
fn docker_program() -> Result<String> {
    unihelm_distro::exec::resolve_program(DOCKER)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|_| {
            UnihelmError::new(
                ErrorCode::NotFound,
                "Docker is not installed on this server, and this PHP version runs in a \
                 container. Install Docker from the Stack Manager first.",
            )
        })
}

/// The gid of a group name, through NSS rather than by reading `/etc/group`, so
/// an operator's LDAP or sssd configuration works here as it does everywhere
/// else on the box.
fn group_gid(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `getgrnam` returns a pointer into a static buffer owned by libc;
    // we read it immediately and copy out the one integer we need.
    unsafe {
        let gr = libc::getgrnam(c_name.as_ptr());
        if gr.is_null() {
            return None;
        }
        Some((*gr).gr_gid)
    }
}

/// One inspect. A container that is not there is [`ContainerState::absent`] and
/// not an error — every caller has something sensible to do about it — while
/// anything else, a stopped daemon most of all, is an error: reporting a stopped
/// `docker.service` as "your PHP is gone" sends an operator looking for
/// something they still have.
async fn state(docker: &str, container: &ContainerRef) -> Result<ContainerState> {
    let out = run_raw(docker, &inspect_argv(container), READ_BUDGET).await?;
    if !out.success() {
        let text = out.failure_text();
        let lower = text.to_ascii_lowercase();
        if lower.contains("no such object") || lower.contains("no such container") {
            return Ok(ContainerState::absent());
        }
        return Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            text.trim().to_string(),
        ));
    }
    parse_state(out.trimmed_stdout())
}

/// How many tab-separated fields [`INSPECT_FORMAT`] produces.
const INSPECT_FIELDS: usize = 5;

fn parse_state(text: &str) -> Result<ContainerState> {
    let fields: Vec<&str> = text.trim().split('\t').collect();
    if fields.len() < INSPECT_FIELDS {
        return Err(UnihelmError::internal(
            "`docker inspect` answered in a shape this build does not recognise",
        ));
    }
    Ok(ContainerState {
        present: true,
        running: fields[0] == "true",
        status: fields[1].to_string(),
        // A field Docker did not fill is zero rather than a failed read: the
        // exit code is context in a message, and the running flag beside it is
        // what anything decides on.
        exit_code: fields[2].parse().unwrap_or(0),
        restarts: fields[3].parse().unwrap_or(0),
        id: fields[4].to_string(),
    })
}

async fn run_raw(
    docker: &str,
    args: &[String],
    budget: Duration,
) -> Result<unihelm_distro::exec::CmdOutput> {
    unihelm_distro::Cmd::new(docker)
        .args(args)
        .timeout(budget)
        .run()
        .await
        .map_err(UnihelmError::from)
}

async fn run_checked(docker: &str, args: &[String], budget: Duration) -> Result<String> {
    let out = run_raw(docker, args, budget).await?;
    if !out.success() {
        return Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            out.failure_text(),
        ));
    }
    Ok(out.trimmed_stdout().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(version: PhpVersion) -> FpmContainer {
        FpmContainer::plan(Family::Debian, version).expect("a catalogued PHP version")
    }

    /// Whether `argv` carries `flag` followed by `value`.
    fn has_pair(argv: &[String], flag: &str, value: &str) -> bool {
        argv.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    fn values_of(argv: &[String], flag: &str) -> Vec<String> {
        argv.windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].clone())
            .collect()
    }

    // -----------------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------------

    /// The catalogue offers 8.3; the image is `php:8.3-fpm` and nothing else.
    /// A tag that drifted from the page would mean an operator choosing one
    /// version and getting another, on a server full of sites.
    #[test]
    fn the_image_and_the_container_are_the_versions_the_catalogue_offers() {
        assert_eq!(image_name(PhpVersion::V83), "php:8.3-fpm");
        assert_eq!(container_name(PhpVersion::V83), "unihelm-php-8.3");

        for &version in PhpVersion::ALL {
            let plan = plan(version);
            assert_eq!(
                plan.image().as_str(),
                format!("php:{}-fpm", version.as_str()),
                "{version} does not resolve to the official image"
            );
            assert!(
                catalogue::version("php", version.as_str()).is_some(),
                "{version} is planned but is not on the Stack page"
            );
        }
    }

    /// One container per version, so two versions can never collide on a name
    /// and one version can never become two containers.
    #[test]
    fn every_version_has_its_own_container_and_only_one() {
        let names: std::collections::BTreeSet<String> =
            PhpVersion::ALL.iter().map(|v| container_name(*v)).collect();
        assert_eq!(names.len(), PhpVersion::ALL.len());
    }

    // -----------------------------------------------------------------------
    // The mounts
    // -----------------------------------------------------------------------

    /// The panel's pool directory is what the master reads, at the path the
    /// image looks in, and it is not copied.
    ///
    /// A copy would go stale the moment a site was created: the pool would be
    /// written, the reload would be signalled, and the master would re-read a
    /// snapshot that had never heard of it.
    #[test]
    fn the_pool_directory_is_bind_mounted_where_the_image_reads_it() {
        let plan = plan(PhpVersion::V83);
        let mounts = values_of(&run_argv(&plan), "--volume");
        let host = paths::fpm_pool_dir(Family::Debian, PhpVersion::V83);
        assert!(
            mounts.contains(&format!("{}:{IMAGE_POOL_DIR}:ro", host.display())),
            "the pool directory is not mounted at {IMAGE_POOL_DIR}: {mounts:?}"
        );
    }

    /// The socket directory is the contract with the web server: same path on
    /// both sides, writable, so `fastcgi_pass unix:...` reaches the pool without
    /// the vhost knowing anything changed.
    #[test]
    fn the_socket_directory_is_shared_at_the_path_the_vhost_names() {
        let plan = plan(PhpVersion::V83);
        let mounts = values_of(&run_argv(&plan), "--volume");
        let dir = paths::fpm_socket_dir();
        assert!(
            mounts.contains(&format!("{0}:{0}", dir.display())),
            "the socket directory is not shared read-write: {mounts:?}"
        );
        // The socket the vhost was rendered with has to be inside it, or the
        // mount is of the wrong directory.
        assert!(
            paths::fpm_socket("example_com", PhpVersion::V83).starts_with(&dir),
            "the socket path and the mounted directory have drifted apart"
        );
    }

    /// uid 1007 inside must be `uh_abc123` outside, and `listen.group = nginx`
    /// must resolve. Both come from the host's own account files, read-only.
    #[test]
    fn the_hosts_accounts_come_in_read_only() {
        let mounts = values_of(&run_argv(&plan(PhpVersion::V83)), "--volume");
        assert!(
            mounts.contains(&"/etc/passwd:/etc/passwd:ro".to_string()),
            "{mounts:?}"
        );
        assert!(
            mounts.contains(&"/etc/group:/etc/group:ro".to_string()),
            "{mounts:?}"
        );
    }

    /// The code is in the tenant homes, and the per-site logs FPM opens while
    /// starting are not.
    #[test]
    fn the_sites_and_their_logs_are_both_mounted() {
        let mounts = values_of(&run_argv(&plan(PhpVersion::V83)), "--volume");
        for dir in [paths::home_root(), paths::site_log_root()] {
            assert!(
                mounts.contains(&format!("{0}:{0}", dir.display())),
                "{} is not mounted: {mounts:?}",
                dir.display()
            );
        }
    }

    // -----------------------------------------------------------------------
    // The run
    // -----------------------------------------------------------------------

    /// It speaks over a unix socket in a shared directory. A published port
    /// would put a PHP interpreter on the network — and Docker's DNAT rule sits
    /// ahead of `INPUT`, so it would answer the internet whatever the firewall
    /// had been told.
    #[test]
    fn nothing_is_published() {
        let argv = run_argv(&plan(PhpVersion::V83));
        for flag in ["--publish", "-p", "-P", "--publish-all", "--expose"] {
            assert!(
                !argv.iter().any(|a| a == flag),
                "{flag} is on the argv: {argv:?}"
            );
        }
        // Host networking would be the same mistake spelled differently: every
        // port the master ever bound would be the host's.
        assert!(!has_pair(&argv, "--network", "host"), "{argv:?}");
    }

    /// The master stays root inside the container so a pool can become its own
    /// user. With `--user` it could not, and FPM would run every site on the
    /// version as one account — the isolation boundary gone, quietly, with a
    /// warning in a log nobody reads.
    #[test]
    fn the_master_stays_root_so_a_pool_can_become_its_own_user() {
        let argv = run_argv(&plan(PhpVersion::V83));
        assert!(
            !argv.iter().any(|a| a == "--user" || a == "-u"),
            "a --user flag would stop every pool switching to its tenant: {argv:?}"
        );

        // ...and the privilege is narrowed with capabilities instead.
        assert!(has_pair(&argv, "--cap-drop", "ALL"), "{argv:?}");
        for capability in ["SETUID", "SETGID"] {
            assert!(
                has_pair(&argv, "--cap-add", capability),
                "without {capability} no pool can run as its tenant: {argv:?}"
            );
        }
    }

    /// The socket is created inside and read from outside. `listen.owner` and
    /// `listen.group` are a chown and `listen.mode` a chmod of a file the master
    /// no longer owns by then — without both capabilities the socket comes out
    /// unreadable to nginx and every PHP site 502s.
    #[test]
    fn the_master_can_give_the_socket_its_owner_and_its_mode() {
        let argv = run_argv(&plan(PhpVersion::V83));
        assert!(has_pair(&argv, "--cap-add", "CHOWN"), "{argv:?}");
        assert!(has_pair(&argv, "--cap-add", "FOWNER"), "{argv:?}");
        // And it must be able to signal workers that are no longer its uid.
        assert!(has_pair(&argv, "--cap-add", "KILL"), "{argv:?}");
    }

    /// Without `--nodaemonize` the master forks, PID 1 exits, and the container
    /// stops a second after `docker run` reported success — because the mount
    /// over the pool directory hides the image's own `daemonize = no`.
    #[test]
    fn the_master_is_told_not_to_daemonise_because_the_mount_hides_the_images_setting() {
        let argv = run_argv(&plan(PhpVersion::V83));
        assert!(argv.contains(&"--nodaemonize".to_string()), "{argv:?}");
        // And its startup errors have to reach `docker logs`, or a master that
        // refuses to start is reported as "PHP did not come up" and nothing else.
        assert!(argv.contains(&"--force-stderr".to_string()), "{argv:?}");
    }

    /// `docker stop` sends SIGTERM, which FPM treats as "terminate now". One
    /// master holds every site on the version, so the default would drop every
    /// in-flight request on all of them at once.
    #[test]
    fn stopping_drains_rather_than_killing() {
        assert!(has_pair(
            &run_argv(&plan(PhpVersion::V83)),
            "--stop-signal",
            "SIGQUIT"
        ));
        let stop = stop_argv(plan(PhpVersion::V83).container());
        assert!(
            !stop.iter().any(|a| a == "-f" || a == "--force"),
            "{stop:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Nothing here removes anything
    // -----------------------------------------------------------------------

    /// The pools are configuration the panel owns and the sockets are FPM's own.
    /// Neither is the container's to delete, and neither is this module's.
    #[test]
    fn nothing_here_deletes_a_pool_or_a_socket() {
        let remove = remove_argv(plan(PhpVersion::V83).container());
        for flag in ["-v", "--volumes", "-f", "--force"] {
            assert!(
                !remove.iter().any(|a| a == flag),
                "{flag} on a removal: {remove:?}"
            );
        }

        // And no path is deleted anywhere in the file. A grep, because the way
        // this rule breaks is somebody adding a tidy-up years from now.
        let source = include_str!("fpmcontainer.rs");
        for call in ["remove_file", "remove_dir", "remove_dir_all"] {
            assert!(
                !source.contains(&format!("fs::{call}")),
                "{call} appears in fpmcontainer.rs; the pools and the sockets are not \
                 this module's to delete"
            );
        }
    }

    // -----------------------------------------------------------------------
    // FPM will not start with no pool
    // -----------------------------------------------------------------------

    /// The bug that took a production site offline, in one decision table.
    #[test]
    fn a_version_with_no_pools_is_stopped_rather_than_started() {
        // Fresh install, nothing names it yet: do not start it. Starting would
        // exit with "No pool defined" and the restart policy would loop.
        assert_eq!(
            ReloadPlan::decide(true, false, 0),
            ReloadPlan::StopUntilThereIsAPool
        );
        // The last site on the version was deleted: stop the master, do not
        // signal it. A signalled master re-reads, finds nothing, and dies.
        assert_eq!(
            ReloadPlan::decide(true, true, 0),
            ReloadPlan::StopUntilThereIsAPool
        );
        // The first site arrives: start it.
        assert_eq!(ReloadPlan::decide(true, false, 1), ReloadPlan::Start);
        // A second site arrives: signal it, never restart it.
        assert_eq!(ReloadPlan::decide(true, true, 2), ReloadPlan::Signal);
        // This version is on the host: not ours to touch.
        assert_eq!(ReloadPlan::decide(false, false, 3), ReloadPlan::NotOurs);
    }

    /// A pool added or changed reaches the running master by signal. `docker
    /// restart` would drop every in-flight request on every other site the
    /// master holds, which on the host path is exactly why the reload is
    /// `SvcAction::Reload` and not `Restart`.
    #[test]
    fn a_pool_change_is_signalled_and_never_restarted() {
        let argv = reload_argv(plan(PhpVersion::V83).container());
        assert_eq!(argv[0], "kill");
        assert!(has_pair(&argv, "--signal", "SIGUSR2"), "{argv:?}");
        assert!(!argv.iter().any(|a| a == "restart"), "{argv:?}");
    }

    // -----------------------------------------------------------------------
    // Reading the pool directory
    // -----------------------------------------------------------------------

    fn pool_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_pool_is_a_section_that_is_not_global() {
        assert!(pool_in("[example_com]\nuser = uh_abc\n"));
        assert!(!pool_in("[global]\nerror_log = /dev/stderr\n"));
        assert!(!pool_in("; only comments\n"));
        // A global block followed by a pool is still a pool.
        assert!(pool_in("[global]\ndaemonize = no\n\n[example_com]\n"));
    }

    /// The socket is read out of the file, and `listen.owner` sits directly
    /// above `listen` in the template — matching on a prefix would take the
    /// tenant's username for a socket path.
    #[test]
    fn the_socket_comes_from_the_listen_line_and_not_from_the_ones_beside_it() {
        let body = "[example_com]\n\
                    listen = /run/unihelm/fpm/example_com-php83.sock\n\
                    listen.owner = uh_abc123\n\
                    listen.group = nginx\n\
                    listen.mode = 0660\n";
        assert_eq!(
            listen_socket(body),
            Some(PathBuf::from("/run/unihelm/fpm/example_com-php83.sock"))
        );
        // The order in the file must not be what decides the answer: the
        // template happens to put `listen` above its neighbours today, and a
        // reader who assumed that is a reader who will move a line.
        let reordered = "[example_com]\n\
                         listen.owner = uh_abc123\n\
                         listen.group = nginx\n\
                         listen = /run/unihelm/fpm/example_com-php83.sock\n";
        assert_eq!(
            listen_socket(reordered),
            Some(PathBuf::from("/run/unihelm/fpm/example_com-php83.sock"))
        );
        // And a pool with only the neighbours and no `listen` of its own has no
        // socket at all, rather than one made of a username.
        assert_eq!(listen_socket("[www]\nlisten.owner = uh_abc123\n"), None);

        // A pool listening on TCP has no socket to look for, and that is not a
        // failure to report.
        assert_eq!(listen_socket("[www]\nlisten = 9000\n"), None);
        // A commented-out listen is not a listen.
        assert_eq!(listen_socket("[www]\n; listen = /tmp/x.sock\n"), None);
    }

    #[test]
    fn only_conf_files_that_declare_a_pool_are_counted() {
        let dir = pool_dir();
        std::fs::write(
            dir.path().join("unihelm-example.com.conf"),
            "[example_com]\nlisten = /run/unihelm/fpm/example_com-php83.sock\n",
        )
        .unwrap();
        // Retired by `crate::fpm`: FPM does not include it, so neither do we.
        std::fs::write(
            dir.path().join("www.conf.unihelm-disabled"),
            "[www]\nlisten = /run/php/www.sock\n",
        )
        .unwrap();
        // Global settings are not a pool, and a master with only this would not
        // start.
        std::fs::write(dir.path().join("00-global.conf"), "[global]\n").unwrap();

        let pools = PoolSet::read(dir.path());
        assert_eq!(pools.len(), 1, "{pools:?}");
        assert_eq!(
            pools.sockets(),
            vec![Path::new("/run/unihelm/fpm/example_com-php83.sock")]
        );
    }

    /// A pool directory that does not exist yet holds no pools — which is the
    /// same answer as an empty one and leads to the same decision, rather than
    /// to an error on a version nobody has made a site on.
    #[test]
    fn a_missing_pool_directory_is_no_pools_and_not_a_failure() {
        let pools = PoolSet::read(Path::new("/nonexistent/unihelm/pool.d"));
        assert!(pools.is_empty());
        assert_eq!(
            ReloadPlan::decide(true, true, pools.len()),
            ReloadPlan::StopUntilThereIsAPool
        );
    }

    // -----------------------------------------------------------------------
    // The socket the web server has to open
    // -----------------------------------------------------------------------

    #[test]
    fn a_socket_that_never_appeared_is_named_rather_than_timed_out_silently() {
        let dir = pool_dir();
        let missing = dir.path().join("example_com-php83.sock");
        assert_eq!(check_socket(&missing, "nginx"), SocketVerdict::Missing);

        let pools = PoolSet {
            pools: vec![Pool {
                file: dir.path().join("unihelm-example.com.conf"),
                socket: Some(missing.clone()),
            }],
        };
        let why = first_problem(&pools, "nginx").expect("a problem");
        assert!(why.contains(&missing.display().to_string()), "{why}");
    }

    /// A regular file where a socket should be is not a socket, and calling it
    /// one would report a version as serving while nginx got a 502 from every
    /// site on it.
    #[test]
    fn something_that_is_not_a_socket_is_not_a_socket() {
        let dir = pool_dir();
        let path = dir.path().join("example_com-php83.sock");
        std::fs::write(&path, b"").unwrap();
        assert_eq!(check_socket(&path, "nginx"), SocketVerdict::NotASocket);
    }

    /// The mode is read back from the kernel rather than assumed from the
    /// template. 0600 is what a master that could not chown or chmod leaves
    /// behind, and nginx cannot open it.
    #[test]
    fn a_socket_the_web_server_cannot_open_says_so() {
        use std::os::unix::net::UnixListener;

        let dir = pool_dir();
        let path = dir.path().join("example_com-php83.sock");
        let _listener = UnixListener::bind(&path).expect("a unix socket");

        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        match check_socket(&path, "nginx") {
            SocketVerdict::Unreachable(why) => {
                assert!(why.contains("0600"), "{why}");
                assert!(why.contains("nginx"), "{why}");
            }
            other => panic!("a 0600 socket was called {other:?}"),
        }

        // 0660 is what the pool asks for. The group check then compares against
        // the host's own `nginx` gid; a machine with no such group cannot be
        // wrong about it, so that arm reports reachable.
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o660))
            .unwrap();
        let verdict = check_socket(&path, "a-group-no-server-has");
        assert_eq!(verdict, SocketVerdict::Reachable, "{verdict:?}");
    }

    // -----------------------------------------------------------------------
    // One or the other, per version
    // -----------------------------------------------------------------------

    /// The rule this whole step is written around: a version already serving on
    /// the host is never moved.
    #[test]
    fn a_version_the_host_already_runs_is_never_moved_into_a_container() {
        assert!(
            host_owns_this_version(true, false, false, false),
            "the unit alone is enough"
        );
        assert!(
            host_owns_this_version(false, true, false, false),
            "an installed php-fpm binary alone is enough"
        );
        assert!(
            host_owns_this_version(false, false, true, false),
            "the row alone is enough"
        );
        assert!(!host_owns_this_version(false, false, false, false));
    }

    /// The unit lookup is a command, and a command can fail — `svc::status`
    /// answers `Err` when `systemctl` will not run at all, and the caller reads
    /// that as "no unit". The interpreter on disk is the answer that does not
    /// depend on a service manager, and it is what keeps that fail-open from
    /// putting a container beside a serving host master.
    #[test]
    fn a_host_install_is_still_found_when_the_service_manager_will_not_answer() {
        assert!(
            host_owns_this_version(false, true, false, true),
            "an unreadable unit plus a php-fpm binary on the host must still refuse, \
             container record or not"
        );
    }

    /// `stack.install` writes `php8.3` → `Installed` for a container install as
    /// well as a host one, so the row alone cannot tell them apart. Left
    /// unwaived it refuses the panel's own repair of a version it already runs
    /// in a container, telling the operator to remove host packages that are not
    /// on the machine.
    #[test]
    fn the_panels_own_container_record_is_not_read_as_a_host_install() {
        assert!(
            !host_owns_this_version(false, false, true, true),
            "a row written by this module's own install must not refuse the next one"
        );
        // And waiving it does not waive the machine's own answers.
        assert!(host_owns_this_version(true, false, true, true));
    }

    /// A pool whose socket is in a directory the container cannot see does not
    /// fail alone: FPM binds every socket while starting and fails the whole
    /// master if one will not bind, so it takes every other site on the version
    /// with it. The usual source is the distribution's own `www.conf`, left
    /// behind by removing host PHP without purging it — which is the path the
    /// refusal in `host_owns_it_error` sends an operator down.
    #[test]
    fn a_pool_listening_outside_the_mounts_is_refused_before_anything_is_pulled() {
        let plan = plan(PhpVersion::V83);

        let ours = Pool {
            file: plan.pool_dir().join("unihelm-example.com.conf"),
            socket: Some(paths::fpm_socket("example_com", PhpVersion::V83)),
        };
        let stock = Pool {
            file: plan.pool_dir().join("www.conf"),
            socket: Some(PathBuf::from("/run/php/php8.3-fpm.sock")),
        };
        let tcp = Pool {
            file: plan.pool_dir().join("imported.conf"),
            socket: None,
        };

        let pools = PoolSet {
            pools: vec![ours.clone(), tcp.clone()],
        };
        assert!(
            sockets_the_container_cannot_create(&plan, &pools).is_empty(),
            "a pool in the shared socket directory, and one on TCP, are both runnable"
        );

        let pools = PoolSet {
            pools: vec![ours, stock.clone(), tcp],
        };
        let stray = sockets_the_container_cannot_create(&plan, &pools);
        assert_eq!(stray, vec![&stock], "{stray:?}");

        // And the refusal names the file, not the symptom: `docker logs` would
        // eventually say "unable to bind listening socket", by which point the
        // master is crash-looping and every site on the version is down.
        let e = a_pool_this_container_cannot_run(&plan, &stock);
        assert_eq!(e.code, ErrorCode::Conflict);
        assert!(e.detail.contains("www.conf"), "{}", e.detail);
        assert!(
            e.detail.contains("/run/php/php8.3-fpm.sock"),
            "{}",
            e.detail
        );
        assert!(
            e.detail.contains("unihelm-disabled"),
            "the refusal has to name the way out: {}",
            e.detail
        );
    }

    /// A `read_dir` that fails is not an empty directory, and the difference is
    /// whether a master serving every site on the version keeps running.
    /// `PoolSet::read` cannot tell them apart — both are "no pools" — and "no
    /// pools" is what stops the master.
    #[test]
    fn an_unreadable_pool_directory_does_not_stop_a_running_master() {
        let dir = pool_dir();
        assert!(pool_dir_must_be_readable(dir.path()).is_ok());

        // Missing is genuinely no pools: the ordinary state of a version nobody
        // has made a site on, and stopping over it is what hazard 3 wants.
        assert!(pool_dir_must_be_readable(Path::new("/nonexistent/unihelm/pool.d")).is_ok());

        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o000),
        )
        .unwrap();
        let readable = pool_dir_must_be_readable(dir.path());
        // Running the suite as root makes every directory readable, and a test
        // that cannot create the condition must not claim to have checked it.
        // SAFETY: `geteuid` reads a process property and cannot fail.
        let as_root = unsafe { libc::geteuid() } == 0;
        if !as_root {
            let e = readable.expect_err("an unreadable pool directory must not read as empty");
            assert!(
                e.detail.contains("serving sites"),
                "the refusal has to say what it is protecting: {}",
                e.detail
            );
        }
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
    }

    /// The registry says container, the container is gone: the pool would be
    /// written and nothing would ever read it. That is the failure shape this
    /// whole step exists to prevent, and returning quietly is how it happens.
    #[test]
    fn a_container_that_has_gone_missing_is_named_and_not_passed_over() {
        let plan = plan(PhpVersion::V83);
        let e = the_container_has_gone_missing(&plan, 4);
        assert_eq!(e.code, ErrorCode::NotFound);
        assert!(e.detail.contains("unihelm-php-8.3"), "{}", e.detail);
        assert!(e.detail.contains('4'), "{}", e.detail);
        assert!(
            e.detail.contains("502"),
            "the sentence has to say what the sites are doing: {}",
            e.detail
        );
        assert!(
            e.detail.contains("kept"),
            "and that the pools survive, or nobody dares reinstall: {}",
            e.detail
        );
    }

    /// The registry is what tells every later pool change whether PHP is a
    /// container or a service. A document that will not parse must be an error:
    /// read as an empty map it says "host" for every version, and pools would be
    /// written and signalled to a systemd unit that is not there while the
    /// container actually serving those sites never heard about them.
    #[tokio::test]
    async fn an_unreadable_registry_is_an_error_and_never_an_empty_one() {
        let db = Db::open_memory().await.unwrap();
        assert!(registry(&db).await.unwrap().is_empty());

        record_version(
            &db,
            FpmRecord {
                version: "8.3".to_string(),
                image: "php:8.3-fpm".to_string(),
                container: "unihelm-php-8.3".to_string(),
                pool_dir: "/etc/php/8.3/fpm/pool.d".to_string(),
            },
        )
        .await
        .unwrap();
        assert!(is_containerised(&db, PhpVersion::V83).await.unwrap());
        assert!(!is_containerised(&db, PhpVersion::V84).await.unwrap());

        db.set_setting(FPM_CONTAINERS_SETTING, &"not a registry at all")
            .await
            .unwrap();
        let e = registry(&db).await.unwrap_err();
        assert!(e.detail.contains(FPM_CONTAINERS_SETTING), "{}", e.detail);

        // And the failure is not swallowed by the question site changes ask.
        assert!(is_containerised(&db, PhpVersion::V83).await.is_err());

        forget_version(&db, PhpVersion::V83).await.unwrap_err();
    }

    /// And the refusal says what to do instead. "Conflict" on its own sends
    /// somebody to remove the wrong thing.
    #[test]
    fn the_refusal_says_what_to_do_instead() {
        let e = host_owns_it_error(PhpVersion::V83, "php8.3-fpm.service");
        assert_eq!(e.code, ErrorCode::Conflict);
        assert!(e.detail.contains("php8.3-fpm.service"), "{}", e.detail);
        assert!(
            e.detail.contains("Stack Manager"),
            "the refusal has to name the way out: {}",
            e.detail
        );
        assert!(
            e.detail
                .contains(&paths::fpm_socket_dir().display().to_string()),
            "the refusal has to name what the two would fight over: {}",
            e.detail
        );
    }

    // -----------------------------------------------------------------------
    // Reading Docker back
    // -----------------------------------------------------------------------

    /// A master that is up but has been restarted is a crash loop, and
    /// `docker ps` calls that `Up 2 seconds` for as long as it goes on.
    #[test]
    fn a_restarting_master_is_a_failure_and_not_health() {
        let state = parse_state("true\trunning\t0\t4\tdeadbeef").unwrap();
        assert!(state.running);
        assert_eq!(state.unit_state(), UnitState::Failed);
        assert!(!state.healthy(0));
        // Against a baseline it already carried, it is fine.
        assert!(state.healthy(4));
    }

    /// A version this module stopped for having no pools exited zero, and must
    /// not read as broken.
    #[test]
    fn a_master_stopped_on_purpose_is_inactive_and_not_failed() {
        let stopped = parse_state("false\texited\t0\t0\tdeadbeef").unwrap();
        assert_eq!(stopped.unit_state(), UnitState::Inactive);

        let broken = parse_state("false\texited\t78\t0\tdeadbeef").unwrap();
        assert_eq!(broken.unit_state(), UnitState::Failed);

        assert_eq!(ContainerState::absent().unit_state(), UnitState::NotFound);
    }
}
