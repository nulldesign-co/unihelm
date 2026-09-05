//! Running one tenant application as one container.
//!
//! Step two of `docs/design/containerised-runtimes.md`. Step one was
//! [`crate::engine`] — databases and caches — and this file is deliberately
//! shaped like it, because it is the same problem one rung further in: resolve
//! an image from a catalogue version, name a container deterministically,
//! publish a port on loopback, read the state back rather than trusting an exit
//! status, and never let a removal touch the data.
//!
//! ## Why one container per application, and not one per version
//!
//! PHP multiplexes: one FPM master holds a pool per site, so a hundred sites is
//! one container. Node, Python and Ruby have no such thing — an application is
//! its own process with its own port and its own lifetime — so a Node container
//! cannot host four applications without the panel inventing a multiplexer that
//! does not exist. The container is therefore per application, built from the
//! version's image, which keeps the property the design asked for (every app
//! naming Node 22 runs the same image) without pretending at a pool model.
//!
//! ## What deliberately does not change
//!
//! **nginx.** A proxy site already points at `127.0.0.1:<port>`; the container
//! publishes that same port on that same address, so the vhost is byte-identical
//! whether the app is a systemd unit or a container. Nothing in
//! `templates/nginx` is touched by this file, and nothing should be.
//!
//! **The port.** The database allocates it (`node_apps.port`, and the vhost was
//! rendered with the number), so this module publishes the port it is handed and
//! never picks one. That is the single largest difference from [`crate::engine`],
//! which has to allocate because two MariaDBs both want 3306.
//!
//! ## The four things that had to be right
//!
//! 1. **The uid.** The container runs as the tenant's numeric uid and gid, read
//!    from the host's passwd through `getpwnam` — see [`Account::lookup`]. Skip
//!    it and every file the application writes into the tenant's own home is
//!    owned by root: the file manager cannot open it, SFTP cannot replace it,
//!    and the tenant cannot deploy again. The host's `/etc/passwd` and
//!    `/etc/group` come in read-only for the same reason the design document
//!    gives for FPM: the container does not create accounts, it names the ones
//!    the host already has, so a program that calls `getpwuid(geteuid())` — git,
//!    `Dir.home`, `os.path.expanduser` — gets an answer instead of an error.
//! 2. **The port is already allocated.** See above; [`AppContainer::plan`] takes
//!    it off the row and [`run_argv`] publishes exactly that number.
//! 3. **`docker run` exiting zero means it started, not that it stayed up.** An
//!    application with a missing module exits in under a second and
//!    `--restart unless-stopped` then hides it behind a container that is
//!    "running" again by the time anybody looks. [`wait_until_up`] therefore
//!    watches the restart counter as well as the running flag, and reports the
//!    container's own last words when it did not survive.
//! 4. **The app directory is somebody's source code.** It is a bind mount, not a
//!    volume: [`remove_argv`] carries neither `-v` nor `-f`, nothing in this file
//!    deletes a path, and the mount source is refused unless it is a real
//!    directory that already exists (see [`check_bind_source`]).
//!
//! ## The one thing this changes for a tenant, which the caller must say out loud
//!
//! An application in a container has its own network namespace, so `127.0.0.1`
//! inside it is the container and not the host. A connection string naming
//! `127.0.0.1:3306` — which is where [`crate::engine`] publishes a containerised
//! database — will not connect. The host is reachable as
//! `host.docker.internal`, which [`run_argv`] maps explicitly, and that is the
//! sentence the UI has to show when an app moves into a container. The tidier
//! answer is a shared Docker network for engines and apps, which cannot be built
//! here because it changes how engines are run.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use unihelm_config::paths;
use unihelm_core::{AppName, ErrorCode, LinuxUser, Result, TenantPath, UnihelmError};
use unihelm_db::node_apps::{AppRuntime, NodeApp};
use unihelm_distro::svc::UnitState;

use crate::catalogue;
use crate::docker::{ContainerRef, ImageRef};
use crate::registry::OpContext;

/// Docker's own client, not the daemon socket — the same choice, for the same
/// reason, as [`crate::docker`] and [`crate::engine`].
const DOCKER: &str = "docker";

/// Where an application's port is published, and nowhere else.
///
/// nginx reaches it here and nothing outside the machine has any business
/// doing so. Docker's published-port DNAT rule is inserted ahead of `INPUT`, so
/// `-p 20001:20001` would answer the internet whatever ufw had been told — an
/// application reachable on a raw port, bypassing the vhost, its TLS and its
/// access rules.
const LOOPBACK: &str = "127.0.0.1";

/// The name the host answers to from inside the container.
///
/// `--add-host <name>:host-gateway` is Docker's own supported spelling for
/// "route this name at the bridge gateway", which is the host. It is mapped
/// because the alternative is a tenant with no way at all to reach a
/// containerised database, and it is a *name* rather than an address because the
/// bridge subnet is Docker's to choose and changes between machines.
const HOST_ALIAS: &str = "host.docker.internal";

/// Labels the panel stamps on every application container it creates.
///
/// [`crate::engine`] needed none of this: an engine's facts live in the panel's
/// own registry file. An application's live in its database row — and four of
/// the six operations below (`restart`, `remove`, `logs`, `status`) are handed
/// only a tenant and an app name, because that is all their caller has when a
/// person clicks Restart on a list. The labels are what lets those four work
/// from the container alone instead of the caller fetching a row and rebuilding
/// a plan to ask Docker one question.
///
/// `unihelm.app.port` is the one that earns its keep: a restart has to know
/// where to look for the application to come back, and the alternative is
/// parsing Docker's port-binding structure back out of an inspect.
///
/// They are also how an operator tells the panel's containers from everything
/// else on a shared box: `docker ps --filter label=unihelm.app.user=uh_abc123`.
const LABEL_USER: &str = "unihelm.app.user";
const LABEL_NAME: &str = "unihelm.app.name";
const LABEL_PORT: &str = "unihelm.app.port";

/// How long an image is given to arrive. [`crate::engine::install_container`]'s
/// number and its reasoning: a killed pull does not retry, it throws away the
/// layers it had and starts the same slow link again.
const PULL_BUDGET: Duration = Duration::from_secs(15 * 60);

/// A lifecycle command's budget, matching [`crate::docker`]'s: a stop takes the
/// full grace period, a restart takes that plus a start, and the IPC layer's own
/// timeout is 30s.
const ACTION_BUDGET: Duration = Duration::from_secs(25);

/// A read — an inspect or a log tail. Docker is either quick or wedged.
const READ_BUDGET: Duration = Duration::from_secs(10);

/// How long a container is given to exit on SIGTERM before Docker SIGKILLs it.
/// Docker's own default, passed explicitly so [`ACTION_BUDGET`] is derived from
/// a number this file controls.
const GRACE_SECONDS: u32 = 10;

/// How long an application is given to bind its port before the panel stops
/// waiting and says so.
///
/// Not a failure when it expires — see [`wait_until_up`]. Thirty seconds is past
/// a cold `node` start on a small VPS and short of the point where somebody
/// watching a progress log assumes the panel has hung.
const LISTEN_BUDGET: Duration = Duration::from_secs(30);

/// The smallest memory ceiling worth applying, in MB.
///
/// [`crate::nodeapp`]'s clamp, for its reason plus one of Docker's own: no
/// interpreter starts in a few megabytes, and `docker run --memory` below 6m is
/// refused outright, so an un-clamped ceiling of 4 would not cap an application,
/// it would refuse to create one.
const MIN_MEMORY_MB: u32 = 64;

/// Environment variables this module sets and a tenant therefore may not.
///
/// `PORT` is the proxy wiring and `HOME` is what makes a container running as a
/// bare uid usable at all; the per-ecosystem production flag is added from
/// [`AppRuntime::env_var`] at validation time, because it differs per runtime.
const RESERVED_ENV_KEYS: &[&str] = &["PORT", "HOME"];

// ---------------------------------------------------------------------------
// The image
// ---------------------------------------------------------------------------

/// Which image runs a runtime, and what tag an unpinned application gets.
#[derive(Debug, Clone, Copy)]
struct RuntimeImage {
    /// Docker Hub's name for the official image.
    repository: &'static str,
    /// The catalogue entry whose recommended version is the tag when the
    /// application pins none. `None` where this panel has no catalogue entry for
    /// the runtime at all — Bun and Deno ship as single vendor binaries and are
    /// not installable from the Stack page.
    catalogue_slug: Option<&'static str>,
    /// The tag to use when the catalogue has no number to give.
    ///
    /// Python and Ruby are catalogued as `distro`, because on the host they are
    /// whatever the release maintains — a container has no distribution to
    /// inherit from, so the pin lives here. It is a pin and never a `latest`,
    /// for [`crate::engine`]'s reason: a tag that moves under a running
    /// application turns a restart into a major-version upgrade nobody asked
    /// for, and here that upgrade lands on somebody's production application
    /// rather than on a cache.
    fallback_tag: &'static str,
    /// The argv the image is given, with the entry file appended.
    ///
    /// Everything before the entry is a fixed string in this file, so the only
    /// caller-derived word on the command is a path already proven to sit inside
    /// the bind mount.
    command: &'static [&'static str],
}

/// The image for a runtime, or `None` where the panel does not run it in a
/// container.
///
/// **Go is `None`, and that is the answer rather than an omission.** A Go
/// application is a compiled binary: there is no interpreter to supply, so there
/// is no `go:1.23` runtime image to build it from — the `golang` image is a
/// toolchain, a gigabyte of compiler that would run the binary no differently
/// from the host. Containerising it would buy a slower start, a larger disk and
/// a second lifecycle to maintain, in exchange for nothing at all, since the one
/// thing a container gives an interpreted app — a pinned interpreter — is a fact
/// about the build for a Go program and not about this server.
/// `AppRuntime::is_compiled` already says the same thing about the systemd path,
/// and this keeps the two agreeing: **Go applications stay systemd units.**
const fn image_for(runtime: AppRuntime) -> Option<RuntimeImage> {
    Some(match runtime {
        AppRuntime::Node => RuntimeImage {
            repository: "node",
            catalogue_slug: Some("node"),
            fallback_tag: "22",
            command: &["node"],
        },
        AppRuntime::Python => RuntimeImage {
            repository: "python",
            catalogue_slug: Some("python"),
            fallback_tag: "3.12",
            command: &["python"],
        },
        AppRuntime::Ruby => RuntimeImage {
            repository: "ruby",
            catalogue_slug: Some("ruby"),
            fallback_tag: "3.2",
            command: &["ruby"],
        },
        AppRuntime::Bun => RuntimeImage {
            repository: "oven/bun",
            catalogue_slug: None,
            fallback_tag: "1",
            command: &["bun", "run"],
        },
        AppRuntime::Deno => RuntimeImage {
            repository: "denoland/deno",
            catalogue_slug: None,
            fallback_tag: "2",
            // Deno denies network, environment and filesystem access unless it
            // is granted, so a bare `deno run` produces an application that
            // cannot bind its port — which reads to the operator as an app that
            // will not start. The isolation this panel relies on is the
            // container and the uid, not Deno's own flags, so the permission is
            // granted here and the boundary stays where every other runtime's
            // is.
            command: &["deno", "run", "--allow-all"],
        },
        AppRuntime::Go => return None,
    })
}

/// Whether this panel can run an application of this runtime as a container.
pub fn is_containerisable(runtime: AppRuntime) -> bool {
    image_for(runtime).is_some()
}

/// The image table entry, or the sentence saying why this runtime has none.
///
/// The sentence matters more than the refusal: "Go is not supported" would send
/// somebody looking for a missing feature, when what is true is that a Go
/// application has nothing to put in a container and already runs the better
/// way.
fn runtime_image(runtime: AppRuntime) -> Result<RuntimeImage> {
    image_for(runtime).ok_or_else(|| {
        UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "a {} application is a compiled binary, so there is no runtime image to run \
                 it in — it stays a service on this host. Applications that run in \
                 containers are: {}.",
                runtime.label(),
                AppRuntime::ALL
                    .iter()
                    .filter(|r| is_containerisable(**r))
                    .map(|r| r.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .with_field("runtime")
    })
}

/// The image an application of this runtime and version runs on: `node:22`.
///
/// **Pure**, and that is a requirement rather than a nicety.
/// `nodeapp::plan_launch` calls this before the row is inserted, so that an
/// impossible application is refused without touching the machine — and, more
/// importantly, without looking for an interpreter. The host arm of that same
/// match resolves a binary on this server; if this arm did too, a box with no
/// Node installed could not run a Node application in a container, which is the
/// entire reason the container mode exists.
pub fn plan_image(runtime: AppRuntime, version: Option<&str>) -> Result<String> {
    let image = runtime_image(runtime)?;
    let tag = tag_for(runtime, version, &image)?;
    Ok(format!("{}:{tag}", image.repository))
}

/// The tag for a pinned version, or the catalogue's recommendation when there is
/// no pin.
///
/// A version with a digit in it is one somebody chose off the page and is the
/// tag verbatim — the same test [`crate::engine`] applies, for the same reason:
/// `distro` and `stable` are not versions anybody picked, and asking Docker for
/// `python:distro` is a pull that fails at install time with a message about a
/// manifest.
fn tag_for(runtime: AppRuntime, pinned: Option<&str>, image: &RuntimeImage) -> Result<String> {
    if let Some(want) = pinned {
        check_tag(runtime, want)?;
        return Ok(want.to_string());
    }
    let recommended = image
        .catalogue_slug
        .and_then(catalogue::default_version)
        .map(|v| v.version)
        .filter(|v| has_digit(v));
    Ok(recommended.unwrap_or(image.fallback_tag).to_string())
}

fn has_digit(s: &str) -> bool {
    s.bytes().any(|b| b.is_ascii_digit())
}

/// Refuse a pinned version that is not a tag.
///
/// [`ImageRef::parse`] would catch most of this a moment later, but it would
/// catch it as "image may contain letters, digits and . - _ / : @ only", which
/// tells an operator nothing about the version field they typed into. A `:` in
/// particular has to die here: `22:latest` would otherwise render `node:22:latest`
/// and, worse, a version of `22 --privileged` would be refused for the wrong
/// reason, leaving the impression that the refusal is about characters rather
/// than about arguments.
fn check_tag(runtime: AppRuntime, version: &str) -> Result<()> {
    let ok = !version.is_empty()
        && version.len() <= 128
        && version
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if ok {
        return Ok(());
    }
    Err(UnihelmError::new(
        ErrorCode::InvalidInput,
        format!(
            "`{version}` is not a {} version this panel can pull: a version is digits, \
             letters, dots, dashes and underscores, like 22 or 3.12.4.",
            runtime.label()
        ),
    )
    .with_field("runtime_version"))
}

// ---------------------------------------------------------------------------
// The account
// ---------------------------------------------------------------------------

/// The tenant's numeric identity on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
}

impl Account {
    /// Resolve a tenant account through the host's passwd.
    ///
    /// `getpwnam` rather than reading `/etc/passwd`, so NSS sources — LDAP, sssd,
    /// anything an operator has configured — work here exactly as they do for
    /// every other program on the box.
    pub fn lookup(user: &LinuxUser) -> Result<Self> {
        let (uid, gid) = passwd_entry(user.as_str()).ok_or_else(|| {
            UnihelmError::new(
                ErrorCode::NotFound,
                format!(
                    "the Linux account `{}` does not exist on this server, so there is no \
                     uid to run the application's container as.",
                    user.as_str()
                ),
            )
        })?;
        Self::checked(user, uid, gid)
    }

    /// The numbers passwd gave, once they have been shown not to be root's.
    ///
    /// Split out from [`Account::lookup`] because it is the half that carries a
    /// rule, and the half a test can reach: [`LinuxUser`] refuses `root` by name,
    /// so no test can drive the guard through `lookup`, and the account this
    /// guard actually catches is not named `root` anyway — it is a `uh_*` tenant
    /// whose passwd entry says 0 because a restore, a manual `usermod` or a
    /// half-finished provision left it that way.
    fn checked(user: &LinuxUser, uid: u32, gid: u32) -> Result<Self> {
        // A tenant that resolves to 0 means the account database is wrong in a
        // way no container should be started on: the app would write root-owned
        // files into a tenant home, which is the exact failure the `--user` flag
        // exists to prevent, and it would do it while running tenant-authored
        // code.
        if uid == 0 || gid == 0 {
            return Err(UnihelmError::internal(format!(
                "`{}` maps to uid/gid 0; refusing to run an application container as root",
                user.as_str()
            )));
        }
        Ok(Self { uid, gid })
    }
}

/// The same helper [`crate::wordpress`] and [`crate::fsops`] each keep a copy of.
///
/// Duplicated rather than hoisted for their stated reason: hoisting it means
/// editing a shared module mid-wave, and three copies of six lines that call one
/// libc function is a smaller problem than two agents rewriting one file.
fn passwd_entry(username: &str) -> Option<(u32, u32)> {
    let c_name = std::ffi::CString::new(username).ok()?;
    // SAFETY: `getpwnam` returns a pointer into a static buffer owned by libc;
    // we read it immediately and copy out the two integers we need.
    unsafe {
        let pw = libc::getpwnam(c_name.as_ptr());
        if pw.is_null() {
            return None;
        }
        Some(((*pw).pw_uid, (*pw).pw_gid))
    }
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// The container an application runs in, as a validated reference.
///
/// The name itself is [`crate::nodeapp::app_container_name`]'s and is
/// deliberately not spelled again here: naming an application is that module's
/// job in both modes, and two functions that have to agree on a string are one
/// function. What this adds is the parse — every name that reaches an argv in
/// this file goes through [`ContainerRef`], so there is no path by which a
/// string becomes a Docker argument without being checked.
///
/// Infallible in practice for any validated pair (a [`LinuxUser`] is
/// `[a-z0-9_-]{1,32}` and an [`AppName`] is `[a-z0-9][a-z0-9_-]{0,31}`, both
/// inside Docker's alphabet), and still a `Result`, because "in practice" is not
/// a property worth betting an argv on.
fn container_ref(user: &LinuxUser, name: &AppName) -> Result<ContainerRef> {
    ContainerRef::parse(&crate::nodeapp::app_container_name(user, name))
}

/// What a caller may vary about an application container.
#[derive(Debug, Default, Clone)]
pub struct AppContainerOptions {
    /// The app's own memory ceiling, as `app.create` accepts it.
    pub memory_mb: Option<u32>,
    /// The tenant's own environment, as key/value pairs. Validated here, not
    /// trusted: [`check_env`].
    pub env: Vec<(String, String)>,
}

/// One application resolved into everything needed to run it as a container.
///
/// Built from a row, a validated account name and a validated app name, so every
/// string that reaches an argv below has already been through a newtype.
#[derive(Debug, Clone)]
pub struct AppContainer {
    container: ContainerRef,
    image: ImageRef,
    runtime: AppRuntime,
    /// The tenant's application directory on the host, bind-mounted at the
    /// identical path inside the container.
    app_dir: PathBuf,
    /// The entry file, absolute, and valid on both sides of the mount.
    entry: PathBuf,
    /// The port the row allocated. Published, never chosen.
    port: u16,
    account: Account,
    /// `KEY=VALUE`, in the order they go onto the argv.
    env: Vec<String>,
    memory_mb: Option<u32>,
    /// The tenant's systemd slice, when this host has one for them.
    cgroup_parent: Option<String>,
    /// `key=value`, in the order they go onto the argv. See [`LABEL_USER`].
    labels: Vec<String>,
    /// What to call this application in a sentence.
    label: String,
}

impl AppContainer {
    /// Resolve an application row into a container plan.
    pub fn plan(
        app: &NodeApp,
        user: &LinuxUser,
        name: &AppName,
        options: AppContainerOptions,
    ) -> Result<Self> {
        Self::plan_as(app, user, name, options, Account::lookup(user)?)
    }

    /// The same, with the account already resolved.
    ///
    /// Pure: no passwd, no filesystem, no Docker. Everything the argv is built
    /// from is decided here, which is what makes the tests below able to hold
    /// the run arguments without a container runtime or a tenant on the machine.
    fn plan_as(
        app: &NodeApp,
        user: &LinuxUser,
        name: &AppName,
        options: AppContainerOptions,
        account: Account,
    ) -> Result<Self> {
        // Through `plan_image`, not around it: `nodeapp` reports that string in
        // the create reply before this plan exists, and an application whose
        // reply named `node:22` while its container ran something else would be
        // a lie nobody could catch by reading either file alone.
        let reference = ImageRef::parse(&plan_image(app.runtime, app.runtime_version.as_deref())?)?;
        let container = container_ref(user, name)?;

        // The row's port, not a choice: the proxy vhost in front of this
        // application was rendered with this number before the app had ever
        // started, and every client and note the operator has says the same.
        let port = u16::try_from(app.port).map_err(|_| {
            UnihelmError::internal(format!(
                "the port allocated to `{}` ({}) is not a port number",
                app.name, app.port
            ))
        })?;

        let app_dir = paths::app_dir(user.as_str(), name.as_str());
        let entry = entry_inside(&app_dir, user, name, &app.entry)?;

        let mut env = Vec::new();
        check_env(app.runtime, &options.env)?;
        for (key, value) in &options.env {
            env.push(format!("{key}={value}"));
        }
        // The panel's own **last**, because `docker run` takes the last
        // `--env` for a repeated key. (The systemd unit puts them first, since
        // systemd's rule is the same and the template appends the tenant's
        // afterwards; the two files differ in order for the identical reason.)
        // The reserved-key check above is the other half, so neither alone has
        // to be right.
        if let Some(var) = app.runtime.env_var() {
            env.push(format!("{var}={}", app.node_env.as_str()));
        }
        env.push(format!("PORT={port}"));
        // A container running as a bare uid has no home: `HOME` is unset, so it
        // defaults to `/`, and the first thing a package manager or a logging
        // library does is fail to write `/.npm` or `/.cache`. Pointing it at the
        // application's own directory keeps every such write inside the one
        // place the tenant owns.
        env.push(format!("HOME={}", app_dir.display()));

        // Only when the host actually has the slice unit. Docker resolves this
        // against systemd, and naming a slice that does not exist would fail the
        // run of an application whose only problem is that its tenant predates
        // the slice machinery.
        let slice = crate::slices::slice_file_name(user);
        let cgroup_parent = paths::systemd_unit(&slice).exists().then_some(slice);

        Ok(Self {
            container,
            image: reference,
            runtime: app.runtime,
            app_dir,
            entry,
            port,
            account,
            env,
            memory_mb: options.memory_mb.map(|mb| mb.max(MIN_MEMORY_MB)),
            cgroup_parent,
            labels: vec![
                format!("{LABEL_USER}={}", user.as_str()),
                format!("{LABEL_NAME}={}", name.as_str()),
                format!("{LABEL_PORT}={port}"),
            ],
            label: format!("{} ({})", name.as_str(), user.as_str()),
        })
    }

    pub fn container(&self) -> &ContainerRef {
        &self.container
    }

    pub fn image(&self) -> &ImageRef {
        &self.image
    }

    /// The directory bind-mounted into the container. Somebody's source code.
    pub fn app_dir(&self) -> &Path {
        &self.app_dir
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn account(&self) -> Account {
        self.account
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

/// The entry file as an absolute path, proven to be inside the bind mount.
///
/// `node_apps.entry` is relative to the **tenant home**, not to the application
/// directory, because a systemd unit could name any file the tenant could read.
/// A container can only see what is mounted, and what is mounted is the
/// application directory — mounting the whole home instead would hand every
/// application a view of every site, every other app and every dotfile the
/// tenant has, which is a boundary this step should be tightening rather than
/// leaving where it was.
///
/// So an entry outside the application directory is refused, in a sentence that
/// says what to do about it. It is refused rather than worked around because the
/// alternative — mounting whatever directory the entry happens to be in — makes
/// the mount a function of a path the tenant controls.
fn entry_inside(app_dir: &Path, user: &LinuxUser, name: &AppName, entry: &str) -> Result<PathBuf> {
    // Parsed again on the way out of the database. The row was written through
    // this same newtype, so this cannot normally fail — and "normally" is not a
    // property worth betting an argv on.
    let relative = TenantPath::parse(entry)?;
    let absolute = paths::tenant_home(user.as_str()).join(relative.as_str());

    if !absolute.starts_with(app_dir) || absolute == app_dir {
        return Err(UnihelmError::new(
            ErrorCode::InvalidPath,
            format!(
                "`{entry}` is outside the application directory. A containerised \
                 application can only see `{}`, so its entry file has to live there — move \
                 the code into the `{}` application directory, or run this app on the host \
                 instead.",
                app_dir.display(),
                name.as_str()
            ),
        )
        .with_field("entry"));
    }
    Ok(absolute)
}

/// Refuse an environment a tenant should not be able to set.
///
/// The argv is an array, so nothing here can smuggle a flag; what it can do is
/// quietly win. `PORT` decides where the application listens and the vhost in
/// front of it already names that number, so a tenant overriding it produces a
/// site that 502s with every part of the panel reporting health.
fn check_env(runtime: AppRuntime, env: &[(String, String)]) -> Result<()> {
    let mut reserved: Vec<&str> = RESERVED_ENV_KEYS.to_vec();
    if let Some(var) = runtime.env_var() {
        reserved.push(var);
    }

    let mut seen: Vec<&str> = Vec::with_capacity(env.len());
    for (key, value) in env {
        let key = key.as_str();
        if key.is_empty() || key.len() > 64 {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "an environment variable name must be 1-64 characters",
            )
            .with_field("env"));
        }
        let first = key.bytes().next().expect("non-empty");
        if !(first.is_ascii_alphabetic() || first == b'_')
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                format!("`{key}` is not a valid environment variable name"),
            )
            .with_field("env"));
        }
        if reserved.iter().any(|r| r.eq_ignore_ascii_case(key)) {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                format!("`{key}` is set by the panel and cannot be overridden"),
            )
            .with_field("env"));
        }
        if seen.contains(&key) {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                format!("`{key}` is declared twice; the container would keep the last one"),
            )
            .with_field("env"));
        }
        seen.push(key);

        // A NUL cannot cross into a child process at all — the spawn fails with
        // an error about an interior nul byte, which tells nobody anything — and
        // a newline turns one variable into what looks like two in every log
        // line and `docker inspect` that ever prints it.
        if value.contains('\0') || value.contains('\n') {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                format!("the value of `{key}` contains a newline or a NUL byte"),
            )
            .with_field("env"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The argv
// ---------------------------------------------------------------------------

fn pull_argv(image: &ImageRef) -> Vec<String> {
    vec!["pull".to_string(), image.as_str().to_string()]
}

/// The whole `docker run`.
///
/// Every byte of it is derived from the row, the catalogue and this file — there
/// is no field a caller can put a flag in, which is the property
/// [`crate::docker`] refuses to give up and this file inherits.
fn run_argv(plan: &AppContainer) -> Vec<String> {
    let mut argv = vec![
        "run".to_string(),
        "--detach".to_string(),
        "--name".to_string(),
        plan.container.as_str().to_string(),
        // The containerised form of `systemctl enable`: an application must be
        // back after a reboot. `unless-stopped` rather than `always`, so an app
        // an operator deliberately stopped stays stopped across a daemon
        // restart.
        "--restart".to_string(),
        "unless-stopped".to_string(),
        // **The uid**, and the reason for the whole flag: without it every file
        // the application writes into the tenant's home is owned by root, and
        // the tenant can neither deploy over it nor delete it.
        "--user".to_string(),
        format!("{}:{}", plan.account.uid, plan.account.gid),
        // The port the database allocated, on loopback. Same number on both
        // sides so the application's own "listening on 20001" line and the
        // vhost's `proxy_pass` agree with each other.
        "--publish".to_string(),
        format!("{LOOPBACK}:{}:{}", plan.port, plan.port),
        // The code, at the identical path. An absolute path in a stack trace,
        // an error message or a log line then names a file the operator can
        // actually open on the host, and the entry needs no translating.
        "--volume".to_string(),
        format!("{0}:{0}", plan.app_dir.display()),
        "--workdir".to_string(),
        plan.app_dir.display().to_string(),
        // The host's accounts, read-only, exactly as the design document
        // specifies for FPM: the container does not create users, it names the
        // ones the host has. Without this the uid above has no passwd entry and
        // anything calling `getpwuid` fails on an application that is otherwise
        // fine. Read-only is not decoration — a writable bind of the host's
        // passwd inside a tenant's container is the whole machine.
        "--volume".to_string(),
        "/etc/passwd:/etc/passwd:ro".to_string(),
        "--volume".to_string(),
        "/etc/group:/etc/group:ro".to_string(),
        // 127.0.0.1 inside a container is the container. An application talking
        // to a containerised database needs a name for the host, and this is
        // Docker's own.
        "--add-host".to_string(),
        format!("{HOST_ALIAS}:host-gateway"),
        // PID 1 in the image is the application, which was not written to reap
        // children or to handle SIGTERM — so `docker stop` would wait the full
        // grace period and then SIGKILL an app mid-request, and any app that
        // spawns a subprocess would accumulate zombies. `--init` puts a real
        // init in front of it.
        "--init".to_string(),
        // The unit file's `NoNewPrivileges=yes`, kept. A setuid binary inside
        // the image is otherwise a way out of the uid above.
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        // Nothing an HTTP application does needs a capability. The unit had no
        // equivalent because a plain user process holds none anyway; a container
        // grants a default set, so it is dropped explicitly.
        "--cap-drop".to_string(),
        "ALL".to_string(),
    ];

    if let Some(mb) = plan.memory_mb {
        argv.push("--memory".to_string());
        argv.push(format!("{mb}m"));
        // Equal to `--memory` is Docker's spelling for "no swap", which is the
        // tenant slice's `MemorySwapMax=0`. Left off, Docker allows twice the
        // ceiling in swap and one application's overrun becomes every tenant's
        // disk latency.
        argv.push("--memory-swap".to_string());
        argv.push(format!("{mb}m"));
    }

    // The tenant's slice, so the plan's ceilings still hold. A container escapes
    // the systemd unit that used to carry `Slice=`, so without this an
    // application in a container is outside its tenant's aggregate memory, CPU
    // and pids limits — a tenant with six apps could then use six times what
    // their plan sold them. Docker applies it through systemd where the daemon
    // uses the systemd cgroup driver, which is what the distributions this panel
    // supports ship.
    if let Some(slice) = &plan.cgroup_parent {
        argv.push("--cgroup-parent".to_string());
        argv.push(slice.clone());
    }

    // Before the environment, so that a plan with a hundred tenant variables
    // still shows the panel's own identity in the first screen of a
    // `docker inspect`.
    for label in &plan.labels {
        argv.push("--label".to_string());
        argv.push(label.clone());
    }

    for line in &plan.env {
        argv.push("--env".to_string());
        argv.push(line.clone());
    }

    argv.push(plan.image.as_str().to_string());
    let image = image_for(plan.runtime).expect("a plan exists only for a containerised runtime");
    argv.extend(image.command.iter().map(|c| c.to_string()));
    argv.push(plan.entry.display().to_string());
    argv
}

/// Stop, with the grace period [`crate::docker`] uses. An application mid-request
/// is the reason it is a stop and not a kill.
fn stop_argv(container: &ContainerRef) -> Vec<String> {
    vec![
        "stop".to_string(),
        "-t".to_string(),
        GRACE_SECONDS.to_string(),
        container.as_str().to_string(),
    ]
}

fn restart_argv(container: &ContainerRef) -> Vec<String> {
    vec![
        "restart".to_string(),
        "-t".to_string(),
        GRACE_SECONDS.to_string(),
        container.as_str().to_string(),
    ]
}

/// Bare `rm`, and both omissions are load bearing.
///
/// No `--force`, which is a SIGKILL to an application that may be finishing a
/// request. No `--volumes`: the application directory is a **bind mount of
/// somebody's source code**, and while `-v` removes anonymous volumes rather
/// than bind mounts, a flag that means "and delete the data" has no business on
/// the argv that removes an application — the day this file grows a named volume
/// is the day it would become true.
fn remove_argv(container: &ContainerRef) -> Vec<String> {
    vec!["rm".to_string(), container.as_str().to_string()]
}

fn logs_argv(container: &ContainerRef, tail: u32) -> Vec<String> {
    vec![
        "logs".to_string(),
        // The only thing that can put stdout and stderr back into one order.
        "--timestamps".to_string(),
        "--tail".to_string(),
        tail.to_string(),
        container.as_str().to_string(),
    ]
}

/// `{{.State.Running}}` is what decisions are made from; the rest is why.
///
/// `RestartCount` is the field that catches a crash loop: a container whose
/// application exits immediately is restarted by the policy above and is
/// "running" again by the time anything asks, so the flag alone would call a
/// broken application healthy.
///
/// `Id` and the port label are what make an operation that was handed only a
/// tenant and an app name able to finish: the id locates the cgroup a memory
/// reading comes from, and the label says where a restarted application should
/// be listened for. One inspect answers all of it, which matters because
/// `app.list` asks this question once per application on a page somebody is
/// waiting for.
const INSPECT_FORMAT: &str = concat!(
    "{{.State.Running}}\t{{.State.Status}}\t{{.State.ExitCode}}\t{{.RestartCount}}",
    "\t{{.Id}}\t{{index .Config.Labels \"unihelm.app.port\"}}"
);

fn inspect_argv(container: &ContainerRef) -> Vec<String> {
    vec![
        "inspect".to_string(),
        // Without `--type container`, `docker inspect` will happily answer about
        // an *image* of the same name.
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

/// What Docker says about one application container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerState {
    /// Whether the container exists at all. A plan with no container is an app
    /// that was never started, or one somebody removed behind the panel's back.
    pub present: bool,
    pub running: bool,
    /// Docker's own word: `running`, `exited`, `created`, `restarting`.
    pub status: String,
    /// The exit code of the last run, meaningful only once it has exited.
    pub exit_code: i64,
    /// How many times the restart policy has put it back. Non-zero on a running
    /// container is a crash loop, not health.
    pub restarts: i64,
    /// The full container id, which is how its cgroup is named.
    pub id: String,
    /// The port this container publishes, off its own label.
    ///
    /// `None` for a container created before the label existed. Everything that
    /// reads it treats the absence as "do not probe", never as port zero: a
    /// restart that cannot find the port still restarts, it just cannot promise
    /// the application answered.
    pub port: Option<u16>,
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
            port: None,
        }
    }

    /// Whether this container is up and has stayed up since `baseline` restarts.
    fn healthy(&self, baseline: i64) -> bool {
        self.running && self.restarts <= baseline
    }

    /// The same state in systemd's vocabulary.
    ///
    /// Translated rather than reported in Docker's own words because the UI has
    /// one status renderer and one set of translated strings for `active` /
    /// `failed` / `not_found`, shared with every host application on the page. A
    /// second vocabulary would be a second renderer and a second set of strings,
    /// to say the thing the first set already says.
    ///
    /// A running container that has been restarted is [`UnitState::Failed`] and
    /// not `Active`, which is the one place this mapping is opinionated: a crash
    /// loop is the failure an operator most needs to see, and Docker's own
    /// `docker ps` calls it `Up 2 seconds` for as long as it goes on.
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
            // An application that stopped on purpose exited zero; anything else
            // stopped because it broke, and "inactive" would hide that.
            "exited" if self.exit_code == 0 => UnitState::Inactive,
            "exited" | "dead" => UnitState::Failed,
            _ => UnitState::Unknown,
        }
    }
}

/// One application container, in the words the applications list already speaks.
///
/// The shape [`crate::nodeapp`]'s `app.list` needs from either mode, so that one
/// row renderer serves a unit and a container alike.
#[derive(Debug, Clone, Serialize)]
pub struct AppStatus {
    pub state: UnitState,
    /// What the container is using right now, or `None` when this kernel does
    /// not lay its cgroups out anywhere this can find them. See [`memory_bytes`].
    pub memory_bytes: Option<u64>,
    /// Everything Docker said, for a caller that wants to be specific about a
    /// crash loop rather than only saying "failed".
    pub container: ContainerState,
}

/// What starting an application produced.
#[derive(Debug, Clone, Serialize)]
pub struct StartOutput {
    pub container: String,
    pub image: String,
    pub port: u16,
    /// Whether anything is actually accepting connections on the published port.
    ///
    /// False is **not** a failure: a worker with no HTTP server never binds, and
    /// refusing to create one would be this module deciding what an application
    /// is. It is reported so the caller can say the one true thing about it —
    /// until something listens, the vhost in front of it answers 502.
    pub listening: bool,
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
//
// Two shapes of entry point, and the split is the caller's rather than this
// module's taste. `create` and `update` are handed the application row, because
// they decide what to run and need every field of it. `restart`, `remove`,
// `logs` and `status` are handed a tenant and an app name and nothing else,
// because that is what `nodeapp` has when somebody clicks a button on a list —
// and everything those four need beyond the name is on the container itself, in
// the labels stamped there when it was created.

/// Create the container for an application and start it. **`app.create`.**
///
/// Does, in one call, what the host path does in three: the memory ceiling is a
/// run flag rather than a slice drop-in, and surviving a reboot is a restart
/// policy rather than a `WantedBy=`, so there is no unit to write, no drop-in to
/// apply and nothing to enable.
///
/// **The application directory is never created here.** `docker run` would
/// create a missing bind-mount source itself, as root, inside the tenant's home
/// — a directory the tenant could not then write to, made by a panel that
/// reported success. `nodeapp::ensure_app_dir` creates it, owned by the tenant,
/// before this is called, and [`check_bind_source`] refuses to proceed if that
/// did not happen.
pub async fn create(
    ctx: &OpContext,
    app: &NodeApp,
    name: &AppName,
    user: &LinuxUser,
    env: &[crate::nodeapp::EnvVar],
    memory_mb: Option<u32>,
) -> Result<StartOutput> {
    let plan = AppContainer::plan(
        app,
        user,
        name,
        AppContainerOptions {
            memory_mb,
            env: env
                .iter()
                .map(|v| (v.key.clone(), v.value.clone()))
                .collect(),
        },
    )?;
    create_planned(ctx, &plan).await
}

/// Replace an application's container with one built from its new image.
/// **`app.update`.**
///
/// A new runtime version is a new image, and there is no equivalent of
/// re-rendering one line of a unit file: the container has to be made again.
/// What must not be made again is the tenant's environment, which for a
/// container lives in the container rather than in a file on disk — so it is
/// read back off the one being replaced, exactly as `nodeapp::carried_environment`
/// reads it back out of the unit file on the host path.
///
/// It degrades the same way that function does, too. A container that is not
/// there carries nothing, and this proceeds rather than refusing, because the
/// row has already been updated by the time it is called and leaving an
/// application with a changed runtime and no container at all would be worse
/// than one that has lost variables it can be given again. It says so in the
/// log either way, so nobody has to infer it from an application that stopped
/// finding its database.
pub async fn update(
    ctx: &OpContext,
    app: &NodeApp,
    name: &AppName,
    user: &LinuxUser,
) -> Result<()> {
    let docker = docker_program()?;
    let container = container_ref(user, name)?;
    let carried = carried_configuration(&docker, &container).await;

    match &carried {
        Some(config) if !config.env.is_empty() => ctx.log(format!(
            "carrying {} environment variable(s) over from the old container",
            config.env.len()
        )),
        Some(_) => {}
        None => ctx.log(format!(
            "{container} could not be read, so any environment it held is not carried \
             over — set it again with app.update if the application stops finding it"
        )),
    }

    let (env, memory_mb) = match carried {
        Some(config) => (config.env, config.memory_mb),
        None => (Vec::new(), None),
    };

    let plan = AppContainer::plan(app, user, name, AppContainerOptions { memory_mb, env })?;
    create_planned(ctx, &plan).await?;
    Ok(())
}

/// Restart an application, and confirm it came back. **`app.restart`.**
///
/// `docker restart` rather than a stop and a fresh `run`, because the
/// container's arguments were decided when it was created; re-deciding them here
/// would let a restart quietly change what is running, which is the one thing a
/// restart must never do.
pub async fn restart(ctx: &OpContext, user: &LinuxUser, name: &AppName) -> Result<()> {
    let docker = docker_program()?;
    let container = container_ref(user, name)?;
    let found = state(&docker, &container).await?;

    // The distinction the host path draws between "stopped" and "never
    // installed", drawn here too. A stopped container restarts; a missing one is
    // a different problem with a different answer, and reporting it as a failed
    // restart would send somebody looking at their application code.
    if !found.present {
        return Err(UnihelmError::new(
            ErrorCode::NotFound,
            format!(
                "`{container}` is not on this server — the container for {} is missing, so \
                 there is nothing to restart. Delete the application and create it again to \
                 put it back; the files in its directory are untouched.",
                name.as_str()
            ),
        ));
    }

    ctx.log(format!("docker restart {container}"));
    run_checked(&docker, &restart_argv(&container), ACTION_BUDGET).await?;

    // Whether it came back answering goes into the log rather than into a return
    // value, because `app.restart`'s reply has no field for it and inventing one
    // would change the shape of a reply the UI already renders. The operator
    // watching the task sees the sentence either way, which is where they were
    // looking.
    let label = format!("{} ({})", name.as_str(), user.as_str());
    wait_until_up(ctx, &docker, &container, found.port, &label).await?;
    Ok(())
}

/// Stop and remove an application's container. **The application directory
/// survives.** Used by `app.delete` and by the rollback of a failed `app.create`.
///
/// The directory is a bind mount of the tenant's source code and their deployed
/// dependencies. The container is the thing that was created here; the directory
/// is not, and removing one must never be how somebody finds out about the
/// other. Nothing in this module deletes a path — `removing_a_container_never_takes_the_code_with_it`
/// asserts that against the source text — and [`remove_argv`] carries no flag
/// that could.
///
/// Idempotent. A container that is not there is not a failed removal: deletes
/// get retried, an interrupted one has to be able to finish, and a create that
/// failed before the `run` has nothing to roll back.
pub async fn remove(ctx: &OpContext, user: &LinuxUser, name: &AppName) -> Result<()> {
    let docker = docker_program()?;
    let container = container_ref(user, name)?;
    let found = state(&docker, &container).await?;
    if !found.present {
        ctx.log(format!(
            "{container} is not on this server; nothing to remove"
        ));
        return Ok(());
    }
    if found.running {
        ctx.log(format!("docker stop {container}"));
        run_checked(&docker, &stop_argv(&container), ACTION_BUDGET).await?;
    }
    ctx.log(format!(
        "docker rm {container} — {} is kept",
        paths::app_dir(user.as_str(), name.as_str()).display()
    ));
    run_checked(&docker, &remove_argv(&container), ACTION_BUDGET).await?;
    Ok(())
}

/// What this application is doing, in the applications list's own vocabulary.
/// **`app.list`.**
///
/// `ctx` is unused and still taken: this is one arm of a match whose other arm
/// needs it, and a signature that differed between the two would make the call
/// site branch on more than the mode.
pub async fn status(_ctx: &OpContext, user: &LinuxUser, name: &AppName) -> Result<AppStatus> {
    let docker = docker_program()?;
    let container = container_ref(user, name)?;
    let found = state(&docker, &container).await?;
    let slice = crate::slices::slice_file_name(user);
    Ok(AppStatus {
        state: found.unit_state(),
        // Only for a container that is actually running: a stopped one has no
        // cgroup, and the reading would come back either absent or stale.
        memory_bytes: found
            .running
            .then(|| memory_bytes(&found.id, Some(&slice)))
            .flatten(),
        container: found,
    })
}

/// The last `lines` lines the application has written, both streams in one
/// order. **`app.logs`.**
pub async fn logs(
    _ctx: &OpContext,
    user: &LinuxUser,
    name: &AppName,
    lines: u32,
) -> Result<Vec<String>> {
    let docker = docker_program()?;
    let container = container_ref(user, name)?;
    // Clamped again here rather than trusted. The caller clamps to bound one IPC
    // frame, which is a property of the reply; this bounds what a tail asks
    // Docker for, which is a property of the command, and a caller that stopped
    // clamping must not be able to ask for every line a busy application has
    // ever written.
    let tail = lines.clamp(1, MAX_LOG_LINES);
    let out = run_raw(&docker, &logs_argv(&container, tail), READ_BUDGET).await?;
    if !out.success() {
        let text = out.failure_text();
        let lower = text.to_ascii_lowercase();
        if lower.contains("no such object") || lower.contains("no such container") {
            return Err(UnihelmError::new(
                ErrorCode::NotFound,
                format!(
                    "`{container}` is not on this server, so there are no logs to read for \
                     {}.",
                    name.as_str()
                ),
            ));
        }
        return Err(UnihelmError::new(ErrorCode::CommandFailed, text));
    }
    Ok(interleave(&out.stdout, &out.stderr, tail as usize))
}

/// The ceiling on one log request. This bounds a single IPC frame, not the
/// operator's access to their logs — [`crate::docker`]'s number, for its reason.
const MAX_LOG_LINES: u32 = 2_000;

// ---------------------------------------------------------------------------
// Create, from a resolved plan
// ---------------------------------------------------------------------------

/// Pull the image, replace any container of this name, start it, and confirm it
/// stayed up.
///
/// The shared half of [`create`] and [`update`], which differ only in where the
/// plan came from.
async fn create_planned(ctx: &OpContext, plan: &AppContainer) -> Result<StartOutput> {
    let docker = docker_program()?;
    check_bind_source(&plan.app_dir)?;

    ctx.log(format!("docker pull {}", plan.image.as_str()));
    run_checked(&docker, &pull_argv(&plan.image), PULL_BUDGET).await?;

    // The name is the identity, so a container already holding it is this same
    // application — an interrupted create, or a runtime change being applied —
    // rather than somebody else's container to work around. `docker run` would
    // refuse the name.
    //
    // After the pull, never before: taking a serving application down and then
    // spending a quarter of an hour on a download is an outage bought for
    // nothing, and bought again if the download fails.
    if state(&docker, &plan.container).await?.present {
        ctx.log(format!(
            "{} already exists; replacing it — the application directory is untouched",
            plan.container
        ));
        if state(&docker, &plan.container).await?.running {
            run_checked(&docker, &stop_argv(&plan.container), ACTION_BUDGET).await?;
        }
        run_checked(&docker, &remove_argv(&plan.container), ACTION_BUDGET).await?;
    }

    ctx.log(format!(
        "docker run {} as {}, published on {LOOPBACK}:{}",
        plan.image.as_str(),
        plan.container,
        plan.port
    ));
    run_checked(&docker, &run_argv(plan), ACTION_BUDGET).await?;

    let listening =
        wait_until_up(ctx, &docker, &plan.container, Some(plan.port), plan.label()).await?;
    Ok(StartOutput {
        container: plan.container.as_str().to_string(),
        image: plan.image.as_str().to_string(),
        port: plan.port,
        listening,
    })
}

// ---------------------------------------------------------------------------
// What a replaced container was carrying
// ---------------------------------------------------------------------------

/// The tenant's own configuration, read back off a container about to be
/// replaced.
struct CarriedConfiguration {
    env: Vec<(String, String)>,
    memory_mb: Option<u32>,
}

/// `{{json .Config.Env}}` and the memory ceiling, in bytes.
///
/// A second inspect rather than more columns on [`INSPECT_FORMAT`], because this
/// is asked once per update and that one is asked once per application on every
/// list — and a JSON array embedded in a tab-separated line is a parser waiting
/// to be surprised by a value containing a tab.
fn carried_argv(container: &ContainerRef) -> Vec<String> {
    vec![
        "inspect".to_string(),
        "--type".to_string(),
        "container".to_string(),
        "--format".to_string(),
        "{{json .Config.Env}}\t{{.HostConfig.Memory}}".to_string(),
        container.as_str().to_string(),
    ]
}

async fn carried_configuration(
    docker: &str,
    container: &ContainerRef,
) -> Option<CarriedConfiguration> {
    let out = run_raw(docker, &carried_argv(container), READ_BUDGET)
        .await
        .ok()?;
    if !out.success() {
        return None;
    }
    parse_carried(out.trimmed_stdout())
}

fn parse_carried(text: &str) -> Option<CarriedConfiguration> {
    let (env_json, memory) = text.trim().split_once('\t')?;
    let lines: Vec<String> = serde_json::from_str(env_json).ok()?;
    let bytes: u64 = memory.trim().parse().unwrap_or(0);
    Some(CarriedConfiguration {
        env: lines.iter().filter_map(|l| tenant_variable(l)).collect(),
        // Docker reports no ceiling as 0, which is not a ceiling of zero
        // megabytes. Rounding up keeps a 512m ceiling from becoming 511m after
        // an update; a ceiling below a megabyte cannot have been set through
        // this panel, and [`MIN_MEMORY_MB`] would clamp it back anyway.
        memory_mb: (bytes > 0).then(|| bytes.div_ceil(1024 * 1024) as u32),
    })
}

/// One `KEY=VALUE` line, if it is the tenant's rather than the panel's.
///
/// The image supplies its own — `PATH`, `NODE_VERSION`, `LANG` — and re-declaring
/// those on the next `docker run` would pin an old image's values onto a new
/// image, which is precisely how a runtime upgrade turns into a mystery. So the
/// filter is a positive one: the panel's own keys are dropped because it will
/// set them again, and everything an image would plausibly define is dropped
/// because the new image defines it better.
///
/// The cost of being wrong in this direction is a variable a tenant has to set
/// again, which they can. The cost of being wrong in the other is an application
/// that silently keeps running against the old runtime's paths.
fn tenant_variable(line: &str) -> Option<(String, String)> {
    let (key, value) = line.split_once('=')?;
    let panel_owned = RESERVED_ENV_KEYS.contains(&key)
        || AppRuntime::ALL.iter().any(|r| r.env_var() == Some(key));
    let image_owned = matches!(
        key,
        "PATH" | "HOSTNAME" | "LANG" | "LC_ALL" | "TERM" | "PWD" | "SHLVL"
    ) || key.ends_with("_VERSION")
        || key.ends_with("_SHA256")
        || key.ends_with("_KEYS");
    (!panel_owned && !image_owned).then(|| (key.to_string(), value.to_string()))
}

// ---------------------------------------------------------------------------
// "Started" is not "running"
// ---------------------------------------------------------------------------

/// Watch the container until it is demonstrably up, or demonstrably not.
///
/// `docker run` exiting zero means Docker accepted the container, and nothing
/// more. An application with a missing dependency or a syntax error exits in
/// well under a second, and `--restart unless-stopped` then puts it back — so a
/// single `State.Running` read a moment later says `true` about an application
/// that has already died three times. The restart counter is what separates the
/// two, and it is sampled against a baseline taken immediately after the start
/// rather than against zero, because a container that has been alive and crashed
/// in the past carries its old count.
///
/// Returns whether the port ever answered. A container that is up but silent is
/// reported, not refused: a queue worker legitimately never binds, and this
/// module does not get to decide what an application is.
///
/// `port` is `None` only for a container from a build before the port label
/// existed. The wait still watches it stay up — that half needs no port — and
/// simply cannot promise anything answered.
async fn wait_until_up(
    ctx: &OpContext,
    docker: &str,
    container: &ContainerRef,
    port: Option<u16>,
    label: &str,
) -> Result<bool> {
    let baseline = state(docker, container).await?.restarts;
    let deadline = tokio::time::Instant::now() + LISTEN_BUDGET;
    let mut delay = Duration::from_millis(200);

    loop {
        let found = state(docker, container).await?;
        if !found.healthy(baseline) {
            return Err(did_not_stay_up(docker, container, label, &found).await);
        }
        // The published port is the path nginx will take, so asking here catches
        // an application that came up bound to the wrong interface — the classic
        // one is a server listening on 127.0.0.1 *inside* the container, which
        // nothing outside its namespace can ever reach.
        if let Some(port) = port
            && tokio::net::TcpStream::connect((LOOPBACK, port))
                .await
                .is_ok()
        {
            ctx.log(format!("{label} is answering on {LOOPBACK}:{port}"));
            return Ok(true);
        }
        if tokio::time::Instant::now() + delay >= deadline {
            break;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(2));
    }

    // One last look, so a container that died in the final second of the wait is
    // reported as dead rather than as quiet.
    let found = state(docker, container).await?;
    if !found.healthy(baseline) {
        return Err(did_not_stay_up(docker, container, label, &found).await);
    }
    match port {
        Some(port) => ctx.log(format!(
            "{label} is running, but nothing is listening on {LOOPBACK}:{port} yet — a \
             site in front of it will answer 502 until the application binds that port \
             (read it from the PORT environment variable)"
        )),
        None => ctx.log(format!("{label} is running")),
    }
    Ok(false)
}

/// The error for an application that did not survive its own start, carrying the
/// only thing that actually helps: what the application said on its way out.
async fn did_not_stay_up(
    docker: &str,
    container: &ContainerRef,
    label: &str,
    found: &ContainerState,
) -> UnihelmError {
    let tail = last_words(docker, container).await;
    let what = if found.restarts > 0 {
        format!(
            "started and then crashed {} time(s) in a row",
            found.restarts
        )
    } else {
        format!("exited immediately with status {}", found.exit_code)
    };
    UnihelmError::new(
        ErrorCode::ServiceActionFailed,
        format!(
            "{label} {what}. The container is `{container}` and this is the end of its \
             log:\n{tail}"
        ),
    )
}

/// How many lines of a dead application's log go into the error message.
///
/// Enough for a stack trace's first frames, short of turning one error into a
/// screen of text nobody reads.
const LAST_WORDS_LINES: u32 = 20;

async fn last_words(docker: &str, container: &ContainerRef) -> String {
    match run_raw(docker, &logs_argv(container, LAST_WORDS_LINES), READ_BUDGET).await {
        Ok(out) => {
            let lines = interleave(&out.stdout, &out.stderr, LAST_WORDS_LINES as usize);
            if lines.is_empty() {
                format!("(nothing; `docker logs {container}` is empty)")
            } else {
                lines.join("\n")
            }
        }
        Err(e) => format!("(its log could not be read: {e})"),
    }
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// Refuse to bind-mount anything but a real, existing directory.
///
/// Two failures, both of them somebody's server:
///
/// - **Missing.** `docker run` creates a missing bind source itself, owned by
///   root. In a tenant home that is a directory the tenant cannot write to,
///   produced by a panel that reported success.
/// - **A symlink.** `<home>/apps/<name>` sits inside a directory the tenant
///   owns, so they can replace it with a link to anywhere, and Docker resolves
///   the path on the host before mounting it. The same refusal, for the same
///   reason, as `nodeapp::check_app_dir_target` and `sftp`'s subdir steps.
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
                "{} does not exist. The application directory has to be created, owned by \
                 the tenant, before its container starts — Docker would otherwise create \
                 it as root inside their home.",
                dir.display()
            ),
        )),
        Err(e) => Err(UnihelmError::internal(format!(
            "could not inspect {}: {e}",
            dir.display()
        ))),
    }
}

/// The `docker` binary, or the reason there is nothing to run an application in.
fn docker_program() -> Result<String> {
    unihelm_distro::exec::resolve_program(DOCKER)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|_| {
            UnihelmError::new(
                ErrorCode::NotFound,
                "Docker is not installed on this server, and this application runs in a \
                 container. Install Docker from the Stack Manager first.",
            )
        })
}

/// One inspect. A container that is not there is [`ContainerState::absent`] and
/// not an error, because every caller here has something sensible to do about
/// it; anything else — a daemon that is down, most of all — is an error, since
/// reporting a stopped `docker.service` as "your application is gone" sends an
/// operator looking for something they still have.
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
const INSPECT_FIELDS: usize = 6;

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
        // A field Docker did not fill is reported as zero rather than failing the
        // whole read: the exit code is context in a message, and the running flag
        // beside it is what anything actually decides on.
        exit_code: fields[2].parse().unwrap_or(0),
        restarts: fields[3].parse().unwrap_or(0),
        id: fields[4].to_string(),
        // A container with no such label renders as Go's `<no value>`, which
        // parses to nothing — the same answer as a container from a build before
        // the label existed, and the right one for both.
        port: fields[5].parse().ok(),
    })
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// What this container is using, read from the kernel rather than from Docker.
///
/// `docker stats` is the obvious answer and the wrong one here. It samples, so a
/// single `--no-stream` call costs the better part of a second, and `app.list`
/// asks this question once per application — which is the shape of the bug that
/// made the Stack page go quiet for twenty seconds after every click. A cgroup
/// file is a read.
///
/// Where that file is depends on the daemon's cgroup driver, so all the layouts
/// are tried and the first that answers wins:
///
/// - cgroup v2 with the systemd driver, which is what the distributions this
///   panel supports ship, and where `--cgroup-parent` puts the container inside
///   the tenant's own slice;
/// - cgroup v2 with the systemd driver and no slice, under `system.slice`;
/// - cgroup v2 with the cgroupfs driver;
/// - cgroup v1, whose accounting file has a different name again.
///
/// `None` when none of them exist, which is the honest answer and the same one
/// the host path gives for a unit whose status could not be read — the column
/// renders empty rather than showing a zero that would read as "using nothing".
fn memory_bytes(id: &str, slice: Option<&str>) -> Option<u64> {
    if id.is_empty() {
        return None;
    }
    let root = Path::new("/sys/fs/cgroup");
    let scope = format!("docker-{id}.scope");
    let mut candidates = Vec::with_capacity(4);
    if let Some(slice) = slice {
        candidates.push(root.join(slice).join(&scope).join("memory.current"));
    }
    candidates.push(
        root.join("system.slice")
            .join(&scope)
            .join("memory.current"),
    );
    candidates.push(root.join("docker").join(id).join("memory.current"));
    candidates.push(
        root.join("memory")
            .join("docker")
            .join(id)
            .join("memory.usage_in_bytes"),
    );

    candidates.iter().find_map(|path| {
        let text = std::fs::read_to_string(path).ok()?;
        // cgroup v2 writes `max` here when nothing is charged yet, which is not
        // a number and is not a usage either.
        text.trim().parse::<u64>().ok()
    })
}

/// The two halves of a container's log, put back into one order.
///
/// `docker logs` writes the container's stdout to our stdout and its stderr to
/// our stderr, and there is no shell here to redirect one into the other. Most
/// application frameworks log to stderr, so reading only stdout shows an empty
/// log for an application that is logging perfectly well. Concatenating misorders
/// them; `--timestamps` makes them sortable, because Docker emits a fixed-width
/// RFC 3339 UTC prefix and lexicographic order is then chronological order. A
/// line with no timestamp is a continuation — the second line of a stack trace —
/// and inherits the key above it in its own stream so a traceback stays whole.
///
/// The same shape as [`crate::docker`]'s, and duplicated for the reason
/// [`passwd_entry`] is: that one is private to a module this wave does not open.
fn interleave(stdout: &str, stderr: &str, limit: usize) -> Vec<String> {
    let mut keyed: Vec<(String, String)> = Vec::new();
    for stream in [stdout, stderr] {
        let mut last = String::new();
        for line in stream.lines() {
            let key = match line.split_once(' ') {
                Some((first, _)) if is_timestamp(first) => {
                    last = first.to_string();
                    last.clone()
                }
                _ => last.clone(),
            };
            keyed.push((key, line.to_string()));
        }
    }
    // Stable, so two lines written in the same nanosecond keep the order they
    // were read in rather than swapping between refreshes.
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let start = keyed.len().saturating_sub(limit);
    keyed.drain(..start);
    keyed.into_iter().map(|(_, line)| line).collect()
}

fn is_timestamp(token: &str) -> bool {
    let b = token.as_bytes();
    b.len() >= 20 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && token.contains('T')
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
    use crate::nodeapp::app_container_name as container_name;
    use unihelm_core::SubscriptionId;
    use unihelm_db::node_apps::{AppMode, NodeEnv};

    fn user() -> LinuxUser {
        LinuxUser::parse("uh_abc12345").unwrap()
    }

    fn name() -> AppName {
        AppName::parse("blog").unwrap()
    }

    fn account() -> Account {
        Account {
            uid: 1007,
            gid: 1007,
        }
    }

    fn app_row(runtime: AppRuntime, version: Option<&str>, entry: &str) -> NodeApp {
        NodeApp {
            id: 1,
            subscription_id: SubscriptionId(1),
            site_id: None,
            name: "blog".into(),
            entry: entry.into(),
            port: 20_001,
            runtime,
            mode: AppMode::Container,
            node_env: NodeEnv::Production,
            runtime_version: version.map(str::to_string),
            enabled: true,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn plan(runtime: AppRuntime, version: Option<&str>) -> AppContainer {
        plan_with(runtime, version, AppContainerOptions::default())
    }

    fn plan_with(
        runtime: AppRuntime,
        version: Option<&str>,
        options: AppContainerOptions,
    ) -> AppContainer {
        AppContainer::plan_as(
            &app_row(runtime, version, "apps/blog/server.js"),
            &user(),
            &name(),
            options,
            account(),
        )
        .expect("a containerisable runtime")
    }

    /// The value of `flag`, or a panic naming what was actually there.
    fn value_of(argv: &[String], flag: &str) -> String {
        argv.windows(2)
            .find(|w| w[0] == flag)
            .map(|w| w[1].clone())
            .unwrap_or_else(|| panic!("no {flag} in {argv:?}"))
    }

    // -----------------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------------

    /// An operator reading `docker ps` and one reading `systemctl` have to see
    /// the same application. If either naming scheme moves, the two views stop
    /// agreeing and nobody finds out from a page — they find out at 3am.
    #[test]
    fn every_container_is_named_for_its_unit() {
        let unit = crate::nodeapp::unit_file_name(&user(), &name());
        assert_eq!(
            format!("{}.service", container_name(&user(), &name())),
            unit
        );
        assert_eq!(
            container_name(&user(), &name()),
            "unihelm-app-uh_abc12345-blog"
        );
    }

    /// Two tenants may each have a `blog`, and one tenant may have two apps.
    /// Either half of the name alone would collide.
    #[test]
    fn the_name_carries_both_the_tenant_and_the_app() {
        let other = LinuxUser::parse("uh_zzz99999").unwrap();
        let second = AppName::parse("api").unwrap();
        assert_ne!(
            container_name(&user(), &name()),
            container_name(&other, &name())
        );
        assert_ne!(
            container_name(&user(), &name()),
            container_name(&user(), &second)
        );
    }

    /// "Pin this app to 22.11.0" has to mean 22.11.0. An app that quietly ran on
    /// something else would be the panel changing a production runtime nobody
    /// asked it to change.
    #[test]
    fn a_pinned_version_is_the_tag_verbatim() {
        for (runtime, version, image) in [
            (AppRuntime::Node, "22.11.0", "node:22.11.0"),
            (AppRuntime::Node, "20", "node:20"),
            (AppRuntime::Python, "3.12", "python:3.12"),
            (AppRuntime::Ruby, "3.2", "ruby:3.2"),
            (AppRuntime::Bun, "1.1.34", "oven/bun:1.1.34"),
            (AppRuntime::Deno, "2.1.4", "denoland/deno:2.1.4"),
        ] {
            assert_eq!(plan(runtime, Some(version)).image().as_str(), image);
        }
    }

    /// An unpinned Node app takes the catalogue's recommendation, so "install
    /// Node 22" and "run this app on Node" mean the same version.
    #[test]
    fn an_unpinned_app_takes_the_catalogues_recommendation() {
        let recommended = catalogue::default_version("node").unwrap().version;
        assert_eq!(
            plan(AppRuntime::Node, None).image().as_str(),
            format!("node:{recommended}")
        );
    }

    /// Python and Ruby are catalogued as `distro`, which is not a Docker tag —
    /// `python:distro` is a pull that fails on a manifest nobody can read. Every
    /// runtime must still resolve to an exact tag, and never to `latest`: a tag
    /// that moves under a running app turns a restart into a major upgrade of
    /// somebody's production application.
    #[test]
    fn every_unpinned_runtime_still_resolves_to_an_exact_tag() {
        for runtime in AppRuntime::ALL
            .iter()
            .copied()
            .filter(|r| is_containerisable(*r))
        {
            let image = plan(runtime, None).image().as_str().to_string();
            let (_, tag) = image.rsplit_once(':').expect("an image carries a tag");
            assert!(
                has_digit(tag),
                "{} resolved to `{image}`, which pins nothing",
                runtime.label()
            );
            assert_ne!(tag, "latest", "{} may not float", runtime.label());
        }
    }

    /// A version reaches an image reference, so it has to be a tag and not an
    /// argument or a second image.
    #[test]
    fn a_version_that_is_not_a_tag_is_refused() {
        for bad in ["22:latest", "-22", "22 --privileged", "../etc", ""] {
            assert!(
                AppContainer::plan_as(
                    &app_row(AppRuntime::Node, Some(bad), "apps/blog/server.js"),
                    &user(),
                    &name(),
                    AppContainerOptions::default(),
                    account(),
                )
                .is_err(),
                "`{bad}` was accepted as a version"
            );
        }
    }

    /// Go compiles to a binary: there is no interpreter image, so a Go app stays
    /// a systemd unit. Silently running it in the `golang` toolchain image would
    /// be a gigabyte of compiler wrapped around a program that needs none.
    #[test]
    fn a_compiled_runtime_has_no_container() {
        assert!(!is_containerisable(AppRuntime::Go));
        let refused = AppContainer::plan_as(
            &app_row(AppRuntime::Go, None, "apps/blog/server"),
            &user(),
            &name(),
            AppContainerOptions::default(),
            account(),
        )
        .expect_err("Go has no runtime image");
        assert!(
            refused.detail.contains("compiled"),
            "the refusal has to say why: {}",
            refused.detail
        );
        // And the two answers agree, so nothing can containerise a runtime the
        // rest of the panel treats as compiled.
        for runtime in AppRuntime::ALL {
            assert_eq!(
                is_containerisable(*runtime),
                !runtime.is_compiled(),
                "{} disagrees with itself",
                runtime.label()
            );
        }
    }

    // -----------------------------------------------------------------------
    // The argv
    // -----------------------------------------------------------------------

    /// Without `--user` every file the application writes into the tenant's own
    /// home is owned by root: the file manager cannot open it, SFTP cannot
    /// replace it, and the next deploy fails on a directory the tenant owns.
    #[test]
    fn the_container_runs_as_the_tenants_own_uid() {
        let argv = run_argv(&plan(AppRuntime::Node, None));
        assert_eq!(value_of(&argv, "--user"), "1007:1007");
    }

    /// A tenant that maps to root is an account database this panel will not run
    /// tenant code under: `--user 0:0` puts root-owned files in a tenant's home
    /// while running that tenant's own code, which is every failure this module
    /// exists to prevent, at once.
    ///
    /// `root` cannot be reached by name — [`LinuxUser`] refuses reserved system
    /// users — so the account this catches is a `uh_*` tenant whose passwd entry
    /// says 0 after a restore or a manual `usermod`, which is why the guard is
    /// tested on the numbers rather than on the name.
    #[test]
    fn a_tenant_that_maps_to_root_is_refused() {
        assert_eq!(Account::checked(&user(), 1007, 1007).unwrap(), account());
        for (uid, gid) in [(0, 1007), (1007, 0), (0, 0)] {
            assert!(
                Account::checked(&user(), uid, gid).is_err(),
                "uid {uid}, gid {gid} was accepted"
            );
        }
        // And an account that is not on this host is a refusal rather than a
        // guess: there is no uid to run the container as.
        let absent = LinuxUser::parse("uh_notonthisbox").unwrap();
        assert!(Account::lookup(&absent).is_err());
    }

    /// An application published on every interface is reachable on a raw port,
    /// past the vhost, its TLS and its access rules — and Docker's DNAT rule
    /// sits in front of `INPUT`, so the firewall does not save it.
    #[test]
    fn the_port_is_published_on_loopback_only() {
        for runtime in AppRuntime::ALL
            .iter()
            .copied()
            .filter(|r| is_containerisable(*r))
        {
            let publish = value_of(&run_argv(&plan(runtime, None)), "--publish");
            assert!(
                publish.starts_with("127.0.0.1:"),
                "{} would be reachable from the internet: {publish}",
                runtime.label()
            );
        }
    }

    /// The database allocated the port and the proxy vhost was rendered with it.
    /// A container that published anything else would leave nginx proxying to a
    /// number nothing listens on, which is a 502 on somebody's domain.
    #[test]
    fn the_published_port_is_the_one_the_row_allocated() {
        let argv = run_argv(&plan(AppRuntime::Node, None));
        assert_eq!(value_of(&argv, "--publish"), "127.0.0.1:20001:20001");
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--env" && w[1] == "PORT=20001"),
            "the app is told which port to bind: {argv:?}"
        );
    }

    /// The code is mounted at the same absolute path on both sides, so a stack
    /// trace names a file the operator can open, and the entry needs no
    /// translating between host and container.
    #[test]
    fn the_app_directory_is_bind_mounted_at_the_same_path() {
        let argv = run_argv(&plan(AppRuntime::Node, None));
        let dir = "/home/uh_abc12345/apps/blog";
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--volume" && w[1] == format!("{dir}:{dir}")),
            "{argv:?}"
        );
        assert_eq!(value_of(&argv, "--workdir"), dir);
        assert_eq!(
            argv.last().map(String::as_str),
            Some("/home/uh_abc12345/apps/blog/server.js"),
            "the entry is the last word, inside the mount: {argv:?}"
        );
    }

    /// The host's accounts, read-only. Writable, a bind of the host's passwd
    /// inside a tenant's container would be the whole machine; absent, the uid
    /// above has no name and anything calling `getpwuid` fails on an application
    /// that is otherwise fine.
    #[test]
    fn the_hosts_accounts_come_in_read_only() {
        let argv = run_argv(&plan(AppRuntime::Node, None));
        for mount in ["/etc/passwd:/etc/passwd:ro", "/etc/group:/etc/group:ro"] {
            assert!(
                argv.windows(2).any(|w| w[0] == "--volume" && w[1] == mount),
                "{mount} missing from {argv:?}"
            );
        }
        assert!(
            !argv.iter().any(|a| a == "/etc/passwd:/etc/passwd"),
            "a writable passwd mount is root on this machine: {argv:?}"
        );
    }

    /// Each runtime has to be started by the command that actually runs it.
    /// Deno additionally denies the network unless it is granted, so a bare
    /// `deno run` produces an application that can never bind its port.
    #[test]
    fn each_runtime_is_started_by_its_own_command() {
        let expected = [
            (AppRuntime::Node, vec!["node"]),
            (AppRuntime::Python, vec!["python"]),
            (AppRuntime::Ruby, vec!["ruby"]),
            (AppRuntime::Bun, vec!["bun", "run"]),
            (AppRuntime::Deno, vec!["deno", "run", "--allow-all"]),
        ];
        for (runtime, command) in expected {
            let resolved = plan(runtime, None);
            let argv = run_argv(&resolved);
            let image = argv
                .iter()
                .position(|a| a == resolved.image().as_str())
                .unwrap_or_else(|| panic!("{argv:?} names no image"));
            // The command comes after the image, or Docker reads it as a flag.
            assert_eq!(
                argv[image + 1..image + 1 + command.len()],
                command.iter().map(|c| c.to_string()).collect::<Vec<_>>()[..],
                "{argv:?}"
            );
        }
    }

    /// An application must come back after a reboot, and must stay stopped when
    /// an operator stopped it. This is the container's `systemctl enable`.
    #[test]
    fn an_application_comes_back_after_a_reboot() {
        let argv = run_argv(&plan(AppRuntime::Node, None));
        assert_eq!(value_of(&argv, "--restart"), "unless-stopped");
    }

    /// A memory cap that can spill into swap is not a cap — it turns one
    /// application's overrun into every tenant's disk latency, which is exactly
    /// what the tenant slice's `MemorySwapMax=0` says on the systemd path.
    #[test]
    fn the_memory_ceiling_cannot_spill_into_swap() {
        let argv = run_argv(&plan_with(
            AppRuntime::Node,
            None,
            AppContainerOptions {
                memory_mb: Some(512),
                env: vec![],
            },
        ));
        assert_eq!(value_of(&argv, "--memory"), "512m");
        assert_eq!(value_of(&argv, "--memory-swap"), "512m");
        // No ceiling asked for is no ceiling applied, not a default this file
        // invented.
        assert!(
            !run_argv(&plan(AppRuntime::Node, None))
                .iter()
                .any(|a| a == "--memory")
        );
    }

    /// Docker refuses `--memory` under 6m and no interpreter starts in single
    /// megabytes, so an un-clamped ceiling of 4 would not cap an application, it
    /// would refuse to create one.
    #[test]
    fn a_memory_ceiling_too_small_to_start_is_clamped() {
        let argv = run_argv(&plan_with(
            AppRuntime::Node,
            None,
            AppContainerOptions {
                memory_mb: Some(4),
                env: vec![],
            },
        ));
        assert_eq!(value_of(&argv, "--memory"), format!("{MIN_MEMORY_MB}m"));
    }

    /// The hardening the systemd unit carried, kept. `NoNewPrivileges` closes
    /// every setuid path out of the uid above, and a container grants a default
    /// capability set that a web application has no use for.
    #[test]
    fn the_units_hardening_survives_the_move() {
        let argv = run_argv(&plan(AppRuntime::Node, None));
        assert_eq!(value_of(&argv, "--security-opt"), "no-new-privileges");
        assert_eq!(value_of(&argv, "--cap-drop"), "ALL");
        assert!(argv.iter().any(|a| a == "--init"), "{argv:?}");
    }

    /// 127.0.0.1 inside a container is the container. Without a name for the
    /// host, an application cannot reach a containerised database at all.
    #[test]
    fn the_host_is_reachable_by_name_from_inside() {
        let argv = run_argv(&plan(AppRuntime::Node, None));
        assert_eq!(
            value_of(&argv, "--add-host"),
            "host.docker.internal:host-gateway"
        );
    }

    /// The panel's own variables are written last, because `docker run` keeps
    /// the last of a repeated key — the opposite order from the systemd unit,
    /// where the template appends the tenant's afterwards. Get this backwards
    /// and a tenant's `PORT` silently wins over the one the vhost names.
    #[test]
    fn the_panels_own_environment_wins() {
        let argv = run_argv(&plan_with(
            AppRuntime::Node,
            None,
            AppContainerOptions {
                memory_mb: None,
                env: vec![("DATABASE_URL".into(), "postgres://x".into())],
            },
        ));
        let position = |needle: &str| {
            argv.iter()
                .position(|a| a == needle)
                .unwrap_or_else(|| panic!("no {needle} in {argv:?}"))
        };
        assert!(position("DATABASE_URL=postgres://x") < position("PORT=20001"));
        assert!(argv.iter().any(|a| a == "NODE_ENV=production"), "{argv:?}");
    }

    /// A container running as a bare uid has no home, so `HOME` defaults to `/`
    /// and the first write a package manager or a logging library makes fails on
    /// a read-only root. Pointing it at the app directory keeps those writes in
    /// the one place the tenant owns.
    #[test]
    fn the_application_has_a_home_it_can_write_to() {
        let argv = run_argv(&plan(AppRuntime::Node, None));
        assert!(
            argv.iter().any(|a| a == "HOME=/home/uh_abc12345/apps/blog"),
            "{argv:?}"
        );
    }

    /// A tenant setting `PORT` breaks the proxy wiring; one setting `HOME`
    /// breaks every write the runtime makes. Both are the panel's.
    #[test]
    fn a_tenant_cannot_override_what_the_panel_owns() {
        for key in ["PORT", "port", "HOME", "NODE_ENV"] {
            assert!(
                check_env(AppRuntime::Node, &[(key.into(), "x".into())]).is_err(),
                "`{key}` was accepted"
            );
        }
        // And the per-ecosystem flag is per ecosystem: RACK_ENV is Ruby's, and
        // is an ordinary variable to a Node application.
        assert!(check_env(AppRuntime::Ruby, &[("RACK_ENV".into(), "x".into())]).is_err());
        assert!(check_env(AppRuntime::Node, &[("RACK_ENV".into(), "x".into())]).is_ok());
    }

    /// A newline cannot cross into a child's environment usefully and a NUL
    /// cannot cross at all — the spawn fails with a message about an interior
    /// nul byte, which tells nobody anything.
    #[test]
    fn an_environment_value_that_cannot_be_carried_is_refused() {
        assert!(check_env(AppRuntime::Node, &[("A".into(), "x\ny".into())]).is_err());
        assert!(check_env(AppRuntime::Node, &[("A".into(), "x\0y".into())]).is_err());
        assert!(check_env(AppRuntime::Node, &[("A".into(), "a space".into())]).is_ok());
    }

    // -----------------------------------------------------------------------
    // The code survives
    // -----------------------------------------------------------------------

    /// Removing a container must never be how somebody finds out their source
    /// code is gone. `-f` SIGKILLs an application mid-request; `-v` is the flag
    /// that would mean "and the data" the day this file grows a volume.
    #[test]
    fn removing_a_container_never_takes_the_code_with_it() {
        let target = plan(AppRuntime::Node, None);
        assert_eq!(
            remove_argv(target.container()),
            vec!["rm", "unihelm-app-uh_abc12345-blog"]
        );
        for forbidden in ["-v", "--volumes", "-f", "--force"] {
            assert!(
                !remove_argv(target.container())
                    .iter()
                    .any(|a| a == forbidden),
                "{forbidden} would be on the removal argv"
            );
        }
        // The stop in front of it is graceful, for an application that may be
        // finishing a request.
        assert_eq!(
            stop_argv(target.container()),
            vec!["stop", "-t", "10", "unihelm-app-uh_abc12345-blog"]
        );
        // And nothing in this module removes a path at all: the source directory
        // is a bind mount, and the container is the only thing that was created
        // here. The needles are spelled in halves so that this assertion is not
        // itself the occurrence it is looking for — written whole, the test
        // fails on its own text and tells nobody anything.
        let source = include_str!("appcontainer.rs");
        for banned in [concat!("remove_", "dir"), concat!("remove_", "file")] {
            assert!(
                !source.contains(banned),
                "`{banned}` appears in this module; removing an application must never \
                 delete a tenant's source code"
            );
        }
    }

    /// `<home>/apps/<name>` sits in a directory the tenant owns, so they can
    /// replace it with a link to anywhere — and Docker resolves the path on the
    /// host before it mounts it.
    #[test]
    fn a_symlinked_app_directory_is_never_mounted() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(check_bind_source(&real).is_ok());
        assert!(check_bind_source(&link).is_err());
        // Missing is refused too: `docker run` would create it as root inside
        // the tenant's home, leaving a directory they cannot write to.
        assert!(check_bind_source(&tmp.path().join("absent")).is_err());
    }

    /// The container can only see the application directory, so an entry
    /// anywhere else would name a file that does not exist inside it — and the
    /// alternative, mounting whatever directory the entry sits in, makes the
    /// mount a function of a path the tenant controls.
    #[test]
    fn an_entry_outside_the_application_directory_is_refused() {
        let dir = paths::app_dir("uh_abc12345", "blog");
        assert!(entry_inside(&dir, &user(), &name(), "apps/blog/server.js").is_ok());
        assert!(entry_inside(&dir, &user(), &name(), "apps/blog/src/main.py").is_ok());
        for outside in ["server.js", "apps/other/server.js", "sites/x/app.js"] {
            assert!(
                entry_inside(&dir, &user(), &name(), outside).is_err(),
                "`{outside}` was accepted as an entry"
            );
        }
        // A path that traverses never gets this far, but the newtype is asked
        // again on the way out of the database rather than trusted.
        assert!(entry_inside(&dir, &user(), &name(), "apps/blog/../../etc/passwd").is_err());
    }

    // -----------------------------------------------------------------------
    // "Started" is not "running"
    // -----------------------------------------------------------------------

    /// A container whose application exits immediately is put straight back by
    /// the restart policy, so it reads as `running` to anything that asks a
    /// moment later. The restart counter is the only field that tells a healthy
    /// application from a crash loop.
    #[test]
    fn a_crash_loop_is_not_a_running_application() {
        // Six fields, the shape INSPECT_FORMAT actually asks for: running,
        // status, exit code, restarts, id, and the port label.
        let healthy = parse_state("true\trunning\t0\t0\tabc123\t20001").unwrap();
        assert!(healthy.running && healthy.restarts == 0);

        let looping = parse_state("true\trunning\t1\t4\tabc123\t20001").unwrap();
        assert!(
            looping.running,
            "this is exactly the container that lies about its health"
        );
        assert_eq!(looping.restarts, 4);

        let dead = parse_state("false\texited\t127\t0\tabc123\t20001").unwrap();
        assert!(!dead.running);
        assert_eq!(dead.exit_code, 127);
    }

    /// The inspect format and the parser have to agree; a field added to one and
    /// not the other silently shifts every column.
    #[test]
    fn the_inspect_format_and_its_parser_agree() {
        // The tab count and the parser's field count are the same fact stated
        // twice, and a field added to one and not the other shifts every column
        // silently — which is what this pins.
        assert_eq!(INSPECT_FORMAT.matches('\t').count(), INSPECT_FIELDS - 1);
        assert!(
            parse_state("true\trunning\t0").is_err(),
            "a short answer must be refused rather than read with shifted columns"
        );
        let argv = inspect_argv(plan(AppRuntime::Node, None).container());
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--type" && w[1] == "container"),
            "an image of the same name would answer instead: {argv:?}"
        );
    }

    /// Most application frameworks log to stderr, so a reader that took only
    /// stdout would show an empty log for an application logging perfectly well
    /// — and concatenating the two misorders them.
    #[test]
    fn both_log_streams_come_back_in_one_order() {
        let out = "2026-01-01T00:00:01.000000000Z listening on 20001\n";
        let err = "2026-01-01T00:00:00.000000000Z starting\n  at Object.<anonymous>\n";
        let merged = interleave(out, err, 10);
        assert_eq!(
            merged,
            vec![
                "2026-01-01T00:00:00.000000000Z starting",
                "  at Object.<anonymous>",
                "2026-01-01T00:00:01.000000000Z listening on 20001",
            ],
            "a continuation line must stay with the line it belongs to"
        );
        // The tail flag is what makes the merge sortable at all.
        let argv = logs_argv(plan(AppRuntime::Node, None).container(), 50);
        assert!(argv.iter().any(|a| a == "--timestamps"), "{argv:?}");
    }
}
