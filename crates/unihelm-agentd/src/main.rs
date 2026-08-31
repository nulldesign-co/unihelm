//! `unihelm-agentd` — the root half of the panel (spec §5.1).
//!
//! This process holds every privilege the panel has, so it is deliberately dull:
//! it listens on one Unix socket, accepts only the panel user, and runs only what
//! is in the operation registry. It speaks no HTTP, serves no files, and has no
//! way to execute a string.
//!
//! It is also the process that must not fall over. Under systemd it is
//! `Restart=always` with a watchdog, all its state is in SQLite, and a restart
//! reconciles whatever was in flight (spec §5.5).

mod handler;
mod scheduler;
mod tasks;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use unihelm_core::config::{LogFormat, UnihelmConfig, paths};
use unihelm_core::notify;
use unihelm_db::Db;
use unihelm_distro::Distro;
use unihelm_ipc::peercred::PeerCred;
use unihelm_ipc::peercred::PeerPolicy;
use unihelm_ipc::server::{EventSink, HandlerFactory, IpcServer, RequestHandler};
use unihelm_ops::{OpRegistry, Services};

use crate::handler::{Agent, ConnectionHandler};
use crate::tasks::TaskBus;

/// How often expired terminal sessions are reaped.
///
/// A minute is well inside the shortest limit that matters (the idle timeout is
/// measured in minutes) and costs one lock of an almost-always-empty map.
const TERMINAL_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Parser, Debug)]
#[command(name = "unihelm-agentd", version, about = "Unihelm privileged agent")]
struct Args {
    /// Path to config.toml.
    #[arg(long, default_value = paths::CONFIG)]
    config: PathBuf,

    /// Run against a throwaway directory instead of the packaged layout, with
    /// human-readable logs and no root requirement.
    #[arg(long)]
    dev: Option<PathBuf>,

    /// Check the configuration and the environment, then exit.
    #[arg(long)]
    check: bool,
}

fn main() -> Result<()> {
    // The file-manager helper re-exec (spec §5.2 rule 3) is dispatched before
    // clap, config, tracing — before *anything*. The helper's argv is fixed by
    // the agent itself, and every line of code that runs before the privilege
    // drop is code that runs as root on behalf of a tenant request.
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--fs-helper")) {
        std::process::exit(fs_helper_main());
    }
    // The WordPress toolkit's helper (spec §11.12) is the same idea for a
    // different payload: WP-CLI loads the site's own plugins and themes, which
    // is tenant-authored PHP, so it must never run as root either. It gets its
    // own entry point rather than an `Exec` arm on the file manager's protocol
    // — that protocol is a closed set of filesystem verbs, and widening it to
    // carry commands would turn the panel's most tightly bounded interface into
    // a general exec channel. What is shared is the part that matters: the
    // re-exec, [`drop_privileges`], and its `setuid(0)`-must-fail proof.
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--wp-helper")) {
        std::process::exit(wp_helper_main());
    }
    // And the web terminal's (spec 11.16). Same shape again, and the same
    // reason it is dispatched here rather than anywhere later: for a tenant
    // session every instruction executed before [`drop_privileges`] returns is
    // an instruction running as root on behalf of a browser.
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--pty-helper")) {
        std::process::exit(pty_helper_main());
    }

    let args = Args::parse();
    let config = load_config(&args)?;
    init_tracing(&config);
    install_panic_hook();

    // A single-threaded-per-core runtime would be enough for the agent's own
    // work, but package installs and metric sweeps are blocking-ish, so the
    // multi-thread runtime keeps one slow task off everyone else's back.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("unihelm-agentd")
        .build()
        .context("could not start the tokio runtime")?;

    runtime.block_on(run(args, config))
}

async fn run(args: Args, config: UnihelmConfig) -> Result<()> {
    let dev_mode = args.dev.is_some();

    // A development instance writes its managed files under the scratch
    // directory instead of /etc and /var, so the whole chain — render, validate,
    // record a revision, roll back — can be exercised without root.
    if let Some(dir) = &args.dev {
        let root = dir.join("root");
        std::fs::create_dir_all(&root)
            .with_context(|| format!("could not create {}", root.display()))?;
        unihelm_config::paths::set_root(&root);
        tracing::info!(root = %root.display(), "managed files are rooted here (dev mode)");
    }

    if !dev_mode && !is_root() {
        anyhow::bail!(
            "unihelm-agentd must run as root (it is the privileged half of the panel); \
             use --dev <dir> for a local, unprivileged instance"
        );
    }

    let distro = match Distro::detect() {
        Ok(d) => {
            tracing::info!(
                distro = %d.info.pretty_name,
                family = d.info.family.as_str(),
                arch = d.info.arch.as_str(),
                pkg = d.pkg.name(),
                fw = d.fw.name(),
                "detected system"
            );
            for problem in d.info.preflight() {
                tracing::warn!(problem, "preflight warning");
            }
            d
        }
        Err(e) if dev_mode => {
            tracing::warn!(error = %e, "running with mock system backends (dev mode)");
            Distro::mock()
        }
        Err(e) => return Err(e).context("this system is not supported"),
    };

    // The agent owns the schema (spec §5.1, §5.5), and is the only production
    // process that migrates. It does so under an exclusive lock, and it does so
    // *before* it binds the socket below — which is what makes the installer's
    // wait for /run/unihelm/agent.sock a wait for "the schema is ready", relied
    // on by `unihelm user create-admin` and by unihelm-web.
    let db = Db::open_and_migrate(&config.panel.database)
        .await
        .with_context(|| format!("could not open {}", config.panel.database.display()))?;

    // The agent runs as root and creates the database file, but `unihelm-web`
    // owns the session and audit tables and must be able to write them. Hand it
    // over explicitly rather than leaving a root-owned file the panel cannot use.
    if !dev_mode {
        grant_db_access(&config)?;
    }
    tracing::info!(path = %config.panel.database.display(), "panel database ready");

    // Anything that was mid-flight when we died gets a verdict before we accept
    // new work (spec §5.5).
    tasks::reconcile_on_start(&db).await;

    let master_key = load_master_key(&args)?;

    // Templates are compiled here, so a broken one is a boot failure rather
    // than a 500 the first time somebody creates a site.
    let services = Arc::new(
        Services::new(distro, db, master_key)
            .context("could not load the configuration templates")?,
    );
    let registry = Arc::new(OpRegistry::new(services));
    tracing::info!(operations = registry.len(), "operation registry loaded");

    let policy = build_peer_policy(&config, dev_mode)?;
    let owner = socket_owner(&config, dev_mode);

    if args.check {
        println!("configuration OK");
        println!("  operations: {}", registry.len());
        println!("  socket:     {}", config.agent.socket.display());
        println!(
            "  peers:      uids {:?} (root allowed: {})",
            policy.allowed_uids, policy.allow_root
        );
        return Ok(());
    }

    let server = IpcServer::bind(&config.agent.socket, owner, policy)
        .with_context(|| format!("could not bind {}", config.agent.socket.display()))?;

    let bus = TaskBus::new();
    let agent = Arc::new(Agent::new(registry.clone(), bus.clone()));
    let terminal_agent = agent.clone();
    let factory = Arc::new(AgentFactory { agent });

    notify::ready();
    notify::status("ready");
    tracing::info!("unihelm-agentd ready");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // Heartbeat, so a wedged agent is restarted rather than left looking alive.
    let watchdog = {
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let Some(interval) = notify::watchdog_interval() else {
                return;
            };
            tracing::info!(?interval, "watchdog heartbeat enabled");
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    _ = ticker.tick() => notify::watchdog(),
                }
            }
        })
    };

    let serving = {
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            server
                .serve(factory, async move {
                    let _ = rx.changed().await;
                })
                .await;
        })
    };

    // The scheduler (spec §10.2). Certificate renewal lives here, so a panel
    // left alone for three months still has working certificates.
    let scheduling = {
        let mut rx = shutdown_rx.clone();
        let scheduler = crate::scheduler::Scheduler::new(registry, bus);
        tokio::spawn(async move {
            scheduler
                .run(async move {
                    let _ = rx.changed().await;
                })
                .await;
        })
    };

    // Terminal sessions expire on a clock, not on a request (spec 11.16): the
    // dangerous case is an abandoned root shell, and an abandoned shell is
    // precisely the one nobody is sending frames about.
    let terminal_sweep = {
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(TERMINAL_SWEEP_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    _ = ticker.tick() => terminal_agent.sweep_terminals().await,
                }
            }
        })
    };

    wait_for_signal().await;
    tracing::info!("shutting down");
    notify::stopping();
    let _ = shutdown_tx.send(true);

    let _ = serving.await;
    let _ = scheduling.await;
    let _ = terminal_sweep.await;
    watchdog.abort();
    Ok(())
}

/// Load the key that seals secrets at rest (spec §12 rule 6).
///
/// In production it must already exist: the installer generates it, and
/// generating a new one here would silently orphan every secret sealed with the
/// old one. A development instance keeps its own inside the scratch directory.
fn load_master_key(args: &Args) -> Result<unihelm_db::MasterKey> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let path = match &args.dev {
        Some(dir) => dir.join("secret.key"),
        None => PathBuf::from(paths::SECRET_KEY),
    };

    if path.exists() {
        return unihelm_db::MasterKey::load(&path)
            .with_context(|| format!("could not read {}", path.display()));
    }

    if args.dev.is_none() {
        anyhow::bail!(
            "{} does not exist. The installer generates it; creating a new one here would \
             orphan every secret already sealed with the old key.",
            path.display()
        );
    }

    let key = unihelm_db::MasterKey::generate();
    let mut file = std::fs::File::create(&path)
        .with_context(|| format!("could not create {}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(key.to_hex().as_bytes())?;
    tracing::info!(path = %path.display(), "generated a development master key");
    Ok(key)
}

/// Make the panel database readable and writable by the unprivileged web user.
///
/// WAL mode means three files, and all three need the same ownership — a
/// root-owned `-wal` beside a group-writable `.db` produces a confusing
/// "attempt to write a readonly database" long after startup.
fn grant_db_access(config: &UnihelmConfig) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Some((uid, gid)) = passwd_entry(&config.agent.web_user) else {
        anyhow::bail!(
            "the panel user `{}` does not exist; the installer creates it",
            config.agent.web_user
        );
    };

    let base = &config.panel.database;
    // The schema lock holds no data, but handing it over with the rest means the
    // web process owns it outright after the first agent start, rather than
    // depending on a root-created file happening to be readable.
    for suffix in ["", "-wal", "-shm", unihelm_db::migrate_lock::LOCK_SUFFIX] {
        let path = if suffix.is_empty() {
            base.clone()
        } else {
            let mut name = base.as_os_str().to_os_string();
            name.push(suffix);
            PathBuf::from(name)
        };
        if !path.exists() {
            continue;
        }
        chown(&path, uid, gid).with_context(|| format!("could not chown {}", path.display()))?;
        // Owner and group only: the database holds password hashes.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .with_context(|| format!("could not chmod {}", path.display()))?;
    }
    Ok(())
}

fn chown(path: &std::path::Path, uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let c_path =
        std::ffi::CString::new(path.as_os_str().as_bytes()).context("path contains a NUL byte")?;
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call.
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Gives every connection its own handler, with its own set of watched tasks.
struct AgentFactory {
    agent: Arc<Agent>,
}

#[async_trait]
impl HandlerFactory for AgentFactory {
    async fn accept(&self, peer: PeerCred, events: EventSink) -> Arc<dyn RequestHandler> {
        tracing::debug!(uid = peer.uid, pid = ?peer.pid, "ipc client connected");
        let handler = Arc::new(ConnectionHandler::new(self.agent.clone()));
        handler.spawn_event_forwarder(events);
        handler
    }
}

fn load_config(args: &Args) -> Result<UnihelmConfig> {
    let config = if let Some(dir) = &args.dev {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
        UnihelmConfig::for_dev(dir)
    } else {
        match std::fs::read_to_string(&args.config) {
            Ok(text) => UnihelmConfig::from_toml(&text)
                .map_err(|e| anyhow::anyhow!("{}: {e}", args.config.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A missing config is not an error: the packaged defaults are the
                // supported configuration, and the file only overrides them.
                UnihelmConfig::default()
            }
            Err(e) => {
                return Err(e).with_context(|| format!("could not read {}", args.config.display()));
            }
        }
    };
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
    Ok(config)
}

/// Which uids may talk to the socket (spec §12 rule 1).
fn build_peer_policy(config: &UnihelmConfig, dev_mode: bool) -> Result<PeerPolicy> {
    if dev_mode {
        return Ok(PeerPolicy::same_user_only());
    }
    let uid = lookup_uid(&config.agent.web_user).with_context(|| {
        format!(
            "the panel user `{}` does not exist; the installer creates it",
            config.agent.web_user
        )
    })?;
    Ok(PeerPolicy::new(vec![uid]))
}

fn socket_owner(config: &UnihelmConfig, dev_mode: bool) -> Option<(u32, u32)> {
    if dev_mode {
        return None;
    }
    let uid = lookup_uid(&config.agent.web_user)?;
    let gid = lookup_gid(&config.agent.web_user).unwrap_or(uid);
    Some((uid, gid))
}

fn lookup_uid(username: &str) -> Option<u32> {
    passwd_entry(username).map(|(uid, _)| uid)
}

fn lookup_gid(username: &str) -> Option<u32> {
    passwd_entry(username).map(|(_, gid)| gid)
}

/// Resolve an account through `getpwnam`, so NSS sources (LDAP, sssd) work the
/// same way they do for every other program on the box.
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

fn is_root() -> bool {
    // SAFETY: `geteuid` reads process state and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

// ---------------------------------------------------------------------------
// --fs-helper: the privilege-dropping child (spec §5.2 rule 3, §11.7)
// ---------------------------------------------------------------------------

/// Entry point for `unihelm-agentd --fs-helper --uid N --gid N --home PATH`.
///
/// The contract is brutal on purpose: parse three arguments, drop to the
/// tenant, and only then hand control to `unihelm_ops::fsops::helper::run()`,
/// which reads the actual request from stdin. **Nothing is dispatched before
/// the drop succeeds** — a request never gets to run a single filesystem call
/// as root. Failures are written to stderr and reported by exit code; the
/// parent treats a non-zero exit as fatal regardless of anything on stdout.
fn fs_helper_main() -> i32 {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(2).collect();
    let parsed = match parse_fs_helper_args(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("fs-helper: {msg}");
            return 2;
        }
    };
    if let Err(msg) = drop_privileges(parsed.uid, parsed.gid) {
        eprintln!("fs-helper: {msg}");
        return 3;
    }
    unihelm_ops::fsops::helper::run()
}

#[derive(Debug)]
struct FsHelperArgs {
    uid: u32,
    gid: u32,
    /// Parsed and validated for shape, but the operative home is the one in
    /// the stdin request — the argv copy exists so `ps` shows whose helper
    /// this is when one ever hangs.
    #[allow(dead_code)]
    home: PathBuf,
}

/// Parse `--uid N --gid N --home PATH`, all three required.
///
/// uid and gid 0 are refused here *and* re-checked in [`drop_privileges`]:
/// "drop to root" is not a drop, and an agent bug that computed uid 0 must
/// die loudly, not run a tenant's request with full privilege.
fn parse_fs_helper_args(args: &[std::ffi::OsString]) -> std::result::Result<FsHelperArgs, String> {
    let mut uid: Option<u32> = None;
    let mut gid: Option<u32> = None;
    let mut home: Option<PathBuf> = None;

    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--uid") => {
                uid = Some(
                    value
                        .to_str()
                        .and_then(|v| v.parse().ok())
                        .ok_or("--uid must be an integer")?,
                );
            }
            Some("--gid") => {
                gid = Some(
                    value
                        .to_str()
                        .and_then(|v| v.parse().ok())
                        .ok_or("--gid must be an integer")?,
                );
            }
            Some("--home") => home = Some(PathBuf::from(value)),
            other => {
                return Err(format!(
                    "unexpected argument `{}`",
                    other.unwrap_or("<non-utf8>")
                ));
            }
        }
    }

    let uid = uid.ok_or("--uid is required")?;
    let gid = gid.ok_or("--gid is required")?;
    let home = home.ok_or("--home is required")?;
    if uid == 0 || gid == 0 {
        return Err("refusing to run as uid/gid 0: that is not a privilege drop".into());
    }
    if !home.is_absolute() {
        return Err("--home must be an absolute path".into());
    }
    Ok(FsHelperArgs { uid, gid, home })
}

// ---------------------------------------------------------------------------
// --wp-helper: WP-CLI as the tenant (spec §11.12, §5.2 rule 3)
// ---------------------------------------------------------------------------

/// Entry point for
/// `unihelm-agentd --wp-helper --uid N --gid N --home PATH --dir PATH -- <wp argv…>`.
///
/// Identical in shape to [`fs_helper_main`], and identical in the part that
/// matters: parse, drop, *then* work. `unihelm_ops::wordpress::helper::run` does
/// its own re-check of the argument vector — after the drop, because that is
/// where the privilege boundary is — and never executes anything but the
/// pinned WP-CLI phar through the PHP binary resolved from
/// `unihelm_distro`'s trusted directories. There is deliberately no way to name
/// a program on this command line.
fn wp_helper_main() -> i32 {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(2).collect();
    let parsed = match parse_wp_helper_args(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("wp-helper: {msg}");
            return 2;
        }
    };
    if let Err(msg) = drop_privileges(parsed.uid, parsed.gid) {
        eprintln!("wp-helper: {msg}");
        return 3;
    }
    unihelm_ops::wordpress::helper::run(&parsed.home, &parsed.dir, &parsed.wp_args)
}

#[derive(Debug)]
struct WpHelperArgs {
    uid: u32,
    gid: u32,
    /// The tenant home, which becomes `$HOME` for WP-CLI's cache and config.
    home: PathBuf,
    /// The installation directory. Also carried inside `wp_args` as
    /// `--path=<dir>`; the helper refuses to run if the two disagree.
    dir: PathBuf,
    /// Everything after `--`: the WP-CLI argument vector.
    wp_args: Vec<std::ffi::OsString>,
}

/// Parse `--uid N --gid N --home PATH --dir PATH -- <wp argv…>`.
///
/// Everything after the first bare `--` is passed through untouched: it is
/// WP-CLI's, not ours, and re-parsing it here would only create a second
/// opinion about what an argument means. What is *not* passed through is a
/// program name — there is no flag for one, so this helper can only ever start
/// the pinned phar.
fn parse_wp_helper_args(args: &[std::ffi::OsString]) -> std::result::Result<WpHelperArgs, String> {
    let mut uid: Option<u32> = None;
    let mut gid: Option<u32> = None;
    let mut home: Option<PathBuf> = None;
    let mut dir: Option<PathBuf> = None;
    let mut wp_args: Vec<std::ffi::OsString> = Vec::new();

    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        if flag.to_str() == Some("--") {
            wp_args.extend(iter.cloned());
            break;
        }
        let value = iter
            .next()
            .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--uid") => {
                uid = Some(
                    value
                        .to_str()
                        .and_then(|v| v.parse().ok())
                        .ok_or("--uid must be an integer")?,
                );
            }
            Some("--gid") => {
                gid = Some(
                    value
                        .to_str()
                        .and_then(|v| v.parse().ok())
                        .ok_or("--gid must be an integer")?,
                );
            }
            Some("--home") => home = Some(PathBuf::from(value)),
            Some("--dir") => dir = Some(PathBuf::from(value)),
            other => {
                return Err(format!(
                    "unexpected argument `{}`",
                    other.unwrap_or("<non-utf8>")
                ));
            }
        }
    }

    let uid = uid.ok_or("--uid is required")?;
    let gid = gid.ok_or("--gid is required")?;
    let home = home.ok_or("--home is required")?;
    let dir = dir.ok_or("--dir is required")?;
    if uid == 0 || gid == 0 {
        return Err("refusing to run as uid/gid 0: that is not a privilege drop".into());
    }
    if !home.is_absolute() || !dir.is_absolute() {
        return Err("--home and --dir must be absolute paths".into());
    }
    // The directory the tenant's WordPress lives in is inside their home by
    // construction (`wordpress::target_for_site` refuses anything else). Saying
    // so again here means a malformed pair cannot even reach the phar.
    if !dir.starts_with(&home) {
        return Err("--dir must be inside --home".into());
    }
    if wp_args.is_empty() {
        return Err("no WP-CLI arguments were given after `--`".into());
    }
    Ok(WpHelperArgs {
        uid,
        gid,
        home,
        dir,
        wp_args,
    })
}

// ---------------------------------------------------------------------------
// --pty-helper: the web terminal's shell (spec 11.16, 5.2 rule 3)
// ---------------------------------------------------------------------------

/// Entry point for
/// `unihelm-agentd --pty-helper (--root | --uid N --gid N) --home PATH --shell PATH`.
///
/// The standard descriptors are already the pty slave when this runs — the
/// parent set them up and `pre_exec` made the slave this process's controlling
/// terminal — so all that is left is to become the right account and exec the
/// shell.
///
/// `--root` is the one entry point in this binary that deliberately does *not*
/// drop privilege, because an admin's web terminal is a root shell by
/// definition (spec 11.16). Everything that decides whether a caller may ask
/// for it lives in `unihelm_ops::terminal::authorize`, which has no branch a
/// customer can reach; this flag only carries that decision across the exec.
/// It is refused outright when the agent is not root, so a `--dev` instance
/// cannot quietly hand out a "root" shell that is really the developer's own
/// account.
fn pty_helper_main() -> i32 {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(2).collect();
    let parsed = match parse_pty_helper_args(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("pty-helper: {msg}");
            return 2;
        }
    };

    match parsed.account {
        PtyAccount::Root => {
            if !is_root() {
                eprintln!("pty-helper: a root terminal was requested but the agent is not root");
                return 3;
            }
        }
        PtyAccount::Tenant { uid, gid } => {
            if let Err(msg) = drop_privileges(uid, gid) {
                eprintln!("pty-helper: {msg}");
                return 3;
            }
        }
    }

    unihelm_ops::terminal::helper::run(&parsed.home, &parsed.shell)
}

#[derive(Debug, PartialEq, Eq)]
enum PtyAccount {
    Root,
    Tenant { uid: u32, gid: u32 },
}

#[derive(Debug)]
struct PtyHelperArgs {
    account: PtyAccount,
    home: PathBuf,
    /// Re-checked against `unihelm_ops::terminal`'s allowlist after the drop —
    /// this side of the trust boundary is the side that counts.
    shell: PathBuf,
}

/// Parse the helper's argv.
///
/// `--root` and `--uid`/`--gid` are mutually exclusive, and asking for both is a
/// refusal rather than a precedence rule: a command line that says two
/// different things about which account to run as is one nobody should be
/// guessing the meaning of.
fn parse_pty_helper_args(
    args: &[std::ffi::OsString],
) -> std::result::Result<PtyHelperArgs, String> {
    let mut root = false;
    let mut uid: Option<u32> = None;
    let mut gid: Option<u32> = None;
    let mut home: Option<PathBuf> = None;
    let mut shell: Option<PathBuf> = None;

    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        if flag.to_str() == Some("--root") {
            root = true;
            continue;
        }
        let value = iter
            .next()
            .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--uid") => {
                uid = Some(
                    value
                        .to_str()
                        .and_then(|v| v.parse().ok())
                        .ok_or("--uid must be an integer")?,
                );
            }
            Some("--gid") => {
                gid = Some(
                    value
                        .to_str()
                        .and_then(|v| v.parse().ok())
                        .ok_or("--gid must be an integer")?,
                );
            }
            Some("--home") => home = Some(PathBuf::from(value)),
            Some("--shell") => shell = Some(PathBuf::from(value)),
            other => {
                return Err(format!(
                    "unexpected argument `{}`",
                    other.unwrap_or("<non-utf8>")
                ));
            }
        }
    }

    let account = match (root, uid, gid) {
        (true, None, None) => PtyAccount::Root,
        (true, _, _) => {
            return Err("--root and --uid/--gid say different things; refusing to guess".into());
        }
        (false, Some(uid), Some(gid)) => {
            if uid == 0 || gid == 0 {
                return Err("refusing to run as uid/gid 0 without --root".into());
            }
            PtyAccount::Tenant { uid, gid }
        }
        (false, _, _) => return Err("either --root or both --uid and --gid are required".into()),
    };

    let home = home.ok_or("--home is required")?;
    let shell = shell.ok_or("--shell is required")?;
    if !home.is_absolute() || !shell.is_absolute() {
        return Err("--home and --shell must be absolute paths".into());
    }
    Ok(PtyHelperArgs {
        account,
        home,
        shell,
    })
}

/// Become the tenant, irreversibly, or die.
///
/// Order matters and is fixed: `setgroups` and `setgid` while still root
/// (both are root-only calls), then `setuid` last — the call that burns the
/// bridge. Afterwards the drop is *proven*, not assumed: `setuid(0)` must
/// fail. If it succeeds, the saved-uid was left behind (the classic
/// setuid-ordering bug) and the process is still secretly root — that is not
/// an error to report, it is a state to abort from.
fn drop_privileges(uid: u32, gid: u32) -> std::result::Result<(), String> {
    if uid == 0 || gid == 0 {
        return Err("refusing to run as uid/gid 0".into());
    }

    // SAFETY: plain libc syscalls on integers; every result is checked.
    unsafe {
        if libc::setgroups(1, &gid) != 0 {
            return Err(format!(
                "setgroups failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::setgid(gid) != 0 {
            return Err(format!(
                "setgid({gid}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::setuid(uid) != 0 {
            return Err(format!(
                "setuid({uid}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // The proof. On a correct drop the kernel refuses to give root back.
        if libc::setuid(0) == 0 {
            eprintln!("fs-helper: root could be re-acquired after the drop; aborting");
            std::process::abort();
        }
        if libc::geteuid() != uid || libc::getegid() != gid {
            return Err("the privilege drop did not land on the expected ids".into());
        }
    }
    Ok(())
}

fn init_tracing(config: &UnihelmConfig) {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.level));

    match config.log.format {
        // journald reads stderr; JSON there means structured logs for free.
        LogFormat::Json => {
            fmt()
                .json()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .init();
        }
        LogFormat::Text => {
            fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .init();
        }
    }
}

/// Log panics before they take the process down.
///
/// With `Restart=always` a panic is survivable, but a restart with no explanation
/// in the journal is the thing that makes a panel feel haunted.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "unihelm-agentd panicked");
        default(info);
    }));
}

async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "could not install SIGTERM handler");
            return;
        }
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT"),
        _ = term.recv() => tracing::info!("received SIGTERM"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<std::ffi::OsString> {
        parts.iter().map(std::ffi::OsString::from).collect()
    }

    // `drop_privileges` itself needs root to exercise; what a test *can* prove
    // is that the argument boundary never hands it a root target or a
    // half-specified one. The drop's own proof — setuid(0) failing afterwards
    // — runs on every real invocation, in production, every time.

    #[test]
    fn a_pty_helper_command_line_that_says_two_things_about_the_account_is_refused() {
        // `--root` plus `--uid` is a command line asking to run as two
        // different accounts. Picking one would mean a bug on the agent side
        // silently deciding between "the tenant" and "root".
        let err = parse_pty_helper_args(&argv(&[
            "--root",
            "--uid",
            "1001",
            "--gid",
            "1001",
            "--home",
            "/root",
            "--shell",
            "/bin/bash",
        ]))
        .unwrap_err();
        assert!(err.contains("refusing to guess"), "{err}");
    }

    #[test]
    fn a_pty_helper_tenant_can_never_be_uid_zero() {
        // "Drop to root" is not a drop. Refused at the boundary as well as
        // inside `drop_privileges`, because this is the argv an agent bug
        // would have produced.
        for args in [
            argv(&[
                "--uid",
                "0",
                "--gid",
                "0",
                "--home",
                "/root",
                "--shell",
                "/bin/bash",
            ]),
            argv(&[
                "--uid",
                "0",
                "--gid",
                "1001",
                "--home",
                "/home/x",
                "--shell",
                "/bin/bash",
            ]),
            argv(&[
                "--uid",
                "1001",
                "--gid",
                "0",
                "--home",
                "/home/x",
                "--shell",
                "/bin/bash",
            ]),
        ] {
            let err = parse_pty_helper_args(&args).unwrap_err();
            assert!(err.contains("uid/gid 0"), "{err}");
        }
    }

    #[test]
    fn a_pty_helper_needs_a_complete_and_absolute_command_line() {
        // A half-specified account, a relative home, or a relative shell all
        // mean the caller is not the agent — refuse rather than improvise.
        for args in [
            argv(&["--home", "/root", "--shell", "/bin/bash"]),
            argv(&["--uid", "1001", "--home", "/home/x", "--shell", "/bin/bash"]),
            argv(&["--root", "--shell", "/bin/bash"]),
            argv(&["--root", "--home", "/root"]),
            argv(&["--root", "--home", "root", "--shell", "/bin/bash"]),
            argv(&["--root", "--home", "/root", "--shell", "bash"]),
            argv(&[
                "--root",
                "--home",
                "/root",
                "--shell",
                "/bin/bash",
                "--sneaky",
                "x",
            ]),
        ] {
            assert!(parse_pty_helper_args(&args).is_err(), "accepted {args:?}");
        }

        let ok = parse_pty_helper_args(&argv(&[
            "--uid",
            "5001",
            "--gid",
            "5001",
            "--home",
            "/home/uh_ab12",
            "--shell",
            "/bin/bash",
        ]))
        .unwrap();
        assert_eq!(
            ok.account,
            PtyAccount::Tenant {
                uid: 5001,
                gid: 5001
            }
        );
        assert_eq!(ok.shell, PathBuf::from("/bin/bash"));

        let root = parse_pty_helper_args(&argv(&[
            "--root",
            "--home",
            "/root",
            "--shell",
            "/bin/bash",
        ]))
        .unwrap();
        assert_eq!(root.account, PtyAccount::Root);
    }

    #[test]
    fn helper_args_parse_when_complete() {
        let parsed = parse_fs_helper_args(&argv(&[
            "--uid",
            "1001",
            "--gid",
            "1001",
            "--home",
            "/home/uh_ab12",
        ]))
        .unwrap();
        assert_eq!(parsed.uid, 1001);
        assert_eq!(parsed.gid, 1001);
        assert_eq!(parsed.home, PathBuf::from("/home/uh_ab12"));
    }

    #[test]
    fn a_root_uid_or_gid_is_refused_before_any_drop_is_attempted() {
        for (uid, gid) in [("0", "1001"), ("1001", "0"), ("0", "0")] {
            let err =
                parse_fs_helper_args(&argv(&["--uid", uid, "--gid", gid, "--home", "/home/x"]))
                    .unwrap_err();
            assert!(err.contains("not a privilege drop"), "{uid}/{gid}: {err}");
        }
    }

    #[test]
    fn missing_or_malformed_helper_args_are_refused() {
        for args in [
            &["--uid", "1001", "--gid", "1001"][..], // no home
            &["--uid", "1001", "--home", "/h"][..],  // no gid
            &["--gid", "1001", "--home", "/h"][..],  // no uid
            &["--uid", "abc", "--gid", "1", "--home", "/h"][..],
            &["--uid", "-4", "--gid", "1", "--home", "/h"][..],
            &["--uid", "1001", "--gid", "1001", "--home", "relative/home"][..],
            &[
                "--uid", "1001", "--gid", "1001", "--home", "/h", "--extra", "x",
            ][..],
            &["--uid"][..],
        ] {
            assert!(parse_fs_helper_args(&argv(args)).is_err(), "{args:?}");
        }
    }

    #[test]
    fn drop_privileges_refuses_root_targets_outright() {
        assert!(drop_privileges(0, 1001).is_err());
        assert!(drop_privileges(1001, 0).is_err());
    }

    // --- the WP-CLI helper's argument boundary -----------------------------

    #[test]
    fn wp_helper_args_parse_and_pass_the_wp_argv_through_untouched() {
        let parsed = parse_wp_helper_args(&argv(&[
            "--uid",
            "1001",
            "--gid",
            "1001",
            "--home",
            "/home/uh_ab12",
            "--dir",
            "/home/uh_ab12/sites/example.com/public",
            "--",
            "--path=/home/uh_ab12/sites/example.com/public",
            "core",
            "version",
        ]))
        .unwrap();
        assert_eq!(parsed.uid, 1001);
        assert_eq!(
            parsed.dir,
            PathBuf::from("/home/uh_ab12/sites/example.com/public")
        );
        assert_eq!(
            parsed.wp_args,
            argv(&[
                "--path=/home/uh_ab12/sites/example.com/public",
                "core",
                "version",
            ])
        );
    }

    /// Everything after `--` belongs to WP-CLI, including things that look
    /// like our own flags. Re-parsing them here would be a second opinion
    /// about what an argument means, which is how flag-injection bugs happen.
    #[test]
    fn arguments_after_the_separator_are_never_reinterpreted_as_helper_flags() {
        let parsed = parse_wp_helper_args(&argv(&[
            "--uid",
            "1001",
            "--gid",
            "1001",
            "--home",
            "/home/uh_x",
            "--dir",
            "/home/uh_x/sites/d/public",
            "--",
            "--path=/home/uh_x/sites/d/public",
            "option",
            "update",
            "--uid",
            "--home",
        ]))
        .unwrap();
        assert_eq!(parsed.uid, 1001, "the trailing --uid is WP-CLI's, not ours");
        assert_eq!(parsed.home, PathBuf::from("/home/uh_x"));
        assert!(parsed.wp_args.contains(&std::ffi::OsString::from("--uid")));
    }

    /// The same root refusal as the file helper, for the same reason: WP-CLI
    /// loads tenant-authored PHP, so "drop to root" is the one outcome that
    /// must never be reachable.
    #[test]
    fn the_wp_helper_refuses_a_root_target_or_an_escaping_directory() {
        let base = |uid: &str, gid: &str, home: &str, dir: &str| {
            argv(&[
                "--uid", uid, "--gid", gid, "--home", home, "--dir", dir, "--", "x",
            ])
        };
        for (uid, gid) in [("0", "1001"), ("1001", "0")] {
            let err = parse_wp_helper_args(&base(uid, gid, "/home/x", "/home/x/s")).unwrap_err();
            assert!(err.contains("not a privilege drop"), "{err}");
        }

        // A directory outside the home would mean the privilege drop bought
        // nothing: the tenant's uid has no particular rights there.
        let err = parse_wp_helper_args(&base("1001", "1001", "/home/x", "/etc")).unwrap_err();
        assert!(err.contains("inside --home"), "{err}");

        // Relative paths, and a missing argument vector.
        assert!(parse_wp_helper_args(&base("1001", "1001", "home/x", "home/x/s")).is_err());
        assert!(
            parse_wp_helper_args(&argv(&[
                "--uid",
                "1001",
                "--gid",
                "1001",
                "--home",
                "/home/x",
                "--dir",
                "/home/x/s",
            ]))
            .is_err(),
            "an empty WP-CLI argument vector must be refused"
        );
    }

    #[test]
    fn missing_or_malformed_wp_helper_args_are_refused() {
        for args in [
            &["--uid", "1001", "--gid", "1001", "--home", "/h", "--", "x"][..], // no dir
            &["--uid", "1001", "--gid", "1001", "--dir", "/h/s", "--", "x"][..], // no home
            &["--gid", "1001", "--home", "/h", "--dir", "/h/s", "--", "x"][..], // no uid
            &[
                "--uid", "x", "--gid", "1", "--home", "/h", "--dir", "/h/s", "--", "x",
            ][..],
            &[
                "--uid", "1", "--gid", "1", "--home", "/h", "--dir", "/h/s", "--bad", "1",
            ][..],
        ] {
            assert!(parse_wp_helper_args(&argv(args)).is_err(), "{args:?}");
        }
    }
}
