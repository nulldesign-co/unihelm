//! `ferrum-agentd` — the root half of the panel (spec §5.1).
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
mod tasks;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use ferrum_core::config::{FerrumConfig, LogFormat, paths};
use ferrum_core::notify;
use ferrum_db::Db;
use ferrum_distro::Distro;
use ferrum_ipc::peercred::PeerCred;
use ferrum_ipc::peercred::PeerPolicy;
use ferrum_ipc::server::{EventSink, HandlerFactory, IpcServer, RequestHandler};
use ferrum_ops::{OpRegistry, Services};

use crate::handler::{Agent, ConnectionHandler};
use crate::tasks::TaskBus;

#[derive(Parser, Debug)]
#[command(name = "ferrum-agentd", version, about = "Ferrum privileged agent")]
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
        .thread_name("ferrum-agentd")
        .build()
        .context("could not start the tokio runtime")?;

    runtime.block_on(run(args, config))
}

async fn run(args: Args, config: FerrumConfig) -> Result<()> {
    let dev_mode = args.dev.is_some();

    if !dev_mode && !is_root() {
        anyhow::bail!(
            "ferrum-agentd must run as root (it is the privileged half of the panel); \
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

    let db = Db::open(&config.panel.database)
        .await
        .with_context(|| format!("could not open {}", config.panel.database.display()))?;

    // The agent runs as root and creates the database file, but `ferrum-web`
    // owns the session and audit tables and must be able to write them. Hand it
    // over explicitly rather than leaving a root-owned file the panel cannot use.
    if !dev_mode {
        grant_db_access(&config)?;
    }
    tracing::info!(path = %config.panel.database.display(), "panel database ready");

    // Anything that was mid-flight when we died gets a verdict before we accept
    // new work (spec §5.5).
    tasks::reconcile_on_start(&db).await;

    let services = Arc::new(Services::new(distro, db));
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

    let agent = Arc::new(Agent::new(registry, TaskBus::new()));
    let factory = Arc::new(AgentFactory { agent });

    notify::ready();
    notify::status("ready");
    tracing::info!("ferrum-agentd ready");

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

    wait_for_signal().await;
    tracing::info!("shutting down");
    notify::stopping();
    let _ = shutdown_tx.send(true);

    let _ = serving.await;
    watchdog.abort();
    Ok(())
}

/// Make the panel database readable and writable by the unprivileged web user.
///
/// WAL mode means three files, and all three need the same ownership — a
/// root-owned `-wal` beside a group-writable `.db` produces a confusing
/// "attempt to write a readonly database" long after startup.
fn grant_db_access(config: &FerrumConfig) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Some((uid, gid)) = passwd_entry(&config.agent.web_user) else {
        anyhow::bail!(
            "the panel user `{}` does not exist; the installer creates it",
            config.agent.web_user
        );
    };

    let base = &config.panel.database;
    for suffix in ["", "-wal", "-shm"] {
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

fn load_config(args: &Args) -> Result<FerrumConfig> {
    let config = if let Some(dir) = &args.dev {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
        FerrumConfig::for_dev(dir)
    } else {
        match std::fs::read_to_string(&args.config) {
            Ok(text) => FerrumConfig::from_toml(&text)
                .map_err(|e| anyhow::anyhow!("{}: {e}", args.config.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A missing config is not an error: the packaged defaults are the
                // supported configuration, and the file only overrides them.
                FerrumConfig::default()
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
fn build_peer_policy(config: &FerrumConfig, dev_mode: bool) -> Result<PeerPolicy> {
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

fn socket_owner(config: &FerrumConfig, dev_mode: bool) -> Option<(u32, u32)> {
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

fn init_tracing(config: &FerrumConfig) {
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
        tracing::error!(panic = %info, "ferrum-agentd panicked");
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
