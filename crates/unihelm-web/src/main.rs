//! `unihelm-web` — the unprivileged half of the panel (spec §5.1).
//!
//! This is the process that faces the internet, and it holds no privileges at
//! all: it cannot restart a service, write a vhost, or read another tenant's
//! files. Everything privileged crosses the Unix socket into `unihelm-agentd`,
//! which checks the request again before acting (spec §12 rules 1 and 4).
//!
//! It also serves the React application, embedded in this binary, so a panel
//! install is one file plus a systemd unit.

mod agent;
mod auth;
mod error;
mod routes;
mod state;
mod ui;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::http::{HeaderName, HeaderValue, Request, header};
use clap::Parser;
use tower_http::compression::CompressionLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use unihelm_core::config::{LogFormat, UnihelmConfig, paths};
use unihelm_core::notify;
use unihelm_db::Db;

use crate::state::AppState;

/// Request bodies larger than this are refused before they are buffered. File
/// uploads get their own chunked path when the file manager lands (spec §11.7).
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Parser, Debug)]
#[command(name = "unihelm-web", version, about = "Unihelm panel web server")]
struct Args {
    #[arg(long, default_value = paths::CONFIG)]
    config: PathBuf,

    /// Run against a throwaway directory, with human-readable logs.
    #[arg(long)]
    dev: Option<PathBuf>,

    /// Override the listen address from the config.
    #[arg(long)]
    listen: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut config = load_config(&args)?;
    if let Some(listen) = &args.listen {
        listen
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid --listen `{listen}`"))?;
        config.panel.listen = listen.clone();
    }

    init_tracing(&config);
    install_panic_hook();

    if is_root() {
        anyhow::bail!(
            "refusing to run as root: unihelm-web is the unprivileged half of the panel \
             and must run as the `unihelm` user (spec §12 rule 1)"
        );
    }

    let addr: SocketAddr = config.panel.listen.parse().expect("validated at load");

    if !config.panel.secure_cookies {
        tracing::warn!(
            "secure_cookies is off — session cookies may be sent over plain HTTP. \
             Development only."
        );
    } else if !addr.ip().is_loopback() {
        // The cookie will carry `Secure`, so a browser will refuse to send it
        // back over plain http. Without TLS in front, every login appears to
        // succeed and then bounces straight back to the login form.
        tracing::warn!(
            %addr,
            "listening on a non-loopback address: put TLS in front of the panel, or \
             logins will not stick — the session cookie is marked Secure and a browser \
             will not return it over plain HTTP"
        );
    }

    let db = Db::open(&config.panel.database)
        .await
        .with_context(|| format!("could not open {}", config.panel.database.display()))?;

    if !db.has_any_user().await? {
        tracing::warn!(
            "no accounts exist yet — create the first administrator with `unihelm user create-admin`"
        );
    }

    let state = Arc::new(AppState::new(db, config));
    let app = build_router(state.clone());

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("could not bind {addr}"))?;
    tracing::info!(%addr, "unihelm-web listening");

    // Probe the agent once at startup so the log says plainly whether the two
    // halves can see each other.
    if state.agent.is_healthy().await {
        tracing::info!("agent reachable");
    } else {
        tracing::warn!(
            socket = %state.config.agent.socket.display(),
            "agent is not reachable; the panel will serve, but privileged actions will fail"
        );
    }

    notify::ready();
    notify::status(&format!("listening on {addr}"));
    let watchdog = spawn_watchdog();

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")?;

    notify::stopping();
    watchdog.abort();
    Ok(())
}

/// systemd watchdog heartbeat (spec §5.5). A no-op when not run by systemd.
fn spawn_watchdog() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        let Some(interval) = notify::watchdog_interval() else {
            return;
        };
        tracing::info!(?interval, "watchdog heartbeat enabled");
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            notify::watchdog();
        }
    })
}

fn build_router(state: state::SharedState) -> Router {
    let security_headers = tower::ServiceBuilder::new()
        // The panel loads nothing from anywhere else, so the policy can be
        // strict enough to make an injected script useless.
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data:; font-src 'self' data:; connect-src 'self'; \
                 frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("same-origin"),
        ));

    Router::new()
        .merge(routes::api())
        .fallback(ui::serve)
        .layer(security_headers)
        .layer(CompressionLayer::new())
        // The file manager carries file content in its JSON, so it gets its
        // own, larger cap (routes::files::MAX_BODY_BYTES); this outer layer
        // would otherwise win, because outer layers see the body first.
        .layer(RequestBodyLimitLayer::new(routes::files::MAX_BODY_BYTES))
        .route_layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                // One id per request, threaded through the IPC frame, the task
                // record and the audit row (spec §5.3).
                let request_id = uuid::Uuid::new_v4().to_string();
                tracing::info_span!(
                    "http",
                    method = %request.method(),
                    path = %request.uri().path(),
                    request_id = %request_id,
                )
            }),
        )
        .with_state(state)
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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => UnihelmConfig::default(),
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

fn init_tracing(config: &UnihelmConfig) {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.level));

    match config.log.format {
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

/// Log panics. `axum` unwinds one task per request, so a panic here costs one
/// request rather than the process — but it must still be visible.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "unihelm-web panicked");
        default(info);
    }));
}

fn is_root() -> bool {
    // SAFETY: `geteuid` reads process state and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let term = async {
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => tracing::error!(error = %e, "could not install SIGTERM handler"),
        }
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT"),
        _ = term => tracing::info!("received SIGTERM"),
    }
}
