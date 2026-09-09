//! `unihelm-web` — the unprivileged half of the panel (spec §5.1).
//!
//! This is the process that faces the internet, and it holds no privileges at
//! all: it cannot restart a service, write a vhost, or read another tenant's
//! files. Everything privileged crosses the Unix socket into `unihelm-agentd`,
//! which checks the request again before acting (spec §12 rules 1 and 4).
//!
//! It also serves the React application, embedded in this binary, so a panel
//! install is one file plus a systemd unit.

use unihelm_core::config::PanelTls;

mod agent;
mod auth;
mod error;
mod plaintext;
mod routes;
mod state;
mod tls;
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
use unihelm_db::{Db, DbError};

use crate::state::AppState;

/// Request bodies larger than this are refused before they are buffered. File
/// uploads get their own chunked path when the file manager lands (spec §11.7).
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// How long to wait for the agent to create and migrate the panel database.
/// Long enough to cover a cold start on a small VPS, short enough to stay
/// well inside systemd's 90s default `TimeoutStartSec`.
const SCHEMA_WAIT: std::time::Duration = std::time::Duration::from_secs(45);

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

    // Read before `config` is moved into the state.
    let config_tls = config.panel.tls;
    let state_dir = config.panel.state_dir.clone();

    // Generated once and reused, so a restart neither logs anybody out nor
    // re-warns the browser.
    let (cert_pem, key_pem) = if config_tls == PanelTls::SelfSigned {
        // rustls refuses to pick a provider for you when more than one could be
        // compiled in, and panics deep inside the accept loop rather than at
        // startup if nobody chose — the panel listened, logged that it was
        // listening, and then died on the first byte of the first handshake.
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .map_err(|_| anyhow::anyhow!("a TLS provider was already installed"))?;
        let addresses = tls::local_addresses();
        let (c, k) = tls::load_or_generate(&state_dir, &addresses)
            .context("preparing the panel's certificate")?;
        (c, k)
    } else {
        (Vec::new(), Vec::new())
    };

    if !config.panel.secure_cookies {
        tracing::warn!(
            "secure_cookies is off — session cookies may be sent over plain HTTP. \
             Development only."
        );
    } else if config_tls == PanelTls::Off && !addr.ip().is_loopback() {
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

    // The watchdog is armed before the database wait, not after. `WatchdogSec=30`
    // in unihelm-web.service is measured from process start, not from READY=1,
    // so a wait with the heartbeat still below it would get this process killed
    // on exactly the machine the wait exists to serve.
    let watchdog = spawn_watchdog();

    // `unihelm-agentd` owns the schema (spec §5.1, §5.5). This half used to
    // migrate on open, which meant both daemons ran sqlx's migrator
    // concurrently — and sqlx has no cross-process lock on SQLite, so whichever
    // process lost reported `table users already exists` and refused to start.
    //
    // In dev there may be no agent at all, so a dev instance is an owner and
    // migrates for itself; the exclusive lock is what makes that safe.
    let db = if args.dev.is_some() {
        Db::open_and_migrate(&config.panel.database).await
    } else {
        // Waiting rather than failing fast: with Restart=always/RestartSec=2 and
        // StartLimitBurst=10, failing fast would put this unit permanently in
        // `failed` about twenty seconds into a slow agent start.
        Db::open_waiting(&config.panel.database, SCHEMA_WAIT).await
    };
    let db = match db {
        Ok(db) => db,
        Err(e @ (DbError::NotInitialised { .. } | DbError::SchemaNotReady { .. })) => {
            anyhow::bail!("{e}\nunihelm-agentd applies migrations; unihelm-web does not.")
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("could not open {}", config.panel.database.display()));
        }
    };

    if !db.has_any_user().await? {
        tracing::warn!(
            "no accounts exist yet — create the first administrator with `unihelm user create-admin`"
        );
    }

    let state = Arc::new(AppState::new(db, config));
    let app = build_router(state.clone());

    let serve_tls = config_tls == PanelTls::SelfSigned;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("could not bind {addr}"))?;
    tracing::info!(%addr, tls = serve_tls, "unihelm-web listening");

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

    // One accept loop for both schemes, so the shutdown path cannot differ
    // between them again — it already had, and in both directions: the TLS
    // branch had no shutdown at all, and the plain branch's had no deadline.
    //
    // A deadline is the point. `with_graceful_shutdown` waits for every
    // connection to end, and /api/events never ends: its sender lives in
    // AppState for the life of the process and a 15s keep-alive comment stops
    // the socket idling out, so one open panel tab held the drain until
    // systemd's 90s stop timeout expired and SIGKILLed us — during an upgrade
    // the operator was watching.
    let handle = axum_server::Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        async move {
            shutdown_signal().await;
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
        }
    });

    let std_listener = listener.into_std().context("detaching the listener")?;
    let service = app.into_make_service_with_connect_info::<SocketAddr>();

    if serve_tls {
        let acceptor = axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem)
            .await
            .context("loading the panel's certificate")?;
        axum_server::from_tcp_rustls(std_listener, acceptor)
            // 8088 is not 443, so a browser given the panel's address with no
            // scheme sends plain HTTP into this TLS listener. Handing that to
            // rustls produced ERR_INVALID_HTTP_RESPONSE, which every operator
            // read as a dead panel rather than a missing `https://`. This peeks
            // the first byte and answers those connections itself.
            .map(|tls| tls.acceptor(plaintext::HttpsRedirect::new()))
            .handle(handle)
            .serve(service)
            .await
            .context("server error")?;
    } else {
        axum_server::from_tcp(std_listener)
            .handle(handle)
            .serve(service)
            .await
            .context("server error")?;
    }

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

/// The panel loads nothing from anywhere else, so the policy can be strict
/// enough to make an injected script useless — with one exception it has to
/// name: the theme script index.html runs before the first paint. Its hash is
/// taken from the bytes being served, so editing the script cannot leave the
/// policy behind.
fn csp_header() -> HeaderValue {
    let hashes = ui::inline_script_hashes();
    let script_src = if hashes.is_empty() {
        "'self'".to_string()
    } else {
        format!("'self' {}", hashes.join(" "))
    };
    let policy = format!(
        "default-src 'self'; script-src {script_src}; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; font-src 'self' data:; connect-src 'self'; \
         frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    );
    HeaderValue::from_str(&policy).expect("the policy is ascii")
}

/// Refuse a request whose `Host` is not one this panel answers on.
///
/// Any `Host` at all used to be served. Today the only thing that reads the
/// header is per-host branding, which falls back to the panel default and
/// treats the value as untrusted, so the immediate damage was small — but "any
/// Host is served" is the standing precondition for the two attacks that follow
/// from it: a cache in front of the panel keyed on a forged host, and any
/// absolute URL built from the header, which is how password-reset links get
/// sent to somebody else's domain. Closing it now costs one comparison; closing
/// it after the first such link exists costs an incident.
///
/// 421 rather than 404, because 421 is the status that means exactly this — the
/// request reached a server that does not answer for that authority — and a 404
/// would tell an operator debugging a proxy that their *path* was wrong.
///
/// # The gaps this deliberately leaves
///
/// **Every IP-literal `Host` is accepted**, not only the addresses this process
/// can see on itself. A fresh install is reached at `https://<address>:8088`
/// before any domain exists, and the panel cannot enumerate the addresses it is
/// actually reached on: behind one-to-one NAT, a floating IP, or an IPv6
/// privacy address, the address the operator types appears on no local
/// interface and in no setting. Refusing an address we could not account for
/// would lock the operator out of their own new server, which is a worse and far
/// more likely failure than the header forgery this narrows. So an attacker can
/// still forge an IP-shaped `Host`; they cannot forge a *domain*, which is what
/// a poisoned cache key and a phishing link both need.
///
/// **Every `Host` is accepted until this panel has a name of its own**, which is
/// 0.7's behaviour, kept for exactly as long as the allowlist would have nothing
/// to say. The first cut of this shipped without that: it refused any DNS name
/// that was not the recorded `panel.domain`, and the refusal is a JSON body on
/// *every* path — the layer sits outside `ui::serve` too — so the login page
/// itself became raw JSON. Two ordinary operators got that. One had pointed DNS
/// at the box and browsed to it before running `unihelm cert panel`, which is
/// the documented order. The other fronts the panel with their own TLS
/// terminator under `tls = "off"` (a supported deployment; Caddy, Traefik and
/// Cloudflare Tunnel all preserve the original `Host`) and so never records a
/// domain at all — for them every page of the panel 421'd on upgrade, and the
/// remedy the message names would have rendered a managed vhost they do not
/// want. A panel with no domain of its own has no domain to poison a cache key
/// or a reset link *for*, so there is nothing to defend yet; the moment
/// `panel.domain` is recorded the allowlist takes effect in full.
async fn host_is_served(
    axum::extract::State(state): axum::extract::State<state::SharedState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    let claimed = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        // HTTP/2 has no `Host` line: the authority arrives as a pseudo-header
        // and hyper puts it in the URI.
        .or_else(|| request.uri().host().map(str::to_string));

    let Some(claimed) = claimed else {
        // Nothing was claimed, so there is nothing to forge — the branding
        // lookup falls back to the panel default and no URL can be built out of
        // a header that is not there.
        return next.run(request).await;
    };

    if host_is_ours(&state, &claimed).await {
        return next.run(request).await;
    }

    tracing::warn!(host = %claimed, "refused a request for a Host this panel does not serve");
    (
        axum::http::StatusCode::MISDIRECTED_REQUEST,
        axum::Json(crate::error::ApiErrorBody {
            code: unihelm_core::ErrorCode::InvalidInput.code(),
            slug: unihelm_core::ErrorCode::InvalidInput.slug(),
            message: format!(
                "this panel does not answer for `{claimed}`. It serves its own domain, any \
                 white-label login host, localhost, and this server's addresses — point the \
                 client (or the proxy in front of it) at one of those. To have it answer for \
                 this name as well, either give the panel the domain with `unihelm cert panel \
                 <domain>`, which also gets it a certificate, or add the name on its own with \
                 `unihelm branding set --login-host <host>`. Both run over the agent socket, \
                 so they work from a shell while this is refusing."
            ),
            field: Some("Host".into()),
            request_id: None,
        }),
    )
        .into_response()
}

/// Is `claimed` a name this panel is served under?
///
/// Read per request rather than snapshotted at startup: `unihelm cert panel`
/// and a reseller's branding both change the answer while the process is
/// running, and a snapshot would mean the operator who has just attached a
/// domain is told the panel does not serve it until somebody restarts it. The
/// cost is a settings lookup — one indexed row — and only for a `Host` that is
/// neither localhost nor an address.
async fn host_is_ours(state: &state::AppState, claimed: &str) -> bool {
    // The same normalisation the branding lookup stores and compares with:
    // lowercased, port stripped, IPv6 brackets kept, trailing dot removed.
    // Comparing a raw header against a stored value would make the allowlist
    // mean "only on the default port", which is precisely the lockout to avoid.
    let host = unihelm_db::branding::normalize_login_host(claimed);
    if host.is_empty() {
        return false;
    }
    if host == "localhost" {
        return true;
    }
    // See the note on the gap above: any address, not just ours.
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host);
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }

    match state
        .db
        .get_setting::<String>(unihelm_db::panel::DOMAIN_KEY)
        .await
    {
        Ok(Some(domain)) if unihelm_db::branding::normalize_login_host(&domain) == host => {
            return true;
        }
        Ok(Some(_)) => {}
        // No domain of record: this panel has no name of its own to be
        // impersonated for, and the name in front of us may well be the only
        // one the operator has. See "the gaps this deliberately leaves" — a
        // refusal here is a login page that renders as JSON, and the remedy it
        // names is reachable only over ssh.
        Ok(None) => {
            tracing::debug!(host = %host,
                "no panel domain is recorded, so this Host is served; `unihelm cert panel <domain>` starts refusing the others");
            return true;
        }
        Err(e) => {
            // Fail open, and say so. A database hiccup must not turn into "the
            // panel serves nothing": the header is not a credential, and the
            // worst an accepted forgery does today is show the default logo.
            tracing::warn!(error = %e, host = %host,
                "could not read the panel domain; allowing this Host rather than refusing every request");
            return true;
        }
    }

    match state.db.branding_for_login_host(&host).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            tracing::warn!(error = %e, host = %host,
                "could not read the branding hosts; allowing this Host rather than refusing every request");
            true
        }
    }
}

fn build_router(state: state::SharedState) -> Router {
    let security_headers = tower::ServiceBuilder::new()
        // The panel loads nothing from anywhere else, so the policy can be
        // strict enough to make an injected script useless.
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            csp_header(),
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
        // Inside the security headers and the tracing span, outside every
        // route and the UI fallback: a refusal still carries the panel's
        // headers, and its warning is logged inside the request's own span, so
        // it comes out with the same request id as everything else on it.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            host_is_served,
        ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;
    use unihelm_db::Db;

    async fn state() -> state::SharedState {
        let db = Db::open_memory().await.expect("in-memory panel database");
        Arc::new(state::AppState::new(db, UnihelmConfig::default()))
    }

    /// One request through the whole router, claiming `host`.
    async fn with_host(state: &state::SharedState, host: &str) -> StatusCode {
        with_host_at(state, host, "/api/branding").await
    }

    /// The same, for a path that is not the API — the UI fallback is behind
    /// this layer too, which is what makes a refusal a login page made of JSON.
    async fn with_host_at(state: &state::SharedState, host: &str, path: &str) -> StatusCode {
        let request = Request::builder()
            .uri(path)
            .header(header::HOST, host)
            .body(Body::empty())
            .expect("a valid test request");
        build_router(state.clone())
            .oneshot(request)
            .await
            .expect("the router answers")
            .status()
    }

    /// Give the panel a name of its own, which is what arms the allowlist.
    async fn with_panel_domain(state: &state::SharedState, domain: &str) {
        state
            .db
            .set_setting(unihelm_db::panel::DOMAIN_KEY, &domain.to_string())
            .await
            .expect("the setting stores");
    }

    /// Issue 58: every `Host` was served. Only branding read the header, so
    /// nothing was directly exploitable yet — but a cache keyed on a forged
    /// host, or the first absolute URL built from it (a password-reset link is
    /// the classic), turns that into somebody else's domain in the panel's own
    /// mail.
    #[tokio::test]
    async fn a_host_this_panel_does_not_serve_is_refused_with_421() {
        let state = state().await;
        // Once the panel has a domain: that is the name a forgery would be
        // aimed at, and the point from which the allowlist has something to
        // defend.
        with_panel_domain(&state, "panel.example.com").await;
        let status = with_host(&state, "attacker.example").await;
        assert_eq!(
            status,
            StatusCode::MISDIRECTED_REQUEST,
            "421 is the status that says `not this host`; 404 would send an \
             operator looking at their paths"
        );
    }

    /// The regression this release shipped and then fixed: a DNS name the panel
    /// has not been told about was refused on *every* path, the UI fallback
    /// included, so the login page rendered as a JSON error. Two ordinary
    /// operators are in that state — one who pointed DNS before running
    /// `unihelm cert panel`, which is the documented order, and one fronting the
    /// panel with their own terminator under `tls = "off"`, who never runs it at
    /// all. A panel with no domain of its own has nothing to be impersonated
    /// for, so until it has one it answers, exactly as 0.7 did.
    #[tokio::test]
    async fn a_dns_name_still_serves_the_panel_while_it_has_no_domain_of_its_own() {
        let state = state().await;
        for reached_by in ["box.example.com", "box.example.com:8088", "panel.acme.test"] {
            assert_ne!(
                with_host_at(&state, reached_by, "/").await,
                StatusCode::MISDIRECTED_REQUEST,
                "`{reached_by}` must still render the login page"
            );
            assert_ne!(
                with_host(&state, reached_by).await,
                StatusCode::MISDIRECTED_REQUEST,
                "`{reached_by}` must still reach the API the page calls"
            );
        }

        // And the moment the panel has a name, the allowlist means what it says.
        with_panel_domain(&state, "panel.example.com").await;
        assert_eq!(
            with_host_at(&state, "box.example.com", "/").await,
            StatusCode::MISDIRECTED_REQUEST
        );
    }

    #[tokio::test]
    async fn the_refusal_names_the_host_that_was_sent() {
        let state = state().await;
        with_panel_domain(&state, "panel.example.com").await;
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/branding")
                    .header(header::HOST, "attacker.example")
                    .body(Body::empty())
                    .expect("a valid test request"),
            )
            .await
            .expect("the router answers");
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("a bounded body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("attacker.example"),
            "an operator debugging a proxy needs to see what was sent: {body}"
        );
    }

    /// The lockout this must never cause: a fresh install has no domain and is
    /// reached at `https://<address>:8088`, and the address it is reached on is
    /// routinely one this process cannot see on itself — behind NAT, a floating
    /// IP, or IPv6 privacy addressing.
    #[tokio::test]
    async fn an_address_host_always_works_because_that_is_how_a_new_server_is_reached() {
        let state = state().await;
        // With a domain recorded, so this is the address rule doing the work
        // and not the "no name of its own yet" one.
        with_panel_domain(&state, "panel.example.com").await;
        for reachable in [
            "127.0.0.1:8088",
            "localhost:8088",
            "LOCALHOST",
            "203.0.113.10",
            "203.0.113.10:8088",
            "[2001:db8::1]:8088",
            "[::1]",
        ] {
            assert_ne!(
                with_host(&state, reachable).await,
                StatusCode::MISDIRECTED_REQUEST,
                "`{reachable}` must keep working"
            );
        }
    }

    /// Attaching a domain must take effect on the next request, not the next
    /// restart — otherwise `unihelm cert panel <domain>` hands the operator a
    /// panel that refuses the domain it has just been given a certificate for.
    #[tokio::test]
    async fn the_panel_domain_and_a_branding_login_host_are_both_served() {
        let state = state().await;
        // An unrelated name, refused only because this panel already answers
        // for one of its own — before that it would be served, and must be.
        with_panel_domain(&state, "first.example.com").await;
        assert_eq!(
            with_host(&state, "panel.example.com").await,
            StatusCode::MISDIRECTED_REQUEST
        );

        state
            .db
            .set_setting(
                unihelm_db::panel::DOMAIN_KEY,
                &"panel.example.com".to_string(),
            )
            .await
            .expect("the setting stores");
        assert_ne!(
            with_host(&state, "Panel.Example.COM:8443").await,
            StatusCode::MISDIRECTED_REQUEST,
            "a hostname is case-insensitive and the port is not part of it"
        );

        state
            .db
            .save_branding(
                unihelm_db::branding::PANEL_DEFAULT,
                unihelm_db::BrandingUpdate {
                    login_host: Some("panel.acme.example".into()),
                    ..Default::default()
                },
            )
            .await
            .expect("branding stores");
        assert_ne!(
            with_host(&state, "panel.acme.example").await,
            StatusCode::MISDIRECTED_REQUEST,
            "a reseller's white-label login host is one this panel answers on"
        );
    }
}
