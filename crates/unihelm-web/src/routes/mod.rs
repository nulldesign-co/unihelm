//! The REST API (spec §13).
//!
//! Everything the UI can do, it does through these endpoints — there is no
//! private channel between the React app and the server. That is what keeps the
//! API honest: if a feature is missing from the API, it is missing from the
//! product (spec §2.6).

pub mod adminer;
pub mod alerts;
pub mod apps;
pub mod auth;
pub mod backups;
pub mod branding;
pub mod certs;
pub mod cron;
pub mod databases;
pub mod dns;
pub mod events;
pub mod files;
pub mod firewall;
pub mod health;
pub mod imports;
pub mod mail;
pub mod openapi;
pub mod ops;
pub mod panel_tls;
pub mod plans;
pub mod plugins;
pub mod quota;
pub mod runtimes;
pub mod server;
pub mod sites;
pub mod stack;
pub mod tasks;
pub mod terminal;
pub mod waf;
pub mod webhooks;
pub mod wordpress;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

use crate::state::SharedState;

/// Cap on a `PUT /api/branding/settings` body.
///
/// The login background may be 2 MiB (`unihelm_ops::branding::max_bytes`), and
/// the UI offers exactly that number to the operator — but the bytes ride
/// base64 inside the JSON, so 2 MiB of image is ~2.7 MiB of body and the
/// panel-wide 2 MiB default refused the upload the API advertises, with a bare
/// 413 that is not even a panel error envelope. 4 MiB covers the inflation and
/// still sits under `main`'s outer `RequestBodyLimitLayer`.
const BRANDING_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Routes that require a session.
fn protected() -> Router<SharedState> {
    Router::new()
        .route("/api/auth/me", get(auth::me))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/server/overview", get(server::overview))
        .route("/api/server/services", get(server::services))
        .route("/api/runtimes", get(runtimes::list))
        .route("/api/runtimes/install", post(runtimes::install))
        .route("/api/server/docker", get(runtimes::docker))
        .route("/api/sites/discover", get(runtimes::discover))
        .route("/api/stack", get(stack::status))
        .route("/api/stack/install", post(stack::install))
        .route("/api/stack/remove", post(stack::remove))
        .route("/api/sites", get(sites::list).post(sites::create))
        .route(
            "/api/sites/{id}",
            axum::routing::patch(sites::update).delete(sites::delete),
        )
        .route("/api/sites/{id}/drift", get(sites::drift))
        .route("/api/sites/{id}/certificate", post(certs::issue))
        .route("/api/certificates", get(certs::list))
        .route("/api/tasks", get(tasks::list))
        .route("/api/tasks/{id}", get(tasks::detail))
        .route("/api/tasks/{id}/logs", get(tasks::logs))
        .route("/api/events", get(events::stream))
        .route("/api/openapi.json", get(openapi::document))
        .route(
            "/api/server/panel-tls",
            get(panel_tls::status).post(panel_tls::issue),
        )
        // The file manager brings its own routes and its own body limit
        // (file content rides inside JSON there — see files::MAX_BODY_BYTES).
        .merge(files::router())
        .route(
            "/api/databases/adminer",
            get(adminer::adminer_status).post(adminer::adminer_set),
        )
        .route(
            "/api/databases",
            get(databases::list).post(databases::create),
        )
        .route(
            "/api/databases/{id}",
            axum::routing::delete(databases::drop),
        )
        .route("/api/databases/users", post(databases::user_create))
        .route(
            "/api/databases/users/{username}",
            axum::routing::delete(databases::user_drop),
        )
        .route(
            "/api/databases/users/{username}/password",
            post(databases::user_password),
        )
        .route("/api/databases/grants", post(databases::grant))
        .route("/api/server/quota-backend", get(quota::backend))
        .route("/api/plans", get(plans::list).post(plans::create))
        .route(
            "/api/plans/{id}",
            axum::routing::patch(plans::update).delete(plans::delete),
        )
        .route("/api/plans/{id}/assign", post(plans::assign))
        .route("/api/subscriptions", get(plans::subscriptions))
        .route("/api/subscriptions/{id}/suspend", post(plans::suspend))
        .route("/api/subscriptions/{id}/unsuspend", post(plans::unsuspend))
        .route("/api/alerts", get(alerts::events))
        .route(
            "/api/alerts/rules",
            get(alerts::rules_list).post(alerts::rules_set),
        )
        .route(
            "/api/alerts/channels",
            get(alerts::channels_list).post(alerts::channels_set),
        )
        .route(
            "/api/alerts/channels/{id}",
            axum::routing::delete(alerts::channels_delete),
        )
        .route(
            "/api/alerts/channels/{id}/test",
            post(alerts::channels_test),
        )
        .route("/api/apps", get(apps::list).post(apps::create))
        .route("/api/apps/{id}", axum::routing::delete(apps::delete))
        .route("/api/apps/{id}/runtime", post(apps::update))
        .route("/api/apps/{id}/restart", post(apps::restart))
        .route("/api/apps/{id}/logs", get(apps::logs))
        .route("/api/cron", get(cron::list).post(cron::create))
        .route(
            "/api/cron/{id}",
            axum::routing::put(cron::update).delete(cron::delete),
        )
        .route("/api/firewall", get(firewall::rules))
        .route("/api/firewall/ports", post(firewall::port_open))
        .route("/api/firewall/ports/close", post(firewall::port_close))
        .route(
            "/api/firewall/bans",
            get(firewall::bans).post(firewall::ban),
        )
        .route(
            "/api/firewall/bans/{ip}",
            axum::routing::delete(firewall::unban),
        )
        .route(
            "/api/firewall/sentinel",
            get(firewall::sentinel_get).put(firewall::sentinel_set),
        )
        .route("/api/dns/check", get(dns::check))
        .route("/api/dns/provider", axum::routing::put(dns::provider_set))
        .route(
            "/api/sites/{id}/certificate-wildcard",
            post(dns::issue_wildcard),
        )
        .route(
            "/api/backups/repos",
            get(backups::repos_list).post(backups::repos_create),
        )
        .route(
            "/api/backups/repos/{id}",
            axum::routing::delete(backups::repos_delete),
        )
        .route("/api/backups/repos/{id}/snapshots", get(backups::snapshots))
        .route(
            "/api/backups/schedules",
            get(backups::schedules_list).post(backups::schedules_create),
        )
        .route(
            "/api/backups/schedules/{id}",
            axum::routing::delete(backups::schedules_delete),
        )
        .route(
            "/api/backups/runs",
            get(backups::runs_list).post(backups::runs_create),
        )
        .route("/api/backups/restores", post(backups::restores_create))
        .route(
            "/api/wordpress",
            get(wordpress::detect).post(wordpress::install),
        )
        .route("/api/wordpress/{id}/update", post(wordpress::update))
        .route("/api/wordpress/{id}/plugins", get(wordpress::plugins))
        .route(
            "/api/wordpress/{id}/plugins/update",
            post(wordpress::plugins_update),
        )
        .route("/api/wordpress/{id}/cli", post(wordpress::cli))
        .route("/api/imports", get(imports::list).post(imports::create))
        .route("/api/imports/{id}", get(imports::detail))
        .route("/api/imports/{id}/apply", post(imports::apply))
        .route("/api/tasks/{id}/cancel", post(tasks::cancel))
        .route("/api/tasks/{id}/retry", post(tasks::retry))
        // The web terminal (spec §11.16). The ticket is minted by a normal
        // CSRF-protected mutation; the upgrade presents it alongside the
        // session cookie — see routes/terminal.rs for why both are required.
        .route("/api/terminal/sessions", post(terminal::open))
        .route("/api/terminal/ws", get(terminal::ws))
        .route(
            "/api/ssh-keys",
            get(terminal::keys_list).post(terminal::keys_add),
        )
        .route(
            "/api/ssh-keys/{fingerprint}",
            axum::routing::delete(terminal::keys_remove),
        )
        .route("/api/waf", get(waf::status))
        .route("/api/waf/enable", post(waf::enable))
        .route("/api/waf/disable", post(waf::disable))
        .route("/api/waf/rules", axum::routing::put(waf::rules_set))
        .route("/api/server/security-posture", get(waf::security_posture))
        .route("/api/webhooks", get(webhooks::list).post(webhooks::create))
        .route(
            "/api/webhooks/{id}",
            get(webhooks::detail)
                .put(webhooks::update)
                .delete(webhooks::delete),
        )
        .route("/api/webhooks/{id}/test", post(webhooks::test))
        .route("/api/plugins", get(plugins::list).post(plugins::install))
        .route(
            "/api/plugins/{slug}",
            axum::routing::delete(plugins::remove),
        )
        .route("/api/plugins/{slug}/enable", post(plugins::enable))
        .route("/api/plugins/{slug}/disable", post(plugins::disable))
        .route("/api/mail/relay", get(mail::relay_get).put(mail::relay_set))
        .route("/api/mail/relay/test", post(mail::relay_test))
        .route("/api/mail/dns/publish", post(mail::dns_publish))
        // The *authenticated* half of branding. `GET /api/branding` and the
        // asset route are in `public()`: the login page renders before there
        // is a session (spec §11.19). Merged rather than chained so the image
        // bytes get their own body limit — an inner `DefaultBodyLimit` wins
        // over the panel-wide default, the same way `files::router` does.
        .merge(
            Router::new()
                .route(
                    "/api/branding/settings",
                    get(branding::settings_get).put(branding::settings_set),
                )
                .layer(DefaultBodyLimit::max(BRANDING_BODY_BYTES)),
        )
}

/// Routes reachable without a session.
fn public() -> Router<SharedState> {
    Router::new()
        .route("/api/auth/login", post(auth::login))
        // Liveness, for systemd and for a load balancer. Says nothing an
        // unauthenticated caller should not know.
        .route("/healthz", get(health::healthz))
        // Branding, because the login page has to render before anybody has a
        // session (spec §11.19). Read-only, and deliberately narrow: a name, a
        // support URL, a colour and up to three image URLs — no identifiers, no
        // counts, and the same response shape whether or not the `Host` header
        // matched a reseller. See routes/branding.rs.
        .route("/api/branding", get(branding::public_get))
        .route("/api/branding/assets/{kind}", get(branding::asset))
}

pub fn api() -> Router<SharedState> {
    public().merge(protected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tower::ServiceExt as _;
    use unihelm_core::{Email, Role, TenantScope, Username};
    use unihelm_db::Db;
    use unihelm_db::users::NewUser;

    /// `unihelm_ops::branding::max_bytes(AssetKind::LoginBackground)`, which
    /// the UI shows the operator as the allowed size. Duplicated because
    /// `unihelm-ops` is the agent's crate and the panel does not link it.
    const LOGIN_BACKGROUND_MAX: usize = 2 * 1024 * 1024;

    #[tokio::test]
    async fn a_login_background_at_the_size_the_api_advertises_reaches_the_handler() {
        let db = Db::open_memory().await.unwrap();
        let user = db
            .users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Admin,
                email: Email::parse("admin@example.com").unwrap(),
                username: Username::parse("admin").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let issued = db
            .create_session(user.id, None, None, unihelm_db::sessions::DEFAULT_TTL, None)
            .await
            .unwrap();

        let mut config = unihelm_core::UnihelmConfig::default();
        // No agent: a request that got past the body limit fails 503 at the
        // socket, which is what makes "the limit let it through" observable.
        config.agent.socket = std::path::PathBuf::from("/nonexistent/unihelm-agent.sock");
        let state: SharedState = Arc::new(crate::state::AppState::new(db, config));
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let app = api()
            .layer(axum::Extension(ConnectInfo(peer)))
            .with_state(state);

        // Base64 inflates by 4/3, so the largest image the API accepts is a
        // body of roughly 2.7 MiB — over the panel-wide 2 MiB default.
        let b64 = "A".repeat(LOGIN_BACKGROUND_MAX.div_ceil(3) * 4);
        let body = format!(r#"{{"login_background":{{"action":"set","content_b64":"{b64}"}}}}"#);
        let request = Request::builder()
            .method("PUT")
            .uri("/api/branding/settings")
            .header(
                "cookie",
                format!("{}={}", crate::auth::SESSION_COOKIE, issued.token),
            )
            .header(crate::auth::CSRF_HEADER, &issued.csrf)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
