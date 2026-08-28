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
pub mod certs;
pub mod cron;
pub mod databases;
pub mod dns;
pub mod events;
pub mod files;
pub mod health;
pub mod openapi;
pub mod ops;
pub mod panel_tls;
pub mod quota;
pub mod plans;
pub mod server;
pub mod sites;
pub mod stack;
pub mod tasks;
pub mod wordpress;

use axum::Router;
use axum::routing::{get, post};

use crate::state::SharedState;

/// Routes that require a session.
fn protected() -> Router<SharedState> {
    Router::new()
        .route("/api/auth/me", get(auth::me))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/server/overview", get(server::overview))
        .route("/api/server/services", get(server::services))
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
        .route("/api/alerts/channels/{id}/test", post(alerts::channels_test))
        .route("/api/apps", get(apps::list).post(apps::create))
        .route("/api/apps/{id}", axum::routing::delete(apps::delete))
        .route("/api/apps/{id}/restart", post(apps::restart))
        .route("/api/apps/{id}/logs", get(apps::logs))
        .route("/api/cron", get(cron::list).post(cron::create))
        .route(
            "/api/cron/{id}",
            axum::routing::put(cron::update).delete(cron::delete),
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
}

/// Routes reachable without a session.
fn public() -> Router<SharedState> {
    Router::new()
        .route("/api/auth/login", post(auth::login))
        // Liveness, for systemd and for a load balancer. Says nothing an
        // unauthenticated caller should not know.
        .route("/healthz", get(health::healthz))
}

pub fn api() -> Router<SharedState> {
    public().merge(protected())
}
