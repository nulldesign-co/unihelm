//! The REST API (spec §13).
//!
//! Everything the UI can do, it does through these endpoints — there is no
//! private channel between the React app and the server. That is what keeps the
//! API honest: if a feature is missing from the API, it is missing from the
//! product (spec §2.6).

pub mod auth;
pub mod certs;
pub mod events;
pub mod health;
pub mod ops;
pub mod quota;
pub mod server;
pub mod sites;
pub mod stack;
pub mod tasks;

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
        .route("/api/server/quota-backend", get(quota::backend))
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
