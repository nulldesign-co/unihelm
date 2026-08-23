//! The REST API (spec §13).
//!
//! Everything the UI can do, it does through these endpoints — there is no
//! private channel between the React app and the server. That is what keeps the
//! API honest: if a feature is missing from the API, it is missing from the
//! product (spec §2.6).

pub mod auth;
pub mod events;
pub mod health;
pub mod server;
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
        .route("/api/tasks", get(tasks::list))
        .route("/api/tasks/{id}", get(tasks::detail))
        .route("/api/tasks/{id}/logs", get(tasks::logs))
        .route("/api/events", get(events::stream))
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
