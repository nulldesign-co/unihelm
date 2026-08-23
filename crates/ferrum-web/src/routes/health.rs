//! Liveness and readiness.

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::state::SharedState;

#[derive(Serialize)]
pub struct Health {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: i64,
}

/// Deliberately minimal: an unauthenticated caller learns that the panel process
/// is up and what version it is, and nothing about the server it manages.
pub async fn healthz(State(state): State<SharedState>) -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.uptime_seconds(),
    })
}
