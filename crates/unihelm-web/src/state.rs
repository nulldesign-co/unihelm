//! Shared application state.

use std::sync::Arc;
use tokio::sync::Semaphore;

use unihelm_core::config::UnihelmConfig;
use unihelm_db::Db;

use crate::agent::AgentLink;
use crate::auth::PASSWORD_VERIFY_PERMITS;

pub struct AppState {
    pub db: Db,
    pub agent: Arc<AgentLink>,
    pub config: UnihelmConfig,
    pub started_at: time::OffsetDateTime,
    /// How much argon2 the login endpoint may have in flight at once.
    ///
    /// Process-wide on purpose: the cost being bounded is memory and CPU on
    /// this one machine, so the bound belongs to the process rather than to a
    /// request, a session or an account. See [`PASSWORD_VERIFY_PERMITS`] for
    /// the number and what the absence of it cost.
    pub password_verifications: Semaphore,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(db: Db, config: UnihelmConfig) -> Self {
        let agent = Arc::new(AgentLink::new(config.agent.socket.clone()));
        Self {
            db,
            agent,
            config,
            started_at: time::OffsetDateTime::now_utc(),
            password_verifications: Semaphore::new(PASSWORD_VERIFY_PERMITS),
        }
    }

    pub fn uptime_seconds(&self) -> i64 {
        (time::OffsetDateTime::now_utc() - self.started_at)
            .whole_seconds()
            .max(0)
    }
}
