//! Shared application state.

use std::sync::Arc;

use unihelm_core::config::UnihelmConfig;
use unihelm_db::Db;

use crate::agent::AgentLink;

pub struct AppState {
    pub db: Db,
    pub agent: Arc<AgentLink>,
    pub config: UnihelmConfig,
    pub started_at: time::OffsetDateTime,
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
        }
    }

    pub fn uptime_seconds(&self) -> i64 {
        (time::OffsetDateTime::now_utc() - self.started_at)
            .whole_seconds()
            .max(0)
    }
}
