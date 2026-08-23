//! The web process's connection to the agent.
//!
//! The agent is `Restart=always`, so it *will* disappear from under us — during
//! a self-update, after a crash, or because an operator restarted it. This
//! wrapper makes that a hiccup rather than an outage: a call on a dead connection
//! reconnects once and retries, and a failure to reach the agent is reported as
//! `FER-1500`, never as a 500.

use std::path::PathBuf;
use std::sync::Arc;

use ferrum_core::{AuthContext, FerrumError};
use ferrum_ipc::frame::{EventFrame, ResponseBody};
use ferrum_ipc::{IpcClient, IpcError};
use tokio::sync::{Mutex, broadcast};

/// A lazily-connected, self-healing agent client.
pub struct AgentLink {
    socket: PathBuf,
    client: Mutex<Option<Arc<IpcClient>>>,
    /// Re-broadcast of agent events, so SSE subscribers survive a reconnect.
    events: broadcast::Sender<EventFrame>,
}

impl AgentLink {
    pub fn new(socket: PathBuf) -> Self {
        let (events, _) = broadcast::channel(1024);
        Self {
            socket,
            client: Mutex::new(None),
            events,
        }
    }

    /// Every event the agent has pushed since this call.
    pub fn events(&self) -> broadcast::Receiver<EventFrame> {
        self.events.subscribe()
    }

    /// Call an operation, reconnecting once if the connection has died.
    pub async fn call(
        &self,
        op: &str,
        auth: &AuthContext,
        input: serde_json::Value,
    ) -> Result<ResponseBody, FerrumError> {
        match self.try_call(op, auth, input.clone()).await {
            Ok(body) => Ok(body),
            Err(IpcError::Closed | IpcError::Io(_)) => {
                tracing::info!(op, "agent connection lost; reconnecting");
                self.drop_client().await;
                self.try_call(op, auth, input).await.map_err(Into::into)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Call an operation that must return data.
    pub async fn call_ok(
        &self,
        op: &str,
        auth: &AuthContext,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, FerrumError> {
        match self.call(op, auth, input).await? {
            ResponseBody::Ok { data } => Ok(data),
            ResponseBody::Err { error } => Err(error),
            ResponseBody::Task { task_id } => Ok(serde_json::json!({ "task_id": task_id })),
        }
    }

    /// Is the agent reachable right now? Used by the health endpoint and by
    /// `ferrum doctor`.
    pub async fn is_healthy(&self) -> bool {
        match self.client().await {
            Ok(client) => client.ping().await.is_ok(),
            Err(_) => false,
        }
    }

    async fn try_call(
        &self,
        op: &str,
        auth: &AuthContext,
        input: serde_json::Value,
    ) -> Result<ResponseBody, IpcError> {
        let client = self.client().await?;
        client.call(op, auth, input).await
    }

    /// The live client, connecting if needed.
    async fn client(&self) -> Result<Arc<IpcClient>, IpcError> {
        let mut guard = self.client.lock().await;

        if let Some(existing) = guard.as_ref()
            && !existing.is_closed()
        {
            return Ok(existing.clone());
        }

        let client = Arc::new(IpcClient::connect(&self.socket).await?);
        self.spawn_event_pump(client.clone());
        *guard = Some(client.clone());
        tracing::info!(socket = %self.socket.display(), "connected to the agent");
        Ok(client)
    }

    /// Forward agent events onto our own broadcast, so SSE subscribers do not
    /// have to re-subscribe when the underlying connection is replaced.
    fn spawn_event_pump(&self, client: Arc<IpcClient>) {
        let mut rx = client.events();
        let tx = self.events.clone();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let _ = tx.send(event);
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "event bridge fell behind");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    async fn drop_client(&self) {
        *self.client.lock().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_core::{ErrorCode, Role, TenantScope, UserId};

    fn auth() -> AuthContext {
        AuthContext::from_role(UserId(1), Role::Admin, TenantScope::Global, "req-test")
    }

    #[tokio::test]
    async fn calls_fail_cleanly_when_the_agent_socket_does_not_exist() {
        let link = AgentLink::new(PathBuf::from("/nonexistent/ferrum-agent.sock"));
        let err = link
            .call_ok("sys.ping", &auth(), serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::AgentUnavailable);
        assert_eq!(err.http_status(), 503, "a missing agent is not a 500");
    }

    #[tokio::test]
    async fn health_is_false_rather_than_an_error_when_the_agent_is_down() {
        let link = AgentLink::new(PathBuf::from("/nonexistent/ferrum-agent.sock"));
        assert!(!link.is_healthy().await);
    }
}
