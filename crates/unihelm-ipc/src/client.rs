//! The web/CLI side of the socket.
//!
//! One connection is multiplexed: a reader task fans replies back to the caller
//! that is waiting on that request id, and pushes events onto a broadcast channel
//! the SSE layer subscribes to.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use unihelm_core::{AuthContext, TaskId, UnihelmError};
use uuid::Uuid;

use crate::frame::{
    ClientFrame, ControlFrame, ControlKind, EventFrame, PROTOCOL_VERSION, RequestFrame,
    ResponseBody, ResponseFrame, ServerFrame,
};
use crate::transport::{FrameTransport, StreamTransport, recv_json};
use crate::{IpcError, Result};

/// How long a non-task call may take before the caller gives up. Long work is
/// supposed to come back as a task id well inside this window (spec §10.1).
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Event fan-out depth. A slow SSE consumer lags rather than stalling the agent.
const EVENT_CHANNEL_CAPACITY: usize = 1024;

type Pending = Arc<Mutex<HashMap<Uuid, oneshot::Sender<ResponseFrame>>>>;

pub struct IpcClient {
    outbound: mpsc::Sender<Vec<u8>>,
    pending: Pending,
    events: broadcast::Sender<EventFrame>,
    closed: Arc<AtomicBool>,
    call_timeout: Duration,
}

impl IpcClient {
    /// Connect to a listening agent.
    pub async fn connect(socket_path: impl AsRef<std::path::Path>) -> Result<Self> {
        let stream = UnixStream::connect(socket_path.as_ref()).await?;
        Ok(Self::from_transport(StreamTransport::new(stream)))
    }

    /// Build a client over any transport — used by tests and, later, by a remote
    /// mTLS agent connection.
    pub fn from_transport<T: FrameTransport + 'static>(transport: T) -> Self {
        let (mut writer, mut reader) = transport.split();
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
        let (ev_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));

        // Writer task: the single owner of the write half.
        {
            let closed = closed.clone();
            tokio::spawn(async move {
                while let Some(bytes) = out_rx.recv().await {
                    if let Err(e) = writer.send_frame(&bytes).await {
                        tracing::warn!(error = %e, "ipc write failed, closing client");
                        break;
                    }
                }
                closed.store(true, Ordering::SeqCst);
            });
        }

        // Reader task: routes replies to their caller, events to subscribers.
        {
            let pending = pending.clone();
            let ev_tx = ev_tx.clone();
            let closed = closed.clone();
            tokio::spawn(async move {
                loop {
                    match recv_json::<ServerFrame>(reader.as_mut()).await {
                        Ok(Some(ServerFrame::Response(resp))) => {
                            if let Some(tx) = pending.lock().await.remove(&resp.id) {
                                let _ = tx.send(resp);
                            } else {
                                tracing::debug!(id = %resp.id, "reply for an unknown request id");
                            }
                        }
                        Ok(Some(ServerFrame::Event(ev))) => {
                            // Err just means nobody is subscribed right now.
                            let _ = ev_tx.send(ev);
                        }
                        Ok(None) => {
                            tracing::info!("agent closed the ipc connection");
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "ipc read failed, closing client");
                            break;
                        }
                    }
                }
                closed.store(true, Ordering::SeqCst);
                // Wake everyone still waiting instead of letting them hit the timeout.
                pending.lock().await.clear();
            });
        }

        Self {
            outbound: out_tx,
            pending,
            events: ev_tx,
            closed,
            call_timeout: DEFAULT_CALL_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    /// True once either half of the connection has failed; the caller should
    /// build a fresh client (the agent may have restarted under systemd).
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Invoke an operation and wait for the agent's verdict.
    pub async fn call(
        &self,
        op: &str,
        auth: &AuthContext,
        input: serde_json::Value,
    ) -> Result<ResponseBody> {
        let req = RequestFrame::new(op, auth.clone(), input);
        let id = req.id;
        let resp = self.send_and_wait(id, &ClientFrame::Request(req)).await?;
        if resp.v != PROTOCOL_VERSION {
            return Err(IpcError::UnsupportedVersion(resp.v));
        }
        Ok(resp.body)
    }

    /// Call an operation that is expected to return data, mapping an agent-side
    /// failure into the panel's error type.
    pub async fn call_ok(
        &self,
        op: &str,
        auth: &AuthContext,
        input: serde_json::Value,
    ) -> std::result::Result<serde_json::Value, UnihelmError> {
        match self.call(op, auth, input).await? {
            ResponseBody::Ok { data } => Ok(data),
            ResponseBody::Err { error } => Err(error),
            ResponseBody::Task { task_id } => Ok(serde_json::json!({ "task_id": task_id })),
        }
    }

    /// Liveness probe for the mutual watchdog (spec §5.5).
    pub async fn ping(&self) -> Result<()> {
        let frame = ControlFrame::new(ControlKind::Ping);
        let bytes = serde_json::to_vec(&ClientFrame::Control(frame))
            .map_err(|e| IpcError::Malformed(e.to_string()))?;
        let mut rx = self.events.subscribe();
        self.outbound
            .send(bytes)
            .await
            .map_err(|_| IpcError::Closed)?;
        let deadline = tokio::time::timeout(self.call_timeout, async {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if matches!(ev.kind, crate::frame::EventKind::Pong { .. }) {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Err(IpcError::Closed),
                }
            }
        });
        deadline.await.map_err(|_| IpcError::Timeout)?
    }

    /// Subscribe to a task's log and state events.
    ///
    /// Subscribe *before* you start the task where possible; events emitted
    /// before the subscription exists are only available from `task_logs`.
    pub async fn subscribe_task(&self, task_id: TaskId) -> Result<broadcast::Receiver<EventFrame>> {
        let rx = self.events.subscribe();
        self.send_control(ControlKind::Subscribe { task_id })
            .await?;
        Ok(rx)
    }

    pub async fn unsubscribe_task(&self, task_id: TaskId) -> Result<()> {
        self.send_control(ControlKind::Unsubscribe { task_id })
            .await
    }

    pub async fn cancel_task(&self, task_id: TaskId) -> Result<()> {
        self.send_control(ControlKind::CancelTask { task_id }).await
    }

    /// Push a control frame the caller built itself.
    ///
    /// The web terminal needs this: its frames are a conversation with one PTY
    /// (open, input, resize, close) rather than a request that has a reply, so
    /// wrapping each one in its own method here would be five identical
    /// forwarders. The reply, when there is one, arrives on [`Self::events`]
    /// as a `Terminal*` event.
    pub async fn control(&self, kind: ControlKind) -> Result<()> {
        self.send_control(kind).await
    }

    /// Every event the agent pushes, for the SSE bridge.
    pub fn events(&self) -> broadcast::Receiver<EventFrame> {
        self.events.subscribe()
    }

    async fn send_control(&self, kind: ControlKind) -> Result<()> {
        let bytes = serde_json::to_vec(&ClientFrame::Control(ControlFrame::new(kind)))
            .map_err(|e| IpcError::Malformed(e.to_string()))?;
        self.outbound
            .send(bytes)
            .await
            .map_err(|_| IpcError::Closed)
    }

    async fn send_and_wait(&self, id: Uuid, frame: &ClientFrame) -> Result<ResponseFrame> {
        if self.is_closed() {
            return Err(IpcError::Closed);
        }
        let bytes = serde_json::to_vec(frame).map_err(|e| IpcError::Malformed(e.to_string()))?;

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

        if let Err(e) = self.outbound.send(bytes).await {
            self.pending.lock().await.remove(&id);
            drop(e);
            return Err(IpcError::Closed);
        }

        match tokio::time::timeout(self.call_timeout, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            // The reader task cleared the map: the connection died.
            Ok(Err(_)) => Err(IpcError::Closed),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err(IpcError::Timeout)
            }
        }
    }
}
