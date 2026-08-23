//! Turning IPC frames into operations (spec §5.2, §10.1).
//!
//! Everything privileged funnels through here, and the funnel is narrow on
//! purpose: look up the name in the registry, let the registry re-verify the
//! caller, then either answer inline or hand the work to a task.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use ferrum_core::{ErrorCode, FerrumError, TaskId};
use ferrum_db::tasks::NewTask;
use ferrum_ipc::frame::{
    ControlFrame, ControlKind, EventFrame, EventKind, RequestFrame, ResponseBody,
};
use ferrum_ipc::peercred::PeerCred;
use ferrum_ipc::server::{EventSink, RequestHandler};
use ferrum_ops::{Execution, OpRegistry};
use tokio::sync::Mutex;

use crate::tasks::{TaskBus, spawn_task};

/// Shared agent state.
pub struct Agent {
    pub registry: Arc<OpRegistry>,
    pub bus: TaskBus,
}

impl Agent {
    pub fn new(registry: Arc<OpRegistry>, bus: TaskBus) -> Self {
        Self { registry, bus }
    }
}

/// Per-connection handler.
///
/// Each connection tracks which tasks it wants events for. A connection is
/// automatically interested in the tasks it started, so the common case needs no
/// explicit subscription.
pub struct ConnectionHandler {
    agent: Arc<Agent>,
    interests: Mutex<HashSet<TaskId>>,
}

impl ConnectionHandler {
    pub fn new(agent: Arc<Agent>) -> Self {
        Self {
            agent,
            interests: Mutex::new(HashSet::new()),
        }
    }

    /// Forward bus events for tasks this connection cares about.
    pub fn spawn_event_forwarder(self: &Arc<Self>, sink: EventSink) {
        let this = self.clone();
        let mut rx = this.agent.bus.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let Some(task_id) = event_task_id(&event) else {
                            continue;
                        };
                        if this.interests.lock().await.contains(&task_id) && !sink.emit(event).await
                        {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            skipped,
                            "event consumer fell behind; some log lines were dropped from the live stream (they are still in task_logs)"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
}

fn event_task_id(event: &EventFrame) -> Option<TaskId> {
    match &event.kind {
        EventKind::TaskLog { task_id, .. } | EventKind::TaskState { task_id, .. } => Some(*task_id),
        EventKind::Pong { .. } => None,
    }
}

#[async_trait]
impl RequestHandler for ConnectionHandler {
    async fn handle_request(
        &self,
        req: RequestFrame,
        peer: PeerCred,
        _events: EventSink,
    ) -> ResponseBody {
        let Some(op) = self.agent.registry.get(&req.op) else {
            return ResponseBody::Err {
                error: FerrumError::new(
                    ErrorCode::UnknownOperation,
                    format!("`{}` is not a registered operation", req.op),
                ),
            };
        };

        match op.execution() {
            Execution::Immediate => {
                match self
                    .agent
                    .registry
                    .dispatch(&req.op, &req.auth, req.input, None)
                    .await
                {
                    Ok(data) => ResponseBody::Ok { data },
                    Err(error) => ResponseBody::Err { error },
                }
            }

            Execution::Task {
                cancellable,
                idempotent,
            } => {
                let task_id = TaskId::new();
                let db = self.agent.registry.services().db.clone();

                let created = db
                    .create_task(NewTask {
                        id: task_id,
                        op: req.op.clone(),
                        input: req.input.clone(),
                        actor_user_id: Some(req.auth.actor_user_id),
                        subscription_id: req.auth.tenant_scope.subscription_id(),
                        cancellable,
                        idempotent,
                        request_id: Some(req.auth.request_id.clone()),
                    })
                    .await;

                if let Err(e) = created {
                    return ResponseBody::Err { error: e.into() };
                }

                // The caller is implicitly watching what it just started.
                self.interests.lock().await.insert(task_id);

                spawn_task(
                    self.agent.registry.clone(),
                    self.agent.bus.clone(),
                    task_id,
                    req.op,
                    req.auth,
                    req.input,
                );

                tracing::info!(task_id = %task_id, uid = peer.uid, "task accepted");
                ResponseBody::Task { task_id }
            }
        }
    }

    async fn handle_control(&self, ctl: ControlFrame, _peer: PeerCred, events: EventSink) {
        match ctl.kind {
            ControlKind::Ping => {
                events
                    .emit(EventFrame::for_request(
                        ctl.id,
                        EventKind::Pong {
                            agent_version: env!("CARGO_PKG_VERSION").to_string(),
                        },
                    ))
                    .await;
            }
            ControlKind::Subscribe { task_id } => {
                self.interests.lock().await.insert(task_id);
            }
            ControlKind::Unsubscribe { task_id } => {
                self.interests.lock().await.remove(&task_id);
            }
            ControlKind::CancelTask { task_id } => {
                // Marking the row is what makes cancellation durable; the worker
                // notices on its next checkpoint.
                let db = &self.agent.registry.services().db;
                match db.cancel_task(task_id).await {
                    Ok(()) => {
                        self.agent
                            .bus
                            .publish(EventFrame::new(EventKind::TaskState {
                                task_id,
                                status: "cancelled".into(),
                                progress: None,
                                detail: Some("cancelled by request".into()),
                            }));
                    }
                    Err(e) => tracing::info!(task_id = %task_id, error = %e, "cancel refused"),
                }
            }
        }
    }
}
