//! Task execution and live log streaming (spec §10.1).
//!
//! A task's output goes two places at once: `task_logs`, so it survives a
//! disconnect or a restart, and the event bus, so an open task drawer shows it as
//! it happens. The persisted copy is authoritative — a viewer that falls behind
//! loses lines from the *stream*, never from the record.

use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};
use unihelm_core::{AuthContext, TaskId, UnihelmError};
use unihelm_distro::pkg::LogSink;
use unihelm_ipc::frame::{EventFrame, EventKind};
use unihelm_ops::OpRegistry;

/// Fan-out for task events. Depth is generous because a package install is
/// chatty and a slow consumer should lag, not stall the worker.
const BUS_CAPACITY: usize = 4096;

#[derive(Clone)]
pub struct TaskBus {
    tx: broadcast::Sender<EventFrame>,
}

impl TaskBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        Self { tx }
    }

    /// Publish an event. An error means nobody is listening, which is fine.
    pub fn publish(&self, event: EventFrame) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventFrame> {
        self.tx.subscribe()
    }
}

impl Default for TaskBus {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`LogSink`] that hands lines to the persistence pump.
///
/// The sink itself is synchronous and never blocks: operations call it from
/// inside tight command-output loops, and an unbounded queue plus a draining
/// task keeps a chatty install from throttling itself on database writes.
struct TaskLog {
    tx: mpsc::UnboundedSender<String>,
}

impl LogSink for TaskLog {
    fn line(&self, line: &str) {
        let _ = self.tx.send(line.to_string());
    }
}

/// Run an operation as a task: claim it, execute, record the outcome.
pub fn spawn_task(
    registry: Arc<OpRegistry>,
    bus: TaskBus,
    task_id: TaskId,
    op: String,
    auth: AuthContext,
    input: serde_json::Value,
) {
    tokio::spawn(async move {
        let db = registry.services().db.clone();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();

        // Persist-and-publish pump. Owns the only database writes for this
        // task's logs, so sequence numbers stay dense and ordered.
        let pump = {
            let db = db.clone();
            let bus = bus.clone();
            tokio::spawn(async move {
                while let Some(line) = rx.recv().await {
                    match db.append_task_log(task_id, &line).await {
                        Ok(seq) => {
                            bus.publish(EventFrame::new(EventKind::TaskLog { task_id, seq, line }))
                        }
                        Err(e) => {
                            tracing::warn!(task_id = %task_id, error = %e, "could not persist a task log line");
                        }
                    }
                }
            })
        };

        if let Err(e) = db.start_task(task_id).await {
            tracing::warn!(task_id = %task_id, error = %e, "could not start task");
            drop(tx);
            let _ = pump.await;
            return;
        }
        publish_state(&bus, task_id, "running", None);

        let log: Arc<dyn LogSink> = Arc::new(TaskLog { tx: tx.clone() });
        let outcome = registry
            .dispatch(&op, &auth, input, Some((task_id, log)))
            .await;

        // Close the sink and let every queued line land before the terminal
        // state goes out, so the UI never shows "failed" above the line that
        // explains why.
        drop(tx);
        let _ = pump.await;

        match outcome {
            Ok(_) => {
                if let Err(e) = db.finish_task_ok(task_id).await {
                    tracing::warn!(task_id = %task_id, error = %e, "could not finish task");
                }
                publish_state(&bus, task_id, "ok", None);
            }
            Err(error) => {
                record_failure(&db, task_id, &error).await;
                publish_state(&bus, task_id, "failed", Some(error.detail.clone()));
            }
        }
    });
}

async fn record_failure(db: &unihelm_db::Db, task_id: TaskId, error: &UnihelmError) {
    // The reason belongs in the log as well as the row: the task drawer shows
    // the log, and a failure with no visible cause is the thing operators hate.
    let _ = db
        .append_task_log(
            task_id,
            &format!("task failed: [{}] {}", error.code.code(), error.detail),
        )
        .await;
    if let Err(e) = db.finish_task_failed(task_id, error).await {
        tracing::warn!(task_id = %task_id, error = %e, "could not record task failure");
    }
}

fn publish_state(bus: &TaskBus, task_id: TaskId, status: &str, detail: Option<String>) {
    bus.publish(EventFrame::new(EventKind::TaskState {
        task_id,
        status: status.to_string(),
        progress: None,
        detail,
    }));
}

/// Re-queue or fail whatever was running when the agent last died (spec §5.5).
pub async fn reconcile_on_start(db: &unihelm_db::Db) {
    match db.reconcile_interrupted_tasks().await {
        Ok((0, 0)) => {}
        Ok((requeued, failed)) => {
            tracing::warn!(
                requeued,
                failed,
                "reconciled tasks interrupted by an agent restart"
            );
        }
        Err(e) => tracing::error!(error = %e, "task reconciliation failed"),
    }
}
