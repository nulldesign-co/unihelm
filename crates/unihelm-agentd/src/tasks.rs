//! Task execution and live log streaming (spec §10.1).
//!
//! A task's output goes two places at once: `task_logs`, so it survives a
//! disconnect or a restart, and the event bus, so an open task drawer shows it as
//! it happens. The persisted copy is authoritative — a viewer that falls behind
//! loses lines from the *stream*, never from the record.

use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};
use unihelm_core::{AuthContext, TaskId, TenantScope, UnihelmError};
use unihelm_db::TaskStatus;
use unihelm_db::tasks::{NewTask, TaskFilter};
use unihelm_distro::pkg::LogSink;
use unihelm_ipc::frame::{EventFrame, EventKind};
use unihelm_ops::OpRegistry;
use unihelm_ops::mail::mta::ConfigState;

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

// ---------------------------------------------------------------------------
// the mail migration an upgraded machine runs for itself
// ---------------------------------------------------------------------------

/// The operation that moves a machine onto the panel's own MTA.
pub const MTA_INSTALL: &str = "mail.mta.install";

/// What a task queued here is recorded as having been asked for.
///
/// `adopt` is spelled out rather than left to the input's default: the one
/// thing this must never do is take over a `main.cf` somebody else wrote, and
/// that is worth being visible in the task's stored input, where an operator
/// reading the row can see what was asked for.
fn mta_install_input() -> serde_json::Value {
    serde_json::json!({ "adopt": false })
}

/// The states of previous `mail.mta.install` tasks that stop another being
/// queued.
///
/// `Failed` is in here, and it is the point. `unihelm-agentd` is
/// `Restart=always`: a decision that only looked at what is *pending* would
/// queue a package install every few seconds on the one machine where it cannot
/// succeed. A failure is a fact for a person to read in the task list and act
/// on — with the reason attached — not a thing to attempt again on every boot.
const BLOCKING: [TaskStatus; 3] = [TaskStatus::Queued, TaskStatus::Running, TaskStatus::Failed];

/// Should this machine queue the move onto the panel's own MTA?
///
/// Pure, and every input is a fact read a moment before, because all three
/// answers are ones a wrong reading turns into damage: no relay and this
/// installs a null client with nowhere to send, an MTA that is already the
/// panel's and it re-runs a migration that is finished, a previous attempt
/// unexamined and it loops.
pub fn mta_migration_due(relay_live: bool, mta: ConfigState, previous: &[TaskStatus]) -> bool {
    // A null client with no relay behind it is a queue nobody drains, and
    // `mail.mta.install` refuses on exactly this ground. Queueing it would put
    // a failed task in front of every operator who has not configured mail.
    if !relay_live {
        return false;
    }
    // Already the panel's, in either state: `Edited` is a `main.cf` a human
    // changed, which is still Postfix's working configuration and still not
    // ours to re-render behind their back.
    if mta.is_ours() {
        return false;
    }
    !previous.iter().any(|s| BLOCKING.contains(s))
}

/// Queue that migration if this machine needs it, and say what was queued.
///
/// The upgrade path, without the sentence that used to be in the release notes.
/// A 0.7 server has a working relay and a site's worth of per-site msmtp files,
/// and its operator has no reason to re-save a relay that is already correct —
/// so the machine notices for itself, once, at the first start of the agent
/// that knows about the MTA.
///
/// A task rather than an install done here: `apt` on a small VPS is minutes,
/// boot must not wait on it, and a mirror that is down must not be the reason
/// the agent does not come up. As a task it is visible in the panel's task
/// list, streams its log, ends in a state somebody can read, and is reconciled
/// on the next start like anything else.
///
/// Returns the row that was created, for the caller to run — the row itself, so
/// what executes and what an operator reads in the task list are the same op
/// and the same input rather than two spellings of them. `None` is the ordinary
/// answer on every machine that does not need this, which is all of them after
/// the first time.
pub async fn queue_mta_migration(
    db: &unihelm_db::Db,
    mta: ConfigState,
) -> Option<unihelm_db::Task> {
    let relay_live = match db.mail_relay().await {
        Ok(relay) => relay.is_some_and(|r| r.is_live()),
        Err(e) => {
            tracing::error!(error = %e, "could not read the mail relay, so the mail migration was not considered");
            return None;
        }
    };

    let previous = match previous_mta_installs(db).await {
        Ok(states) => states,
        // Not knowing what previous starts queued is precisely the state in
        // which queueing again is how a restart loop is built.
        Err(e) => {
            tracing::error!(error = %e, "could not read previous mail migrations, so none was queued");
            return None;
        }
    };

    if !mta_migration_due(relay_live, mta, &previous) {
        return None;
    }

    let id = TaskId::new();
    match db
        .create_task(NewTask {
            id,
            op: MTA_INSTALL.into(),
            input: mta_install_input(),
            // No user did this; the audit trail says so, the same way the
            // scheduler's renewals do.
            actor_user_id: None,
            subscription_id: None,
            cancellable: false,
            // Every step of it converges, and it is written to be re-run.
            idempotent: true,
            request_id: Some("agent-start-mail-mta-migration".into()),
        })
        .await
    {
        Ok(task) => {
            tracing::info!(
                task_id = %id,
                "a relay is configured but the local MTA is not the panel's; queued the mail migration"
            );
            Some(task)
        }
        Err(e) => {
            tracing::error!(error = %e, "could not queue the mail migration");
            None
        }
    }
}

/// Which of the blocking states previous `mail.mta.install` tasks are in.
///
/// One query per state rather than a page of history filtered here: the answer
/// has to be exact whatever else has run on this machine, and a page could have
/// left the one row that matters just off the end of it.
async fn previous_mta_installs(db: &unihelm_db::Db) -> unihelm_db::Result<Vec<TaskStatus>> {
    let tasks = db.tasks(&TenantScope::Global);
    let mut found = Vec::new();
    for status in BLOCKING {
        let filter = TaskFilter {
            op: Some(MTA_INSTALL.to_string()),
            status: Some(status),
            ..TaskFilter::default()
        };
        if !tasks.list_filtered(&filter, 1, 0).await?.is_empty() {
            found.push(status);
        }
    }
    Ok(found)
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

#[cfg(test)]
mod tests {
    use super::*;
    use unihelm_core::ErrorCode;
    use unihelm_db::{Db, NewMailRelay, TlsMode};

    /// The relay a 0.7 machine already has: configured, switched on, working.
    async fn seed_relay(db: &Db, enabled: bool) {
        db.save_mail_relay(NewMailRelay {
            host: "smtp.postmarkapp.com".into(),
            port: 587,
            tls_mode: TlsMode::Starttls,
            username: Some("token-user".into()),
            password_sealed: Some("deadbeef".into()),
            from_address: "noreply@acme.example".into(),
            from_name: None,
            enabled,
        })
        .await
        .unwrap();
    }

    async fn queued_migrations(db: &Db) -> Vec<unihelm_db::Task> {
        db.tasks(&TenantScope::Global)
            .list_filtered(
                &TaskFilter {
                    op: Some(MTA_INSTALL.to_string()),
                    ..TaskFilter::default()
                },
                50,
                0,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn an_upgraded_machine_queues_its_own_move_onto_the_panels_mta_exactly_once() {
        // The machine this exists for: a 0.7 server with a working relay, no
        // MTA of the panel's, and an operator who has no reason to re-save a
        // relay that is already correct. It used to wait for somebody to read a
        // release note and run a command.
        let db = Db::open_memory().await.unwrap();
        seed_relay(&db, true).await;

        let first = queue_mta_migration(&db, ConfigState::Unwritten)
            .await
            .expect("an upgraded machine has to queue its own migration");
        assert_eq!(first.op, MTA_INSTALL);
        assert_eq!(
            first.input["adopt"], false,
            "taking over somebody's main.cf must never be automatic"
        );

        // `unihelm-agentd` is Restart=always. A second start must find the
        // first attempt and leave it alone, or a wedged machine queues a
        // package install every few seconds forever.
        assert!(
            queue_mta_migration(&db, ConfigState::Unwritten)
                .await
                .is_none(),
            "a restart queued a second migration on top of a pending one"
        );

        // And a failure is a fact for a person to read, not a thing to attempt
        // again on every boot: the reason is on the row, with a retry button
        // next to it.
        db.finish_task_failed(
            first.id,
            &UnihelmError::new(ErrorCode::CommandFailed, "apt could not reach the mirror"),
        )
        .await
        .unwrap();
        assert!(
            queue_mta_migration(&db, ConfigState::Unwritten)
                .await
                .is_none(),
            "a failed migration was retried on the next restart"
        );

        assert_eq!(queued_migrations(&db).await.len(), 1);
    }

    #[tokio::test]
    async fn a_machine_with_no_relay_queues_no_migration() {
        // A null client with no relay behind it is a queue nobody drains, and
        // `mail.mta.install` refuses on exactly that ground — so queueing it
        // would put a failed task in front of every operator who has not
        // configured mail, on every install of the panel.
        let db = Db::open_memory().await.unwrap();
        assert!(
            queue_mta_migration(&db, ConfigState::Unwritten)
                .await
                .is_none()
        );

        // A row that exists is not a relay that accepts mail: `is_live()`, not
        // `is_some()`, the same distinction the rest of the mail code makes.
        seed_relay(&db, false).await;
        assert!(
            queue_mta_migration(&db, ConfigState::Unwritten)
                .await
                .is_none()
        );

        assert!(queued_migrations(&db).await.is_empty());
    }

    #[tokio::test]
    async fn a_machine_already_on_the_panels_mta_queues_no_migration() {
        // Nothing to move: the null client is already configured. `Edited` is
        // counted here too — a `main.cf` a human changed is still Postfix's
        // working configuration, and re-rendering it behind their back is not
        // something a restart gets to decide.
        let db = Db::open_memory().await.unwrap();
        seed_relay(&db, true).await;

        for state in [ConfigState::Ours, ConfigState::Edited] {
            assert!(
                queue_mta_migration(&db, state).await.is_none(),
                "{state:?} queued a migration for a machine that is already migrated"
            );
        }
        assert!(queued_migrations(&db).await.is_empty());
    }

    #[test]
    fn the_decision_is_one_function_with_every_reason_it_can_say_no() {
        // The three inputs, each of which turns into damage when read wrong: no
        // relay installs a null client with nowhere to send, an MTA already the
        // panel's re-runs a finished migration, and an unexamined previous
        // attempt is how a restart loop is built.
        assert!(mta_migration_due(true, ConfigState::Unwritten, &[]));
        assert!(!mta_migration_due(false, ConfigState::Unwritten, &[]));
        assert!(!mta_migration_due(true, ConfigState::Ours, &[]));
        for blocking in BLOCKING {
            assert!(
                !mta_migration_due(true, ConfigState::Unwritten, &[blocking]),
                "{blocking:?} did not stop another migration being queued"
            );
        }
        // A migration that finished is not a reason to refuse a later one: the
        // only way back to this state is a `main.cf` that stopped being the
        // panel's, which is a machine that needs configuring again.
        assert!(mta_migration_due(
            true,
            ConfigState::Unwritten,
            &[TaskStatus::Ok, TaskStatus::Cancelled]
        ));
    }
}
