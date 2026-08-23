//! The task engine's storage (spec §10.1).
//!
//! Everything slower than a few hundred milliseconds becomes a Task: a row that
//! survives a crash, streams its log, and always reaches a terminal state with a
//! human-readable reason. `ferrum-agentd` is the only writer here (spec §5.5).

use ferrum_core::{ErrorCode, FerrumError, SubscriptionId, TaskId, TenantScope, UserId};

use crate::models::{Task, TaskLogLine, TaskRow, TaskStatus};
use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// What is needed to enqueue a task.
#[derive(Debug, Clone)]
pub struct NewTask {
    pub id: TaskId,
    pub op: String,
    pub input: serde_json::Value,
    pub actor_user_id: Option<UserId>,
    pub subscription_id: Option<SubscriptionId>,
    /// Whether the UI may offer a cancel button.
    pub cancellable: bool,
    /// Only idempotent tasks are ever retried automatically (spec §10.1).
    pub idempotent: bool,
    pub request_id: Option<String>,
}

pub struct TaskRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn tasks(&self, scope: &TenantScope) -> TaskRepo<'_> {
        TaskRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    /// Enqueue a task. Agent-side; not scoped, because the agent has already
    /// verified the caller's scope against the operation's target.
    pub async fn create_task(&self, new: NewTask) -> Result<Task> {
        let row = sqlx::query_as::<_, TaskRow>(
            "INSERT INTO tasks (id, op, input_json, actor_user_id, subscription_id, status,
                                cancellable, idempotent, request_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6, ?7, ?8, ?9)
             RETURNING *",
        )
        .bind(new.id.to_string())
        .bind(&new.op)
        .bind(serde_json::to_string(&new.input).unwrap_or_else(|_| "{}".into()))
        .bind(new.actor_user_id.map(|u| u.get()))
        .bind(new.subscription_id.map(|s| s.get()))
        .bind(i64::from(new.cancellable))
        .bind(i64::from(new.idempotent))
        .bind(&new.request_id)
        .bind(to_sql_time(now()))
        .fetch_one(self.pool())
        .await?;
        Task::try_from(row)
    }

    /// Claim the task and mark it running.
    pub async fn start_task(&self, id: TaskId) -> Result<()> {
        let affected = sqlx::query(
            "UPDATE tasks SET status = 'running', started_at = ?2
             WHERE id = ?1 AND status = 'queued'",
        )
        .bind(id.to_string())
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(DbError::Domain(FerrumError::new(
                ErrorCode::Conflict,
                "task is not queued and cannot be started",
            )));
        }
        Ok(())
    }

    pub async fn set_task_progress(&self, id: TaskId, progress: u8) -> Result<()> {
        sqlx::query("UPDATE tasks SET progress = ?2 WHERE id = ?1 AND status = 'running'")
            .bind(id.to_string())
            .bind(i64::from(progress.min(100)))
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Finish successfully. Progress is forced to 100 so no task ends at 87%.
    pub async fn finish_task_ok(&self, id: TaskId) -> Result<()> {
        sqlx::query(
            "UPDATE tasks SET status = 'ok', progress = 100, finished_at = ?2
             WHERE id = ?1 AND status IN ('queued', 'running')",
        )
        .bind(id.to_string())
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Finish with a failure. Both the stable code and the human reason are
    /// stored, because the UI shows one and support asks about the other.
    pub async fn finish_task_failed(&self, id: TaskId, error: &FerrumError) -> Result<()> {
        sqlx::query(
            "UPDATE tasks SET status = 'failed', error_code = ?2, error_detail = ?3, finished_at = ?4
             WHERE id = ?1 AND status IN ('queued', 'running')",
        )
        .bind(id.to_string())
        .bind(error.code.code())
        .bind(&error.detail)
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Mark a task cancelled. Refuses tasks that did not opt in.
    pub async fn cancel_task(&self, id: TaskId) -> Result<()> {
        let affected = sqlx::query(
            "UPDATE tasks SET status = 'cancelled', finished_at = ?2
             WHERE id = ?1 AND cancellable = 1 AND status IN ('queued', 'running')",
        )
        .bind(id.to_string())
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(DbError::Domain(FerrumError::new(
                ErrorCode::TaskNotCancellable,
                "this task cannot be cancelled",
            )));
        }
        Ok(())
    }

    /// Append a log line, allocating the next sequence number.
    pub async fn append_task_log(&self, id: TaskId, line: &str) -> Result<i64> {
        // Truncating here rather than at the source keeps one runaway command
        // from filling the disk with a single log row.
        const MAX_LINE: usize = 8 * 1024;
        let line = if line.len() > MAX_LINE {
            &line[..MAX_LINE]
        } else {
            line
        };

        let row: (i64,) = sqlx::query_as(
            "INSERT INTO task_logs (task_id, seq, at, line)
             VALUES (?1, (SELECT COALESCE(MAX(seq), 0) + 1 FROM task_logs WHERE task_id = ?1), ?2, ?3)
             RETURNING seq",
        )
        .bind(id.to_string())
        .bind(to_sql_time(now()))
        .bind(line)
        .fetch_one(self.pool())
        .await?;
        Ok(row.0)
    }

    /// Re-queue or fail tasks that were running when the agent died.
    ///
    /// This is what makes the crash-only design honest: after a restart no task
    /// is left claiming to be running (spec §5.5).
    pub async fn reconcile_interrupted_tasks(&self) -> Result<(u64, u64)> {
        let ts = to_sql_time(now());

        // Idempotent work is safe to run again.
        let requeued = sqlx::query(
            "UPDATE tasks SET status = 'queued', started_at = NULL, progress = 0
             WHERE status = 'running' AND idempotent = 1",
        )
        .execute(self.pool())
        .await?
        .rows_affected();

        // Everything else ends with a reason, rather than being silently retried.
        let failed = sqlx::query(
            "UPDATE tasks
             SET status = 'failed',
                 error_code = ?1,
                 error_detail = 'the agent restarted while this task was running',
                 finished_at = ?2
             WHERE status = 'running'",
        )
        .bind(ErrorCode::TaskFailed.code())
        .bind(&ts)
        .execute(self.pool())
        .await?
        .rows_affected();

        Ok((requeued, failed))
    }

    /// Oldest queued task, for the worker pool.
    pub async fn next_queued_task(&self) -> Result<Option<Task>> {
        let row = sqlx::query_as::<_, TaskRow>(
            "SELECT * FROM tasks WHERE status = 'queued' ORDER BY created_at ASC, rowid ASC LIMIT 1",
        )
        .fetch_optional(self.pool())
        .await?;
        row.map(Task::try_from).transpose()
    }
}

impl TaskRepo<'_> {
    pub async fn by_id(&self, id: TaskId) -> Result<Option<Task>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, TaskRow>("SELECT * FROM tasks WHERE id = ?1")
                    .bind(id.to_string())
                    .fetch_optional(self.db.pool())
                    .await?
            }
            // Reseller task visibility needs the subscriptions table, which
            // arrives in Phase 2. Until then a reseller sees the tasks it started.
            ScopeFilter::Reseller(user_id) | ScopeFilter::Customer(user_id) => {
                sqlx::query_as::<_, TaskRow>(
                    "SELECT * FROM tasks WHERE id = ?1 AND actor_user_id = ?2",
                )
                .bind(id.to_string())
                .bind(user_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, TaskRow>(
                    "SELECT * FROM tasks WHERE id = ?1 AND subscription_id = ?2",
                )
                .bind(id.to_string())
                .bind(subscription_id)
                .fetch_optional(self.db.pool())
                .await?
            }
        };
        row.map(Task::try_from).transpose()
    }

    /// Recent tasks visible to this scope, newest first.
    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<Task>> {
        let limit = limit.clamp(1, 200);
        let rows =
            match self.scope {
                ScopeFilter::All => sqlx::query_as::<_, TaskRow>(
                    "SELECT * FROM tasks ORDER BY created_at DESC, rowid DESC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?,
                ScopeFilter::Reseller(user_id) | ScopeFilter::Customer(user_id) => {
                    sqlx::query_as::<_, TaskRow>(
                        "SELECT * FROM tasks WHERE actor_user_id = ?1
                     ORDER BY created_at DESC, rowid DESC LIMIT ?2 OFFSET ?3",
                    )
                    .bind(user_id)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(self.db.pool())
                    .await?
                }
                ScopeFilter::Subscription {
                    subscription_id, ..
                } => {
                    sqlx::query_as::<_, TaskRow>(
                        "SELECT * FROM tasks WHERE subscription_id = ?1
                     ORDER BY created_at DESC, rowid DESC LIMIT ?2 OFFSET ?3",
                    )
                    .bind(subscription_id)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(self.db.pool())
                    .await?
                }
            };
        rows.into_iter().map(Task::try_from).collect()
    }

    /// Log lines after `after_seq`, so a reconnecting UI can resume the stream.
    pub async fn logs(&self, id: TaskId, after_seq: i64, limit: i64) -> Result<Vec<TaskLogLine>> {
        // Reading logs requires being able to read the task itself.
        if self.by_id(id).await?.is_none() {
            return Err(DbError::NotFound { what: "task" });
        }
        let limit = limit.clamp(1, 5_000);
        let rows: Vec<(i64, String, String)> = sqlx::query_as(
            "SELECT seq, at, line FROM task_logs WHERE task_id = ?1 AND seq > ?2
             ORDER BY seq ASC LIMIT ?3",
        )
        .bind(id.to_string())
        .bind(after_seq)
        .bind(limit)
        .fetch_all(self.db.pool())
        .await?;

        rows.into_iter()
            .map(|(seq, at, line)| {
                Ok(TaskLogLine {
                    seq,
                    at: from_sql_time(&at)?,
                    line,
                })
            })
            .collect()
    }

    /// Count by status, for the task drawer's badge.
    pub async fn count_active(&self) -> Result<i64> {
        let row: (i64,) = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as("SELECT COUNT(*) FROM tasks WHERE status IN ('queued', 'running')")
                    .fetch_one(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(user_id) | ScopeFilter::Customer(user_id) => sqlx::query_as(
                "SELECT COUNT(*) FROM tasks WHERE status IN ('queued', 'running') AND actor_user_id = ?1",
            )
            .bind(user_id)
            .fetch_one(self.db.pool())
            .await?,
            ScopeFilter::Subscription { subscription_id, .. } => sqlx::query_as(
                "SELECT COUNT(*) FROM tasks WHERE status IN ('queued', 'running') AND subscription_id = ?1",
            )
            .bind(subscription_id)
            .fetch_one(self.db.pool())
            .await?,
        };
        Ok(row.0)
    }
}

/// Status helper used by the agent's worker loop.
pub fn is_terminal(status: TaskStatus) -> bool {
    status.is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::NewUser;
    use ferrum_core::{Email, Role, Username};

    async fn seed() -> (Db, UserId, UserId) {
        let db = Db::open_memory().await.unwrap();
        let mk = |name: &'static str| NewUser {
            role: Role::Customer,
            email: Email::parse(&format!("{name}@example.com")).unwrap(),
            username: Username::parse(name).unwrap(),
            password: "a-long-enough-password".into(),
            reseller_id: None,
            full_name: None,
            locale: "en".into(),
        };
        let a = db
            .users(&TenantScope::Global)
            .create(mk("alice"))
            .await
            .unwrap();
        let b = db
            .users(&TenantScope::Global)
            .create(mk("bobby"))
            .await
            .unwrap();
        (db, a.id, b.id)
    }

    fn new_task(actor: UserId, op: &str) -> NewTask {
        NewTask {
            id: TaskId::new(),
            op: op.into(),
            input: serde_json::json!({}),
            actor_user_id: Some(actor),
            subscription_id: None,
            cancellable: false,
            idempotent: false,
            request_id: Some("req-1".into()),
        }
    }

    #[tokio::test]
    async fn a_task_moves_through_its_lifecycle() {
        let (db, alice, _) = seed().await;
        let t = db
            .create_task(new_task(alice, "php.install"))
            .await
            .unwrap();
        assert_eq!(t.status, TaskStatus::Queued);

        db.start_task(t.id).await.unwrap();
        db.set_task_progress(t.id, 50).await.unwrap();
        db.finish_task_ok(t.id).await.unwrap();

        let done = db
            .tasks(&TenantScope::Global)
            .by_id(t.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(done.status, TaskStatus::Ok);
        assert_eq!(
            done.progress, 100,
            "a finished task must not sit at a partial percentage"
        );
        assert!(done.finished_at.is_some());
    }

    #[tokio::test]
    async fn a_task_cannot_be_started_twice() {
        let (db, alice, _) = seed().await;
        let t = db
            .create_task(new_task(alice, "php.install"))
            .await
            .unwrap();
        db.start_task(t.id).await.unwrap();
        assert!(
            db.start_task(t.id).await.is_err(),
            "double-claiming a task must fail"
        );
    }

    #[tokio::test]
    async fn failures_record_the_stable_code_and_the_reason() {
        let (db, alice, _) = seed().await;
        let t = db
            .create_task(new_task(alice, "php.install"))
            .await
            .unwrap();
        db.start_task(t.id).await.unwrap();
        db.finish_task_failed(
            t.id,
            &FerrumError::new(
                ErrorCode::PackageBackendFailed,
                "apt could not reach the mirror",
            ),
        )
        .await
        .unwrap();

        let failed = db
            .tasks(&TenantScope::Global)
            .by_id(t.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(failed.status, TaskStatus::Failed);
        assert_eq!(failed.error_code.as_deref(), Some("FER-1601"));
        assert!(failed.error_detail.unwrap().contains("mirror"));
    }

    #[tokio::test]
    async fn a_finished_task_is_not_reopened_by_a_late_update() {
        let (db, alice, _) = seed().await;
        let t = db
            .create_task(new_task(alice, "php.install"))
            .await
            .unwrap();
        db.start_task(t.id).await.unwrap();
        db.finish_task_ok(t.id).await.unwrap();

        db.finish_task_failed(t.id, &FerrumError::internal("too late"))
            .await
            .unwrap();
        let after = db
            .tasks(&TenantScope::Global)
            .by_id(t.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.status, TaskStatus::Ok, "terminal state must be final");
    }

    #[tokio::test]
    async fn only_cancellable_tasks_can_be_cancelled() {
        let (db, alice, _) = seed().await;
        let plain = db
            .create_task(new_task(alice, "php.install"))
            .await
            .unwrap();
        assert!(db.cancel_task(plain.id).await.is_err());

        let mut spec = new_task(alice, "backup.run");
        spec.cancellable = true;
        let cancellable = db.create_task(spec).await.unwrap();
        db.cancel_task(cancellable.id).await.unwrap();
        let after = db
            .tasks(&TenantScope::Global)
            .by_id(cancellable.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.status, TaskStatus::Cancelled);
    }

    #[tokio::test]
    async fn log_sequence_numbers_are_dense_and_ordered() {
        let (db, alice, _) = seed().await;
        let t = db
            .create_task(new_task(alice, "php.install"))
            .await
            .unwrap();
        for i in 0..5 {
            let seq = db
                .append_task_log(t.id, &format!("line {i}"))
                .await
                .unwrap();
            assert_eq!(seq, i + 1);
        }
        let logs = db
            .tasks(&TenantScope::Global)
            .logs(t.id, 0, 100)
            .await
            .unwrap();
        assert_eq!(logs.len(), 5);
        assert_eq!(logs[0].line, "line 0");

        // Resuming after a reconnect.
        let rest = db
            .tasks(&TenantScope::Global)
            .logs(t.id, 3, 100)
            .await
            .unwrap();
        assert_eq!(rest.len(), 2);
        assert_eq!(rest[0].seq, 4);
    }

    #[tokio::test]
    async fn absurdly_long_log_lines_are_truncated() {
        let (db, alice, _) = seed().await;
        let t = db
            .create_task(new_task(alice, "php.install"))
            .await
            .unwrap();
        db.append_task_log(t.id, &"x".repeat(100_000))
            .await
            .unwrap();
        let logs = db
            .tasks(&TenantScope::Global)
            .logs(t.id, 0, 10)
            .await
            .unwrap();
        assert!(logs[0].line.len() <= 8 * 1024);
    }

    #[tokio::test]
    async fn interrupted_tasks_are_reconciled_on_restart() {
        let (db, alice, _) = seed().await;
        let plain = db
            .create_task(new_task(alice, "site.create"))
            .await
            .unwrap();
        let mut spec = new_task(alice, "metrics.rollup");
        spec.idempotent = true;
        let idempotent = db.create_task(spec).await.unwrap();

        db.start_task(plain.id).await.unwrap();
        db.start_task(idempotent.id).await.unwrap();

        let (requeued, failed) = db.reconcile_interrupted_tasks().await.unwrap();
        assert_eq!((requeued, failed), (1, 1));

        let repo = db.tasks(&TenantScope::Global);
        assert_eq!(
            repo.by_id(idempotent.id).await.unwrap().unwrap().status,
            TaskStatus::Queued
        );
        let dead = repo.by_id(plain.id).await.unwrap().unwrap();
        assert_eq!(dead.status, TaskStatus::Failed);
        assert!(dead.error_detail.unwrap().contains("agent restarted"));
    }

    #[tokio::test]
    async fn one_tenant_cannot_read_another_tenants_tasks_or_logs() {
        let (db, alice, bobby) = seed().await;
        let t = db
            .create_task(new_task(alice, "site.create"))
            .await
            .unwrap();
        db.append_task_log(t.id, "secret path /home/alice")
            .await
            .unwrap();

        let intruder = TenantScope::Customer { customer_id: bobby };
        assert!(db.tasks(&intruder).by_id(t.id).await.unwrap().is_none());
        assert!(matches!(
            db.tasks(&intruder).logs(t.id, 0, 100).await,
            Err(DbError::NotFound { .. })
        ));
        assert!(db.tasks(&intruder).list(100, 0).await.unwrap().is_empty());

        let owner = TenantScope::Customer { customer_id: alice };
        assert!(db.tasks(&owner).by_id(t.id).await.unwrap().is_some());
        assert_eq!(db.tasks(&owner).logs(t.id, 0, 100).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_queue_is_fifo() {
        let (db, alice, _) = seed().await;
        let first = db.create_task(new_task(alice, "a")).await.unwrap();
        let _second = db.create_task(new_task(alice, "b")).await.unwrap();
        assert_eq!(db.next_queued_task().await.unwrap().unwrap().id, first.id);

        db.start_task(first.id).await.unwrap();
        assert_eq!(db.next_queued_task().await.unwrap().unwrap().op, "b");
    }

    #[tokio::test]
    async fn active_count_feeds_the_task_drawer() {
        let (db, alice, _) = seed().await;
        let t = db.create_task(new_task(alice, "a")).await.unwrap();
        assert_eq!(
            db.tasks(&TenantScope::Global).count_active().await.unwrap(),
            1
        );
        db.start_task(t.id).await.unwrap();
        db.finish_task_ok(t.id).await.unwrap();
        assert_eq!(
            db.tasks(&TenantScope::Global).count_active().await.unwrap(),
            0
        );
    }
}
