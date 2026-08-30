//! The one path from the CLI to the agent (spec §11.20).
//!
//! There is no second API surface here and no second way to authenticate. The
//! CLI opens the same Unix socket `unihelm-web` uses, names an existing
//! administrator account, and the agent re-derives that account's rights from
//! the database before it acts (spec §12 rule 4). A forged or stale context can
//! only ever lose privileges on the way in, never gain them — which is why it
//! is safe for the CLI to assert an identity at all.
//!
//! Exit codes are part of the contract, because a CLI that only says "1" cannot
//! be branched on:
//!
//! | Exit | Meaning |
//! |------|---------|
//! | 0 | success |
//! | 1 | the CLI could not get far enough to ask (no config, no database, no admin) |
//! | 2 | clap's own usage error |
//! | 10–18 | the operation failed; the digit pair is the `FER-1xxx` block |
//!
//! `FER-1402 domain_already_exists` exits **14**, the resource-state block; an
//! agent that is not running is `FER-1500` and exits **15**. The full four-digit
//! code is always printed, so a script that needs the exact reason reads that
//! (or `--json`) and a script that only needs a category reads `$?`.

use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use unihelm_core::config::UnihelmConfig;
use unihelm_core::{AuthContext, ErrorCode, Role, TaskId, TenantScope, UnihelmError};
use unihelm_db::Db;
use unihelm_ipc::{IpcClient, ResponseBody};

use crate::invoke::{Action, Invocation};
use crate::output;

/// Exit code 1 is reserved for "the CLI never got as far as asking".
pub const EXIT_LOCAL_FAILURE: i32 = 1;

/// How often a followed task's log is re-read.
///
/// The agent persists every line as it is produced and only writes the terminal
/// status once the log pump has drained, so polling the database sees a
/// complete log — unlike an event subscription, which cannot show a line that
/// was emitted before the subscription existed.
const FOLLOW_INTERVAL: Duration = Duration::from_millis(250);

/// How long `task cancel` waits for the row to actually change.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(3);

/// The failure code an operation's *area* maps onto.
///
/// Four-digit codes do not fit in a byte, so the block does: 1402 → 14. The
/// blocks are stable (spec §10.5) and the exact code is always printed.
pub fn exit_code_for(code: ErrorCode) -> i32 {
    i32::from(code.number() / 100)
}

/// The same mapping for a code that has already been rendered to `FER-1402`, as
/// the `tasks` table stores it.
pub fn exit_code_for_stored(code: &str) -> i32 {
    code.strip_prefix("FER-")
        .and_then(|digits| digits.parse::<u16>().ok())
        .map(|n| i32::from(n / 100))
        .unwrap_or(EXIT_LOCAL_FAILURE)
}

pub struct Session {
    /// Absent for the commands that read the database and nothing else.
    /// Refusing to connect for those is deliberate: `unihelm task logs` has to
    /// work when the agent has died, which is exactly when somebody wants to
    /// read the last task's log.
    client: Option<IpcClient>,
    auth: AuthContext,
    db: Db,
    json: bool,
    follow: bool,
}

impl Session {
    /// Open the database only.
    pub async fn local(config: &UnihelmConfig, json: bool, follow: bool) -> Result<Self> {
        let db = Db::open(&config.panel.database)
            .await
            .with_context(|| format!("could not open {}", config.panel.database.display()))?;
        let auth = admin_auth(&db).await?;
        Ok(Self {
            client: None,
            auth,
            db,
            json,
            follow,
        })
    }

    /// Open the database and connect to the agent.
    pub async fn connected(config: &UnihelmConfig, json: bool, follow: bool) -> Result<Self> {
        let mut session = Self::local(config, json, follow).await?;
        session.client = Some(match IpcClient::connect(&config.agent.socket).await {
            Ok(client) => client,
            // A dead agent is `FER-1500`, and the documented exit code for that
            // is 15. Wrapping this in a plain string error instead would make
            // "the agent is not running" — the single most likely failure a
            // script has to branch on — indistinguishable from a typo in the
            // config path.
            Err(e) => {
                let unihelm = UnihelmError::from(e);
                return Err(anyhow::Error::new(TransportFailure(UnihelmError::new(
                    unihelm.code,
                    format!(
                        "could not reach the agent at {}: {}",
                        config.agent.socket.display(),
                        unihelm.detail
                    ),
                ))));
            }
        });
        Ok(session)
    }

    fn client(&self) -> Result<&IpcClient> {
        self.client
            .as_ref()
            .context("this command needs the agent, and no connection was opened")
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub fn auth(&self) -> &AuthContext {
        &self.auth
    }

    pub fn json(&self) -> bool {
        self.json
    }

    pub fn follow(&self) -> bool {
        self.follow
    }

    pub async fn close(self) {
        self.db.close().await;
    }

    /// Run whatever the command line planned, print it, and answer with the
    /// process exit code.
    pub async fn execute(&self, action: &Action) -> Result<i32> {
        match action {
            Action::Call(invocation) => self.call(invocation).await,
            Action::MergeSentinelSettings(patch) => {
                // Read first: the operation takes every field, so writing one
                // knob means sending the other four back unchanged.
                let current = match self
                    .raw(&Invocation {
                        op: "sentinel.settings",
                        input: json!({}),
                    })
                    .await?
                {
                    ResponseBody::Ok { data } => data,
                    ResponseBody::Err { error } => return Ok(self.report_error(&error)),
                    ResponseBody::Task { task_id } => {
                        anyhow::bail!("sentinel.settings unexpectedly became task {task_id}")
                    }
                };
                self.call(&Invocation {
                    op: "sentinel.settings.set",
                    input: patch.apply(current),
                })
                .await
            }
            Action::Local => Ok(0),
        }
    }

    async fn call(&self, invocation: &Invocation) -> Result<i32> {
        match self.raw(invocation).await? {
            ResponseBody::Ok { data } => {
                self.print(invocation.op, &data);
                Ok(0)
            }
            ResponseBody::Err { error } => Ok(self.report_error(&error)),
            ResponseBody::Task { task_id } => {
                if self.follow {
                    return self.follow_task(task_id).await;
                }
                if self.json {
                    self.print_json(&json!({ "task_id": task_id }));
                } else {
                    println!("task {task_id} started");
                    println!("follow it with: unihelm task logs {task_id} --follow");
                }
                Ok(0)
            }
        }
    }

    async fn raw(&self, invocation: &Invocation) -> Result<ResponseBody> {
        self.client()?
            .call(invocation.op, &self.auth, invocation.input.clone())
            .await
            // A transport failure is still a UnihelmError with a real code, so
            // it gets the same exit-code treatment as an operation that ran and
            // said no.
            .map_err(|e| anyhow::Error::new(TransportFailure(UnihelmError::from(e))))
    }

    pub fn print(&self, op: &str, data: &Value) {
        if self.json {
            self.print_json(data);
        } else {
            print!("{}", output::render(op, data));
        }
    }

    pub fn print_json(&self, data: &Value) {
        match serde_json::to_string_pretty(data) {
            Ok(text) => println!("{text}"),
            Err(e) => eprintln!("could not serialise the reply: {e}"),
        }
    }

    /// Print a failure the way the caller asked for it, and return its exit code.
    ///
    /// In `--json` mode the error goes to stdout with everything else, so a
    /// script reads one stream; otherwise it goes to stderr, so a human piping
    /// the output still sees it.
    pub fn report_error(&self, error: &UnihelmError) -> i32 {
        if self.json {
            self.print_json(&json!({
                "error": {
                    "code": error.code.code(),
                    "slug": error.code.slug(),
                    "detail": error.detail,
                    "field": error.field.clone(),
                }
            }));
        } else {
            eprint!("error: {} {}", error.code.code(), error.code.slug());
            if let Some(field) = &error.field {
                eprint!(" ({field})");
            }
            eprintln!(": {}", error.detail);
        }
        exit_code_for(error.code)
    }

    /// Stream a task's log until it reaches a terminal state, then exit with
    /// that state.
    pub async fn follow_task(&self, task_id: TaskId) -> Result<i32> {
        let repo = self.db.tasks(&self.auth.tenant_scope);
        // Refuse early rather than tailing a task that does not exist: an
        // infinite wait on a typo is the worst possible answer.
        repo.by_id(task_id)
            .await?
            .with_context(|| format!("no task {task_id}"))?;

        let mut after_seq = 0;
        let task = loop {
            after_seq = self.drain_logs(task_id, after_seq).await?;
            let task = repo.by_id(task_id).await?.with_context(|| {
                format!("task {task_id} disappeared while it was being followed")
            })?;
            if task.status.is_terminal() {
                // The agent writes the terminal status only after its log pump
                // has drained, so anything still unread was written between the
                // two reads above. One more pass and the log is complete.
                self.drain_logs(task_id, after_seq).await?;
                break task;
            }
            tokio::time::sleep(FOLLOW_INTERVAL).await;
        };

        if self.json {
            self.print_json(&serde_json::to_value(&task)?);
        } else {
            println!("task {} {}", task.id, task.status.as_str());
            if let Some(detail) = &task.error_detail {
                eprintln!(
                    "error: {} {detail}",
                    task.error_code.as_deref().unwrap_or("FER-1702")
                );
            }
        }

        Ok(match task.status {
            unihelm_db::models::TaskStatus::Ok => 0,
            // A cancelled task did not do what was asked, so it must not look
            // like success to the script that asked for it.
            _ => task
                .error_code
                .as_deref()
                .map(exit_code_for_stored)
                .unwrap_or_else(|| exit_code_for(ErrorCode::TaskFailed)),
        })
    }

    async fn drain_logs(&self, task_id: TaskId, after_seq: i64) -> Result<i64> {
        let repo = self.db.tasks(&self.auth.tenant_scope);
        let mut cursor = after_seq;
        loop {
            let lines = repo.logs(task_id, cursor, 500).await?;
            if lines.is_empty() {
                return Ok(cursor);
            }
            for line in &lines {
                if !self.json {
                    println!("{}", line.line);
                }
                cursor = cursor.max(line.seq);
            }
        }
    }

    /// Ask the agent to cancel, then wait to see whether the row actually moved.
    ///
    /// Cancellation is a control frame with no reply, and the agent refuses a
    /// task that did not opt in. Printing "cancelled" on the strength of having
    /// sent the frame would be a lie, so this watches for the change instead.
    pub async fn cancel_task(&self, task_id: TaskId) -> Result<i32> {
        let repo = self.db.tasks(&self.auth.tenant_scope);
        let task = repo
            .by_id(task_id)
            .await?
            .with_context(|| format!("no task {task_id}"))?;
        if task.status.is_terminal() {
            anyhow::bail!("task {task_id} already finished ({})", task.status.as_str());
        }

        self.client()?
            .cancel_task(task_id)
            .await
            .map_err(|e| anyhow::Error::new(TransportFailure(UnihelmError::from(e))))?;

        let deadline = std::time::Instant::now() + CANCEL_TIMEOUT;
        loop {
            let task = repo
                .by_id(task_id)
                .await?
                .with_context(|| format!("no task {task_id}"))?;
            if task.status.is_terminal() {
                if self.json {
                    self.print_json(&serde_json::to_value(&task)?);
                } else {
                    println!("task {} {}", task.id, task.status.as_str());
                }
                return Ok(0);
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "task {task_id} did not stop; it may not be cancellable (cancellable = {})",
                    task.cancellable
                );
            }
            tokio::time::sleep(FOLLOW_INTERVAL).await;
        }
    }
}

/// A transport failure carrying the code it maps onto, so `main` can give it
/// the same exit treatment as an operation-level error.
#[derive(Debug)]
pub struct TransportFailure(pub UnihelmError);

impl std::fmt::Display for TransportFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.0.code.code(),
            self.0.code.slug(),
            self.0.detail
        )
    }
}

impl std::error::Error for TransportFailure {}

/// Build an auth context for the local administrator.
///
/// The CLI does not invent privileges: it names an existing admin account, and
/// the agent re-derives that account's rights from the database before acting
/// (spec §12 rule 4).
pub async fn admin_auth(db: &Db) -> Result<AuthContext> {
    let admin = db
        .users(&TenantScope::Global)
        .list(500, 0)
        .await?
        .into_iter()
        .find(|u| u.role == Role::Admin && u.status.can_log_in())
        .context("no active administrator account exists; run `unihelm user create-admin`")?;

    Ok(AuthContext::from_role(
        admin.id,
        Role::Admin,
        TenantScope::Global,
        format!("cli-{}", request_id()),
    ))
}

/// A short random request id. The CLI does not need a real UUID, only something
/// unique enough to correlate one invocation's log lines.
fn request_id() -> String {
    use rand::Rng;
    let n: u64 = rand::thread_rng().r#gen();
    format!("{n:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exit_code_names_the_block_its_error_came_from() {
        // The property a script depends on: the same class of failure always
        // exits the same way, whatever the specific code inside it.
        assert_eq!(exit_code_for(ErrorCode::DomainAlreadyExists), 14);
        assert_eq!(exit_code_for(ErrorCode::NotFound), 14);
        assert_eq!(exit_code_for(ErrorCode::PermissionDenied), 13);
        assert_eq!(exit_code_for(ErrorCode::InvalidInput), 12);
        assert_eq!(exit_code_for(ErrorCode::AgentUnavailable), 15);
        assert_eq!(exit_code_for(ErrorCode::TaskFailed), 17);
        assert_eq!(exit_code_for(ErrorCode::Internal), 10);
    }

    #[test]
    fn every_error_code_fits_in_an_exit_status_and_never_looks_like_success() {
        // 0 means success and 1 and 2 are already taken (local failure, clap
        // usage). A new error block that collided with one of those would make
        // a failing command look like a passing one.
        for code in ErrorCode::ALL {
            let exit = exit_code_for(*code);
            assert!(
                (10..=99).contains(&exit),
                "{code:?} exits {exit}, outside the 10-99 range the CLI documents"
            );
        }
    }

    #[test]
    fn a_stored_task_error_code_maps_back_to_the_same_exit() {
        assert_eq!(exit_code_for_stored("FER-1402"), 14);
        assert_eq!(exit_code_for_stored("FER-1702"), 17);
        // A row written by an older build, or garbage: fail, but do not pretend
        // to know which block it came from.
        assert_eq!(exit_code_for_stored("nonsense"), EXIT_LOCAL_FAILURE);
        assert_eq!(exit_code_for_stored(""), EXIT_LOCAL_FAILURE);
    }
}

/// End-to-end over a real socket pair, against a stand-in agent.
///
/// The unit tests above check arithmetic; these check the thing that actually
/// breaks — that a planned invocation is framed, sent, answered, decoded and
/// turned into the right exit status. The stand-in speaks the real wire format
/// through the real [`IpcClient`], so the only piece being faked is the agent's
/// decision.
#[cfg(test)]
mod against_a_stand_in_agent {
    use std::sync::{Arc, Mutex};

    use serde_json::json;
    use unihelm_core::UserId;
    use unihelm_db::tasks::NewTask;
    use unihelm_ipc::transport::{StreamTransport, recv_json, send_json};
    use unihelm_ipc::{ClientFrame, FrameTransport, RequestFrame, ResponseFrame, ServerFrame};

    use super::*;

    /// What the stand-in answers with, in order.
    enum Reply {
        Ok(serde_json::Value),
        Err(UnihelmError),
        Task(TaskId),
    }

    type Seen = Arc<Mutex<Vec<RequestFrame>>>;

    fn stand_in_agent(replies: Vec<Reply>) -> (IpcClient, Seen) {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let (mut writer, mut reader) = StreamTransport::new(theirs).split();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));

        let recorded = seen.clone();
        tokio::spawn(async move {
            let mut replies = replies.into_iter();
            while let Ok(Some(frame)) = recv_json::<ClientFrame>(reader.as_mut()).await {
                let ClientFrame::Request(request) = frame else {
                    continue;
                };
                let id = request.id;
                recorded.lock().expect("not poisoned").push(request);
                let Some(reply) = replies.next() else { break };
                let response = match reply {
                    Reply::Ok(data) => ResponseFrame::ok(id, data),
                    Reply::Err(error) => ResponseFrame::err(id, error),
                    Reply::Task(task_id) => ResponseFrame::task(id, task_id),
                };
                let _ = send_json(writer.as_mut(), &ServerFrame::Response(response)).await;
            }
        });

        (IpcClient::from_transport(StreamTransport::new(ours)), seen)
    }

    async fn session(client: IpcClient, follow: bool) -> Session {
        Session {
            client: Some(client),
            auth: AuthContext::from_role(
                UserId::new(1),
                Role::Admin,
                TenantScope::Global,
                "cli-test",
            ),
            db: Db::open_memory().await.expect("in-memory database"),
            json: false,
            follow,
        }
    }

    fn call(op: &'static str) -> Action {
        Action::Call(Invocation {
            op,
            input: json!({}),
        })
    }

    #[tokio::test]
    async fn an_operation_that_succeeds_exits_zero_and_sends_what_it_planned() {
        let (client, seen) = stand_in_agent(vec![Reply::Ok(json!({ "sites": [] }))]);
        let session = session(client, false).await;
        let action = Action::Call(Invocation {
            op: "site.list",
            input: json!({ "limit": 10 }),
        });
        assert_eq!(session.execute(&action).await.unwrap(), 0);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].op, "site.list");
        assert_eq!(seen[0].input["limit"], 10);
        assert_eq!(
            seen[0].auth.acting_role,
            Role::Admin,
            "the CLI names the account it is acting as; the agent re-derives its rights"
        );
    }

    #[tokio::test]
    async fn a_refused_operation_exits_with_its_error_block() {
        let (client, _) = stand_in_agent(vec![Reply::Err(UnihelmError::new(
            ErrorCode::DomainAlreadyExists,
            "shop.example is already served here",
        ))]);
        let session = session(client, false).await;
        assert_eq!(session.execute(&call("site.create")).await.unwrap(), 14);
    }

    #[tokio::test]
    async fn a_permission_failure_and_a_validation_failure_do_not_look_alike() {
        // The whole point of coding the block into the exit status: a script
        // retrying on bad input must not retry on "you may not do this".
        for (code, expected) in [
            (ErrorCode::PermissionDenied, 13),
            (ErrorCode::InvalidInput, 12),
        ] {
            let (client, _) = stand_in_agent(vec![Reply::Err(UnihelmError::new(code, "no"))]);
            let session = session(client, false).await;
            assert_eq!(
                session.execute(&call("site.create")).await.unwrap(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn a_task_without_follow_reports_the_id_and_succeeds() {
        let (client, _) = stand_in_agent(vec![Reply::Task(TaskId::new())]);
        let session = session(client, false).await;
        assert_eq!(
            session.execute(&call("stack.install")).await.unwrap(),
            0,
            "starting a task is not a failure; the task's own outcome comes later"
        );
    }

    #[tokio::test]
    async fn following_a_task_that_failed_exits_with_the_task_s_error_block() {
        let task_id = TaskId::new();
        let (client, _) = stand_in_agent(vec![Reply::Task(task_id)]);
        let session = session(client, true).await;

        // A task row the agent would have written, already finished: the
        // follower must read the stored code rather than assume success.
        session
            .db
            .create_task(NewTask {
                id: task_id,
                op: "stack.install".into(),
                input: json!({}),
                actor_user_id: None,
                subscription_id: None,
                cancellable: false,
                idempotent: true,
                request_id: None,
            })
            .await
            .unwrap();
        session.db.start_task(task_id).await.unwrap();
        session
            .db
            .append_task_log(task_id, "installing nginx")
            .await
            .unwrap();
        session
            .db
            .finish_task_failed(
                task_id,
                &UnihelmError::new(ErrorCode::PackageBackendFailed, "apt-get returned 100"),
            )
            .await
            .unwrap();

        assert_eq!(
            session.execute(&call("stack.install")).await.unwrap(),
            16,
            "a followed task that failed must not exit 0"
        );
    }

    #[tokio::test]
    async fn following_a_task_that_succeeded_exits_zero() {
        let task_id = TaskId::new();
        let (client, _) = stand_in_agent(vec![Reply::Task(task_id)]);
        let session = session(client, true).await;
        session
            .db
            .create_task(NewTask {
                id: task_id,
                op: "stack.install".into(),
                input: json!({}),
                actor_user_id: None,
                subscription_id: None,
                cancellable: false,
                idempotent: true,
                request_id: None,
            })
            .await
            .unwrap();
        session.db.start_task(task_id).await.unwrap();
        session.db.finish_task_ok(task_id).await.unwrap();
        assert_eq!(session.execute(&call("stack.install")).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn changing_one_sentinel_setting_sends_the_other_four_back_unchanged() {
        // The regression this exists for: `sentinel.settings.set` has no serde
        // defaults, so a write that only carried `enabled` would blank the
        // allowlist — turning a "switch Sentinel on" into "stop protecting the
        // addresses you told me never to ban".
        let current = json!({
            "enabled": false,
            "ssh_threshold": 6,
            "window_minutes": 10,
            "ban_minutes": 60,
            "allowlist": ["203.0.113.7"],
        });
        let (client, seen) = stand_in_agent(vec![
            Reply::Ok(current),
            Reply::Ok(json!({ "enabled": true })),
        ]);
        let session = session(client, false).await;

        let action = Action::MergeSentinelSettings(crate::invoke::SentinelPatch {
            enabled: Some(true),
            ..Default::default()
        });
        assert_eq!(session.execute(&action).await.unwrap(), 0);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "it must read before it writes");
        assert_eq!(seen[0].op, "sentinel.settings");
        assert_eq!(seen[1].op, "sentinel.settings.set");
        assert_eq!(seen[1].input["enabled"], true);
        assert_eq!(seen[1].input["ban_minutes"], 60);
        assert_eq!(seen[1].input["allowlist"], json!(["203.0.113.7"]));
    }

    #[tokio::test]
    async fn a_read_that_is_refused_stops_the_write() {
        // Half of a read-modify-write is worse than none: writing defaults over
        // a settings row the caller was not allowed to read would be a
        // privilege failure that silently changed the firewall.
        let (client, seen) = stand_in_agent(vec![Reply::Err(UnihelmError::new(
            ErrorCode::PermissionDenied,
            "not yours",
        ))]);
        let session = session(client, false).await;
        let action = Action::MergeSentinelSettings(crate::invoke::SentinelPatch {
            enabled: Some(true),
            ..Default::default()
        });
        assert_eq!(session.execute(&action).await.unwrap(), 13);
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "the write must not be attempted after the read was refused"
        );
    }
}
