//! Turning IPC frames into operations (spec §5.2, §10.1).
//!
//! Everything privileged funnels through here, and the funnel is narrow on
//! purpose: look up the name in the registry, let the registry re-verify the
//! caller, then either answer inline or hand the work to a task.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ferrum_core::{AuthContext, ErrorCode, FerrumError, TaskId, UserId};
use ferrum_db::tasks::NewTask;
use ferrum_ipc::frame::{
    ControlFrame, ControlKind, EventFrame, EventKind, RequestFrame, ResponseBody, TerminalTarget,
};
use ferrum_ipc::peercred::PeerCred;
use ferrum_ipc::server::{EventSink, RequestHandler};
use ferrum_ops::terminal::{SessionHandle, TerminalRegistry};
use ferrum_ops::{Execution, OpRegistry};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::tasks::{TaskBus, spawn_task};

/// The largest keystroke payload one frame may carry.
///
/// A paste is the honest reason a client sends more than a few bytes, and 64 KiB
/// is a very large paste. Beyond that the frame is refused rather than fed to a
/// shell, so a client cannot use a terminal as an unbounded write into the
/// agent's memory.
const MAX_TERMINAL_INPUT: usize = 64 * 1024;

/// Shared agent state.
pub struct Agent {
    pub registry: Arc<OpRegistry>,
    pub bus: TaskBus,
    /// Every live web terminal (spec 11.16). It lives on the *agent* rather
    /// than on a connection so a session outlives the `ferrum-web` process that
    /// opened it, which is the whole acceptance criterion.
    pub terminals: Arc<TerminalRegistry>,
}

impl Agent {
    pub fn new(registry: Arc<OpRegistry>, bus: TaskBus) -> Self {
        let terminals = TerminalRegistry::production(registry.services().db.clone());
        Self {
            registry,
            bus,
            terminals,
        }
    }

    /// Close terminal sessions that are past their idle or lifetime limit.
    ///
    /// Driven by the agent's own ticker, not by a request: the case that
    /// matters most is the one where nobody is asking anything, because the
    /// browser tab was abandoned.
    pub async fn sweep_terminals(&self) {
        let closed = self.terminals.sweep().await;
        if closed > 0 {
            tracing::info!(closed, "closed expired terminal sessions");
        }
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
    /// Terminal sessions this connection is streaming, and the task doing the
    /// streaming. Dropping the connection aborts the forwarders but leaves the
    /// sessions running — that separation is what lets a browser reconnect to a
    /// shell after `ferrum-web` restarts (spec 11.16).
    ///
    /// Shared with the pumps so each can drop its own entry when its session
    /// ends. `ferrum-web` holds one IPC connection for its whole process life,
    /// so this map is effectively permanent: an entry that outlives its session
    /// pins the pty master, the scrollback and the writer thread until the web
    /// process restarts.
    attached: Arc<Mutex<std::collections::HashMap<Uuid, Attachment>>>,
}

/// One terminal this connection is streaming.
///
/// The verified `auth` is kept because the later frames of a session —
/// keystrokes, a resize, a close — carry no identity of their own. Holding the
/// identity that was checked at open (or attach) time means an input frame is
/// only ever applied to a session *this* connection proved it owns, so a frame
/// naming somebody else's session id reaches nothing.
struct Attachment {
    handle: Arc<SessionHandle>,
    auth: AuthContext,
    pump: tokio::task::JoinHandle<()>,
}

impl Drop for ConnectionHandler {
    fn drop(&mut self) {
        // The pumps borrow nothing from the connection, so without this they
        // would keep running against a socket nobody is reading.
        //
        // Not the only thing that stops them, and deliberately so: this handler
        // is also held by the task-event forwarder, which can outlive the
        // connection, so `drop` is a prompt cleanup rather than a guarantee.
        // A pump also exits the moment a send fails or its session ends, and
        // the number that can be idle at once is bounded by the session cap.
        if let Ok(mut attached) = self.attached.try_lock() {
            for (_, attachment) in attached.drain() {
                attachment.pump.abort();
            }
        }
    }
}

impl ConnectionHandler {
    pub fn new(agent: Arc<Agent>) -> Self {
        Self {
            agent,
            interests: Mutex::new(HashSet::new()),
            attached: Arc::new(Mutex::new(std::collections::HashMap::new())),
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

impl ConnectionHandler {
    /// Open a session: verify the identity the frame claims, then let
    /// `ferrum_ops::terminal` decide what that identity may have.
    ///
    /// The verification is the point. A control frame does not travel through
    /// `OpRegistry::dispatch`, so without this call the agent would be taking
    /// the web process's word for who is asking — and the thing being asked
    /// for is a shell.
    async fn terminal_open(
        &self,
        session: Uuid,
        target: TerminalTarget,
        cols: u16,
        rows: u16,
        claimed: AuthContext,
        events: EventSink,
    ) {
        let claimed_actor = claimed.actor_user_id;
        let auth = match self.agent.registry.verify_auth(&claimed).await {
            Ok(auth) => auth,
            Err(e) => {
                events
                    .emit(terminal_state(
                        session,
                        claimed_actor,
                        "denied",
                        Some(e.detail),
                        None,
                    ))
                    .await;
                return;
            }
        };

        match self
            .agent
            .terminals
            .open(session, &auth, &target, cols, rows)
            .await
        {
            Ok(handle) => {
                let account = handle.info.account.clone();
                let owner = handle.info.owner;
                self.attach_locally(handle, auth, events.clone()).await;
                events
                    .emit(terminal_state(session, owner, "open", None, Some(account)))
                    .await;
            }
            Err(e) => {
                events
                    .emit(terminal_state(
                        session,
                        claimed_actor,
                        "denied",
                        Some(e.detail),
                        None,
                    ))
                    .await;
            }
        }
    }

    /// Re-attach to a session that is still running — the reconnect path after
    /// a `ferrum-web` restart or a dropped WebSocket (spec 11.16 AC).
    async fn terminal_attach(&self, session: Uuid, claimed: AuthContext, events: EventSink) {
        let claimed_actor = claimed.actor_user_id;
        let auth = match self.agent.registry.verify_auth(&claimed).await {
            Ok(auth) => auth,
            Err(e) => {
                events
                    .emit(terminal_state(
                        session,
                        claimed_actor,
                        "denied",
                        Some(e.detail),
                        None,
                    ))
                    .await;
                return;
            }
        };

        // `for_owner` is what stops an attach to somebody else's session: a
        // session id is not an authorisation, and one belonging to another
        // account is `not_found` rather than forbidden.
        match self.agent.terminals.for_owner(session, &auth).await {
            Ok(handle) => {
                let account = handle.info.account.clone();
                let owner = handle.info.owner;
                self.attach_locally(handle, auth, events.clone()).await;
                events
                    .emit(terminal_state(session, owner, "open", None, Some(account)))
                    .await;
            }
            Err(e) => {
                events
                    .emit(terminal_state(
                        session,
                        claimed_actor,
                        "closed",
                        Some(e.detail),
                        None,
                    ))
                    .await;
            }
        }
    }

    /// Start streaming a session's output down this connection.
    async fn attach_locally(
        &self,
        handle: Arc<SessionHandle>,
        auth: AuthContext,
        events: EventSink,
    ) {
        let session = handle.info.id;
        let pump = spawn_terminal_pump(handle.clone(), events, Arc::clone(&self.attached));
        let mut map = self.attached.lock().await;
        // Belt and braces for a pump that was aborted before it could tidy up:
        // an entry whose session is finished can never be useful again.
        map.retain(|id, a| *id == session || !a.handle.is_closed());
        let previous = map.insert(session, Attachment { handle, auth, pump });
        drop(map);
        // Re-attaching on the same connection replaces the old stream rather
        // than doubling every byte.
        if let Some(previous) = previous {
            previous.pump.abort();
        }
    }

    /// The session `actor` attached on this connection, if it is theirs.
    ///
    /// The actor check is the load-bearing half. One `ferrum-web` process
    /// multiplexes every browser it serves over a *single* agent connection, so
    /// this map is shared between viewers: without comparing the actor, a frame
    /// naming a session id somebody else had attached would be applied to that
    /// somebody else's shell.
    async fn attached_handle(&self, session: Uuid, actor: UserId) -> Option<Arc<SessionHandle>> {
        self.attached
            .lock()
            .await
            .get(&session)
            .filter(|a| a.auth.actor_user_id == actor && a.handle.info.owner == actor)
            .map(|a| a.handle.clone())
    }

    async fn terminal_input(&self, session: Uuid, actor: UserId, data: &str, events: EventSink) {
        let Some(handle) = self.attached_handle(session, actor).await else {
            // Not this connection's session. Saying "closed" rather than
            // "denied" keeps the answer identical whether the id belongs to
            // somebody else or to nobody.
            events
                .emit(terminal_state(
                    session,
                    actor,
                    "closed",
                    Some("no such terminal session on this connection".into()),
                    None,
                ))
                .await;
            return;
        };

        let Ok(bytes) = BASE64.decode(data) else {
            tracing::warn!(session = %session, "dropping a terminal input frame that is not base64");
            return;
        };
        if bytes.len() > MAX_TERMINAL_INPUT {
            tracing::warn!(
                session = %session,
                bytes = bytes.len(),
                "dropping an oversized terminal input frame"
            );
            return;
        }
        handle.write(&bytes);
    }

    async fn terminal_close(&self, session: Uuid, actor: UserId, events: EventSink) {
        // Peek before removing, so a frame from the wrong account cannot even
        // detach somebody else's stream.
        if self.attached_handle(session, actor).await.is_none() {
            return;
        }
        let Some(attachment) = self.attached.lock().await.remove(&session) else {
            return;
        };
        attachment.pump.abort();
        if let Err(e) = self
            .agent
            .terminals
            .close(session, &attachment.auth, "closed by the client")
            .await
        {
            tracing::info!(session = %session, error = %e, "terminal close refused");
        }
        events
            .emit(terminal_state(session, actor, "closed", None, None))
            .await;
    }
}

/// Forward one session's scrollback and then its live output to a connection.
///
/// The replay comes first and carries the same sequence numbers the live stream
/// continues from, so a client that reconnected can drop what it already drew.
fn spawn_terminal_pump(
    handle: Arc<SessionHandle>,
    events: EventSink,
    attached: Arc<Mutex<std::collections::HashMap<Uuid, Attachment>>>,
) -> tokio::task::JoinHandle<()> {
    let session = handle.info.id;
    let owner = handle.info.owner;
    tokio::spawn(async move {
        let (replay, mut live) = handle.attach().await;
        for chunk in replay {
            if !events
                .emit(output_event(session, owner, chunk.seq, &chunk.data))
                .await
            {
                return;
            }
        }

        loop {
            tokio::select! {
                // Biased so a shell that exits mid-burst still gets its last
                // bytes delivered before the closing state.
                biased;
                received = live.recv() => match received {
                    Ok(chunk) => {
                        if !events
                            .emit(output_event(session, owner, chunk.seq, &chunk.data))
                            .await
                        {
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(session = %session, skipped, "terminal consumer lagged");
                        events
                            .emit(terminal_state(
                                session,
                                owner,
                                "lagged",
                                Some(format!("{skipped} chunks of output were dropped")),
                                None,
                            ))
                            .await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
                () = handle.ended() => break,
            }
        }

        events
            .emit(terminal_state(
                session,
                owner,
                "closed",
                Some("the shell exited".into()),
                None,
            ))
            .await;

        // Let the attachment go. Only when the session is actually finished:
        // this task is also aborted and replaced when the same connection
        // re-attaches, and that successor's entry must not be removed by its
        // predecessor. A live session's entry is removed by `terminal_close`
        // or by dropping the connection, as before.
        if handle.is_closed() {
            attached.lock().await.remove(&session);
        }
    })
}

fn output_event(session: Uuid, owner: UserId, seq: u64, data: &[u8]) -> EventFrame {
    EventFrame::new(EventKind::TerminalOutput {
        session,
        owner,
        seq,
        // Base64 because a shell writes bytes, not text: a UTF-8 sequence split
        // across two reads is routine and would make a JSON string invalid.
        data: BASE64.encode(data),
    })
}

fn event_task_id(event: &EventFrame) -> Option<TaskId> {
    match &event.kind {
        EventKind::TaskLog { task_id, .. } | EventKind::TaskState { task_id, .. } => Some(*task_id),
        // Terminal traffic never rides the task bus: it is point-to-point
        // between one connection and one PTY, so broadcasting it to every
        // connected client would be handing a shell's output to whoever else
        // happened to be connected.
        EventKind::Pong { .. }
        | EventKind::TerminalOutput { .. }
        | EventKind::TerminalState { .. } => None,
    }
}

/// The `terminal.state` event, in one place so the wording is consistent.
fn terminal_state(
    session: Uuid,
    owner: UserId,
    status: &str,
    detail: Option<String>,
    user: Option<String>,
) -> EventFrame {
    EventFrame::new(EventKind::TerminalState {
        session,
        owner,
        status: status.to_string(),
        detail,
        user,
    })
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
            // --- web terminal (spec 11.16) ---------------------------------
            ControlKind::TerminalOpen {
                session,
                target,
                cols,
                rows,
                auth,
            } => {
                self.terminal_open(session, target, cols, rows, auth, events)
                    .await;
            }
            ControlKind::TerminalAttach { session, auth } => {
                self.terminal_attach(session, auth, events).await;
            }
            ControlKind::TerminalInput {
                session,
                actor,
                data,
            } => {
                self.terminal_input(session, actor, &data, events).await;
            }
            ControlKind::TerminalResize {
                session,
                actor,
                cols,
                rows,
            } => {
                if let Some(handle) = self.attached_handle(session, actor).await {
                    handle.resize(cols, rows);
                }
            }
            ControlKind::TerminalClose { session, actor } => {
                self.terminal_close(session, actor, events).await;
            }
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
