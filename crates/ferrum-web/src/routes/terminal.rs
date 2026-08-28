//! The web terminal's HTTP face, and the SSH key manager (spec §11.16).
//!
//! **This file fronts the most dangerous surface in the panel.** The shell
//! itself lives in `ferrum_ops::terminal`, which says so at length and holds
//! every authorisation decision; nothing here decides who gets a shell. What
//! this file owns is the *transport*, and the transport has two problems of its
//! own worth stating plainly.
//!
//! # A WebSocket cannot carry the CSRF header
//!
//! Every mutation in this API presents `x-ferrum-csrf` (spec §12.7), and the
//! browser WebSocket API has no way to set a request header. The cookie alone
//! is `SameSite=Strict`, which browsers do already withhold from a cross-site
//! WebSocket handshake — but "the browser will not do that" is a single point
//! of failure for a root shell, and it is exactly the kind of assumption that
//! stops being true after a spec change.
//!
//! So opening a terminal takes two steps:
//!
//! 1. `POST /api/terminal/sessions` — an ordinary mutation, so it carries the
//!    session cookie *and* the CSRF header, and answers with a single-use
//!    ticket that expires in [`TICKET_TTL`].
//! 2. `GET /api/terminal/ws?ticket=…` — the upgrade, which requires the ticket
//!    **and** the session cookie, and requires the two to name the same
//!    account.
//!
//! A cross-site page cannot obtain a ticket (step 1 needs the CSRF token, which
//! it cannot read), and a leaked ticket is useless without the session cookie
//! and dead within a minute either way. The ticket is in the query string
//! because that is the only channel the browser gives us; it is a capability
//! with a one-minute life, not an identity, and it is never logged.
//!
//! # Closing the socket must not close the shell
//!
//! Spec §11.16's acceptance criterion is that a session survives a `ferrum-web`
//! restart. A restart looks exactly like a dropped WebSocket, so a socket that
//! ended is never taken as a request to end the session — only an explicit
//! `close` message is. Sessions nobody comes back to are reaped by the agent's
//! idle sweep.

use std::sync::OnceLock;
use std::time::Duration;

use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use ferrum_core::{ErrorCode, Permission, UserId};
use ferrum_db::audit::NewAuditEntry;
use ferrum_ipc::frame::{ControlKind, EventKind, TerminalTarget};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use tokio::sync::Mutex;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// How long a ticket is worth anything.
///
/// Long enough for a browser to follow one redirect and open a socket, short
/// enough that a ticket sitting in a proxy log or a browser history entry has
/// already expired by the time anyone reads it.
const TICKET_TTL: Duration = Duration::from_secs(60);

/// A hard cap on unredeemed tickets, so a loop of `POST /api/terminal/sessions`
/// cannot grow the web process's memory. Tickets are tiny and expire in a
/// minute; this only ever trips under abuse.
const MAX_PENDING_TICKETS: usize = 256;

/// The largest message the browser may send us, matching the agent's own input
/// ceiling once base64 expansion is accounted for.
const MAX_CLIENT_MESSAGE: usize = 128 * 1024;

// ---------------------------------------------------------------------------
// Tickets
// ---------------------------------------------------------------------------

/// What a redeemed ticket authorises.
#[derive(Debug, Clone)]
struct Ticket {
    user_id: UserId,
    session: Uuid,
    /// `None` for a re-attach: the session already exists and its target was
    /// decided (and audited) when it was opened.
    open: Option<OpenParams>,
    expires: time::OffsetDateTime,
}

#[derive(Debug, Clone)]
struct OpenParams {
    target: TerminalTarget,
    cols: u16,
    rows: u16,
}

/// Single-use tickets awaiting their WebSocket.
#[derive(Default)]
pub struct TicketStore {
    tickets: Mutex<std::collections::HashMap<String, Ticket>>,
}

impl TicketStore {
    async fn issue(&self, ticket: Ticket) -> Option<String> {
        let mut tickets = self.tickets.lock().await;
        let now = time::OffsetDateTime::now_utc();
        tickets.retain(|_, t| t.expires > now);
        if tickets.len() >= MAX_PENDING_TICKETS {
            return None;
        }
        // Two v4 UUIDs: 244 bits from the platform CSPRNG, which is what a
        // bearer token for a root shell should be made of. Using `uuid` rather
        // than adding a random-number dependency keeps the crate's surface as
        // it was; the entropy source is the same `getrandom` either way.
        let token = format!(
            "{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        tickets.insert(token.clone(), ticket);
        Some(token)
    }

    /// Take a ticket, if it is live. Removing it *is* the single-use rule.
    async fn redeem(&self, token: &str) -> Option<Ticket> {
        let mut tickets = self.tickets.lock().await;
        let ticket = tickets.remove(token)?;
        (ticket.expires > time::OffsetDateTime::now_utc()).then_some(ticket)
    }
}

/// The process-wide store.
///
/// A static rather than a field on `AppState` because a ticket is meaningful
/// only to the process that issued it — it is redeemed seconds later by the
/// same binary — and because the alternative would put a mutable side-table on
/// the state every other route shares. Restarting `ferrum-web` invalidates
/// every outstanding ticket, which is correct: the browser simply asks for
/// another one, and the *session* it names is on the agent and still alive.
fn tickets() -> &'static TicketStore {
    static STORE: OnceLock<TicketStore> = OnceLock::new();
    STORE.get_or_init(TicketStore::default)
}

// ---------------------------------------------------------------------------
// POST /api/terminal/sessions
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct OpenRequest {
    /// `root` for an administrator's root shell, or `tenant` for a shell as a
    /// subscription's Linux account. Ignored when `session_id` is set.
    #[serde(default)]
    pub target: Option<TargetBody>,
    /// Which subscription a `tenant` shell belongs to. Omitted means "my own";
    /// an administrator must name one, because their scope is the whole server.
    #[serde(default)]
    pub subscription_id: Option<i64>,
    #[serde(default = "default_cols")]
    pub cols: u16,
    #[serde(default = "default_rows")]
    pub rows: u16,
    /// Re-attach to a session that is still running instead of opening a new
    /// one — the reconnect after a dropped socket or a panel restart.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub session_id: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetBody {
    Root,
    Tenant,
}

fn default_cols() -> u16 {
    80
}

fn default_rows() -> u16 {
    24
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OpenResponse {
    /// The id to reconnect with. Stable for the life of the shell.
    #[schema(value_type = String)]
    pub session_id: Uuid,
    /// Single-use, expires in a minute. Present it on the WebSocket URL.
    pub ticket: String,
    /// Seconds until the ticket expires, so a client can decide to ask again
    /// rather than opening a socket it knows will be refused.
    pub expires_in: u64,
    /// Where to connect.
    pub websocket_url: String,
}

/// Ask for a terminal session and get the ticket that opens it.
///
/// This does not start a shell: the agent does that when the WebSocket arrives
/// and it has re-derived the caller's rights for itself. What it does is prove
/// the request came from the panel's own UI, which is the one thing the socket
/// handshake cannot do for itself.
#[utoipa::path(
    post,
    path = "/api/terminal/sessions",
    tag = "terminal",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = OpenRequest,
    responses(
        (status = 200, description = "A session id and a single-use ticket for the WebSocket", body = OpenResponse),
        (status = 400, description = "`invalid_input`: an administrator asked for a tenant shell without naming a subscription", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `terminal_access` / `csrf_invalid`", body = ApiErrorBody),
        (status = 429, description = "`rate_limited`: too many unredeemed tickets", body = ApiErrorBody),
    ),
)]
pub async fn open(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<OpenRequest>,
) -> ApiResult<Json<OpenResponse>> {
    // The agent checks this again against the database, and the plan flag on
    // top of it. Checking here as well means a caller with no business asking
    // never gets so far as a ticket.
    current
        .auth
        .require(Permission::TerminalAccess)
        .map_err(ApiError::from)?;

    let (session, open) = match body.session_id {
        Some(session) => (session, None),
        None => {
            let target = match body.target.unwrap_or(TargetBody::Tenant) {
                TargetBody::Root => TerminalTarget::Root,
                TargetBody::Tenant => TerminalTarget::Tenant {
                    subscription_id: body.subscription_id,
                },
            };
            (
                Uuid::new_v4(),
                Some(OpenParams {
                    target,
                    cols: body.cols.clamp(1, 500),
                    rows: body.rows.clamp(1, 300),
                }),
            )
        }
    };

    // The agent writes the authoritative `terminal.open` row before the PTY
    // exists. This one records the *request*, with the address it came from —
    // which the agent never sees, because the IPC socket has no client address.
    audit_request(&state, &current, &headers, &peer, session, open.as_ref()).await?;

    let expires = time::OffsetDateTime::now_utc() + TICKET_TTL;
    let ticket = tickets()
        .issue(Ticket {
            user_id: current.user.id,
            session,
            open,
            expires,
        })
        .await
        .ok_or_else(|| {
            ApiError::code(
                ErrorCode::RateLimited,
                "too many terminal sessions are being opened; try again in a minute",
            )
        })?;

    Ok(Json(OpenResponse {
        session_id: session,
        websocket_url: format!("/api/terminal/ws?ticket={ticket}"),
        ticket,
        expires_in: TICKET_TTL.as_secs(),
    }))
}

async fn audit_request(
    state: &SharedState,
    current: &CurrentUser,
    headers: &HeaderMap,
    peer: &SocketAddr,
    session: Uuid,
    open: Option<&OpenParams>,
) -> ApiResult<()> {
    let detail = json!({
        "session": session,
        "reattach": open.is_none(),
        "root": matches!(open.map(|o| &o.target), Some(TerminalTarget::Root)),
    });
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(peer), headers)),
            action: "terminal.request".into(),
            target: Some(session.to_string()),
            detail,
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/terminal/ws
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct WsQuery {
    /// The single-use ticket from `POST /api/terminal/sessions`.
    pub ticket: String,
}

/// The terminal's byte pipe.
///
/// Both credentials are required: the ticket (which only the panel's own UI can
/// obtain, because issuing one takes the CSRF header) and the session cookie,
/// and they must name the same account. Either alone is not enough.
#[utoipa::path(
    get,
    path = "/api/terminal/ws",
    tag = "terminal",
    security(("session_cookie" = [])),
    params(WsQuery),
    responses(
        (status = 101, description = "Upgraded. Messages are JSON: `{type:\"input\"|\"resize\"|\"close\"}` up, `{type:\"output\"|\"state\"}` down; `data` is base64 because a shell writes bytes, not text"),
        (status = 401, description = "`session_invalid`, or a ticket that has expired, been used, or belongs to another account", body = ApiErrorBody),
    ),
)]
pub async fn ws(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<WsQuery>,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    let ticket = tickets().redeem(&q.ticket).await.ok_or_else(|| {
        ApiError::code(
            ErrorCode::SessionInvalid,
            "this terminal ticket has expired or was already used",
        )
    })?;

    // A ticket is a capability, not an identity: it says *what* may be opened,
    // and the cookie says *who* is asking. Requiring them to agree means a
    // leaked ticket is worth nothing without the session it was issued to.
    if ticket.user_id != current.user.id {
        return Err(ApiError::code(
            ErrorCode::SessionInvalid,
            "this terminal ticket belongs to a different account",
        ));
    }

    let auth = current.auth.clone();
    Ok(upgrade.on_upgrade(move |socket| bridge(state, socket, ticket, auth)))
}

/// What the browser sends us.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    /// Keystrokes, base64.
    Input { data: String },
    Resize { cols: u16, rows: u16 },
    /// End the session for real. Nothing else does — see the module docs.
    Close,
}

/// Pump bytes between one browser socket and one agent-side PTY.
///
/// Note what this function does *not* do when the socket ends: close the
/// session. That is the whole reconnect story (spec §11.16 AC).
async fn bridge(
    state: SharedState,
    socket: WebSocket,
    ticket: Ticket,
    auth: ferrum_core::AuthContext,
) {
    use futures::{SinkExt, StreamExt};

    let session = ticket.session;
    let (mut sink, mut stream) = socket.split();

    // Subscribe before asking, so the agent's answer cannot arrive before we
    // are listening for it.
    let mut events = state.agent.events();

    let control = match &ticket.open {
        Some(params) => ControlKind::TerminalOpen {
            session,
            target: params.target.clone(),
            cols: params.cols,
            rows: params.rows,
            auth: auth.clone(),
        },
        None => ControlKind::TerminalAttach {
            session,
            auth: auth.clone(),
        },
    };
    if let Err(e) = state.agent.control(control).await {
        let _ = sink
            .send(Message::Text(
                json!({ "type": "state", "status": "denied", "detail": e.detail }).to_string().into(),
            ))
            .await;
        return;
    }

    // Agent → browser.
    let downstream = tokio::spawn(async move {
        loop {
            let frame = match events.recv().await {
                Ok(frame) => frame,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            // Every connected client sees every agent event; the session id is
            // what makes this socket only ever forward its own.
            let payload = match &frame.kind {
                EventKind::TerminalOutput {
                    session: id,
                    seq,
                    data,
                } if *id == session => {
                    json!({ "type": "output", "seq": seq, "data": data })
                }
                EventKind::TerminalState {
                    session: id,
                    status,
                    detail,
                    user,
                } if *id == session => {
                    json!({
                        "type": "state",
                        "status": status,
                        "detail": detail,
                        "user": user,
                    })
                }
                _ => continue,
            };
            let terminal = matches!(&frame.kind, EventKind::TerminalState { status, .. }
                if status == "closed" || status == "denied");
            if sink
                .send(Message::Text(payload.to_string().into()))
                .await
                .is_err()
            {
                break;
            }
            if terminal {
                let _ = sink.close().await;
                break;
            }
        }
    });

    // Browser → agent.
    while let Some(Ok(message)) = stream.next().await {
        let text = match message {
            Message::Text(text) => text,
            // A browser that sends binary is not our client; ping/pong and
            // close are handled by the library and by the loop ending.
            Message::Close(_) => break,
            _ => continue,
        };
        if text.len() > MAX_CLIENT_MESSAGE {
            tracing::warn!(session = %session, "dropping an oversized terminal message");
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<ClientMessage>(&text) else {
            continue;
        };

        let control = match parsed {
            ClientMessage::Input { data } => ControlKind::TerminalInput { session, data },
            ClientMessage::Resize { cols, rows } => ControlKind::TerminalResize {
                session,
                cols: cols.clamp(1, 500),
                rows: rows.clamp(1, 300),
            },
            ClientMessage::Close => {
                let _ = state
                    .agent
                    .control(ControlKind::TerminalClose { session })
                    .await;
                break;
            }
        };
        if state.agent.control(control).await.is_err() {
            break;
        }
    }

    // The socket is done; the shell is not. Only the explicit `close` above
    // ends a session, so a reload reconnects to the same shell.
    downstream.abort();
}

// ---------------------------------------------------------------------------
// SSH keys
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct KeysQuery {
    /// Whose keys. Omitted means the caller's own subscription.
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

/// The keys in the account's Ferrum-managed `authorized_keys` block.
#[utoipa::path(
    get,
    path = "/api/ssh-keys",
    tag = "terminal",
    security(("session_cookie" = [])),
    params(KeysQuery),
    responses(
        (status = 200, description = "Fingerprints, algorithms, comments and key sizes, plus whether the file holds keys the panel does not manage", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `plan_feature_disabled`: the plan has no `can_ssh`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such subscription in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn keys_list(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<KeysQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::TerminalAccess)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "ssh.keys.list",
        json!({ "subscription_id": q.subscription_id }),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddKeyRequest {
    /// One `authorized_keys` line: `<algorithm> <base64> [comment]`. Options
    /// such as `command=` are refused, and so is anything but a single line.
    #[schema(example = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… farzam@laptop")]
    pub key: String,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

/// Install a public key.
#[utoipa::path(
    post,
    path = "/api/ssh-keys",
    tag = "terminal",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = AddKeyRequest,
    responses(
        (status = 200, description = "The stored key's fingerprint and how many the account now has", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: the `key` field is named in the error — a bad type, a body that disagrees with it, an options prefix, or a key that is not one line", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid` / `plan_feature_disabled`", body = ApiErrorBody),
        (status = 409, description = "`already_exists`: that fingerprint is already installed / `config_drift`: the block in authorized_keys is not intact", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn keys_add(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<AddKeyRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::TerminalAccess)
        .map_err(ApiError::from)?;

    // The key itself is public by definition, but it is a credential's other
    // half: recording *which* key was installed is the point of the row, and
    // the fingerprint the agent returns is the readable form of that.
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "ssh.keys.add",
        json!({ "key": body.key, "subscription_id": body.subscription_id }),
    )
    .await?;

    audit_keys(
        &state,
        &current,
        &headers,
        &peer,
        "ssh.keys.add",
        data.get("key")
            .and_then(|k| k.get("fingerprint"))
            .and_then(|f| f.as_str())
            .unwrap_or("unknown"),
        body.subscription_id,
    )
    .await?;
    Ok(Json(data))
}

/// Remove a public key by fingerprint.
#[utoipa::path(
    delete,
    path = "/api/ssh-keys/{fingerprint}",
    tag = "terminal",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(
        ("fingerprint" = String, Path, description = "The `SHA256:…` fingerprint from the list"),
        KeysQuery,
    ),
    responses(
        (status = 200, description = "Whether a key was removed, and how many remain", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid` / `plan_feature_disabled`", body = ApiErrorBody),
        (status = 409, description = "`config_drift`: the block in authorized_keys is not intact", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn keys_remove(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Path(fingerprint): Path<String>,
    Query(q): Query<KeysQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::TerminalAccess)
        .map_err(ApiError::from)?;

    audit_keys(
        &state,
        &current,
        &headers,
        &peer,
        "ssh.keys.remove",
        &fingerprint,
        q.subscription_id,
    )
    .await?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "ssh.keys.remove",
        json!({ "fingerprint": fingerprint, "subscription_id": q.subscription_id }),
    )
    .await?;
    Ok(Json(data))
}

async fn audit_keys(
    state: &SharedState,
    current: &CurrentUser,
    headers: &HeaderMap,
    peer: &SocketAddr,
    action: &str,
    fingerprint: &str,
    subscription_id: Option<i64>,
) -> ApiResult<()> {
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(peer), headers)),
            action: action.to_string(),
            target: Some(fingerprint.to_string()),
            detail: json!({ "subscription_id": subscription_id }),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket(user: u32, expires_in: i64) -> Ticket {
        Ticket {
            user_id: UserId(user as i64),
            session: Uuid::new_v4(),
            open: Some(OpenParams {
                target: TerminalTarget::Root,
                cols: 80,
                rows: 24,
            }),
            expires: time::OffsetDateTime::now_utc() + time::Duration::seconds(expires_in),
        }
    }

    #[tokio::test]
    async fn a_ticket_works_exactly_once() {
        // The WebSocket URL is the one place a credential of ours is visible in
        // a browser history and a proxy log, so it must be worthless the moment
        // after it is used.
        let store = TicketStore::default();
        let token = store.issue(ticket(1, 60)).await.unwrap();

        assert!(store.redeem(&token).await.is_some());
        assert!(
            store.redeem(&token).await.is_none(),
            "a replayed ticket must open nothing"
        );
    }

    #[tokio::test]
    async fn an_expired_ticket_opens_nothing() {
        let store = TicketStore::default();
        let token = store.issue(ticket(1, -1)).await.unwrap();
        assert!(store.redeem(&token).await.is_none());
    }

    #[tokio::test]
    async fn an_unknown_ticket_opens_nothing() {
        let store = TicketStore::default();
        assert!(store.redeem("not-a-ticket").await.is_none());
        // And a token from a different store — i.e. a restarted web process —
        // is equally worthless.
        let other = TicketStore::default();
        let token = other.issue(ticket(1, 60)).await.unwrap();
        assert!(store.redeem(&token).await.is_none());
    }

    #[tokio::test]
    async fn tickets_are_unguessable_and_bounded_in_number() {
        let store = TicketStore::default();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..MAX_PENDING_TICKETS {
            let token = store.issue(ticket(1, 60)).await.unwrap();
            assert_eq!(token.len(), 64, "two v4 UUIDs' worth of hex");
            assert!(seen.insert(token), "tickets must never repeat");
        }
        assert!(
            store.issue(ticket(1, 60)).await.is_none(),
            "a loop of open requests must not grow the process without bound"
        );
    }

    #[tokio::test]
    async fn expired_tickets_are_swept_so_the_cap_is_not_a_permanent_lockout() {
        let store = TicketStore::default();
        for _ in 0..MAX_PENDING_TICKETS {
            store.issue(ticket(1, -1)).await.unwrap();
        }
        assert!(
            store.issue(ticket(1, 60)).await.is_some(),
            "dead tickets must not hold the budget"
        );
    }

    #[test]
    fn client_messages_parse_into_exactly_the_three_verbs_we_accept() {
        // A message the terminal does not understand must not become one it
        // does: this is the whole surface the browser can reach.
        let input: ClientMessage =
            serde_json::from_str(r#"{"type":"input","data":"bHM="}"#).unwrap();
        assert!(matches!(input, ClientMessage::Input { .. }));
        let resize: ClientMessage =
            serde_json::from_str(r#"{"type":"resize","cols":120,"rows":40}"#).unwrap();
        assert!(matches!(
            resize,
            ClientMessage::Resize {
                cols: 120,
                rows: 40
            }
        ));
        assert!(matches!(
            serde_json::from_str::<ClientMessage>(r#"{"type":"close"}"#).unwrap(),
            ClientMessage::Close
        ));

        for bad in [
            r#"{"type":"exec","command":"rm -rf /"}"#,
            r#"{"type":"open","target":"root"}"#,
            r#"{"data":"bHM="}"#,
            r#"not json"#,
        ] {
            assert!(
                serde_json::from_str::<ClientMessage>(bad).is_err(),
                "accepted {bad}"
            );
        }
    }
}
