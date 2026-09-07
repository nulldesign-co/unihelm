//! The web terminal's HTTP face, and the SSH key manager (spec §11.16).
//!
//! **This file fronts the most dangerous surface in the panel.** The shell
//! itself lives in `unihelm_ops::terminal`, which says so at length and holds
//! every authorisation decision; nothing here decides who gets a shell. What
//! this file owns is the *transport*, and the transport has two problems of its
//! own worth stating plainly.
//!
//! # A WebSocket cannot carry the CSRF header
//!
//! Every mutation in this API presents `x-unihelm-csrf` (spec §12.7), and the
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
//! Step 2 also refuses a handshake whose `Origin` names a host other than the
//! one the request was addressed to. Be clear about what that is worth: it is
//! **not** what holds the door today. `SameSite=Strict` is — a cross-site
//! handshake carries no session cookie, so `CurrentUser` turns it away and no
//! ticket is ever consulted. The `Origin` check is the second lock, and it is
//! written down here so nobody removes the first one believing this replaced
//! it: loosen the cookie for some future sign-in flow and this becomes the
//! only thing between a page on the internet and a root shell. A handshake
//! with *no* `Origin` is allowed through, because only browsers send one — the
//! CLI and every other non-browser client do not, and refusing them would
//! break the terminal for the people least placed to work out why.
//!
//! # One agent connection, many browsers
//!
//! `unihelm-web` multiplexes every browser it serves over a *single* IPC
//! connection, so the agent's terminal events arrive here on one broadcast that
//! every open socket can see, and every control frame this file sends leaves by
//! the same wire. Neither direction may be routed by session id alone: an id is
//! an identifier, not an authorisation.
//!
//! So both directions carry the account. Frames going out carry `actor` (the
//! account this request authenticated as) and the agent refuses one whose actor
//! does not own the session it names; frames coming back carry `owner` and
//! [`socket_payload`] forwards a chunk only when both the session *and* the
//! owner match this socket. Either check alone would leave a shell's output one
//! guessed UUID away from the wrong browser.
//!
//! # Closing the socket must not close the shell
//!
//! Spec §11.16's acceptance criterion is that a session survives a `unihelm-web`
//! restart. A restart looks exactly like a dropped WebSocket, so a socket that
//! ended is never taken as a request to end the session — only an explicit
//! `close` message is. Sessions nobody comes back to are reaped by the agent's
//! idle sweep.
//!
//! # A hole in the output is named, never hidden
//!
//! The agent's event broadcast is bounded, so a socket that cannot keep up with
//! a burst of output — a build, a `cat` of a large file — has frames dropped out
//! from under it to make room. This loop used to answer that with a bare
//! `continue`: the browser then rendered the surviving frames end to end, so a
//! log read through the terminal came out with pieces missing and *looked* like
//! the file. Somebody reading it got a wrong answer and had no way to know.
//!
//! So lag is counted, logged, and sent down the socket as a `lagged` state the
//! terminal draws as a visible break. Nothing here retries: the channel is
//! bounded and the frames are already gone, so there is nothing to ask for. A
//! gap the operator can see is the whole point.

use std::sync::OnceLock;
use std::time::Duration;

use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use tokio::sync::Mutex;
use unihelm_core::{ErrorCode, Permission, UserId};
use unihelm_db::audit::NewAuditEntry;
use unihelm_ipc::frame::{ControlKind, EventKind, TerminalTarget};
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

/// And the most any one account may hold of that budget.
///
/// `terminal::session` already refuses to let one account take every session
/// (`Limits::max_per_user`, 3). The ticket in front of a session needs the same
/// rule, or the cheaper endpoint becomes the way around the expensive one: a
/// loop of mint requests would fill the global table and every *other* account
/// — including the admin reaching for a root shell mid-incident — would be
/// refused. Four leaves room for a re-attach racing an unredeemed open.
const MAX_PENDING_TICKETS_PER_USER: usize = 4;

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
        let mine = tickets
            .values()
            .filter(|t| t.user_id == ticket.user_id)
            .count();
        if mine >= MAX_PENDING_TICKETS_PER_USER {
            return None;
        }
        // Two v4 UUIDs: 244 bits from the platform CSPRNG, which is what a
        // bearer token for a root shell should be made of. Using `uuid` rather
        // than adding a random-number dependency keeps the crate's surface as
        // it was; the entropy source is the same `getrandom` either way.
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
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
/// the state every other route shares. Restarting `unihelm-web` invalidates
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
        (status = 403, description = "`csrf_invalid`: the handshake carried an `Origin` naming a different host than it was sent to", body = ApiErrorBody),
    ),
)]
pub async fn ws(
    State(state): State<SharedState>,
    current: CurrentUser,
    headers: HeaderMap,
    Query(q): Query<WsQuery>,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    // Before the ticket, not after: redeeming is what makes a ticket single-use,
    // so a handshake we were always going to refuse must not be allowed to burn
    // the one the operator's own tab is about to present.
    let origin = headers.get(header::ORIGIN).map(HeaderValue::as_bytes);
    let host = headers.get(header::HOST).map(HeaderValue::as_bytes);
    if !origin_permits_upgrade(origin, host) {
        return Err(ApiError::code(
            ErrorCode::CsrfInvalid,
            format!(
                "refusing a terminal WebSocket sent from {} to host {}: the panel upgrades \
                 a handshake only when the Origin names the host the request was addressed \
                 to. If the panel sits behind a proxy, have it forward the browser's own \
                 Host header rather than rewriting it to the backend's address.",
                origin.map_or_else(
                    || "an unnamed origin".into(),
                    |o| String::from_utf8_lossy(o)
                ),
                host.map_or_else(
                    || "(none: the request carried no Host header)".into(),
                    |h| String::from_utf8_lossy(h)
                ),
            ),
        ));
    }

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

/// May a handshake carrying this `Origin`, addressed to this `Host`, be
/// upgraded?
///
/// Three answers, and the reasoning behind each is the point:
///
/// - **No `Origin` at all: yes.** Only browsers attach one. The CLI, `wscat`
///   and anything else scripting the panel send none, and the attack this
///   guards against is a *browser* being talked into opening a socket with an
///   operator's cookies attached — which is precisely the case that does
///   announce itself. Refusing the silent clients would cost the terminal for
///   users who could not diagnose it and buy nothing.
/// - **An `Origin` naming this host: yes.** Compared as whole authorities,
///   port included, so `panel:8443` and `panel:9999` are different origins —
///   which they are.
/// - **Anything else: no.** `null` (a sandboxed iframe, a `file://` page) and
///   custom schemes have no host to match and fall out here. So does an
///   `Origin` with no `Host` to compare against: "cannot show they agree" is
///   not "same origin", and on HTTP/1.1 a handshake without a `Host` is
///   already malformed.
///
/// Bytes rather than `&str` deliberately: a header that is not valid UTF-8 must
/// come out of this as *some* origin that does not match, never as no origin at
/// all, and a lossy conversion up front is one more place to get that backwards.
///
/// See the module docs for why this is defence in depth behind
/// `SameSite=Strict` rather than the thing currently doing the work.
fn origin_permits_upgrade(origin: Option<&[u8]>, host: Option<&[u8]>) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    let Some(authority) = origin
        .strip_prefix(b"https://")
        .or_else(|| origin.strip_prefix(b"http://"))
    else {
        return false;
    };
    host.is_some_and(|host| authority.eq_ignore_ascii_case(host))
}

/// What the browser sends us.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    /// Keystrokes, base64.
    Input {
        data: String,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
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
    auth: unihelm_core::AuthContext,
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
                json!({ "type": "state", "status": "denied", "detail": e.detail })
                    .to_string()
                    .into(),
            ))
            .await;
        return;
    }

    // Agent → browser.
    let viewer = ticket.user_id;
    let downstream = tokio::spawn(async move {
        loop {
            let frame = match events.recv().await {
                Ok(frame) => frame,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    // The frames are gone; the only thing left to do with them
                    // is say so. See the module docs for what the old silent
                    // `continue` cost.
                    tracing::warn!(
                        session = %session,
                        skipped,
                        "a terminal socket fell behind the agent broadcast; output was dropped"
                    );
                    if sink
                        .send(Message::Text(lag_notice(skipped).to_string().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            let Some(payload) = socket_payload(&frame.kind, session, viewer) else {
                continue;
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

        // `actor` on every frame, not just the first: the agent's attachment
        // table is shared between every browser this process serves.
        let control = match parsed {
            ClientMessage::Input { data } => ControlKind::TerminalInput {
                session,
                actor: viewer,
                data,
            },
            ClientMessage::Resize { cols, rows } => ControlKind::TerminalResize {
                session,
                actor: viewer,
                cols: cols.clamp(1, 500),
                rows: rows.clamp(1, 300),
            },
            ClientMessage::Close => {
                let _ = state
                    .agent
                    .control(ControlKind::TerminalClose {
                        session,
                        actor: viewer,
                    })
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

/// What the browser is told when the broadcast dropped frames under this socket.
///
/// Carried in `detail` — the same field a refusal uses — so the terminal can
/// print the server's own sentence and the count travels without the wire
/// protocol growing a field for one message kind.
///
/// The wording is hedged on purpose, and the hedge is the honest part. This
/// process multiplexes every browser and every task over one broadcast, so
/// `skipped` counts *events*, not this shell's bytes, and some of them will have
/// belonged to another session entirely. "May be missing" is the strongest claim
/// the panel can actually support; "you lost 142 lines" would be the same class
/// of lie as saying nothing.
fn lag_notice(skipped: u64) -> serde_json::Value {
    json!({
        "type": "state",
        "status": "lagged",
        "detail": format!(
            "the panel's event stream fell behind and dropped {skipped} \
             message{}; some output above may be missing",
            if skipped == 1 { "" } else { "s" },
        ),
        "user": serde_json::Value::Null,
    })
}

/// Should this agent event go down this socket, and as what?
///
/// Both halves of the guard are load-bearing, and the second one is the
/// unobvious one: every socket in this process sees every terminal event, so a
/// session-id-only match would put one account's shell output into another
/// account's browser the moment somebody guessed — or was told — a session id.
/// The owner check makes the id irrelevant to the decision.
fn socket_payload(kind: &EventKind, session: Uuid, viewer: UserId) -> Option<serde_json::Value> {
    match kind {
        EventKind::TerminalOutput {
            session: id,
            owner,
            seq,
            data,
        } if *id == session && *owner == viewer => {
            Some(json!({ "type": "output", "seq": seq, "data": data }))
        }
        EventKind::TerminalState {
            session: id,
            owner,
            status,
            detail,
            user,
        } if *id == session && *owner == viewer => Some(json!({
            "type": "state",
            "status": status,
            "detail": detail,
            "user": user,
        })),
        _ => None,
    }
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

/// The keys in the account's Unihelm-managed `authorized_keys` block.
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
    async fn one_account_cannot_spend_the_whole_ticket_budget() {
        // Otherwise the cheap endpoint is the way around the expensive one: a
        // customer who cannot even be given a shell loops the mint route, fills
        // the table, and the admin's root shell is refused for as long as it
        // runs.
        let store = TicketStore::default();
        for _ in 0..MAX_PENDING_TICKETS_PER_USER {
            assert!(store.issue(ticket(7, 60)).await.is_some());
        }
        assert!(
            store.issue(ticket(7, 60)).await.is_none(),
            "an account past its share is refused"
        );
        assert!(
            store.issue(ticket(8, 60)).await.is_some(),
            "and everybody else is unaffected"
        );
    }

    #[tokio::test]
    async fn tickets_are_unguessable_and_bounded_in_number() {
        let store = TicketStore::default();
        let mut seen = std::collections::HashSet::new();
        // Spread over accounts: one account cannot reach the global cap on its
        // own any more, which is what the next test is about.
        for i in 0..MAX_PENDING_TICKETS {
            let token = store
                .issue(ticket(i as u32 / MAX_PENDING_TICKETS_PER_USER as u32, 60))
                .await
                .unwrap();
            assert_eq!(token.len(), 64, "two v4 UUIDs' worth of hex");
            assert!(seen.insert(token), "tickets must never repeat");
        }
        assert!(
            store.issue(ticket(9999, 60)).await.is_none(),
            "a loop of open requests must not grow the process without bound"
        );
    }

    #[tokio::test]
    async fn expired_tickets_are_swept_so_the_cap_is_not_a_permanent_lockout() {
        let store = TicketStore::default();
        for i in 0..MAX_PENDING_TICKETS {
            store
                .issue(ticket(i as u32 / MAX_PENDING_TICKETS_PER_USER as u32, -1))
                .await
                .unwrap();
        }
        assert!(
            store.issue(ticket(1, 60)).await.is_some(),
            "dead tickets must not hold the budget"
        );
    }

    fn output(session: Uuid, owner: u32) -> EventKind {
        EventKind::TerminalOutput {
            session,
            owner: UserId(owner as i64),
            seq: 1,
            data: "cm9vdCMg".into(),
        }
    }

    #[test]
    fn a_socket_never_forwards_another_accounts_shell() {
        // One agent connection serves every browser, so every socket sees every
        // terminal event. A session id is an identifier; the owner is the
        // authorisation, and without it a guessed id would put a root shell's
        // output into somebody else's tab.
        let mine = Uuid::new_v4();
        let me = UserId(7);
        let you = UserId(8);

        assert!(socket_payload(&output(mine, 7), mine, me).is_some());

        // Same session id, different owner: refused. This is the case that
        // matters — it is what a guessed or leaked id looks like.
        assert!(socket_payload(&output(mine, 8), mine, me).is_none());
        // Same owner, different session: also refused, so a second tab of mine
        // does not double-render.
        assert!(socket_payload(&output(Uuid::new_v4(), 7), mine, me).is_none());
        // And from the other side of the same pair.
        assert!(socket_payload(&output(mine, 7), mine, you).is_none());
    }

    #[test]
    fn state_events_are_filtered_by_owner_as_well() {
        let session = Uuid::new_v4();
        let state = |owner: i64| EventKind::TerminalState {
            session,
            owner: UserId(owner),
            status: "open".into(),
            detail: None,
            user: Some("root".into()),
        };
        assert!(socket_payload(&state(7), session, UserId(7)).is_some());
        assert!(
            socket_payload(&state(8), session, UserId(7)).is_none(),
            "another account's session must not even announce itself here"
        );
    }

    #[test]
    fn task_events_never_leak_into_a_terminal_socket() {
        // The same broadcast carries task logs. A terminal socket forwards
        // exactly two event kinds and ignores the rest.
        let kind = EventKind::TaskLog {
            task_id: unihelm_core::TaskId::new(),
            seq: 1,
            line: "installing".into(),
        };
        assert!(socket_payload(&kind, Uuid::new_v4(), UserId(7)).is_none());
    }

    #[test]
    fn a_socket_that_fell_behind_tells_the_browser_how_much_it_missed() {
        // The loop used to `continue` here, so a burst of output arrived with
        // holes in it and the screen looked whole. The browser now gets a state
        // message it already knows how to draw as a break in the stream, and the
        // number is in it so "a frame or two" and "four thousand" are not the
        // same sentence.
        let notice = lag_notice(142);
        assert_eq!(notice["type"], "state");
        assert_eq!(
            notice["status"], "lagged",
            "the client switches on this string to draw the gap"
        );
        let detail = notice["detail"].as_str().unwrap_or_default();
        assert!(detail.contains("142"), "the count must reach the operator");
        assert!(
            detail.contains("may be missing"),
            "one broadcast carries every session, so this socket cannot claim \
             the dropped frames were its own: {detail}"
        );
        // `user` is null rather than absent: the client's state message has the
        // field on every variant, and a missing key is a shape it has not been
        // told to expect.
        assert!(notice["user"].is_null());

        // One dropped frame is still a gap, and it must not read as "1 messages".
        let one = lag_notice(1);
        let detail = one["detail"].as_str().unwrap_or_default();
        assert!(detail.contains("1 message;"), "{detail}");
    }

    /// Same shape a handshake arrives in, minus the header plumbing.
    fn upgrade_from(origin: Option<&str>, host: Option<&str>) -> bool {
        origin_permits_upgrade(origin.map(str::as_bytes), host.map(str::as_bytes))
    }

    #[test]
    fn the_panels_own_page_may_open_a_terminal() {
        // The ordinary case, in the three shapes a real install produces: a
        // domain on 443, the bare IP a fresh server is first reached on, and
        // the non-standard port an operator picked. Getting any of these wrong
        // takes the terminal away from someone who is entitled to it.
        assert!(upgrade_from(
            Some("https://panel.example.com"),
            Some("panel.example.com")
        ));
        assert!(upgrade_from(
            Some("https://198.51.100.7:8443"),
            Some("198.51.100.7:8443")
        ));
        assert!(upgrade_from(
            Some("http://127.0.0.1:8088"),
            Some("127.0.0.1:8088")
        ));
        // Hostnames are case-insensitive and browsers do not always agree with
        // the address bar about which case that is.
        assert!(upgrade_from(
            Some("https://Panel.Example.COM"),
            Some("panel.example.com")
        ));
    }

    #[test]
    fn a_handshake_from_another_site_is_refused() {
        // `SameSite=Strict` already means this request arrives with no session
        // cookie and dies at `CurrentUser`. This is the second lock, so that the
        // day the cookie attribute changes is not the day a root shell becomes
        // reachable from any page on the internet.
        assert!(!upgrade_from(
            Some("https://evil.example.net"),
            Some("panel.example.com")
        ));
        // The suffix trick, which a naive `ends_with` would wave through.
        assert!(!upgrade_from(
            Some("https://panel.example.com.evil.net"),
            Some("panel.example.com")
        ));
        // A different port is a different origin, and on a panel host that is
        // exactly where a tenant's own web app is listening.
        assert!(!upgrade_from(
            Some("https://panel.example.com:9999"),
            Some("panel.example.com:8443")
        ));
        // A sandboxed iframe or a `file://` page. No host to match, so no.
        assert!(!upgrade_from(Some("null"), Some("panel.example.com")));
        // An Origin we cannot compare against anything is not an Origin we can
        // call same-site.
        assert!(!upgrade_from(Some("https://panel.example.com"), None));
    }

    #[test]
    fn a_client_that_sends_no_origin_is_still_served() {
        // Only browsers send `Origin`. Rejecting a request without one would
        // break the CLI and every script against the panel, for no security
        // gain at all — the browser is the thing being defended against here,
        // and it always identifies itself.
        assert!(upgrade_from(None, Some("panel.example.com")));
        assert!(upgrade_from(None, None));
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
