//! A small SMTP submission client, written for one job: proving that the
//! configured relay actually accepts mail from this server (spec §11.18).
//!
//! # Why this exists rather than a dependency
//!
//! `mail.relay.test` has to report "the SMTP conversation's outcome honestly,
//! including a failure reason". A library that answers `Err(SendError)` cannot
//! do that: the useful information is *which* step failed and what the server
//! said — `550 5.7.1 Sender address rejected` at `MAIL FROM` and
//! `535 5.7.8 Authentication credentials invalid` at `AUTH` are two completely
//! different support tickets, and both arrive as "send failed" through a
//! typical API. This client keeps a transcript and names the stage, which is
//! the whole product value of the operation.
//!
//! It is deliberately not a general-purpose mailer: no queueing, no retries, no
//! MX resolution, no DSN handling. Sites send their mail through msmtp against
//! the same relay; this code path exists only for the panel's own test message
//! and, later, for panel notifications.
//!
//! # Two refusals that are the point
//!
//! 1. **Credentials never cross a plaintext connection.** If the operator
//!    configured `tls_mode = none` and also gave a username, the client aborts
//!    before `AUTH` rather than putting the password on the wire in base64,
//!    which is encoding and not encryption. `AUTH` over an unencrypted session
//!    is how a hosting provider's relay credential becomes everybody's.
//! 2. **A failed `STARTTLS` is fatal.** No fallback to plaintext, ever: an
//!    active attacker who can strip the `STARTTLS` capability from the EHLO
//!    response gets a cleartext session and, in a client that falls back,
//!    the credential with it.
//!
//! Related, and easy to miss: after `STARTTLS` the client asserts that its read
//! buffer is empty. A server (or a man in the middle) that pipelines data
//! before the TLS handshake is attempting the plaintext-injection attack that
//! CVE-2011-0411 named — bytes sent in the clear get treated as though they had
//! arrived inside the protected session. Discarding is what RFC 3207 §4.2
//! requires; treating it as an attack and aborting says so out loud.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use unihelm_db::TlsMode;

/// How long the whole conversation may take.
///
/// Bounded because this runs inside an immediate operation, and bounded *below*
/// `unihelm_ipc::DEFAULT_CALL_TIMEOUT` (30 s) on purpose: a relay that accepts
/// the TCP connection and then says nothing must produce a report naming the
/// stage it stalled at, not an `agent_timeout` with no transcript at all.
pub const CONVERSATION_BUDGET: Duration = Duration::from_secs(20);

/// How long one read may block. Smaller than the whole budget so a stalled step
/// is reported as *that* step stalling.
const STEP_TIMEOUT: Duration = Duration::from_secs(8);

/// The furthest the conversation got. This is what turns "it failed" into
/// something an operator can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// DNS resolution or the TCP connect itself.
    Connect,
    /// The TLS handshake, implicit or after `STARTTLS`.
    Tls,
    /// The server's opening `220`.
    Greeting,
    Ehlo,
    Starttls,
    Auth,
    MailFrom,
    RcptTo,
    Data,
    /// The message body and the terminating dot.
    Body,
    Quit,
}

impl Stage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Connect => "connect",
            Stage::Tls => "tls",
            Stage::Greeting => "greeting",
            Stage::Ehlo => "ehlo",
            Stage::Starttls => "starttls",
            Stage::Auth => "auth",
            Stage::MailFrom => "mail_from",
            Stage::RcptTo => "rcpt_to",
            Stage::Data => "data",
            Stage::Body => "body",
            Stage::Quit => "quit",
        }
    }

    /// One sentence naming what an operator should go and look at.
    ///
    /// A pure function so the wording is testable and the UI does not keep its
    /// own copy of this decision table — the same reasoning as
    /// `dns::advice_for`.
    pub const fn hint(self) -> &'static str {
        match self {
            Stage::Connect => {
                "The relay's host and port could not be reached. Check the address, and check \
                 that outbound connections on that port are not blocked by the firewall."
            }
            Stage::Tls => {
                "The TLS handshake failed. A self-signed or private-CA certificate will not \
                 verify against the public roots this client trusts."
            }
            Stage::Greeting => {
                "Something is listening on that port but it did not answer as an SMTP server."
            }
            Stage::Ehlo => {
                "The relay refused the greeting. Some relays reject unknown clients here."
            }
            Stage::Starttls => {
                "The relay did not offer or did not complete STARTTLS. Try implicit TLS on \
                 port 465, or plain submission on 587 only if the relay is on a private network."
            }
            Stage::Auth => {
                "The relay rejected the username and password. Many providers issue SMTP \
                 credentials separate from the account login."
            }
            Stage::MailFrom => {
                "The relay rejected the envelope sender. It usually means this address, or its \
                 domain, is not one the relay is authorised to send for."
            }
            Stage::RcptTo => {
                "The relay rejected the recipient. On a sandboxed provider account only \
                 verified recipients are accepted."
            }
            Stage::Data | Stage::Body => {
                "The relay accepted the envelope but rejected the message itself."
            }
            Stage::Quit => "The message was accepted; only the closing handshake was untidy.",
        }
    }
}

/// What happened, in enough detail to act on.
#[derive(Debug, Clone, Serialize)]
pub struct SendReport {
    pub delivered: bool,
    /// Where it stopped. On success, the last stage reached.
    pub stage: Stage,
    /// The server's own words, or the transport error. Never paraphrased —
    /// `550 5.7.1 Sender address rejected` is the answer, and rewording it
    /// helps nobody.
    pub detail: String,
    /// The last SMTP reply code seen, when there was one. Absent for a failure
    /// below the protocol (connect, TLS).
    pub code: Option<u16>,
    /// The conversation, redacted. Credentials are replaced before the line is
    /// ever pushed, so there is no window in which a transcript holds one.
    pub transcript: Vec<String>,
    /// Whether the session was encrypted when the message was handed over.
    /// A `true` here is the difference between a working relay and a working
    /// relay that anyone on the path can read.
    pub encrypted: bool,
}

impl SendReport {
    fn failure(stage: Stage, detail: impl Into<String>, transcript: Vec<String>) -> Self {
        Self {
            delivered: false,
            stage,
            detail: detail.into(),
            code: None,
            transcript,
            encrypted: false,
        }
    }
}

/// Where to connect and how to protect it.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub tls_mode: TlsMode,
}

/// The credential, if the relay wants one.
///
/// `password` is deliberately behind a manual `Debug` for the same reason
/// `dns::SecretToken` is: `#[derive(Debug)]` on a struct that transitively
/// holds this is the normal thing to write, and `tracing` renders it.
#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    password: String,
}

impl Credentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// One message.
#[derive(Debug, Clone)]
pub struct Message {
    pub from: String,
    pub from_name: Option<String>,
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// A field that would have been able to inject SMTP commands or extra headers.
///
/// Every address and header value crosses a line-oriented protocol, so a bare
/// CR or LF in one is not a formatting problem — it ends the current line and
/// starts a command the caller did not write. Rejecting is the only correct
/// answer; sanitising by stripping would silently send a message to an address
/// nobody typed.
pub fn reject_control_characters(field: &'static str, value: &str) -> Result<(), String> {
    if let Some(bad) = value
        .chars()
        .find(|c| *c == '\r' || *c == '\n' || *c == '\0' || c.is_control())
    {
        return Err(format!(
            "`{field}` contains a control character (U+{:04X}); in a line-oriented protocol \
             that is a way to inject a command or a header",
            bad as u32
        ));
    }
    Ok(())
}

/// One reply: the code plus every line of its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    pub fn text(&self) -> String {
        self.lines.join(" / ")
    }

    /// 2xx. SMTP's positive completion class.
    pub const fn is_positive(&self) -> bool {
        self.code >= 200 && self.code < 300
    }

    /// 3xx — "go ahead", which `DATA` and `AUTH` answer with mid-exchange.
    pub const fn is_intermediate(&self) -> bool {
        self.code >= 300 && self.code < 400
    }
}

/// Parse a complete multi-line SMTP reply out of the lines that make it up.
///
/// `250-PIPELINING` / `250 OK`: every line but the last carries `-` in the
/// fourth column. A reply whose lines disagree about the code is malformed, and
/// treating that as "the last code wins" is how a client accepts a `250` that a
/// `550` was hiding behind.
pub fn parse_reply(raw: &[String]) -> Result<Reply, String> {
    let mut code: Option<u16> = None;
    let mut lines = Vec::new();
    for line in raw {
        if line.len() < 3 {
            return Err(format!("`{line}` is too short to be an SMTP reply"));
        }
        let this: u16 = line[..3]
            .parse()
            .map_err(|_| format!("`{line}` does not start with a three-digit reply code"))?;
        match code {
            None => code = Some(this),
            Some(previous) if previous != this => {
                return Err(format!(
                    "the reply changed code mid-way ({previous} then {this}); refusing to guess \
                     which one the server meant"
                ));
            }
            Some(_) => {}
        }
        lines.push(
            line[3..]
                .trim_start_matches(['-', ' '])
                .trim_end()
                .to_string(),
        );
    }
    match code {
        Some(code) => Ok(Reply { code, lines }),
        None => Err("the server closed the connection without replying".into()),
    }
}

/// Is this line the last of a multi-line reply?
fn is_final_line(line: &str) -> bool {
    // `250 OK` ends it; `250-PIPELINING` does not. A three-character line with
    // nothing after it is also final — some servers send a bare `250`.
    line.len() == 3 || line.as_bytes().get(3) != Some(&b'-')
}

// ---------------------------------------------------------------------------
// the connection
// ---------------------------------------------------------------------------

enum Conn {
    Plain(BufReader<TcpStream>),
    Tls(Box<BufReader<TlsStream<TcpStream>>>),
    /// A transient placeholder, held only between taking the plaintext socket
    /// out for the `STARTTLS` handshake and putting the encrypted one back.
    ///
    /// Every method on it errors rather than silently succeeding, so an
    /// upgrade that failed and left it in place produces a loud failure on the
    /// next command instead of a session that quietly continued in the clear.
    Upgrading,
}

/// The one error text the placeholder ever produces.
fn upgrading() -> std::io::Error {
    std::io::Error::other("the connection is mid-upgrade and cannot be used")
}

impl Conn {
    async fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let framed = format!("{line}\r\n");
        self.write_raw(framed.as_bytes()).await
    }

    async fn write_raw(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => {
                s.get_mut().write_all(data).await?;
                s.get_mut().flush().await
            }
            Conn::Tls(s) => {
                s.get_mut().write_all(data).await?;
                s.get_mut().flush().await
            }
            Conn::Upgrading => Err(upgrading()),
        }
    }

    async fn read_line(&mut self, into: &mut String) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read_line(into).await,
            Conn::Tls(s) => s.read_line(into).await,
            Conn::Upgrading => Err(upgrading()),
        }
    }

    /// Bytes already read but not yet consumed.
    ///
    /// Only consulted at the `STARTTLS` boundary; see the module docs.
    fn buffered(&self) -> &[u8] {
        match self {
            Conn::Plain(s) => s.buffer(),
            Conn::Tls(s) => s.buffer(),
            Conn::Upgrading => &[],
        }
    }

    const fn is_encrypted(&self) -> bool {
        matches!(self, Conn::Tls(_))
    }
}

/// The TLS configuration this client uses, built once.
///
/// The crypto provider is named explicitly rather than taken from the process
/// default. `unihelm-ops` already links rustls with `aws-lc-rs` for ACME, and
/// `rustls`'s process default panics when more than one provider feature is
/// enabled in the graph and nothing has installed one — a panic at the first
/// mail test rather than at startup.
fn tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the default protocol versions are always supported")
    .with_root_certificates(roots)
    .with_no_client_auth();
    Arc::new(config)
}

/// A conversation in progress, plus its transcript.
struct Session {
    conn: Conn,
    transcript: Vec<String>,
    last_code: Option<u16>,
}

impl Session {
    fn note(&mut self, line: impl Into<String>) {
        // Bounded: a server that answers every command with two hundred lines
        // of banner must not be able to grow an operation's JSON without limit.
        if self.transcript.len() < 200 {
            self.transcript.push(line.into());
        }
    }

    async fn read_reply(&mut self, stage: Stage) -> Result<Reply, (Stage, String)> {
        let mut raw = Vec::new();
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout(STEP_TIMEOUT, self.conn.read_line(&mut line))
                .await
                .map_err(|_| {
                    (
                        stage,
                        format!(
                            "the relay did not answer within {} seconds",
                            STEP_TIMEOUT.as_secs()
                        ),
                    )
                })?
                .map_err(|e| (stage, format!("reading the reply failed: {e}")))?;

            if read == 0 {
                break;
            }
            let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
            self.note(format!("S: {trimmed}"));
            let final_line = is_final_line(&trimmed);
            raw.push(trimmed);
            if final_line {
                break;
            }
            // A server that never sends a final line would otherwise hold this
            // loop until the whole-conversation budget expires with no useful
            // transcript.
            if raw.len() > 100 {
                return Err((stage, "the relay's reply never ended".into()));
            }
        }

        let reply = parse_reply(&raw).map_err(|e| (stage, e))?;
        self.last_code = Some(reply.code);
        Ok(reply)
    }

    /// Send a command, echo it into the transcript, and read the reply.
    async fn command(&mut self, stage: Stage, line: &str) -> Result<Reply, (Stage, String)> {
        self.note(format!("C: {line}"));
        self.send_unlogged(stage, line).await
    }

    /// The same, for a line whose contents must never be written down.
    async fn secret_command(
        &mut self,
        stage: Stage,
        line: &str,
        redacted: &str,
    ) -> Result<Reply, (Stage, String)> {
        self.note(format!("C: {redacted}"));
        self.send_unlogged(stage, line).await
    }

    async fn send_unlogged(&mut self, stage: Stage, line: &str) -> Result<Reply, (Stage, String)> {
        self.conn
            .write_line(line)
            .await
            .map_err(|e| (stage, format!("writing to the relay failed: {e}")))?;
        self.read_reply(stage).await
    }
}

/// Run the whole conversation and report what happened.
///
/// Never returns `Err` for anything the relay did: a rejection is an *answer*,
/// and an operator testing a relay needs the answer more than they need an
/// error type. The only failures that escape as a report with `delivered:
/// false` are transport ones, which are equally answers.
pub async fn send(
    endpoint: &Endpoint,
    credentials: Option<&Credentials>,
    message: &Message,
    ehlo_name: &str,
) -> SendReport {
    match tokio::time::timeout(
        CONVERSATION_BUDGET,
        converse(endpoint, credentials, message, ehlo_name),
    )
    .await
    {
        Ok(report) => report,
        Err(_) => SendReport::failure(
            Stage::Connect,
            format!(
                "the conversation did not finish within {} seconds",
                CONVERSATION_BUDGET.as_secs()
            ),
            Vec::new(),
        ),
    }
}

async fn converse(
    endpoint: &Endpoint,
    credentials: Option<&Credentials>,
    message: &Message,
    ehlo_name: &str,
) -> SendReport {
    // Refuse before a single packet: a credential over an unencrypted session
    // is a credential given away, and finding that out after the fact is not
    // an option (see the module docs).
    if credentials.is_some() && !endpoint.tls_mode.is_encrypted() {
        return SendReport::failure(
            Stage::Auth,
            "this relay is configured with a username but without TLS. The panel will not send \
             a password over an unencrypted connection — base64 is an encoding, not encryption. \
             Use STARTTLS or implicit TLS, or configure the relay without a credential.",
            Vec::new(),
        );
    }

    for (field, value) in [
        ("from_address", message.from.as_str()),
        ("to", message.to.as_str()),
        ("subject", message.subject.as_str()),
        ("from_name", message.from_name.as_deref().unwrap_or("")),
    ] {
        if let Err(detail) = reject_control_characters(field, value) {
            return SendReport::failure(Stage::MailFrom, detail, Vec::new());
        }
    }

    let mut session = match connect(endpoint).await {
        Ok(s) => s,
        Err((stage, detail)) => return SendReport::failure(stage, detail, Vec::new()),
    };

    match run(&mut session, endpoint, credentials, message, ehlo_name).await {
        Ok(reply) => SendReport {
            delivered: true,
            stage: Stage::Body,
            detail: format!("{} {}", reply.code, reply.text()),
            code: Some(reply.code),
            encrypted: session.conn.is_encrypted(),
            transcript: session.transcript,
        },
        Err((stage, detail)) => SendReport {
            delivered: false,
            stage,
            detail,
            code: session.last_code,
            encrypted: session.conn.is_encrypted(),
            transcript: session.transcript,
        },
    }
}

async fn connect(endpoint: &Endpoint) -> Result<Session, (Stage, String)> {
    let address = format!("{}:{}", endpoint.host, endpoint.port);
    let tcp = tokio::time::timeout(STEP_TIMEOUT, TcpStream::connect(&address))
        .await
        .map_err(|_| {
            (
                Stage::Connect,
                format!(
                    "connecting to {address} did not complete within {} seconds",
                    STEP_TIMEOUT.as_secs()
                ),
            )
        })?
        .map_err(|e| {
            (
                Stage::Connect,
                format!("connecting to {address} failed: {e}"),
            )
        })?;

    // Nagle off: this protocol is a sequence of tiny writes each waiting for a
    // reply, which is the exact shape Nagle's algorithm delays.
    let _ = tcp.set_nodelay(true);

    let mut session = Session {
        conn: Conn::Plain(BufReader::new(tcp)),
        transcript: vec![format!(
            "connected to {address} ({})",
            endpoint.tls_mode.as_str()
        )],
        last_code: None,
    };

    if endpoint.tls_mode == TlsMode::Implicit {
        session.conn = upgrade(session.conn, &endpoint.host).await?;
        session.note("TLS handshake completed (implicit)");
    }
    Ok(session)
}

async fn upgrade(conn: Conn, host: &str) -> Result<Conn, (Stage, String)> {
    let Conn::Plain(buffered) = conn else {
        return Err((
            Stage::Tls,
            "internal: only a plaintext connection can be upgraded".into(),
        ));
    };
    let server_name = ServerName::try_from(host.to_string()).map_err(|_| {
        (
            Stage::Tls,
            format!("`{host}` is not a valid TLS server name"),
        )
    })?;
    let stream = buffered.into_inner();
    let connector = TlsConnector::from(tls_config());
    let tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| (Stage::Tls, format!("the TLS handshake failed: {e}")))?;
    Ok(Conn::Tls(Box::new(BufReader::new(tls))))
}

async fn run(
    session: &mut Session,
    endpoint: &Endpoint,
    credentials: Option<&Credentials>,
    message: &Message,
    ehlo_name: &str,
) -> Result<Reply, (Stage, String)> {
    let greeting = session.read_reply(Stage::Greeting).await?;
    if greeting.code != 220 {
        return Err((Stage::Greeting, describe(&greeting)));
    }

    let mut capabilities = ehlo(session, ehlo_name).await?;

    if endpoint.tls_mode == TlsMode::Starttls {
        if !capabilities.iter().any(|c| c == "STARTTLS") {
            return Err((
                Stage::Starttls,
                "the relay does not offer STARTTLS. The panel will not fall back to plaintext: \
                 an attacker who can remove that capability from the greeting would get the \
                 whole session, credential included."
                    .into(),
            ));
        }
        let reply = session.command(Stage::Starttls, "STARTTLS").await?;
        if !reply.is_positive() {
            return Err((Stage::Starttls, describe(&reply)));
        }
        // RFC 3207 §4.2, and CVE-2011-0411's whole family: anything already in
        // the buffer arrived in the clear and must not be treated as part of
        // the protected session.
        if !session.conn.buffered().is_empty() {
            return Err((
                Stage::Starttls,
                "the relay sent data before the TLS handshake. That is the SMTP command \
                 injection pattern, so the session was abandoned rather than trusted."
                    .into(),
            ));
        }
        let plain = std::mem::replace(&mut session.conn, Conn::Upgrading);
        session.conn = upgrade(plain, &endpoint.host).await?;
        session.note("TLS handshake completed (STARTTLS)");
        // Everything learned before the upgrade is discarded, per RFC 3207.
        capabilities = ehlo(session, ehlo_name).await?;
    }

    if let Some(creds) = credentials {
        authenticate(session, creds, &capabilities).await?;
    }

    let reply = session
        .command(Stage::MailFrom, &format!("MAIL FROM:<{}>", message.from))
        .await?;
    if !reply.is_positive() {
        return Err((Stage::MailFrom, describe(&reply)));
    }

    let reply = session
        .command(Stage::RcptTo, &format!("RCPT TO:<{}>", message.to))
        .await?;
    if !reply.is_positive() {
        return Err((Stage::RcptTo, describe(&reply)));
    }

    let reply = session.command(Stage::Data, "DATA").await?;
    if !reply.is_intermediate() {
        return Err((Stage::Data, describe(&reply)));
    }

    let body = render_message(message);
    session
        .conn
        .write_raw(body.as_bytes())
        .await
        .map_err(|e| (Stage::Body, format!("writing the message failed: {e}")))?;
    session.note(format!("C: <{} bytes of message>", body.len()));
    session.note("C: .");
    session
        .conn
        .write_line(".")
        .await
        .map_err(|e| (Stage::Body, format!("ending the message failed: {e}")))?;

    let reply = session.read_reply(Stage::Body).await?;
    if !reply.is_positive() {
        return Err((Stage::Body, describe(&reply)));
    }

    // The relay has taken the message. A rude close now costs nothing, but a
    // polite one lets the server flush its own logs.
    let _ = session.command(Stage::Quit, "QUIT").await;
    Ok(reply)
}

async fn ehlo(session: &mut Session, ehlo_name: &str) -> Result<Vec<String>, (Stage, String)> {
    let reply = session
        .command(Stage::Ehlo, &format!("EHLO {ehlo_name}"))
        .await?;
    if !reply.is_positive() {
        return Err((Stage::Ehlo, describe(&reply)));
    }
    Ok(reply
        .lines
        .iter()
        .map(|l| l.trim().to_ascii_uppercase())
        .collect())
}

async fn authenticate(
    session: &mut Session,
    creds: &Credentials,
    capabilities: &[String],
) -> Result<(), (Stage, String)> {
    let mechanisms: Vec<&str> = capabilities
        .iter()
        .find_map(|c| c.strip_prefix("AUTH "))
        .map(|rest| rest.split_whitespace().collect())
        .unwrap_or_default();

    if mechanisms.contains(&"PLAIN") || mechanisms.is_empty() {
        // `\0user\0password`, RFC 4616. Redacted in the transcript, so an
        // operator can paste a failing conversation into a support ticket.
        let payload = BASE64.encode(format!("\0{}\0{}", creds.username, creds.password));
        let reply = session
            .secret_command(
                Stage::Auth,
                &format!("AUTH PLAIN {payload}"),
                "AUTH PLAIN <redacted>",
            )
            .await?;
        if !reply.is_positive() {
            return Err((Stage::Auth, describe(&reply)));
        }
        return Ok(());
    }

    if mechanisms.contains(&"LOGIN") {
        let reply = session.command(Stage::Auth, "AUTH LOGIN").await?;
        if !reply.is_intermediate() {
            return Err((Stage::Auth, describe(&reply)));
        }
        let reply = session
            .secret_command(
                Stage::Auth,
                &BASE64.encode(&creds.username),
                "<username, redacted>",
            )
            .await?;
        if !reply.is_intermediate() {
            return Err((Stage::Auth, describe(&reply)));
        }
        let reply = session
            .secret_command(
                Stage::Auth,
                &BASE64.encode(&creds.password),
                "<password, redacted>",
            )
            .await?;
        if !reply.is_positive() {
            return Err((Stage::Auth, describe(&reply)));
        }
        return Ok(());
    }

    Err((
        Stage::Auth,
        format!(
            "the relay offers only {} , none of which this client speaks. PLAIN or LOGIN over \
             TLS is what a submission service is expected to accept.",
            mechanisms.join(", ")
        ),
    ))
}

fn describe(reply: &Reply) -> String {
    format!("{} {}", reply.code, reply.text())
}

/// Build the RFC 5322 message, dot-stuffed and CRLF-terminated.
///
/// Dot-stuffing is not cosmetic: a line consisting of a single `.` ends the
/// `DATA` phase, so a message body containing one would truncate the mail and
/// leave the remainder to be parsed as SMTP commands.
pub fn render_message(message: &Message) -> String {
    let date = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".into());

    let from = match &message.from_name {
        Some(name) => format!("{} <{}>", encode_header_word(name), message.from),
        None => format!("<{}>", message.from),
    };

    let mut out = String::new();
    out.push_str(&format!("From: {from}\r\n"));
    out.push_str(&format!("To: <{}>\r\n", message.to));
    out.push_str(&format!(
        "Subject: {}\r\n",
        encode_header_word(&message.subject)
    ));
    out.push_str(&format!("Date: {date}\r\n"));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    // Marks the message as automatic so a relay's own loop detection and a
    // recipient's filters can see it for what it is.
    out.push_str("Auto-Submitted: auto-generated\r\n");
    out.push_str("\r\n");

    for line in message.body.split('\n') {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix('.') {
            out.push('.');
            out.push('.');
            out.push_str(rest);
        } else {
            out.push_str(line);
        }
        out.push_str("\r\n");
    }
    out
}

/// RFC 2047 encode a header value that is not pure ASCII.
///
/// Plain ASCII passes through unchanged — an encoded-word around `Unihelm test
/// message` would be correct and unreadable in every mail client's raw view.
pub fn encode_header_word(value: &str) -> String {
    if value.is_ascii() {
        return value.to_string();
    }
    format!("=?UTF-8?B?{}?=", BASE64.encode(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A scripted SMTP server: each entry is (expected command prefix, reply).
    ///
    /// Deliberately not a real MTA. What is being tested is this client's half
    /// of the conversation — that it sends the right commands in the right
    /// order, stops at the right place, and says so.
    type Script = Vec<(&'static str, &'static str)>;

    async fn scripted(script: Script) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = tokio::io::BufReader::new(stream);
            let mut seen: Vec<String> = Vec::new();
            let mut script = script.into_iter();

            // An entry with an empty expectation is the opening banner: it goes
            // out before anything is read.
            let mut pending = script.next();
            if let Some((expect, reply)) = pending
                && expect.is_empty()
            {
                reader.get_mut().write_all(reply.as_bytes()).await.unwrap();
                pending = script.next();
            }

            let mut in_data = false;
            while let Some((expect, reply)) = pending {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let trimmed = line.trim_end().to_string();
                if in_data {
                    // Message content, not a command. Only the lone dot ends it.
                    if trimmed != "." {
                        continue;
                    }
                    in_data = false;
                }
                assert!(
                    trimmed
                        .to_ascii_uppercase()
                        .starts_with(&expect.to_ascii_uppercase()),
                    "expected a command starting {expect:?}, got {trimmed:?}",
                );
                seen.push(trimmed.clone());
                reader.get_mut().write_all(reply.as_bytes()).await.unwrap();
                if trimmed.to_ascii_uppercase().starts_with("DATA") {
                    in_data = true;
                }
                pending = script.next();
            }
            seen
        });
        (address.to_string(), handle)
    }

    fn endpoint(address: &str) -> Endpoint {
        let (host, port) = address.rsplit_once(':').unwrap();
        Endpoint {
            host: host.to_string(),
            port: port.parse().unwrap(),
            tls_mode: TlsMode::None,
        }
    }

    fn message() -> Message {
        Message {
            from: "panel@example.com".into(),
            from_name: Some("Unihelm".into()),
            to: "ops@example.com".into(),
            subject: "Unihelm relay test".into(),
            body: "This is a test.\n".into(),
        }
    }

    #[tokio::test]
    async fn a_message_the_relay_accepts_is_reported_as_delivered() {
        let (address, server) = scripted(vec![
            ("", "220 relay.example ESMTP\r\n"),
            ("EHLO", "250-relay.example\r\n250 SIZE 10240000\r\n"),
            ("MAIL FROM", "250 2.1.0 Ok\r\n"),
            ("RCPT TO", "250 2.1.5 Ok\r\n"),
            ("DATA", "354 End data with <CR><LF>.<CR><LF>\r\n"),
            (".", "250 2.0.0 Ok: queued as 4F2\r\n"),
            ("QUIT", "221 2.0.0 Bye\r\n"),
        ])
        .await;

        let report = send(&endpoint(&address), None, &message(), "panel.example").await;
        assert!(report.delivered, "{report:?}");
        assert_eq!(report.code, Some(250));
        assert!(report.detail.contains("queued as 4F2"));

        let seen = server.await.unwrap();
        assert!(seen[0].starts_with("EHLO panel.example"));
        assert_eq!(seen[1], "MAIL FROM:<panel@example.com>");
        assert_eq!(seen[2], "RCPT TO:<ops@example.com>");
    }

    #[tokio::test]
    async fn a_rejected_sender_names_the_stage_and_repeats_the_servers_own_words() {
        // The whole point of the operation: `550 5.7.1 Sender address rejected`
        // at MAIL FROM and the same code at RCPT TO are different tickets.
        let (address, _server) = scripted(vec![
            ("", "220 relay.example ESMTP\r\n"),
            ("EHLO", "250 relay.example\r\n"),
            (
                "MAIL FROM",
                "550 5.7.1 Sender address rejected: not owned by user\r\n",
            ),
        ])
        .await;

        let report = send(&endpoint(&address), None, &message(), "panel.example").await;
        assert!(!report.delivered);
        assert_eq!(report.stage, Stage::MailFrom);
        assert_eq!(report.code, Some(550));
        assert!(
            report.detail.contains("Sender address rejected"),
            "{report:?}"
        );
        assert!(
            report
                .transcript
                .iter()
                .any(|l| l.starts_with("C: MAIL FROM"))
        );
    }

    #[tokio::test]
    async fn a_rejected_recipient_is_reported_at_rcpt_and_not_as_a_generic_failure() {
        let (address, _server) = scripted(vec![
            ("", "220 relay.example ESMTP\r\n"),
            ("EHLO", "250 relay.example\r\n"),
            ("MAIL FROM", "250 Ok\r\n"),
            (
                "RCPT TO",
                "553 5.7.1 Recipient not verified in sandbox mode\r\n",
            ),
        ])
        .await;

        let report = send(&endpoint(&address), None, &message(), "panel.example").await;
        assert_eq!(report.stage, Stage::RcptTo);
        assert!(report.detail.contains("sandbox"));
        assert!(Stage::RcptTo.hint().contains("recipient"));
    }

    #[tokio::test]
    async fn a_credential_is_never_sent_over_an_unencrypted_connection() {
        // Not "it fails at AUTH": it must not connect at all, because a
        // connection that reaches AUTH has already decided to send the secret.
        let creds = Credentials::new("panel@example.com", "hunter2");
        let report = send(
            &Endpoint {
                host: "127.0.0.1".into(),
                // Nothing is listening; if the client tried to connect this
                // would fail at Connect, which is exactly what must not happen.
                port: 1,
                tls_mode: TlsMode::None,
            },
            Some(&creds),
            &message(),
            "panel.example",
        )
        .await;

        assert!(!report.delivered);
        assert_eq!(report.stage, Stage::Auth);
        assert!(report.transcript.is_empty(), "nothing may reach the wire");
        assert!(report.detail.contains("not send a password"));
    }

    #[tokio::test]
    async fn starttls_is_never_downgraded_to_plaintext() {
        // An attacker who can strip STARTTLS from the greeting gets the whole
        // session in a client that falls back. This one refuses.
        let (address, _server) = scripted(vec![
            ("", "220 relay.example ESMTP\r\n"),
            ("EHLO", "250-relay.example\r\n250 PIPELINING\r\n"),
        ])
        .await;
        let mut ep = endpoint(&address);
        ep.tls_mode = TlsMode::Starttls;

        let report = send(&ep, None, &message(), "panel.example").await;
        assert!(!report.delivered);
        assert_eq!(report.stage, Stage::Starttls);
        assert!(report.detail.contains("will not fall back"));
        assert!(!report.encrypted);
    }

    #[tokio::test]
    async fn a_relay_that_pipelines_before_the_tls_handshake_is_treated_as_an_attack() {
        // RFC 3207 §4.2 / CVE-2011-0411: bytes that arrived in the clear must
        // not be honoured as part of the protected session.
        let (address, _server) = scripted(vec![
            ("", "220 relay.example ESMTP\r\n"),
            ("EHLO", "250-relay.example\r\n250 STARTTLS\r\n"),
            // The 220 and an injected reply in one write, before any handshake.
            ("STARTTLS", "220 Ready to start TLS\r\n250 injected\r\n"),
        ])
        .await;
        let mut ep = endpoint(&address);
        ep.tls_mode = TlsMode::Starttls;

        let report = send(&ep, None, &message(), "panel.example").await;
        assert!(!report.delivered);
        assert_eq!(report.stage, Stage::Starttls);
        assert!(report.detail.contains("injection"), "{report:?}");
    }

    #[tokio::test]
    async fn a_relay_that_accepts_nothing_at_the_greeting_is_reported_at_the_greeting() {
        let (address, _server) =
            scripted(vec![("", "554 relay.example No service here\r\n")]).await;
        let report = send(&endpoint(&address), None, &message(), "panel.example").await;
        assert_eq!(report.stage, Stage::Greeting);
        assert!(report.detail.contains("No service"));
    }

    #[tokio::test]
    async fn nothing_listening_fails_at_connect_with_the_address_in_the_message() {
        let report = send(
            &Endpoint {
                host: "127.0.0.1".into(),
                port: 1,
                tls_mode: TlsMode::None,
            },
            None,
            &message(),
            "panel.example",
        )
        .await;
        assert_eq!(report.stage, Stage::Connect);
        assert!(report.detail.contains("127.0.0.1:1"), "{report:?}");
    }

    #[tokio::test]
    async fn an_address_carrying_a_newline_cannot_inject_an_smtp_command() {
        // `MAIL FROM:<a@b\r\nRCPT TO:<victim@c>>` is the classic. Rejection has
        // to happen before the connection, not by escaping on the way out.
        let mut m = message();
        m.to = "ops@example.com>\r\nRCPT TO:<victim@example.net".into();
        let report = send(
            &Endpoint {
                host: "127.0.0.1".into(),
                port: 1,
                tls_mode: TlsMode::None,
            },
            None,
            &m,
            "panel.example",
        )
        .await;
        assert!(!report.delivered);
        assert!(report.detail.contains("control character"), "{report:?}");
        assert!(report.transcript.is_empty());
    }

    #[test]
    fn a_subject_carrying_a_newline_cannot_inject_a_header() {
        assert!(reject_control_characters("subject", "Test\r\nBcc: everyone@example.net").is_err());
        assert!(reject_control_characters("subject", "Unihelm relay test").is_ok());
    }

    #[test]
    fn a_multiline_reply_parses_to_one_code_and_every_line() {
        let reply = parse_reply(&[
            "250-relay.example".to_string(),
            "250-PIPELINING".to_string(),
            "250 STARTTLS".to_string(),
        ])
        .unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines.len(), 3);
        assert!(reply.is_positive());
    }

    #[test]
    fn a_reply_whose_code_changes_mid_way_is_refused_rather_than_guessed() {
        // Accepting "the last line wins" lets a 550 hide behind a 250.
        let err = parse_reply(&["550-nope".to_string(), "250 fine".to_string()]).unwrap_err();
        assert!(err.contains("changed code"));
    }

    #[test]
    fn a_reply_that_is_not_a_three_digit_code_is_refused() {
        assert!(parse_reply(&["OK".to_string()]).is_err());
        assert!(parse_reply(&["".to_string()]).is_err());
        assert!(parse_reply(&[]).is_err());
    }

    #[test]
    fn the_final_line_of_a_reply_is_the_one_without_a_dash() {
        assert!(!is_final_line("250-PIPELINING"));
        assert!(is_final_line("250 OK"));
        assert!(is_final_line("250"));
    }

    #[test]
    fn a_body_line_that_is_a_lone_dot_is_stuffed_so_it_cannot_end_the_message() {
        let mut m = message();
        m.body = "before\n.\nafter\n".into();
        let rendered = render_message(&m);
        assert!(rendered.contains("\r\n..\r\n"), "{rendered}");
        // And the real terminator is still only ever written by the client.
        assert!(!rendered.ends_with("\r\n.\r\n"));
    }

    #[test]
    fn every_header_line_ends_with_crlf_and_the_body_is_separated_by_a_blank_line() {
        let rendered = render_message(&message());
        assert!(rendered.starts_with("From: Unihelm <panel@example.com>\r\n"));
        assert!(rendered.contains("\r\n\r\nThis is a test.\r\n"));
        assert!(rendered.contains("Auto-Submitted: auto-generated"));
    }

    #[test]
    fn a_non_ascii_display_name_is_rfc_2047_encoded_and_ascii_is_left_alone() {
        // Persian is a first-class locale in this panel, so an operator's
        // display name being non-ASCII is the normal case, not the edge one.
        assert_eq!(encode_header_word("Unihelm"), "Unihelm");
        let encoded = encode_header_word("میزبانی فروم");
        assert!(encoded.starts_with("=?UTF-8?B?"));
        assert!(encoded.ends_with("?="));
        assert!(encoded.is_ascii(), "a header must be ASCII on the wire");
    }

    #[test]
    fn credentials_do_not_print_their_password() {
        let rendered = format!("{:?}", Credentials::new("user", "hunter2"));
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn every_stage_has_a_hint_that_says_what_to_look_at() {
        for stage in [
            Stage::Connect,
            Stage::Tls,
            Stage::Greeting,
            Stage::Ehlo,
            Stage::Starttls,
            Stage::Auth,
            Stage::MailFrom,
            Stage::RcptTo,
            Stage::Data,
            Stage::Body,
            Stage::Quit,
        ] {
            assert!(stage.hint().len() > 20, "{}", stage.as_str());
            assert!(!stage.as_str().is_empty());
        }
    }
}
