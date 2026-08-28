//! Outbound webhooks (spec §2.4, §9 `webhooks`, §14 Phase 6).
//!
//! Spec §2.4 is a promise made by omission: "**No billing/invoicing** — expose
//! a clean API + webhooks so WHMCS/FOSSBilling can integrate later." A panel
//! that will never grow a billing module has to be a panel somebody else's
//! billing module can watch, and this is that seam.
//!
//! # Three decisions carry this module
//!
//! **1. Deliveries are signed, and the signature covers a timestamp.** A bare
//! POST to a URL is authenticated by nothing but the secrecy of the URL, which
//! survives exactly until it appears in a proxy log. Every delivery carries an
//! HMAC-SHA256 over `v1:<timestamp>:<body>` ([`sign`]), so a receiver can
//! prove the panel sent it *and* refuse a replay of yesterday's message. The
//! exact scheme is written down in `docs/webhooks.md` because a signature only
//! a Rust program can compute is not an integration point.
//!
//! **2. Delivery is at-least-once, and the queue is bounded at both ends.**
//! The queue is durable (`webhook_deliveries`) so an agent restart does not
//! drop the "backup failed" nobody has read yet. Each delivery gets
//! [`MAX_ATTEMPTS`] tries on a bounded exponential curve ([`backoff`]), and a
//! hook whose consecutive failures reach [`FAILURE_THRESHOLD`] is switched off
//! with a reason and its queue abandoned. Without the second bound, one
//! customer pointing a hook at a host that stopped existing turns the
//! scheduler into a machine for retrying forever.
//!
//! **3. The event catalogue is closed.** [`EVENTS`] is the whole list a hook
//! may subscribe to, and `webhook.set` refuses a name that is not in it. A
//! typo in an event name is otherwise a hook that silently never fires, which
//! is the worst failure mode an integration can have — everything looks
//! configured and nothing arrives.
//!
//! # What a webhook is *not*
//!
//! It is not a control channel. Nothing a receiver returns is interpreted:
//! only the HTTP status decides success, the body is discarded unread, and a
//! redirect is followed at most once and never down to plain HTTP (the same
//! policy the alert notifier uses, and literally the same function —
//! [`crate::alerts::redirect_allowed`], because a webhook URL and an alert
//! webhook URL are the same kind of secret in the same kind of path).

use std::sync::OnceLock;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use ferrum_core::{ErrorCode, FerrumError, Permission, Result, UserId};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::registry::{Execution, OpContext, TypedOperation};

// ---------------------------------------------------------------------------
// The event catalogue
// ---------------------------------------------------------------------------

/// Every event a webhook may subscribe to.
///
/// Closed on purpose (see the module docs). The names are dotted and past
/// tense, matching the operation registry's own convention: an event says what
/// happened, an operation says what to do.
pub const EVENTS: &[&str] = &[
    // A new account was provisioned.
    "account.created",
    // A tenant crossed the near-full line on its disk quota.
    "quota.near_limit",
    // A certificate was renewed (or issued) successfully.
    "certificate.renewed",
    // A backup run finished without error.
    "backup.completed",
    // A backup run failed — the event every integrator asks for first.
    "backup.failed",
    // A subscription was suspended.
    "subscription.suspended",
    // A site was created.
    "site.created",
    // A site was deleted.
    "site.deleted",
];

/// The wildcard subscription: "every event, including ones added later".
///
/// Opt-in rather than the default, because a receiver that has not been
/// written against an event still gets it — which is fine for a log sink and
/// wrong for a state machine.
pub const WILDCARD: &str = "*";

fn known_event(name: &str) -> bool {
    EVENTS.contains(&name)
}

// ---------------------------------------------------------------------------
// The signature scheme (documented in docs/webhooks.md)
// ---------------------------------------------------------------------------

/// The signature scheme version, carried in the header value.
///
/// Present from the first release so that changing the scheme later is a
/// second `v2=` element beside the first rather than a flag day: a receiver
/// picks the version it understands and ignores the rest.
pub const SIGNATURE_VERSION: &str = "v1";

/// `X-Ferrum-Signature: v1=<hex>`.
pub const SIGNATURE_HEADER: &str = "X-Ferrum-Signature";
/// `X-Ferrum-Timestamp: <unix seconds>` — inside the signed string, so it
/// cannot be rewritten by anyone who did not have the secret.
pub const TIMESTAMP_HEADER: &str = "X-Ferrum-Timestamp";
/// `X-Ferrum-Event: <event name>`.
pub const EVENT_HEADER: &str = "X-Ferrum-Event";
/// `X-Ferrum-Delivery: <delivery id>` — stable across retries of the same
/// delivery, which is what makes at-least-once safe to consume.
pub const DELIVERY_HEADER: &str = "X-Ferrum-Delivery";

/// The bytes a receiver must reconstruct before verifying.
///
/// `v1:<unix seconds>:<raw body>`. Three properties, each of which a scheme
/// without it has been broken by in the wild:
///
/// * the **version prefix** means a future scheme cannot be confused for this
///   one by an old receiver;
/// * the **timestamp inside the MAC** is what makes replay detection possible
///   at all — a timestamp sent only in a header is a timestamp an attacker
///   edits;
/// * the **raw body**, not a re-serialisation of it. A receiver that parses
///   JSON and re-encodes it before verifying will fail on key order and
///   whitespace, so the panel signs exactly the bytes it puts on the wire and
///   the docs say to verify before parsing.
pub fn signing_string(timestamp: i64, body: &str) -> String {
    format!("{SIGNATURE_VERSION}:{timestamp}:{body}")
}

/// `v1=<lowercase hex HMAC-SHA256>`.
///
/// The MAC key is the secret **exactly as the panel showed it**, as ASCII
/// bytes — not hex-decoded first. That is the choice that makes a five-line
/// receiver in any language correct: `hmac_sha256(secret_string, payload)`.
pub fn sign(secret: &str, timestamp: i64, body: &str) -> String {
    // `new_from_slice` on HMAC accepts any key length (it hashes over-long
    // keys and zero-pads short ones), so this cannot fail for our 64-character
    // secret — but expressing that as an expect rather than an unwrap says why.
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(signing_string(timestamp, body).as_bytes());
    format!(
        "{SIGNATURE_VERSION}={}",
        hex::encode(mac.finalize().into_bytes())
    )
}

/// Mint a signing secret: 32 bytes of CSPRNG, hex-encoded.
///
/// Hex rather than base64 so the value is safe in a shell, a YAML file, an
/// environment variable and a URL without anyone having to think about it —
/// the places integrators actually paste secrets.
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Retry policy
// ---------------------------------------------------------------------------

/// How many times one delivery is attempted before it is abandoned.
///
/// Six attempts on the curve below span about sixteen minutes, which covers
/// a receiver restart, a deploy, or a brief network partition. Beyond that the
/// endpoint is not "briefly unavailable", it is broken, and a queue is the
/// wrong place to wait for a human.
pub const MAX_ATTEMPTS: i64 = 6;

/// The first retry delay. Everything after it doubles.
const BASE_DELAY_SECS: i64 = 30;

/// The ceiling on a single delay, so the curve is bounded rather than merely
/// slow.
const MAX_DELAY_SECS: i64 = 3600;

/// Consecutive failed attempts that switch a hook off.
///
/// Deliberately larger than [`MAX_ATTEMPTS`]: one bad night must not disable a
/// working integration, but a hook that has failed twenty times in a row
/// without a single success has an endpoint that is gone. Any 2xx resets the
/// counter to zero, so this counts a *streak*, never a lifetime total.
pub const FAILURE_THRESHOLD: i64 = 20;

/// When to try again after `attempts_so_far` failed attempts, or `None` when
/// the delivery has used them all up.
///
/// Bounded exponential: 30 s, 60 s, 120 s, 240 s, 480 s after the first
/// through fifth failures, then give up — each capped at [`MAX_DELAY_SECS`],
/// which matters only once somebody raises [`MAX_ATTEMPTS`] and the doubling
/// would otherwise run to days. The whole curve is under sixteen minutes, and
/// [`the_backoff_curve_is_bounded_and_terminates`](self) pins that.
pub fn backoff(attempts_so_far: i64) -> Option<time::Duration> {
    if !(1..MAX_ATTEMPTS).contains(&attempts_so_far) {
        return None;
    }
    // The first retry waits the base delay, not twice it — hence the `- 1`.
    // `attempts_so_far` is bounded by MAX_ATTEMPTS above, so the shift cannot
    // overflow; the clamp is what keeps that true if the constant grows.
    let exponent = (attempts_so_far - 1).clamp(0, 32) as u32;
    let secs = BASE_DELAY_SECS
        .saturating_mul(1i64 << exponent)
        .min(MAX_DELAY_SECS);
    Some(time::Duration::seconds(secs))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const MAX_URL_LEN: usize = 2048;

/// Reject a URL that is not one we would ever POST to.
///
/// The same reasoning as the alert notifier's check, and deliberately the same
/// permissiveness: private and loopback addresses are **not** blocked, because
/// relaying through something local is the common legitimate case and only an
/// account that already holds `server_manage` can register a hook. What is
/// refused is the part somebody gets wrong by pasting — a non-HTTP scheme, an
/// embedded newline (header injection into the request we are about to build),
/// whitespace, or an absurd length.
pub fn validate_url(url: &str) -> Result<String> {
    let url = url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "a webhook URL must start with https:// or http://",
        )
        .with_field("url"));
    }
    if url.len() > MAX_URL_LEN {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "that webhook URL is implausibly long",
        )
        .with_field("url"));
    }
    if url.chars().any(|c| c.is_control() || c == ' ') {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "a webhook URL cannot contain spaces or control characters",
        )
        .with_field("url"));
    }
    Ok(url.to_string())
}

/// Reject an event list with a name the panel will never emit.
///
/// An empty list is refused too: a hook subscribed to nothing is a hook that
/// looks configured and never fires, and that is a support ticket rather than
/// a valid configuration.
pub fn validate_events(events: &[String]) -> Result<Vec<String>> {
    if events.is_empty() {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!(
                "subscribe to at least one event, or to `{WILDCARD}` for all of them; \
                 known events: {}",
                EVENTS.join(", ")
            ),
        )
        .with_field("events"));
    }
    let mut out: Vec<String> = Vec::with_capacity(events.len());
    for event in events {
        let name = event.trim();
        if name != WILDCARD && !known_event(name) {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!(
                    "`{name}` is not an event this panel emits; known events: {}",
                    EVENTS.join(", ")
                ),
            )
            .with_field("events"));
        }
        if !out.iter().any(|e| e == name) {
            out.push(name.to_string());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// One signed POST.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    pub url: String,
    pub body: String,
    pub event: String,
    pub delivery_id: i64,
    pub timestamp: i64,
    /// The full `X-Ferrum-Signature` value, `v1=<hex>`.
    pub signature: String,
}

impl SignedRequest {
    /// Build the request for one delivery. Split out from sending so the header
    /// set is testable without a network.
    pub fn build(
        url: &str,
        secret: &str,
        event: &str,
        delivery_id: i64,
        body: &str,
        timestamp: i64,
    ) -> Self {
        Self {
            url: url.to_string(),
            body: body.to_string(),
            event: event.to_string(),
            delivery_id,
            timestamp,
            signature: sign(secret, timestamp, body),
        }
    }

    /// The headers, in the order the docs list them.
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        vec![
            (EVENT_HEADER, self.event.clone()),
            (DELIVERY_HEADER, self.delivery_id.to_string()),
            (TIMESTAMP_HEADER, self.timestamp.to_string()),
            (SIGNATURE_HEADER, self.signature.clone()),
        ]
    }
}

/// How a delivery physically leaves the box.
///
/// A trait rather than a bare `reqwest` call, for the same reason the alert
/// notifier has one: the retry state machine is the interesting part and it
/// must be testable against a transport that fails on demand rather than
/// against whatever the test machine's network is doing.
#[async_trait]
pub trait Deliverer: Send + Sync {
    /// POST the signed request. `Ok` carries the HTTP status; `Err` is a
    /// transport failure (no status was ever seen).
    async fn deliver(&self, request: &SignedRequest) -> std::result::Result<u16, String>;
}

/// Per-request timeout. Delivery runs inside the scheduler tick, so an endpoint
/// that accepts a connection and then says nothing must not hold the schedule.
const HTTP_TIMEOUT_SECS: u64 = 10;

/// The real transport: reqwest over rustls, with the alert notifier's redirect
/// policy.
pub struct HttpDeliverer {
    /// `None` if the client could not be built. A delivery failure is never
    /// fatal to the agent, and that includes this one.
    client: Option<reqwest::Client>,
}

impl HttpDeliverer {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(StdDuration::from_secs(HTTP_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                let from = attempt
                    .previous()
                    .last()
                    .map(|u| u.scheme().to_string())
                    .unwrap_or_default();
                // Same rule as the alert notifier: at most one hop, never down
                // to plain HTTP. A webhook URL usually carries its own
                // authorization in the path, and following a downgrade would
                // hand that credential to anyone on the wire.
                if crate::alerts::redirect_allowed(
                    &from,
                    attempt.url().scheme(),
                    attempt.previous().len(),
                ) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .user_agent(concat!("ferrum-panel/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| tracing::error!(error = %e, "could not build the webhook HTTP client"))
            .ok();
        Self { client }
    }
}

impl Default for HttpDeliverer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Deliverer for HttpDeliverer {
    async fn deliver(&self, request: &SignedRequest) -> std::result::Result<u16, String> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| "the webhook HTTP client is unavailable".to_string())?;
        let mut builder = client
            .post(&request.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request.body.clone());
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        let response = builder.send().await.map_err(|e| e.to_string())?;
        // The body is deliberately never read: nothing a receiver says is
        // interpreted, and downloading a hostile endpoint's megabyte of reply
        // would be work done on its behalf.
        Ok(response.status().as_u16())
    }
}

/// The process-wide live deliverer. One client means one connection pool.
fn live_deliverer() -> &'static HttpDeliverer {
    static LIVE: OnceLock<HttpDeliverer> = OnceLock::new();
    LIVE.get_or_init(HttpDeliverer::new)
}

/// A 2xx is delivered; anything else is a failure worth retrying.
///
/// 4xx included, and that is a decision. A 401 or a 404 usually means the
/// receiver is misconfigured, and retrying gives whoever is fixing it a window
/// in which the event still arrives. The bound is [`MAX_ATTEMPTS`], and a hook
/// that keeps answering 404 hits [`FAILURE_THRESHOLD`] and is switched off with
/// its status recorded — which is a far more useful state than "we dropped it
/// silently at 09:14".
pub const fn is_success(status: u16) -> bool {
    status >= 200 && status < 300
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// The envelope every delivery carries.
///
/// Flat and boring on purpose: `event`, `id`, `at`, `data`. A receiver
/// switching on `event` and reading `data` is the whole integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event: String,
    /// The delivery id, repeated in the body so a receiver that logs only
    /// bodies can still de-duplicate.
    pub id: i64,
    /// RFC 3339, UTC — the panel's one clock.
    pub at: String,
    pub data: serde_json::Value,
}

/// Fan one event out to every subscribed, active hook.
///
/// Returns how many deliveries were queued. **Never fails the caller**: an
/// operation that succeeded must not be reported as failed because a
/// notification could not be queued (the same rule the alert notifier works
/// under, spec §11.11), so problems are logged and the count comes back short.
///
/// The payload is rendered once and stored per delivery, so every receiver of
/// one event sees byte-identical `data` and a retry is a redelivery rather
/// than a fresh observation of a changed world.
pub async fn emit(ctx: &OpContext, event: &str, data: serde_json::Value) -> usize {
    debug_assert!(
        known_event(event),
        "`{event}` is not in the webhook event catalogue"
    );

    let hooks = match ctx.db().webhooks_subscribed_to(event).await {
        Ok(hooks) => hooks,
        Err(e) => {
            tracing::warn!(event, error = %e, "could not read webhook subscriptions");
            return 0;
        }
    };
    if hooks.is_empty() {
        return 0;
    }

    let at = ferrum_db::to_sql_time(ferrum_db::now());
    let mut queued = 0;
    for hook in hooks {
        // The id inside the envelope has to be the delivery's own, and the row
        // does not exist until it is inserted — so the row is written with a
        // placeholder-free body built from the id the insert returns. Doing it
        // the other way round (id first, body second) would need a second
        // UPDATE per delivery for no gain.
        let envelope = EventEnvelope {
            event: event.to_string(),
            id: 0,
            at: at.clone(),
            data: data.clone(),
        };
        let Ok(mut body) = serde_json::to_value(&envelope) else {
            tracing::error!(event, "a webhook payload would not serialise");
            continue;
        };

        let placeholder = serde_json::to_string(&body).unwrap_or_default();
        match ctx
            .db()
            .enqueue_delivery(hook.id, event, &placeholder, ferrum_db::now())
            .await
        {
            Ok(id) => {
                body["id"] = serde_json::json!(id);
                let final_body = serde_json::to_string(&body).unwrap_or(placeholder);
                if let Err(e) = ctx.db().set_delivery_payload(id, &final_body).await {
                    tracing::warn!(event, error = %e, "could not finalise a webhook payload");
                }
                queued += 1;
            }
            Err(e) => {
                tracing::warn!(event, hook = hook.id, error = %e, "could not queue a webhook delivery")
            }
        }
    }
    queued
}

// ---------------------------------------------------------------------------
// The delivery loop
// ---------------------------------------------------------------------------

/// How many deliveries one scheduler tick attempts.
///
/// Bounded so a panel coming back from an outage with a thousand queued
/// deliveries drains them over several ticks instead of opening a thousand
/// connections at once — the same reasoning as the certificate renewer's
/// per-tick cap.
pub const DELIVERIES_PER_TICK: i64 = 20;

/// One pass of the delivery loop, against a given transport.
///
/// Returns a human summary for the scheduler's log, empty when there was
/// nothing to do.
pub async fn deliver_due(ctx: &OpContext, transport: &dyn Deliverer) -> Result<String> {
    let db = ctx.db();
    let due = db
        .due_deliveries(DELIVERIES_PER_TICK)
        .await
        .map_err(FerrumError::from)?;
    if due.is_empty() {
        return Ok(String::new());
    }

    let mut delivered = 0;
    let mut failed = 0;
    // Hooks switched off part-way through this batch. The batch was read
    // before any of them was disabled, so without this the loop would keep
    // POSTing to an endpoint it has just given up on — which is exactly the
    // unbounded retrying the threshold exists to stop.
    let mut disabled: Vec<i64> = Vec::new();

    for item in due {
        if disabled.contains(&item.delivery.webhook_id) {
            continue;
        }
        // Validate the row on the way out. A hand-edited (or restored) database
        // must not be able to make the panel POST somewhere it would have
        // refused to store — the same "render from the table, validate again"
        // contract the crontab renderer works under.
        let url = match validate_url(&item.url) {
            Ok(url) => url,
            Err(e) => {
                let _ = db
                    .delivery_failed(
                        item.delivery.id,
                        item.delivery.webhook_id,
                        &e.detail,
                        None,
                        None,
                    )
                    .await;
                let _ = db
                    .disable_webhook(
                        item.delivery.webhook_id,
                        "the stored URL is not deliverable",
                    )
                    .await;
                disabled.push(item.delivery.webhook_id);
                continue;
            }
        };

        let secret = match ctx.master_key().open_str(&item.secret_sealed) {
            Ok(secret) => secret,
            Err(e) => {
                // The master key changed, or the row was restored without it.
                // Nothing retryable about that, and every future attempt would
                // fail identically.
                tracing::error!(hook = item.delivery.webhook_id, error = %e,
                    "a webhook secret could not be opened");
                let _ = db
                    .disable_webhook(
                        item.delivery.webhook_id,
                        "the signing secret could not be opened with this panel's master key",
                    )
                    .await;
                disabled.push(item.delivery.webhook_id);
                continue;
            }
        };

        let request = SignedRequest::build(
            &url,
            &secret,
            &item.delivery.event,
            item.delivery.id,
            &item.delivery.payload_json,
            unix_seconds(),
        );

        let outcome = transport.deliver(&request).await;
        let (error, status) = match outcome {
            Ok(status) if is_success(status) => {
                let _ = db
                    .delivery_succeeded(item.delivery.id, item.delivery.webhook_id, status)
                    .await;
                delivered += 1;
                continue;
            }
            Ok(status) => (format!("the endpoint answered HTTP {status}"), Some(status)),
            Err(e) => (e, None),
        };

        let retry_at = backoff(item.delivery.attempts + 1).map(|d| ferrum_db::now() + d);
        let streak = db
            .delivery_failed(
                item.delivery.id,
                item.delivery.webhook_id,
                &error,
                status,
                retry_at,
            )
            .await
            .map_err(FerrumError::from)?;
        failed += 1;

        if streak >= FAILURE_THRESHOLD {
            // The bound that stops a dead endpoint from becoming an unbounded
            // retry queue (spec §14 Phase 6).
            let reason = format!(
                "disabled after {streak} consecutive failed deliveries; last error: {error}"
            );
            if let Err(e) = db.disable_webhook(item.delivery.webhook_id, &reason).await {
                tracing::error!(error = %e, "could not disable a failing webhook");
            } else {
                disabled.push(item.delivery.webhook_id);
                tracing::warn!(hook = item.delivery.webhook_id, streak, "webhook disabled");
            }
        }
    }

    Ok(format!(
        "{delivered} delivered, {failed} failed, {} hook(s) disabled",
        disabled.len()
    ))
}

/// The scheduler's entry point: one delivery pass over the live transport.
pub async fn delivery_tick(ctx: &OpContext) -> std::result::Result<String, String> {
    deliver_due(ctx, live_deliverer())
        .await
        .map_err(|e| e.detail)
}

fn unix_seconds() -> i64 {
    ferrum_db::now().unix_timestamp()
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// The public shape of a hook. The secret is absent by construction.
#[derive(Debug, Serialize)]
pub struct WebhookView {
    pub id: i64,
    pub owner_user_id: i64,
    pub url: String,
    pub events: Vec<String>,
    pub active: bool,
    pub last_delivery_at: Option<String>,
    pub last_status: Option<i64>,
    pub failure_count: i64,
    pub disabled_reason: Option<String>,
}

impl From<ferrum_db::Webhook> for WebhookView {
    fn from(w: ferrum_db::Webhook) -> Self {
        Self {
            id: w.id,
            owner_user_id: w.owner_user_id.get(),
            url: w.url,
            events: w.events,
            active: w.active,
            last_delivery_at: w.last_delivery_at.map(ferrum_db::to_sql_time),
            last_status: w.last_status,
            failure_count: w.failure_count,
            disabled_reason: w.disabled_reason,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListInput {
    /// Include the recent delivery history for one hook.
    #[serde(default)]
    pub id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub webhooks: Vec<WebhookView>,
    /// The whole event catalogue, so a UI never hard-codes it.
    pub events: Vec<&'static str>,
    pub max_per_owner: i64,
    /// Present only when `id` was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deliveries: Option<Vec<ferrum_db::WebhookDelivery>>,
}

pub struct List;

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "webhook.list";
    // Reading which endpoints this panel notifies is a server-configuration
    // read. There is no `webhook_manage` permission to use (spec §6.1's
    // permission set is fixed for this wave), and `server_read` is the closest
    // honest fit: admins and resellers hold it, customers do not.
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let repo = ctx.db().webhooks(ctx.scope());
        let webhooks = repo.list().await.map_err(FerrumError::from)?;

        let deliveries = match input.id {
            Some(id) => {
                // Resolve through the scope first: history for a hook the
                // caller cannot see is `not_found`, not an empty list.
                if !webhooks.iter().any(|w| w.id == id) {
                    return Err(FerrumError::not_found("webhook"));
                }
                Some(
                    ctx.db()
                        .recent_deliveries(id, 50)
                        .await
                        .map_err(FerrumError::from)?,
                )
            }
            None => None,
        };

        Ok(ListOutput {
            webhooks: webhooks.into_iter().map(WebhookView::from).collect(),
            events: EVENTS.to_vec(),
            max_per_owner: ferrum_db::webhooks::MAX_HOOKS_PER_OWNER,
            deliveries,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct SetInput {
    /// Update this hook instead of creating one.
    #[serde(default)]
    pub id: Option<i64>,
    pub url: String,
    pub events: Vec<String>,
    /// Defaults to active: a hook nobody asked to disable is one somebody
    /// wants to receive.
    #[serde(default = "yes")]
    pub active: bool,
    /// Whose hook it is. Defaults to the caller's own account.
    #[serde(default)]
    pub owner_user_id: Option<i64>,
    /// Mint a new signing secret. On create this is implied; on update it is
    /// how a leaked secret is rotated.
    #[serde(default)]
    pub rotate_secret: bool,
}

const fn yes() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct SetOutput {
    pub webhook: WebhookView,
    /// The signing secret, **shown once**. Absent on an update that did not
    /// rotate it, because the panel cannot show what it has already sealed
    /// away — and a secret that can be read back later is a secret in every
    /// backup of this database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// How to verify a delivery, so the answer travels with the secret.
    pub signature_scheme: &'static str,
}

const SCHEME_HINT: &str = "HMAC-SHA256 over `v1:<X-Ferrum-Timestamp>:<raw body>`, \
                           compared against X-Ferrum-Signature (see docs/webhooks.md)";

pub struct Set;

#[async_trait]
impl TypedOperation for Set {
    type Input = SetInput;
    type Output = SetOutput;

    const NAME: &'static str = "webhook.set";
    // Registering an endpoint means this panel will POST its internal events to
    // an address of the caller's choosing. That is a server-configuration
    // change, not a tenant one.
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let url = validate_url(&input.url)?;
        let events = validate_events(&input.events)?;
        let repo = ctx.db().webhooks(ctx.scope());

        match input.id {
            Some(id) => {
                let secret = input.rotate_secret.then(generate_secret);
                let sealed = match &secret {
                    Some(s) => Some(ctx.master_key().seal_str(s).map_err(FerrumError::from)?),
                    None => None,
                };
                let hook = repo
                    .update(id, &url, &events, input.active, sealed.as_deref())
                    .await
                    .map_err(FerrumError::from)?;
                Ok(SetOutput {
                    webhook: hook.into(),
                    secret,
                    signature_scheme: SCHEME_HINT,
                })
            }
            None => {
                let owner = self.resolve_owner(ctx, input.owner_user_id).await?;
                let secret = generate_secret();
                let sealed = ctx
                    .master_key()
                    .seal_str(&secret)
                    .map_err(FerrumError::from)?;
                let hook = repo
                    .create(ferrum_db::NewWebhook {
                        owner_user_id: owner,
                        url,
                        secret_sealed: sealed,
                        events,
                        active: input.active,
                    })
                    .await
                    .map_err(FerrumError::from)?;
                Ok(SetOutput {
                    webhook: hook.into(),
                    secret: Some(secret),
                    signature_scheme: SCHEME_HINT,
                })
            }
        }
    }
}

impl Set {
    /// Whose hook this is: the caller's own account, or a named one the
    /// caller's scope can actually see.
    ///
    /// The scoped user lookup is what stops an id from being a way to plant a
    /// hook on somebody else's account — an id outside the scope is
    /// `not_found`, which says nothing about whether it exists.
    async fn resolve_owner(&self, ctx: &OpContext, requested: Option<i64>) -> Result<UserId> {
        let Some(raw) = requested else {
            return Ok(ctx.auth().actor_user_id);
        };
        let id = UserId(raw);
        ctx.db()
            .users(ctx.scope())
            .by_id(id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("account"))?;
        Ok(id)
    }
}

#[derive(Debug, Deserialize)]
pub struct DeleteInput {
    pub id: i64,
}

#[derive(Debug, Serialize)]
pub struct DeleteOutput {
    pub id: i64,
}

pub struct Delete;

#[async_trait]
impl TypedOperation for Delete {
    type Input = DeleteInput;
    type Output = DeleteOutput;

    const NAME: &'static str = "webhook.delete";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        ctx.db()
            .webhooks(ctx.scope())
            .delete(input.id)
            .await
            .map_err(FerrumError::from)?;
        Ok(DeleteOutput { id: input.id })
    }
}

#[derive(Debug, Deserialize)]
pub struct TestInput {
    pub id: i64,
}

#[derive(Debug, Serialize)]
pub struct TestOutput {
    pub delivered: bool,
    pub status: Option<u16>,
    pub error: Option<String>,
    /// Echoed back so an integrator debugging their verifier can compare.
    pub timestamp: i64,
    pub signature: String,
}

/// `webhook.test` — send one synthetic delivery and report what happened.
///
/// Synchronous rather than queued, and that is the whole value: an operator
/// pressing "test" wants the endpoint's answer, not a task id and a promise.
/// It is also the only path that reveals the signature it sent, so somebody
/// writing the other side can diff their computation against ours.
///
/// The test payload uses the reserved `webhook.test` event name, which is
/// deliberately **not** in [`EVENTS`]: a hook cannot subscribe to it, so a
/// receiver switching on `event` can tell a drill from the real thing.
pub struct Test {
    transport: Option<&'static dyn Deliverer>,
}

impl Test {
    pub fn live() -> Self {
        Self {
            transport: Some(live_deliverer()),
        }
    }
}

pub const TEST_EVENT: &str = "webhook.test";

#[async_trait]
impl TypedOperation for Test {
    type Input = TestInput;
    type Output = TestOutput;

    const NAME: &'static str = "webhook.test";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let hook = ctx
            .db()
            .webhooks(ctx.scope())
            .by_id(input.id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("webhook"))?;

        let url = validate_url(&hook.url)?;
        let secret = ctx
            .master_key()
            .open_str(&hook.secret_sealed)
            .map_err(FerrumError::from)?;

        let body = serde_json::to_string(&EventEnvelope {
            event: TEST_EVENT.to_string(),
            // Not a queued delivery, so it has no row and no id. Zero says so
            // rather than colliding with a real delivery a receiver has stored.
            id: 0,
            at: ferrum_db::to_sql_time(ferrum_db::now()),
            data: serde_json::json!({ "panel": "ferrum", "hook_id": hook.id }),
        })
        .map_err(|e| FerrumError::internal(format!("test payload: {e}")))?;

        let request = SignedRequest::build(&url, &secret, TEST_EVENT, 0, &body, unix_seconds());

        let Some(transport) = self.transport else {
            // Constructed without a transport: only reachable from a test
            // registry, and saying so beats pretending the POST happened.
            return Err(FerrumError::new(
                ErrorCode::NotImplemented,
                "this build has no webhook transport",
            ));
        };

        let (delivered, status, error) = match transport.deliver(&request).await {
            Ok(status) if is_success(status) => (true, Some(status), None),
            Ok(status) => (
                false,
                Some(status),
                Some(format!("the endpoint answered HTTP {status}")),
            ),
            Err(e) => (false, None, Some(e)),
        };

        // A test counts: it is a real delivery to a real endpoint, and an
        // operator who tests a hook twenty times against a dead host has
        // learned the same thing the failure counter has.
        if delivered {
            let _ = ctx
                .db()
                .set_webhook_probe_result(hook.id, status.map(i64::from), true)
                .await;
        } else {
            let _ = ctx
                .db()
                .set_webhook_probe_result(hook.id, status.map(i64::from), false)
                .await;
        }

        Ok(TestOutput {
            delivered,
            status,
            error,
            timestamp: request.timestamp,
            signature: request.signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use ferrum_core::Role;
    use std::sync::Mutex;

    // -- the signature scheme ------------------------------------------------

    /// The vector in docs/webhooks.md. If this changes, every receiver written
    /// against the documented scheme breaks, so it is pinned here byte for
    /// byte rather than recomputed.
    #[test]
    fn the_documented_signature_vector_still_holds() {
        let signature = sign("topsecret", 1_700_000_000, r#"{"event":"site.created"}"#);
        assert_eq!(
            signature, "v1=364d1332b8987cf01317f9300e328255efac8a800eaedb815da6e1b4b339449f",
            "the signature scheme is a published contract"
        );
    }

    #[test]
    fn the_timestamp_is_inside_the_mac_so_a_replay_cannot_be_relabelled() {
        let body = r#"{"event":"site.created"}"#;
        let a = sign("s", 1_700_000_000, body);
        let b = sign("s", 1_700_000_060, body);
        assert_ne!(
            a, b,
            "moving the timestamp must invalidate the signature, or replay \
             protection is decoration"
        );
    }

    #[test]
    fn a_different_secret_produces_a_different_signature() {
        let body = r#"{"event":"site.created"}"#;
        assert_ne!(sign("a", 1, body), sign("b", 1, body));
    }

    #[test]
    fn the_signed_string_is_exactly_version_timestamp_body() {
        assert_eq!(signing_string(42, "{}"), "v1:42:{}");
    }

    #[test]
    fn a_minted_secret_is_256_bits_of_hex() {
        let a = generate_secret();
        let b = generate_secret();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two secrets from one CSPRNG must not collide");
    }

    // -- retry policy --------------------------------------------------------

    #[test]
    fn the_backoff_curve_is_bounded_and_terminates() {
        let mut total = time::Duration::ZERO;
        let mut attempts = 1;
        while let Some(delay) = backoff(attempts) {
            assert!(
                delay <= time::Duration::seconds(MAX_DELAY_SECS),
                "no single delay may exceed the ceiling"
            );
            total += delay;
            attempts += 1;
            assert!(attempts <= 100, "the curve must terminate");
        }
        assert_eq!(attempts, MAX_ATTEMPTS);
        assert_eq!(backoff(1), Some(time::Duration::seconds(30)));
        // The point of the bound: a dead endpoint is abandoned inside sixteen
        // minutes, not retried until the disk fills.
        assert!(total <= time::Duration::minutes(16), "total wait {total:?}");
    }

    #[test]
    fn each_retry_waits_at_least_as_long_as_the_last() {
        let mut previous = time::Duration::ZERO;
        for attempt in 1..MAX_ATTEMPTS {
            let delay = backoff(attempt).expect("inside the attempt budget");
            assert!(delay >= previous, "the curve must not go backwards");
            previous = delay;
        }
        assert!(backoff(MAX_ATTEMPTS).is_none());
        assert!(backoff(MAX_ATTEMPTS + 100).is_none());
    }

    #[test]
    fn only_2xx_counts_as_delivered() {
        assert!(is_success(200));
        assert!(is_success(204));
        assert!(is_success(299));
        for status in [199, 300, 301, 400, 401, 404, 410, 500, 503] {
            assert!(!is_success(status), "{status} must not count as delivered");
        }
    }

    // -- validation ----------------------------------------------------------

    #[test]
    fn a_url_that_could_inject_a_header_is_refused() {
        for hostile in [
            "https://example.com/hook\r\nX-Evil: 1",
            "https://example.com/ hook",
            "https://exa\tmple.com/hook",
            "file:///etc/shadow",
            "ftp://example.com/hook",
            "javascript:alert(1)",
            "//example.com/hook",
        ] {
            let err = validate_url(hostile).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "accepted {hostile:?}");
            assert_eq!(err.field.as_deref(), Some("url"));
        }
        // Surrounding whitespace is trimmed rather than refused — the stored
        // value is the trimmed one, so a pasted URL with a trailing newline is
        // a paste, not an injection.
        assert_eq!(
            validate_url("  https://example.com/hook\n").unwrap(),
            "https://example.com/hook"
        );
        assert!(validate_url("http://127.0.0.1:9000/hook").is_ok());
    }

    #[test]
    fn an_absurdly_long_url_is_refused() {
        let long = format!("https://example.com/{}", "a".repeat(MAX_URL_LEN));
        assert!(validate_url(&long).is_err());
    }

    #[test]
    fn an_unknown_event_name_is_refused_rather_than_silently_never_firing() {
        let err = validate_events(&["site.craeted".into()]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(
            err.detail.contains("site.created"),
            "the refusal must list the real names: {}",
            err.detail
        );
    }

    #[test]
    fn an_empty_subscription_is_refused() {
        assert!(validate_events(&[]).is_err());
    }

    #[test]
    fn duplicate_event_names_collapse() {
        let events = validate_events(&["site.created".into(), "site.created".into()]).unwrap();
        assert_eq!(events, vec!["site.created".to_string()]);
    }

    #[test]
    fn the_wildcard_is_accepted_and_the_catalogue_is_non_empty() {
        assert!(validate_events(&[WILDCARD.into()]).is_ok());
        assert!(!EVENTS.is_empty());
        // The events the task brief names must all exist, spelled the way the
        // documentation spells them.
        for required in [
            "account.created",
            "quota.near_limit",
            "certificate.renewed",
            "backup.completed",
            "backup.failed",
            "subscription.suspended",
            "site.created",
            "site.deleted",
        ] {
            assert!(EVENTS.contains(&required), "missing event {required}");
        }
    }

    #[test]
    fn the_test_event_is_not_subscribable() {
        assert!(
            !EVENTS.contains(&TEST_EVENT),
            "a drill must be distinguishable from the real thing"
        );
        assert!(validate_events(&[TEST_EVENT.into()]).is_err());
    }

    // -- the request -------------------------------------------------------

    #[test]
    fn every_delivery_carries_the_four_documented_headers() {
        let request = SignedRequest::build(
            "https://example.com/hook",
            "topsecret",
            "site.created",
            77,
            "{}",
            1_700_000_000,
        );
        let headers = request.headers();
        let names: Vec<&str> = headers.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec![
                EVENT_HEADER,
                DELIVERY_HEADER,
                TIMESTAMP_HEADER,
                SIGNATURE_HEADER
            ]
        );
        assert_eq!(headers[1].1, "77", "the delivery id is the de-dup key");
        assert!(headers[3].1.starts_with("v1="));
    }

    // -- the delivery loop ---------------------------------------------------

    /// A transport whose answer the test dictates, and which records what it
    /// was asked to send.
    struct ScriptedTransport {
        answer: std::result::Result<u16, String>,
        seen: Mutex<Vec<SignedRequest>>,
    }

    impl ScriptedTransport {
        fn answering(answer: std::result::Result<u16, String>) -> Self {
            Self {
                answer,
                seen: Mutex::new(Vec::new()),
            }
        }
        fn count(&self) -> usize {
            self.seen.lock().unwrap().len()
        }

        /// The one request this transport was asked to send, cloned out from
        /// under the lock so a caller never holds a guard across an await.
        fn first(&self) -> SignedRequest {
            let seen = self.seen.lock().unwrap();
            assert_eq!(seen.len(), 1, "expected exactly one delivery");
            seen[0].clone()
        }
    }

    #[async_trait]
    impl Deliverer for ScriptedTransport {
        async fn deliver(&self, request: &SignedRequest) -> std::result::Result<u16, String> {
            self.seen.lock().unwrap().push(request.clone());
            self.answer.clone()
        }
    }

    async fn hook_for(
        reg: &crate::registry::OpRegistry,
        admin: ferrum_core::UserId,
        events: &[&str],
    ) -> (i64, String) {
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let out = Set
            .run(
                &ctx,
                SetInput {
                    id: None,
                    url: "https://example.com/hook".into(),
                    events: events.iter().map(|e| (*e).to_string()).collect(),
                    active: true,
                    owner_user_id: None,
                    rotate_secret: false,
                },
            )
            .await
            .unwrap();
        (out.webhook.id, out.secret.expect("a new hook mints one"))
    }

    #[tokio::test]
    async fn a_new_hook_shows_its_secret_exactly_once() {
        let (reg, admin, _) = registry().await;
        let (id, secret) = hook_for(&reg, admin, &["site.created"]).await;
        assert_eq!(secret.len(), 64);

        // Listing it again must not hand the secret back.
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let listed = List.run(&ctx, ListInput { id: Some(id) }).await.unwrap();
        let json = serde_json::to_string(&listed).unwrap();
        assert!(
            !json.contains(&secret),
            "a signing secret must never be readable back: {json}"
        );
    }

    #[tokio::test]
    async fn an_emitted_event_reaches_only_its_subscribers() {
        let (reg, admin, _) = registry().await;
        let (wanted, _) = hook_for(&reg, admin, &["site.created"]).await;
        let (other, _) = hook_for(&reg, admin, &["backup.failed"]).await;

        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let queued = emit(
            &ctx,
            "site.created",
            serde_json::json!({ "domain": "a.example" }),
        )
        .await;
        assert_eq!(queued, 1);

        let db = &reg.services().db;
        assert_eq!(db.recent_deliveries(wanted, 10).await.unwrap().len(), 1);
        assert!(db.recent_deliveries(other, 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_queued_payload_carries_its_own_delivery_id() {
        let (reg, admin, _) = registry().await;
        let (id, _) = hook_for(&reg, admin, &["site.created"]).await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        emit(
            &ctx,
            "site.created",
            serde_json::json!({ "domain": "a.example" }),
        )
        .await;

        let delivery = reg.services().db.recent_deliveries(id, 1).await.unwrap();
        let envelope: EventEnvelope = serde_json::from_str(&delivery[0].payload_json).unwrap();
        assert_eq!(envelope.id, delivery[0].id);
        assert_eq!(envelope.event, "site.created");
        assert_eq!(envelope.data["domain"], "a.example");
    }

    #[tokio::test]
    async fn a_successful_delivery_is_signed_with_the_hooks_own_secret() {
        let (reg, admin, _) = registry().await;
        let (id, secret) = hook_for(&reg, admin, &["site.created"]).await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        emit(&ctx, "site.created", serde_json::json!({})).await;

        let transport = ScriptedTransport::answering(Ok(200));
        deliver_due(&ctx, &transport).await.unwrap();

        // Copy out of the transport before awaiting again: a std MutexGuard
        // must not be alive across an await point.
        let request = transport.first();
        assert_eq!(
            request.signature,
            sign(&secret, request.timestamp, &request.body),
            "a receiver holding the secret must be able to recompute this"
        );

        let history = reg.services().db.recent_deliveries(id, 1).await.unwrap();
        assert_eq!(history[0].status, "delivered");
        assert_eq!(history[0].response_status, Some(200));
    }

    #[tokio::test]
    async fn a_failed_delivery_waits_before_it_is_tried_again() {
        let (reg, admin, _) = registry().await;
        let (id, _) = hook_for(&reg, admin, &["site.created"]).await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        emit(&ctx, "site.created", serde_json::json!({})).await;

        let transport = ScriptedTransport::answering(Err("connection refused".into()));
        deliver_due(&ctx, &transport).await.unwrap();
        assert_eq!(transport.count(), 1);

        // The second tick, immediately after, must find nothing due — that is
        // the backoff doing its job.
        deliver_due(&ctx, &transport).await.unwrap();
        assert_eq!(
            transport.count(),
            1,
            "a retry must wait for its backoff, not spin"
        );

        let history = reg.services().db.recent_deliveries(id, 1).await.unwrap();
        assert_eq!(history[0].attempts, 1);
        assert_eq!(history[0].status, "pending");
        assert!(history[0].last_error.as_deref() == Some("connection refused"));
    }

    #[tokio::test]
    async fn a_dead_endpoint_is_disabled_instead_of_retried_forever() {
        let (reg, admin, _) = registry().await;
        let (id, _) = hook_for(&reg, admin, &["site.created"]).await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let db = reg.services().db.clone();

        let transport = ScriptedTransport::answering(Ok(410));

        // Drive the loop the way time would: emit, deliver, drag the next
        // attempt back into the past, repeat. The bound under test is the
        // consecutive-failure threshold, not the wall clock.
        for _ in 0..FAILURE_THRESHOLD {
            emit(&ctx, "site.created", serde_json::json!({})).await;
            sqlx::query(
                "UPDATE webhook_deliveries SET next_attempt_at = ?1 WHERE status = 'pending'",
            )
            .bind(ferrum_db::to_sql_time(
                ferrum_db::now() - time::Duration::hours(1),
            ))
            .execute(db.pool())
            .await
            .unwrap();
            deliver_due(&ctx, &transport).await.unwrap();
            let hook = db
                .webhooks(&ferrum_core::TenantScope::Global)
                .by_id(id)
                .await
                .unwrap()
                .unwrap();
            if !hook.active {
                break;
            }
        }

        let hook = db
            .webhooks(&ferrum_core::TenantScope::Global)
            .by_id(id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !hook.active,
            "a hook that never answers must be switched off"
        );
        assert!(
            hook.disabled_reason
                .as_deref()
                .unwrap_or_default()
                .contains("consecutive"),
            "the panel must say why: {:?}",
            hook.disabled_reason
        );

        // And the queue is not left behind as a backlog.
        assert!(db.due_deliveries(100).await.unwrap().is_empty());

        // Nothing more is attempted once it is off.
        let before = transport.count();
        emit(&ctx, "site.created", serde_json::json!({})).await;
        deliver_due(&ctx, &transport).await.unwrap();
        assert_eq!(transport.count(), before);
    }

    /// The batch is read before any hook in it is disabled, so a hook that
    /// crosses the threshold on its first delivery must not have the rest of
    /// its batch POSTed anyway.
    #[tokio::test]
    async fn a_hook_disabled_part_way_through_a_batch_gets_no_further_attempts() {
        let (reg, admin, _) = registry().await;
        let (id, _) = hook_for(&reg, admin, &["site.created"]).await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let db = reg.services().db.clone();

        // One failure away from the threshold.
        sqlx::query("UPDATE webhooks SET failure_count = ?2 WHERE id = ?1")
            .bind(id)
            .bind(FAILURE_THRESHOLD - 1)
            .execute(db.pool())
            .await
            .unwrap();

        for _ in 0..5 {
            emit(&ctx, "site.created", serde_json::json!({})).await;
        }

        let transport = ScriptedTransport::answering(Ok(500));
        deliver_due(&ctx, &transport).await.unwrap();
        assert_eq!(
            transport.count(),
            1,
            "the loop kept delivering to a hook it had just switched off"
        );
    }

    #[tokio::test]
    async fn a_hook_that_cannot_be_opened_is_disabled_not_retried() {
        let (reg, admin, _) = registry().await;
        let (id, _) = hook_for(&reg, admin, &["site.created"]).await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let db = reg.services().db.clone();
        emit(&ctx, "site.created", serde_json::json!({})).await;

        // Simulate a database restored without its master key.
        sqlx::query("UPDATE webhooks SET secret_sealed = 'not-a-sealed-value' WHERE id = ?1")
            .bind(id)
            .execute(db.pool())
            .await
            .unwrap();

        let transport = ScriptedTransport::answering(Ok(200));
        deliver_due(&ctx, &transport).await.unwrap();
        assert_eq!(
            transport.count(),
            0,
            "nothing may be POSTed unsigned when the secret cannot be opened"
        );
        let hook = db
            .webhooks(&ferrum_core::TenantScope::Global)
            .by_id(id)
            .await
            .unwrap()
            .unwrap();
        assert!(!hook.active);
    }

    #[tokio::test]
    async fn a_stored_url_that_would_be_refused_today_is_never_posted_to() {
        let (reg, admin, _) = registry().await;
        let (id, _) = hook_for(&reg, admin, &["site.created"]).await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let db = reg.services().db.clone();
        emit(&ctx, "site.created", serde_json::json!({})).await;

        // A hand-edited row, the way a restore or a direct sqlite session
        // produces one.
        sqlx::query("UPDATE webhooks SET url = 'file:///etc/shadow' WHERE id = ?1")
            .bind(id)
            .execute(db.pool())
            .await
            .unwrap();

        let transport = ScriptedTransport::answering(Ok(200));
        deliver_due(&ctx, &transport).await.unwrap();
        assert_eq!(transport.count(), 0);
    }

    #[tokio::test]
    async fn a_customer_cannot_register_a_webhook() {
        let (reg, _, customer) = registry().await;
        let err = reg
            .dispatch(
                "webhook.set",
                &auth_for(customer, Role::Customer),
                serde_json::json!({ "url": "https://evil.example/x", "events": ["*"] }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn history_for_an_invisible_hook_is_not_found_not_empty() {
        let (reg, admin, customer) = registry().await;
        let (id, _) = hook_for(&reg, admin, &["site.created"]).await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(customer, Role::Customer));
        let err = List
            .run(&ctx, ListInput { id: Some(id) })
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn rotating_a_secret_invalidates_the_previous_one() {
        let (reg, admin, _) = registry().await;
        let (id, first) = hook_for(&reg, admin, &["site.created"]).await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));

        let rotated = Set
            .run(
                &ctx,
                SetInput {
                    id: Some(id),
                    url: "https://example.com/hook".into(),
                    events: vec!["site.created".into()],
                    active: true,
                    owner_user_id: None,
                    rotate_secret: true,
                },
            )
            .await
            .unwrap();
        let second = rotated.secret.expect("rotation shows the new secret");
        assert_ne!(first, second);

        emit(&ctx, "site.created", serde_json::json!({})).await;
        let transport = ScriptedTransport::answering(Ok(200));
        deliver_due(&ctx, &transport).await.unwrap();
        let sent = transport.first();
        assert_eq!(sent.signature, sign(&second, sent.timestamp, &sent.body));
        assert_ne!(sent.signature, sign(&first, sent.timestamp, &sent.body));
    }

    #[tokio::test]
    async fn an_update_that_does_not_rotate_keeps_the_secret_hidden() {
        let (reg, admin, _) = registry().await;
        let (id, _) = hook_for(&reg, admin, &["site.created"]).await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let out = Set
            .run(
                &ctx,
                SetInput {
                    id: Some(id),
                    url: "https://example.com/other".into(),
                    events: vec!["*".into()],
                    active: true,
                    owner_user_id: None,
                    rotate_secret: false,
                },
            )
            .await
            .unwrap();
        assert!(out.secret.is_none());
        assert_eq!(out.webhook.url, "https://example.com/other");
    }
}
