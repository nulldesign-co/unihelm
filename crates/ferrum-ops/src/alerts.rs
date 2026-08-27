//! Alert evaluation and notification (spec §11.11, driven by the scheduler in
//! spec §10.2).
//!
//! # Why this module is mostly a state machine
//!
//! Evaluating thresholds is arithmetic; anybody can write it. What makes a
//! monitoring system usable is what happens *after* the threshold is crossed.
//! The naive design — "every minute, compare, notify if over" — sends a message
//! a minute for as long as the disk stays full, and the second thing every
//! operator does with such a channel is mute it. The third thing is miss the
//! outage.
//!
//! So an alert here is a **span with two edges**. `alert_events` rows open when
//! a condition starts holding and close when it stops, and only the two
//! transitions produce a message: one "this started", one "this stopped". While
//! the condition merely continues, nothing is sent.
//!
//! That alone is not enough, because a real signal does not sit still. A disk
//! genuinely at the 90% line reads 89.9, 90.1, 90.0, 89.8 on consecutive
//! samples, and a bare `>= threshold` test would call each of those a state
//! change: twenty messages an hour from a machine whose disk never actually
//! moved. The fix is **hysteresis**: the condition starts at the threshold but
//! only stops once the reading has come back past it by a band wide enough to
//! mean something really changed ([`hysteresis`]). Together, the span model and
//! the band are what the tests at the bottom of this file exist to prove.
//!
//! # Layering
//!
//! [`collect`] does the IO (metrics, services, certificates), [`plan`] is a
//! pure function from readings plus open events to transitions, and
//! [`evaluate`] applies the transitions and notifies. The split is what makes
//! the interesting behaviour testable against fixture snapshots instead of
//! against whatever the test machine's disks happen to be doing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use ferrum_core::{ErrorCode, FerrumError, Permission, PhpVersion, Result};
use ferrum_db::alerts::{AlertEvent, AlertKind, AlertRule, ChannelKind, NotifyChannel};
use ferrum_distro::svc::{ManagedUnit, UnitState};
use ferrum_metrics::ServerSnapshot;
use serde::{Deserialize, Serialize};

use crate::registry::{Execution, OpContext, TypedOperation};

/// How far a reading must come back past the threshold before the alert is
/// considered over.
///
/// The band is the whole reason a disk hovering at 90% does not page anybody
/// every minute. The numbers are chosen to be larger than sampling noise and
/// smaller than a real change:
///
/// * percentages — two points; a filesystem that has genuinely been cleaned up
///   frees far more than 2% (one rotated log does it), while the jitter of a
///   busy filesystem's `statfs` is well under it;
/// * load — a quarter, against a one-minute average that is already smoothed;
/// * certificate days — one day, so a certificate sitting exactly on the
///   fourteen-day line cannot flip on rounding between two evaluations.
///
/// `service_down` has no band because it is not a measurement: a unit is
/// running or it is not. Its equivalent of hysteresis is treating systemd's
/// `activating`/`deactivating` as "not down", so an ordinary restart is not an
/// outage (see [`service_is_down`]).
pub fn hysteresis(kind: AlertKind) -> f64 {
    match kind {
        AlertKind::DiskPct | AlertKind::MemPct => 2.0,
        AlertKind::Load => 0.25,
        AlertKind::CertExpiryDays => 1.0,
        AlertKind::ServiceDown => 0.0,
    }
}

/// Does this reading start (or sustain) the alert?
pub fn breaches(kind: AlertKind, threshold: f64, value: f64) -> bool {
    if kind.rises() {
        value >= threshold
    } else {
        value <= threshold
    }
}

/// Has this reading come back far enough to end the alert?
///
/// Note that a value between [`clears`] and [`breaches`] does *neither*: it
/// leaves the alert in whatever state it was already in. That gap is the band,
/// and living in it is the normal condition of a system sitting at its limit.
pub fn clears(kind: AlertKind, threshold: f64, value: f64) -> bool {
    let band = hysteresis(kind);
    if kind.rises() {
        value < threshold - band
    } else {
        value > threshold + band
    }
}

/// systemd states that count as "down" for a `service_down` rule.
///
/// `Activating` and `Deactivating` are deliberately not down: a `systemctl
/// restart` passes through them, and alerting on a restart would make every
/// certificate renewal (which reloads nginx) look like an outage. `NotFound` is
/// not down either — a server without MariaDB installed does not have a MariaDB
/// problem; that case is handled by the unit simply not being observable.
pub fn service_is_down(state: UnitState) -> bool {
    matches!(state, UnitState::Inactive | UnitState::Failed)
}

/// The managed units a `service_down` rule may name.
///
/// A whitelist, like `svc.action`'s: the rule target is operator-supplied text,
/// and the only thing it is ever allowed to become is one of the units the
/// panel already manages. There is no spelling of this string that reaches an
/// arbitrary systemd unit.
pub fn service_target(target: &str) -> Option<ManagedUnit> {
    Some(match target {
        "nginx" => ManagedUnit::Nginx,
        "mariadb" => ManagedUnit::MariaDb,
        "postgresql" => ManagedUnit::PostgreSql,
        "kv_store" => ManagedUnit::KvStore,
        "docker" => ManagedUnit::Docker,
        "sshd" => ManagedUnit::Sshd,
        "ferrum_web" => ManagedUnit::FerrumWeb,
        "ferrum_agentd" => ManagedUnit::FerrumAgentd,
        other => ManagedUnit::PhpFpm {
            version: PhpVersion::parse(other.strip_prefix("php_fpm:")?).ok()?,
        },
    })
}

// ---------------------------------------------------------------------------
// readings
// ---------------------------------------------------------------------------

/// One reading of one thing a rule watches.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    /// Stable identity of the thing within its rule: a mount point, a unit
    /// name, a domain. This is the debounce key, so it must not wobble between
    /// evaluations.
    pub subject: String,
    pub value: f64,
    /// The reading in words, reused by both the raise and the resolve message.
    pub describe: String,
}

/// Everything one evaluation pass looks at.
#[derive(Debug, Clone)]
pub struct Readings {
    pub snapshot: ServerSnapshot,
    /// Managed-unit target → is it down. **Absent means not observable** (not
    /// installed, or the status call failed), which is deliberately different
    /// from `Some(false)`: we do not know, so we say nothing.
    pub services: BTreeMap<String, bool>,
    /// Primary domain → days until the certificate expires.
    pub certificates: Vec<(String, f64)>,
}

/// Read everything the given rules need.
///
/// Only what they need: a panel with no `service_down` rules makes no
/// `systemctl show` calls, which matters because the collector's whole budget
/// is 1% of a core (spec §11.11).
pub async fn collect(ctx: &OpContext, rules: &[AlertRule]) -> Result<Readings> {
    // The dashboard's own snapshot, throttled by the collector — the panel
    // footprint is left off on purpose (`metrics.snapshot` documents it as
    // opt-in because it costs an extra /proc walk, and no rule watches it).
    let snapshot = ctx.metrics().snapshot().await;

    let mut services = BTreeMap::new();
    for rule in rules.iter().filter(|r| r.enabled) {
        if rule.kind != AlertKind::ServiceDown {
            continue;
        }
        let Some(target) = rule.target.as_deref() else {
            continue;
        };
        let Some(unit) = service_target(target) else {
            continue;
        };
        match ctx.distro().svc.managed_status(unit).await {
            Ok(status) if status.is_installed() => {
                services.insert(target.to_string(), service_is_down(status.state));
            }
            // Not installed: nothing to say about it.
            Ok(_) => {}
            // A failed status call is not evidence of an outage. Log it and
            // leave the subject unobserved rather than inventing a down.
            Err(e) => {
                tracing::warn!(target = %target, error = %e, "could not read a unit's state for alerting");
            }
        }
    }

    let mut certificates = Vec::new();
    if rules
        .iter()
        .any(|r| r.enabled && r.kind == AlertKind::CertExpiryDays)
    {
        // `certificates_for_alerting`, not `certificates_for`: the latter
        // answers "what may this tenant see?", so it joins through `sites` and
        // therefore drops every row with `site_id IS NULL` — including the
        // panel's own certificate. For alerting that omission is exactly
        // backwards, because the panel certificate expiring locks the operator
        // out of the tool they would use to fix it (spec §11.5, §11.11). The
        // query also filters to `status = 'active'`: a superseded or failed row
        // is history, and warning about a file nginx no longer reads is noise.
        let all = ctx
            .db()
            .certificates_for_alerting()
            .await
            .map_err(FerrumError::from)?;
        for cert in all {
            let (Some(days), Some(domain)) = (cert.days_remaining(), cert.domains.first()) else {
                continue;
            };
            certificates.push((domain.clone(), days as f64));
        }
    }

    Ok(Readings {
        snapshot,
        services,
        certificates,
    })
}

/// The readings that apply to one rule.
///
/// Pure, so the thresholds can be exercised against fixture snapshots rather
/// than against whatever the machine running the tests happens to be doing.
pub fn observe(rule: &AlertRule, readings: &Readings) -> Vec<Observation> {
    match rule.kind {
        AlertKind::DiskPct => readings
            .snapshot
            .disks
            .iter()
            // A rule with a target watches that one mount; without one it
            // watches every filesystem the collector reports.
            .filter(|d| rule.target.as_deref().is_none_or(|t| t == d.mount))
            .map(|d| {
                let pct = f64::from(d.used_pct());
                Observation {
                    subject: d.mount.clone(),
                    value: pct,
                    describe: format!("filesystem {} is {pct:.1}% full", d.mount),
                }
            })
            .collect(),

        AlertKind::MemPct => {
            let pct = f64::from(readings.snapshot.memory.used_pct());
            vec![Observation {
                subject: "memory".into(),
                value: pct,
                describe: format!("memory is {pct:.1}% used"),
            }]
        }

        AlertKind::Load => {
            let one = readings.snapshot.load.one;
            vec![Observation {
                subject: "load".into(),
                value: one,
                describe: format!("the one-minute load average is {one:.2}"),
            }]
        }

        AlertKind::ServiceDown => rule
            .target
            .as_deref()
            .and_then(|t| readings.services.get(t).map(|down| (t, *down)))
            .map(|(target, down)| {
                vec![Observation {
                    subject: target.to_string(),
                    // Boolean dressed as a number so one threshold comparison
                    // covers every kind.
                    value: if down { 1.0 } else { 0.0 },
                    describe: format!(
                        "{target} is {}",
                        if down { "not running" } else { "running" }
                    ),
                }]
            })
            .unwrap_or_default(),

        AlertKind::CertExpiryDays => readings
            .certificates
            .iter()
            .filter(|(domain, _)| rule.target.as_deref().is_none_or(|t| t == domain))
            .map(|(domain, days)| Observation {
                subject: domain.clone(),
                value: *days,
                describe: if *days < 0.0 {
                    format!("the certificate for {domain} expired {} days ago", -days)
                } else {
                    format!("the certificate for {domain} expires in {days:.0} days")
                },
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// the state machine
// ---------------------------------------------------------------------------

/// Which edge of an alert span this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    Raised,
    Resolved,
}

impl AlertState {
    pub const fn as_str(self) -> &'static str {
        match self {
            AlertState::Raised => "raised",
            AlertState::Resolved => "resolved",
        }
    }
}

/// A decided edge, before it has been written or sent.
#[derive(Debug, Clone, PartialEq)]
pub enum Transition {
    Raise {
        rule_id: i64,
        subject: String,
        message: String,
        value: Option<f64>,
    },
    Resolve {
        event_id: i64,
        rule_id: i64,
        subject: String,
        message: String,
        value: Option<f64>,
    },
}

impl Transition {
    pub fn subject(&self) -> &str {
        match self {
            Transition::Raise { subject, .. } | Transition::Resolve { subject, .. } => subject,
        }
    }

    pub fn state(&self) -> AlertState {
        match self {
            Transition::Raise { .. } => AlertState::Raised,
            Transition::Resolve { .. } => AlertState::Resolved,
        }
    }
}

/// Decide every edge this pass should produce.
///
/// Pure by design — the entire debounce argument is provable from this function
/// plus a list of open events, with no database and no clock involved.
pub fn plan(rules: &[AlertRule], readings: &Readings, open: &[AlertEvent]) -> Vec<Transition> {
    let mut out = Vec::new();

    for rule in rules {
        let open_for_rule: BTreeMap<&str, &AlertEvent> = open
            .iter()
            .filter(|e| e.rule_id == rule.id && e.is_open())
            .map(|e| (e.subject.as_str(), e))
            .collect();

        // A disabled rule stops watching, and an alert nobody is watching any
        // more must not stay open forever — the operator would come back to a
        // dashboard full of red from a rule they switched off months ago.
        if !rule.enabled {
            for event in open_for_rule.values() {
                out.push(Transition::Resolve {
                    event_id: event.id,
                    rule_id: rule.id,
                    subject: event.subject.clone(),
                    message: format!(
                        "{} is no longer being watched: the {} rule was disabled",
                        event.subject,
                        rule.label()
                    ),
                    value: None,
                });
            }
            continue;
        }

        let observations = observe(rule, readings);
        let mut seen: BTreeSet<&str> = BTreeSet::new();

        for o in &observations {
            seen.insert(o.subject.as_str());
            let already_open = open_for_rule.get(o.subject.as_str());

            match already_open {
                // Still breaching, already told them. This is the branch that
                // runs on all but one of the sixty evaluations an hour, and it
                // does nothing at all — the entire point of the module.
                Some(_) if !clears(rule.kind, rule.threshold, o.value) => {}
                Some(event) => out.push(Transition::Resolve {
                    event_id: event.id,
                    rule_id: rule.id,
                    subject: o.subject.clone(),
                    message: resolve_message(rule, o),
                    value: Some(o.value),
                }),
                None if breaches(rule.kind, rule.threshold, o.value) => {
                    out.push(Transition::Raise {
                        rule_id: rule.id,
                        subject: o.subject.clone(),
                        message: raise_message(rule, o),
                        value: Some(o.value),
                    });
                }
                None => {}
            }
        }

        // Something we had an open alert about stopped being reported at all —
        // an unmounted filesystem, a certificate that was replaced, a service
        // that was uninstalled. Closing it is more honest than leaving a red
        // row about a thing that no longer exists.
        for (subject, event) in &open_for_rule {
            if seen.contains(subject) {
                continue;
            }
            out.push(Transition::Resolve {
                event_id: event.id,
                rule_id: rule.id,
                subject: (*subject).to_string(),
                message: format!("{subject} is no longer being reported"),
                value: None,
            });
        }
    }

    out
}

fn threshold_text(rule: &AlertRule) -> String {
    match rule.kind {
        AlertKind::DiskPct | AlertKind::MemPct => format!("{:.0}%", rule.threshold),
        AlertKind::Load => format!("{:.2}", rule.threshold),
        AlertKind::CertExpiryDays => format!("{:.0} days", rule.threshold),
        AlertKind::ServiceDown => "running".into(),
    }
}

fn raise_message(rule: &AlertRule, o: &Observation) -> String {
    match rule.kind {
        AlertKind::ServiceDown => o.describe.clone(),
        AlertKind::CertExpiryDays => {
            format!("{} (alert below {})", o.describe, threshold_text(rule))
        }
        _ => format!("{} (alert above {})", o.describe, threshold_text(rule)),
    }
}

fn resolve_message(rule: &AlertRule, o: &Observation) -> String {
    match rule.kind {
        AlertKind::ServiceDown => format!("{} again", o.describe),
        _ => format!("{}, back within the {} limit", o.describe, threshold_text(rule)),
    }
}

// ---------------------------------------------------------------------------
// notification
// ---------------------------------------------------------------------------

/// What a channel is sent. Stable on purpose: it is somebody's integration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationPayload {
    /// The panel's configured name, so an operator running three of them can
    /// tell which one is shouting.
    pub panel: String,
    /// The rule, as `kind` or `kind:target`.
    pub rule: String,
    pub message: String,
    /// `raised` or `resolved`.
    pub state: String,
    /// RFC 3339, UTC — the panel's one clock (`ferrum_db::now`).
    pub at: String,
}

/// How a notification physically leaves the box.
///
/// A trait rather than a bare `reqwest` call so the payload and the per-channel
/// failure handling are testable without a network, and so a future channel
/// (SMTP, Slack) has an obvious seam to sit behind.
#[async_trait]
pub trait Transport: Send + Sync {
    /// POST `body` to `url` as `application/json`; `Ok` carries the HTTP status.
    async fn post_json(&self, url: &str, body: &str) -> std::result::Result<u16, String>;
}

/// Per-request timeout. Notification runs inside the scheduler tick, so a
/// webhook host that accepts a connection and then says nothing must not be
/// able to hold the whole schedule still.
const HTTP_TIMEOUT_SECS: u64 = 5;

/// At most one redirect, and only within the same or a stronger scheme.
///
/// A webhook URL usually carries its own authorization in the path
/// (`/services/T000/B000/xxxx`), so following a redirect from HTTPS onto plain
/// HTTP would hand that credential to anyone on the wire. One hop is enough for
/// the legitimate case (a host that moved), and refusing the rest keeps a
/// hostile or compromised endpoint from walking the panel around the network.
pub fn redirect_allowed(from_scheme: &str, to_scheme: &str, previous_hops: usize) -> bool {
    if previous_hops > 1 {
        return false;
    }
    match to_scheme {
        "https" => true,
        "http" => from_scheme == "http",
        // Anything else — file, data, ftp — is not a webhook.
        _ => false,
    }
}

/// The real transport: reqwest over rustls, so a release build needs no system
/// TLS library (same reasoning as the repository-key fetcher in `stack.rs`).
pub struct HttpTransport {
    /// `None` if the client could not be built. Notification failures are never
    /// fatal (spec §11.11), and that includes this one — the agent must still
    /// start.
    client: Option<reqwest::Client>,
}

impl HttpTransport {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                let from = attempt
                    .previous()
                    .last()
                    .map(|u| u.scheme().to_string())
                    .unwrap_or_default();
                if redirect_allowed(&from, attempt.url().scheme(), attempt.previous().len()) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .user_agent(concat!("ferrum-panel/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| {
                tracing::error!(error = %e, "could not build the notification HTTP client");
            })
            .ok();
        Self { client }
    }
}

impl Default for HttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn post_json(&self, url: &str, body: &str) -> std::result::Result<u16, String> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| "the notification HTTP client is unavailable".to_string())?;
        let response = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Ok(response.status().as_u16())
    }
}

/// The process-wide live transport. One client means one connection pool.
fn live_transport() -> &'static HttpTransport {
    static LIVE: OnceLock<HttpTransport> = OnceLock::new();
    LIVE.get_or_init(HttpTransport::new)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
}

/// Reject a webhook URL that is not a URL we would ever POST to.
///
/// Private and loopback addresses are *not* blocked, and that is a decision
/// rather than an oversight: only an admin holding `ServerManage` can add a
/// channel, that admin already has root on this machine, and forbidding
/// `http://127.0.0.1:9000/hook` would break the common and legitimate case of
/// relaying through something local. What is blocked is the part an admin could
/// get wrong by pasting: a non-HTTP scheme, an embedded newline (header
/// injection), or an absurd length.
fn validate_webhook(config: &WebhookConfig) -> Result<()> {
    let url = config.url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "a webhook URL must start with https:// or http://",
        )
        .with_field("config.url"));
    }
    if url.len() > 2048 {
        return Err(
            FerrumError::new(ErrorCode::InvalidInput, "that webhook URL is implausibly long")
                .with_field("config.url"),
        );
    }
    if url.chars().any(|c| c.is_control() || c == ' ') {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "a webhook URL cannot contain spaces or control characters",
        )
        .with_field("config.url"));
    }
    Ok(())
}

/// Reject a Telegram configuration that could rewrite the request path.
///
/// The bot token is interpolated into `https://api.telegram.org/bot<token>/sendMessage`,
/// so a token containing `/`, `?`, `#` or whitespace does not merely fail — it
/// aims the request somewhere else on the host. Telegram's own format is
/// `<digits>:<alphanumerics, `-`, `_`>`, which the check below enforces
/// exactly.
fn validate_telegram(config: &TelegramConfig) -> Result<()> {
    let bad_token = |detail: &str| {
        FerrumError::new(ErrorCode::InvalidInput, detail.to_string()).with_field("config.bot_token")
    };

    let (id, secret) = config
        .bot_token
        .split_once(':')
        .ok_or_else(|| bad_token("a Telegram bot token looks like `123456:AA...`"))?;
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad_token("the part of the token before `:` must be the bot's numeric id"));
    }
    if secret.len() < 20
        || !secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(bad_token(
            "the part of the token after `:` must be at least 20 characters of \
             letters, digits, `-` or `_`",
        ));
    }

    let chat = config.chat_id.trim();
    if chat.is_empty()
        || chat.len() > 64
        || !chat
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b.is_ascii_alphanumeric() || b == b'@')
    {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "a Telegram chat id is a number like `-1001234567890` or an `@channelname`",
        )
        .with_field("config.chat_id"));
    }
    Ok(())
}

/// Check a channel configuration and return it sealed, ready to store.
///
/// The plaintext exists only inside this function; the caller gets a ciphertext
/// and the database never sees anything else (spec §12 rule 6).
fn seal_config(ctx: &OpContext, kind: ChannelKind, config: &serde_json::Value) -> Result<String> {
    let plaintext = match kind {
        ChannelKind::Webhook => {
            let parsed: WebhookConfig = serde_json::from_value(config.clone()).map_err(|e| {
                FerrumError::new(
                    ErrorCode::InvalidInput,
                    format!("a webhook channel needs a `url`: {e}"),
                )
                .with_field("config")
            })?;
            validate_webhook(&parsed)?;
            serde_json::to_string(&parsed)
        }
        ChannelKind::Telegram => {
            let parsed: TelegramConfig = serde_json::from_value(config.clone()).map_err(|e| {
                FerrumError::new(
                    ErrorCode::InvalidInput,
                    format!("a Telegram channel needs a `bot_token` and a `chat_id`: {e}"),
                )
                .with_field("config")
            })?;
            validate_telegram(&parsed)?;
            serde_json::to_string(&parsed)
        }
    }
    .expect("a struct of owned Strings always serialises");

    ctx.master_key()
        .seal_str(&plaintext)
        .map_err(FerrumError::from)
}

/// Send one payload to one channel.
///
/// Returns the failure rather than logging it, so the caller can report *which*
/// channel broke; the caller is also the one that guarantees a failure here is
/// never fatal.
async fn deliver(
    ctx: &OpContext,
    transport: &dyn Transport,
    channel: &NotifyChannel,
    payload: &NotificationPayload,
) -> std::result::Result<(), String> {
    let opened = ctx
        .master_key()
        .open_str(&channel.config_sealed)
        .map_err(|e| {
            format!("its stored configuration could not be decrypted ({e}); re-enter it")
        })?;

    let (url, body) = match channel.kind {
        ChannelKind::Webhook => {
            let config: WebhookConfig = serde_json::from_str(&opened)
                .map_err(|e| format!("its stored configuration is not a webhook config: {e}"))?;
            let body = serde_json::to_string(payload)
                .map_err(|e| format!("the payload would not serialise: {e}"))?;
            (config.url, body)
        }
        ChannelKind::Telegram => {
            let config: TelegramConfig = serde_json::from_str(&opened)
                .map_err(|e| format!("its stored configuration is not a Telegram config: {e}"))?;
            // Re-validated on the way out, not only on the way in: a row that
            // predates the validation (or was hand-edited) must not be able to
            // steer the request path.
            validate_telegram(&config).map_err(|e| e.detail)?;
            let body = serde_json::to_string(&serde_json::json!({
                "chat_id": config.chat_id,
                "text": telegram_text(payload),
                "disable_web_page_preview": true,
            }))
            .map_err(|e| format!("the payload would not serialise: {e}"))?;
            (
                format!(
                    "https://api.telegram.org/bot{}/sendMessage",
                    config.bot_token
                ),
                body,
            )
        }
    };

    match transport.post_json(&url, &body).await {
        Ok(status) if (200..300).contains(&status) => Ok(()),
        Ok(status) => Err(format!("the endpoint answered HTTP {status}")),
        Err(e) => Err(e),
    }
}

/// Telegram takes plain text, not the JSON envelope a webhook gets.
fn telegram_text(payload: &NotificationPayload) -> String {
    let icon = if payload.state == AlertState::Resolved.as_str() {
        "RESOLVED"
    } else {
        "ALERT"
    };
    format!(
        "[{icon}] {panel}\n{message}\n({rule}, {at})",
        panel = payload.panel,
        message = payload.message,
        rule = payload.rule,
        at = payload.at,
    )
}

/// Send one payload to every enabled channel.
///
/// Returns how many channels took it. **Never fails**: a broken webhook is a
/// problem with the webhook, and it must not be able to stop the panel from
/// recording that the disk is full (spec §11.11).
pub async fn notify(
    ctx: &OpContext,
    transport: &dyn Transport,
    payload: &NotificationPayload,
) -> usize {
    let channels = match ctx.db().enabled_notify_channels().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "could not read the notification channels");
            return 0;
        }
    };

    let mut delivered = 0usize;
    for channel in &channels {
        match deliver(ctx, transport, channel, payload).await {
            Ok(()) => delivered += 1,
            Err(e) => {
                // The label, never the configuration: the URL is a credential.
                tracing::warn!(
                    channel = %channel.label,
                    kind = channel.kind.as_str(),
                    error = %e,
                    "an alert notification could not be delivered"
                );
                ctx.log(format!(
                    "notification channel `{}` failed: {e}",
                    channel.label
                ));
            }
        }
    }
    delivered
}

// ---------------------------------------------------------------------------
// evaluation
// ---------------------------------------------------------------------------

/// One edge that actually happened, as the scheduler and the API see it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Raised {
    pub event_id: i64,
    pub rule_id: i64,
    pub rule: String,
    pub subject: String,
    pub message: String,
    pub state: AlertState,
    pub value: Option<f64>,
    /// How many channels took the notification. Zero with channels configured
    /// means they all failed; zero with none configured is the default install.
    pub notified: usize,
}

/// A ceiling on notifications per pass.
///
/// Notification is network IO inside the scheduler's tick, so a pathological
/// pass (a rule that suddenly matches forty filesystems) must not be able to
/// hold the schedule still for forty timeouts. Everything above the cap is
/// still recorded in `alert_events` with `notified = 0`, so nothing is lost —
/// it just is not shouted about.
const MAX_NOTIFICATIONS_PER_PASS: usize = 20;

/// Evaluate every rule, apply the transitions, notify on each one.
///
/// This is what the scheduler calls once a minute (spec §10.2).
pub async fn evaluate(ctx: &OpContext) -> Result<Vec<Raised>> {
    evaluate_with(ctx, live_transport()).await
}

/// [`evaluate`] with an injected transport, for tests.
pub async fn evaluate_with(ctx: &OpContext, transport: &dyn Transport) -> Result<Vec<Raised>> {
    let db = ctx.db();

    // Every rule, not only the enabled ones: `plan` closes the open events of a
    // rule that has since been switched off.
    let rules = db.alert_rules().await.map_err(FerrumError::from)?;
    if rules.is_empty() {
        return Ok(Vec::new());
    }

    let readings = collect(ctx, &rules).await?;
    let open = db.open_alert_events().await.map_err(FerrumError::from)?;
    let transitions = plan(&rules, &readings, &open);
    if transitions.is_empty() {
        return Ok(Vec::new());
    }

    let by_id: BTreeMap<i64, &AlertRule> = rules.iter().map(|r| (r.id, r)).collect();
    let panel = db
        .get_setting_or(
            ferrum_db::settings::keys::PANEL_NAME,
            "Ferrum".to_string(),
        )
        .await;

    let mut out = Vec::new();
    for transition in transitions {
        let rule_id = match &transition {
            Transition::Raise { rule_id, .. } | Transition::Resolve { rule_id, .. } => *rule_id,
        };
        let label = by_id
            .get(&rule_id)
            .map(|r| r.label())
            .unwrap_or_else(|| rule_id.to_string());

        // Write first, then notify. A crash between the two costs one missing
        // message; the other order would cost a message per minute forever,
        // because nothing would remember the alert had been raised.
        let (event, message, value) = match transition {
            Transition::Raise {
                subject,
                message,
                value,
                ..
            } => {
                match db
                    .raise_alert(rule_id, &subject, &message, value)
                    .await
                    .map_err(FerrumError::from)?
                {
                    Some(event) => (event, message, value),
                    // Another pass got there first. Correct outcome, no message.
                    None => continue,
                }
            }
            Transition::Resolve {
                event_id,
                message,
                value,
                ..
            } => match db
                .resolve_alert(event_id)
                .await
                .map_err(FerrumError::from)?
            {
                Some(event) => (event, message, value),
                None => continue,
            },
        };

        let state = if event.is_open() {
            AlertState::Raised
        } else {
            AlertState::Resolved
        };

        let notified = if out.len() < MAX_NOTIFICATIONS_PER_PASS {
            let payload = NotificationPayload {
                panel: panel.clone(),
                rule: label.clone(),
                message: message.clone(),
                state: state.as_str().to_string(),
                at: ferrum_db::to_sql_time(ferrum_db::now()),
            };
            let n = notify(ctx, transport, &payload).await;
            if n > 0 {
                // Best-effort bookkeeping: failing to record a delivery must not
                // undo the delivery.
                let _ = db.mark_alert_notified(event.id).await;
            }
            n
        } else {
            tracing::warn!(
                cap = MAX_NOTIFICATIONS_PER_PASS,
                "too many alert transitions in one pass; the rest are recorded but not sent"
            );
            0
        };

        ctx.log(format!("[{}] {message}", state.as_str()));
        out.push(Raised {
            event_id: event.id,
            rule_id,
            rule: label,
            subject: event.subject,
            message,
            state,
            value,
            notified,
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// operations
// ---------------------------------------------------------------------------

/// `alert.rules.list` — the configured rules and what is currently firing.
pub struct RulesList;

#[derive(Debug, Deserialize)]
pub struct RulesListInput {}

#[derive(Debug, Serialize)]
pub struct RulesListOutput {
    pub rules: Vec<AlertRule>,
    /// The events open right now, so the settings page can show which rule is
    /// red without a second round trip.
    pub open: Vec<AlertEvent>,
    /// Every kind a rule may have, for the form's select.
    pub kinds: Vec<&'static str>,
}

#[async_trait]
impl TypedOperation for RulesList {
    type Input = RulesListInput;
    type Output = RulesListOutput;

    const NAME: &'static str = "alert.rules.list";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        Ok(RulesListOutput {
            rules: ctx.db().alert_rules().await.map_err(FerrumError::from)?,
            open: ctx
                .db()
                .open_alert_events()
                .await
                .map_err(FerrumError::from)?,
            kinds: AlertKind::ALL.iter().map(|k| k.as_str()).collect(),
        })
    }
}

/// `alert.rules.set` — create or edit the rule for one `(kind, target)`.
pub struct RulesSet;

#[derive(Debug, Deserialize)]
pub struct RulesSetInput {
    pub kind: AlertKind,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub threshold: Option<f64>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct RulesSetOutput {
    pub rule: AlertRule,
}

#[async_trait]
impl TypedOperation for RulesSet {
    type Input = RulesSetInput;
    type Output = RulesSetOutput;

    const NAME: &'static str = "alert.rules.set";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let target = input
            .target
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string);
        let threshold = validate_rule(input.kind, target.as_deref(), input.threshold)?;

        let rule = ctx
            .db()
            .set_alert_rule(input.kind, target.as_deref(), threshold, input.enabled)
            .await
            .map_err(FerrumError::from)?;
        Ok(RulesSetOutput { rule })
    }
}

/// Check a rule the operator is trying to save, and settle its threshold.
///
/// The bounds are not pedantry: a `disk_pct` rule at 0 fires on every disk on
/// the machine the moment it is saved and never stops, which is exactly the
/// alert-fatigue failure this whole module is written to avoid.
fn validate_rule(kind: AlertKind, target: Option<&str>, threshold: Option<f64>) -> Result<f64> {
    let field = |detail: String, f: &'static str| {
        FerrumError::new(ErrorCode::InvalidInput, detail).with_field(f)
    };

    match kind {
        AlertKind::ServiceDown => {
            let target = target.ok_or_else(|| {
                field(
                    "a service_down rule has to name the service to watch".into(),
                    "target",
                )
            })?;
            if service_target(target).is_none() {
                return Err(field(
                    format!(
                        "`{target}` is not a service the panel manages; use one of \
                         nginx, mariadb, postgresql, kv_store, docker, sshd, \
                         ferrum_web, ferrum_agentd or php_fpm:<version>"
                    ),
                    "target",
                ));
            }
            // Boolean rule: the stored threshold is a sentinel, and letting an
            // operator set it to 0.5 would be a knob that means nothing.
            return Ok(1.0);
        }
        AlertKind::DiskPct => {
            if let Some(t) = target
                && !t.starts_with('/')
            {
                return Err(field(
                    format!("`{t}` is not a mount point; leave the target empty to watch every filesystem"),
                    "target",
                ));
            }
        }
        AlertKind::MemPct | AlertKind::Load => {
            if target.is_some() {
                return Err(field(
                    format!("a {} rule watches the whole server and takes no target", kind.as_str()),
                    "target",
                ));
            }
        }
        // A cert rule may name one domain or watch them all.
        AlertKind::CertExpiryDays => {}
    }

    let threshold = threshold.ok_or_else(|| {
        field(
            format!("a {} rule needs a threshold", kind.as_str()),
            "threshold",
        )
    })?;
    if !threshold.is_finite() {
        return Err(field("the threshold must be a number".into(), "threshold"));
    }

    let (low, high, unit) = match kind {
        AlertKind::DiskPct | AlertKind::MemPct => (1.0, 100.0, "a percentage between 1 and 100"),
        // Above 1000 the machine is not loaded, the number is a typo.
        AlertKind::Load => (0.1, 1000.0, "a load average between 0.1 and 1000"),
        // Beyond 89 days a rule would fire the instant a 90-day certificate is
        // issued, which is not a warning, it is a stuck horn.
        AlertKind::CertExpiryDays => (1.0, 89.0, "a number of days between 1 and 89"),
        AlertKind::ServiceDown => unreachable!("returned above"),
    };
    if threshold < low || threshold > high {
        return Err(field(
            format!("the threshold for a {} rule must be {unit}", kind.as_str()),
            "threshold",
        ));
    }
    Ok(threshold)
}

/// `alert.events.list` — the alert history.
pub struct EventsList;

#[derive(Debug, Deserialize)]
pub struct EventsListInput {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub open_only: bool,
}

#[derive(Debug, Serialize)]
pub struct EventsListOutput {
    pub events: Vec<AlertEvent>,
}

#[async_trait]
impl TypedOperation for EventsList {
    type Input = EventsListInput;
    type Output = EventsListOutput;

    const NAME: &'static str = "alert.events.list";
    // A read: alert history is dashboard content, and the dashboard is
    // `ServerRead`. Nothing here is a secret — the channel configuration, which
    // is, lives behind `alert.channels.list`.
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let events = if input.open_only {
            ctx.db()
                .open_alert_events()
                .await
                .map_err(FerrumError::from)?
        } else {
            ctx.db()
                .recent_alert_events(input.limit.unwrap_or(100))
                .await
                .map_err(FerrumError::from)?
        };
        Ok(EventsListOutput { events })
    }
}

/// `alert.channels.list` — configured channels, never their configuration.
pub struct ChannelsList;

#[derive(Debug, Deserialize)]
pub struct ChannelsListInput {}

#[derive(Debug, Serialize)]
pub struct ChannelsListOutput {
    pub channels: Vec<NotifyChannel>,
}

#[async_trait]
impl TypedOperation for ChannelsList {
    type Input = ChannelsListInput;
    type Output = ChannelsListOutput;

    const NAME: &'static str = "alert.channels.list";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        Ok(ChannelsListOutput {
            // `NotifyChannel` skips `config_sealed` in its Serialize impl, so
            // this cannot leak the sealed blob even by accident.
            channels: ctx.db().notify_channels().await.map_err(FerrumError::from)?,
        })
    }
}

/// `alert.channels.set` — add a channel, or edit one.
pub struct ChannelsSet;

#[derive(Debug, Deserialize)]
pub struct ChannelsSetInput {
    /// Absent = create.
    #[serde(default)]
    pub id: Option<i64>,
    #[serde(default)]
    pub kind: Option<ChannelKind>,
    #[serde(default)]
    pub label: Option<String>,
    /// Absent on an edit = keep whatever is stored, so renaming a channel does
    /// not require the operator to paste the bot token again.
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ChannelsSetOutput {
    pub channel: NotifyChannel,
}

#[async_trait]
impl TypedOperation for ChannelsSet {
    type Input = ChannelsSetInput;
    type Output = ChannelsSetOutput;

    const NAME: &'static str = "alert.channels.set";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let label = input
            .label
            .as_deref()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string);

        let channel = match input.id {
            None => {
                let kind = input.kind.ok_or_else(|| {
                    FerrumError::new(ErrorCode::InvalidInput, "a new channel needs a `kind`")
                        .with_field("kind")
                })?;
                let label = label.ok_or_else(|| {
                    FerrumError::new(ErrorCode::InvalidInput, "a new channel needs a `label`")
                        .with_field("label")
                })?;
                let config = input.config.ok_or_else(|| {
                    FerrumError::new(
                        ErrorCode::InvalidInput,
                        "a new channel needs its `config`",
                    )
                    .with_field("config")
                })?;
                let sealed = seal_config(ctx, kind, &config)?;
                ctx.db()
                    .create_notify_channel(kind, &label, &sealed, input.enabled.unwrap_or(true))
                    .await
                    .map_err(FerrumError::from)?
            }
            Some(id) => {
                let existing = ctx
                    .db()
                    .notify_channel(id)
                    .await
                    .map_err(FerrumError::from)?
                    .ok_or_else(|| FerrumError::not_found("notify channel"))?;
                // A channel's kind is fixed. Reinterpreting a stored Telegram
                // config as a webhook would either fail confusingly or, worse,
                // POST a bot token at somebody's URL.
                if let Some(kind) = input.kind
                    && kind != existing.kind
                {
                    return Err(FerrumError::new(
                        ErrorCode::Conflict,
                        "a channel's kind cannot be changed; delete it and add a new one",
                    )
                    .with_field("kind"));
                }
                let sealed = input
                    .config
                    .as_ref()
                    .map(|c| seal_config(ctx, existing.kind, c))
                    .transpose()?;
                ctx.db()
                    .update_notify_channel(id, label.as_deref(), sealed.as_deref(), input.enabled)
                    .await
                    .map_err(FerrumError::from)?
            }
        };

        Ok(ChannelsSetOutput { channel })
    }
}

/// `alert.channels.delete` — remove a channel.
pub struct ChannelsDelete;

#[derive(Debug, Deserialize)]
pub struct ChannelsDeleteInput {
    pub id: i64,
}

#[derive(Debug, Serialize)]
pub struct ChannelsDeleteOutput {
    pub deleted: bool,
}

#[async_trait]
impl TypedOperation for ChannelsDelete {
    type Input = ChannelsDeleteInput;
    type Output = ChannelsDeleteOutput;

    const NAME: &'static str = "alert.channels.delete";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let deleted = ctx
            .db()
            .delete_notify_channel(input.id)
            .await
            .map_err(FerrumError::from)?;
        if !deleted {
            return Err(FerrumError::not_found("notify channel"));
        }
        Ok(ChannelsDeleteOutput { deleted })
    }
}

/// `alert.channels.test` — send a test notification through one channel.
///
/// Worth an operation of its own because the alternative is finding out that
/// the bot token was pasted with a trailing space at three in the morning,
/// during the outage the channel existed to report.
pub struct ChannelsTest {
    transport: Arc<dyn Transport>,
}

impl ChannelsTest {
    /// The registered form: talks to the real network.
    pub fn live() -> Self {
        Self {
            transport: Arc::new(HttpTransport::new()),
        }
    }

    /// For tests, and for anything that wants to substitute the transport.
    pub fn with_transport(transport: Arc<dyn Transport>) -> Self {
        Self { transport }
    }
}

#[derive(Debug, Deserialize)]
pub struct ChannelsTestInput {
    pub id: i64,
}

#[derive(Debug, Serialize)]
pub struct ChannelsTestOutput {
    pub delivered: bool,
    /// Why it failed, in words an operator can act on. `None` on success.
    pub detail: Option<String>,
}

#[async_trait]
impl TypedOperation for ChannelsTest {
    type Input = ChannelsTestInput;
    type Output = ChannelsTestOutput;

    const NAME: &'static str = "alert.channels.test";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let channel = ctx
            .db()
            .notify_channel(input.id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("notify channel"))?;

        let panel = ctx
            .db()
            .get_setting_or(
                ferrum_db::settings::keys::PANEL_NAME,
                "Ferrum".to_string(),
            )
            .await;
        let payload = NotificationPayload {
            panel,
            rule: "test".into(),
            message: format!("test notification from the `{}` channel", channel.label),
            state: AlertState::Resolved.as_str().to_string(),
            at: ferrum_db::to_sql_time(ferrum_db::now()),
        };

        // A failed test is a 200 with `delivered: false`, not an error: the
        // operator asked "does this work?" and "no, because the endpoint
        // answered 403" is a successful answer to that question.
        match deliver(ctx, self.transport.as_ref(), &channel, &payload).await {
            Ok(()) => Ok(ChannelsTestOutput {
                delivered: true,
                detail: None,
            }),
            Err(detail) => Ok(ChannelsTestOutput {
                delivered: false,
                detail: Some(detail),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use ferrum_core::Role;
    use ferrum_metrics::{CpuUsage, DiskUsage, LoadAverage, MemoryUsage, NetworkTotals};
    use serde_json::json;
    use std::sync::Mutex;

    // -- fixtures ----------------------------------------------------------

    fn snapshot(disks: Vec<(&str, u64, u64)>, mem_pct: u64, load: f64) -> ServerSnapshot {
        ServerSnapshot {
            at: time::OffsetDateTime::UNIX_EPOCH,
            uptime_seconds: 1,
            load: LoadAverage {
                one: load,
                five: load,
                fifteen: load,
            },
            cpu: CpuUsage {
                cores: 2,
                usage_pct: 10.0,
            },
            memory: MemoryUsage {
                total_bytes: 100,
                used_bytes: mem_pct,
                available_bytes: 100 - mem_pct,
                swap_total_bytes: 0,
                swap_used_bytes: 0,
            },
            disks: disks
                .into_iter()
                .map(|(mount, used, total)| DiskUsage {
                    mount: mount.into(),
                    filesystem: "ext4".into(),
                    total_bytes: total,
                    used_bytes: used,
                    available_bytes: total - used,
                })
                .collect(),
            network: NetworkTotals {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_bytes_per_sec: 0,
                tx_bytes_per_sec: 0,
            },
            panel: Default::default(),
        }
    }

    fn readings_with_disk(used_pct: u64) -> Readings {
        Readings {
            snapshot: snapshot(vec![("/", used_pct, 100)], 10, 0.1),
            services: BTreeMap::new(),
            certificates: Vec::new(),
        }
    }

    fn rule(id: i64, kind: AlertKind, target: Option<&str>, threshold: f64) -> AlertRule {
        AlertRule {
            id,
            kind,
            target: target.map(str::to_string),
            threshold,
            enabled: true,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn open_event(id: i64, rule_id: i64, subject: &str) -> AlertEvent {
        AlertEvent {
            id,
            rule_id,
            subject: subject.into(),
            message: "…".into(),
            value: None,
            raised_at: time::OffsetDateTime::UNIX_EPOCH,
            resolved_at: None,
            notified: 1,
        }
    }

    /// Records every POST instead of making one.
    #[derive(Default)]
    struct RecordingTransport {
        sent: Mutex<Vec<(String, String)>>,
        fail_with: Option<String>,
        status: Option<u16>,
    }

    impl RecordingTransport {
        fn sent(&self) -> Vec<(String, String)> {
            self.sent.lock().expect("transport log").clone()
        }
        fn bodies(&self) -> Vec<serde_json::Value> {
            self.sent()
                .into_iter()
                .map(|(_, b)| serde_json::from_str(&b).expect("bodies are JSON"))
                .collect()
        }
    }

    #[async_trait]
    impl Transport for RecordingTransport {
        async fn post_json(&self, url: &str, body: &str) -> std::result::Result<u16, String> {
            self.sent
                .lock()
                .expect("transport log")
                .push((url.to_string(), body.to_string()));
            match &self.fail_with {
                Some(e) => Err(e.clone()),
                None => Ok(self.status.unwrap_or(200)),
            }
        }
    }

    // -- thresholds and hysteresis ----------------------------------------

    #[test]
    fn a_rising_rule_starts_at_the_threshold_and_ends_below_the_band() {
        let k = AlertKind::DiskPct;
        assert!(breaches(k, 90.0, 90.0), "the threshold itself counts");
        assert!(breaches(k, 90.0, 99.9));
        assert!(!breaches(k, 90.0, 89.9));

        assert!(!clears(k, 90.0, 89.9), "still inside the band");
        assert!(!clears(k, 90.0, 88.0), "the band edge is not past it");
        assert!(clears(k, 90.0, 87.9));
    }

    #[test]
    fn a_falling_rule_reads_the_other_way_round() {
        // Certificate days: small is bad.
        let k = AlertKind::CertExpiryDays;
        assert!(breaches(k, 14.0, 14.0));
        assert!(breaches(k, 14.0, 0.0));
        assert!(breaches(k, 14.0, -3.0), "already expired is very much a breach");
        assert!(!breaches(k, 14.0, 15.0));

        assert!(!clears(k, 14.0, 15.0), "inside the one-day band");
        assert!(clears(k, 14.0, 16.0), "a renewal jumps it to ~90");
    }

    #[test]
    fn there_is_a_band_where_a_reading_changes_nothing() {
        // This gap *is* the debounce. Anything in it leaves the alert as it was.
        for value in [88.0, 88.5, 89.0, 89.9] {
            assert!(!breaches(AlertKind::DiskPct, 90.0, value));
            assert!(!clears(AlertKind::DiskPct, 90.0, value));
        }
    }

    #[test]
    fn a_service_is_down_only_when_it_has_actually_stopped() {
        assert!(service_is_down(UnitState::Inactive));
        assert!(service_is_down(UnitState::Failed));
        // A restart passes through these; alerting on them would make every
        // nginx reload look like an outage.
        assert!(!service_is_down(UnitState::Activating));
        assert!(!service_is_down(UnitState::Deactivating));
        assert!(!service_is_down(UnitState::Active));
        assert!(!service_is_down(UnitState::NotFound));
    }

    #[test]
    fn only_managed_units_can_be_named_by_a_service_rule() {
        assert_eq!(service_target("nginx"), Some(ManagedUnit::Nginx));
        assert!(service_target("php_fpm:8.3").is_some());
        for hostile in [
            "evil.service",
            "nginx.service",
            "../../etc/passwd",
            "nginx; rm -rf /",
            "php_fpm:9.9",
            "",
            "NGINX",
        ] {
            assert!(
                service_target(hostile).is_none(),
                "`{hostile}` must not resolve to a unit"
            );
        }
    }

    // -- the state machine -------------------------------------------------

    #[test]
    fn a_disk_hovering_at_the_threshold_raises_once_and_then_says_nothing() {
        // The failure this module exists to prevent: sixty samples of a disk
        // that is genuinely at 90% must produce one message, not sixty.
        let rules = vec![rule(1, AlertKind::DiskPct, None, 90.0)];
        let mut open: Vec<AlertEvent> = Vec::new();
        let mut raises = 0;
        let mut resolves = 0;

        // A realistic wobble around the line, including dipping under it.
        let samples = [90, 91, 89, 90, 88, 90, 89, 91, 90, 89, 88, 90];
        for (i, used) in samples.iter().cycle().take(60).enumerate() {
            let transitions = plan(&rules, &readings_with_disk(*used), &open);
            for t in transitions {
                match t {
                    Transition::Raise { subject, .. } => {
                        raises += 1;
                        open.push(open_event(100 + i as i64, 1, &subject));
                    }
                    Transition::Resolve { event_id, .. } => {
                        resolves += 1;
                        open.retain(|e| e.id != event_id);
                    }
                }
            }
        }

        assert_eq!(raises, 1, "one message, on the way in");
        assert_eq!(resolves, 0, "88% is inside the band, not a recovery");
    }

    #[test]
    fn a_disk_that_really_fills_and_is_really_cleaned_up_sends_exactly_two() {
        let rules = vec![rule(1, AlertKind::DiskPct, None, 90.0)];
        let mut open: Vec<AlertEvent> = Vec::new();
        let mut messages: Vec<AlertState> = Vec::new();

        // Ten samples full, ten samples cleaned up, ten more full again.
        let script: Vec<u64> = std::iter::repeat_n(95u64, 10)
            .chain(std::iter::repeat_n(40, 10))
            .chain(std::iter::repeat_n(95, 10))
            .collect();

        for (i, used) in script.into_iter().enumerate() {
            for t in plan(&rules, &readings_with_disk(used), &open) {
                messages.push(t.state());
                match t {
                    Transition::Raise { subject, .. } => open.push(open_event(200 + i as i64, 1, &subject)),
                    Transition::Resolve { event_id, .. } => open.retain(|e| e.id != event_id),
                }
            }
        }

        assert_eq!(
            messages,
            vec![AlertState::Raised, AlertState::Resolved, AlertState::Raised],
            "thirty evaluations, three real state changes"
        );
    }

    #[test]
    fn each_filesystem_gets_its_own_event() {
        let rules = vec![rule(1, AlertKind::DiskPct, None, 90.0)];
        let readings = Readings {
            snapshot: snapshot(vec![("/", 95, 100), ("/var", 20, 100)], 10, 0.1),
            services: BTreeMap::new(),
            certificates: Vec::new(),
        };

        let first = plan(&rules, &readings, &[]);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].subject(), "/");

        // With `/` already open, `/var` filling up must still be heard.
        let readings = Readings {
            snapshot: snapshot(vec![("/", 95, 100), ("/var", 99, 100)], 10, 0.1),
            ..readings
        };
        let second = plan(&rules, &readings, &[open_event(1, 1, "/")]);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].subject(), "/var");
        assert_eq!(second[0].state(), AlertState::Raised);
    }

    #[test]
    fn a_targeted_disk_rule_ignores_every_other_filesystem() {
        let rules = vec![rule(1, AlertKind::DiskPct, Some("/var"), 90.0)];
        let readings = Readings {
            snapshot: snapshot(vec![("/", 99, 100), ("/var", 10, 100)], 10, 0.1),
            services: BTreeMap::new(),
            certificates: Vec::new(),
        };
        assert!(plan(&rules, &readings, &[]).is_empty());
    }

    #[test]
    fn an_unmounted_filesystem_closes_its_open_alert() {
        let rules = vec![rule(1, AlertKind::DiskPct, None, 90.0)];
        let readings = Readings {
            snapshot: snapshot(vec![("/", 10, 100)], 10, 0.1),
            services: BTreeMap::new(),
            certificates: Vec::new(),
        };
        let transitions = plan(&rules, &readings, &[open_event(7, 1, "/mnt/backup")]);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].state(), AlertState::Resolved);
        assert!(matches!(
            &transitions[0],
            Transition::Resolve { message, .. } if message.contains("no longer being reported")
        ));
    }

    #[test]
    fn disabling_a_rule_closes_the_alerts_it_had_open() {
        let mut r = rule(1, AlertKind::DiskPct, None, 90.0);
        r.enabled = false;
        let transitions = plan(&[r], &readings_with_disk(99), &[open_event(3, 1, "/")]);
        assert_eq!(transitions.len(), 1, "and it does not re-raise while disabled");
        assert_eq!(transitions[0].state(), AlertState::Resolved);
    }

    #[test]
    fn memory_and_load_rules_read_the_snapshot_they_are_given() {
        let readings = Readings {
            snapshot: snapshot(vec![], 96, 12.5),
            services: BTreeMap::new(),
            certificates: Vec::new(),
        };
        let rules = vec![
            rule(1, AlertKind::MemPct, None, 95.0),
            rule(2, AlertKind::Load, None, 8.0),
        ];
        let transitions = plan(&rules, &readings, &[]);
        assert_eq!(transitions.len(), 2);
        assert_eq!(transitions[0].subject(), "memory");
        assert_eq!(transitions[1].subject(), "load");
    }

    #[test]
    fn a_service_rule_says_nothing_about_a_service_that_is_not_installed() {
        // An absent reading is "we do not know", not "it is down".
        let rules = vec![rule(1, AlertKind::ServiceDown, Some("mariadb"), 1.0)];
        let readings = Readings {
            snapshot: snapshot(vec![], 10, 0.1),
            services: BTreeMap::new(),
            certificates: Vec::new(),
        };
        assert!(plan(&rules, &readings, &[]).is_empty());
    }

    #[test]
    fn an_expiring_certificate_raises_and_a_renewed_one_resolves() {
        let rules = vec![rule(1, AlertKind::CertExpiryDays, None, 14.0)];
        let expiring = Readings {
            snapshot: snapshot(vec![], 10, 0.1),
            services: BTreeMap::new(),
            certificates: vec![("example.com".into(), 3.0)],
        };
        let raise = plan(&rules, &expiring, &[]);
        assert_eq!(raise.len(), 1);
        assert!(matches!(&raise[0], Transition::Raise { message, .. } if message.contains("expires in 3 days")));

        // Still inside the band the day after: no second message.
        let renewed = Readings {
            certificates: vec![("example.com".into(), 15.0)],
            ..expiring.clone()
        };
        assert!(plan(&rules, &renewed, &[open_event(1, 1, "example.com")]).is_empty());

        // A real renewal jumps to ninety days.
        let renewed = Readings {
            certificates: vec![("example.com".into(), 89.0)],
            ..expiring
        };
        let resolve = plan(&rules, &renewed, &[open_event(1, 1, "example.com")]);
        assert_eq!(resolve.len(), 1);
        assert_eq!(resolve[0].state(), AlertState::Resolved);
    }

    // -- rule validation ---------------------------------------------------

    #[test]
    fn rule_validation_refuses_thresholds_that_would_fire_forever() {
        for (kind, target, threshold) in [
            (AlertKind::DiskPct, None, Some(0.0)),
            (AlertKind::DiskPct, None, Some(101.0)),
            (AlertKind::MemPct, None, Some(-5.0)),
            (AlertKind::Load, None, Some(0.0)),
            (AlertKind::CertExpiryDays, None, Some(90.0)),
            (AlertKind::CertExpiryDays, None, Some(0.0)),
            (AlertKind::DiskPct, None, Some(f64::NAN)),
            (AlertKind::DiskPct, None, Some(f64::INFINITY)),
            (AlertKind::DiskPct, None, None),
            // Wrong shape rather than wrong number:
            (AlertKind::MemPct, Some("/"), Some(90.0)),
            (AlertKind::Load, Some("cpu0"), Some(1.0)),
            (AlertKind::DiskPct, Some("var"), Some(90.0)),
            (AlertKind::ServiceDown, None, Some(1.0)),
            (AlertKind::ServiceDown, Some("evil.service"), Some(1.0)),
        ] {
            let err = validate_rule(kind, target, threshold)
                .expect_err("{kind:?} {target:?} {threshold:?} should be refused");
            assert_eq!(err.code, ErrorCode::InvalidInput);
        }

        assert_eq!(validate_rule(AlertKind::DiskPct, None, Some(90.0)).unwrap(), 90.0);
        // A boolean rule's threshold is settled for it.
        assert_eq!(
            validate_rule(AlertKind::ServiceDown, Some("nginx"), Some(0.3)).unwrap(),
            1.0
        );
    }

    // -- channel configuration --------------------------------------------

    #[test]
    fn a_webhook_url_that_is_not_a_webhook_url_is_refused() {
        for bad in [
            "ftp://example.com/hook",
            "file:///etc/shadow",
            "javascript:alert(1)",
            "example.com/hook",
            "https://example.com/a\nb",
            "https://exa mple.com/",
        ] {
            let err = validate_webhook(&WebhookConfig { url: bad.into() }).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "`{bad}` should be refused");
        }
        assert!(validate_webhook(&WebhookConfig {
            url: "https://hooks.example.test/services/T0/B0/xyz".into()
        })
        .is_ok());
        // Loopback is allowed on purpose — see validate_webhook's comment.
        assert!(validate_webhook(&WebhookConfig {
            url: "http://127.0.0.1:9000/hook".into()
        })
        .is_ok());
    }

    #[test]
    fn a_telegram_token_cannot_rewrite_the_request_path() {
        // The token is interpolated into the URL path, so this is the hostile
        // input that matters most in the module.
        for bad in [
            "123456:../../../botOTHER/getUpdates",
            "123456:aaaa/bbbbbbbbbbbbbbbbbbbb",
            "123456:aaaa?bbbbbbbbbbbbbbbbbbbb",
            "123456:aaaa#bbbbbbbbbbbbbbbbbbbb",
            "123456:aaaa bbbbbbbbbbbbbbbbbbbb",
            "abcdef:AAaaaaaaaaaaaaaaaaaaaaaaaaa",
            "123456:short",
            "no-colon-at-all",
            "",
        ] {
            let err = validate_telegram(&TelegramConfig {
                bot_token: bad.into(),
                chat_id: "-1001234567890".into(),
            })
            .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "`{bad}` should be refused");
        }

        assert!(validate_telegram(&TelegramConfig {
            bot_token: "123456789:AAHkq-Zx_pQ1234567890abcdefghij".into(),
            chat_id: "-1001234567890".into(),
        })
        .is_ok());

        // And the chat id gets the same treatment.
        let err = validate_telegram(&TelegramConfig {
            bot_token: "123456789:AAHkq-Zx_pQ1234567890abcdefghij".into(),
            chat_id: "../../evil".into(),
        })
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn one_redirect_is_followed_and_a_downgrade_never_is() {
        assert!(redirect_allowed("https", "https", 1));
        assert!(redirect_allowed("http", "https", 1), "an upgrade is fine");
        assert!(redirect_allowed("http", "http", 1));
        assert!(
            !redirect_allowed("https", "http", 1),
            "a webhook URL is a credential; it must not fall back to cleartext"
        );
        assert!(!redirect_allowed("https", "https", 2), "one hop, no more");
        assert!(!redirect_allowed("https", "file", 1));
    }

    // -- notification ------------------------------------------------------

    async fn admin_ctx() -> (crate::registry::OpRegistry, OpContext) {
        let (reg, admin, _) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        (reg, ctx)
    }

    async fn add_channel(ctx: &OpContext, kind: ChannelKind, label: &str, config: serde_json::Value) -> i64 {
        let sealed = seal_config(ctx, kind, &config).expect("the fixture config is valid");
        ctx.db()
            .create_notify_channel(kind, label, &sealed, true)
            .await
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn a_webhook_gets_the_documented_payload() {
        let (_reg, ctx) = admin_ctx().await;
        add_channel(
            &ctx,
            ChannelKind::Webhook,
            "ops",
            json!({ "url": "https://hooks.example.test/abc" }),
        )
        .await;

        let transport = RecordingTransport::default();
        let payload = NotificationPayload {
            panel: "Ferrum".into(),
            rule: "disk_pct".into(),
            message: "filesystem / is 94.0% full (alert above 90%)".into(),
            state: "raised".into(),
            at: "2026-08-26T09:00:00Z".into(),
        };
        assert_eq!(notify(&ctx, &transport, &payload).await, 1);

        let sent = transport.sent();
        assert_eq!(sent[0].0, "https://hooks.example.test/abc");
        // The wire shape is somebody's integration; pin it.
        assert_eq!(
            transport.bodies()[0],
            json!({
                "panel": "Ferrum",
                "rule": "disk_pct",
                "message": "filesystem / is 94.0% full (alert above 90%)",
                "state": "raised",
                "at": "2026-08-26T09:00:00Z",
            })
        );
    }

    #[tokio::test]
    async fn telegram_posts_sendmessage_with_the_token_in_the_path_only() {
        let (_reg, ctx) = admin_ctx().await;
        add_channel(
            &ctx,
            ChannelKind::Telegram,
            "ops room",
            json!({
                "bot_token": "123456789:AAHkq-Zx_pQ1234567890abcdefghij",
                "chat_id": "-1001234567890",
            }),
        )
        .await;

        let transport = RecordingTransport::default();
        let payload = NotificationPayload {
            panel: "Ferrum".into(),
            rule: "service_down:nginx".into(),
            message: "nginx is not running".into(),
            state: "raised".into(),
            at: "2026-08-26T09:00:00Z".into(),
        };
        assert_eq!(notify(&ctx, &transport, &payload).await, 1);

        let (url, body) = transport.sent().remove(0);
        assert_eq!(
            url,
            "https://api.telegram.org/bot123456789:AAHkq-Zx_pQ1234567890abcdefghij/sendMessage"
        );
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["chat_id"], "-1001234567890");
        assert!(body["text"].as_str().unwrap().contains("nginx is not running"));
        assert!(body["text"].as_str().unwrap().starts_with("[ALERT]"));
        assert_eq!(body["disable_web_page_preview"], true);
    }

    #[tokio::test]
    async fn a_broken_channel_does_not_stop_the_working_one() {
        // Spec §11.11: per-channel failures are logged, never fatal.
        let (_reg, ctx) = admin_ctx().await;
        add_channel(&ctx, ChannelKind::Webhook, "good", json!({ "url": "https://a.test/h" })).await;
        // A row whose sealed blob was written under a different master key.
        ctx.db()
            .create_notify_channel(ChannelKind::Webhook, "unreadable", "00ff00ff", true)
            .await
            .unwrap();
        add_channel(&ctx, ChannelKind::Webhook, "also good", json!({ "url": "https://b.test/h" })).await;

        let transport = RecordingTransport::default();
        let payload = NotificationPayload {
            panel: "Ferrum".into(),
            rule: "load".into(),
            message: "busy".into(),
            state: "raised".into(),
            at: "2026-08-26T09:00:00Z".into(),
        };
        assert_eq!(
            notify(&ctx, &transport, &payload).await,
            2,
            "the undecryptable channel must not take the others down with it"
        );
    }

    #[tokio::test]
    async fn a_disabled_channel_is_not_sent_to() {
        let (_reg, ctx) = admin_ctx().await;
        let id = add_channel(&ctx, ChannelKind::Webhook, "ops", json!({ "url": "https://a.test/h" })).await;
        ctx.db()
            .update_notify_channel(id, None, None, Some(false))
            .await
            .unwrap();

        let transport = RecordingTransport::default();
        let payload = NotificationPayload {
            panel: "Ferrum".into(),
            rule: "load".into(),
            message: "busy".into(),
            state: "raised".into(),
            at: "2026-08-26T09:00:00Z".into(),
        };
        assert_eq!(notify(&ctx, &transport, &payload).await, 0);
        assert!(transport.sent().is_empty());
    }

    #[tokio::test]
    async fn a_non_2xx_answer_counts_as_a_failure() {
        let (_reg, ctx) = admin_ctx().await;
        add_channel(&ctx, ChannelKind::Webhook, "ops", json!({ "url": "https://a.test/h" })).await;

        let transport = RecordingTransport {
            status: Some(403),
            ..Default::default()
        };
        let payload = NotificationPayload {
            panel: "Ferrum".into(),
            rule: "load".into(),
            message: "busy".into(),
            state: "raised".into(),
            at: "2026-08-26T09:00:00Z".into(),
        };
        assert_eq!(notify(&ctx, &transport, &payload).await, 0);
    }

    #[tokio::test]
    async fn a_sealed_channel_config_round_trips_and_is_never_stored_in_the_clear() {
        let (_reg, ctx) = admin_ctx().await;
        let token = "123456789:AAHkq-Zx_pQ1234567890abcdefghij";
        let id = add_channel(
            &ctx,
            ChannelKind::Telegram,
            "ops room",
            json!({ "bot_token": token, "chat_id": "-1001234567890" }),
        )
        .await;

        let stored = ctx.db().notify_channel(id).await.unwrap().unwrap();
        assert!(
            !stored.config_sealed.contains("AAHkq"),
            "the token must not be readable in the column"
        );
        assert!(stored.config_sealed.chars().all(|c| c.is_ascii_hexdigit()));

        let opened: TelegramConfig =
            serde_json::from_str(&ctx.master_key().open_str(&stored.config_sealed).unwrap()).unwrap();
        assert_eq!(opened.bot_token, token);
        assert_eq!(opened.chat_id, "-1001234567890");
    }

    // -- evaluate, end to end ---------------------------------------------

    /// Leave exactly one seeded rule live, so the machine running the tests
    /// cannot make them flaky with its own disks.
    async fn only_rule(ctx: &OpContext, keep: AlertKind) {
        for rule in ctx.db().alert_rules().await.unwrap() {
            if rule.kind != keep {
                ctx.db()
                    .set_alert_rule(rule.kind, rule.target.as_deref(), rule.threshold, false)
                    .await
                    .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn a_service_going_down_and_coming_back_sends_exactly_two_messages() {
        use ferrum_distro::svc::SvcAction;

        let (_reg, ctx) = admin_ctx().await;
        only_rule(&ctx, AlertKind::ServiceDown).await;
        add_channel(&ctx, ChannelKind::Webhook, "ops", json!({ "url": "https://a.test/h" })).await;

        let nginx = ManagedUnit::Nginx.unit_name(ctx.distro().info.family);
        let transport = RecordingTransport::default();

        // Running: nothing to say, however often we look.
        ctx.distro().svc.action(&nginx, SvcAction::Start).await.unwrap();
        for _ in 0..5 {
            assert!(evaluate_with(&ctx, &transport).await.unwrap().is_empty());
        }

        // Down: one message, then silence for as long as it stays down.
        ctx.distro().svc.action(&nginx, SvcAction::Stop).await.unwrap();
        let raised = evaluate_with(&ctx, &transport).await.unwrap();
        assert_eq!(raised.len(), 1);
        assert_eq!(raised[0].state, AlertState::Raised);
        assert_eq!(raised[0].rule, "service_down:nginx");
        assert_eq!(raised[0].notified, 1);
        for _ in 0..20 {
            assert!(
                evaluate_with(&ctx, &transport).await.unwrap().is_empty(),
                "an outage that continues is not news"
            );
        }

        // Back up: one more, and then silence again.
        ctx.distro().svc.action(&nginx, SvcAction::Start).await.unwrap();
        let resolved = evaluate_with(&ctx, &transport).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].state, AlertState::Resolved);
        for _ in 0..20 {
            assert!(evaluate_with(&ctx, &transport).await.unwrap().is_empty());
        }

        assert_eq!(
            transport.sent().len(),
            2,
            "forty-seven evaluations, two messages"
        );
        let states: Vec<String> = transport
            .bodies()
            .iter()
            .map(|b| b["state"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(states, vec!["raised", "resolved"]);

        // And the ledger agrees.
        let events = ctx.db().recent_alert_events(10).await.unwrap();
        assert_eq!(events.len(), 1, "one span, not two");
        assert_eq!(events[0].notified, 2, "one raise, one resolve");
        assert!(!events[0].is_open());
    }

    #[tokio::test]
    async fn the_panels_own_expiring_certificate_is_alerted_on() {
        // A regression test with a name that says what it is for. The obvious
        // way to write `collect` is `certificates_for(TenantScope::Global)`,
        // and it is wrong: that query joins through `sites`, so a certificate
        // with `site_id IS NULL` — which is precisely the panel's own — is
        // invisible to it, and the one expiry that locks the operator out of
        // the panel would be the one nobody is told about (spec §11.5).
        let (_reg, ctx) = admin_ctx().await;
        only_rule(&ctx, AlertKind::CertExpiryDays).await;

        let cert = ctx
            .db()
            .create_certificate(
                None, // no site: this is the panel's own certificate
                ferrum_db::CertKind::Le,
                &["panel.example.com".to_string()],
                "/etc/ferrum/certs/panel.example.com",
            )
            .await
            .unwrap();
        let now = ferrum_db::now();
        ctx.db()
            .certificate_issued(cert.id, "Test CA", now, now + time::Duration::days(3))
            .await
            .unwrap();

        let transport = RecordingTransport::default();
        let raised = evaluate_with(&ctx, &transport).await.unwrap();
        assert_eq!(raised.len(), 1);
        assert_eq!(raised[0].subject, "panel.example.com");
        assert!(raised[0].message.contains("expires in"));

        // Renewal moves it out to ninety days.
        ctx.db()
            .certificate_issued(cert.id, "Test CA", now, now + time::Duration::days(89))
            .await
            .unwrap();
        let resolved = evaluate_with(&ctx, &transport).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].state, AlertState::Resolved);
    }

    #[tokio::test]
    async fn evaluation_records_the_event_even_when_every_channel_fails() {
        let (_reg, ctx) = admin_ctx().await;
        only_rule(&ctx, AlertKind::ServiceDown).await;
        add_channel(&ctx, ChannelKind::Webhook, "ops", json!({ "url": "https://a.test/h" })).await;

        let nginx = ManagedUnit::Nginx.unit_name(ctx.distro().info.family);
        ctx.distro()
            .svc
            .action(&nginx, ferrum_distro::svc::SvcAction::Start)
            .await
            .unwrap();
        ctx.distro()
            .svc
            .action(&nginx, ferrum_distro::svc::SvcAction::Stop)
            .await
            .unwrap();

        let transport = RecordingTransport {
            fail_with: Some("connection refused".into()),
            ..Default::default()
        };
        let raised = evaluate_with(&ctx, &transport).await.unwrap();
        assert_eq!(raised.len(), 1, "a dead webhook must not lose the alert");
        assert_eq!(raised[0].notified, 0);

        let events = ctx.db().open_alert_events().await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].notified, 0, "nothing was delivered, and we say so");

        // Crucially: the failure must not make it re-raise every minute.
        assert!(evaluate_with(&ctx, &transport).await.unwrap().is_empty());
    }

    // -- operations --------------------------------------------------------

    #[tokio::test]
    async fn rules_and_channels_are_admin_only() {
        let (reg, _admin, customer) = registry().await;
        let auth = auth_for(customer, Role::Customer);
        for (op, input) in [
            ("alert.rules.list", json!({})),
            ("alert.rules.set", json!({ "kind": "disk_pct", "threshold": 80 })),
            ("alert.channels.list", json!({})),
            ("alert.channels.set", json!({ "kind": "webhook", "label": "x", "config": { "url": "https://a.test" } })),
            ("alert.channels.delete", json!({ "id": 1 })),
            ("alert.channels.test", json!({ "id": 1 })),
            ("alert.events.list", json!({})),
        ] {
            let err = reg.dispatch(op, &auth, input, None).await.unwrap_err();
            assert_eq!(
                err.code,
                ferrum_core::ErrorCode::PermissionDenied,
                "`{op}` must not be reachable by a customer"
            );
        }
    }

    #[tokio::test]
    async fn the_rules_operation_round_trips_through_dispatch() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);

        let out = reg
            .dispatch(
                "alert.rules.set",
                &auth,
                json!({ "kind": "disk_pct", "threshold": 80, "enabled": true }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["rule"]["threshold"], 80.0);
        assert_eq!(out["rule"]["kind"], "disk_pct");

        let listed = reg
            .dispatch("alert.rules.list", &auth, json!({}), None)
            .await
            .unwrap();
        let rules = listed["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 3, "updated in place, not appended");
        assert!(listed["kinds"].as_array().unwrap().contains(&json!("load")));
    }

    #[tokio::test]
    async fn an_unknown_rule_kind_never_reaches_the_database() {
        let (reg, admin, _) = registry().await;
        let err = reg
            .dispatch(
                "alert.rules.set",
                &auth_for(admin, Role::Admin),
                json!({ "kind": "rm_rf_slash", "threshold": 1 }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn a_channel_can_be_added_renamed_and_deleted_without_re_entering_the_secret() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);

        let created = reg
            .dispatch(
                "alert.channels.set",
                &auth,
                json!({
                    "kind": "telegram",
                    "label": "ops room",
                    "config": {
                        "bot_token": "123456789:AAHkq-Zx_pQ1234567890abcdefghij",
                        "chat_id": "-1001234567890",
                    },
                }),
                None,
            )
            .await
            .unwrap();
        let id = created["channel"]["id"].as_i64().unwrap();
        assert!(
            !created.to_string().contains("AAHkq"),
            "the API response must never echo the credential back"
        );

        let renamed = reg
            .dispatch(
                "alert.channels.set",
                &auth,
                json!({ "id": id, "label": "night shift", "enabled": false }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(renamed["channel"]["label"], "night shift");
        assert_eq!(renamed["channel"]["enabled"], false);

        // The token survived the rename.
        let db = reg.services().db.clone();
        let stored = db.notify_channel(id).await.unwrap().unwrap();
        let opened: TelegramConfig = serde_json::from_str(
            &reg.services().master_key.open_str(&stored.config_sealed).unwrap(),
        )
        .unwrap();
        assert_eq!(opened.chat_id, "-1001234567890");

        let listed = reg
            .dispatch("alert.channels.list", &auth, json!({}), None)
            .await
            .unwrap();
        assert!(!listed.to_string().contains("config_sealed"));

        reg.dispatch("alert.channels.delete", &auth, json!({ "id": id }), None)
            .await
            .unwrap();
        let gone = reg
            .dispatch("alert.channels.delete", &auth, json!({ "id": id }), None)
            .await
            .unwrap_err();
        assert_eq!(gone.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn a_channels_kind_cannot_be_changed_under_its_stored_config() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);
        let created = reg
            .dispatch(
                "alert.channels.set",
                &auth,
                json!({
                    "kind": "telegram",
                    "label": "ops",
                    "config": { "bot_token": "123456789:AAHkq-Zx_pQ1234567890abcdefghij", "chat_id": "1" },
                }),
                None,
            )
            .await
            .unwrap();
        let id = created["channel"]["id"].as_i64().unwrap();

        let err = reg
            .dispatch(
                "alert.channels.set",
                &auth,
                json!({ "id": id, "kind": "webhook" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn a_hostile_channel_config_is_refused_before_it_is_sealed() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);
        for config in [
            json!({ "kind": "webhook", "label": "a", "config": { "url": "file:///etc/shadow" } }),
            json!({ "kind": "webhook", "label": "b", "config": {} }),
            json!({ "kind": "telegram", "label": "c", "config": { "bot_token": "1:../../x", "chat_id": "1" } }),
            json!({ "kind": "telegram", "label": "d", "config": { "chat_id": "1" } }),
        ] {
            let err = reg
                .dispatch("alert.channels.set", &auth, config.clone(), None)
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{config} should be refused");
        }
        assert!(
            reg.services().db.notify_channels().await.unwrap().is_empty(),
            "nothing invalid should have been stored"
        );
    }

    #[tokio::test]
    async fn testing_a_channel_reports_the_endpoints_answer_rather_than_failing() {
        let (_reg, ctx) = admin_ctx().await;
        let id = add_channel(&ctx, ChannelKind::Webhook, "ops", json!({ "url": "https://a.test/h" })).await;

        let ok = ChannelsTest::with_transport(Arc::new(RecordingTransport::default()))
            .run(&ctx, ChannelsTestInput { id })
            .await
            .unwrap();
        assert!(ok.delivered);
        assert!(ok.detail.is_none());

        let refused = ChannelsTest::with_transport(Arc::new(RecordingTransport {
            status: Some(403),
            ..Default::default()
        }))
        .run(&ctx, ChannelsTestInput { id })
        .await
        .unwrap();
        assert!(!refused.delivered);
        assert!(refused.detail.unwrap().contains("403"));
    }

    #[tokio::test]
    async fn testing_a_channel_that_does_not_exist_is_not_found() {
        let (_reg, ctx) = admin_ctx().await;
        let err = ChannelsTest::with_transport(Arc::new(RecordingTransport::default()))
            .run(&ctx, ChannelsTestInput { id: 4242 })
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn the_events_operation_shows_history_and_the_open_set() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);
        let db = reg.services().db.clone();
        let rule = db.alert_rules().await.unwrap()[0].clone();

        let a = db.raise_alert(rule.id, "/", "full", Some(99.0)).await.unwrap().unwrap();
        db.resolve_alert(a.id).await.unwrap();
        db.raise_alert(rule.id, "/var", "full", Some(99.0)).await.unwrap();

        let all = reg
            .dispatch("alert.events.list", &auth, json!({}), None)
            .await
            .unwrap();
        assert_eq!(all["events"].as_array().unwrap().len(), 2);

        let open = reg
            .dispatch("alert.events.list", &auth, json!({ "open_only": true }), None)
            .await
            .unwrap();
        let open = open["events"].as_array().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0]["subject"], "/var");
    }
}
