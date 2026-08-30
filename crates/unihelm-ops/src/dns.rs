//! DNS: the pointing advisory, Cloudflare credentials, and DNS-01 wildcards
//! (spec §11.13, §11.5).
//!
//! # Cloudflare API Tokens only. Never the Global API Key.
//!
//! Cloudflare offers two credentials and they are not two spellings of the same
//! thing:
//!
//! - a **Global API Key** authenticates *the account*. It carries every
//!   permission the human has, on every zone, plus billing, plus membership. It
//!   cannot be scoped, and it is the same secret the owner uses to log in to the
//!   API for everything else, so revoking it because a hosting panel was
//!   breached means revoking it everywhere at once.
//! - an **API Token** carries an explicit permission list against an explicit
//!   resource list. The token this panel wants is `Zone:Read` +
//!   `Zone:DNS:Edit`, scoped to the single zone whose wildcard is being issued.
//!
//! This module accepts only the second, and the difference is the entire
//! security story of storing somebody's DNS credential on a shared hosting box.
//! A panel holding a Global Key has taken custody of the customer's whole
//! Cloudflare account on the strength of its own disk encryption; a panel
//! holding a scoped token can, at absolute worst, edit DNS in one zone — which
//! is exactly the authority it was given the credential to exercise. There is no
//! code path here that sends `X-Auth-Key`/`X-Auth-Email`, and there should never
//! be one: the API would happily accept it, which is why the refusal has to live
//! in this file rather than in a policy document.
//!
//! Because a scoped token cannot see zones it was not scoped to, an operator
//! hosting several customers' domains needs several tokens. That is why
//! `dns_providers` is unique on `(kind, label)` rather than on `kind`, and why
//! wildcard issuance walks every stored credential looking for one whose zone
//! list covers the name (see [`ProviderSet`] and [`IssueWildcard`]).
//!
//! # The TXT record is always cleaned up
//!
//! A DNS-01 challenge publishes `_acme-challenge.<domain> TXT <digest>` in a
//! zone the panel does not own. Leaving one behind is not cosmetic: the records
//! accumulate one per attempt, they are visible to anyone who queries the zone,
//! and a stale set of them is what makes the *next* order fail in a way nobody
//! can explain. Every publish therefore goes through
//! [`with_challenge_records`], which deletes what it created on the success
//! path, the failure path, and the path where creating the second record failed
//! after the first one succeeded.
//!
//! # nginx is reloaded explicitly after issuance
//!
//! Copied deliberately from `cert.rs`, and for the reason recorded there: nginx
//! holds certificates in memory from the moment it loads them, and a renewal
//! does not change the vhost text, so the config engine correctly reports
//! "nothing to do" and skips the reload. On a live server that combination
//! served a stale certificate while reporting success.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_config::paths;
use unihelm_core::{Domain, ErrorCode, Permission, Result, SiteId, UnihelmError};
use unihelm_db::{CertKind, DnsProviderKind};

use crate::acme::{self, Directory};
use crate::registry::{Execution, OpContext, TypedOperation};

// ---------------------------------------------------------------------------
// the token, as a value that cannot be printed by accident
// ---------------------------------------------------------------------------

/// A Cloudflare API token.
///
/// A newtype rather than a `String` for one reason: `#[derive(Debug)]` on an
/// operation's input struct is the normal thing to write, and `tracing` will
/// happily render it. The manual `Debug` below is what makes that harmless. The
/// value is readable only through [`SecretToken::expose`], which is grep-able —
/// a reviewer can find every place the token is actually used.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SecretToken(String);

impl SecretToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// The token itself. Only two callers: the HTTP transport that authenticates
    /// with it, and the sealing step that puts it in the database.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretToken(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// the Cloudflare transport seam
// ---------------------------------------------------------------------------

/// The HTTP verbs this client needs. An enum rather than a string so a typo
/// cannot become a request nobody meant to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfMethod {
    Get,
    Post,
    Delete,
}

impl CfMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            CfMethod::Get => "GET",
            CfMethod::Post => "POST",
            CfMethod::Delete => "DELETE",
        }
    }
}

/// One call to the Cloudflare v4 API, described rather than performed.
#[derive(Debug, Clone)]
pub struct CfRequest {
    pub method: CfMethod,
    /// Path under `/client/v4`, e.g. `/zones` or `/zones/abc/dns_records/def`.
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<serde_json::Value>,
}

/// What came back. The status is kept alongside the body because Cloudflare
/// signals authentication failures in the status *and* in `success: false`, and
/// the two want different error codes.
#[derive(Debug, Clone)]
pub struct CfResponse {
    pub status: u16,
    pub body: serde_json::Value,
}

/// The seam every Cloudflare call goes through.
///
/// It exists so the client's logic — envelope handling, pagination, the
/// longest-suffix zone match, the create/delete pairing — is testable without a
/// Cloudflare account, and so that the token lives in exactly one implementation
/// of one trait rather than being threaded through every method.
#[async_trait]
pub trait CfTransport: Send + Sync {
    async fn send(&self, request: CfRequest) -> Result<CfResponse>;
}

/// The real transport: reqwest over rustls, bearer-token authenticated.
pub struct HttpTransport {
    client: reqwest::Client,
    base_url: String,
}

/// Cloudflare's API root. A constant rather than a setting: a configurable API
/// endpoint for a credential this sensitive is a redirection primitive.
pub const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";

impl HttpTransport {
    /// Build a transport that authenticates with `token`.
    ///
    /// The `Authorization` header is marked sensitive so reqwest redacts it in
    /// its own `Debug` output, and it is baked into the client's default headers
    /// so no call site can forget it or, worse, log the request it built.
    pub fn new(token: &SecretToken) -> Result<Self> {
        use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

        let mut value =
            HeaderValue::from_str(&format!("Bearer {}", token.expose())).map_err(|_| {
                // The token is not echoed: an attacker who can make this fail
                // must not also get their input reflected into a log line.
                UnihelmError::new(
                    ErrorCode::InvalidInput,
                    "the API token contains characters an HTTP header cannot carry",
                )
                .with_field("token")
            })?;
        value.set_sensitive(true);

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value);

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .user_agent(concat!("unihelm-panel/", env!("CARGO_PKG_VERSION")))
            // A DNS API that hangs must not hang an operation that holds a
            // published TXT record it still has to clean up.
            .timeout(Duration::from_secs(20))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| UnihelmError::internal(format!("could not build an HTTPS client: {e}")))?;

        Ok(Self {
            client,
            base_url: CLOUDFLARE_API_BASE.to_string(),
        })
    }
}

#[async_trait]
impl CfTransport for HttpTransport {
    async fn send(&self, request: CfRequest) -> Result<CfResponse> {
        let url = format!("{}{}", self.base_url, request.path);
        let mut builder = match request.method {
            CfMethod::Get => self.client.get(&url),
            CfMethod::Post => self.client.post(&url),
            CfMethod::Delete => self.client.delete(&url),
        };
        if !request.query.is_empty() {
            builder = builder.query(&request.query);
        }
        if let Some(body) = &request.body {
            builder = builder.json(body);
        }

        let response = builder.send().await.map_err(|e| {
            // `e` is a reqwest error over a client whose auth header is marked
            // sensitive, so it cannot carry the token.
            UnihelmError::new(
                ErrorCode::ServiceUnavailable,
                format!("could not reach the Cloudflare API: {e}"),
            )
        })?;

        let status = response.status().as_u16();
        let text = response.text().await.map_err(|e| {
            UnihelmError::new(
                ErrorCode::ServiceUnavailable,
                format!("the Cloudflare API response could not be read: {e}"),
            )
        })?;

        // An HTML error page from an intermediary is not JSON; say so rather
        // than reporting a serde message about line 1 column 1.
        let body = if text.trim().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&text).map_err(|_| {
                UnihelmError::new(
                    ErrorCode::CommandFailed,
                    format!("the Cloudflare API answered HTTP {status} with a non-JSON body"),
                )
            })?
        };

        Ok(CfResponse { status, body })
    }
}

// ---------------------------------------------------------------------------
// the Cloudflare client
// ---------------------------------------------------------------------------

/// A DNS zone as Cloudflare reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Zone {
    pub id: String,
    /// The zone apex, e.g. `example.co.uk`.
    pub name: String,
}

/// Cloudflare's v4 API, in the four calls this panel makes.
pub struct Cloudflare {
    transport: Arc<dyn CfTransport>,
}

/// Deliberately opaque, and hand-written rather than derived.
///
/// A client reaches callers inside a `Result` tuple, and `Result::unwrap_err`
/// (plus every `assert!`, `expect` and `tracing` field) formats the `Ok` side
/// with `Debug`. A derive would walk into the transport, which holds the bearer
/// token — so the one line that would have made a token appear in a panic
/// message is the line that is not written here (spec §12 rule 6).
impl std::fmt::Debug for Cloudflare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cloudflare { .. }")
    }
}

impl Cloudflare {
    pub fn new(transport: Arc<dyn CfTransport>) -> Self {
        Self { transport }
    }

    /// Build a client that talks to the real API with `token`.
    pub fn with_token(token: &SecretToken) -> Result<Self> {
        Ok(Self::new(Arc::new(HttpTransport::new(token)?)))
    }

    /// Send a request and unwrap Cloudflare's envelope.
    ///
    /// Every v4 response is `{success, errors, messages, result}`, and
    /// `success: false` arrives with HTTP 200 often enough that checking only
    /// the status would let failures through as empty results.
    async fn call(&self, request: CfRequest) -> Result<serde_json::Value> {
        let what = format!("{} {}", request.method.as_str(), request.path);
        let response = self.transport.send(request).await?;

        let success = response.body.get("success").and_then(|v| v.as_bool());
        if response.status < 400 && success == Some(true) {
            return Ok(response
                .body
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null));
        }

        let detail = cloudflare_errors(&response.body);
        Err(UnihelmError::new(
            cloudflare_error_code(response.status),
            format!(
                "Cloudflare refused `{what}` (HTTP {}){}",
                response.status,
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            ),
        ))
    }

    /// `GET /user/tokens/verify` — is this token live, and is it a token at all?
    ///
    /// Returns the reported status (`active`). This is the first call
    /// `dns.provider.set` makes, because it is the one call that distinguishes
    /// "wrong credential" from "right credential, wrong scope": a Global API Key
    /// sent as a bearer token fails *here*, with an authentication error, rather
    /// than later with a confusing per-zone permission error.
    pub async fn verify_token(&self) -> Result<String> {
        let result = self
            .call(CfRequest {
                method: CfMethod::Get,
                path: "/user/tokens/verify".into(),
                query: Vec::new(),
                body: None,
            })
            .await?;

        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        if status != "active" {
            return Err(UnihelmError::new(
                ErrorCode::PermissionDenied,
                format!(
                    "the token verified but its status is `{status}` — Cloudflare will \
                     reject DNS edits made with it"
                ),
            ));
        }
        Ok(status)
    }

    /// Every zone the token can see.
    ///
    /// A scoped token sees exactly the zones it was scoped to, which is the
    /// point: this list *is* the credential's blast radius, and the panel shows
    /// it back to the operator so they can check that it is as small as they
    /// intended.
    pub async fn zones(&self) -> Result<Vec<Zone>> {
        // Cloudflare paginates at 50 by default and caps `per_page` at 50 for
        // this endpoint. The page cap bounds an operation that would otherwise
        // follow an unbounded `total_pages` from a remote server.
        const PER_PAGE: usize = 50;
        const MAX_PAGES: usize = 20;

        let mut out = Vec::new();
        for page in 1..=MAX_PAGES {
            let result = self
                .call(CfRequest {
                    method: CfMethod::Get,
                    path: "/zones".into(),
                    query: vec![
                        ("per_page".into(), PER_PAGE.to_string()),
                        ("page".into(), page.to_string()),
                    ],
                    body: None,
                })
                .await?;

            let Some(items) = result.as_array() else {
                return Err(UnihelmError::new(
                    ErrorCode::CommandFailed,
                    "Cloudflare returned a zone list that is not a list",
                ));
            };
            let batch = items.len();
            for item in items {
                let (Some(id), Some(name)) = (
                    item.get("id").and_then(|v| v.as_str()),
                    item.get("name").and_then(|v| v.as_str()),
                ) else {
                    // One malformed entry must not silently shrink the zone
                    // list — a missing zone becomes "no provider covers this
                    // domain", which reads like a scoping mistake.
                    return Err(UnihelmError::new(
                        ErrorCode::CommandFailed,
                        "Cloudflare returned a zone with no id or name",
                    ));
                };
                out.push(Zone {
                    id: id.to_string(),
                    name: name.trim_end_matches('.').to_ascii_lowercase(),
                });
            }

            if batch < PER_PAGE {
                break;
            }
        }
        Ok(out)
    }

    /// Create one TXT record and return its id.
    pub async fn create_txt(&self, zone_id: &str, name: &str, content: &str) -> Result<String> {
        // 60 s is Cloudflare's floor for an explicit TTL. It matters: the
        // record is deleted minutes later, and a long TTL would leave resolvers
        // caching a challenge value that no longer exists, which is what makes
        // the *next* order fail.
        let result = self
            .call(CfRequest {
                method: CfMethod::Post,
                path: format!("/zones/{zone_id}/dns_records"),
                query: Vec::new(),
                body: Some(serde_json::json!({
                    "type": "TXT",
                    "name": name,
                    "content": content,
                    "ttl": 60,
                    "comment": "unihelm ACME DNS-01 challenge (temporary)",
                })),
            })
            .await?;

        result
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| {
                UnihelmError::new(
                    ErrorCode::CommandFailed,
                    "Cloudflare accepted the TXT record but returned no id, so it \
                     cannot be cleaned up",
                )
            })
    }

    /// Remove a record.
    pub async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<()> {
        self.call(CfRequest {
            method: CfMethod::Delete,
            path: format!("/zones/{zone_id}/dns_records/{record_id}"),
            query: Vec::new(),
            body: None,
        })
        .await?;
        Ok(())
    }
}

/// Join Cloudflare's `errors` array into one sentence.
fn cloudflare_errors(body: &serde_json::Value) -> String {
    let Some(errors) = body.get("errors").and_then(|v| v.as_array()) else {
        return String::new();
    };
    errors
        .iter()
        .filter_map(|e| {
            let message = e.get("message").and_then(|v| v.as_str())?;
            match e.get("code").and_then(serde_json::Value::as_i64) {
                Some(code) => Some(format!("{message} (code {code})")),
                None => Some(message.to_string()),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Map an HTTP status onto the panel's error vocabulary.
///
/// 403 is `permission_denied` rather than a generic failure because it is the
/// status a correctly-configured-but-under-scoped token produces, and that is a
/// fix the operator can make in thirty seconds if the panel says so.
fn cloudflare_error_code(status: u16) -> ErrorCode {
    match status {
        401 | 403 => ErrorCode::PermissionDenied,
        404 => ErrorCode::NotFound,
        429 => ErrorCode::RateLimited,
        500..=599 => ErrorCode::ServiceUnavailable,
        _ => ErrorCode::CommandFailed,
    }
}

// ---------------------------------------------------------------------------
// pure helpers
// ---------------------------------------------------------------------------

/// The zone that owns `name`, by longest suffix.
///
/// Longest, not first. A token scoped to both `example.co.uk` and (say) a
/// parked `co.uk` would match either by a naive suffix test, and picking the
/// shorter one means writing the challenge record into the wrong zone — where
/// it is invisible to the CA and the order times out with nothing to look at.
/// The public-suffix list is deliberately *not* consulted: it is a moving target
/// and it is not needed here, because a zone only appears in this list if
/// Cloudflare says the token administers it.
///
/// Matching is on label boundaries. `evil-example.com` must not match a zone
/// named `example.com`, which a bare `ends_with` would happily do.
pub fn longest_suffix_zone<'a>(zones: &'a [Zone], name: &str) -> Option<&'a Zone> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let name = name.strip_prefix("*.").unwrap_or(&name);

    zones
        .iter()
        .filter(|zone| {
            let zone_name = zone.name.trim_end_matches('.');
            if zone_name.is_empty() {
                return false;
            }
            name == zone_name
                || name
                    .strip_suffix(zone_name)
                    // The character before the zone name must be the label
                    // separator, or this is a different domain that merely ends
                    // in the same letters.
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
        .max_by_key(|zone| zone.name.len())
}

/// The name a DNS-01 challenge for `base` is published at.
pub fn challenge_name(base: &str) -> String {
    format!("_acme-challenge.{}", base.trim_end_matches('.'))
}

/// How long to wait before propagation attempt `attempt` (0-based).
///
/// Exponential, capped, and jittered. Each piece earns its place:
///
/// - *exponential* because a record usually appears within seconds and
///   occasionally takes minutes, so a fixed interval is either wasteful or
///   too impatient;
/// - *capped* at 20 s so the tail of the wait stays responsive rather than
///   sleeping for a minute past the moment the record went live;
/// - *jittered* because every panel on every server renews on the same
///   thirty-days-remaining schedule, and a fleet polling one provider in
///   lockstep is how a rate limit gets hit by accident.
///
/// `jitter` is supplied by the caller (a random value in `[0, 1)`) rather than
/// drawn here, which is what makes this function pure and therefore testable:
/// the bounds below are asserted, not hoped for.
pub fn propagation_delay(attempt: u32, jitter: f64) -> Duration {
    const BASE_MS: f64 = 2_000.0;
    const FACTOR: f64 = 1.7;
    const CAP_MS: f64 = 20_000.0;
    /// ±25 %: enough to spread a fleet, not so much that one poller waits twice
    /// as long as another for no reason.
    const SPREAD: f64 = 0.25;

    let jitter = jitter.clamp(0.0, 1.0);
    let base = (BASE_MS * FACTOR.powi(attempt.min(16) as i32)).min(CAP_MS);
    let scale = 1.0 + SPREAD * (2.0 * jitter - 1.0);
    Duration::from_millis((base * scale) as u64)
}

/// How many times propagation is polled before the order is abandoned.
///
/// With [`propagation_delay`] this is a little over three minutes of waiting,
/// which is past the point where a zone that was going to update has updated.
/// Bounded on purpose: an unbounded wait holds a published TXT record and an
/// open ACME order for as long as the provider is broken.
pub const PROPAGATION_ATTEMPTS: u32 = 14;

/// Total time the propagation wait can consume, worst case.
pub fn propagation_budget() -> Duration {
    (0..PROPAGATION_ATTEMPTS)
        .map(|attempt| propagation_delay(attempt, 1.0))
        .sum()
}

/// Cloudflare's published anycast ranges, as of this build.
///
/// Used only for the *hint* in `dns.check`: when a domain's A record points at
/// one of these, `matches_server` is false and that is correct rather than
/// broken — the traffic reaches the origin through Cloudflare's proxy. Saying so
/// is the difference between a useful advisory and one that tells every
/// Cloudflare-proxied customer their DNS is wrong.
///
/// A stale list degrades to "no hint", never to a wrong answer, which is why it
/// is acceptable to hard-code it rather than fetch `/ips` at runtime — a network
/// call in an advisory path that must answer in seconds.
const CLOUDFLARE_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(173, 245, 48, 0), 20),
    (Ipv4Addr::new(103, 21, 244, 0), 22),
    (Ipv4Addr::new(103, 22, 200, 0), 22),
    (Ipv4Addr::new(103, 31, 4, 0), 22),
    (Ipv4Addr::new(141, 101, 64, 0), 18),
    (Ipv4Addr::new(108, 162, 192, 0), 18),
    (Ipv4Addr::new(190, 93, 240, 0), 20),
    (Ipv4Addr::new(188, 114, 96, 0), 20),
    (Ipv4Addr::new(197, 234, 240, 0), 22),
    (Ipv4Addr::new(198, 41, 128, 0), 17),
    (Ipv4Addr::new(162, 158, 0, 0), 15),
    (Ipv4Addr::new(104, 16, 0, 0), 13),
    (Ipv4Addr::new(104, 24, 0, 0), 14),
    (Ipv4Addr::new(172, 64, 0, 0), 13),
    (Ipv4Addr::new(131, 0, 72, 0), 22),
];

const CLOUDFLARE_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0x2400, 0xcb00, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2803, 0xf800, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0xb500, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0x8100, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2a06, 0x98c0, 0, 0, 0, 0, 0, 0), 29),
    (Ipv6Addr::new(0x2c0f, 0xf248, 0, 0, 0, 0, 0, 0), 32),
];

/// Does `address` fall inside `network/prefix`?
fn in_prefix(address: &[u8], network: &[u8], prefix: u8) -> bool {
    debug_assert_eq!(address.len(), network.len());
    let whole = usize::from(prefix / 8);
    let bits = prefix % 8;
    if address[..whole] != network[..whole] {
        return false;
    }
    if bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - bits);
    address.get(whole).copied().unwrap_or(0) & mask
        == network.get(whole).copied().unwrap_or(0) & mask
}

/// Is this address one Cloudflare answers on?
pub fn is_cloudflare_proxy_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => CLOUDFLARE_V4
            .iter()
            .any(|(net, bits)| in_prefix(&v4.octets(), &net.octets(), *bits)),
        IpAddr::V6(v6) => CLOUDFLARE_V6
            .iter()
            .any(|(net, bits)| in_prefix(&v6.octets(), &net.octets(), *bits)),
    }
}

/// Could a public client reach this address?
///
/// Loopback, link-local, private and carrier-grade-NAT space are all addresses a
/// server can legitimately be bound to and that no customer's DNS should ever
/// point at, so they are filtered out of "this server's addresses" before the
/// comparison is made. Otherwise a domain pointed at `10.0.0.5` — which happens
/// on a mis-copied record — would be reported as correctly pointed at a server
/// that also has `10.0.0.5` on an internal interface.
pub fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // 100.64.0.0/10, carrier-grade NAT: routable, but not to you.
                || (a == 100 && (64..128).contains(&b))
                // 0.0.0.0/8 and 240.0.0.0/4.
                || a == 0
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10 link-local and fc00::/7 unique-local.
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00)
        }
    }
}

// ---------------------------------------------------------------------------
// this server's public addresses
// ---------------------------------------------------------------------------

/// Where `dns.check` compares a domain against.
///
/// Three sources, in order, and the order is the whole design:
///
/// 1. **The `dns.server_addresses` setting.** Explicit beats inferred. A server
///    behind a NAT, a floating IP or a load balancer answers on an address that
///    appears on no local interface, and no amount of probing will find it — an
///    operator has to say. This is the documented fix when the advisory is
///    wrong.
/// 2. **The addresses actually bound to local interfaces**, via
///    `fwops::local_addresses` (`getifaddrs(3)` — already in the codebase for
///    Sentinel's self-ban guard, so the panel has exactly one answer to "what
///    are my addresses"), filtered to the globally routable ones. Correct on the
///    single-homed public VPS that is the common case.
/// 3. **A best-effort default-route probe.** A UDP socket `connect()`ed to a
///    documentation address sends no packets; it only asks the kernel which
///    source address it *would* use. That is the right answer behind a
///    one-to-one NAT's inside address and still the wrong one behind
///    many-to-one NAT — hence its position last, and hence the setting.
async fn server_public_addresses(ctx: &OpContext) -> Vec<IpAddr> {
    let configured: Vec<String> = ctx
        .db()
        .get_setting_or(unihelm_db::settings::keys::DNS_SERVER_ADDRESSES, Vec::new())
        .await;
    if !configured.is_empty() {
        let mut out = Vec::new();
        for entry in &configured {
            match entry.parse::<IpAddr>() {
                Ok(ip) => out.push(ip),
                // A typo in one entry must not discard the others, and it must
                // not be silent either.
                Err(_) => tracing::warn!(
                    entry = %entry,
                    "dns.server_addresses contains something that is not an IP address"
                ),
            }
        }
        if !out.is_empty() {
            return out;
        }
    }

    let local: Vec<IpAddr> = crate::fwops::local_addresses()
        .into_iter()
        .filter(|ip| is_globally_routable(*ip))
        .collect();
    if !local.is_empty() {
        return local;
    }

    default_route_addresses()
}

/// The source addresses the kernel would use to reach the public internet.
fn default_route_addresses() -> Vec<IpAddr> {
    use std::net::UdpSocket;

    // TEST-NET-1 and the documentation prefix (RFC 5737 / RFC 3849). `connect`
    // on a UDP socket transmits nothing — it installs a destination so
    // `local_addr` can report the route the kernel picked — so these addresses
    // are never actually contacted.
    let probes: [(&str, &str); 2] = [("0.0.0.0:0", "192.0.2.1:9"), ("[::]:0", "[2001:db8::1]:9")];

    probes
        .into_iter()
        .filter_map(|(bind, target)| {
            let socket = UdpSocket::bind(bind).ok()?;
            socket.connect(target).ok()?;
            let ip = socket.local_addr().ok()?.ip();
            is_globally_routable(ip).then_some(ip)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// resolution
// ---------------------------------------------------------------------------

/// Build a resolver over the host's own configuration.
///
/// Falls back to a public recursor when `/etc/resolv.conf` cannot be read. That
/// is not a privacy decision made lightly: `dns.check` asks "what does the
/// internet see when it looks up this name", the answer must not depend on the
/// panel's own resolver being healthy, and a server whose `resolv.conf` is
/// unreadable would otherwise report every domain as broken.
fn system_resolver() -> Result<hickory_resolver::TokioResolver> {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::{GOOGLE, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;

    let builder = match TokioResolver::builder_tokio() {
        Ok(builder) => builder,
        Err(e) => {
            tracing::warn!(error = %e, "no usable system resolver configuration; using a public recursor for the DNS advisory");
            TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&GOOGLE),
                TokioRuntimeProvider::default(),
            )
        }
    };
    builder.build().map_err(|e| {
        UnihelmError::new(
            ErrorCode::ServiceUnavailable,
            format!("could not start a DNS resolver: {e}"),
        )
    })
}

/// A resolver that talks only to `servers`, with caching switched off.
///
/// Both halves matter for propagation polling. Talking to the zone's
/// *authoritative* servers skips every recursive cache between here and there,
/// and turning off this resolver's own cache stops it from answering the second
/// poll with the NXDOMAIN it learned on the first — which is the failure that
/// looks exactly like "Cloudflare never created the record".
fn authoritative_resolver(servers: &[IpAddr]) -> Result<hickory_resolver::TokioResolver> {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;

    let name_servers = servers
        .iter()
        .map(|ip| {
            NameServerConfig::new(
                *ip,
                true,
                vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
            )
        })
        .collect();

    let mut builder = TokioResolver::builder_with_config(
        ResolverConfig::from_parts(None, Vec::new(), name_servers),
        TokioRuntimeProvider::default(),
    );
    {
        let options = builder.options_mut();
        options.cache_size = 0;
        options.timeout = Duration::from_secs(5);
        options.attempts = 1;
        // The name is already fully qualified; appending a search domain to it
        // would query something that does not exist.
        options.ndots = 0;
    }

    builder.build().map_err(|e| {
        UnihelmError::new(
            ErrorCode::ServiceUnavailable,
            format!("could not start a resolver against the zone's nameservers: {e}"),
        )
    })
}

/// What one name resolves to.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NameRecords {
    pub name: String,
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    /// Why there is nothing, when there is nothing. `NXDOMAIN` and "the
    /// resolver timed out" are entirely different problems with entirely
    /// different fixes, and an empty list says neither.
    pub error: Option<String>,
}

async fn resolve_name(resolver: &hickory_resolver::TokioResolver, name: &str) -> NameRecords {
    use hickory_resolver::proto::rr::{RData, RecordType};

    let mut record = NameRecords {
        name: name.to_string(),
        a: Vec::new(),
        aaaa: Vec::new(),
        error: None,
    };

    // Two queries rather than `lookup_ip`, so an A that exists and an AAAA that
    // does not are reported as what they are. `lookup_ip` merges them and a
    // dual-stack failure becomes indistinguishable from a v4-only zone.
    match resolver.lookup(name, RecordType::A).await {
        Ok(lookup) => {
            for answer in lookup.answers() {
                if let RData::A(a) = &answer.data {
                    record.a.push(a.0.to_string());
                }
            }
        }
        Err(e) => record.error = Some(e.to_string()),
    }

    match resolver.lookup(name, RecordType::AAAA).await {
        Ok(lookup) => {
            for answer in lookup.answers() {
                if let RData::AAAA(aaaa) = &answer.data {
                    record.aaaa.push(aaaa.0.to_string());
                }
            }
        }
        Err(e) => {
            // Only report the AAAA failure when the A lookup did not already
            // explain the situation; two copies of "no records found" is noise.
            if record.error.is_none() && record.a.is_empty() {
                record.error = Some(e.to_string());
            }
        }
    }

    record
}

/// The addresses of a zone's authoritative nameservers.
async fn authoritative_servers(
    resolver: &hickory_resolver::TokioResolver,
    zone: &str,
) -> Vec<IpAddr> {
    use hickory_resolver::proto::rr::{RData, RecordType};

    let Ok(lookup) = resolver.lookup(zone, RecordType::NS).await else {
        return Vec::new();
    };

    let mut names = Vec::new();
    for answer in lookup.answers() {
        if let RData::NS(ns) = &answer.data {
            names.push(ns.0.to_utf8());
        }
    }

    let mut out = Vec::new();
    for name in names {
        if let Ok(ips) = resolver.lookup_ip(name.as_str()).await {
            out.extend(ips.iter());
        }
    }
    out.sort();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// `dns.check`
// ---------------------------------------------------------------------------

/// `dns.check` — is this domain pointed at this server?
pub struct Check;

#[derive(Debug, Deserialize)]
pub struct CheckInput {
    pub domain: Domain,
}

#[derive(Debug, Serialize)]
pub struct CheckOutput {
    pub domain: String,
    /// The apex and its `www.` form, in that order.
    pub records: Vec<NameRecords>,
    pub server_addresses: Vec<String>,
    /// At least one address of the apex is one of this server's.
    pub matches_server: bool,
    /// The apex resolves into Cloudflare's anycast space, so `matches_server`
    /// being false is expected rather than wrong.
    pub proxied_hint: bool,
    /// One sentence for the UI, so the advisory does not need a decision table
    /// in the front end as well.
    pub advice: String,
}

/// The whole advisory must answer inside one IPC round trip.
///
/// Deliberately above the ~300 ms an immediate operation is supposed to take,
/// and deliberately not a task: this is an inline hint next to a domain field,
/// and an advisory delivered through the task drawer thirty seconds later is one
/// nobody reads. Four lookups against a cold recursor is the real cost; the
/// budget bounds it well inside the 30 s IPC call timeout, and a timeout comes
/// back as an advisory that says the lookup timed out rather than as an error.
const CHECK_BUDGET: Duration = Duration::from_secs(6);

#[async_trait]
impl TypedOperation for Check {
    type Input = CheckInput;
    type Output = CheckOutput;

    const NAME: &'static str = "dns.check";
    // Not `DnsManage`: this reads public DNS and compares it with addresses the
    // caller's own site already answers on. It reveals nothing a `dig` from any
    // shell would not, it holds no credential, and a customer about to point a
    // domain at their site is exactly who needs it (spec §11.13).
    const PERMISSION: Permission = Permission::SiteRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let domain = input.domain;
        let www = domain.with_www()?;
        let server_addresses = server_public_addresses(ctx).await;

        let resolver = system_resolver()?;
        let lookups = async {
            vec![
                resolve_name(&resolver, domain.as_str()).await,
                resolve_name(&resolver, www.as_str()).await,
            ]
        };

        let records = match tokio::time::timeout(CHECK_BUDGET, lookups).await {
            Ok(records) => records,
            Err(_) => vec![
                NameRecords {
                    name: domain.as_str().to_string(),
                    a: Vec::new(),
                    aaaa: Vec::new(),
                    error: Some(format!(
                        "the lookup did not finish within {} seconds",
                        CHECK_BUDGET.as_secs()
                    )),
                },
                NameRecords {
                    name: www.as_str().to_string(),
                    a: Vec::new(),
                    aaaa: Vec::new(),
                    error: Some("not attempted".into()),
                },
            ],
        };

        let apex_addresses: Vec<IpAddr> = records
            .first()
            .map(|r| {
                r.a.iter()
                    .chain(r.aaaa.iter())
                    .filter_map(|s| s.parse::<IpAddr>().ok())
                    .collect()
            })
            .unwrap_or_default();

        let matches_server = apex_addresses
            .iter()
            .any(|ip| server_addresses.contains(ip));
        let proxied_hint = apex_addresses
            .iter()
            .any(|ip| is_cloudflare_proxy_address(*ip));

        let advice = advice_for(
            matches_server,
            proxied_hint,
            apex_addresses.is_empty(),
            server_addresses.is_empty(),
        );

        Ok(CheckOutput {
            domain: domain.as_str().to_string(),
            records,
            server_addresses: server_addresses.iter().map(ToString::to_string).collect(),
            matches_server,
            proxied_hint,
            advice,
        })
    }
}

/// The advisory sentence. A pure function so the wording is testable and so the
/// UI has one source of truth rather than its own copy of this decision table.
pub fn advice_for(
    matches_server: bool,
    proxied_hint: bool,
    no_records: bool,
    no_server_addresses: bool,
) -> String {
    if no_server_addresses {
        return "This server's public address could not be determined, so the comparison \
                was skipped. Set `dns.server_addresses` to this server's public IPs."
            .into();
    }
    if no_records {
        return "The domain does not resolve yet. Create an A (or AAAA) record pointing at \
                this server and allow for the previous record's TTL."
            .into();
    }
    if matches_server {
        return "The domain resolves to this server. HTTP-01 issuance will work.".into();
    }
    if proxied_hint {
        return "The domain resolves into Cloudflare's proxy, not to this server directly. \
                That is expected with the orange cloud on; the origin still has to be this \
                server, and HTTP-01 issuance needs the proxy to pass \
                /.well-known/acme-challenge/ through — DNS-01 avoids the question entirely."
            .into();
    }
    "The domain resolves somewhere else. Point its A/AAAA record at this server, or \
     issue over DNS-01 if it is served through a proxy."
        .into()
}

// ---------------------------------------------------------------------------
// `dns.provider.set`
// ---------------------------------------------------------------------------

/// `dns.provider.set` — store a verified Cloudflare API token.
pub struct ProviderSet;

#[derive(Debug, Deserialize)]
pub struct ProviderSetInput {
    pub kind: DnsProviderKind,
    /// The operator's name for this credential. It is the only handle they get
    /// on a value they can never read back.
    pub label: String,
    pub token: SecretToken,
}

/// What comes back. Note what is absent: there is no field here, and no field
/// anywhere on the path from the agent to the browser, that could carry the
/// token. `a_stored_token_is_never_returned_or_logged` asserts it.
#[derive(Debug, Serialize)]
pub struct ProviderSetOutput {
    pub id: i64,
    pub kind: &'static str,
    pub label: String,
    /// Cloudflare's verdict on the token: `active`.
    pub token_status: String,
    /// Every zone the token can administer — the credential's blast radius,
    /// shown back so the operator can check it is as small as they meant.
    pub zones: Vec<String>,
}

#[async_trait]
impl TypedOperation for ProviderSet {
    type Input = ProviderSetInput;
    type Output = ProviderSetOutput;

    const NAME: &'static str = "dns.provider.set";
    // `ServerManage`, which only an admin holds — not `DnsManage`, which a
    // reseller holds too. This credential is server-wide: every tenant's
    // wildcard issuance runs through whatever token is stored here, so a
    // reseller who could replace it could redirect the panel's DNS writes at a
    // Cloudflare account they control. Storing the credential is an admin act;
    // *using* it (`cert.issue_wildcard`) is not.
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let label = validate_label(&input.label)?;

        // Verify before storing, always. A token that does not work is worse
        // than no token: it turns every future wildcard issuance into a failure
        // discovered minutes into a task, and it spends ACME rate-limit budget
        // to find out. Two calls, because they answer different questions —
        // "is this a live token" and "what can it actually reach".
        let cloudflare = Cloudflare::with_token(&input.token)?;
        let token_status = cloudflare.verify_token().await?;
        let zones = cloudflare.zones().await?;

        if zones.is_empty() {
            return Err(UnihelmError::new(
                ErrorCode::PermissionDenied,
                "the token is valid but can see no zones. It needs Zone:Read and \
                 Zone:DNS:Edit on the zone whose records the panel will manage.",
            )
            .with_field("token"));
        }

        let sealed = ctx
            .master_key()
            .seal_str(input.token.expose())
            .map_err(UnihelmError::from)?;
        let saved = ctx
            .db()
            .save_dns_provider(input.kind, &label, &sealed)
            .await
            .map_err(UnihelmError::from)?;

        // The label and the zone count, never the token. This line is the one a
        // reviewer checks first.
        ctx.log(format!(
            "stored the `{label}` Cloudflare token; it administers {} zone(s)",
            zones.len()
        ));

        Ok(ProviderSetOutput {
            id: saved.id,
            kind: saved.kind.as_str(),
            label,
            token_status,
            zones: zones.into_iter().map(|z| z.name).collect(),
        })
    }
}

/// Labels are shown in the UI and stored; keep them boring.
fn validate_label(label: &str) -> Result<String> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Err(
            UnihelmError::new(ErrorCode::InvalidInput, "the credential needs a label")
                .with_field("label"),
        );
    }
    if trimmed.chars().count() > 64 {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "the label may be at most 64 characters",
        )
        .with_field("label"));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "the label may not contain control characters",
        )
        .with_field("label"));
    }
    Ok(trimmed.to_string())
}

// ---------------------------------------------------------------------------
// `cert.issue_wildcard`
// ---------------------------------------------------------------------------

/// `cert.issue_wildcard` — a DNS-01 certificate covering `example.com` and
/// `*.example.com`.
pub struct IssueWildcard;

#[derive(Debug, Deserialize)]
pub struct IssueWildcardInput {
    pub site_id: i64,
    /// Use the staging directory. Its root is not publicly trusted, so a staging
    /// certificate must never be installed on a live site — but it is the right
    /// way to prove the DNS-01 flow works without spending rate-limit budget.
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub contact_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IssueWildcardOutput {
    pub certificate_id: i64,
    pub domains: Vec<String>,
    pub zone: String,
    pub provider_label: String,
    pub issuer: String,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: time::OffsetDateTime,
    pub days_valid: i64,
}

#[async_trait]
impl TypedOperation for IssueWildcard {
    type Input = IssueWildcardInput;
    type Output = IssueWildcardOutput;

    const NAME: &'static str = "cert.issue_wildcard";
    const PERMISSION: Permission = Permission::SiteManage;
    // Minutes: the CA validates through public DNS, which means waiting for a
    // zone this panel does not own to publish a record.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: false,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db().clone();
        let site_id = SiteId(input.site_id);

        let site = db
            .sites(ctx.scope())
            .by_id(site_id)
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("site"))?;

        let apex = Domain::parse(&site.domain)?;
        let wildcard = format!("*.{}", apex.as_str());
        // Both names in one certificate. A `*.example.com` certificate does not
        // match `example.com` — the wildcard covers exactly one label — so a
        // wildcard-only certificate leaves the apex broken, which is the single
        // most common wildcard mistake.
        let names = vec![apex.as_str().to_string(), wildcard];

        let directory = if input.staging {
            Directory::Staging
        } else {
            Directory::Production
        };
        let contact = input
            .contact_email
            .clone()
            .unwrap_or_else(|| format!("admin@{}", apex.as_str()));

        // Find the credential that administers this name before anything else
        // happens: it is the cheapest failure and the one an operator is most
        // likely to hit.
        let (provider_label, zone, cloudflare) = resolve_provider(ctx, apex.as_str()).await?;
        ctx.log(format!(
            "`{}` is in the `{}` zone, administered by the `{provider_label}` token",
            apex.as_str(),
            zone.name
        ));

        let cert_dir = paths::cert_dir(apex.as_str());
        // The row before the attempt, exactly as `cert.issue` does, so a failure
        // has somewhere to be recorded and the UI can explain why the site still
        // has no wildcard.
        let record = db
            .create_certificate(
                Some(site_id),
                CertKind::Le,
                &names,
                &cert_dir.to_string_lossy(),
            )
            .await
            .map_err(UnihelmError::from)?;

        let account = crate::cert::acme_account(ctx, &contact, directory).await?;
        let log = |line: &str| ctx.log(line);

        let outcome = issue_dns01(&account, &names, &cloudflare, &zone, &log).await;

        let issued = match outcome {
            Ok(issued) => issued,
            Err(e) => {
                let _ = db.certificate_failed(record.id, &e.detail).await;
                return Err(e);
            }
        };

        // Files first, then the row, then the vhost: nginx must never be pointed
        // at a certificate that is not on disk yet.
        acme::write_certificate(&cert_dir, &issued)?;
        ctx.log(format!("certificate written to {}", cert_dir.display()));

        db.certificate_issued(
            record.id,
            &issued.issuer,
            issued.not_before,
            issued.not_after,
        )
        .await
        .map_err(UnihelmError::from)?;

        let subscription = db
            .subscriptions(&unihelm_core::TenantScope::Global)
            .by_id(site.subscription_id)
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::internal("the site's subscription is missing"))?;
        let linux_user = unihelm_core::LinuxUser::parse(&subscription.linux_user)?;
        crate::site::render_vhost(ctx, &site, &linux_user).await?;

        // Not optional, and not a duplicate of the vhost render. nginx holds
        // certificates in memory from the moment it loads them, and on a renewal
        // the vhost text does not change — same paths, same options — so the
        // config engine correctly reports "nothing to do" and skips the reload.
        // Without this line every renewal appears to succeed while the expiring
        // certificate stays live. That happened on a live server (see cert.rs).
        {
            use unihelm_config::apply::Reloader;
            let reloader = crate::services::UnitReloader::nginx(ctx.distro());
            reloader.reload().await.map_err(|e| {
                UnihelmError::new(
                    ErrorCode::ConfigRollback,
                    format!("the certificate is on disk but nginx would not reload: {e}"),
                )
            })?;
            ctx.log("nginx reloaded onto the new wildcard certificate");
        }

        let days_valid = (issued.not_after - unihelm_db::now()).whole_days();
        ctx.log(format!(
            "{} and *.{} are now served over HTTPS",
            apex.as_str(),
            apex.as_str()
        ));

        Ok(IssueWildcardOutput {
            certificate_id: record.id,
            domains: names,
            zone: zone.name,
            provider_label,
            issuer: issued.issuer,
            not_after: issued.not_after,
            days_valid,
        })
    }
}

/// Find the stored credential whose zone list covers `name`.
///
/// Walks every Cloudflare credential in insertion order and takes the first
/// whose zones contain a suffix match. Listing zones per credential is a network
/// call, which is why the walk stops at the first hit rather than gathering
/// every candidate: the common case is one token, and the expensive case is an
/// operator with many zone-scoped ones.
async fn resolve_provider(ctx: &OpContext, name: &str) -> Result<(String, Zone, Cloudflare)> {
    let providers = ctx
        .db()
        .dns_providers(DnsProviderKind::Cloudflare)
        .await
        .map_err(UnihelmError::from)?;

    if providers.is_empty() {
        return Err(UnihelmError::new(
            ErrorCode::NotFound,
            "no Cloudflare credential is stored. Add one with `dns.provider.set` \
             (an API token scoped to Zone:Read + Zone:DNS:Edit, never a Global API Key).",
        ));
    }

    let mut reachable = 0usize;
    for provider in &providers {
        let token = SecretToken::new(
            ctx.master_key()
                .open_str(&provider.credentials_sealed)
                .map_err(|e| {
                    UnihelmError::internal(format!(
                        "the stored `{}` DNS credential could not be decrypted ({e}). \
                     If /etc/unihelm/secret.key was replaced, set the token again.",
                        provider.label
                    ))
                })?,
        );
        let cloudflare = Cloudflare::with_token(&token)?;

        // One broken credential must not hide a working one further down the
        // list; a revoked token is exactly the situation this walk exists for.
        let zones = match cloudflare.zones().await {
            Ok(zones) => {
                reachable += 1;
                zones
            }
            Err(e) => {
                ctx.log(format!(
                    "the `{}` Cloudflare token could not list zones ({}); trying the next credential",
                    provider.label, e.detail
                ));
                continue;
            }
        };

        if let Some(zone) = longest_suffix_zone(&zones, name) {
            return Ok((provider.label.clone(), zone.clone(), cloudflare));
        }
    }

    Err(UnihelmError::new(
        ErrorCode::NotFound,
        if reachable == 0 {
            format!(
                "none of the {} stored Cloudflare credentials could list any zones — \
                 they are probably revoked. Set a working token.",
                providers.len()
            )
        } else {
            format!(
                "no stored Cloudflare credential administers a zone covering `{name}`. \
                 The token must be scoped to that zone."
            )
        },
    ))
}

// ---------------------------------------------------------------------------
// the DNS-01 order
// ---------------------------------------------------------------------------

/// Publish `records`, run `body`, and remove what was published — always.
///
/// This is the whole cleanup guarantee, in one place, so that "did we clean up
/// on that path?" has one answer rather than one per `?`. Three properties, all
/// tested:
///
/// - the records are deleted when `body` succeeds;
/// - they are deleted when `body` fails, and the body's error is the one that
///   propagates (a cleanup failure must not mask the reason the order failed);
/// - a *creation* that fails halfway still removes the records already created,
///   which is the path a naive implementation misses because nothing has
///   "started" yet.
///
/// There is no early `return` between the first create and the cleanup loop, and
/// no `?` either: every fallible step assigns into `outcome` instead. That is
/// what makes the guarantee readable rather than merely true.
async fn with_challenge_records<T, F, Fut>(
    cloudflare: &Cloudflare,
    zone_id: &str,
    records: &[(String, String)],
    log: &(dyn Fn(&str) + Send + Sync),
    body: F,
) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut created: Vec<String> = Vec::new();
    let mut outcome: Result<T> = Err(UnihelmError::internal("the challenge body never ran"));

    let mut publish_error = None;
    for (name, value) in records {
        match cloudflare.create_txt(zone_id, name, value).await {
            Ok(id) => {
                log(&format!("published {name} TXT"));
                created.push(id);
            }
            Err(e) => {
                publish_error = Some(e);
                break;
            }
        }
    }

    if publish_error.is_none() {
        outcome = body().await;
    }

    for id in &created {
        match cloudflare.delete_record(zone_id, id).await {
            Ok(()) => log("removed a challenge record"),
            // Best effort by design: a cleanup failure is reported, never
            // substituted for the outcome. Losing "the CA said the challenge was
            // invalid" because a delete 500'd afterwards would hide the only
            // useful sentence in the whole task log.
            Err(e) => log(&format!(
                "warning: a challenge TXT record could not be removed ({}); \
                 delete `_acme-challenge` records in the zone by hand",
                e.detail
            )),
        }
    }

    match publish_error {
        Some(e) => Err(e),
        None => outcome,
    }
}

/// Run a DNS-01 order for `names` through `cloudflare`.
async fn issue_dns01(
    account: &instant_acme::Account,
    names: &[String],
    cloudflare: &Cloudflare,
    zone: &Zone,
    log: &(dyn Fn(&str) + Send + Sync),
) -> Result<acme::Issued> {
    use instant_acme::{AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus};

    let identifiers: Vec<Identifier> = names.iter().cloned().map(Identifier::Dns).collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(acme::acme_error)?;

    // Pass one: what has to be published?
    //
    // Two passes over the authorizations, not one, and it is forced rather than
    // stylistic. Every record must be live *before* any challenge is marked
    // ready — a CA that validates the first challenge while the second record is
    // still unpublished fails the order — and a `ChallengeHandle` borrows the
    // order for as long as it exists, so the handles cannot be held across the
    // publish. Re-iterating refetches the authorizations, which is cheap and
    // also picks up anything that went valid in the meantime.
    let mut wanted: Vec<(String, String)> = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(acme::acme_error)?;

            match authz.status {
                // The normal renewal path: the CA reuses a valid authorization,
                // so there is nothing to publish for this identifier.
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => {
                    return Err(UnihelmError::new(
                        ErrorCode::CommandFailed,
                        format!("the CA reported an unexpected authorization status: {other:?}"),
                    ));
                }
            }

            // The identifier is the base name with no `*.` on it, for both the
            // apex and the wildcard — which is why both authorizations publish
            // at the same `_acme-challenge.example.com` name, with two different
            // values. Cloudflare holds multiple TXT records at one name; a
            // provider that did not would need a merge here.
            let base = match authz.identifier().identifier {
                Identifier::Dns(dns) => dns.clone(),
                other => {
                    return Err(UnihelmError::new(
                        ErrorCode::NotImplemented,
                        format!("DNS-01 cannot validate the identifier {other:?}"),
                    ));
                }
            };

            let challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| {
                UnihelmError::new(
                    ErrorCode::NotImplemented,
                    "the CA offered no dns-01 challenge for this name",
                )
            })?;
            wanted.push((
                challenge_name(&base),
                challenge.key_authorization().dns_value(),
            ));
        }
    } // the authorization iterator borrows `order`; it must end here.

    if wanted.is_empty() {
        log("every authorization is already valid; finalising without publishing anything");
        return finalize_order(&mut order).await;
    }

    let expected = group_by_name(&wanted);
    with_challenge_records(cloudflare, &zone.id, &wanted, log, || async {
        await_propagation(&zone.name, &expected, log).await?;

        // Pass two: tell the CA to come and look.
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz = result.map_err(acme::acme_error)?;
                if authz.status != AuthorizationStatus::Pending {
                    continue;
                }
                let mut challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| {
                    UnihelmError::new(
                        ErrorCode::NotImplemented,
                        "the CA offered no dns-01 challenge for this name",
                    )
                })?;
                challenge.set_ready().await.map_err(acme::acme_error)?;
            }
        }

        log("waiting for validation");
        let status = order
            .poll_ready(&acme::RETRY)
            .await
            .map_err(acme::acme_error)?;
        if status != OrderStatus::Ready {
            let detail = challenge_errors(&mut order).await;
            return Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                if detail.is_empty() {
                    format!("the CA ended the order as {status:?}")
                } else {
                    detail.join("; ")
                },
            ));
        }

        finalize_order(&mut order).await
    })
    .await
}

/// Generate a key, finalise and collect the chain.
async fn finalize_order(order: &mut instant_acme::Order) -> Result<acme::Issued> {
    let key_pem = order.finalize().await.map_err(acme::acme_error)?;
    let chain_pem = order
        .poll_certificate(&acme::RETRY)
        .await
        .map_err(acme::acme_error)?;
    acme::issued_from(chain_pem, key_pem)
}

/// Per-challenge errors after a failed order — the sentence that says what to
/// fix, which the order's own error almost never carries.
async fn challenge_errors(order: &mut instant_acme::Order) -> Vec<String> {
    let mut out = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(Ok(authz)) = authorizations.next().await {
        let identifier = authz.identifier().to_string();
        for challenge in &authz.challenges {
            if let Some(problem) = &challenge.error {
                out.push(format!("{identifier}: {problem}"));
            }
        }
    }
    out
}

/// Collapse `(name, value)` pairs into the set of values expected at each name.
pub fn group_by_name(records: &[(String, String)]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in records {
        out.entry(name.clone()).or_default().push(value.clone());
    }
    for values in out.values_mut() {
        values.sort();
        values.dedup();
    }
    out
}

/// Wait until every expected TXT value is visible at the zone's authoritative
/// nameservers.
///
/// Authoritative rather than recursive, because a recursive answer can be a
/// cached NXDOMAIN from a query made moments ago — and the CA, which queries
/// authoritatively, would then see the record while the panel does not, or the
/// reverse. Neither is a state anybody can debug from a task log.
///
/// If the nameservers cannot be found the wait is skipped rather than failed:
/// the CA's own retry policy is the real backstop, and refusing to proceed
/// because *our* NS lookup failed would turn a working setup into a failed
/// order.
async fn await_propagation(
    zone_name: &str,
    expected: &BTreeMap<String, Vec<String>>,
    log: &(dyn Fn(&str) + Send + Sync),
) -> Result<()> {
    use hickory_resolver::proto::rr::{RData, RecordType};
    use rand::Rng;

    let system = system_resolver()?;
    let servers = authoritative_servers(&system, zone_name).await;
    if servers.is_empty() {
        log(&format!(
            "could not find the authoritative nameservers for {zone_name}; \
             skipping the propagation wait and letting the CA retry"
        ));
        return Ok(());
    }
    let resolver = authoritative_resolver(&servers)?;
    log(&format!(
        "waiting for {} to appear at {} authoritative nameserver(s)",
        expected.keys().cloned().collect::<Vec<_>>().join(", "),
        servers.len()
    ));

    for attempt in 0..PROPAGATION_ATTEMPTS {
        // Sleep first. The record was created moments ago; querying immediately
        // buys one guaranteed miss and a negative cache entry somewhere.
        let jitter: f64 = rand::thread_rng().gen_range(0.0..1.0);
        tokio::time::sleep(propagation_delay(attempt, jitter)).await;

        let mut all_present = true;
        for (name, values) in expected {
            let found: Vec<String> = match resolver.lookup(name.as_str(), RecordType::TXT).await {
                Ok(lookup) => lookup
                    .answers()
                    .iter()
                    .filter_map(|answer| match &answer.data {
                        // A TXT rdata is a list of character-strings that the
                        // wire format splits at 255 bytes; joining them back is
                        // what the CA does too.
                        RData::TXT(txt) => Some(
                            txt.txt_data
                                .iter()
                                .flat_map(|chunk| {
                                    String::from_utf8_lossy(chunk).into_owned().into_bytes()
                                })
                                .map(char::from)
                                .collect::<String>(),
                        ),
                        _ => None,
                    })
                    .collect(),
                Err(_) => Vec::new(),
            };

            if !values
                .iter()
                .all(|want| found.iter().any(|got| got == want))
            {
                all_present = false;
                break;
            }
        }

        if all_present {
            log("the challenge records are visible; asking the CA to validate");
            return Ok(());
        }
    }

    Err(UnihelmError::new(
        ErrorCode::AgentTimeout,
        format!(
            "the challenge TXT record was still not visible at {zone_name}'s nameservers \
             after {} seconds. The record was created, so this is a propagation delay or \
             a zone that is not actually served by those nameservers.",
            propagation_budget().as_secs()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // -- a transport that answers from a script and records what it was asked --

    struct MockTransport {
        /// `(method, path-prefix) -> response`, matched in order.
        responses: Mutex<Vec<(CfMethod, String, CfResponse)>>,
        seen: Mutex<Vec<(CfMethod, String, Option<serde_json::Value>)>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                responses: Mutex::new(Vec::new()),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn on(
            self: Arc<Self>,
            method: CfMethod,
            path: &str,
            status: u16,
            body: serde_json::Value,
        ) -> Arc<Self> {
            self.responses.lock().unwrap().push((
                method,
                path.to_string(),
                CfResponse { status, body },
            ));
            self
        }

        fn ok(
            self: Arc<Self>,
            method: CfMethod,
            path: &str,
            result: serde_json::Value,
        ) -> Arc<Self> {
            self.on(
                method,
                path,
                200,
                serde_json::json!({ "success": true, "errors": [], "result": result }),
            )
        }

        fn calls(&self) -> Vec<(CfMethod, String)> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|(m, p, _)| (*m, p.clone()))
                .collect()
        }

        fn bodies(&self) -> Vec<Option<serde_json::Value>> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|(_, _, b)| b.clone())
                .collect()
        }
    }

    #[async_trait]
    impl CfTransport for MockTransport {
        async fn send(&self, request: CfRequest) -> Result<CfResponse> {
            self.seen.lock().unwrap().push((
                request.method,
                request.path.clone(),
                request.body.clone(),
            ));

            let mut responses = self.responses.lock().unwrap();
            let position = responses
                .iter()
                .position(|(m, p, _)| *m == request.method && request.path.starts_with(p.as_str()));
            match position {
                Some(index) => Ok(responses.remove(index).2),
                None => Ok(CfResponse {
                    status: 404,
                    body: serde_json::json!({
                        "success": false,
                        "errors": [{ "code": 7003, "message": "no route for that URI" }],
                    }),
                }),
            }
        }
    }

    fn zone(id: &str, name: &str) -> Zone {
        Zone {
            id: id.into(),
            name: name.into(),
        }
    }

    // -- the client ---------------------------------------------------------

    #[tokio::test]
    async fn an_active_token_verifies_and_an_inactive_one_does_not() {
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Get,
            "/user/tokens/verify",
            serde_json::json!({ "id": "abc", "status": "active" }),
        );
        let cf = Cloudflare::new(transport.clone());
        assert_eq!(cf.verify_token().await.unwrap(), "active");
        assert_eq!(
            transport.calls(),
            vec![(CfMethod::Get, "/user/tokens/verify".to_string())]
        );

        let disabled = Arc::new(MockTransport::new()).ok(
            CfMethod::Get,
            "/user/tokens/verify",
            serde_json::json!({ "status": "disabled" }),
        );
        let err = Cloudflare::new(disabled).verify_token().await.unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(err.detail.contains("disabled"), "{}", err.detail);
    }

    #[tokio::test]
    async fn a_rejected_token_is_a_permission_error_not_a_generic_failure() {
        // The status a Global API Key sent as a bearer token produces, and the
        // status an under-scoped token produces. Both are fixable in thirty
        // seconds if the panel says which.
        let transport = Arc::new(MockTransport::new()).on(
            CfMethod::Get,
            "/user/tokens/verify",
            401,
            serde_json::json!({
                "success": false,
                "errors": [{ "code": 1000, "message": "Invalid API Token" }],
            }),
        );
        let err = Cloudflare::new(transport).verify_token().await.unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(err.detail.contains("Invalid API Token"), "{}", err.detail);
    }

    #[tokio::test]
    async fn a_success_false_body_with_http_200_is_still_a_failure() {
        // Cloudflare returns 200 with `success: false` often enough that a
        // status-only check would silently read an empty result.
        let transport = Arc::new(MockTransport::new()).on(
            CfMethod::Get,
            "/zones",
            200,
            serde_json::json!({
                "success": false,
                "errors": [{ "code": 9109, "message": "Invalid access" }],
                "result": null,
            }),
        );
        let err = Cloudflare::new(transport).zones().await.unwrap_err();
        assert_eq!(err.code, ErrorCode::CommandFailed);
        assert!(err.detail.contains("Invalid access"), "{}", err.detail);
    }

    #[tokio::test]
    async fn zone_names_are_normalised_and_a_short_page_ends_the_walk() {
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Get,
            "/zones",
            serde_json::json!([
                { "id": "z1", "name": "Example.COM." },
                { "id": "z2", "name": "example.co.uk" },
            ]),
        );
        let zones = Cloudflare::new(transport.clone()).zones().await.unwrap();
        assert_eq!(
            zones,
            vec![zone("z1", "example.com"), zone("z2", "example.co.uk")]
        );
        // One page: the second request must never have been made.
        assert_eq!(transport.calls().len(), 1);
    }

    #[tokio::test]
    async fn creating_a_txt_record_returns_the_id_needed_to_delete_it() {
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Post,
            "/zones/z1/dns_records",
            serde_json::json!({ "id": "rec1" }),
        );
        let cf = Cloudflare::new(transport.clone());
        let id = cf
            .create_txt("z1", "_acme-challenge.example.com", "digest")
            .await
            .unwrap();
        assert_eq!(id, "rec1");

        let body = transport.bodies()[0].clone().unwrap();
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["name"], "_acme-challenge.example.com");
        assert_eq!(body["content"], "digest");
        assert_eq!(body["ttl"], 60);
    }

    #[tokio::test]
    async fn a_created_record_with_no_id_is_refused_because_it_could_not_be_cleaned_up() {
        // A record the panel cannot delete is worse than a record it failed to
        // create: the first leaves litter in a customer's zone for ever.
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Post,
            "/zones/z1/dns_records",
            serde_json::json!({ "no_id_here": true }),
        );
        let err = Cloudflare::new(transport)
            .create_txt("z1", "_acme-challenge.example.com", "digest")
            .await
            .unwrap_err();
        assert!(err.detail.contains("cleaned up"), "{}", err.detail);
    }

    #[tokio::test]
    async fn deleting_a_record_addresses_it_by_zone_and_id() {
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Delete,
            "/zones/z1/dns_records/rec1",
            serde_json::json!({ "id": "rec1" }),
        );
        Cloudflare::new(transport.clone())
            .delete_record("z1", "rec1")
            .await
            .unwrap();
        assert_eq!(
            transport.calls(),
            vec![(CfMethod::Delete, "/zones/z1/dns_records/rec1".to_string())]
        );
    }

    // -- longest-suffix zone matching ---------------------------------------

    #[test]
    fn the_longest_matching_zone_wins_including_the_co_uk_trap() {
        // The trap: a token that can see both `example.co.uk` and a parked
        // `co.uk` matches both by a naive suffix test. Choosing `co.uk` writes
        // the challenge into the wrong zone, where the CA never sees it and the
        // order dies with nothing to look at.
        let zones = vec![
            zone("short", "co.uk"),
            zone("right", "example.co.uk"),
            zone("other", "example.com"),
        ];
        assert_eq!(
            longest_suffix_zone(&zones, "www.example.co.uk").unwrap().id,
            "right"
        );
        assert_eq!(
            longest_suffix_zone(&zones, "example.co.uk").unwrap().id,
            "right"
        );
        // A name that really is only under `co.uk` still matches `co.uk`.
        assert_eq!(
            longest_suffix_zone(&zones, "somethingelse.co.uk")
                .unwrap()
                .id,
            "short"
        );
    }

    #[test]
    fn a_zone_only_matches_on_a_label_boundary() {
        // `evil-example.com` ends with `example.com` as a string but is a
        // completely different domain. A bare `ends_with` would hand an attacker
        // who registers it the right to have records written into the victim's
        // zone.
        let zones = vec![zone("z", "example.com")];
        assert!(longest_suffix_zone(&zones, "evil-example.com").is_none());
        assert!(longest_suffix_zone(&zones, "notexample.com").is_none());
        assert!(longest_suffix_zone(&zones, "example.com.evil.net").is_none());
        assert!(longest_suffix_zone(&zones, "example.com").is_some());
        assert!(longest_suffix_zone(&zones, "a.b.example.com").is_some());
    }

    #[test]
    fn matching_ignores_case_a_trailing_dot_and_a_wildcard_prefix() {
        let zones = vec![zone("z", "example.com")];
        assert!(longest_suffix_zone(&zones, "WWW.Example.COM.").is_some());
        assert!(longest_suffix_zone(&zones, "*.example.com").is_some());
        assert!(longest_suffix_zone(&[], "example.com").is_none());
    }

    // -- backoff ------------------------------------------------------------

    #[test]
    fn the_propagation_backoff_grows_and_then_stops() {
        // Mid-jitter, so the sequence is the underlying curve.
        let at = |attempt| propagation_delay(attempt, 0.5).as_millis();
        assert_eq!(at(0), 2_000);
        assert!(at(1) > at(0));
        assert!(at(4) > at(2));
        // Capped, so the tail of the wait stays responsive.
        assert_eq!(at(20), 20_000);
        assert!(at(9) <= 20_000);
    }

    #[test]
    fn the_propagation_backoff_is_jittered_within_a_quarter() {
        // A fleet renewing on the same thirty-days-remaining schedule must not
        // poll one provider in lockstep.
        let low = propagation_delay(3, 0.0).as_millis() as f64;
        let mid = propagation_delay(3, 0.5).as_millis() as f64;
        let high = propagation_delay(3, 1.0).as_millis() as f64;
        assert!(low < mid && mid < high, "{low} {mid} {high}");

        // The spread is asserted as a ratio with a millisecond of slack rather
        // than as an exact equality. `2000 * 1.7^3` is not representable, so the
        // curve lands a hair under 9826 ms and an exact `low == mid * 3 / 4`
        // compares one truncation against a different one — a test that fails on
        // arithmetic nobody cares about while the property it names still holds.
        assert!((low / mid - 0.75).abs() < 1e-3, "low {low} vs mid {mid}");
        assert!((high / mid - 1.25).abs() < 1e-3, "high {high} vs mid {mid}");
    }

    #[test]
    fn a_jitter_outside_the_unit_interval_cannot_stretch_the_wait() {
        // The caller supplies the randomness; a bad caller must not be able to
        // turn a bounded wait into an unbounded one.
        assert_eq!(
            propagation_delay(2, 99.0),
            propagation_delay(2, 1.0),
            "jitter is clamped"
        );
        assert_eq!(propagation_delay(2, -5.0), propagation_delay(2, 0.0));
    }

    #[test]
    fn the_whole_propagation_wait_is_bounded() {
        // An unbounded wait holds a published TXT record and an open ACME order
        // for as long as the provider is broken.
        let budget = propagation_budget();
        assert!(
            budget >= Duration::from_secs(120),
            "{budget:?} is impatient"
        );
        assert!(budget <= Duration::from_secs(400), "{budget:?} is too long");
    }

    // -- TXT cleanup --------------------------------------------------------

    #[tokio::test]
    async fn the_challenge_records_are_removed_when_the_order_succeeds() {
        let transport = Arc::new(MockTransport::new())
            .ok(
                CfMethod::Post,
                "/zones/z1/dns_records",
                serde_json::json!({ "id": "r1" }),
            )
            .ok(
                CfMethod::Delete,
                "/zones/z1/dns_records/r1",
                serde_json::json!({ "id": "r1" }),
            );
        let cf = Cloudflare::new(transport.clone());

        let records = vec![("_acme-challenge.example.com".into(), "value-1".into())];
        let out = with_challenge_records(&cf, "z1", &records, &|_| {}, || async { Ok(7) })
            .await
            .unwrap();

        assert_eq!(out, 7);
        assert!(
            transport
                .calls()
                .contains(&(CfMethod::Delete, "/zones/z1/dns_records/r1".to_string()))
        );
    }

    #[tokio::test]
    async fn the_challenge_records_are_removed_when_the_order_fails() {
        // The path that matters. A failed order that leaves `_acme-challenge`
        // TXT records behind poisons the next attempt and litters a zone the
        // panel does not own.
        let transport = Arc::new(MockTransport::new())
            .ok(
                CfMethod::Post,
                "/zones/z1/dns_records",
                serde_json::json!({ "id": "r1" }),
            )
            .ok(
                CfMethod::Post,
                "/zones/z1/dns_records",
                serde_json::json!({ "id": "r2" }),
            )
            .ok(
                CfMethod::Delete,
                "/zones/z1/dns_records/r1",
                serde_json::json!({}),
            )
            .ok(
                CfMethod::Delete,
                "/zones/z1/dns_records/r2",
                serde_json::json!({}),
            );
        let cf = Cloudflare::new(transport.clone());

        let records = vec![
            ("_acme-challenge.example.com".into(), "value-1".into()),
            ("_acme-challenge.example.com".into(), "value-2".into()),
        ];
        let err = with_challenge_records(&cf, "z1", &records, &|_| {}, || async {
            Err::<(), _>(UnihelmError::new(
                ErrorCode::CommandFailed,
                "the CA said no",
            ))
        })
        .await
        .unwrap_err();

        // The order's error survives; it is the only useful sentence in the log.
        assert_eq!(err.detail, "the CA said no");

        let calls = transport.calls();
        assert!(calls.contains(&(CfMethod::Delete, "/zones/z1/dns_records/r1".to_string())));
        assert!(calls.contains(&(CfMethod::Delete, "/zones/z1/dns_records/r2".to_string())));
    }

    #[tokio::test]
    async fn a_half_finished_publish_still_removes_what_it_created() {
        // The path a naive implementation misses: the second create fails, so
        // nothing has "started" — but the first record is live in a customer's
        // zone and must come back out.
        let transport = Arc::new(MockTransport::new())
            .ok(
                CfMethod::Post,
                "/zones/z1/dns_records",
                serde_json::json!({ "id": "r1" }),
            )
            .on(
                CfMethod::Post,
                "/zones/z1/dns_records",
                403,
                serde_json::json!({
                    "success": false,
                    "errors": [{ "code": 10000, "message": "Authentication error" }],
                }),
            )
            .ok(
                CfMethod::Delete,
                "/zones/z1/dns_records/r1",
                serde_json::json!({}),
            );
        let cf = Cloudflare::new(transport.clone());

        let records = vec![
            ("_acme-challenge.example.com".into(), "value-1".into()),
            ("_acme-challenge.example.com".into(), "value-2".into()),
        ];
        let mut ran = false;
        let err = with_challenge_records(&cf, "z1", &records, &|_| {}, || {
            ran = true;
            async { Ok(()) }
        })
        .await
        .unwrap_err();

        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(
            !ran,
            "the order body must not run without every record live"
        );
        assert!(
            transport
                .calls()
                .contains(&(CfMethod::Delete, "/zones/z1/dns_records/r1".to_string())),
            "the record that was created must be removed: {:?}",
            transport.calls()
        );
    }

    #[tokio::test]
    async fn a_cleanup_failure_does_not_mask_the_reason_the_order_failed() {
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Post,
            "/zones/z1/dns_records",
            serde_json::json!({ "id": "r1" }),
        );
        // No DELETE is scripted, so the mock answers 404.
        let cf = Cloudflare::new(transport);

        let records = vec![("_acme-challenge.example.com".into(), "v".into())];
        let err = with_challenge_records(&cf, "z1", &records, &|_| {}, || async {
            Err::<(), _>(UnihelmError::new(ErrorCode::RateLimited, "too many orders"))
        })
        .await
        .unwrap_err();

        assert_eq!(err.code, ErrorCode::RateLimited);
        assert_eq!(err.detail, "too many orders");
    }

    // -- challenge naming and grouping --------------------------------------

    #[test]
    fn both_names_of_a_wildcard_order_publish_at_one_challenge_name() {
        // The apex authorization and the wildcard authorization share an
        // identifier, so both TXT records land at the same name with different
        // values. A provider client that treated the second create as a
        // duplicate would break every wildcard order.
        assert_eq!(challenge_name("example.com"), "_acme-challenge.example.com");
        assert_eq!(
            challenge_name("example.com."),
            "_acme-challenge.example.com"
        );

        let grouped = group_by_name(&[
            ("_acme-challenge.example.com".into(), "b".into()),
            ("_acme-challenge.example.com".into(), "a".into()),
        ]);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped["_acme-challenge.example.com"], vec!["a", "b"]);
    }

    // -- address classification ---------------------------------------------

    #[test]
    fn cloudflare_proxy_addresses_are_recognised_and_others_are_not() {
        for proxied in ["104.16.0.1", "172.64.5.5", "131.0.72.1", "2606:4700::1111"] {
            assert!(
                is_cloudflare_proxy_address(proxied.parse().unwrap()),
                "{proxied} is Cloudflare"
            );
        }
        for direct in [
            "203.0.113.10",
            "8.8.8.8",
            "104.15.255.255",
            "2001:4860:4860::8888",
        ] {
            assert!(
                !is_cloudflare_proxy_address(direct.parse().unwrap()),
                "{direct} is not Cloudflare"
            );
        }
    }

    #[test]
    fn only_publicly_reachable_addresses_count_as_this_servers_own() {
        // A domain mis-pointed at 10.0.0.5 must not be reported as correct just
        // because this server also has 10.0.0.5 on an internal interface.
        for private in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.10",
            "172.16.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            // TEST-NET-1/2/3 (RFC 5737). Excluded on purpose: no real server
            // answers the internet on one, so an interface carrying one is a lab
            // fixture rather than an address a customer should point a domain at.
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.10",
        ] {
            assert!(
                !is_globally_routable(private.parse().unwrap()),
                "{private} is not publicly reachable"
            );
        }
        for public in ["8.8.8.8", "185.199.108.153", "1.1.1.1", "2606:4700::1111"] {
            assert!(
                is_globally_routable(public.parse().unwrap()),
                "{public} is publicly reachable"
            );
        }
    }

    // -- the advisory sentence ----------------------------------------------

    #[test]
    fn a_proxied_domain_is_not_reported_as_misconfigured() {
        // Without this branch every Cloudflare-proxied customer is told their
        // DNS is wrong, which is both false and the most common setup.
        let proxied = advice_for(false, true, false, false);
        assert!(proxied.contains("proxy"), "{proxied}");
        assert!(!proxied.contains("resolves somewhere else"), "{proxied}");

        assert!(advice_for(true, false, false, false).contains("resolves to this server"));
        assert!(advice_for(false, false, true, false).contains("does not resolve yet"));
        assert!(advice_for(false, false, false, true).contains("dns.server_addresses"));
    }

    // -- input validation ---------------------------------------------------

    #[test]
    fn a_label_must_be_a_short_printable_string() {
        assert_eq!(validate_label("  acme-corp  ").unwrap(), "acme-corp");
        for bad in ["", "   ", "a\nb", "x\u{0}y"] {
            assert!(validate_label(bad).is_err(), "`{bad}` should be refused");
        }
        assert!(validate_label(&"x".repeat(65)).is_err());
        assert!(validate_label(&"x".repeat(64)).is_ok());
    }

    #[test]
    fn a_token_is_never_printable_by_accident() {
        // `#[derive(Debug)]` on an operation input is the normal thing to write,
        // and tracing will happily render it.
        let token = SecretToken::new("v1.0-abcdefghijklmnop");
        assert_eq!(format!("{token:?}"), "SecretToken(<redacted>)");

        let input = ProviderSetInput {
            kind: DnsProviderKind::Cloudflare,
            label: "acme".into(),
            token,
        };
        let rendered = format!("{input:?}");
        assert!(!rendered.contains("abcdefghijklmnop"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn the_operation_output_has_nowhere_to_put_a_token() {
        // The claim: the token is never returned. Asserted on the serialised
        // output, because that is what actually reaches the browser.
        let output = ProviderSetOutput {
            id: 1,
            kind: "cloudflare",
            label: "acme".into(),
            token_status: "active".into(),
            zones: vec!["example.com".into()],
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(!json.contains("token\":\"v1"), "{json}");
        assert!(!json.to_lowercase().contains("secret"), "{json}");
        // Only the fields an operator needs.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = parsed
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["id", "kind", "label", "token_status", "zones"]);
    }

    // -- the operations, through the registry -------------------------------

    #[tokio::test]
    async fn a_customer_cannot_store_a_dns_credential() {
        // The credential is server-wide: every tenant's wildcard issuance runs
        // through it.
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, _admin, customer) = registry().await;
        let err = reg
            .dispatch(
                "dns.provider.set",
                &auth_for(customer, Role::Customer),
                serde_json::json!({
                    "kind": "cloudflare",
                    "label": "mine",
                    "token": "v1.0-attacker-token",
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn a_reseller_cannot_replace_the_servers_dns_credential() {
        // A reseller holds `dns_manage`, which is why this operation is gated on
        // `server_manage` instead: replacing the token would redirect every
        // tenant's DNS writes at an account the reseller controls.
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::{Role, TenantScope, UserId};

        let (reg, _admin, _customer) = registry().await;
        let reseller = reg
            .services()
            .db
            .users(&TenantScope::Global)
            .create(unihelm_db::users::NewUser {
                role: Role::Reseller,
                email: unihelm_core::Email::parse("reseller@example.com").unwrap(),
                username: unihelm_core::Username::parse("reseller").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let id: UserId = reseller.id;

        let err = reg
            .dispatch(
                "dns.provider.set",
                &auth_for(id, Role::Reseller),
                serde_json::json!({
                    "kind": "cloudflare",
                    "label": "theirs",
                    "token": "v1.0-reseller-token",
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn issuing_a_wildcard_for_a_site_in_another_tenant_is_not_found() {
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, _admin, customer) = registry().await;
        let err = reg
            .dispatch(
                "cert.issue_wildcard",
                &auth_for(customer, Role::Customer),
                serde_json::json!({ "site_id": 999 }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn dns_check_refuses_something_that_is_not_a_domain() {
        // Parsing is the validation: `Domain` rejects its bad values before the
        // operation body runs at all (spec §12 rule 3).
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, admin, _) = registry().await;
        for bad in ["", "no-dot", "192.0.2.1", "-leading.example.com"] {
            let err = reg
                .dispatch(
                    "dns.check",
                    &auth_for(admin, Role::Admin),
                    serde_json::json!({ "domain": bad }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "`{bad}` was accepted");
        }
    }

    #[tokio::test]
    async fn a_wildcard_without_a_stored_credential_says_what_to_add() {
        // The cheapest failure, and the one an operator is most likely to hit.
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, admin, _) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let err = resolve_provider(&ctx, "example.com").await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(err.detail.contains("dns.provider.set"), "{}", err.detail);
        assert!(err.detail.contains("Global API Key"), "{}", err.detail);
    }

    #[tokio::test]
    async fn a_stored_token_seals_on_the_way_in_and_opens_on_the_way_out() {
        // The round trip through the *operation's own* seam — `ctx.master_key()`
        // — rather than through a key the test made up. `ProviderSet` seals with
        // this and `resolve_provider` opens with it, exactly the way `cert.rs`
        // handles the ACME account credential, so this is the assertion that
        // would fail if the two halves ever drifted onto different keys.
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, admin, _) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));

        let token = "v1.0-a-token-that-must-not-appear-on-disk";
        let sealed = ctx.master_key().seal_str(token).unwrap();
        let saved = ctx
            .db()
            .save_dns_provider(DnsProviderKind::Cloudflare, "acme-corp", &sealed)
            .await
            .unwrap();

        // What a `sqlite3` reader of a panel backup would see.
        assert!(!saved.credentials_sealed.contains("must-not-appear"));
        assert_ne!(saved.credentials_sealed, token);

        let opened = ctx
            .master_key()
            .open_str(&saved.credentials_sealed)
            .unwrap();
        assert_eq!(opened, token);
        // And once opened it is a `SecretToken` again, so the value cannot fall
        // out of a `Debug` line on the way to the transport.
        assert_eq!(
            format!("{:?}", SecretToken::new(&opened)),
            "SecretToken(<redacted>)"
        );
    }
}
