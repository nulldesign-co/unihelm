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
    /// A whole-record replace. Cloudflare also offers PATCH, and the panel does
    /// not use it: a PATCH sends only the fields that changed, so a field the
    /// edit form forgot to include keeps its old value silently. PUT makes the
    /// request say what the record will be in full, which is the same shape the
    /// form already holds.
    Put,
    Delete,
}

impl CfMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            CfMethod::Get => "GET",
            CfMethod::Post => "POST",
            CfMethod::Put => "PUT",
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
            CfMethod::Put => self.client.put(&url),
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
    /// The Cloudflare account the zone belongs to, when the API says.
    ///
    /// Shown next to the zone so an operator with tokens from several
    /// Cloudflare accounts can tell which account a zone is being edited in.
    /// `None` rather than an empty string when the field is absent, because
    /// "Cloudflare did not say" and "the account is named nothing" are
    /// different facts and only one of them is worth printing.
    pub account: Option<String>,
}

/// The comment the panel stamps on records it creates for a feature of its own.
///
/// Read back in [`record_impact`]: a record the panel wrote is one the panel
/// will write again the next time that feature is applied, so an operator
/// editing it by hand is editing a copy, not the source.
pub const PANEL_RECORD_COMMENT: &str = "added by Unihelm";

/// One DNS record as Cloudflare holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfRecord {
    pub id: String,
    /// `A`, `CNAME`, `TXT`… Cloudflare's own spelling, upper case.
    pub kind: String,
    /// Always fully qualified, as Cloudflare returns it.
    pub name: String,
    pub content: String,
    /// `1` is Cloudflare's "automatic".
    pub ttl: u32,
    /// `None` for a type Cloudflare cannot put behind its proxy.
    pub proxied: Option<bool>,
    /// MX and SRV only.
    pub priority: Option<u16>,
    pub comment: Option<String>,
}

/// The fields a create or a replace carries.
///
/// One struct for both because Cloudflare's POST and PUT take the same body:
/// two structs would be two places for a field to go missing from, and a field
/// missing from a PUT body is a value silently reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordWrite {
    pub kind: String,
    pub name: String,
    pub content: String,
    pub ttl: u32,
    pub proxied: Option<bool>,
    pub priority: Option<u16>,
    pub comment: Option<String>,
}

/// A page of a zone's records, and whether it is the whole zone.
///
/// The flag is not decoration. A zone with more records than the walk below
/// will read must not be rendered as if it were complete — an operator who
/// cannot see a record concludes it is not there and adds a second one.
#[derive(Debug, Clone)]
pub struct RecordPage {
    pub records: Vec<CfRecord>,
    pub truncated: bool,
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
                    account: item
                        .get("account")
                        .and_then(|a| a.get("name"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                });
            }

            if batch < PER_PAGE {
                break;
            }
        }
        Ok(out)
    }

    /// Records of one type already at one name.
    ///
    /// Used to decide whether to write at all: a record an operator put there by
    /// hand is theirs, and the panel adding a second SPF policy beside it would
    /// break mail delivery rather than improve it — more than one SPF record on
    /// a name is a permerror, not a merge.
    pub async fn find_records(
        &self,
        zone_id: &str,
        record_type: &str,
        name: &str,
    ) -> Result<Vec<String>> {
        let result = self
            .call(CfRequest {
                method: CfMethod::Get,
                path: format!("/zones/{zone_id}/dns_records"),
                query: vec![
                    ("type".into(), record_type.into()),
                    ("name".into(), name.into()),
                ],
                body: None,
            })
            .await?;

        Ok(result
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Create one record of any type, and return its id.
    ///
    /// The ACME path has its own `create_txt` with a 60 s TTL because those
    /// records are deleted minutes later. These are records an operator means to
    /// keep, so they get the zone's default TTL and a comment saying where they
    /// came from — a zone is somebody's, and a record that appears in it without
    /// explanation is worse than no record.
    pub async fn create_record(
        &self,
        zone_id: &str,
        record_type: &str,
        name: &str,
        content: &str,
        priority: Option<u16>,
    ) -> Result<String> {
        let mut body = serde_json::json!({
            "type": record_type,
            "name": name,
            "content": content,
            "comment": "added by Unihelm",
        });
        if let Some(p) = priority {
            body["priority"] = serde_json::json!(p);
        }

        let result = self
            .call(CfRequest {
                method: CfMethod::Post,
                path: format!("/zones/{zone_id}/dns_records"),
                query: Vec::new(),
                body: Some(body),
            })
            .await?;

        result
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| {
                UnihelmError::new(
                    ErrorCode::Internal,
                    "Cloudflare accepted the record but returned no id",
                )
            })
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

    /// Every record in a zone, as far as the walk is allowed to go.
    ///
    /// Bounded the same way [`Cloudflare::zones`] is, and for the same reason:
    /// `total_pages` comes from a remote server and an unbounded loop on it is
    /// an operation that never returns. Where the bound bites, the caller is
    /// *told* — `truncated` — rather than handed a short list that looks whole.
    pub async fn list_records(&self, zone_id: &str) -> Result<RecordPage> {
        const PER_PAGE: usize = 100;
        const MAX_PAGES: usize = 20;

        let mut records = Vec::new();
        let mut truncated = false;
        for page in 1..=MAX_PAGES {
            let result = self
                .call(CfRequest {
                    method: CfMethod::Get,
                    path: format!("/zones/{zone_id}/dns_records"),
                    query: vec![
                        ("per_page".into(), PER_PAGE.to_string()),
                        ("page".into(), page.to_string()),
                        // Stable across pages, so a record cannot be skipped or
                        // seen twice while the walk is in progress.
                        ("order".into(), "type".into()),
                    ],
                    body: None,
                })
                .await?;

            let Some(items) = result.as_array() else {
                return Err(UnihelmError::new(
                    ErrorCode::CommandFailed,
                    "Cloudflare returned a record list that is not a list",
                ));
            };
            let batch = items.len();
            for item in items {
                records.push(parse_record(item)?);
            }

            if batch < PER_PAGE {
                return Ok(RecordPage {
                    records,
                    truncated: false,
                });
            }
            truncated = page == MAX_PAGES;
        }

        Ok(RecordPage { records, truncated })
    }

    /// One record, by id.
    ///
    /// The read that every write in this module makes first: an edit or a
    /// delete addressed by id alone is a change to whatever now sits under that
    /// id, and what the operator was looking at is what they meant.
    pub async fn record(&self, zone_id: &str, record_id: &str) -> Result<CfRecord> {
        let result = self
            .call(CfRequest {
                method: CfMethod::Get,
                path: format!("/zones/{zone_id}/dns_records/{record_id}"),
                query: Vec::new(),
                body: None,
            })
            .await?;
        parse_record(&result)
    }

    /// Create a record from a full write, and return it as Cloudflare stored it.
    ///
    /// The *returned* record, not the one that was sent: Cloudflare normalises
    /// names, resolves an automatic TTL and refuses a proxy on a type that
    /// cannot carry one, so echoing the request back would show the operator a
    /// record that does not exist.
    pub async fn create_full_record(&self, zone_id: &str, write: &RecordWrite) -> Result<CfRecord> {
        let result = self
            .call(CfRequest {
                method: CfMethod::Post,
                path: format!("/zones/{zone_id}/dns_records"),
                query: Vec::new(),
                body: Some(write.to_body()),
            })
            .await?;
        parse_record(&result)
    }

    /// Replace a record wholesale, and return it as Cloudflare stored it.
    pub async fn replace_record(
        &self,
        zone_id: &str,
        record_id: &str,
        write: &RecordWrite,
    ) -> Result<CfRecord> {
        let result = self
            .call(CfRequest {
                method: CfMethod::Put,
                path: format!("/zones/{zone_id}/dns_records/{record_id}"),
                query: Vec::new(),
                body: Some(write.to_body()),
            })
            .await?;
        parse_record(&result)
    }
}

impl RecordWrite {
    /// The JSON body Cloudflare's create and replace both take.
    fn to_body(&self) -> serde_json::Value {
        let mut body = serde_json::json!({
            "type": self.kind,
            "name": self.name,
            "content": self.content,
            "ttl": self.ttl,
        });
        if let Some(proxied) = self.proxied {
            body["proxied"] = serde_json::json!(proxied);
        }
        if let Some(priority) = self.priority {
            body["priority"] = serde_json::json!(priority);
        }
        // Sent even when it is empty, because a PUT that omits it clears the
        // comment on the record it replaces — which is how the provenance of a
        // record the panel wrote would disappear the first time somebody
        // corrected its TTL.
        body["comment"] = match &self.comment {
            Some(comment) => serde_json::json!(comment),
            None => serde_json::Value::Null,
        };
        body
    }
}

/// Read one record out of a Cloudflare response object.
///
/// Missing `id`, `type`, `name` or `content` is an error rather than a default:
/// a record with an empty name would be rendered as the zone apex, and a record
/// with no id is one the panel would offer an Edit button for that could only
/// fail.
fn parse_record(item: &serde_json::Value) -> Result<CfRecord> {
    let field = |key: &str| item.get(key).and_then(|v| v.as_str());
    let (Some(id), Some(kind), Some(name), Some(content)) =
        (field("id"), field("type"), field("name"), field("content"))
    else {
        return Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            "Cloudflare returned a DNS record with no id, type, name or content",
        ));
    };

    Ok(CfRecord {
        id: id.to_string(),
        kind: kind.to_ascii_uppercase(),
        name: name.trim_end_matches('.').to_ascii_lowercase(),
        content: content.to_string(),
        // 1 is Cloudflare's "automatic"; it is also the value it reports when
        // the field is absent on a proxied record.
        ttl: item
            .get("ttl")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1) as u32,
        proxied: item.get("proxied").and_then(serde_json::Value::as_bool),
        priority: item
            .get("priority")
            .and_then(serde_json::Value::as_u64)
            .and_then(|p| u16::try_from(p).ok()),
        comment: item
            .get("comment")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    })
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
        .filter(|zone| name_is_in_zone(&zone.name, name))
        .max_by_key(|zone| zone.name.len())
}

/// Is `name` the zone apex or a name under it?
///
/// Both arguments are expected lower-cased and without a trailing dot. Lifted
/// out of [`longest_suffix_zone`] when the record editor needed the same test:
/// two copies of a label-boundary check drift, and the looser copy is the hole
/// — `evil-example.com` ends with `example.com` as a string, and a bare
/// `ends_with` would hand whoever registers it the right to have records
/// written into the victim's zone.
pub fn name_is_in_zone(zone: &str, name: &str) -> bool {
    let zone = zone.trim_end_matches('.');
    if zone.is_empty() {
        return false;
    }
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Every record type the panel will write.
///
/// A closed list rather than whatever the operator typed: Cloudflare supports
/// several dozen types whose content this panel cannot check at all, and a
/// refusal naming the eight it does know is a better answer than a request the
/// API rejects with a schema error.
pub const RECORD_TYPES: &[&str] = &["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"];

/// The types Cloudflare can put behind its proxy.
const PROXYABLE_TYPES: &[&str] = &["A", "AAAA", "CNAME"];

/// Cloudflare's "automatic" TTL, and the only TTL a proxied record may carry.
pub const TTL_AUTOMATIC: u32 = 1;

/// A record as a form or a CLI supplied it, before the panel has judged it.
#[derive(Debug, Clone)]
pub struct RecordDraft {
    pub kind: String,
    pub name: String,
    pub content: String,
    pub ttl: Option<u32>,
    pub proxied: Option<bool>,
    pub priority: Option<u16>,
}

/// The fully-qualified name a typed one means inside `zone`.
///
/// `@` and an empty string are the apex, a bare label is qualified with the
/// zone the way every zone editor does it, and a name that is already inside
/// the zone is taken as it stands.
///
/// The case that earns the refusal is a dotted name that is *not* inside the
/// zone. Cloudflare treats a name it does not recognise as relative and appends
/// the zone to it, so sending `shop.example.net` while editing `example.com`
/// silently creates `shop.example.net.example.com` — a record that exists, that
/// the API reports as created, and that answers nothing. Refusing is the only
/// answer that is not a lie about what happened.
pub fn qualify_record_name(zone: &str, typed: &str) -> Result<String> {
    let zone = zone.trim_end_matches('.').to_ascii_lowercase();
    let typed = typed.trim().trim_end_matches('.').to_ascii_lowercase();

    let refuse = |detail: String| {
        UnihelmError::new(ErrorCode::InvalidInput, detail).with_field("name".to_string())
    };

    if typed.is_empty() || typed == "@" || typed == zone {
        return Ok(zone);
    }

    // A leading `*` is a wildcard label, not part of the name being looked up;
    // it is put back after the rest has been qualified.
    let (wildcard, rest) = match typed.strip_prefix("*.") {
        Some(rest) => (true, rest.to_string()),
        None if typed == "*" => (true, String::new()),
        None => (false, typed.clone()),
    };

    let qualified = if rest.is_empty() || rest == "@" {
        zone.clone()
    } else if name_is_in_zone(&zone, &rest) {
        rest.clone()
    } else if !rest.contains('.') {
        format!("{rest}.{zone}")
    } else {
        return Err(refuse(format!(
            "`{typed}` is not a name inside `{zone}`. Cloudflare would read it as a \
             relative name and create `{typed}.{zone}` instead. Use a name ending in \
             `{zone}`, a bare label such as `www`, or `@` for the zone itself."
        )));
    };

    let full = if wildcard {
        format!("*.{qualified}")
    } else {
        qualified
    };

    if full.len() > 253 {
        return Err(refuse(format!(
            "`{full}` is {} characters; a DNS name may be at most 253.",
            full.len()
        )));
    }
    for label in full.split('.') {
        if label == "*" {
            continue;
        }
        if label.is_empty() {
            return Err(refuse(format!(
                "`{typed}` has an empty label — two dots in a row, or a dot with \
                 nothing before it."
            )));
        }
        if label.len() > 63 {
            return Err(refuse(format!(
                "`{label}` is {} characters; a DNS label may be at most 63.",
                label.len()
            )));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(refuse(format!(
                "`{label}` is not a DNS label: letters, digits, `-` and `_` only. \
                 A space or a stray character is the usual cause."
            )));
        }
    }

    Ok(full)
}

/// Turn a draft into the write Cloudflare will be sent, or say why not.
///
/// Everything here is checkable without a network call, and checking it here is
/// the difference between a message naming the field and Cloudflare's own
/// schema error arriving three seconds later against a form that has already
/// been dismissed. What is deliberately *not* checked is anything Cloudflare
/// alone knows — a CNAME that would collide with an existing record at the same
/// name, a zone that is not on a plan allowing this type — because guessing at
/// those would mean refusing writes the API would have accepted.
///
/// `comment` is carried through rather than composed: on an edit it is the
/// comment the record already had, so a record the panel wrote for mail or for
/// ACME does not quietly lose the note saying where it came from.
pub fn record_write(
    zone: &str,
    draft: &RecordDraft,
    comment: Option<String>,
) -> Result<RecordWrite> {
    let kind = draft.kind.trim().to_ascii_uppercase();
    if !RECORD_TYPES.contains(&kind.as_str()) {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "`{}` is not a record type this panel writes. It writes {}.",
                draft.kind.trim(),
                RECORD_TYPES.join(", ")
            ),
        )
        .with_field("kind"));
    }

    let name = qualify_record_name(zone, &draft.name)?;

    let content = draft.content.trim().to_string();
    let bad_content = |detail: String| {
        UnihelmError::new(ErrorCode::InvalidInput, detail).with_field("content".to_string())
    };
    if content.is_empty() {
        return Err(bad_content(format!(
            "a {kind} record needs content — {}.",
            content_expectation(&kind)
        )));
    }

    match kind.as_str() {
        // The mistake this catches is real and silent: an AAAA address typed
        // into a form that was on A is refused by Cloudflare with a schema
        // error that does not say which field, and an IPv4 address in an AAAA
        // record is accepted by nothing at all.
        "A" => {
            if content.parse::<Ipv4Addr>().is_err() {
                return Err(bad_content(format!(
                    "an A record's content is an IPv4 address, and `{content}` is not one. \
                     Use AAAA for an IPv6 address, or CNAME to point at another name."
                )));
            }
        }
        "AAAA" => {
            if content.parse::<Ipv6Addr>().is_err() {
                return Err(bad_content(format!(
                    "an AAAA record's content is an IPv6 address, and `{content}` is not one. \
                     Use A for an IPv4 address."
                )));
            }
        }
        "CNAME" | "NS" => {
            if content.contains(char::is_whitespace) || !content.contains('.') {
                return Err(bad_content(format!(
                    "a {kind} record's content is a host name such as \
                     `target.example.com`, and `{content}` is not one."
                )));
            }
        }
        "MX" => {
            if content.contains(char::is_whitespace) || !content.contains('.') {
                return Err(bad_content(
                    "an MX record's content is the mail host's name, such as \
                     `mail.example.com` — not an address and not a priority."
                        .to_string(),
                ));
            }
            if draft.priority.is_none() {
                return Err(UnihelmError::new(
                    ErrorCode::InvalidInput,
                    "an MX record needs a priority. Lower is preferred; 10 is the \
                     conventional value for a single mail host.",
                )
                .with_field("priority"));
            }
        }
        _ => {}
    }

    // Priority belongs to MX and SRV. Sent on anything else Cloudflare either
    // ignores it or refuses the record, and a value that is ignored is a
    // setting the operator believes they made.
    if draft.priority.is_some() && !matches!(kind.as_str(), "MX" | "SRV") {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!("a {kind} record has no priority; only MX and SRV do."),
        )
        .with_field("priority"));
    }

    let proxied = draft.proxied.unwrap_or(false);
    if proxied && !PROXYABLE_TYPES.contains(&kind.as_str()) {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "Cloudflare can only proxy {} records, not {kind}.",
                PROXYABLE_TYPES.join(", ")
            ),
        )
        .with_field("proxied"));
    }

    let ttl = draft.ttl.unwrap_or(TTL_AUTOMATIC);
    if proxied && ttl != TTL_AUTOMATIC {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "a proxied record's TTL is Cloudflare's to choose, so a TTL cannot be set \
             alongside the proxy. Leave the TTL automatic, or turn the proxy off.",
        )
        .with_field("ttl"));
    }
    if ttl != TTL_AUTOMATIC && !(60..=86_400).contains(&ttl) {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "a TTL of {ttl} seconds is outside what Cloudflare accepts: 60 to 86400, \
                 or automatic."
            ),
        )
        .with_field("ttl"));
    }

    Ok(RecordWrite {
        kind: kind.clone(),
        name,
        content,
        ttl,
        // Sent only where it means something, so a TXT record is not created
        // carrying `proxied: false` as if the choice had been available.
        proxied: PROXYABLE_TYPES.contains(&kind.as_str()).then_some(proxied),
        priority: draft.priority,
        comment,
    })
}

/// What a type's content is, in one clause, for the "it is empty" refusal.
fn content_expectation(kind: &str) -> &'static str {
    match kind {
        "A" => "an IPv4 address",
        "AAAA" => "an IPv6 address",
        "CNAME" | "NS" => "a host name",
        "MX" => "the mail host's name",
        "TXT" => "the text to publish",
        "SRV" => "the service target",
        "CAA" => "the certificate authority to authorise",
        _ => "a value",
    }
}

/// What changing or removing this record would cost, in sentences.
///
/// A pure function, and the panel's only copy of this decision table — the same
/// arrangement `advice_for` has, and for the same reason: a confirm dialog that
/// keeps its own version of "is this record load-bearing" is a second version
/// to keep in step, and the one that goes stale is the one somebody deletes a
/// live site with.
///
/// `hosted` is the domains of the sites this server actually serves, so the
/// first sentence can name the site rather than describe an address.
pub fn record_impact(record: &CfRecord, points_here: bool, hosted: &[String]) -> Vec<String> {
    let mut out = Vec::new();

    let serves = hosted.iter().find(|domain| {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        record.name == domain || record.name == format!("www.{domain}")
    });

    if matches!(record.kind.as_str(), "A" | "AAAA" | "CNAME") {
        if let Some(site) = serves {
            out.push(format!(
                "`{}` is how visitors reach {site}, a site on this server. Removing or \
                 changing it takes {site} off the internet until DNS propagates the \
                 replacement, and Let's Encrypt cannot renew its certificate over \
                 HTTP-01 while the name does not resolve here.",
                record.name
            ));
        } else if points_here {
            out.push(format!(
                "`{}` resolves to this server's own address ({}). Whatever is served \
                 from that name stops reaching this machine if it is removed or changed.",
                record.name, record.content
            ));
        }
    }

    if record.kind == "TXT" && record.name.starts_with("_acme-challenge.") {
        out.push(format!(
            "`{}` is the name the panel publishes and removes itself while a DNS-01 \
             certificate is issued. If an issuance is running now, removing this record \
             makes that certificate fail; if none is, it is left over from one that \
             ended and can go.",
            record.name
        ));
    }

    if record.comment.as_deref() == Some(PANEL_RECORD_COMMENT) {
        out.push(
            "The panel added this record for one of its own features. Editing it here \
             does not change the setting that produced it, and applying that setting \
             again may write the record back."
                .into(),
        );
    }

    out
}

/// Say what an operator can do about a Cloudflare refusal, without hiding what
/// Cloudflare said.
///
/// A `permission_denied` from the records API means exactly one thing in
/// practice — the token was scoped `Zone:Read` but not `Zone:DNS:Edit`, or it
/// was scoped to a different zone — and that is a fix an operator can make in
/// the Cloudflare dashboard in half a minute *if the panel says so*. Cloudflare's
/// own sentence is kept and appended rather than replaced: it is the part that
/// is true even when this guess is not.
fn explain_write_refusal(error: UnihelmError, zone: &str, label: &str) -> UnihelmError {
    if error.code != ErrorCode::PermissionDenied {
        return error;
    }
    UnihelmError::new(
        ErrorCode::PermissionDenied,
        format!(
            "the `{label}` Cloudflare token cannot edit DNS in `{zone}`. It needs \
             Zone:DNS:Edit on that zone; a Zone:Read token can list records and change \
             none. Cloudflare said: {}",
            error.detail
        ),
    )
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
// the outbound destination guard
// ---------------------------------------------------------------------------

/// Refuse a URL the panel would fetch on somebody else's say-so if its host
/// lands anywhere but the public internet.
///
/// Webhook and alert-channel URLs used to be checked for their scheme and
/// nothing else, which made the panel a confused deputy: a `server_manage`
/// holder — or anyone who reached those settings — could point a hook at
/// `http://169.254.169.254/latest/meta-data/iam/security-credentials/` and have
/// the panel read a cloud instance's credentials and POST them somewhere, or
/// walk the private network from inside it one URL at a time. The panel has
/// network position nobody outside the box does, and that position was on offer
/// to whatever string was pasted into a settings field.
///
/// The test is [`is_globally_routable`] — the same predicate `dns.check` uses to
/// decide whether a customer's record points somewhere the internet can reach,
/// deliberately reused rather than restated, because two lists of private
/// ranges drift apart and the shorter one is the hole. The **resolved**
/// addresses are tested, not the spelling: `http://internal.example.com/` whose
/// A record is `127.0.0.1` is the same request as `http://127.0.0.1/`, and a
/// check on the hostname alone would miss it.
///
/// # What this does not stop
///
/// It is a check at one moment against one answer. A name that resolves to a
/// public address here and to `169.254.169.254` when the HTTP client resolves it
/// a moment later — DNS rebinding, or simply a short TTL and a changed
/// record — passes this and is then fetched anyway. Closing that needs the
/// connection itself to be pinned to the address that was checked, which reqwest
/// does not expose. So this raises the cost of the attack from "paste a URL" to
/// "control a nameserver and win a race"; it does not make it impossible, and it
/// should not be described as if it did.
///
/// `field` is the input path the caller should highlight — `url` for a webhook,
/// `config.url` for an alert channel.
pub async fn ensure_outbound_destination(url: &str, field: &str) -> Result<()> {
    let refuse = |detail: String| {
        UnihelmError::new(ErrorCode::InvalidInput, detail).with_field(field.to_string())
    };

    // A real URL parser rather than string surgery on the authority: a
    // hand-rolled split gets `http://good.example@169.254.169.254/` wrong, and
    // getting it wrong here is the whole bypass. `reqwest::Url` is `url::Url`,
    // which is the parser reqwest itself will apply to the same string — so the
    // host this check judges is the host the request will be sent to.
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| refuse(format!("`{url}` is not a URL the panel can send to: {e}")))?;
    let Some(host) = parsed.host_str() else {
        return Err(refuse(format!(
            "`{url}` names no host, so there is nothing to deliver to"
        )));
    };
    // `host_str` keeps the brackets on an IPv6 literal (`[::1]`); everything
    // below wants the address.
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    let addresses: Vec<IpAddr> = match bare.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => {
            // The system resolver, on purpose: this must agree with what the
            // HTTP client will look up, and the panel's own hickory resolver
            // (used for the DNS advisory, where asking the world's view is the
            // point) can legitimately answer differently from `getaddrinfo`.
            let port = parsed.port_or_known_default().unwrap_or(0);
            tokio::net::lookup_host((bare, port))
                .await
                .map_err(|e| {
                    refuse(format!(
                        "`{bare}` could not be resolved ({e}), so the panel cannot tell where a \
                         delivery would go and will not send one; fix the name, or use an address"
                    ))
                })?
                .map(|socket| socket.ip())
                .collect()
        }
    };

    if addresses.is_empty() {
        return Err(refuse(format!(
            "`{bare}` resolved to no addresses, so the panel cannot tell where a delivery would go"
        )));
    }

    for ip in addresses {
        if !is_globally_routable(unmap(ip)) {
            return Err(refuse(format!(
                "`{bare}` resolves to {ip}, which is not on the public internet. The panel will \
                 not deliver to a loopback, private, link-local or otherwise internal address — \
                 that would turn it into a relay into this server's own network. Point this at a \
                 publicly routable host."
            )));
        }
    }

    Ok(())
}

/// `::ffff:127.0.0.1` is `127.0.0.1`, and must not be readable as a global v6.
///
/// This lives here rather than inside [`is_globally_routable`] because the
/// advisory's callers feed it addresses that came from A/AAAA records and from
/// `getifaddrs(3)`, where the v4-mapped spelling does not occur. A URL host is
/// typed by hand, so here it does — and without this the guard above is two
/// characters away from being bypassed.
fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        // `to_ipv4` covers both `::ffff:a.b.c.d` and the deprecated
        // `::a.b.c.d`; the v4 predicate then rejects `0.0.0.0/8`, which is what
        // `::1` and `::` decode to.
        IpAddr::V6(v6) => v6.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
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
// reading the stored credentials back
// ---------------------------------------------------------------------------

/// Every stored Cloudflare credential, each with a client for it.
///
/// The client is a `Result` per row rather than an error for the whole call: a
/// credential whose seal will not open — `/etc/unihelm/secret.key` restored from
/// a different backup than the database — must be *named* as broken, because
/// the alternative is a list that is short by one and looks complete. Nothing
/// here opens a token into anything but a `SecretToken`.
async fn cloudflare_credentials(ctx: &OpContext) -> Result<Vec<(i64, String, Result<Cloudflare>)>> {
    let providers = ctx
        .db()
        .dns_providers(DnsProviderKind::Cloudflare)
        .await
        .map_err(UnihelmError::from)?;

    Ok(providers
        .into_iter()
        .map(|provider| {
            let client = ctx
                .master_key()
                .open_str(&provider.credentials_sealed)
                .map_err(|e| {
                    UnihelmError::internal(format!(
                        "the stored credential could not be decrypted ({e}). If \
                         /etc/unihelm/secret.key was replaced, set the token again."
                    ))
                })
                .and_then(|token| Cloudflare::with_token(&SecretToken::new(token)));
            (provider.id, provider.label, client)
        })
        .collect())
}

/// `dns.provider.get` — which DNS credential is stored, and what it can reach.
///
/// Issue 44: there was a `PUT` and no `GET`, so a page reload left the operator
/// with an empty form and no way to tell whether a token was stored at all —
/// which is how somebody ends up generating and pasting a fourth token to
/// replace three working ones.
///
/// **This returns the account and the zones, never the token.** A GET that
/// answered with a secret would put it in a browser cache, a proxy log and the
/// screenshot attached to the next support ticket; `StoredProviderView` has no
/// field that could carry one and
/// `a_stored_token_is_never_returned_by_the_read_endpoint` asserts it.
pub struct ProviderGet;

#[derive(Debug, Deserialize)]
pub struct ProviderGetInput {}

/// One stored credential, described by everything except its secret.
#[derive(Debug, Serialize)]
pub struct StoredProviderView {
    pub id: i64,
    pub kind: &'static str,
    pub label: String,
    /// Did the token answer Cloudflare just now?
    ///
    /// Checked live rather than remembered, because a token revoked in the
    /// Cloudflare dashboard is still a row in this table, and a panel that
    /// rendered that row as "Active" would be reporting something untrue about
    /// the credential every certificate renewal depends on.
    pub reachable: bool,
    /// Why it did not, in Cloudflare's own words.
    pub error: Option<String>,
    /// The Cloudflare accounts the zones belong to.
    pub accounts: Vec<String>,
    /// Every zone the token administers — the credential's blast radius.
    pub zones: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProviderGetOutput {
    pub providers: Vec<StoredProviderView>,
}

#[async_trait]
impl TypedOperation for ProviderGet {
    type Input = ProviderGetInput;
    type Output = ProviderGetOutput;

    const NAME: &'static str = "dns.provider.get";
    // The same permission as storing it. The zone list is the set of domains
    // this operator's customers own, which is not a secret but is not a
    // customer's business either, and the credential inventory is an admin's
    // view of an admin's setting.
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let mut providers = Vec::new();
        for (id, label, client) in cloudflare_credentials(ctx).await? {
            let view = match client {
                Err(e) => StoredProviderView {
                    id,
                    kind: DnsProviderKind::Cloudflare.as_str(),
                    label,
                    reachable: false,
                    error: Some(e.detail),
                    accounts: Vec::new(),
                    zones: Vec::new(),
                },
                Ok(cloudflare) => match cloudflare.zones().await {
                    Ok(zones) => {
                        let mut accounts: Vec<String> =
                            zones.iter().filter_map(|z| z.account.clone()).collect();
                        accounts.sort();
                        accounts.dedup();
                        StoredProviderView {
                            id,
                            kind: DnsProviderKind::Cloudflare.as_str(),
                            label,
                            reachable: true,
                            error: None,
                            accounts,
                            zones: zones.into_iter().map(|z| z.name).collect(),
                        }
                    }
                    Err(e) => StoredProviderView {
                        id,
                        kind: DnsProviderKind::Cloudflare.as_str(),
                        label,
                        reachable: false,
                        error: Some(e.detail),
                        accounts: Vec::new(),
                        zones: Vec::new(),
                    },
                },
            };
            providers.push(view);
        }
        Ok(ProviderGetOutput { providers })
    }
}

// ---------------------------------------------------------------------------
// the zone and record editor
// ---------------------------------------------------------------------------

/// Refuse a caller whose scope is not the whole machine, naming what they asked
/// for and why the panel will not spend the operator's credential on it.
///
/// **This is the guard the 0.8.0 release review found missing, and it is the
/// entire boundary these five operations have.** `Permission::DnsManage` gated
/// no operation at all before this release, and `Role::Reseller` holds it by
/// default; the zone and record editor attached itself to that permission and
/// then took the zone name straight out of the request. Any reseller — a tenant,
/// not the operator — could therefore list every zone the operator's Cloudflare
/// token administers and then create, repoint or delete any record in any of
/// them: the A record of the panel's own domain, another reseller's customers'
/// sites, an MX rewritten to intercept their mail, or an `_acme-challenge` TXT
/// that mints a publicly-trusted certificate for a domain belonging to somebody
/// else. The `confirm_name`/`confirm_content` pair on update and delete never
/// helped: it compares against the *live* record, so it catches a stale row and
/// says nothing about whose row it is.
///
/// The comment that justified the split cited `cert.issue_wildcard` as its
/// precedent, and that precedent says the opposite. `IssueWildcard` also spends
/// the operator's token for a tenant, but it takes a `site_id`, loads it through
/// `db.sites(ctx.scope())` — `not_found` outside the caller's tenancy — and only
/// then derives the apex. It acts on a name the panel already knows the caller
/// owns. The five operations here took a bare string.
///
/// # Why "administrator only" and not "a zone some site of yours lives under"
///
/// The other candidate was to accept a zone when a site in `ctx.scope()` sits
/// under it. It was rejected as a boundary that is wrong in an ordinary
/// configuration: sub-domain hosting puts many tenants — and very often the
/// panel's own hostname — under one apex, so "reseller A hosts `a.example.com`"
/// would have handed A the whole of `example.com`, including B's records and the
/// panel's. Editing one record in a zone is not a capability that can be split
/// per tenant while `dns_providers` records no owner for the credential (see
/// `unihelm_db::dns`): the token is the machine's, so its use is the machine
/// operator's.
///
/// Nothing regresses by refusing. `DnsManage` gated nothing before 0.8.0, so no
/// deployment has ever had these operations working for a tenant, and the
/// operator keeps all five. A reseller who needs DNS written for a site they do
/// own still has `cert.issue_wildcard`, which is the one place the panel lends
/// this token to a tenant — bounded to `_acme-challenge` under a domain it has
/// verified is theirs, and cleaned up afterwards.
fn require_operator_scope(ctx: &OpContext, subject: &str) -> Result<()> {
    if ctx.scope().is_global() {
        return Ok(());
    }
    Err(UnihelmError::new(
        ErrorCode::TenantScopeViolation,
        format!(
            "{subject} is administered by the Cloudflare credential this server's operator \
             stored. That credential is a single machine-wide token and the panel records no \
             owner for it, so it cannot tell which of the zones it reaches are yours — and it \
             will not spend it on a zone you have not been shown to own. Ask the server \
             operator to make this change. A certificate for a site of your own does not need \
             it: `cert.issue_wildcard` lends the same token, for a domain the panel already \
             knows is yours."
        ),
    ))
}

/// `dns.zones.list` — every zone the stored credentials can edit.
pub struct ZonesList;

#[derive(Debug, Deserialize)]
pub struct ZonesListInput {}

#[derive(Debug, Serialize)]
pub struct ZoneView {
    pub id: String,
    pub name: String,
    pub account: Option<String>,
    /// Which stored credential administers it.
    pub provider_label: String,
}

#[derive(Debug, Serialize)]
pub struct ZonesListOutput {
    pub zones: Vec<ZoneView>,
    /// Credentials that could not be asked, so this list may be short.
    ///
    /// Reported rather than skipped: a zone missing from the picker because one
    /// token is revoked looks exactly like a zone that was never delegated, and
    /// an operator will go and create it a second time.
    pub unreachable: Vec<String>,
}

#[async_trait]
impl TypedOperation for ZonesList {
    type Input = ZonesListInput;
    type Output = ZonesListOutput;

    const NAME: &'static str = "dns.zones.list";
    // `DnsManage` still, so that an operator can narrow an administrator account
    // to "may look at the server, may not edit DNS" without also taking away
    // `server.manage`. It is not the boundary: `Role::Reseller` holds this
    // permission by default, and the one that keeps a tenant out is
    // `require_operator_scope` below. Read its comment before moving either.
    const PERMISSION: Permission = Permission::DnsManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        // Before any credential is decrypted: this list is every zone the
        // operator's tokens administer, which on a white-label panel is every
        // customer of every reseller.
        require_operator_scope(ctx, "the list of zones this panel can edit")?;

        let mut zones = Vec::new();
        let mut unreachable = Vec::new();

        for (_, label, client) in cloudflare_credentials(ctx).await? {
            let listed = match client {
                Ok(cloudflare) => cloudflare.zones().await,
                Err(e) => Err(e),
            };
            match listed {
                Ok(found) => zones.extend(found.into_iter().map(|zone| ZoneView {
                    id: zone.id,
                    name: zone.name,
                    account: zone.account,
                    provider_label: label.clone(),
                })),
                Err(e) => unreachable.push(format!("{label}: {}", e.detail)),
            }
        }

        zones.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(ZonesListOutput { zones, unreachable })
    }
}

/// One record, plus what the panel knows about what it is holding up.
#[derive(Debug, Clone, Serialize)]
pub struct RecordView {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub content: String,
    pub ttl: u32,
    pub proxied: Option<bool>,
    pub priority: Option<u16>,
    pub comment: Option<String>,
    /// The content is one of this server's own public addresses.
    pub points_here: bool,
    /// What changing or removing it would cost. See [`record_impact`].
    pub impact: Vec<String>,
}

fn record_view(record: CfRecord, addresses: &[IpAddr], hosted: &[String]) -> RecordView {
    let points_here = record
        .content
        .parse::<IpAddr>()
        .is_ok_and(|ip| addresses.contains(&ip));
    let impact = record_impact(&record, points_here, hosted);
    RecordView {
        id: record.id,
        kind: record.kind,
        name: record.name,
        content: record.content,
        ttl: record.ttl,
        proxied: record.proxied,
        priority: record.priority,
        comment: record.comment,
        points_here,
        impact,
    }
}

/// The domains of the sites this server serves, in the caller's scope.
///
/// Read from the panel's own database rather than guessed from the zone, so
/// "this record is what points shop.example.com at this box" is a fact and not
/// an inference. A failure here fails the operation: an impact sentence that
/// silently went missing is the warning nobody saw.
async fn hosted_domains(ctx: &OpContext) -> Result<Vec<String>> {
    const LIMIT: i64 = 1_000;
    Ok(ctx
        .db()
        .sites(ctx.scope())
        .list(LIMIT, 0)
        .await
        .map_err(UnihelmError::from)?
        .into_iter()
        .map(|site| site.domain.trim_end_matches('.').to_ascii_lowercase())
        .collect())
}

/// `dns.records.list` — every record in one zone.
pub struct RecordsList;

#[derive(Debug, Deserialize)]
pub struct RecordsListInput {
    /// The zone apex, as `dns.zones.list` reports it.
    pub zone: String,
}

#[derive(Debug, Serialize)]
pub struct RecordsListOutput {
    pub zone: String,
    pub zone_id: String,
    pub provider_label: String,
    pub records: Vec<RecordView>,
    /// This server's own addresses, so the UI can mark the records that point
    /// here without a second round trip.
    pub server_addresses: Vec<String>,
    /// The zone holds more records than this list carries.
    pub truncated: bool,
    /// The types this panel writes, sent rather than restated in the front end
    /// so the form's picker cannot offer a type the agent will refuse.
    pub record_types: &'static [&'static str],
    /// Of those, the ones Cloudflare can put behind its proxy — the rows the
    /// form shows an orange-cloud switch for.
    pub proxyable_types: &'static [&'static str],
}

#[async_trait]
impl TypedOperation for RecordsList {
    type Input = RecordsListInput;
    type Output = RecordsListOutput;

    const NAME: &'static str = "dns.records.list";
    // See `ZonesList`: the permission is not the boundary, `require_operator_scope` is.
    const PERMISSION: Permission = Permission::DnsManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let zone_name = normalise_zone(&input.zone)?;
        // Before `resolve_provider`, which decrypts the operator's token and
        // spends a Cloudflare call on it. Reading a zone is disclosure in its
        // own right — every record id, name and content in it is what a delete
        // or a repoint needs — so the refusal comes first.
        require_operator_scope(ctx, &format!("the zone `{zone_name}`"))?;

        let (provider_label, zone, cloudflare) = resolve_provider(ctx, &zone_name).await?;
        let addresses = server_public_addresses(ctx).await;
        let hosted = hosted_domains(ctx).await?;

        let page = cloudflare.list_records(&zone.id).await?;
        let mut records: Vec<RecordView> = page
            .records
            .into_iter()
            .map(|record| record_view(record, &addresses, &hosted))
            .collect();
        // Grouped by name rather than left in Cloudflare's order, because the
        // question an operator brings to this table is "what is at this name",
        // and the two records that answer it must not be forty rows apart.
        records.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.content.cmp(&b.content))
        });

        Ok(RecordsListOutput {
            zone: zone.name,
            zone_id: zone.id,
            provider_label,
            records,
            server_addresses: addresses.iter().map(ToString::to_string).collect(),
            truncated: page.truncated,
            record_types: RECORD_TYPES,
            proxyable_types: PROXYABLE_TYPES,
        })
    }
}

/// A zone name, cleaned but not invented.
fn normalise_zone(zone: &str) -> Result<String> {
    let cleaned = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    if cleaned.is_empty() || !cleaned.contains('.') {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!("`{zone}` is not a zone name. Use the apex, such as `example.com`."),
        )
        .with_field("zone"));
    }
    Ok(cleaned)
}

/// What a create or a replace answers with.
#[derive(Debug, Serialize)]
pub struct RecordWriteOutput {
    pub zone: String,
    /// The record as Cloudflare stored it — not as it was sent. Cloudflare
    /// normalises names and resolves an automatic TTL, and echoing the request
    /// back would show a record that does not exist.
    pub record: RecordView,
    /// What stood there before, on an edit.
    pub previous: Option<RecordView>,
}

/// `dns.records.create` — add one record to a zone.
pub struct RecordsCreate;

#[derive(Debug, Deserialize)]
pub struct RecordsCreateInput {
    pub zone: String,
    /// `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SRV` or `CAA`.
    pub kind: String,
    /// `@` or empty for the zone apex; a bare label is qualified with the zone.
    pub name: String,
    pub content: String,
    /// Seconds, or absent for Cloudflare's automatic.
    #[serde(default)]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub proxied: Option<bool>,
    /// MX and SRV only.
    #[serde(default)]
    pub priority: Option<u16>,
}

#[async_trait]
impl TypedOperation for RecordsCreate {
    type Input = RecordsCreateInput;
    type Output = RecordWriteOutput;

    const NAME: &'static str = "dns.records.create";
    // See `ZonesList`: the permission is not the boundary, `require_operator_scope` is.
    const PERMISSION: Permission = Permission::DnsManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let zone_name = normalise_zone(&input.zone)?;
        // A create is how a tenant would write `_acme-challenge` into somebody
        // else's zone and take out a publicly-trusted certificate for their
        // domain. Refused before the token is opened.
        require_operator_scope(ctx, &format!("the zone `{zone_name}`"))?;

        let (provider_label, zone, cloudflare) = resolve_provider(ctx, &zone_name).await?;

        let draft = RecordDraft {
            kind: input.kind,
            name: input.name,
            content: input.content,
            ttl: input.ttl,
            proxied: input.proxied,
            priority: input.priority,
        };
        // A record an operator typed is theirs, so it carries no panel comment:
        // `PANEL_RECORD_COMMENT` is what the panel writes for its own features,
        // and stamping it here would make `record_impact` warn that editing a
        // hand-made record will not change a setting that does not exist.
        let write = record_write(&zone.name, &draft, None)?;

        let stored = cloudflare
            .create_full_record(&zone.id, &write)
            .await
            .map_err(|e| explain_write_refusal(e, &zone.name, &provider_label))?;

        let addresses = server_public_addresses(ctx).await;
        let hosted = hosted_domains(ctx).await?;
        let record = record_view(stored, &addresses, &hosted);
        ctx.log(format!(
            "created {} {} in {} through the `{provider_label}` token",
            record.kind, record.name, zone.name
        ));

        Ok(RecordWriteOutput {
            zone: zone.name,
            record,
            previous: None,
        })
    }
}

/// `dns.records.update` — replace one record with what the form now holds.
pub struct RecordsUpdate;

#[derive(Debug, Deserialize)]
pub struct RecordsUpdateInput {
    pub zone: String,
    /// Cloudflare's record id, from `dns.records.list`.
    pub id: String,
    pub kind: String,
    pub name: String,
    pub content: String,
    #[serde(default)]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub proxied: Option<bool>,
    #[serde(default)]
    pub priority: Option<u16>,
    /// The name this record had when it was shown.
    pub confirm_name: String,
    /// The content it had when it was shown.
    pub confirm_content: String,
}

#[async_trait]
impl TypedOperation for RecordsUpdate {
    type Input = RecordsUpdateInput;
    type Output = RecordWriteOutput;

    const NAME: &'static str = "dns.records.update";
    // See `ZonesList`: the permission is not the boundary, `require_operator_scope` is.
    const PERMISSION: Permission = Permission::DnsManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let zone_name = normalise_zone(&input.zone)?;
        // Ahead of `record_as_shown`: that check compares against the live
        // record and answers "is this still the row you were looking at", never
        // "is this row yours". Both are needed and only one of them was here.
        require_operator_scope(ctx, &format!("the zone `{zone_name}`"))?;

        let (provider_label, zone, cloudflare) = resolve_provider(ctx, &zone_name).await?;

        let current = record_as_shown(
            &cloudflare,
            &zone,
            &input.id,
            &input.confirm_name,
            &input.confirm_content,
        )
        .await?;

        let draft = RecordDraft {
            kind: input.kind,
            name: input.name,
            content: input.content,
            ttl: input.ttl,
            proxied: input.proxied,
            priority: input.priority,
        };
        // The comment travels across the edit. A PUT that dropped it would strip
        // the note saying the panel wrote this record for mail or for ACME —
        // and `record_impact` reads that note to warn the next operator.
        let write = record_write(&zone.name, &draft, current.comment.clone())?;

        let stored = cloudflare
            .replace_record(&zone.id, &current.id, &write)
            .await
            .map_err(|e| explain_write_refusal(e, &zone.name, &provider_label))?;

        let addresses = server_public_addresses(ctx).await;
        let hosted = hosted_domains(ctx).await?;
        let previous = record_view(current, &addresses, &hosted);
        let record = record_view(stored, &addresses, &hosted);
        ctx.log(format!(
            "replaced {} {} = {} with {} {} = {} in {}",
            previous.kind,
            previous.name,
            previous.content,
            record.kind,
            record.name,
            record.content,
            zone.name
        ));

        Ok(RecordWriteOutput {
            zone: zone.name,
            record,
            previous: Some(previous),
        })
    }
}

/// `dns.records.delete` — remove one record, named and quoted back.
pub struct RecordsDelete;

#[derive(Debug, Deserialize)]
pub struct RecordsDeleteInput {
    pub zone: String,
    pub id: String,
    /// The name of the record being removed, as it was shown.
    pub confirm_name: String,
    /// Its content, as it was shown.
    pub confirm_content: String,
}

#[derive(Debug, Serialize)]
pub struct RecordsDeleteOutput {
    pub zone: String,
    /// What was actually removed, with the impact it had while it existed.
    pub deleted: RecordView,
}

#[async_trait]
impl TypedOperation for RecordsDelete {
    type Input = RecordsDeleteInput;
    type Output = RecordsDeleteOutput;

    const NAME: &'static str = "dns.records.delete";
    // See `ZonesList`: the permission is not the boundary, `require_operator_scope` is.
    const PERMISSION: Permission = Permission::DnsManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let zone_name = normalise_zone(&input.zone)?;
        // The worst of the five: an id and two values read a second earlier from
        // `dns.records.list` satisfied the staleness check, and the A record of
        // the panel's own domain went out with it.
        require_operator_scope(ctx, &format!("the zone `{zone_name}`"))?;

        let (provider_label, zone, cloudflare) = resolve_provider(ctx, &zone_name).await?;

        let current = record_as_shown(
            &cloudflare,
            &zone,
            &input.id,
            &input.confirm_name,
            &input.confirm_content,
        )
        .await?;

        let addresses = server_public_addresses(ctx).await;
        let hosted = hosted_domains(ctx).await?;
        let deleted = record_view(current, &addresses, &hosted);

        // Logged before the call, so a delete that removes a site's A record or
        // a live ACME challenge leaves the reason in the task log even when the
        // browser that started it has gone.
        for line in &deleted.impact {
            ctx.log(format!("warning: {line}"));
        }

        cloudflare
            .delete_record(&zone.id, &deleted.id)
            .await
            .map_err(|e| explain_write_refusal(e, &zone.name, &provider_label))?;
        ctx.log(format!(
            "removed {} {} = {} from {}",
            deleted.kind, deleted.name, deleted.content, zone.name
        ));

        Ok(RecordsDeleteOutput {
            zone: zone.name,
            deleted,
        })
    }
}

/// Fetch the record `id` names and refuse unless it is still the one the
/// operator was looking at.
///
/// A record id addresses whatever now sits under it. Between the list being
/// rendered and Delete being pressed, somebody in the Cloudflare dashboard can
/// have edited that record into something else — and then the panel would
/// remove a record nobody chose, which for an A record is a site off the
/// internet. So the caller sends back the name and content it displayed, and a
/// disagreement is a refusal that says what changed, not a delete of the wrong
/// thing. It is the same bargain `db.drop` makes with `confirm_name`.
async fn record_as_shown(
    cloudflare: &Cloudflare,
    zone: &Zone,
    id: &str,
    confirm_name: &str,
    confirm_content: &str,
) -> Result<CfRecord> {
    let current = cloudflare.record(&zone.id, id).await.map_err(|e| {
        if e.code == ErrorCode::NotFound {
            UnihelmError::new(
                ErrorCode::NotFound,
                format!(
                    "there is no record `{id}` in `{}` any more — it has probably already \
                     been removed. Reload the record list.",
                    zone.name
                ),
            )
        } else {
            e
        }
    })?;

    let expected_name = confirm_name
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let expected_content = confirm_content.trim();
    if current.name != expected_name || current.content.trim() != expected_content {
        return Err(UnihelmError::new(
            ErrorCode::Conflict,
            format!(
                "record `{id}` in `{}` is now {} {} = {}, not {} = {} as shown. Somebody \
                 changed it in the meantime. Reload the record list and look again \
                 before removing or editing it.",
                zone.name,
                current.kind,
                current.name,
                current.content,
                expected_name,
                expected_content
            ),
        ));
    }

    Ok(current)
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
            // Whichever server is serving — see the same fix in `cert.rs`.
            let server = crate::webserver::active(ctx).await?;
            let reloader = server.reloader(ctx.distro())?;
            reloader.reload().await.map_err(|e| {
                UnihelmError::new(
                    ErrorCode::ConfigRollback,
                    format!(
                        "the certificate is on disk but {} would not reload: {e}",
                        server.display_name()
                    ),
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
pub(crate) async fn resolve_provider(
    ctx: &OpContext,
    name: &str,
) -> Result<(String, Zone, Cloudflare)> {
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
            account: None,
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

    // -- the outbound destination guard --------------------------------------

    /// Issue 60: webhook and alert-channel URLs were checked for their scheme
    /// and nothing else, so the panel would fetch — and deliver the answer
    /// from — anything reachable from inside the network, including a cloud
    /// instance's IAM credentials.
    ///
    /// Every case here is an IP literal, so the guard answers without a
    /// resolver and this test is the same on a machine with no network.
    #[tokio::test]
    async fn a_destination_off_the_public_internet_is_refused_by_the_address_it_resolved_to() {
        for inward in [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://127.0.0.1:9000/hook",
            "http://10.0.0.5/hook",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://100.64.0.1/",
            "http://0.0.0.0/",
            "https://[::1]/hook",
            "https://[fe80::1]/",
            "https://[fd00::1]/",
            // v4-mapped and the deprecated v4-compatible spellings of
            // loopback: the same socket, written so that a v6 predicate on its
            // own calls them global.
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:169.254.169.254]/",
            // Userinfo before the host: string surgery on the authority reads
            // the host as `example.com` here, which is the whole bypass.
            "https://example.com@169.254.169.254/",
        ] {
            let err = ensure_outbound_destination(inward, "url")
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "accepted {inward}");
            assert_eq!(err.field.as_deref(), Some("url"));
        }
    }

    #[tokio::test]
    async fn the_refusal_names_the_address_so_an_operator_can_act_on_it() {
        let err = ensure_outbound_destination("http://169.254.169.254/latest/meta-data/", "url")
            .await
            .unwrap_err();
        assert!(
            err.detail.contains("169.254.169.254"),
            "`invalid URL` for a URL that looks fine is unactionable: {}",
            err.detail
        );
    }

    #[tokio::test]
    async fn a_publicly_routable_destination_is_still_accepted() {
        for outward in [
            "https://198.18.0.7/hook",
            "http://8.8.8.8:8080/hook",
            "https://[2606:4700::1111]/hook",
        ] {
            ensure_outbound_destination(outward, "url")
                .await
                .unwrap_or_else(|e| panic!("refused {outward}: {}", e.detail));
        }
    }

    #[tokio::test]
    async fn a_url_with_no_host_is_refused_rather_than_resolved() {
        // `file:` never reaches here in practice — the syntactic validators
        // refuse it first — but the guard must not fall open for a URL whose
        // authority is empty, because "nothing to check" is not "safe".
        for hostless in ["file:///etc/shadow", "not a url", "https://"] {
            assert!(
                ensure_outbound_destination(hostless, "url").await.is_err(),
                "accepted {hostless}"
            );
        }
    }

    #[test]
    fn a_v4_mapped_address_is_judged_as_the_v4_address_it_is() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(
            is_globally_routable(mapped),
            "the shared predicate reads this as a global v6 — which is why the \
             guard unmaps before asking it"
        );
        assert!(!is_globally_routable(unmap(mapped)));
        // A genuinely global v6 must survive the round trip untouched.
        let global: IpAddr = "2606:4700::1111".parse().unwrap();
        assert_eq!(unmap(global), global);
        assert!(is_globally_routable(unmap(global)));
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
    async fn a_reseller_cannot_touch_the_operators_zones_or_records() {
        // The 0.8.0 release blocker, in one test. `dns_manage` gated nothing
        // before this release and `Role::Reseller` holds it by default, so the
        // five new operations were reachable by every tenant on the machine —
        // list every zone the operator's token administers, then delete or
        // repoint any record in any of them.
        //
        // **Nothing is stored here on purpose.** With no credential at all an
        // unguarded `dns.zones.list` answers `Ok` with an empty list and an
        // unguarded record operation answers `not_found` — "this *server* has no
        // Cloudflare token", which is a fact about the operator's installation
        // and is already the wrong answer to give a tenant. Both are the shape
        // this test would have caught before the fix, and neither needs the
        // network, so a revert fails here rather than hanging on a socket.
        use crate::registry::testing::{auth_for, auth_for_scope, registry};
        use unihelm_core::{Role, TenantScope, UserId};

        let (reg, admin, customer) = registry().await;
        let reseller = reg
            .services()
            .db
            .users(&TenantScope::Global)
            .create(unihelm_db::users::NewUser {
                role: Role::Reseller,
                email: unihelm_core::Email::parse("dns-reseller@example.com").unwrap(),
                username: unihelm_core::Username::parse("dnsreseller").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let reseller_id: UserId = reseller.id;

        // Through `dispatch`, so the registry's own re-derivation of the caller
        // is in the path — the same hop the HTTP route takes.
        for (op, input) in [
            ("dns.zones.list", serde_json::json!({})),
            (
                "dns.records.list",
                serde_json::json!({ "zone": "victim.example" }),
            ),
            (
                "dns.records.create",
                serde_json::json!({
                    "zone": "victim.example",
                    "kind": "TXT",
                    "name": "_acme-challenge",
                    "content": "a-token-that-would-mint-a-certificate",
                }),
            ),
            (
                "dns.records.update",
                serde_json::json!({
                    "zone": "victim.example",
                    "id": "rec1",
                    "kind": "A",
                    "name": "www",
                    "content": "203.0.113.99",
                    "confirm_name": "www.victim.example",
                    "confirm_content": "203.0.113.10",
                }),
            ),
            (
                "dns.records.delete",
                serde_json::json!({
                    "zone": "victim.example",
                    "id": "rec1",
                    "confirm_name": "www.victim.example",
                    "confirm_content": "203.0.113.10",
                }),
            ),
        ] {
            let err = reg
                .dispatch(
                    op,
                    &auth_for(reseller_id, Role::Reseller),
                    input.clone(),
                    None,
                )
                .await
                .unwrap_err();
            // Two locks, and this asserts the reseller is stopped by *some*
            // lock rather than pinning which. `Role::Reseller` no longer holds
            // `dns_manage` at all — the panel should not advertise a permission
            // that grants nothing — so today the registry's permission check
            // refuses first, and the scope guard inside each operation is what
            // holds if that default is ever widened again. Asserting the inner
            // code alone would go red for the *right* reason and read as a
            // regression; asserting refusal covers both.
            assert!(
                matches!(
                    err.code,
                    ErrorCode::TenantScopeViolation | ErrorCode::PermissionDenied
                ),
                "`{op}` must refuse a reseller, got {:?}: {}",
                err.code,
                err.detail
            );
            // The inner lock, tested against the caller it is actually for: an
            // admin *impersonating* a tenant holds `dns_manage` and does not
            // hold the machine, so the permission check passes and the scope
            // guard is what refuses. That is the path whose message has to name
            // the zone — an operator reading a support ticket cannot act on
            // "permission denied" without knowing which zone was reached for.
            let err = reg
                .dispatch(
                    op,
                    &auth_for_scope(admin, Role::Admin, TenantScope::Reseller { reseller_id }),
                    input.clone(),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::TenantScopeViolation,
                "`{op}` must refuse an impersonating admin: {}",
                err.detail
            );
            if op != "dns.zones.list" {
                assert!(
                    err.detail.contains("victim.example"),
                    "`{op}` must name the zone it refused: {}",
                    err.detail
                );
            }

            // A customer holds neither permission, and is stopped one step
            // earlier — asserted so that removing `dns_manage` from the reseller
            // role later does not quietly become the only thing holding here.
            let err = reg
                .dispatch(op, &auth_for(customer, Role::Customer), input, None)
                .await
                .unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::PermissionDenied,
                "`{op}` for a customer"
            );
        }

        // And the operator is not stranded: the same call, from the account that
        // owns the credential, still runs. Zero stored credentials is the empty
        // answer, not a refusal and not an error.
        let admin_ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let zones = ZonesList.run(&admin_ctx, ZonesListInput {}).await.unwrap();
        assert!(zones.zones.is_empty());
        let err = RecordsList
            .run(
                &admin_ctx,
                RecordsListInput {
                    zone: "victim.example".into(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::NotFound,
            "an admin reaches the credential lookup and is told there is none"
        );
    }

    #[tokio::test]
    async fn only_the_whole_machine_is_a_wide_enough_scope_for_the_shared_token() {
        // The boundary on its own, over every scope the panel builds. A
        // `TenantScope` that is not `Global` is a tenant whatever role reached
        // it — including an administrator who is impersonating one, which is the
        // case a role check rather than a scope check would have missed.
        use crate::registry::testing::registry;
        use unihelm_core::{AuthContext, Role, SubscriptionId, TenantScope, UserId};

        let (reg, admin, _) = registry().await;
        let guard = |scope: TenantScope| {
            let auth = AuthContext::from_role(admin, Role::Admin, scope, "req-test");
            require_operator_scope(
                &OpContext::new(reg.services().clone(), auth),
                "the zone `example.com`",
            )
        };

        assert!(guard(TenantScope::Global).is_ok());
        for tenant in [
            TenantScope::Reseller {
                reseller_id: UserId(7),
            },
            TenantScope::Customer {
                customer_id: UserId(8),
            },
            TenantScope::Subscription {
                subscription_id: SubscriptionId(9),
                customer_id: UserId(8),
            },
        ] {
            let err = guard(tenant).unwrap_err();
            assert_eq!(err.code, ErrorCode::TenantScopeViolation);
            assert!(
                err.detail.contains("example.com"),
                "the refusal must name what was asked for: {}",
                err.detail
            );
            assert!(
                err.detail.contains("cert.issue_wildcard"),
                "a refusal that names no alternative is a dead end: {}",
                err.detail
            );
        }
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

    // -- the record editor: the Cloudflare calls ----------------------------

    fn cf_record(id: &str, kind: &str, name: &str, content: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "type": kind,
            "name": name,
            "content": content,
            "ttl": 300,
            "proxied": false,
        })
    }

    #[tokio::test]
    async fn a_zone_carries_the_cloudflare_account_it_belongs_to() {
        // An operator holding tokens from two Cloudflare accounts needs to know
        // which account a zone is being edited in before they edit it.
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Get,
            "/zones",
            serde_json::json!([
                { "id": "z1", "name": "example.com", "account": { "id": "a1", "name": "Acme Ltd" } },
                { "id": "z2", "name": "example.net" },
            ]),
        );
        let zones = Cloudflare::new(transport).zones().await.unwrap();
        assert_eq!(zones[0].account.as_deref(), Some("Acme Ltd"));
        // Not `Some("")`: "Cloudflare did not say" is a different fact from "the
        // account is called nothing", and only one of them is worth printing.
        assert_eq!(zones[1].account, None);
    }

    #[tokio::test]
    async fn a_zone_with_more_records_than_the_walk_reads_is_reported_as_truncated() {
        // A short list rendered as if it were the whole zone is how an operator
        // concludes a record is missing and adds a second one beside it.
        let full: Vec<serde_json::Value> = (0..100)
            .map(|i| {
                cf_record(
                    &format!("r{i}"),
                    "A",
                    &format!("h{i}.example.com"),
                    "203.0.113.1",
                )
            })
            .collect();
        let mut transport = Arc::new(MockTransport::new());
        for _ in 0..20 {
            transport = transport.ok(
                CfMethod::Get,
                "/zones/z1/dns_records",
                serde_json::Value::Array(full.clone()),
            );
        }
        let page = Cloudflare::new(transport).list_records("z1").await.unwrap();
        assert_eq!(page.records.len(), 2_000);
        assert!(page.truncated, "a bounded walk must say where it stopped");
    }

    #[tokio::test]
    async fn a_short_page_ends_the_record_walk_and_is_not_truncated() {
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Get,
            "/zones/z1/dns_records",
            serde_json::json!([cf_record("r1", "a", "WWW.Example.com.", "203.0.113.9")]),
        );
        let page = Cloudflare::new(transport.clone())
            .list_records("z1")
            .await
            .unwrap();
        assert!(!page.truncated);
        assert_eq!(transport.calls().len(), 1, "one page, one request");
        // Normalised the way zone names are, so a comparison against a site's
        // domain is not defeated by a trailing dot or a capital letter.
        assert_eq!(page.records[0].name, "www.example.com");
        assert_eq!(page.records[0].kind, "A");
    }

    #[tokio::test]
    async fn a_record_missing_its_content_is_an_error_rather_than_a_blank_row() {
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Get,
            "/zones/z1/dns_records",
            serde_json::json!([{ "id": "r1", "type": "A", "name": "www.example.com" }]),
        );
        let err = Cloudflare::new(transport)
            .list_records("z1")
            .await
            .unwrap_err();
        assert!(
            err.detail.contains("no id, type, name or content"),
            "{}",
            err.detail
        );
    }

    #[tokio::test]
    async fn a_replace_sends_every_field_so_a_put_cannot_reset_one() {
        // PUT replaces the whole record. A body that omitted the comment would
        // strip the note saying the panel wrote this record for mail — which is
        // the note `record_impact` reads to warn the next operator.
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Put,
            "/zones/z1/dns_records/r1",
            cf_record("r1", "A", "www.example.com", "203.0.113.10"),
        );
        let write = RecordWrite {
            kind: "A".into(),
            name: "www.example.com".into(),
            content: "203.0.113.10".into(),
            ttl: 300,
            proxied: Some(true),
            priority: None,
            comment: Some(PANEL_RECORD_COMMENT.into()),
        };
        let stored = Cloudflare::new(transport.clone())
            .replace_record("z1", "r1", &write)
            .await
            .unwrap();
        assert_eq!(stored.id, "r1");

        let body = transport.bodies()[0].clone().unwrap();
        assert_eq!(body["type"], "A");
        assert_eq!(body["name"], "www.example.com");
        assert_eq!(body["content"], "203.0.113.10");
        assert_eq!(body["ttl"], 300);
        assert_eq!(body["proxied"], true);
        assert_eq!(body["comment"], PANEL_RECORD_COMMENT);
    }

    // -- the record editor: names -------------------------------------------

    #[test]
    fn a_bare_label_is_qualified_and_the_apex_can_be_written_three_ways() {
        assert_eq!(
            qualify_record_name("example.com", "www").unwrap(),
            "www.example.com"
        );
        assert_eq!(
            qualify_record_name("example.com", "_dmarc").unwrap(),
            "_dmarc.example.com"
        );
        for apex in ["", "@", "example.com", "Example.COM."] {
            assert_eq!(
                qualify_record_name("example.com", apex).unwrap(),
                "example.com",
                "`{apex}` names the apex"
            );
        }
        assert_eq!(
            qualify_record_name("example.com", "*").unwrap(),
            "*.example.com"
        );
        assert_eq!(
            qualify_record_name("example.com", "*.shop").unwrap(),
            "*.shop.example.com"
        );
        assert_eq!(
            qualify_record_name("example.com", "*.example.com").unwrap(),
            "*.example.com"
        );
    }

    #[test]
    fn a_name_from_another_zone_is_refused_rather_than_silently_appended() {
        // Cloudflare reads a name it does not recognise as relative and appends
        // the zone, so this would create `shop.example.net.example.com` — a
        // record that exists, is reported as created, and answers nothing.
        let err = qualify_record_name("example.com", "shop.example.net").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("name"));
        assert!(
            err.detail.contains("shop.example.net.example.com"),
            "the refusal must show what would have been created: {}",
            err.detail
        );

        // The label-boundary trap, in the name field this time.
        assert!(qualify_record_name("example.com", "evil-example.com").is_err());
        for junk in ["a b.example.com", "..example.com", "x/y.example.com"] {
            assert!(
                qualify_record_name("example.com", junk).is_err(),
                "accepted `{junk}`"
            );
        }
    }

    // -- the record editor: content -----------------------------------------

    fn draft(kind: &str, name: &str, content: &str) -> RecordDraft {
        RecordDraft {
            kind: kind.into(),
            name: name.into(),
            content: content.into(),
            ttl: None,
            proxied: None,
            priority: None,
        }
    }

    #[test]
    fn an_address_of_the_wrong_family_is_refused_by_the_field_not_by_cloudflare() {
        // "request failed" three seconds after the dialog closed is not a fix
        // anybody can act on; naming the field and the other type is.
        let err =
            record_write("example.com", &draft("A", "www", "2606:4700::1111"), None).unwrap_err();
        assert_eq!(err.field.as_deref(), Some("content"));
        assert!(err.detail.contains("AAAA"), "{}", err.detail);

        let err =
            record_write("example.com", &draft("AAAA", "www", "203.0.113.10"), None).unwrap_err();
        assert!(err.detail.contains("Use A"), "{}", err.detail);

        let ok = record_write("example.com", &draft("A", "www", " 203.0.113.10 "), None).unwrap();
        assert_eq!(ok.name, "www.example.com");
        assert_eq!(ok.content, "203.0.113.10");
        assert_eq!(ok.ttl, TTL_AUTOMATIC);
        assert_eq!(ok.proxied, Some(false));
    }

    #[test]
    fn a_type_the_panel_cannot_check_is_refused_with_the_list_it_does_write() {
        let err = record_write("example.com", &draft("LOC", "www", "anything"), None).unwrap_err();
        assert_eq!(err.field.as_deref(), Some("kind"));
        for kind in RECORD_TYPES {
            assert!(
                err.detail.contains(kind),
                "the refusal lists {kind}: {}",
                err.detail
            );
        }
        // Case is the operator's business, not the API's.
        assert_eq!(
            record_write("example.com", &draft("txt", "@", "v=spf1 -all"), None)
                .unwrap()
                .kind,
            "TXT"
        );
    }

    #[test]
    fn a_priority_belongs_to_mx_and_a_proxy_belongs_to_addresses() {
        let mut mx = draft("MX", "@", "mail.example.com");
        let err = record_write("example.com", &mx, None).unwrap_err();
        assert_eq!(err.field.as_deref(), Some("priority"));
        mx.priority = Some(10);
        assert_eq!(
            record_write("example.com", &mx, None).unwrap().priority,
            Some(10)
        );

        // A priority on a type that has none is a setting the operator believes
        // they made and the API discards.
        let mut txt = draft("TXT", "@", "hello");
        txt.priority = Some(10);
        assert_eq!(
            record_write("example.com", &txt, None)
                .unwrap_err()
                .field
                .as_deref(),
            Some("priority")
        );

        let mut proxied_txt = draft("TXT", "@", "hello");
        proxied_txt.proxied = Some(true);
        let err = record_write("example.com", &proxied_txt, None).unwrap_err();
        assert_eq!(err.field.as_deref(), Some("proxied"));
        // And a type that cannot be proxied carries no proxy flag at all, so the
        // UI does not render a switch that means nothing.
        assert_eq!(
            record_write("example.com", &draft("TXT", "@", "hi"), None)
                .unwrap()
                .proxied,
            None
        );
    }

    #[test]
    fn a_proxied_record_cannot_also_carry_a_ttl_and_a_ttl_stays_in_range() {
        let mut proxied = draft("A", "www", "203.0.113.10");
        proxied.proxied = Some(true);
        proxied.ttl = Some(300);
        let err = record_write("example.com", &proxied, None).unwrap_err();
        assert_eq!(err.field.as_deref(), Some("ttl"));

        proxied.ttl = None;
        assert_eq!(
            record_write("example.com", &proxied, None).unwrap().ttl,
            TTL_AUTOMATIC
        );

        let mut slow = draft("A", "www", "203.0.113.10");
        slow.ttl = Some(30);
        assert_eq!(
            record_write("example.com", &slow, None)
                .unwrap_err()
                .field
                .as_deref(),
            Some("ttl")
        );
        slow.ttl = Some(3_600);
        assert_eq!(record_write("example.com", &slow, None).unwrap().ttl, 3_600);
    }

    #[test]
    fn empty_content_is_refused_by_saying_what_the_type_wants() {
        for (kind, expected) in [("A", "IPv4"), ("TXT", "text"), ("MX", "mail host")] {
            let err = record_write("example.com", &draft(kind, "@", "   "), None).unwrap_err();
            assert_eq!(err.field.as_deref(), Some("content"));
            assert!(err.detail.contains(expected), "{kind}: {}", err.detail);
        }
    }

    // -- the record editor: what a change would cost ------------------------

    fn stored(kind: &str, name: &str, content: &str) -> CfRecord {
        CfRecord {
            id: "r1".into(),
            kind: kind.into(),
            name: name.into(),
            content: content.into(),
            ttl: 300,
            proxied: Some(false),
            priority: None,
            comment: None,
        }
    }

    #[test]
    fn removing_the_record_that_points_a_site_here_names_the_site_and_the_certificate() {
        // Deleting the wrong record takes a site off the internet. The confirm
        // has to say which site, before the click and not after it.
        let hosted = vec!["shop.example.com".to_string()];
        let impact = record_impact(
            &stored("A", "shop.example.com", "203.0.113.10"),
            true,
            &hosted,
        );
        assert_eq!(impact.len(), 1);
        assert!(impact[0].contains("shop.example.com"), "{}", impact[0]);
        assert!(impact[0].contains("off the internet"), "{}", impact[0]);
        assert!(impact[0].contains("HTTP-01"), "{}", impact[0]);

        // The `www.` form of a hosted domain is the same site.
        assert_eq!(
            record_impact(
                &stored("CNAME", "www.shop.example.com", "shop.example.com"),
                false,
                &hosted
            )
            .len(),
            1
        );

        // A record pointing here for a name this server hosts nothing under
        // still says so, because something is being served from it.
        let elsewhere = record_impact(
            &stored("A", "old.example.com", "203.0.113.10"),
            true,
            &hosted,
        );
        assert_eq!(elsewhere.len(), 1);
        assert!(
            elsewhere[0].contains("this server's own address"),
            "{}",
            elsewhere[0]
        );

        // And a record that is neither is quiet: a warning on every row is a
        // warning nobody reads.
        assert!(
            record_impact(&stored("TXT", "example.com", "v=spf1 -all"), false, &hosted).is_empty()
        );
    }

    #[test]
    fn a_record_the_panel_manages_for_acme_says_so_before_it_is_touched() {
        let challenge = record_impact(
            &stored("TXT", "_acme-challenge.example.com", "digest"),
            false,
            &[],
        );
        assert_eq!(challenge.len(), 1);
        assert!(challenge[0].contains("DNS-01"), "{}", challenge[0]);
        assert!(
            challenge[0].contains("makes that certificate fail"),
            "{}",
            challenge[0]
        );

        // The other half: a record the panel wrote for one of its own features
        // is a copy of a setting, and editing the copy changes nothing.
        let mut managed = stored("TXT", "example.com", "v=spf1 -all");
        managed.comment = Some(PANEL_RECORD_COMMENT.into());
        let impact = record_impact(&managed, false, &[]);
        assert_eq!(impact.len(), 1);
        assert!(
            impact[0].contains("may write the record back"),
            "{}",
            impact[0]
        );
    }

    // -- the record editor: the stale-row guard -----------------------------

    #[tokio::test]
    async fn a_record_that_changed_since_it_was_shown_is_a_refusal_not_a_delete() {
        // The failure this exists for: the list was rendered, somebody edited
        // that record in the Cloudflare dashboard, and Delete now addresses a
        // record nobody chose. For an A record that is a site off the internet.
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Get,
            "/zones/z1/dns_records/r1",
            cf_record("r1", "A", "www.example.com", "198.51.100.4"),
        );
        let cf = Cloudflare::new(transport.clone());
        let err = record_as_shown(
            &cf,
            &zone("z1", "example.com"),
            "r1",
            "www.example.com",
            "203.0.113.10",
        )
        .await
        .unwrap_err();

        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("198.51.100.4"), "{}", err.detail);
        assert!(err.detail.contains("203.0.113.10"), "{}", err.detail);
        // Nothing was removed: the guard runs before the DELETE, not after it.
        assert!(
            !transport
                .calls()
                .iter()
                .any(|(method, _)| *method == CfMethod::Delete),
            "{:?}",
            transport.calls()
        );
    }

    #[tokio::test]
    async fn the_record_the_operator_was_looking_at_passes_the_guard() {
        let transport = Arc::new(MockTransport::new()).ok(
            CfMethod::Get,
            "/zones/z1/dns_records/r1",
            cf_record("r1", "A", "www.example.com", "203.0.113.10"),
        );
        let cf = Cloudflare::new(transport);
        let current = record_as_shown(
            &cf,
            &zone("z1", "example.com"),
            "r1",
            // As the table rendered it, trailing dot and capitals included.
            "WWW.example.com.",
            " 203.0.113.10 ",
        )
        .await
        .unwrap();
        assert_eq!(current.id, "r1");
    }

    #[tokio::test]
    async fn a_record_that_is_already_gone_says_so_rather_than_reporting_a_404() {
        // No GET is scripted, so the mock answers 404 — the state an operator
        // reaches by pressing Delete twice.
        let cf = Cloudflare::new(Arc::new(MockTransport::new()));
        let err = record_as_shown(
            &cf,
            &zone("z1", "example.com"),
            "r1",
            "www.example.com",
            "203.0.113.10",
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(err.detail.contains("already"), "{}", err.detail);
        assert!(err.detail.contains("Reload"), "{}", err.detail);
    }

    #[test]
    fn a_scope_refusal_names_the_token_and_the_zone_and_keeps_cloudflares_own_words() {
        // "request failed" is not actionable; "this token cannot edit DNS for
        // this zone" is, and Cloudflare's sentence is kept because it is the
        // part that stays true when the guess does not.
        let refused = UnihelmError::new(
            ErrorCode::PermissionDenied,
            "Cloudflare refused `POST /zones/z1/dns_records` (HTTP 403): Actor \
             'com.cloudflare.api.token' requires permission 'com.cloudflare.api.account.zone.dns_record.create' (code 10000)",
        );
        let explained = explain_write_refusal(refused, "example.com", "cf-main");
        assert_eq!(explained.code, ErrorCode::PermissionDenied);
        assert!(explained.detail.contains("cf-main"), "{}", explained.detail);
        assert!(
            explained.detail.contains("example.com"),
            "{}",
            explained.detail
        );
        assert!(
            explained.detail.contains("Zone:DNS:Edit"),
            "{}",
            explained.detail
        );
        assert!(
            explained.detail.contains("dns_record.create"),
            "{}",
            explained.detail
        );

        // Everything else travels untouched: a rate limit is not a scope
        // problem, and dressing it as one sends the operator to the wrong page.
        let limited = UnihelmError::new(ErrorCode::RateLimited, "too many requests");
        let same = explain_write_refusal(limited, "example.com", "cf-main");
        assert_eq!(same.code, ErrorCode::RateLimited);
        assert_eq!(same.detail, "too many requests");
    }

    #[test]
    fn a_zone_input_that_is_not_a_zone_is_refused_by_naming_the_field() {
        for bad in ["", "   ", "localhost", "."] {
            let err = normalise_zone(bad).unwrap_err();
            assert_eq!(err.field.as_deref(), Some("zone"), "`{bad}` was accepted");
        }
        assert_eq!(normalise_zone(" Example.COM. ").unwrap(), "example.com");
    }

    // -- the read endpoint --------------------------------------------------

    #[test]
    fn a_stored_token_is_never_returned_by_the_read_endpoint() {
        // Issue 44 asked for a GET. The reason there was none is that a GET
        // returning a secret puts it in a browser cache, a proxy log and the
        // screenshot on the next support ticket — so this asserts the shape
        // that made the GET safe to add.
        let output = ProviderGetOutput {
            providers: vec![StoredProviderView {
                id: 1,
                kind: "cloudflare",
                label: "cf-main".into(),
                reachable: true,
                error: None,
                accounts: vec!["Acme Ltd".into()],
                zones: vec!["example.com".into()],
            }],
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(!json.to_lowercase().contains("token"), "{json}");
        assert!(!json.to_lowercase().contains("secret"), "{json}");
        assert!(!json.contains("credentials_sealed"), "{json}");

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Sorted, because `serde_json::Map` is a `BTreeMap` here and the
        // declaration order is not the order that reaches the browser.
        let mut keys: Vec<&str> = parsed["providers"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "accounts",
                "error",
                "id",
                "kind",
                "label",
                "reachable",
                "zones"
            ]
        );
    }

    #[tokio::test]
    async fn reading_the_provider_with_none_stored_is_an_empty_list_not_an_error() {
        // The state a fresh install is in. "No credential" is an answer the page
        // can render; an error is a page that looks broken, which is what sent
        // operators off to generate a replacement token they did not need.
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, admin, _) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));

        let stored = ProviderGet.run(&ctx, ProviderGetInput {}).await.unwrap();
        assert!(stored.providers.is_empty());

        let zones = ZonesList.run(&ctx, ZonesListInput {}).await.unwrap();
        assert!(zones.zones.is_empty());
        assert!(zones.unreachable.is_empty());
    }

    #[test]
    fn reading_the_credential_is_an_admin_act_and_editing_records_is_a_dns_one() {
        // `dns_manage` separates "may look at this server" from "may write DNS
        // with its token", so an operator can narrow an administrator account to
        // one and not the other. It does *not* separate operator from tenant:
        // `Role::Reseller` holds `dns_manage` by default, so the permission is
        // asserted here only to pin the narrowing, and
        // `a_reseller_cannot_touch_the_operators_zones_or_records` is the test
        // that pins the boundary. The credential inventory stays at
        // `server_manage`; a customer holds neither.
        assert_eq!(
            <ProviderGet as TypedOperation>::PERMISSION,
            <ProviderSet as TypedOperation>::PERMISSION,
        );
        assert_eq!(
            <ProviderGet as TypedOperation>::PERMISSION,
            Permission::ServerManage,
        );
        for permission in [
            <ZonesList as TypedOperation>::PERMISSION,
            <RecordsList as TypedOperation>::PERMISSION,
            <RecordsCreate as TypedOperation>::PERMISSION,
            <RecordsUpdate as TypedOperation>::PERMISSION,
            <RecordsDelete as TypedOperation>::PERMISSION,
        ] {
            assert_eq!(permission, Permission::DnsManage);
        }
    }

    #[test]
    fn the_operation_names_are_the_ones_the_registry_and_the_routes_are_wired_to() {
        // These strings are the wire: the registry keys operations by them, the
        // HTTP layer invokes them by name and `parity.rs` files a CLI command
        // under each. A rename that reached only one of the three is the shape
        // this codebase has shipped before, so the names are asserted where they
        // are defined rather than only where they are used.
        assert_eq!(<ProviderGet as TypedOperation>::NAME, "dns.provider.get");
        assert_eq!(<ZonesList as TypedOperation>::NAME, "dns.zones.list");
        assert_eq!(<RecordsList as TypedOperation>::NAME, "dns.records.list");
        assert_eq!(
            <RecordsCreate as TypedOperation>::NAME,
            "dns.records.create"
        );
        assert_eq!(
            <RecordsUpdate as TypedOperation>::NAME,
            "dns.records.update"
        );
        assert_eq!(
            <RecordsDelete as TypedOperation>::NAME,
            "dns.records.delete"
        );
    }

    #[tokio::test]
    async fn editing_records_without_a_stored_credential_says_what_to_add() {
        // The record page's first failure on a fresh install, and it must name
        // the fix rather than reporting an empty zone list.
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, admin, _) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let err = RecordsList
            .run(
                &ctx,
                RecordsListInput {
                    zone: "example.com".into(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(err.detail.contains("dns.provider.set"), "{}", err.detail);

        // And something that is not a zone is refused before any credential is
        // looked for, by naming the field the operator typed into.
        let err = RecordsList
            .run(
                &ctx,
                RecordsListInput {
                    zone: "not-a-zone".into(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.field.as_deref(), Some("zone"));
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
