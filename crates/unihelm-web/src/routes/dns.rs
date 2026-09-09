//! The DNS API (spec §11.13, §11.5).
//!
//! Thin, like every route module: permission check, an audit row for the
//! mutations, then the operation. The agent re-checks every permission against
//! the same tables (spec §12 rule 4), so the interesting decisions — which
//! credential administers a name, how long to wait for propagation, when a TXT
//! record is removed — live in `unihelm_ops::dns` and not here.
//!
//! What this layer *is* responsible for is the direction the Cloudflare API
//! token travels. It goes in through `PUT /api/dns/provider` and is sealed with
//! the master key before it is stored; it never comes back out. No response
//! shape on this module has a field that could carry a token, and the audit
//! rows record the *label* and the zone count, never the credential.
//!
//! `GET /api/dns/provider` answers what is stored **about** the credential —
//! the label, the Cloudflare accounts and the zones it administers, and whether
//! it still answers Cloudflare — and nothing else. That distinction is the
//! whole design: a GET that returned the token, even to an admin, even over
//! TLS, would put it in a browser cache, a proxy log and the screenshot on the
//! next support ticket. Without this route the panel could not tell an operator
//! whether a token was stored at all, so they generated and pasted a new one
//! every time they reloaded the page — which is a worse outcome for the secret
//! than reading its metadata back.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use unihelm_core::Permission;
use unihelm_db::audit::NewAuditEntry;
use utoipa::{IntoParams, ToSchema};

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CheckQuery {
    /// The domain to look up. Validated as a `Domain` in the agent, so a
    /// non-domain comes back as `invalid_input` on the `domain` field rather
    /// than as a resolver error.
    pub domain: String,
}

/// Is a domain pointed at this server?
///
/// `SiteRead`, not a DNS permission: this reads public DNS and compares it with
/// addresses the server already answers on. It reveals nothing a `dig` from any
/// shell would not, it touches no stored credential, and the customer about to
/// point a domain at their site is exactly who needs the answer (spec §11.13).
///
/// The result is advisory. `matches_server: false` with `proxied_hint: true` is
/// a correct, working Cloudflare-proxied setup, not a fault — `advice` carries
/// the sentence so the UI does not keep a second copy of that decision table.
#[utoipa::path(
    get,
    path = "/api/dns/check",
    tag = "dns",
    security(("session_cookie" = [])),
    params(CheckQuery),
    responses(
        (status = 200, description = "A/AAAA records for the domain and its www form, this server's addresses, and an advisory sentence", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a domain", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `site.read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn check(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<CheckQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::SiteRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "dns.check",
        json!({ "domain": q.domain }),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ProviderRequest {
    /// `cloudflare` — the only provider this build speaks (spec §11.13).
    pub kind: String,
    /// The operator's own name for this credential. It is the only handle they
    /// get on a value they can never read back.
    pub label: String,
    /// A **Cloudflare API Token**, scoped to `Zone:Read` + `Zone:DNS:Edit` on
    /// the zones the panel will manage. Never a Global API Key: that credential
    /// authenticates every action on every zone in the account, including
    /// billing, and cannot be scoped down.
    ///
    /// Verified against Cloudflare before it is stored, then sealed with the
    /// panel master key. It is not returned by this endpoint or any other.
    pub token: String,
}

/// Store or rotate the Cloudflare API token wildcard issuance uses.
///
/// `PUT` rather than `POST` because it is an upsert keyed on `(kind, label)`:
/// re-sending the same label with a fresh token rotates that credential in
/// place. An operator who has just rotated a token in the Cloudflare dashboard
/// must not end up with two rows, the older of which is revoked and would be
/// tried first.
///
/// `ServerManage` — admin only, and deliberately not the reseller-held DNS
/// permission. This credential is server-wide: every tenant's wildcard issuance
/// runs through whatever token is stored here, so anyone who can replace it can
/// redirect the panel's DNS writes into a Cloudflare account they control.
#[utoipa::path(
    put,
    path = "/api/dns/provider",
    tag = "dns",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = ProviderRequest,
    responses(
        (status = 200, description = "The credential's label, Cloudflare's verdict on the token, and the zones it administers. Never the token.", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: empty or over-long label", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.manage`, or Cloudflare rejected the token / it can see no zones", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`, or the Cloudflare API is unreachable", body = ApiErrorBody),
    ),
)]
pub async fn provider_set(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<ProviderRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    // The label and the kind, never the token. An audit trail that recorded the
    // credential would defeat the sealing three lines later, and audit rows are
    // exactly what gets exported when somebody is debugging.
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: "dns.provider.set".into(),
            target: Some(body.label.clone()),
            detail: json!({ "kind": body.kind }),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;

    let data = ops::invoke_now(
        &state,
        &current.auth,
        "dns.provider.set",
        json!({
            "kind": body.kind,
            "label": body.label,
            "token": body.token,
        }),
    )
    .await?;
    Ok(Json(data))
}

/// Which DNS credential is stored, and what it can still reach.
///
/// The read half of `PUT /api/dns/provider`, and the answer to "is Cloudflare
/// configured at all?" — a question the panel could not previously answer after
/// a page reload. It returns the label, the Cloudflare accounts and zones the
/// token administers, and whether the token answered Cloudflare just now.
///
/// **It never returns the token.** The reachability is checked live rather than
/// remembered, because a token revoked in the Cloudflare dashboard is still a
/// row in the panel's table, and rendering that row as "Active" would be a
/// claim about the credential every certificate renewal depends on that is not
/// true. That check is one Cloudflare call per stored credential, which is why
/// the page asks for it on demand and not on a timer — the API is rate-limited
/// and this is not a health probe.
///
/// `ServerManage`, the same permission as storing it: the zone list is every
/// domain this operator's customers own.
#[utoipa::path(
    get,
    path = "/api/dns/provider",
    tag = "dns",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Each stored credential's label, accounts and zones, and whether it still answers Cloudflare. Never the token.", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server.manage`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn provider_get(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "dns.provider.get", json!({})).await?;
    Ok(Json(data))
}

/// Every zone the stored credentials can edit.
///
/// `dns.manage` gets you past this handler; being the operator of the machine is
/// what gets you an answer. The stored Cloudflare token is server-wide and the
/// panel records no owner for it, so `unihelm_ops::dns` refuses every caller
/// whose tenant scope is narrower than the whole machine — `dns.manage` is a
/// `Role::Reseller` default, and before 0.8.0 shipped that meant any reseller
/// could list, repoint and delete records in every zone the operator's token
/// reaches. The judgement lives in the operation and not here for the reason
/// this module gives everywhere else: one place decides, and it is the place
/// that holds the credential.
#[utoipa::path(
    get,
    path = "/api/dns/zones",
    tag = "dns",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "The zones, each with the credential that administers it, and the credentials that could not be asked", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `dns.manage`; or `tenant_scope_violation`: the stored credential is the machine operator's, so only an account scoped to the whole machine may spend it", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn zones(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::DnsManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "dns.zones.list", json!({})).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ZoneQuery {
    /// The zone apex, as `GET /api/dns/zones` reports it.
    pub zone: String,
}

/// Every record in one zone.
///
/// A live Cloudflare read, so the page asks for it when a zone is chosen and
/// when a write lands — never on a timer. The API is rate-limited and a table
/// that re-fetches itself in the background spends that budget on nobody.
#[utoipa::path(
    get,
    path = "/api/dns/records",
    tag = "dns",
    security(("session_cookie" = [])),
    params(ZoneQuery),
    responses(
        (status = 200, description = "The zone's records, each with what changing it would cost, plus this server's own addresses", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not a zone name", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `dns.manage`; `tenant_scope_violation`: the zone is administered by the machine operator's credential, not by your tenancy; or the token itself cannot read this zone", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no stored credential administers this zone", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`, or the Cloudflare API is unreachable", body = ApiErrorBody),
    ),
)]
pub async fn records_list(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<ZoneQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::DnsManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "dns.records.list",
        json!({ "zone": q.zone }),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RecordRequest {
    /// The zone apex the record belongs to.
    pub zone: String,
    /// `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SRV` or `CAA`.
    pub kind: String,
    /// `@` or empty for the zone apex; a bare label is qualified with the zone.
    /// A dotted name outside the zone is refused rather than appended to it.
    pub name: String,
    pub content: String,
    /// Seconds, or absent for Cloudflare's automatic.
    pub ttl: Option<u32>,
    /// The orange cloud. A, AAAA and CNAME only.
    pub proxied: Option<bool>,
    /// MX and SRV only.
    pub priority: Option<u16>,
    /// On an update: the name this record had when the operator was shown it.
    /// The agent refuses the write if the record has changed since.
    #[serde(default)]
    pub confirm_name: Option<String>,
    /// On an update: the content it had when the operator was shown it.
    #[serde(default)]
    pub confirm_content: Option<String>,
}

/// Add a record to a zone.
#[utoipa::path(
    post,
    path = "/api/dns/records",
    tag = "dns",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = RecordRequest,
    responses(
        (status = 200, description = "The record as Cloudflare stored it, with what changing it would cost", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: a field the panel can check before Cloudflare is asked", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`; `tenant_scope_violation`: the zone is administered by the machine operator's credential, not by your tenancy; or the token itself cannot edit DNS in this zone", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no stored credential administers this zone", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`, or the Cloudflare API is unreachable", body = ApiErrorBody),
    ),
)]
pub async fn record_create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<RecordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::DnsManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "dns.records.create",
        &body.zone,
        json!({ "kind": body.kind, "name": body.name, "content": body.content }),
    )
    .await?;

    let data = ops::invoke_now(
        &state,
        &current.auth,
        "dns.records.create",
        record_input(&body, None),
    )
    .await?;
    Ok(Json(data))
}

/// Replace a record with what the form now holds.
///
/// `PUT` because the write is a whole-record replace: Cloudflare's PATCH would
/// leave any field the form omitted at its old value, which is a change nobody
/// asked for happening silently. The id is the path's; the body's `confirm_*`
/// fields say what the operator was looking at, and the agent refuses if the
/// record is no longer that.
#[utoipa::path(
    put,
    path = "/api/dns/records/{id}",
    tag = "dns",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = String, Path, description = "Cloudflare's record id")),
    request_body = RecordRequest,
    responses(
        (status = 200, description = "The record as Cloudflare stored it, and what it replaced", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: a field the panel can check before Cloudflare is asked", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`; `tenant_scope_violation`: the zone is administered by the machine operator's credential, not by your tenancy; or the token itself cannot edit DNS in this zone", body = ApiErrorBody),
        (status = 404, description = "`not_found`: the record is already gone", body = ApiErrorBody),
        (status = 409, description = "`conflict`: the record changed since it was shown", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`, or the Cloudflare API is unreachable", body = ApiErrorBody),
    ),
)]
pub async fn record_update(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    current: CurrentUser,
    Json(body): Json<RecordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::DnsManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "dns.records.update",
        &id,
        json!({
            "zone": body.zone,
            "kind": body.kind,
            "name": body.name,
            "content": body.content,
        }),
    )
    .await?;

    let data = ops::invoke_now(
        &state,
        &current.auth,
        "dns.records.update",
        record_input(&body, Some(&id)),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RecordDeleteQuery {
    pub zone: String,
    /// The record's name, as the operator was shown it.
    pub confirm_name: String,
    /// The record's content, as the operator was shown it.
    pub confirm_content: String,
}

/// Remove a record, quoted back before it goes.
///
/// The `confirm_*` parameters are not ceremony. A record id addresses whatever
/// now sits under it, and between the list being rendered and Delete being
/// pressed somebody in the Cloudflare dashboard can have edited that record into
/// something else — at which point removing it by id alone takes a site off the
/// internet. The agent re-reads the record and refuses if it is not the one that
/// was shown, the same bargain `db.drop` makes with `confirm_name`.
#[utoipa::path(
    delete,
    path = "/api/dns/records/{id}",
    tag = "dns",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = String, Path, description = "Cloudflare's record id"), RecordDeleteQuery),
    responses(
        (status = 200, description = "What was removed, with the impact it had while it existed", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`; `tenant_scope_violation`: the zone is administered by the machine operator's credential, not by your tenancy; or the token itself cannot edit DNS in this zone", body = ApiErrorBody),
        (status = 404, description = "`not_found`: the record is already gone", body = ApiErrorBody),
        (status = 409, description = "`conflict`: the record changed since it was shown", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`, or the Cloudflare API is unreachable", body = ApiErrorBody),
    ),
)]
pub async fn record_delete(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<RecordDeleteQuery>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::DnsManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "dns.records.delete",
        &id,
        json!({
            "zone": q.zone,
            "confirm_name": q.confirm_name,
            "confirm_content": q.confirm_content,
        }),
    )
    .await?;

    let data = ops::invoke_now(
        &state,
        &current.auth,
        "dns.records.delete",
        json!({
            "zone": q.zone,
            "id": id,
            "confirm_name": q.confirm_name,
            "confirm_content": q.confirm_content,
        }),
    )
    .await?;
    Ok(Json(data))
}

/// The agent payload for a create (`id` absent) or an update (`id` from the
/// path).
///
/// The id is the path's on an update and is never taken from the body: a body
/// that could name a different record than the URL is a request whose meaning
/// depends on which half the reader believes. The `confirm_*` fields are sent
/// only where they mean something — a create has nothing to confirm against —
/// and an absent one reaches the agent as an empty string rather than as `null`,
/// because `RecordsUpdateInput` takes a bare `String` and would refuse the null.
fn record_input(body: &RecordRequest, id: Option<&str>) -> serde_json::Value {
    let mut input = json!({
        "zone": body.zone,
        "kind": body.kind,
        "name": body.name,
        "content": body.content,
        "ttl": body.ttl,
        "proxied": body.proxied,
        "priority": body.priority,
    });
    if let Some(id) = id {
        input["id"] = json!(id);
        input["confirm_name"] = json!(body.confirm_name.clone().unwrap_or_default());
        input["confirm_content"] = json!(body.confirm_content.clone().unwrap_or_default());
    }
    input
}

/// One audit row, in the shape every mutation on this module writes.
async fn audit(
    state: &SharedState,
    current: &CurrentUser,
    headers: &HeaderMap,
    peer: &SocketAddr,
    action: &str,
    target: &str,
    detail: serde_json::Value,
) -> ApiResult<()> {
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(peer), headers)),
            action: action.to_string(),
            target: Some(target.to_string()),
            detail,
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct IssueWildcardRequest {
    /// Use the staging directory. Its root is not publicly trusted, so this is
    /// for proving the DNS-01 flow works without spending rate-limit budget,
    /// not for a live site.
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub contact_email: Option<String>,
}

/// Request a wildcard certificate for a site over DNS-01.
///
/// Covers both `example.com` and `*.example.com` in one certificate. A
/// `*.example.com` certificate does not match `example.com` — a wildcard covers
/// exactly one label — so a wildcard-only certificate leaves the apex broken,
/// which is the single most common wildcard mistake.
///
/// 202 and a task id: the CA validates through public DNS, so this waits on a
/// zone the panel does not own and takes minutes rather than the ~300 ms an
/// immediate operation is allowed.
#[utoipa::path(
    post,
    path = "/api/sites/{id}/certificate-wildcard",
    tag = "certificates",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Site id")),
    request_body = IssueWildcardRequest,
    responses(
        (status = 202, description = "Issuance queued; poll the task", body = ops::TaskAccepted),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site in this tenant's scope, or no stored credential administers its zone", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn issue_wildcard(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(site_id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<IssueWildcardRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::SiteManage)
        .map_err(ApiError::from)?;

    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: "cert.issue_wildcard".into(),
            target: Some(site_id.to_string()),
            detail: json!({ "staging": body.staging }),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;

    ops::invoke(
        &state,
        &current.auth,
        "cert.issue_wildcard",
        json!({
            "site_id": site_id,
            "staging": body.staging,
            "contact_email": body.contact_email,
        }),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(value: serde_json::Value) -> RecordRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    /// The rule this module owns: on an update the record id is the path's, so a
    /// body cannot aim the write at a different record than the URL names.
    #[test]
    fn the_record_id_comes_from_the_path_and_never_from_the_body() {
        let body = request(json!({
            "zone": "example.com",
            "kind": "A",
            "name": "www",
            "content": "203.0.113.10",
            "id": "somebody-elses-record",
            "confirm_name": "www.example.com",
            "confirm_content": "198.51.100.4",
        }));

        let update = record_input(&body, Some("rec-from-the-path"));
        assert_eq!(update["id"], json!("rec-from-the-path"));
        assert_eq!(update["confirm_name"], json!("www.example.com"));
        assert_eq!(update["confirm_content"], json!("198.51.100.4"));

        // A create has no id and nothing to confirm against, so it sends
        // neither: an empty `confirm_name` on a create would read as a guard
        // that ran and passed.
        let create = record_input(&body, None);
        let object = create.as_object().expect("object");
        assert!(!object.contains_key("id"), "{create}");
        assert!(!object.contains_key("confirm_name"), "{create}");
        assert!(!object.contains_key("confirm_content"), "{create}");
    }

    /// `RecordsUpdateInput` takes bare `String`s for the confirmations, so a
    /// `null` is a deserialization error in the agent where an empty string is
    /// simply a guard that will not match — which is the refusal we want.
    #[test]
    fn a_missing_confirmation_reaches_the_agent_as_an_empty_string_not_a_null() {
        let body = request(json!({
            "zone": "example.com",
            "kind": "A",
            "name": "www",
            "content": "203.0.113.10",
        }));
        let update = record_input(&body, Some("rec1"));
        assert_eq!(update["confirm_name"], json!(""));
        assert_eq!(update["confirm_content"], json!(""));
    }

    /// The name is passed through byte for byte for the agent to judge. This
    /// layer must not "helpfully" qualify `shop.example.net` with the zone —
    /// that is the silent surprise `qualify_record_name` exists to refuse.
    #[test]
    fn a_name_from_another_zone_travels_untouched_for_the_agent_to_refuse() {
        let body = request(json!({
            "zone": "example.com",
            "kind": "A",
            "name": "shop.example.net",
            "content": "203.0.113.10",
        }));
        let create = record_input(&body, None);
        assert_eq!(create["name"], json!("shop.example.net"));
        assert_eq!(create["zone"], json!("example.com"));
        // Absent optionals travel as null, which the agent's `Option` fields
        // read as "not set" rather than as a value nobody chose.
        assert_eq!(create["ttl"], serde_json::Value::Null);
        assert_eq!(create["proxied"], serde_json::Value::Null);
    }
}
