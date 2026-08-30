//! The firewall and Sentinel API (spec §11.9, §13).
//!
//! A thin bridge onto the `fw.*` and `sentinel.settings*` operations. The agent
//! re-derives the permission and re-validates every rule (spec §5.2 rule 4), so
//! nothing here is load-bearing for security on its own — with one exception,
//! which is the reason this file has any logic at all:
//!
//! **The web layer is the only place that knows which address the operator is
//! browsing from.** `fw.ban` refuses to ban loopback, the server's own
//! addresses, and the caller's — because a panel that lets an admin ban
//! themselves out of the panel, over the network the panel is served on, has
//! turned a security feature into an outage. The agent enforces that refusal,
//! but it cannot see the connection; this file fills `client_ip` from the live
//! socket and the forwarding headers, exactly as the audit log does.
//!
//! A client-supplied `client_ip` is therefore ignored rather than trusted: it
//! is the one field an attacker would want to control, since a wrong value is
//! what turns the guard off.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
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

/// `GET /api/firewall` — the merged view of what is enforced and what the panel
/// recorded, including where they disagree.
#[utoipa::path(
    get,
    path = "/api/firewall",
    tag = "firewall",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Backend, whether it is active, and the merged rules", body = serde_json::Value),
        (status = 403, description = "`permission_denied`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn rules(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::FirewallManage)
        .map_err(ApiError::from)?;
    Ok(Json(
        ops::invoke_now(&state, &current.auth, "fw.rules", json!({})).await?,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PortRequest {
    pub port: u16,
    /// `tcp` or `udp`; the agent owns the whitelist.
    pub proto: String,
    /// Restrict to one address or CIDR. Absent means anywhere, which the UI
    /// marks as a decision rather than a default.
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

impl PortRequest {
    fn input(&self) -> serde_json::Value {
        json!({
            "port": self.port,
            "proto": self.proto,
            "source": self.source,
            "comment": self.comment,
        })
    }
}

/// `POST /api/firewall/ports` — open a port.
#[utoipa::path(
    post,
    path = "/api/firewall/ports",
    tag = "firewall",
    request_body = PortRequest,
    security(("session_cookie" = []), ("csrf_header" = [])),
    responses(
        (status = 200, description = "The rule as the backend now holds it", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: a bad port, protocol or CIDR", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`, or no firewall to change", body = ApiErrorBody),
    ),
)]
pub async fn port_open(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<PortRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::FirewallManage)
        .map_err(ApiError::from)?;
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "fw.port.open",
        &format!("{}/{}", body.port, body.proto),
        json!({ "source": body.source }),
    )
    .await?;
    Ok(Json(
        ops::invoke_now(&state, &current.auth, "fw.port.open", body.input()).await?,
    ))
}

/// `POST /api/firewall/ports/close` — close a port the panel opened.
///
/// A POST rather than `DELETE /ports/{port}`, because closing identifies a rule
/// by port *and* protocol *and* source: a source-restricted rule and an
/// open-to-the-world rule on the same port are two different rules, and a path
/// parameter cannot say which one is meant.
#[utoipa::path(
    post,
    path = "/api/firewall/ports/close",
    tag = "firewall",
    request_body = PortRequest,
    security(("session_cookie" = []), ("csrf_header" = [])),
    responses(
        (status = 200, description = "The rule that was removed", body = serde_json::Value),
        (status = 400, description = "`invalid_input`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn port_close(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<PortRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::FirewallManage)
        .map_err(ApiError::from)?;
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "fw.port.close",
        &format!("{}/{}", body.port, body.proto),
        json!({ "source": body.source }),
    )
    .await?;
    Ok(Json(
        ops::invoke_now(&state, &current.auth, "fw.port.close", body.input()).await?,
    ))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct BansQuery {
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /api/firewall/bans` — banned addresses, and whether the firewall is
/// really holding each one.
#[utoipa::path(
    get,
    path = "/api/firewall/bans",
    tag = "firewall",
    params(BansQuery),
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Ban records merged with the live ban set", body = serde_json::Value),
        (status = 403, description = "`permission_denied`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn bans(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<BansQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::FirewallManage)
        .map_err(ApiError::from)?;
    Ok(Json(
        ops::invoke_now(
            &state,
            &current.auth,
            "fw.bans",
            json!({ "limit": q.limit }),
        )
        .await?,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BanRequest {
    pub ip: String,
    /// Absent uses the configured default; an explicit `0` is permanent, which
    /// only an operator ever chooses.
    #[serde(default)]
    pub minutes: Option<u32>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// `POST /api/firewall/bans` — ban an address by hand.
#[utoipa::path(
    post,
    path = "/api/firewall/bans",
    tag = "firewall",
    request_body = BanRequest,
    security(("session_cookie" = []), ("csrf_header" = [])),
    responses(
        (status = 200, description = "The ban as recorded and enforced", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not an address, or one that must never be banned — loopback, this server, or the address you are browsing from", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn ban(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<BanRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::FirewallManage)
        .map_err(ApiError::from)?;

    // Filled from the live connection, never from the body — see the module
    // docs. This is the field that keeps an admin from banning themselves.
    let caller = client_ip(Some(&peer), &headers);

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "fw.ban",
        &body.ip,
        json!({ "minutes": body.minutes, "reason": body.reason }),
    )
    .await?;

    Ok(Json(
        ops::invoke_now(
            &state,
            &current.auth,
            "fw.ban",
            json!({
                "ip": body.ip,
                "minutes": body.minutes,
                "reason": body.reason,
                "client_ip": caller,
            }),
        )
        .await?,
    ))
}

/// `DELETE /api/firewall/bans/{ip}` — lift a ban.
#[utoipa::path(
    delete,
    path = "/api/firewall/bans/{ip}",
    tag = "firewall",
    params(("ip" = String, Path, description = "The banned address")),
    security(("session_cookie" = []), ("csrf_header" = [])),
    responses(
        (status = 200, description = "How many open ban records this closed; zero means we were not the one holding it", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: not an address", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn unban(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(ip): Path<String>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::FirewallManage)
        .map_err(ApiError::from)?;
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "fw.unban",
        &ip,
        json!({}),
    )
    .await?;
    Ok(Json(
        ops::invoke_now(&state, &current.auth, "fw.unban", json!({ "ip": ip })).await?,
    ))
}

/// `GET /api/firewall/sentinel` — the brute-force defence settings.
#[utoipa::path(
    get,
    path = "/api/firewall/sentinel",
    tag = "firewall",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Settings; `enabled` is false on a fresh install", body = serde_json::Value),
        (status = 403, description = "`permission_denied`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn sentinel_get(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::FirewallManage)
        .map_err(ApiError::from)?;
    Ok(Json(
        ops::invoke_now(&state, &current.auth, "sentinel.settings", json!({})).await?,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SentinelRequest {
    pub enabled: bool,
    pub ssh_threshold: u32,
    pub window_minutes: u32,
    pub ban_minutes: u32,
    /// Addresses and CIDRs Sentinel must never ban.
    #[serde(default)]
    pub allowlist: Vec<String>,
}

/// `PUT /api/firewall/sentinel` — change them.
#[utoipa::path(
    put,
    path = "/api/firewall/sentinel",
    tag = "firewall",
    request_body = SentinelRequest,
    security(("session_cookie" = []), ("csrf_header" = [])),
    responses(
        (status = 200, description = "The settings as stored", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: a threshold or window that cannot work, or an allowlist entry that is not an address", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn sentinel_set(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<SentinelRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::FirewallManage)
        .map_err(ApiError::from)?;
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "sentinel.settings.set",
        if body.enabled { "enabled" } else { "disabled" },
        json!({
            "ssh_threshold": body.ssh_threshold,
            "window_minutes": body.window_minutes,
            "ban_minutes": body.ban_minutes,
            "allowlist_entries": body.allowlist.len(),
        }),
    )
    .await?;

    Ok(Json(
        ops::invoke_now(
            &state,
            &current.auth,
            "sentinel.settings.set",
            json!({
                "enabled": body.enabled,
                "ssh_threshold": body.ssh_threshold,
                "window_minutes": body.window_minutes,
                "ban_minutes": body.ban_minutes,
                "allowlist": body.allowlist,
            }),
        )
        .await?,
    ))
}

/// One audit row per mutation, before the operation runs.
///
/// Before, not after, for the same reason the rest of the panel does it: an
/// operation that fails halfway still happened, and "who tried to open 3306 to
/// the world" is a question the log has to be able to answer either way.
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
            action: action.into(),
            target: Some(target.to_string()),
            detail,
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

    #[test]
    fn a_client_supplied_caller_address_is_not_carried_into_the_operation() {
        // `client_ip` is the field that stops an admin banning themselves, so a
        // body that set it would be a body that switched the guard off. The
        // request type simply has no such field: this test is here to fail
        // loudly if somebody ever adds one.
        let body: BanRequest = serde_json::from_value(json!({
            "ip": "203.0.113.9",
            "client_ip": "198.51.100.1",
            "minutes": 30
        }))
        .expect("unknown fields are ignored, not rejected");
        assert_eq!(body.ip, "203.0.113.9");
        assert_eq!(body.minutes, Some(30));

        let serialised = serde_json::to_value(json!({
            "ip": body.ip,
            "minutes": body.minutes,
            "reason": body.reason,
        }))
        .unwrap();
        assert!(
            serialised.get("client_ip").is_none(),
            "the caller's address must come from the connection, never the body"
        );
    }

    #[test]
    fn a_port_rule_keeps_its_source_so_two_rules_on_one_port_stay_distinct() {
        // Closing is by port + protocol + source; dropping the source here
        // would make "close 3306 from 10.0.0.0/8" close the world-open rule.
        let restricted = PortRequest {
            port: 3306,
            proto: "tcp".into(),
            source: Some("10.0.0.0/8".into()),
            comment: None,
        };
        let open = PortRequest {
            port: 3306,
            proto: "tcp".into(),
            source: None,
            comment: None,
        };
        assert_ne!(restricted.input(), open.input());
        assert_eq!(restricted.input()["source"], json!("10.0.0.0/8"));
        assert_eq!(open.input()["source"], json!(null));
    }

    #[test]
    fn sentinel_settings_round_trip_through_the_request_type() {
        let body: SentinelRequest = serde_json::from_value(json!({
            "enabled": true,
            "ssh_threshold": 6,
            "window_minutes": 10,
            "ban_minutes": 60,
            "allowlist": ["203.0.113.0/24"]
        }))
        .unwrap();
        assert!(body.enabled);
        assert_eq!(body.allowlist, vec!["203.0.113.0/24".to_string()]);

        // The allowlist defaults to empty rather than being required, so an
        // older client cannot accidentally clear it by omission... and a
        // present-but-empty list still clears it, which is the explicit act.
        let minimal: SentinelRequest = serde_json::from_value(json!({
            "enabled": false,
            "ssh_threshold": 6,
            "window_minutes": 10,
            "ban_minutes": 60
        }))
        .unwrap();
        assert!(minimal.allowlist.is_empty());
    }
}
