//! The outbound mail API (spec §11.18).
//!
//! Thin, like every route module: permission check, an audit row for the
//! mutations, then the operation. The interesting decisions — what a relay may
//! be configured as, how the shim is rendered, what the SMTP conversation says
//! — live in `unihelm_ops::mail`, and the agent re-checks every permission
//! against the same tables (spec §12 rule 4).
//!
//! What this layer *is* responsible for is the direction the relay password
//! travels. It goes in through `PUT /api/mail/relay` and is sealed with the
//! master key before it is stored; it never comes back out. There is no route
//! here that reads it, `RelayView` has no field that could carry it, and the
//! audit row records the host and the TLS mode and nothing else. A `GET` that
//! returned the stored password — even to an admin, even over TLS — would put
//! it in a browser cache, a proxy log and the reviewer's screenshot, which is
//! why one does not exist.
//!
//! The one asymmetry worth knowing about: **omitting `password` on a `PUT`
//! keeps the stored one.** It has to, because the field is write-only and an
//! operator editing the port of a working relay cannot re-type a secret they
//! can no longer read. Sending an empty string is how it gets cleared.

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use unihelm_core::Permission;
use unihelm_db::audit::NewAuditEntry;
use utoipa::ToSchema;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// The configured relay, and the DNS records it needs.
///
/// The DNS half is **advisory**. Unihelm does not publish SPF, DKIM or DMARC
/// records and does not verify them (spec §11.18: guidance, not management);
/// every record in the response carries `managed: false`, and the DKIM row has
/// no value at all because only the relay provider can supply the selector and
/// the public key.
#[utoipa::path(
    get,
    path = "/api/mail/relay",
    tag = "mail",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Host, port, TLS mode, username, whether a password is stored (never which one), whether the sendmail agent is installed, and the advisory DNS records", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_manage`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn relay_get(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "mail.relay.get", json!({})).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RelayRequest {
    /// Hostname or IP of the submission server, e.g. `smtp.postmarkapp.com`.
    pub host: String,
    /// 587 with `starttls`, 465 with `implicit`, 25 only for a relay on a
    /// private network.
    pub port: u16,
    /// `none`, `starttls` or `implicit`.
    ///
    /// A relay configured with a username and `none` is **refused**: base64 is
    /// an encoding, not encryption, and the panel will not store or send a
    /// credential that would cross the network in the clear.
    pub tls_mode: String,
    /// Omit or leave empty for a relay that authorises by source IP.
    #[serde(default)]
    pub username: Option<String>,
    /// Write-only. **Omit to keep the stored password**; send an empty string
    /// to clear it. It is sealed with the panel master key before storage and
    /// is never returned by this or any other endpoint.
    #[serde(default)]
    pub password: Option<String>,
    /// The envelope sender all mail from this server leaves as. Relays reject
    /// senders they are not authorised for, so this is the field most likely
    /// to be the reason mail bounces.
    pub from_address: String,
    #[serde(default)]
    pub from_name: Option<String>,
    /// Switching this off re-renders every pool *without* `sendmail_path`, so
    /// PHP stops handing messages to a relay the operator turned off. The
    /// credential is kept.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Store the relay and point every PHP site at it.
///
/// `PUT` because there is exactly one relay and this is an upsert of it.
///
/// 202 and a task id: this rewrites one configuration file per site and
/// reloads PHP-FPM once per PHP version, which on a busy server is well past
/// the ~300 ms an immediate operation is allowed. The task log names each site
/// as it is wired, which is the only way to see which one did not take.
#[utoipa::path(
    put,
    path = "/api/mail/relay",
    tag = "mail",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = RelayRequest,
    responses(
        (status = 202, description = "Stored; the per-site wiring runs as a task", body = ops::TaskAccepted),
        (status = 400, description = "`invalid_input`: a malformed host or address, or a username without TLS", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn relay_set(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<RelayRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    // The host, the port and the TLS mode — never the password, and never the
    // username, which is half a credential. Audit rows are exactly what gets
    // exported when somebody is debugging.
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: "mail.relay.set".into(),
            target: Some(body.host.clone()),
            detail: json!({
                "port": body.port,
                "tls_mode": body.tls_mode,
                "authenticated": body.username.is_some(),
                "enabled": body.enabled,
            }),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;

    ops::invoke(&state, &current.auth, "mail.relay.set", relay_input(&body)).await
}

/// The operation input for a relay request.
///
/// A pure function so the one subtle bit is testable: `password` appears in the
/// input **only** when the client actually sent the field. The operation
/// distinguishes absent ("keep the stored password") from empty ("clear it"),
/// and a `null` would be neither — it would deserialize as absent by accident
/// rather than on purpose, which is not a thing to leave to luck when the
/// difference is whether a working relay keeps working.
fn relay_input(body: &RelayRequest) -> serde_json::Value {
    let mut input = json!({
        "host": body.host,
        "port": body.port,
        "tls_mode": body.tls_mode,
        "username": body.username,
        "from_address": body.from_address,
        "from_name": body.from_name,
    });
    if let Some(password) = &body.password {
        input["password"] = json!(password);
    }
    if let Some(enabled) = body.enabled {
        input["enabled"] = json!(enabled);
    }
    input
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RelayTestRequest {
    /// Where to send the test. Defaults to the relay's own `from_address`.
    #[serde(default)]
    pub to: Option<String>,
}

/// Send a real message through the relay and report what happened.
///
/// **A rejection answers 200 with `delivered: false`.** It is an answer, not an
/// error: `550 Sender address rejected` at `MAIL FROM` and
/// `535 Authentication credentials invalid` at `AUTH` are two different
/// support tickets, and both would arrive as "send failed" if this returned a
/// 5xx. The body names the stage, repeats the server's own words, and carries
/// the conversation with the credential redacted, so it can be pasted into a
/// ticket as-is.
#[utoipa::path(
    post,
    path = "/api/mail/relay/test",
    tag = "mail",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = RelayTestRequest,
    responses(
        (status = 200, description = "The conversation's outcome: delivered, the stage it reached, the relay's own words, whether the session was encrypted, and the redacted transcript", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: the recipient is not an address", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no relay is configured yet", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn relay_test(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<RelayTestRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    // Audited because it sends mail from this server on somebody's authority,
    // and because a stream of tests against a relay is what an attacker who
    // found an admin session would do to enumerate valid recipients.
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(&peer), &headers)),
            action: "mail.relay.test".into(),
            target: body.to.clone(),
            detail: json!({}),
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;

    let data = ops::invoke_now(
        &state,
        &current.auth,
        "mail.relay.test",
        json!({ "to": body.to }),
    )
    .await?;
    Ok(Json(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(value: serde_json::Value) -> RelayRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    fn base() -> serde_json::Value {
        json!({
            "host": "smtp.postmarkapp.com",
            "port": 587,
            "tls_mode": "starttls",
            "username": "token",
            "from_address": "noreply@acme.example",
        })
    }

    #[test]
    fn omitting_the_password_leaves_the_field_out_of_the_operation_input_entirely() {
        // Not `null`: the operation reads absent as "keep what is stored", and
        // an operator editing the port of a working relay cannot re-type a
        // secret they can no longer read.
        let input = relay_input(&request(base()));
        assert!(
            !input.as_object().unwrap().contains_key("password"),
            "{input}"
        );
    }

    #[test]
    fn an_empty_password_is_forwarded_verbatim_so_it_can_clear_the_stored_one() {
        let mut body = base();
        body["password"] = json!("");
        let input = relay_input(&request(body));
        assert_eq!(input["password"], json!(""));
    }

    #[test]
    fn omitting_enabled_leaves_the_field_out_so_the_operation_keeps_the_setting() {
        // Same rule as the password above, and for the same reason: this
        // operation writes the whole row, so a layer that invents `true` here
        // would silently switch a relay the operator had turned off back on
        // the next time they corrected the port. Absent has to reach the
        // operation as absent.
        let input = relay_input(&request(base()));
        assert!(
            !input.as_object().unwrap().contains_key("enabled"),
            "{input}"
        );
    }

    #[test]
    fn an_explicit_enabled_is_forwarded_either_way() {
        for want in [true, false] {
            let mut body = base();
            body["enabled"] = json!(want);
            assert_eq!(relay_input(&request(body))["enabled"], json!(want));
        }
    }

    #[test]
    fn a_tls_mode_this_layer_does_not_recognise_is_passed_through_for_the_agent_to_refuse() {
        // This file must not own a second copy of the TLS vocabulary: it would
        // drift from the agent's, and the agent's is the one that decides.
        let mut body = base();
        body["tls_mode"] = json!("ssl");
        assert_eq!(relay_input(&request(body))["tls_mode"], json!("ssl"));
    }

    #[test]
    fn a_hostile_host_reaches_the_agent_byte_for_byte() {
        // The agent refuses whitespace and control characters in a relay host,
        // because the value is rendered into a line-oriented config file. This
        // layer must not "helpfully" strip them and turn an attack into a
        // valid-looking configuration.
        let payload = "smtp.example.net\ntls_certcheck off";
        let mut body = base();
        body["host"] = json!(payload);
        assert_eq!(relay_input(&request(body))["host"], json!(payload));
    }
}
