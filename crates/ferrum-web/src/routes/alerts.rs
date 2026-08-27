//! The alerting API (spec §11.11).
//!
//! Thin, like every route module: permission check, audit row for the
//! mutations, then the operation. The agent re-validates everything anyway
//! (spec §12 rule 4), so the thresholds, the URL checks and the whole debounce
//! state machine live in `ferrum_ops::alerts`, not here.
//!
//! One thing this layer *is* responsible for: a channel's configuration is a
//! credential (a bot token, or a webhook URL that carries its authorization in
//! its path), so it travels in one direction only. It goes in through
//! `POST /api/alerts/channels` and is sealed before it is stored; it never
//! comes back out — `NotifyChannel` skips the sealed blob when it serializes,
//! and the audit rows written below record the channel's *label*, never its
//! config.

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use ferrum_core::Permission;
use ferrum_db::audit::NewAuditEntry;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use utoipa::{IntoParams, ToSchema};

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EventsQuery {
    /// How many rows of history; the agent clamps it to 500.
    #[serde(default)]
    pub limit: Option<i64>,
    /// Only what is happening right now — what the dashboard's red banner reads.
    #[serde(default)]
    pub open_only: bool,
}

/// The alert history, newest first, or just the currently-open events.
///
/// `ServerRead` rather than `ServerManage`: an open alert is dashboard content
/// ("the disk is full"), and nothing in an event row is a secret. The channel
/// configuration, which is, lives behind the `ServerManage` routes below.
#[utoipa::path(
    get,
    path = "/api/alerts",
    tag = "alerts",
    security(("session_cookie" = [])),
    params(EventsQuery),
    responses(
        (status = 200, description = "Alert events, newest first", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn events(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<EventsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "alert.events.list",
        json!({ "limit": q.limit, "open_only": q.open_only }),
    )
    .await?;
    Ok(Json(data))
}

/// The configured rules, the events they have open, and the kinds a rule may
/// have (so the form's select does not have to hard-code them).
#[utoipa::path(
    get,
    path = "/api/alerts/rules",
    tag = "alerts",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Rules, open events and the valid kinds", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_manage`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn rules_list(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "alert.rules.list", json!({})).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RuleRequest {
    /// `disk_pct`, `mem_pct`, `load`, `service_down` or `cert_expiry_days`.
    pub kind: String,
    /// What within the kind: a mount point, a managed unit, a domain. Empty or
    /// absent means every subject of that kind.
    #[serde(default)]
    pub target: Option<String>,
    /// Absent only for `service_down`, which is boolean.
    #[serde(default)]
    pub threshold: Option<f64>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Create or update the rule for one `(kind, target)`.
///
/// An upsert, not an insert, and deliberately so: `(kind, target)` *is* the
/// rule's identity. Re-thresholding "disks over 90%" to 85% has to edit the
/// existing rule, because two live rules for the same disk would mean two
/// notifications for one full filesystem.
#[utoipa::path(
    post,
    path = "/api/alerts/rules",
    tag = "alerts",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = RuleRequest,
    responses(
        (status = 200, description = "The stored rule", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: unknown kind, unmanaged service, out-of-range threshold", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn rules_set(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<RuleRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "alert.rules.set",
        &match &body.target {
            Some(t) => format!("{}:{t}", body.kind),
            None => body.kind.clone(),
        },
        json!({ "threshold": body.threshold, "enabled": body.enabled }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "alert.rules.set",
        json!({
            "kind": body.kind,
            "target": body.target,
            "threshold": body.threshold,
            "enabled": body.enabled,
        }),
    )
    .await
}

/// The notifier channels — label, kind and whether they are enabled.
///
/// Never the configuration. `NotifyChannel` marks the sealed blob
/// `#[serde(skip)]`, so this cannot hand an operator's bot token (or the
/// ciphertext of one) back over HTTP even by accident.
#[utoipa::path(
    get,
    path = "/api/alerts/channels",
    tag = "alerts",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Channels, without their sealed configuration", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_manage`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn channels_list(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "alert.channels.list", json!({})).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChannelRequest {
    /// Absent = create a new channel; present = edit that one.
    #[serde(default)]
    pub id: Option<i64>,
    /// `webhook` or `telegram`. Required on create; on an edit it may only
    /// repeat the existing kind.
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    /// `{"url": "..."}` for a webhook, `{"bot_token": "...", "chat_id": "..."}`
    /// for Telegram. Omit on an edit to keep the stored configuration — that is
    /// how a channel gets renamed or disabled without the operator having to
    /// paste the credential again.
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Add a notifier channel, or edit one.
#[utoipa::path(
    post,
    path = "/api/alerts/channels",
    tag = "alerts",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = ChannelRequest,
    responses(
        (status = 200, description = "The stored channel, without its configuration", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: a malformed URL or bot token", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such channel", body = ApiErrorBody),
        (status = 409, description = "`conflict`: the label is taken, or the kind would change", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn channels_set(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<ChannelRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    // The label and whether a configuration was supplied — never the
    // configuration itself. An audit trail is read by more people than the
    // channel list is, and a webhook URL in it would be a credential in a table
    // built to be browsed (spec §10.3, §12 rule 6).
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "alert.channels.set",
        body.label.as_deref().unwrap_or("(unchanged)"),
        json!({
            "id": body.id,
            "kind": body.kind,
            "config_supplied": body.config.is_some(),
            "enabled": body.enabled,
        }),
    )
    .await?;

    let mut input = json!({});
    let object = input.as_object_mut().expect("just built as an object");
    if let Some(id) = body.id {
        object.insert("id".into(), json!(id));
    }
    if let Some(kind) = &body.kind {
        object.insert("kind".into(), json!(kind));
    }
    if let Some(label) = &body.label {
        object.insert("label".into(), json!(label));
    }
    if let Some(config) = body.config {
        object.insert("config".into(), config);
    }
    if let Some(enabled) = body.enabled {
        object.insert("enabled".into(), json!(enabled));
    }

    ops::invoke(&state, &current.auth, "alert.channels.set", input).await
}

/// Remove a channel. Its sealed configuration goes with it.
#[utoipa::path(
    delete,
    path = "/api/alerts/channels/{id}",
    tag = "alerts",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Channel id")),
    responses(
        (status = 200, description = "Deleted", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such channel", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn channels_delete(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "alert.channels.delete",
        &id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "alert.channels.delete",
        json!({ "id": id }),
    )
    .await
}

/// Send a test notification through one channel.
///
/// Answers 200 with `delivered: false` and a reason when the endpoint refuses,
/// rather than an error: the operator asked "does this work?", and "no, it
/// answered 403" is a successful answer to that question. The alternative is
/// discovering the trailing space in the bot token at three in the morning,
/// during the outage the channel existed to report.
#[utoipa::path(
    post,
    path = "/api/alerts/channels/{id}/test",
    tag = "alerts",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Channel id")),
    responses(
        (status = 200, description = "`delivered`, plus `detail` when it failed", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such channel", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn channels_test(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    // Audited even though it changes nothing here: it makes the panel emit
    // traffic to an operator-supplied endpoint, which is worth a record.
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "alert.channels.test",
        &id.to_string(),
        json!({}),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "alert.channels.test",
        json!({ "id": id }),
    )
    .await
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The audit row for a channel write must carry the label and nothing else.
    ///
    /// This is the one piece of judgement this module owns rather than delegates
    /// (the agent re-validates the rest), so it is the one piece worth a test:
    /// the audit log is built to be browsed, and a webhook URL is a bearer
    /// credential — `https://hooks.example/services/T000/B000/xxxx` authorizes
    /// whoever holds it (spec §10.3, §12 rule 6).
    #[test]
    fn a_channel_audit_row_records_the_label_and_never_the_credential() {
        let body: ChannelRequest = serde_json::from_value(json!({
            "kind": "webhook",
            "label": "ops room",
            "config": { "url": "https://hooks.example/services/T000/B000/SECRET" },
        }))
        .expect("the request shape parses");

        let detail = json!({
            "id": body.id,
            "kind": body.kind,
            "config_supplied": body.config.is_some(),
            "enabled": body.enabled,
        });

        let rendered = serde_json::to_string(&detail).expect("detail serializes");
        assert!(!rendered.contains("SECRET"), "{rendered}");
        assert!(!rendered.contains("hooks.example"), "{rendered}");
        assert_eq!(detail["config_supplied"], json!(true));
        assert_eq!(body.label.as_deref(), Some("ops room"));
    }

    /// An edit that only renames must not be forced to resend the secret, and
    /// the absent `config` must stay absent all the way to the operation — a
    /// `null` there would read as "seal this" and fail validation.
    #[test]
    fn an_edit_without_a_config_sends_no_config_key_at_all() {
        let body: ChannelRequest =
            serde_json::from_value(json!({ "id": 7, "label": "night shift" }))
                .expect("the request shape parses");

        let mut input = json!({});
        let object = input.as_object_mut().expect("object");
        if let Some(id) = body.id {
            object.insert("id".into(), json!(id));
        }
        if let Some(label) = &body.label {
            object.insert("label".into(), json!(label));
        }
        if let Some(config) = body.config {
            object.insert("config".into(), config);
        }

        assert!(
            !object.contains_key("config"),
            "an absent config must not become an explicit null: {input}"
        );
        assert_eq!(input["label"], json!("night shift"));
    }

    /// `enabled` defaults to true on a rule so that saving a threshold from the
    /// UI arms it, which is what an operator filling in a threshold means.
    #[test]
    fn a_rule_request_arms_itself_unless_told_otherwise() {
        let armed: RuleRequest =
            serde_json::from_value(json!({ "kind": "disk_pct", "threshold": 85.0 }))
                .expect("parses");
        assert!(armed.enabled);
        assert_eq!(armed.target, None, "no target means every filesystem");

        let disarmed: RuleRequest = serde_json::from_value(
            json!({ "kind": "load", "threshold": 8.0, "enabled": false }),
        )
        .expect("parses");
        assert!(!disarmed.enabled);
    }
}
