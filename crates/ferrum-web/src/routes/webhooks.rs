//! The webhooks API (spec §2.4, §14 Phase 6, §13).
//!
//! A thin bridge onto the `webhook.*` operations in `ferrum_ops::webhook`. The
//! agent re-derives the permission from the database and re-validates the URL
//! and the event list (spec §5.2 rule 4), so nothing here is load-bearing for
//! security on its own. Three things are nevertheless decided in this file:
//!
//! 1. **The upsert is split into two verbs.** `webhook.set` creates *or*
//!    updates depending on whether it was given an `id`, which is right for an
//!    operation and wrong for a URL. `POST /api/webhooks` never carries an id;
//!    `PUT /api/webhooks/{id}` always does, and it comes from the path, so a
//!    body that disagrees cannot win.
//!
//! 2. **The audit row records the URL and the event list, never the secret.**
//!    "Where is this panel sending its events" is exactly the question an audit
//!    log exists to answer, and the signing secret is exactly the thing that
//!    must never appear in a table built to be browsed by anyone holding
//!    `audit_read` (spec §12 rule 6). The secret is minted in the agent and
//!    travels in the *response*, once.
//!
//! 3. **`GET /api/webhooks/{id}` is the same operation as the list.** The
//!    agent's `webhook.list` takes an optional id and answers with the delivery
//!    history for it. One code path means the tenant-scope check cannot differ
//!    between "list" and "detail" — the failure mode where a detail endpoint
//!    quietly forgets a filter the list endpoint applies.

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use ferrum_core::Permission;
use ferrum_db::audit::NewAuditEntry;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use utoipa::ToSchema;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// Every webhook this caller's tenant scope can see.
#[utoipa::path(
    get,
    path = "/api/webhooks",
    tag = "webhooks",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Hook rows (URL, subscribed events, active, consecutive failure count, why the panel disabled it) plus the closed event catalogue and `max_per_owner`. Signing secrets are never included.", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn list(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "webhook.list", json!({})).await?;
    Ok(Json(data))
}

/// One webhook and its recent delivery history.
#[utoipa::path(
    get,
    path = "/api/webhooks/{id}",
    tag = "webhooks",
    security(("session_cookie" = [])),
    params(("id" = i64, Path, description = "Webhook id")),
    responses(
        (status = 200, description = "The same shape as the list, plus `deliveries`: the last 50 attempts with their status, attempt count, response code and last error", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_read`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such hook in this tenant's scope — which is also the answer for somebody else's hook", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn detail(
    State(state): State<SharedState>,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "webhook.list", json!({ "id": id })).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetRequest {
    /// Where deliveries are POSTed. `http://` or `https://`, no whitespace or
    /// control characters. Loopback and private addresses are allowed on
    /// purpose — relaying through something local is the common case.
    #[schema(example = "https://billing.example.com/ferrum/events")]
    pub url: String,
    /// Event names from the panel's closed catalogue, or `["*"]` for all of
    /// them. An unknown name is refused rather than silently never firing.
    #[schema(example = json!(["backup.failed", "subscription.suspended"]))]
    pub events: Vec<String>,
    /// A disabled hook keeps its row and receives nothing. Absent means active.
    #[serde(default)]
    pub active: Option<bool>,
    /// Whose hook this is. Defaults to the caller's own account; an id outside
    /// the caller's tenant scope is `not_found`.
    #[serde(default)]
    pub owner_user_id: Option<i64>,
    /// Update only: mint a new signing secret and return it once. How a leaked
    /// secret is rotated.
    #[serde(default)]
    pub rotate_secret: Option<bool>,
}

/// Register a webhook and mint its signing secret.
///
/// The response carries `secret` **exactly once**. It is sealed with the panel
/// master key on the way into the database and cannot be read back — see
/// `docs/webhooks.md` for the signature scheme it belongs to.
#[utoipa::path(
    post,
    path = "/api/webhooks",
    tag = "webhooks",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = SetRequest,
    responses(
        (status = 200, description = "The created hook, its one-time `secret`, and a one-line reminder of the signature scheme", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: the `url` or `events` field is named in the error", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_manage` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such account in this tenant's scope", body = ApiErrorBody),
        (status = 409, description = "`conflict`: this account is at its hook limit", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn create(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<SetRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let input = set_input(None, &body);
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "webhook.set",
        "new",
        &input,
    )
    .await?;
    let data = ops::invoke_now(&state, &current.auth, "webhook.set", input).await?;
    Ok(Json(data))
}

/// Replace a webhook's URL, event list and active flag.
///
/// Re-enabling a hook the panel switched off clears its failure streak, which
/// is the point of the verb: an operator who fixed their endpoint has said the
/// old failures are history.
#[utoipa::path(
    put,
    path = "/api/webhooks/{id}",
    tag = "webhooks",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Webhook id")),
    request_body = SetRequest,
    responses(
        (status = 200, description = "The updated hook. `secret` is present only when `rotate_secret` was true", body = serde_json::Value),
        (status = 400, description = "`invalid_input`: the `url` or `events` field is named in the error", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such hook in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn update(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
    Json(body): Json<SetRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let input = set_input(Some(id), &body);
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "webhook.set",
        &id.to_string(),
        &input,
    )
    .await?;
    let data = ops::invoke_now(&state, &current.auth, "webhook.set", input).await?;
    Ok(Json(data))
}

/// Delete a webhook and everything still queued for it.
#[utoipa::path(
    delete,
    path = "/api/webhooks/{id}",
    tag = "webhooks",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Webhook id")),
    responses(
        (status = 200, description = "The removed hook's id", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such hook in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn delete(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let input = json!({ "id": id });
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "webhook.delete",
        &id.to_string(),
        &input,
    )
    .await?;
    let data = ops::invoke_now(&state, &current.auth, "webhook.delete", input).await?;
    Ok(Json(data))
}

/// Send one synthetic delivery and report what the endpoint answered.
///
/// Synchronous, unlike a real delivery: an operator pressing "test" wants the
/// answer, not a task id. The response echoes the timestamp and signature that
/// were sent, so somebody writing the receiving side can diff their own
/// computation against the panel's.
#[utoipa::path(
    post,
    path = "/api/webhooks/{id}/test",
    tag = "webhooks",
    security(("session_cookie" = [], "csrf_header" = [])),
    params(("id" = i64, Path, description = "Webhook id")),
    responses(
        (status = 200, description = "`delivered`, the HTTP `status` if one was seen, the `error` if not, and the `timestamp` and `signature` that were sent. A test counts toward the hook's failure streak exactly as a real delivery does", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such hook in this tenant's scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn test(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let input = json!({ "id": id });
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "webhook.test",
        &id.to_string(),
        &input,
    )
    .await?;
    let data = ops::invoke_now(&state, &current.auth, "webhook.test", input).await?;
    Ok(Json(data))
}

/// Build the `webhook.set` input.
///
/// Split out from the handlers so the two rules this file owns are testable
/// without an agent: the id comes from the path (never from the body), and an
/// unsent `active` is *absent* rather than `null` — `SetInput::active` is a
/// plain `bool` behind `#[serde(default)]`, so a `null` would be a
/// deserialization error in the agent where an absent key means "active".
///
/// The URL and the event names are deliberately **not** validated here. A
/// second copy of those rules in the web process is a second copy that can
/// disagree with the one that matters, and the agent's refusal already names
/// the field, which is what the form needs.
fn set_input(id: Option<i64>, body: &SetRequest) -> serde_json::Value {
    let mut input = json!({ "url": body.url, "events": body.events });
    let object = input.as_object_mut().expect("just built as an object");
    match id {
        Some(id) => {
            object.insert("id".into(), json!(id));
            // Only on an update: rotation is meaningless on a create, where a
            // secret is minted unconditionally.
            if body.rotate_secret == Some(true) {
                object.insert("rotate_secret".into(), json!(true));
            }
        }
        None => {
            // Only on a create: a hook cannot be moved between accounts, and
            // dropping the field here keeps a client that round-trips a hook
            // object from tripping over that.
            if let Some(owner) = body.owner_user_id {
                object.insert("owner_user_id".into(), json!(owner));
            }
        }
    }
    if let Some(active) = body.active {
        object.insert("active".into(), json!(active));
    }
    input
}

async fn audit(
    state: &SharedState,
    current: &CurrentUser,
    headers: &HeaderMap,
    peer: &SocketAddr,
    action: &str,
    target: &str,
    detail: &serde_json::Value,
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
            detail: detail.clone(),
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

    fn request(value: serde_json::Value) -> SetRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    #[test]
    fn the_id_comes_from_the_path_and_a_body_cannot_override_it() {
        let body = request(json!({
            "url": "https://example.com/hook",
            "events": ["site.created"],
            "owner_user_id": 99,
        }));

        let update = set_input(Some(7), &body);
        assert_eq!(update["id"], json!(7));
        assert!(
            !update.as_object().unwrap().contains_key("owner_user_id"),
            "an update must not try to move the hook to another account: {update}"
        );

        let create = set_input(None, &body);
        assert!(!create.as_object().unwrap().contains_key("id"), "{create}");
        assert_eq!(create["owner_user_id"], json!(99));
    }

    #[test]
    fn an_unset_active_flag_sends_no_key_at_all() {
        let body = request(json!({ "url": "https://x.example/h", "events": ["*"] }));
        let input = set_input(None, &body);
        let object = input.as_object().expect("object");
        assert!(!object.contains_key("active"), "{input}");
        assert!(!object.contains_key("rotate_secret"), "{input}");

        let disabled = request(json!({
            "url": "https://x.example/h",
            "events": ["*"],
            "active": false,
        }));
        assert_eq!(set_input(None, &disabled)["active"], json!(false));
    }

    #[test]
    fn rotation_is_only_offered_on_an_update() {
        let body = request(json!({
            "url": "https://x.example/h",
            "events": ["*"],
            "rotate_secret": true,
        }));
        assert_eq!(set_input(Some(3), &body)["rotate_secret"], json!(true));
        assert!(
            !set_input(None, &body)
                .as_object()
                .unwrap()
                .contains_key("rotate_secret"),
            "a create mints a secret unconditionally; rotation there is meaningless"
        );
    }

    /// This file must not "helpfully" clean a hostile URL and turn an attack
    /// into a valid-looking hook. The agent is where it is refused, and it
    /// refuses by naming the field.
    #[test]
    fn a_hostile_url_reaches_the_agent_untouched() {
        let payload = "https://example.com/hook\r\nX-Evil: 1";
        let body = request(json!({ "url": payload, "events": ["nope.invented"] }));
        let input = set_input(None, &body);
        assert_eq!(input["url"], json!(payload));
        assert_eq!(input["events"], json!(["nope.invented"]));
    }
}
