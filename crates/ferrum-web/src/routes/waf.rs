//! The WAF API and the security posture report (spec §11.9, §13).
//!
//! A thin bridge onto `waf.*` and `security.posture` in `ferrum_ops`. The agent
//! re-derives the permission from the database and re-validates every field
//! (spec §5.2 rule 4), so nothing here is load-bearing for security on its own.
//! Three decisions do live in this file:
//!
//! 1. **Enable and disable are separate endpoints, not one `PUT` with a flag.**
//!    They have different bodies (enable carries a mode and a paranoia level;
//!    disable carries nothing but a scope) and — more importantly — different
//!    consequences. A single toggle whose meaning depends on a boolean in the
//!    body is the shape that makes a mis-sent request switch off a WAF that was
//!    meant to be reconfigured.
//!
//! 2. **The exclusion list is a `PUT`, because it is a whole list.** The
//!    operation replaces the list wholesale, so the verb that says "this is now
//!    the state" is the honest one; a `POST` implying "add one" would describe
//!    an operation that does not exist.
//!
//! 3. **The posture report is a `GET` under `/api/server/`, not `/api/waf/`.**
//!    It is a property of the server, most of it has nothing to do with the
//!    WAF, and putting it behind the WAF's prefix would hide it on every server
//!    where the WAF cannot run — which, today, is all of them.
//!
//! Every mutation writes an audit row *before* the operation runs, so an
//! attempt that the agent then refuses is still recorded (spec §12 rule 10).

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
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

/// What a WAF would need on this server, and what is configured.
///
/// On a stock Ferrum install this answers `available: false` with a populated
/// `blockers` array explaining why — nginx comes from nginx.org, which ships no
/// ModSecurity module. That is the honest answer and it is the *point* of this
/// endpoint: the UI renders the blockers rather than a switch that would fail.
#[utoipa::path(
    get,
    path = "/api/waf",
    tag = "waf",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Module and Core Rule Set state, the blockers that stop the WAF from being enabled here, the per-site policies and the exclusion list", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_manage`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn status(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "waf.status", json!({})).await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EnableRequest {
    /// Enable for one site. Absent means "switch the WAF on for this server",
    /// which is the prerequisite for any per-site policy.
    #[serde(default)]
    pub site_id: Option<i64>,
    /// `detect` (rules run and log, nothing is blocked) or `block`. `off` is
    /// refused here — that is what the disable endpoint is for.
    #[serde(default)]
    #[schema(value_type = Option<String>, example = "detect")]
    pub mode: Option<String>,
    /// OWASP CRS paranoia level, 1–4. Higher levels catch more and reject more
    /// legitimate traffic; 1 is the only level safe on an application nobody
    /// has tuned the rules against.
    #[serde(default)]
    pub paranoia_level: Option<i64>,
}

/// Switch the WAF on, server-wide or for one site.
///
/// Long enough to be a task: a first server-wide enable downloads and verifies
/// the Core Rule Set before it renders anything.
#[utoipa::path(
    post,
    path = "/api/waf/enable",
    tag = "waf",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = EnableRequest,
    responses(
        (status = 202, description = "Accepted; watch the task for the download, the render and the nginx reload", body = crate::routes::ops::TaskAccepted),
        (status = 400, description = "`invalid_input`: `mode` or `paranoia_level` is named in the error", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site", body = ApiErrorBody),
        (status = 409, description = "`conflict`: this server has no loadable ModSecurity module, or a per-site policy was asked for before the WAF was enabled server-wide. The message names exactly what is missing.", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn enable(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<EnableRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let input = enable_input(&body);
    let target = scope_of(body.site_id);
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "waf.enable",
        &target,
        &input,
    )
    .await?;
    ops::invoke(&state, &current.auth, "waf.enable", input).await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DisableRequest {
    /// Disable for one site. Absent switches the WAF off for the whole server,
    /// which removes the nginx include entirely.
    #[serde(default)]
    pub site_id: Option<i64>,
}

/// Switch the WAF off, server-wide or for one site.
#[utoipa::path(
    post,
    path = "/api/waf/disable",
    tag = "waf",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = DisableRequest,
    responses(
        (status = 202, description = "Accepted; watch the task for the render and the nginx reload", body = crate::routes::ops::TaskAccepted),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: no such site", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn disable(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<DisableRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let input = match body.site_id {
        Some(id) => json!({ "site_id": id }),
        None => json!({}),
    };
    let target = scope_of(body.site_id);
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "waf.disable",
        &target,
        &input,
    )
    .await?;
    ops::invoke(&state, &current.auth, "waf.disable", input).await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExclusionRequest {
    /// The site this exclusion applies to. Absent means server-wide.
    #[serde(default)]
    pub site_id: Option<i64>,
    /// The CRS rule id to stop running, e.g. `942100`.
    #[schema(example = 942100)]
    pub rule_id: i64,
    /// Why. Required, and rendered as a comment in the generated rules file: an
    /// unexplained hole in a WAF outlives whoever opened it.
    #[schema(example = "the page editor legitimately posts SQL")]
    pub reason: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RulesRequest {
    /// The complete list. Sending `[]` clears every exclusion.
    pub exclusions: Vec<ExclusionRequest>,
}

/// Replace the rule exclusion list.
///
/// `PUT` because the operation replaces the whole list; there is no "add one"
/// verb to describe.
#[utoipa::path(
    put,
    path = "/api/waf/rules",
    tag = "waf",
    security(("session_cookie" = [], "csrf_header" = [])),
    request_body = RulesRequest,
    responses(
        (status = 202, description = "Accepted; watch the task for the render and the nginx reload. The result reports `applied: false` when the WAF is off, meaning the list was stored but is not in effect.", body = crate::routes::ops::TaskAccepted),
        (status = 400, description = "`invalid_input`: a `rule_id` or an empty/multi-line `reason` is named in the error", body = ApiErrorBody),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied` / `csrf_invalid`", body = ApiErrorBody),
        (status = 404, description = "`not_found`: an exclusion names a site that does not exist", body = ApiErrorBody),
        (status = 409, description = "`conflict`: the same rule was excluded twice in the same scope", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn rules_set(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<RulesRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::ServerManage)
        .map_err(ApiError::from)?;

    let input = rules_input(&body);
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "waf.rules.set",
        "server",
        &input,
    )
    .await?;
    ops::invoke(&state, &current.auth, "waf.rules.set", input).await
}

/// The security advisor's checklist scan.
///
/// `ServerRead`, not `ServerManage`: telling somebody their server accepts
/// password logins is how they come to fix it, and gating that behind the
/// permission to change the server would keep the report from the person most
/// likely to act on it.
#[utoipa::path(
    get,
    path = "/api/server/security-posture",
    tag = "server",
    security(("session_cookie" = [])),
    responses(
        (status = 200, description = "Findings ordered most severe first, each with a severity, a plain-language risk and a remedy — plus the evidence they were derived from. A check whose evidence could not be gathered appears as a `unknown` finding, never as a clean result.", body = serde_json::Value),
        (status = 401, description = "`session_invalid`", body = ApiErrorBody),
        (status = 403, description = "`permission_denied`: needs `server_read`", body = ApiErrorBody),
        (status = 503, description = "`agent_unavailable`", body = ApiErrorBody),
    ),
)]
pub async fn security_posture(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "security.posture", json!({})).await?;
    Ok(Json(data))
}

/// Build the `waf.enable` input.
///
/// Split out so the rule this file owns is testable without an agent: an
/// unsent field is **absent**, never `null`. `EnableInput`'s fields are
/// `Option`s behind `#[serde(default)]`, and while a `null` would happen to
/// deserialize the same today, sending one asks the agent to distinguish
/// "unset" from "explicitly nothing" — a distinction this API does not have and
/// should not start having by accident.
fn enable_input(body: &EnableRequest) -> serde_json::Value {
    let mut input = json!({});
    let object = input.as_object_mut().expect("just built as an object");
    if let Some(site_id) = body.site_id {
        object.insert("site_id".into(), json!(site_id));
    }
    // The mode string is passed through untouched for the agent to parse. A
    // second copy of the mode vocabulary here is a second copy that can
    // disagree with the one that matters, and the agent's refusal already
    // names the field.
    if let Some(mode) = &body.mode {
        object.insert("mode".into(), json!(mode));
    }
    if let Some(level) = body.paranoia_level {
        object.insert("paranoia_level".into(), json!(level));
    }
    input
}

/// Build the `waf.rules.set` input, dropping absent `site_id`s rather than
/// sending `null`s.
fn rules_input(body: &RulesRequest) -> serde_json::Value {
    let exclusions: Vec<serde_json::Value> = body
        .exclusions
        .iter()
        .map(|e| {
            let mut entry = json!({ "rule_id": e.rule_id, "reason": e.reason });
            if let Some(site_id) = e.site_id {
                entry
                    .as_object_mut()
                    .expect("just built as an object")
                    .insert("site_id".into(), json!(site_id));
            }
            entry
        })
        .collect();
    json!({ "exclusions": exclusions })
}

/// What an audit row calls the thing that was changed.
fn scope_of(site_id: Option<i64>) -> String {
    match site_id {
        Some(id) => format!("site:{id}"),
        None => "server".to_string(),
    }
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
            // Nothing here is a secret: a rule id, a mode, a paranoia level and
            // a reason an operator typed. "Which rules did they switch off" is
            // exactly the question this log exists to answer.
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

    fn enable_request(value: serde_json::Value) -> EnableRequest {
        serde_json::from_value(value).expect("the request shape parses")
    }

    #[test]
    fn an_unset_field_is_absent_from_the_operation_input_not_null() {
        let input = enable_input(&enable_request(json!({})));
        let object = input.as_object().expect("object");
        assert!(object.is_empty(), "{input}");

        let full = enable_input(&enable_request(json!({
            "site_id": 4,
            "mode": "block",
            "paranoia_level": 2,
        })));
        assert_eq!(full["site_id"], json!(4));
        assert_eq!(full["mode"], json!("block"));
        assert_eq!(full["paranoia_level"], json!(2));
    }

    #[test]
    fn a_mode_the_web_layer_does_not_recognise_is_passed_through_for_the_agent_to_refuse() {
        // This file must not own a second copy of the mode vocabulary: it would
        // drift from the agent's, and the agent's is the one that decides.
        let input = enable_input(&enable_request(json!({ "mode": "paranoid" })));
        assert_eq!(input["mode"], json!("paranoid"));
    }

    #[test]
    fn an_exclusion_without_a_site_is_sent_as_server_wide_not_as_a_null_site() {
        let body: RulesRequest = serde_json::from_value(json!({
            "exclusions": [
                { "rule_id": 942100, "reason": "the editor posts SQL" },
                { "site_id": 3, "rule_id": 920420, "reason": "the API takes text/plain" },
            ]
        }))
        .unwrap();
        let input = rules_input(&body);
        let list = input["exclusions"].as_array().unwrap();
        assert!(
            !list[0].as_object().unwrap().contains_key("site_id"),
            "{input}"
        );
        assert_eq!(list[1]["site_id"], json!(3));
    }

    #[test]
    fn an_empty_exclusion_list_is_sent_as_an_empty_list_and_clears_the_rules() {
        let body: RulesRequest = serde_json::from_value(json!({ "exclusions": [] })).unwrap();
        let input = rules_input(&body);
        assert_eq!(input["exclusions"], json!([]));
    }

    #[test]
    fn a_hostile_reason_reaches_the_agent_byte_for_byte() {
        // The agent refuses line breaks in a reason, because the reason is
        // rendered as a `#` comment in the ModSecurity rules file and a newline
        // would end the comment. This layer must not "helpfully" strip it and
        // turn an attack into a valid-looking exclusion.
        let payload = "harmless\nSecRuleEngine Off";
        let body: RulesRequest = serde_json::from_value(json!({
            "exclusions": [{ "rule_id": 1, "reason": payload }]
        }))
        .unwrap();
        let input = rules_input(&body);
        assert_eq!(input["exclusions"][0]["reason"], json!(payload));
    }

    #[test]
    fn the_audit_target_distinguishes_a_server_change_from_a_site_change() {
        assert_eq!(scope_of(None), "server");
        assert_eq!(scope_of(Some(12)), "site:12");
    }
}
