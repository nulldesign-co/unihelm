//! The quota API (spec §6.2, §6.3).
//!
//! Only the backend report is routed for now: the spec's installer promise is
//! "detects & reports which level you got", and an operator checking whether
//! their tenants are actually isolated needs this before anything else.
//! Setting limits and reading per-subscription usage ship with the plans UI
//! (they are already live as `quota.set` / `quota.usage` operations).

use axum::Json;
use axum::extract::State;
use ferrum_core::Permission;
use serde_json::json;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

/// Which rung of the quota enforcement ladder this server landed on:
/// XFS project quotas, ext4 user quotas, or the unenforced du fallback.
pub async fn backend(
    State(state): State<SharedState>,
    current: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    current
        .auth
        .require(Permission::ServerRead)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(&state, &current.auth, "quota.backend", json!({})).await?;
    Ok(Json(data))
}
