//! Mapping the panel's error taxonomy onto HTTP (spec §10.5).
//!
//! Every failure a client sees carries the same shape — a stable `FER-xxxx` code,
//! a stable slug, and a human message — so a UI can branch on the code and a
//! script can grep for it.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ferrum_core::{ErrorCode, FerrumError};
use serde::Serialize;

/// The JSON body of every error response.
#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    /// `FER-1402`
    pub code: String,
    /// `domain_already_exists`
    pub slug: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Correlates with the tracing span and the audit row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug)]
pub struct ApiError {
    pub inner: FerrumError,
    pub request_id: Option<String>,
}

impl ApiError {
    pub fn new(inner: FerrumError) -> Self {
        Self {
            inner,
            request_id: None,
        }
    }

    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    pub fn code(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self::new(FerrumError::new(code, detail))
    }

    pub fn unauthorized() -> Self {
        Self::code(ErrorCode::SessionInvalid, "sign in to continue")
    }

    pub fn not_found(what: impl std::fmt::Display) -> Self {
        Self::new(FerrumError::not_found(what))
    }
}

impl From<FerrumError> for ApiError {
    fn from(e: FerrumError) -> Self {
        Self::new(e)
    }
}

impl From<ferrum_db::DbError> for ApiError {
    fn from(e: ferrum_db::DbError) -> Self {
        Self::new(e.into())
    }
}

impl From<ferrum_ipc::IpcError> for ApiError {
    fn from(e: ferrum_ipc::IpcError) -> Self {
        Self::new(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.inner.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        // 5xx means we broke something: log it with the detail, and hand the
        // client the code without a stack of internals.
        if status.is_server_error() {
            tracing::error!(
                code = %self.inner.code.code(),
                detail = %self.inner.detail,
                request_id = ?self.request_id,
                "request failed"
            );
        }

        let body = ApiErrorBody {
            code: self.inner.code.code(),
            slug: self.inner.code.slug(),
            message: self.inner.detail,
            field: self.inner.field,
            request_id: self.request_id,
        };

        (status, Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn status_of(e: ApiError) -> u16 {
        e.into_response().status().as_u16()
    }

    #[test]
    fn errors_map_to_their_declared_status() {
        assert_eq!(status_of(ApiError::unauthorized()), 401);
        assert_eq!(
            status_of(ApiError::code(ErrorCode::PermissionDenied, "no")),
            403
        );
        assert_eq!(status_of(ApiError::not_found("site")), 404);
        assert_eq!(
            status_of(ApiError::code(ErrorCode::DomainAlreadyExists, "taken")),
            409
        );
        assert_eq!(
            status_of(ApiError::code(ErrorCode::AgentUnavailable, "down")),
            503
        );
        assert_eq!(
            status_of(ApiError::code(ErrorCode::RateLimited, "slow down")),
            429
        );
    }

    #[test]
    fn the_body_carries_the_stable_code_and_slug() {
        let e = ApiError::code(ErrorCode::InvalidDomain, "bad domain").with_request_id("req-9");
        let body = ApiErrorBody {
            code: e.inner.code.code(),
            slug: e.inner.code.slug(),
            message: e.inner.detail.clone(),
            field: None,
            request_id: e.request_id.clone(),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["code"], "FER-1201");
        assert_eq!(json["slug"], "invalid_domain");
        assert_eq!(json["request_id"], "req-9");
        assert!(
            json.get("field").is_none(),
            "absent fields should not appear as null"
        );
    }

    #[test]
    fn agent_transport_failures_become_service_unavailable_not_internal() {
        let e: ApiError = ferrum_ipc::IpcError::Closed.into();
        assert_eq!(e.inner.code, ErrorCode::AgentUnavailable);
        assert_eq!(status_of(e), 503);
    }

    #[test]
    fn database_failures_do_not_leak_sql_to_the_client() {
        let e: ApiError = ferrum_db::DbError::Corrupt {
            field: "users.role",
            detail: "SELECT * FROM users WHERE secret = 'hunter2'".into(),
        }
        .into();
        assert_eq!(e.inner.code, ErrorCode::Internal);
        assert!(!e.inner.detail.contains("hunter2"));
    }
}
