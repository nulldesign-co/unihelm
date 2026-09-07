//! Mapping the panel's error taxonomy onto HTTP (spec §10.5).
//!
//! Every failure a client sees carries the same shape — a stable `UNI-xxxx` code,
//! a stable slug, and a human message — so a UI can branch on the code and a
//! script can grep for it.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use unihelm_core::{ErrorCode, UnihelmError};
use utoipa::ToSchema;

/// The JSON body of every error response.
///
/// This struct doubles as the OpenAPI model for the `UNI-xxxx` envelope
/// (spec §13): every documented error response references it, so the shape is
/// written down exactly once.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({
    "code": "UNI-1201",
    "slug": "invalid_domain",
    "message": "domain labels cannot start with a hyphen",
    "field": "domain",
    "request_id": "0f3a1c2e"
}))]
pub struct ApiErrorBody {
    /// `UNI-1402`
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
    pub inner: UnihelmError,
    pub request_id: Option<String>,
}

impl ApiError {
    pub fn new(inner: UnihelmError) -> Self {
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
        Self::new(UnihelmError::new(code, detail))
    }

    pub fn unauthorized() -> Self {
        Self::code(ErrorCode::SessionInvalid, "sign in to continue")
    }

    pub fn not_found(what: impl std::fmt::Display) -> Self {
        Self::new(UnihelmError::not_found(what))
    }
}

impl From<UnihelmError> for ApiError {
    fn from(e: UnihelmError) -> Self {
        Self::new(e)
    }
}

impl From<unihelm_db::DbError> for ApiError {
    fn from(e: unihelm_db::DbError) -> Self {
        Self::new(e.into())
    }
}

impl From<unihelm_ipc::IpcError> for ApiError {
    fn from(e: unihelm_ipc::IpcError) -> Self {
        Self::new(e.into())
    }
}

/// What a 5xx says instead of what went wrong.
///
/// Named, rather than inlined, so a test can pin it and so there is one place
/// to read the promise this message makes: the detail exists, it is in the log,
/// and the request id is how to find it.
const SERVER_ERROR_MESSAGE: &str = concat!(
    "the panel failed while handling this request. The reason was logged ",
    "rather than returned, because it can carry internal paths and command ",
    "output. Quote request id",
);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.inner.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        // 5xx means we broke something, and the detail is whatever broke it —
        // for a failed shell-out that is the command's raw stderr: internal
        // paths, package-manager output, sometimes an argument. That was logged
        // *and* copied into the JSON `message`, so it went to whoever made the
        // request. The log is the right audience for it; the response is not,
        // so this is where the two part company.
        //
        // 4xx bodies are left exactly as they are. Those messages are written
        // for the caller — they name the field, the value and the fix — and
        // they are the panel's whole style of refusal (spec §10.5).
        if status.is_server_error() {
            // Minted here when the caller had none, so the sentence below can
            // promise a correlation that actually exists: this same value is
            // what the log line carries.
            let request_id = self
                .request_id
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            tracing::error!(
                code = %self.inner.code.code(),
                detail = %self.inner.detail,
                request_id = %request_id,
                "request failed"
            );
            let body = ApiErrorBody {
                code: self.inner.code.code(),
                slug: self.inner.code.slug(),
                message: format!("{SERVER_ERROR_MESSAGE} {request_id} to the server's operator."),
                // `field` names an input the caller sent, and on a 5xx it names
                // nothing the caller can change; carrying it here only makes
                // the failure look like the caller's fault.
                field: None,
                request_id: Some(request_id),
            };
            return (status, Json(body)).into_response();
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
        assert_eq!(json["code"], "UNI-1201");
        assert_eq!(json["slug"], "invalid_domain");
        assert_eq!(json["request_id"], "req-9");
        assert!(
            json.get("field").is_none(),
            "absent fields should not appear as null"
        );
    }

    #[test]
    fn agent_transport_failures_become_service_unavailable_not_internal() {
        let e: ApiError = unihelm_ipc::IpcError::Closed.into();
        assert_eq!(e.inner.code, ErrorCode::AgentUnavailable);
        assert_eq!(status_of(e), 503);
    }

    async fn body_of(e: ApiError) -> serde_json::Value {
        let response = e.into_response();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("an error body is small and already in memory");
        serde_json::from_slice(&bytes).expect("every error body is JSON")
    }

    /// Issue 85: the 5xx path logged the detail *and* put it in the JSON
    /// `message`, so a failed shell-out sent its raw stderr — absolute paths,
    /// package-manager output, sometimes an argument — to whoever made the
    /// request. Anyone who could provoke a failure could read the inside of
    /// the box a line at a time.
    #[tokio::test]
    async fn a_5xx_body_carries_a_request_id_instead_of_the_command_output() {
        let stderr = "nginx: [emerg] open() \"/etc/nginx/sites-enabled/acme.conf\" failed \
                      (13: Permission denied); mysql -u root -phunter2";
        let body =
            body_of(ApiError::code(ErrorCode::CommandFailed, stderr).with_request_id("req-7"))
                .await;

        let message = body["message"].as_str().expect("a message is always sent");
        assert!(
            !message.contains("hunter2") && !message.contains("/etc/nginx"),
            "a 5xx must not hand the client what broke: {message}"
        );
        assert!(
            message.contains("req-7"),
            "an operator has to be able to find the logged detail: {message}"
        );
        assert_eq!(body["request_id"], "req-7");
        // The code and slug survive: a UI branches on them, and neither says
        // anything about the inside of the machine.
        assert_eq!(body["slug"], ErrorCode::CommandFailed.slug());
        assert!(
            body.get("field").is_none(),
            "a 5xx names no input the caller can fix"
        );
    }

    /// The 4xx bodies are the panel's whole style of refusal — they name the
    /// field, the value and the fix — so the 5xx boundary must not touch them.
    #[tokio::test]
    async fn a_4xx_body_still_says_exactly_what_was_wrong_and_where() {
        let e = ApiError::new(
            UnihelmError::new(
                ErrorCode::InvalidDomain,
                "domain labels cannot start with a hyphen",
            )
            .with_field("domain"),
        )
        .with_request_id("req-8");
        let body = body_of(e).await;
        assert_eq!(body["message"], "domain labels cannot start with a hyphen");
        assert_eq!(body["field"], "domain");
    }

    /// Not every 5xx reaches here with a request id attached. The message
    /// promises the detail can be found in the log, so the id it quotes has to
    /// be real — it is minted before the log line is written, not after.
    #[tokio::test]
    async fn a_5xx_without_a_request_id_is_given_one_so_the_promise_holds() {
        let body = body_of(ApiError::code(
            ErrorCode::Internal,
            "thread panicked at src/x.rs",
        ))
        .await;
        let id = body["request_id"]
            .as_str()
            .expect("a 5xx always correlates with a log line");
        assert!(!id.is_empty());
        assert!(body["message"].as_str().unwrap_or_default().contains(id));
        assert!(
            !body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("src/x.rs")
        );
    }

    #[test]
    fn database_failures_do_not_leak_sql_to_the_client() {
        let e: ApiError = unihelm_db::DbError::Corrupt {
            field: "users.role",
            detail: "SELECT * FROM users WHERE secret = 'hunter2'".into(),
        }
        .into();
        assert_eq!(e.inner.code, ErrorCode::Internal);
        assert!(!e.inner.detail.contains("hunter2"));
    }
}
