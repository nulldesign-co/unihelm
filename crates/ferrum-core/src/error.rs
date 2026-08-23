//! Stable error taxonomy (spec §10.5).
//!
//! Every error that can cross the API boundary has a **stable machine code**
//! (`FER-1201`) and a **stable slug** (`domain_already_exists`). Clients and the
//! docs page key off those; the human message is free to change with translations.
//!
//! Code ranges — keep new codes inside their block so the docs table stays readable:
//!
//! | Range | Area |
//! |-------|------|
//! | 1000–1099 | generic / internal |
//! | 1100–1199 | authentication & sessions |
//! | 1200–1299 | input validation |
//! | 1300–1399 | authorization / RBAC / quota |
//! | 1400–1499 | resource state (not found, conflict) |
//! | 1500–1599 | IPC & agent transport |
//! | 1600–1699 | system, packages, services |
//! | 1700–1799 | task engine |
//! | 1800–1899 | config management |

use std::fmt;

use serde::{Deserialize, Serialize};

pub type Result<T, E = FerrumError> = std::result::Result<T, E>;

/// The complete set of machine-readable error codes.
///
/// Adding a variant is an API change: add it to the table in `docs/api/errors.md`
/// in the same commit (working agreement §16.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    // ---- 1000–1099 generic ------------------------------------------------
    Internal,
    NotImplemented,
    ServiceUnavailable,
    RateLimited,

    // ---- 1100–1199 auth ---------------------------------------------------
    InvalidCredentials,
    SessionExpired,
    SessionInvalid,
    TotpRequired,
    TotpInvalid,
    AccountSuspended,
    AccountLocked,
    CsrfInvalid,

    // ---- 1200–1299 validation --------------------------------------------
    InvalidInput,
    InvalidDomain,
    InvalidDbName,
    InvalidUsername,
    InvalidPath,
    InvalidPhpVersion,
    InvalidPort,
    PasswordTooWeak,

    // ---- 1300–1399 authorization -----------------------------------------
    PermissionDenied,
    TenantScopeViolation,
    QuotaExceeded,
    PlanFeatureDisabled,
    ResellerAllocationExceeded,

    // ---- 1400–1499 resource state ----------------------------------------
    NotFound,
    AlreadyExists,
    DomainAlreadyExists,
    Conflict,
    DependentsExist,

    // ---- 1500–1599 IPC ----------------------------------------------------
    AgentUnavailable,
    AgentProtocol,
    AgentTimeout,
    PeerCredentialRejected,
    UnknownOperation,

    // ---- 1600–1699 system -------------------------------------------------
    UnsupportedDistro,
    PackageBackendFailed,
    ServiceActionFailed,
    CommandFailed,

    // ---- 1700–1799 tasks --------------------------------------------------
    TaskNotFound,
    TaskNotCancellable,
    TaskFailed,

    // ---- 1800–1899 config -------------------------------------------------
    ConfigDrift,
    ConfigValidationFailed,
    ConfigRollback,
}

impl ErrorCode {
    /// The stable numeric code, e.g. `1201`.
    pub const fn number(self) -> u16 {
        use ErrorCode::*;
        match self {
            Internal => 1000,
            NotImplemented => 1001,
            ServiceUnavailable => 1002,
            RateLimited => 1003,

            InvalidCredentials => 1100,
            SessionExpired => 1101,
            SessionInvalid => 1102,
            TotpRequired => 1103,
            TotpInvalid => 1104,
            AccountSuspended => 1105,
            AccountLocked => 1106,
            CsrfInvalid => 1107,

            InvalidInput => 1200,
            InvalidDomain => 1201,
            InvalidDbName => 1202,
            InvalidUsername => 1203,
            InvalidPath => 1204,
            InvalidPhpVersion => 1205,
            InvalidPort => 1206,
            PasswordTooWeak => 1207,

            PermissionDenied => 1300,
            TenantScopeViolation => 1301,
            QuotaExceeded => 1302,
            PlanFeatureDisabled => 1303,
            ResellerAllocationExceeded => 1304,

            NotFound => 1400,
            AlreadyExists => 1401,
            DomainAlreadyExists => 1402,
            Conflict => 1403,
            DependentsExist => 1404,

            AgentUnavailable => 1500,
            AgentProtocol => 1501,
            AgentTimeout => 1502,
            PeerCredentialRejected => 1503,
            UnknownOperation => 1504,

            UnsupportedDistro => 1600,
            PackageBackendFailed => 1601,
            ServiceActionFailed => 1602,
            CommandFailed => 1603,

            TaskNotFound => 1700,
            TaskNotCancellable => 1701,
            TaskFailed => 1702,

            ConfigDrift => 1800,
            ConfigValidationFailed => 1801,
            ConfigRollback => 1802,
        }
    }

    /// The wire form clients match on, e.g. `"FER-1201"`.
    pub fn code(self) -> String {
        format!("FER-{}", self.number())
    }

    /// The stable slug, e.g. `"domain_already_exists"`.
    pub const fn slug(self) -> &'static str {
        use ErrorCode::*;
        match self {
            Internal => "internal",
            NotImplemented => "not_implemented",
            ServiceUnavailable => "service_unavailable",
            RateLimited => "rate_limited",

            InvalidCredentials => "invalid_credentials",
            SessionExpired => "session_expired",
            SessionInvalid => "session_invalid",
            TotpRequired => "totp_required",
            TotpInvalid => "totp_invalid",
            AccountSuspended => "account_suspended",
            AccountLocked => "account_locked",
            CsrfInvalid => "csrf_invalid",

            InvalidInput => "invalid_input",
            InvalidDomain => "invalid_domain",
            InvalidDbName => "invalid_db_name",
            InvalidUsername => "invalid_username",
            InvalidPath => "invalid_path",
            InvalidPhpVersion => "invalid_php_version",
            InvalidPort => "invalid_port",
            PasswordTooWeak => "password_too_weak",

            PermissionDenied => "permission_denied",
            TenantScopeViolation => "tenant_scope_violation",
            QuotaExceeded => "quota_exceeded",
            PlanFeatureDisabled => "plan_feature_disabled",
            ResellerAllocationExceeded => "reseller_allocation_exceeded",

            NotFound => "not_found",
            AlreadyExists => "already_exists",
            DomainAlreadyExists => "domain_already_exists",
            Conflict => "conflict",
            DependentsExist => "dependents_exist",

            AgentUnavailable => "agent_unavailable",
            AgentProtocol => "agent_protocol",
            AgentTimeout => "agent_timeout",
            PeerCredentialRejected => "peer_credential_rejected",
            UnknownOperation => "unknown_operation",

            UnsupportedDistro => "unsupported_distro",
            PackageBackendFailed => "package_backend_failed",
            ServiceActionFailed => "service_action_failed",
            CommandFailed => "command_failed",

            TaskNotFound => "task_not_found",
            TaskNotCancellable => "task_not_cancellable",
            TaskFailed => "task_failed",

            ConfigDrift => "config_drift",
            ConfigValidationFailed => "config_validation_failed",
            ConfigRollback => "config_rollback",
        }
    }

    /// HTTP status the web layer maps this code to.
    pub const fn http_status(self) -> u16 {
        use ErrorCode::*;
        match self {
            Internal | CommandFailed | PackageBackendFailed | ServiceActionFailed
            | ConfigRollback | TaskFailed => 500,
            NotImplemented => 501,
            ServiceUnavailable | AgentUnavailable => 503,
            AgentTimeout => 504,
            RateLimited => 429,

            InvalidCredentials | SessionExpired | SessionInvalid | TotpRequired | TotpInvalid => {
                401
            }

            AccountSuspended
            | AccountLocked
            | CsrfInvalid
            | PermissionDenied
            | TenantScopeViolation
            | PlanFeatureDisabled
            | PeerCredentialRejected => 403,

            QuotaExceeded | ResellerAllocationExceeded => 402,

            NotFound | TaskNotFound | UnknownOperation => 404,

            AlreadyExists | DomainAlreadyExists | Conflict | DependentsExist | ConfigDrift
            | TaskNotCancellable => 409,

            InvalidInput
            | InvalidDomain
            | InvalidDbName
            | InvalidUsername
            | InvalidPath
            | InvalidPhpVersion
            | InvalidPort
            | PasswordTooWeak
            | AgentProtocol
            | UnsupportedDistro
            | ConfigValidationFailed => 400,
        }
    }

    /// Every code, for the generated docs table and the taxonomy tests.
    pub const ALL: &'static [ErrorCode] = {
        use ErrorCode::*;
        &[
            Internal,
            NotImplemented,
            ServiceUnavailable,
            RateLimited,
            InvalidCredentials,
            SessionExpired,
            SessionInvalid,
            TotpRequired,
            TotpInvalid,
            AccountSuspended,
            AccountLocked,
            CsrfInvalid,
            InvalidInput,
            InvalidDomain,
            InvalidDbName,
            InvalidUsername,
            InvalidPath,
            InvalidPhpVersion,
            InvalidPort,
            PasswordTooWeak,
            PermissionDenied,
            TenantScopeViolation,
            QuotaExceeded,
            PlanFeatureDisabled,
            ResellerAllocationExceeded,
            NotFound,
            AlreadyExists,
            DomainAlreadyExists,
            Conflict,
            DependentsExist,
            AgentUnavailable,
            AgentProtocol,
            AgentTimeout,
            PeerCredentialRejected,
            UnknownOperation,
            UnsupportedDistro,
            PackageBackendFailed,
            ServiceActionFailed,
            CommandFailed,
            TaskNotFound,
            TaskNotCancellable,
            TaskFailed,
            ConfigDrift,
            ConfigValidationFailed,
            ConfigRollback,
        ]
    };
}

/// Render the full code table as Markdown.
///
/// `docs/api/errors.md` is this string, and a test asserts they match — so the
/// published list of error codes is generated, never hand-maintained.
pub fn docs_table() -> String {
    let mut out = String::new();
    out.push_str("# Error codes\n\n");
    out.push_str(concat!(
        "Every error the API returns carries a stable code and slug. Clients should ",
        "branch on the **slug**; the message is free to change with translations.\n\n",
        "This file is generated from `ferrum_core::error::ErrorCode`. ",
        "Regenerate it with:\n\n",
        "```\n",
        "cargo run -p ferrum-core --bin gen-error-docs > docs/api/errors.md\n",
        "```\n\n",
    ));
    out.push_str("| Code | Slug | HTTP | Area |\n");
    out.push_str("|------|------|------|------|\n");

    let mut codes = ErrorCode::ALL.to_vec();
    codes.sort_by_key(|c| c.number());
    for code in codes {
        out.push_str(&format!(
            "| `{}` | `{}` | {} | {} |\n",
            code.code(),
            code.slug(),
            code.http_status(),
            area_of(code.number()),
        ));
    }
    out
}

const fn area_of(number: u16) -> &'static str {
    match number {
        1000..=1099 => "generic",
        1100..=1199 => "authentication",
        1200..=1299 => "validation",
        1300..=1399 => "authorization",
        1400..=1499 => "resource state",
        1500..=1599 => "agent IPC",
        1600..=1699 => "system",
        1700..=1799 => "tasks",
        1800..=1899 => "config management",
        _ => "unassigned",
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FER-{} {}", self.number(), self.slug())
    }
}

/// The panel's error type.
///
/// `detail` is safe to show a user. Anything sensitive (paths outside the tenant,
/// credentials, raw command lines) belongs in the tracing span, never here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FerrumError {
    pub code: ErrorCode,
    pub detail: String,
    /// Optional field path for validation errors, e.g. `"input.domain"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl FerrumError {
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            field: None,
        }
    }

    /// Attach the input field this error refers to, so the UI can highlight it.
    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, detail)
    }

    pub fn not_found(what: impl fmt::Display) -> Self {
        Self::new(ErrorCode::NotFound, format!("{what} not found"))
    }

    pub fn denied(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::PermissionDenied, detail)
    }

    pub fn invalid(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, detail)
    }

    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }
}

impl fmt::Display for FerrumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code.code(), self.detail)
    }
}

impl std::error::Error for FerrumError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn codes_and_slugs_are_unique() {
        let mut numbers = HashSet::new();
        let mut slugs = HashSet::new();
        for &c in ErrorCode::ALL {
            assert!(numbers.insert(c.number()), "duplicate number for {c:?}");
            assert!(slugs.insert(c.slug()), "duplicate slug for {c:?}");
        }
    }

    #[test]
    fn all_list_is_exhaustive() {
        // A new variant that is not added to ALL breaks the docs table and the
        // taxonomy tests, so guard the count explicitly.
        assert_eq!(ErrorCode::ALL.len(), 45);
    }

    #[test]
    fn http_status_is_sane() {
        for &c in ErrorCode::ALL {
            let s = c.http_status();
            assert!((400..=504).contains(&s), "{c:?} maps to odd status {s}");
        }
    }

    #[test]
    fn the_generated_docs_page_is_committed_and_current() {
        // If this fails, run:
        //   cargo run -p ferrum-core --bin gen-error-docs > docs/api/errors.md
        let committed = include_str!("../../../docs/api/errors.md");
        assert_eq!(
            docs_table(),
            committed,
            "docs/api/errors.md is out of date with the error taxonomy"
        );
    }

    #[test]
    fn every_code_lands_in_a_named_area() {
        for &c in ErrorCode::ALL {
            assert_ne!(
                area_of(c.number()),
                "unassigned",
                "{c:?} is outside every documented range"
            );
        }
    }

    #[test]
    fn wire_format_is_stable() {
        assert_eq!(ErrorCode::DomainAlreadyExists.code(), "FER-1402");
        assert_eq!(
            ErrorCode::DomainAlreadyExists.slug(),
            "domain_already_exists"
        );
    }
}
