//! Row types and their validated domain forms.
//!
//! Rows come out of SQLite as strings and integers; the `TryFrom` impls below are
//! where they become typed values again. A row that fails validation is reported
//! as [`crate::DbError::Corrupt`] rather than silently coerced — if a `role`
//! column somehow holds `superadmin`, we want to know, not to guess.

use serde::{Deserialize, Serialize};
use unihelm_core::{Email, Permission, Role, SubscriptionId, TaskId, UserId, Username};

use crate::{DbError, Result, from_sql_time};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Suspended,
    Locked,
}

impl UserStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            UserStatus::Active => "active",
            UserStatus::Suspended => "suspended",
            UserStatus::Locked => "locked",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "active" => UserStatus::Active,
            "suspended" => UserStatus::Suspended,
            "locked" => UserStatus::Locked,
            other => {
                return Err(DbError::Corrupt {
                    field: "users.status",
                    detail: format!("unknown status `{other}`"),
                });
            }
        })
    }

    /// Only an active account may hold a session.
    pub const fn can_log_in(self) -> bool {
        matches!(self, UserStatus::Active)
    }
}

/// A panel account.
///
/// Deliberately **not** `Serialize`: `pass_hash` and `totp_secret` live on this
/// struct, and the way to keep them out of an API response is to make it
/// impossible to serialise the whole thing (spec §12 rule 6).
#[derive(Debug, Clone)]
pub struct User {
    pub id: UserId,
    pub role: Role,
    pub email: Email,
    pub username: Username,
    pub pass_hash: String,
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub status: UserStatus,
    pub reseller_id: Option<UserId>,
    /// Per-account permission overrides; `None` means "role defaults".
    pub permissions: Option<Vec<Permission>>,
    pub full_name: Option<String>,
    pub locale: String,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
    pub last_login_at: Option<time::OffsetDateTime>,
}

/// The raw `users` row, exactly as SQLite stores it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: i64,
    pub role: String,
    pub email: String,
    pub username: String,
    pub pass_hash: String,
    pub totp_secret: Option<String>,
    pub totp_enabled: i64,
    pub status: String,
    pub reseller_id: Option<i64>,
    pub permissions_json: String,
    pub full_name: Option<String>,
    pub locale: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_login_at: Option<String>,
}

impl TryFrom<UserRow> for User {
    type Error = DbError;

    fn try_from(r: UserRow) -> Result<Self> {
        let permissions: Option<Vec<Permission>> = serde_json::from_str(&r.permissions_json)
            .map_err(|e| DbError::Corrupt {
                field: "users.permissions_json",
                detail: e.to_string(),
            })?;

        Ok(User {
            id: UserId(r.id),
            role: Role::parse(&r.role).map_err(|e| DbError::Corrupt {
                field: "users.role",
                detail: e.detail,
            })?,
            email: Email::parse(&r.email).map_err(|e| DbError::Corrupt {
                field: "users.email",
                detail: e.detail,
            })?,
            username: Username::parse(&r.username).map_err(|e| DbError::Corrupt {
                field: "users.username",
                detail: e.detail,
            })?,
            pass_hash: r.pass_hash,
            totp_secret: r.totp_secret,
            totp_enabled: r.totp_enabled != 0,
            status: UserStatus::parse(&r.status)?,
            reseller_id: r.reseller_id.map(UserId),
            permissions,
            full_name: r.full_name,
            locale: r.locale,
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
            last_login_at: r.last_login_at.as_deref().map(from_sql_time).transpose()?,
        })
    }
}

impl User {
    /// The effective permission set: role defaults, narrowed by any per-account
    /// override. An override can only take away (spec §6.1).
    pub fn effective_permissions(&self) -> Vec<Permission> {
        match &self.permissions {
            None => self.role.default_permissions().to_vec(),
            Some(overrides) => self
                .role
                .default_permissions()
                .iter()
                .copied()
                .filter(|p| overrides.contains(p))
                .collect(),
        }
    }
}

/// A live browser session.
#[derive(Debug, Clone)]
pub struct Session {
    /// SHA-256 of the cookie value — never the value itself.
    pub id: String,
    pub user_id: UserId,
    pub csrf: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub impersonator_id: Option<UserId>,
    pub created_at: time::OffsetDateTime,
    pub last_seen_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub revoked: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionRow {
    pub id: String,
    pub user_id: i64,
    pub csrf: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub impersonator_id: Option<i64>,
    pub created_at: String,
    pub last_seen_at: String,
    pub expires_at: String,
    pub revoked: i64,
}

impl TryFrom<SessionRow> for Session {
    type Error = DbError;

    fn try_from(r: SessionRow) -> Result<Self> {
        Ok(Session {
            id: r.id,
            user_id: UserId(r.user_id),
            csrf: r.csrf,
            ip: r.ip,
            user_agent: r.user_agent,
            impersonator_id: r.impersonator_id.map(UserId),
            created_at: from_sql_time(&r.created_at)?,
            last_seen_at: from_sql_time(&r.last_seen_at)?,
            expires_at: from_sql_time(&r.expires_at)?,
            revoked: r.revoked != 0,
        })
    }
}

impl Session {
    pub fn is_valid_at(&self, now: time::OffsetDateTime) -> bool {
        !self.revoked && self.expires_at > now
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Running,
    Ok,
    Failed,
    Cancelled,
}

impl TaskStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            TaskStatus::Queued => "queued",
            TaskStatus::Running => "running",
            TaskStatus::Ok => "ok",
            TaskStatus::Failed => "failed",
            TaskStatus::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "queued" => TaskStatus::Queued,
            "running" => TaskStatus::Running,
            "ok" => TaskStatus::Ok,
            "failed" => TaskStatus::Failed,
            "cancelled" => TaskStatus::Cancelled,
            other => {
                return Err(DbError::Corrupt {
                    field: "tasks.status",
                    detail: format!("unknown status `{other}`"),
                });
            }
        })
    }

    /// No further transitions are possible from here.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskStatus::Ok | TaskStatus::Failed | TaskStatus::Cancelled
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Task {
    pub id: TaskId,
    pub op: String,
    pub input: serde_json::Value,
    pub actor_user_id: Option<UserId>,
    pub subscription_id: Option<SubscriptionId>,
    pub status: TaskStatus,
    pub progress: u8,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
    pub cancellable: bool,
    pub idempotent: bool,
    pub request_id: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub started_at: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub finished_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TaskRow {
    pub id: String,
    pub op: String,
    pub input_json: String,
    pub actor_user_id: Option<i64>,
    pub subscription_id: Option<i64>,
    pub status: String,
    pub progress: i64,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
    pub cancellable: i64,
    pub idempotent: i64,
    pub request_id: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

impl TryFrom<TaskRow> for Task {
    type Error = DbError;

    fn try_from(r: TaskRow) -> Result<Self> {
        Ok(Task {
            id: r.id.parse().map_err(|e| DbError::Corrupt {
                field: "tasks.id",
                detail: format!("{e}"),
            })?,
            op: r.op,
            input: serde_json::from_str(&r.input_json).map_err(|e| DbError::Corrupt {
                field: "tasks.input_json",
                detail: e.to_string(),
            })?,
            actor_user_id: r.actor_user_id.map(UserId),
            subscription_id: r.subscription_id.map(SubscriptionId),
            status: TaskStatus::parse(&r.status)?,
            progress: r.progress.clamp(0, 100) as u8,
            error_code: r.error_code,
            error_detail: r.error_detail,
            cancellable: r.cancellable != 0,
            idempotent: r.idempotent != 0,
            request_id: r.request_id,
            created_at: from_sql_time(&r.created_at)?,
            started_at: r.started_at.as_deref().map(from_sql_time).transpose()?,
            finished_at: r.finished_at.as_deref().map(from_sql_time).transpose()?,
        })
    }
}

/// One line of task output.
#[derive(Debug, Clone, Serialize)]
pub struct TaskLogLine {
    pub seq: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub at: time::OffsetDateTime,
    pub line: String,
}

/// An entry in the audit trail (spec §10.3).
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub at: time::OffsetDateTime,
    pub actor_user_id: Option<UserId>,
    pub actor_username: String,
    pub impersonator_id: Option<UserId>,
    pub ip: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub detail: serde_json::Value,
    pub request_id: Option<String>,
    pub subscription_id: Option<SubscriptionId>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub at: String,
    pub actor_user_id: Option<i64>,
    pub actor_username: String,
    pub impersonator_id: Option<i64>,
    pub ip: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub detail_json: String,
    pub request_id: Option<String>,
    pub subscription_id: Option<i64>,
}

impl TryFrom<AuditRow> for AuditEntry {
    type Error = DbError;

    fn try_from(r: AuditRow) -> Result<Self> {
        Ok(AuditEntry {
            id: r.id,
            at: from_sql_time(&r.at)?,
            actor_user_id: r.actor_user_id.map(UserId),
            actor_username: r.actor_username,
            impersonator_id: r.impersonator_id.map(UserId),
            ip: r.ip,
            action: r.action,
            target: r.target,
            detail: serde_json::from_str(&r.detail_json).unwrap_or(serde_json::Value::Null),
            request_id: r.request_id,
            subscription_id: r.subscription_id.map(SubscriptionId),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_status_terminality() {
        assert!(!TaskStatus::Queued.is_terminal());
        assert!(!TaskStatus::Running.is_terminal());
        for s in [TaskStatus::Ok, TaskStatus::Failed, TaskStatus::Cancelled] {
            assert!(s.is_terminal(), "{s:?} should be terminal");
        }
    }

    #[test]
    fn unknown_enum_values_are_corruption_not_a_default() {
        assert!(TaskStatus::parse("nonsense").is_err());
        assert!(UserStatus::parse("").is_err());
    }

    #[test]
    fn only_active_accounts_can_log_in() {
        assert!(UserStatus::Active.can_log_in());
        assert!(!UserStatus::Suspended.can_log_in());
        assert!(!UserStatus::Locked.can_log_in());
    }

    fn user_row(role: &str, permissions_json: &str) -> UserRow {
        UserRow {
            id: 1,
            role: role.into(),
            email: "a@example.com".into(),
            username: "admin".into(),
            pass_hash: "$argon2id$...".into(),
            totp_secret: None,
            totp_enabled: 0,
            status: "active".into(),
            reseller_id: None,
            permissions_json: permissions_json.into(),
            full_name: None,
            locale: "en".into(),
            created_at: "2026-08-22T10:00:00Z".into(),
            updated_at: "2026-08-22T10:00:00Z".into(),
            last_login_at: None,
        }
    }

    #[test]
    fn null_permissions_mean_role_defaults() {
        let u: User = user_row("customer", "null").try_into().unwrap();
        assert_eq!(
            u.effective_permissions(),
            Role::Customer.default_permissions().to_vec()
        );
    }

    #[test]
    fn permission_overrides_can_only_narrow() {
        // `server_manage` is an admin permission; a customer override naming it
        // must not grant it.
        let u: User = user_row("customer", r#"["site_read","server_manage"]"#)
            .try_into()
            .unwrap();
        let perms = u.effective_permissions();
        assert!(perms.contains(&Permission::SiteRead));
        assert!(!perms.contains(&Permission::ServerManage));
        assert!(
            !perms.contains(&Permission::DbManage),
            "unlisted permissions are dropped"
        );
    }

    #[test]
    fn a_corrupt_role_is_reported_not_coerced() {
        let err = User::try_from(user_row("superadmin", "null")).unwrap_err();
        assert!(matches!(
            err,
            DbError::Corrupt {
                field: "users.role",
                ..
            }
        ));
    }

    #[test]
    fn a_corrupt_permissions_blob_is_reported() {
        let err = User::try_from(user_row("admin", "not json")).unwrap_err();
        assert!(matches!(
            err,
            DbError::Corrupt {
                field: "users.permissions_json",
                ..
            }
        ));
    }
}
