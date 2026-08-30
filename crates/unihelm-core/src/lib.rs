//! `unihelm-core` — the shared vocabulary of the panel.
//!
//! Everything in here is dependency-light on purpose: no tokio, no sqlx, no axum.
//! Both the unprivileged web process and the root agent link against this crate,
//! so it must stay small and side-effect free.
//!
//! Contents:
//! - [`error`] — the stable `FER-xxxx` error taxonomy (spec §10.5)
//! - [`ids`]   — typed identifiers, so a `UserId` can never be passed as a `SiteId`
//! - [`newtypes`] — validated-at-deserialization inputs (spec §12 rule 3)
//! - [`rbac`]  — roles, permissions, auth context, tenant scoping (spec §6.1, §12 rule 4)
//! - [`plan`]  — plan limits / features and the reseller allocation math (spec §6.2)

pub mod config;
pub mod error;
pub mod ids;
pub mod newtypes;
pub mod notify;
pub mod plan;
pub mod rbac;

pub use config::{LogFormat, UnihelmConfig};
pub use error::{ErrorCode, Result, UnihelmError};
pub use ids::{PlanId, SiteId, SubscriptionId, TaskId, UserId};
pub use newtypes::{
    AppName, DbName, Domain, Email, LinuxUser, PhpVersion, Port, TenantPath, Username,
};
pub use plan::{CountedResource, PlanFeatures, PlanLimits, QuotaUsage};
pub use rbac::{AuthContext, Permission, Role, TenantScope};
