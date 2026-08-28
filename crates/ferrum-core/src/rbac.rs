//! Roles, permissions, and tenant scoping (spec §6.1, §12 rule 4).
//!
//! Two ideas carry the whole authorization model:
//!
//! 1. **`AuthContext` travels with every operation.** The web process builds it
//!    from the session, ships it across the IPC boundary, and `ferrum-agentd`
//!    re-checks it against the same tables before doing privileged work.
//! 2. **`TenantScope`, not raw ids.** Repositories take a scope, so writing a
//!    query that forgets its `WHERE tenant_id = ?` is not something you *can*
//!    forget — you have to actively ask for [`TenantScope::Global`].

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, FerrumError, Result};
use crate::ids::{SubscriptionId, UserId};

/// The three fixed roles. Granular capability lives in [`Permission`], not here,
/// so we never grow a fourth role to express "customer, but with docker".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Reseller,
    Customer,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Reseller => "reseller",
            Role::Customer => "customer",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "admin" => Role::Admin,
            "reseller" => Role::Reseller,
            "customer" => Role::Customer,
            other => {
                return Err(FerrumError::new(
                    ErrorCode::InvalidInput,
                    format!("`{other}` is not a valid role"),
                ));
            }
        })
    }

    /// Permissions this role has before per-account and per-plan toggles apply.
    pub fn default_permissions(self) -> &'static [Permission] {
        use Permission::*;
        match self {
            Role::Admin => &[
                ServerRead,
                ServerManage,
                StackManage,
                UserManage,
                PlanManage,
                Impersonate,
                AuditRead,
                TaskRead,
                TaskCancel,
                SiteRead,
                SiteManage,
                DbManage,
                FileManage,
                CronManage,
                SshAccess,
                NodeApps,
                DockerApps,
                BackupManage,
                FirewallManage,
                DnsManage,
                TerminalAccess,
            ],
            Role::Reseller => &[
                ServerRead,
                UserManage,
                PlanManage,
                AuditRead,
                TaskRead,
                TaskCancel,
                SiteRead,
                SiteManage,
                DbManage,
                FileManage,
                CronManage,
                NodeApps,
                BackupManage,
                DnsManage,
            ],
            Role::Customer => &[
                TaskRead,
                // A customer may stop work they started. The tasks page offers
                // cancel and retry (spec §11.17), and the API only ever shows a
                // customer their own rows — the alternative was a button that
                // works for admins and silently fails for everyone else.
                TaskCancel,
                SiteRead,
                SiteManage,
                DbManage,
                FileManage,
                CronManage,
                BackupManage,
                // Held by the role, granted by the plan. Spec §11.16 gives a
                // customer a terminal "only if `can_ssh`", and
                // `PlanFeatures::denied_permissions` already revokes this the
                // moment the flag is off — which it is by default
                // (`PlanFeatures::default`). Without the permission in the
                // role's own set that revocation had nothing to revoke and no
                // customer could ever be granted a terminal, so the flag was
                // unreachable rather than restrictive.
                //
                // This grants nothing on its own:
                // `ferrum_ops::terminal::authorize` re-reads the target
                // subscription's plan and refuses a customer whose plan is
                // absent or has `can_ssh = false`, so the permission and the
                // plan flag must *both* say yes.
                //
                // Deliberately **not** `SshAccess`: that one gates
                // `sftp.enable`, whose own plan check still fails closed for
                // planned subscriptions, and widening it here would open real
                // SFTP access to plan-less tenants as a side effect.
                TerminalAccess,
            ],
        }
    }
}

/// A single capability. Operations declare the one they need; the web layer and
/// the agent both check it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Permission {
    /// Read server-wide status and metrics.
    ServerRead,
    /// Change server settings, panel config, service state.
    ServerManage,
    /// Install/remove stack components.
    StackManage,
    /// Create and modify accounts below you in the hierarchy.
    UserManage,
    /// Create and modify plans you own.
    PlanManage,
    /// "Login as" another account. Always audited.
    Impersonate,
    AuditRead,
    TaskRead,
    TaskCancel,
    SiteRead,
    SiteManage,
    DbManage,
    FileManage,
    CronManage,
    /// Shell access over SFTP/SSH (`can_ssh` on the plan).
    SshAccess,
    NodeApps,
    /// `can_docker_apps` on the plan.
    DockerApps,
    BackupManage,
    FirewallManage,
    DnsManage,
    /// The in-panel web terminal.
    TerminalAccess,
}

impl Permission {
    pub const fn as_str(self) -> &'static str {
        use Permission::*;
        match self {
            ServerRead => "server_read",
            ServerManage => "server_manage",
            StackManage => "stack_manage",
            UserManage => "user_manage",
            PlanManage => "plan_manage",
            Impersonate => "impersonate",
            AuditRead => "audit_read",
            TaskRead => "task_read",
            TaskCancel => "task_cancel",
            SiteRead => "site_read",
            SiteManage => "site_manage",
            DbManage => "db_manage",
            FileManage => "file_manage",
            CronManage => "cron_manage",
            SshAccess => "ssh_access",
            NodeApps => "node_apps",
            DockerApps => "docker_apps",
            BackupManage => "backup_manage",
            FirewallManage => "firewall_manage",
            DnsManage => "dns_manage",
            TerminalAccess => "terminal_access",
        }
    }
}

/// Which slice of the world an actor may see or touch.
///
/// Repositories take this instead of ids so an unscoped query is impossible to
/// write by accident (spec §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TenantScope {
    /// The whole server. Only an admin ever holds this.
    Global,
    /// A reseller and everything provisioned beneath it.
    Reseller { reseller_id: UserId },
    /// One customer and all of its subscriptions.
    Customer { customer_id: UserId },
    /// A single subscription — the narrowest scope, used when an operation
    /// targets one tenant's resources.
    Subscription {
        subscription_id: SubscriptionId,
        customer_id: UserId,
    },
}

impl TenantScope {
    /// True when `self` is at least as wide as `other`.
    ///
    /// Used by the agent to verify that the scope attached to an incoming frame
    /// really contains the resource the operation names.
    pub fn contains(&self, other: &TenantScope) -> bool {
        use TenantScope::*;
        match (self, other) {
            (Global, _) => true,
            (Reseller { reseller_id: a }, Reseller { reseller_id: b }) => a == b,
            // A reseller containing a customer is a database question (is this
            // customer mine?), answered by the repository layer — not something
            // this pure function can decide, so it must not claim `true`.
            (Reseller { .. }, _) => false,
            (Customer { customer_id: a }, Customer { customer_id: b }) => a == b,
            (Customer { customer_id: a }, Subscription { customer_id: b, .. }) => a == b,
            (Customer { .. }, _) => false,
            (
                Subscription {
                    subscription_id: a, ..
                },
                Subscription {
                    subscription_id: b, ..
                },
            ) => a == b,
            (Subscription { .. }, _) => false,
        }
    }

    /// The owning customer, when the scope names one.
    pub fn customer_id(&self) -> Option<UserId> {
        match self {
            TenantScope::Customer { customer_id }
            | TenantScope::Subscription { customer_id, .. } => Some(*customer_id),
            _ => None,
        }
    }

    pub fn subscription_id(&self) -> Option<SubscriptionId> {
        match self {
            TenantScope::Subscription {
                subscription_id, ..
            } => Some(*subscription_id),
            _ => None,
        }
    }

    pub const fn is_global(&self) -> bool {
        matches!(self, TenantScope::Global)
    }
}

/// Everything an operation needs to know about who is asking.
///
/// Built once per request in `ferrum-web`, serialised into the IPC envelope, and
/// re-validated by `ferrum-agentd` — never trusted blindly on either side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContext {
    pub actor_user_id: UserId,
    pub acting_role: Role,
    pub tenant_scope: TenantScope,
    /// Set when an admin is operating through "login as"; the audit row records
    /// both identities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonator_id: Option<UserId>,
    /// Effective permissions after role defaults, per-account overrides and plan
    /// feature flags have been folded together.
    pub permissions: BTreeSet<Permission>,
    /// Correlates the web request, the IPC frame, the task and every log line.
    pub request_id: String,
}

impl AuthContext {
    /// Build a context from a role's defaults. Callers layer plan features and
    /// per-account overrides on top with [`AuthContext::restrict_to`].
    pub fn from_role(
        actor_user_id: UserId,
        acting_role: Role,
        tenant_scope: TenantScope,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            actor_user_id,
            acting_role,
            tenant_scope,
            impersonator_id: None,
            permissions: acting_role.default_permissions().iter().copied().collect(),
            request_id: request_id.into(),
        }
    }

    /// The context the agent's own scheduler acts under (spec §10.2).
    ///
    /// Certificate renewals, metric rollups and retention sweeps have no user
    /// behind them, but they still need an identity for the audit trail and for
    /// the operations they invoke.
    ///
    /// This cannot be forged from outside. Every context arriving over the IPC
    /// socket is re-derived against the `users` table before an operation runs,
    /// and [`Self::SYSTEM_ACTOR`] is not a row anybody can create — the id is
    /// below the first `AUTOINCREMENT` value, so the lookup fails and the
    /// request is refused (spec §12 rule 4).
    pub fn system(reason: &str) -> Self {
        Self {
            actor_user_id: Self::SYSTEM_ACTOR,
            acting_role: Role::Admin,
            tenant_scope: TenantScope::Global,
            impersonator_id: None,
            permissions: Role::Admin.default_permissions().iter().copied().collect(),
            request_id: format!("scheduler-{reason}"),
        }
    }

    /// The actor id the scheduler uses. Never a real account: SQLite's
    /// `AUTOINCREMENT` starts at 1, so nothing can ever occupy it.
    pub const SYSTEM_ACTOR: UserId = UserId(0);

    /// Is this the agent acting on its own behalf rather than for a user?
    pub fn is_system(&self) -> bool {
        self.actor_user_id == Self::SYSTEM_ACTOR
    }

    /// Intersect the current permissions with `allowed`.
    ///
    /// Only ever narrows: a plan flag or an account override cannot grant a
    /// capability the role does not already have.
    pub fn restrict_to(mut self, allowed: &[Permission]) -> Self {
        let allowed: BTreeSet<Permission> = allowed.iter().copied().collect();
        self.permissions.retain(|p| allowed.contains(p));
        self
    }

    /// Remove specific permissions (a disabled plan feature, a suspended account).
    pub fn revoke(mut self, denied: &[Permission]) -> Self {
        for p in denied {
            self.permissions.remove(p);
        }
        self
    }

    pub fn has(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// The check every operation starts with.
    pub fn require(&self, permission: Permission) -> Result<()> {
        if self.has(permission) {
            Ok(())
        } else {
            Err(FerrumError::new(
                ErrorCode::PermissionDenied,
                format!("missing permission `{}`", permission.as_str()),
            ))
        }
    }

    /// Assert that this actor's scope covers the resource being targeted.
    pub fn require_scope(&self, target: &TenantScope) -> Result<()> {
        if self.tenant_scope.contains(target) {
            Ok(())
        } else {
            Err(FerrumError::new(
                ErrorCode::TenantScopeViolation,
                "the requested resource is outside your tenant scope",
            ))
        }
    }

    pub const fn is_impersonating(&self) -> bool {
        self.impersonator_id.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(role: Role, scope: TenantScope) -> AuthContext {
        AuthContext::from_role(UserId(1), role, scope, "req-test")
    }

    #[test]
    fn customers_cannot_manage_the_server() {
        let c = ctx(
            Role::Customer,
            TenantScope::Customer {
                customer_id: UserId(1),
            },
        );
        assert!(c.require(Permission::ServerManage).is_err());
        assert!(c.require(Permission::StackManage).is_err());
        assert!(c.require(Permission::Impersonate).is_err());
        assert!(c.require(Permission::SiteManage).is_ok());
    }

    #[test]
    fn resellers_cannot_touch_the_stack_or_firewall() {
        let r = ctx(
            Role::Reseller,
            TenantScope::Reseller {
                reseller_id: UserId(1),
            },
        );
        assert!(r.require(Permission::StackManage).is_err());
        assert!(r.require(Permission::FirewallManage).is_err());
        assert!(r.require(Permission::UserManage).is_ok());
    }

    #[test]
    fn restrict_only_narrows() {
        let c = ctx(
            Role::Customer,
            TenantScope::Customer {
                customer_id: UserId(1),
            },
        )
        .restrict_to(&[Permission::ServerManage, Permission::SiteRead]);
        assert!(
            !c.has(Permission::ServerManage),
            "restrict_to must never grant"
        );
        assert!(c.has(Permission::SiteRead));
        assert!(
            !c.has(Permission::DbManage),
            "restrict_to must drop unlisted permissions"
        );
    }

    #[test]
    fn a_customer_holds_terminal_access_by_role_but_a_default_plan_takes_it_away() {
        // Spec §11.16: a terminal for a customer is a *plan* feature. The role
        // has to carry the permission for the plan to have something to revoke,
        // and `PlanFeatures::default()` has `can_ssh = false`, so the default
        // answer is still no.
        let c = ctx(
            Role::Customer,
            TenantScope::Customer {
                customer_id: UserId(1),
            },
        );
        assert!(c.has(Permission::TerminalAccess));

        let features = crate::plan::PlanFeatures::default();
        let gated = c.clone().revoke(&features.denied_permissions());
        assert!(
            !gated.has(Permission::TerminalAccess),
            "a plan without can_ssh must leave a customer with no terminal"
        );
        assert!(
            !gated.has(Permission::SshAccess),
            "the same flag gates SFTP; neither half may survive it"
        );

        // And a customer never holds SFTP/SSH by role alone, which is what
        // keeps `sftp.enable` exactly as reachable as it was before.
        assert!(!c.has(Permission::SshAccess));
    }

    #[test]
    fn revoke_removes_plan_disabled_features() {
        let c = ctx(Role::Admin, TenantScope::Global).revoke(&[Permission::DockerApps]);
        assert!(!c.has(Permission::DockerApps));
        assert!(c.has(Permission::NodeApps));
    }

    #[test]
    fn scope_containment() {
        let global = TenantScope::Global;
        let cust = TenantScope::Customer {
            customer_id: UserId(7),
        };
        let sub = TenantScope::Subscription {
            subscription_id: SubscriptionId(3),
            customer_id: UserId(7),
        };
        let other_sub = TenantScope::Subscription {
            subscription_id: SubscriptionId(4),
            customer_id: UserId(8),
        };

        assert!(global.contains(&cust));
        assert!(global.contains(&sub));
        assert!(cust.contains(&sub));
        assert!(!cust.contains(&other_sub));
        assert!(!sub.contains(&other_sub));
        assert!(
            !sub.contains(&cust),
            "a subscription must not widen to its customer"
        );
        assert!(!cust.contains(&global));
    }

    #[test]
    fn reseller_scope_does_not_self_certify_ownership() {
        // Whether customer 9 belongs to reseller 2 is a DB fact; the pure scope
        // check must refuse rather than guess.
        let reseller = TenantScope::Reseller {
            reseller_id: UserId(2),
        };
        let cust = TenantScope::Customer {
            customer_id: UserId(9),
        };
        assert!(!reseller.contains(&cust));
    }

    #[test]
    fn the_system_context_can_act_but_is_not_a_real_account() {
        let system = AuthContext::system("cert.renew");
        assert!(system.is_system());
        assert!(system.has(Permission::SiteManage), "renewals need to re-render a vhost");
        assert!(system.tenant_scope.is_global());
        // Id 0 is below SQLite's first AUTOINCREMENT value, so no user row can
        // ever occupy it — which is what makes a forged system context fail the
        // agent's database re-check.
        assert_eq!(system.actor_user_id, UserId(0));
        assert!(!ctx(Role::Admin, TenantScope::Global).is_system());
    }

    #[test]
    fn require_scope_rejects_cross_tenant() {
        let c = ctx(
            Role::Customer,
            TenantScope::Customer {
                customer_id: UserId(7),
            },
        );
        let victim = TenantScope::Subscription {
            subscription_id: SubscriptionId(1),
            customer_id: UserId(8),
        };
        let e = c.require_scope(&victim).unwrap_err();
        assert_eq!(e.code, ErrorCode::TenantScopeViolation);
    }
}
