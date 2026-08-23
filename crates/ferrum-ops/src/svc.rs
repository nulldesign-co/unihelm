//! Service status and lifecycle (spec §5.2 `svc.action`).
//!
//! The input type is the point of this module: `unit` is a [`ManagedUnit`] enum,
//! so there is no way for an API caller to name an arbitrary systemd unit. The
//! worst a hostile input can do is ask about a service the panel already manages.

use async_trait::async_trait;
use ferrum_core::{ErrorCode, FerrumError, Permission, Result};
use ferrum_distro::svc::{ManagedUnit, SvcAction, UnitStatus};
use serde::{Deserialize, Serialize};

use crate::registry::{Execution, OpContext, TypedOperation};

/// `svc.status` — read one managed service's state.
pub struct Status;

#[derive(Debug, Deserialize)]
pub struct StatusInput {
    pub unit: ManagedUnit,
}

#[derive(Debug, Serialize)]
pub struct StatusOutput {
    pub display_name: String,
    #[serde(flatten)]
    pub status: UnitStatus,
}

#[async_trait]
impl TypedOperation for Status {
    type Input = StatusInput;
    type Output = StatusOutput;

    const NAME: &'static str = "svc.status";
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let family = ctx.distro().info.family;
        let unit_name = input.unit.unit_name(family);
        let status = ctx.distro().svc.status(&unit_name).await?;
        Ok(StatusOutput {
            display_name: input.unit.display_name(),
            status,
        })
    }
}

/// `svc.action` — start, stop, restart or reload a managed service.
pub struct Action;

#[derive(Debug, Deserialize)]
pub struct ActionInput {
    pub unit: ManagedUnit,
    pub action: SvcAction,
}

#[derive(Debug, Serialize)]
pub struct ActionOutput {
    pub unit: String,
    pub action: &'static str,
    /// State after the action, so the UI does not have to poll to find out.
    pub status: UnitStatus,
}

#[async_trait]
impl TypedOperation for Action {
    type Input = ActionInput;
    type Output = ActionOutput;

    const NAME: &'static str = "svc.action";
    const PERMISSION: Permission = Permission::ServerManage;
    // Service actions belong in the fast lane: a stuck package install must
    // never be the reason a restart button does nothing (spec §10.1).
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // Stopping the agent through the agent, or SSH through the panel, is how
        // people lock themselves out of their own server.
        if input.unit.is_critical() && matches!(input.action, SvcAction::Stop) {
            return Err(FerrumError::new(
                ErrorCode::Conflict,
                format!(
                    "{} cannot be stopped from the panel — do it over a console you still control",
                    input.unit.display_name()
                ),
            )
            .with_field("unit"));
        }

        let family = ctx.distro().info.family;
        let unit_name = input.unit.unit_name(family);

        ctx.log(format!("{} {}", input.action.as_str(), unit_name));
        ctx.distro().svc.action(&unit_name, input.action).await?;

        let status = ctx.distro().svc.status(&unit_name).await?;
        Ok(ActionOutput {
            unit: unit_name.as_str().to_string(),
            action: input.action.as_str(),
            status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use ferrum_core::Role;
    use serde_json::json;

    #[tokio::test]
    async fn status_resolves_the_unit_name_for_this_family() {
        let (reg, admin, _) = registry().await;
        let out = reg
            .dispatch(
                "svc.status",
                &auth_for(admin, Role::Admin),
                json!({ "unit": { "unit": "php_fpm", "version": "8.3" } }),
                None,
            )
            .await
            .unwrap();
        // The mock distro is Debian-family.
        assert_eq!(out["unit"], "php8.3-fpm.service");
        assert_eq!(out["display_name"], "PHP 8.3 FPM");
        assert_eq!(out["state"], "not_found");
    }

    #[tokio::test]
    async fn an_action_changes_state_and_reports_it_back() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);

        let out = reg
            .dispatch(
                "svc.action",
                &auth,
                json!({ "unit": { "unit": "nginx" }, "action": "start" }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["unit"], "nginx.service");
        assert_eq!(out["action"], "start");
        assert_eq!(out["status"]["state"], "active");

        let status = reg
            .dispatch(
                "svc.status",
                &auth,
                json!({ "unit": { "unit": "nginx" } }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(status["state"], "active");
    }

    #[tokio::test]
    async fn critical_services_cannot_be_stopped_from_the_panel() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);

        for unit in ["sshd", "ferrum_agentd"] {
            let err = reg
                .dispatch(
                    "svc.action",
                    &auth,
                    json!({ "unit": { "unit": unit }, "action": "stop" }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Conflict, "{unit} should refuse a stop");
        }

        // Restarting them is still allowed.
        assert!(
            reg.dispatch(
                "svc.action",
                &auth,
                json!({ "unit": { "unit": "sshd" }, "action": "restart" }),
                None
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn arbitrary_unit_names_cannot_be_expressed() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);

        for bad in [
            json!({ "unit": { "unit": "evil.service" }, "action": "start" }),
            json!({ "unit": "nginx.service", "action": "start" }),
            json!({ "unit": { "unit": "php_fpm", "version": "9.9" }, "action": "start" }),
            json!({ "unit": { "unit": "nginx" }, "action": "rm -rf /" }),
        ] {
            let err = reg
                .dispatch("svc.action", &auth, bad.clone(), None)
                .await
                .unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::InvalidInput,
                "input {bad} should not parse"
            );
        }
    }

    #[tokio::test]
    async fn reading_status_needs_less_than_changing_it() {
        // A reseller can see the server is healthy but cannot restart nginx.
        let (reg, _, customer) = registry().await;
        let auth = auth_for(customer, Role::Customer);
        assert_eq!(
            reg.dispatch(
                "svc.status",
                &auth,
                json!({ "unit": { "unit": "nginx" } }),
                None
            )
            .await
            .unwrap_err()
            .code,
            ErrorCode::PermissionDenied
        );
    }
}
