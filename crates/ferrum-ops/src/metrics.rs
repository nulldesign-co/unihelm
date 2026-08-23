//! Server metrics (spec §11.11).

use async_trait::async_trait;
use ferrum_core::{Permission, Result};
use ferrum_metrics::ServerSnapshot;
use serde::{Deserialize, Serialize};

use crate::registry::{Execution, OpContext, TypedOperation};

/// `metrics.snapshot` — one reading of CPU, memory, disks, network and the
/// panel's own footprint.
///
/// This is the operation behind the dashboard, so it is on the hot path: the
/// collector throttles refreshes so a room full of open dashboards costs one
/// sweep per second, not one per viewer.
pub struct Snapshot;

#[derive(Debug, Deserialize)]
pub struct SnapshotInput {
    /// Include the panel's own RSS. Costs an extra `/proc` read, so the
    /// dashboard asks for it and alert evaluation does not.
    #[serde(default)]
    pub include_panel_footprint: bool,
    #[serde(default)]
    pub web_pid: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotOutput {
    #[serde(flatten)]
    pub snapshot: ServerSnapshot,
}

#[async_trait]
impl TypedOperation for Snapshot {
    type Input = SnapshotInput;
    type Output = SnapshotOutput;

    const NAME: &'static str = "metrics.snapshot";
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let mut snapshot = ctx.metrics().snapshot().await;

        if input.include_panel_footprint {
            // The agent knows its own pid; the web process passes its own in,
            // since the agent has no reliable way to identify it.
            snapshot.panel = ctx
                .metrics()
                .panel_footprint(input.web_pid, Some(std::process::id()))
                .await;
        }

        Ok(SnapshotOutput { snapshot })
    }
}

#[cfg(test)]
mod tests {
    use crate::registry::testing::{auth_for, registry};
    use ferrum_core::Role;
    use serde_json::json;

    #[tokio::test]
    async fn a_snapshot_comes_back_with_real_numbers() {
        let (reg, admin, _) = registry().await;
        let out = reg
            .dispatch(
                "metrics.snapshot",
                &auth_for(admin, Role::Admin),
                json!({}),
                None,
            )
            .await
            .unwrap();

        assert!(out["cpu"]["cores"].as_u64().unwrap() >= 1);
        assert!(out["memory"]["total_bytes"].as_u64().unwrap() > 0);
        assert!(out["at"].as_str().unwrap().ends_with('Z'));
        assert!(out["disks"].is_array());
    }

    #[tokio::test]
    async fn the_panel_footprint_is_opt_in() {
        let (reg, admin, _) = registry().await;
        let auth = auth_for(admin, Role::Admin);

        let without = reg
            .dispatch("metrics.snapshot", &auth, json!({}), None)
            .await
            .unwrap();
        assert!(without["panel"]["total_rss_bytes"].is_null());

        let with = reg
            .dispatch(
                "metrics.snapshot",
                &auth,
                json!({ "include_panel_footprint": true, "web_pid": std::process::id() }),
                None,
            )
            .await
            .unwrap();
        assert!(with["panel"]["total_rss_bytes"].as_u64().unwrap_or(0) > 0);
    }

    #[tokio::test]
    async fn metrics_need_server_read() {
        let (reg, _, customer) = registry().await;
        let err = reg
            .dispatch(
                "metrics.snapshot",
                &auth_for(customer, Role::Customer),
                json!({}),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ferrum_core::ErrorCode::PermissionDenied);
    }
}
