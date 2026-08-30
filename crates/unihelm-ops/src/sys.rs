//! Liveness and identity operations.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_core::{Permission, Result};

use crate::registry::{Execution, OpContext, TypedOperation};

/// `sys.ping` — is the agent alive, and what is it running on?
///
/// The simplest possible operation, and the one `unihelm doctor` leans on: if this
/// answers, the socket, the peer check, the registry and the database handle all
/// work.
pub struct Ping;

#[derive(Debug, Deserialize)]
pub struct PingInput {
    /// Echoed back, so a caller can correlate without reading the envelope.
    #[serde(default)]
    pub nonce: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PingOutput {
    pub pong: bool,
    pub agent_version: &'static str,
    pub distro: String,
    pub family: &'static str,
    pub arch: &'static str,
    pub package_backend: &'static str,
    pub firewall_backend: &'static str,
    pub security_module: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[async_trait]
impl TypedOperation for Ping {
    type Input = PingInput;
    type Output = PingOutput;

    const NAME: &'static str = "sys.ping";
    // Anyone who can hold a session can check that the agent is up; the reply
    // contains nothing tenant-specific.
    const PERMISSION: Permission = Permission::TaskRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let d = ctx.distro();
        Ok(PingOutput {
            pong: true,
            agent_version: env!("CARGO_PKG_VERSION"),
            distro: d.info.pretty_name.clone(),
            family: d.info.family.as_str(),
            arch: d.info.arch.as_str(),
            package_backend: d.pkg.name(),
            firewall_backend: d.fw.name(),
            security_module: format!("{:?}", d.sec.kind()).to_ascii_lowercase(),
            nonce: input.nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::registry::testing::{auth_for, registry};
    use unihelm_core::Role;

    #[tokio::test]
    async fn ping_answers_with_the_machine_identity() {
        let (reg, admin, _) = registry().await;
        let out = reg
            .dispatch(
                "sys.ping",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "nonce": "abc" }),
                None,
            )
            .await
            .unwrap();

        assert_eq!(out["pong"], true);
        assert_eq!(out["nonce"], "abc");
        assert_eq!(out["family"], "debian");
        assert!(out["agent_version"].as_str().is_some_and(|v| !v.is_empty()));
    }

    #[tokio::test]
    async fn a_customer_may_ping() {
        let (reg, _, customer) = registry().await;
        let out = reg
            .dispatch(
                "sys.ping",
                &auth_for(customer, Role::Customer),
                serde_json::json!({}),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["pong"], true);
        assert!(
            out.get("nonce").is_none(),
            "an absent nonce should not appear as null"
        );
    }
}
