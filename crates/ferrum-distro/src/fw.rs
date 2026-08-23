//! Firewall backends (spec §7.2, §11.9).
//!
//! Debian family gets nftables directly; RHEL family goes through firewalld,
//! because on those systems firewalld owns the ruleset and writing nft rules
//! behind its back is how panels end up with rules that vanish on reload.
//!
//! Nothing here opens a port on its own initiative — every rule traces back to an
//! explicit, audited user action (spec §12 rule 8).

use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::exec::Cmd;
use crate::{DistroError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub const fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// One managed hole in the firewall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRule {
    pub port: u16,
    pub proto: Proto,
    /// Restrict to a source CIDR. `None` means anywhere — which the UI marks
    /// clearly, since "remote database access from 0.0.0.0/0" is a decision, not
    /// a default.
    pub source: Option<String>,
    pub comment: String,
}

impl PortRule {
    pub fn validate(&self) -> Result<()> {
        if self.port == 0 {
            return Err(DistroError::InvalidName(
                "port 0 is not a valid firewall rule".into(),
            ));
        }
        if let Some(src) = &self.source {
            validate_cidr(src)?;
        }
        if self.comment.len() > 128 || self.comment.chars().any(|c| c.is_control()) {
            return Err(DistroError::InvalidName(
                "rule comment is too long or contains control characters".into(),
            ));
        }
        Ok(())
    }
}

/// Accept only a literal `addr` or `addr/len` — never a hostname, which would
/// make the effective rule depend on DNS at apply time.
fn validate_cidr(src: &str) -> Result<()> {
    let (addr, prefix) = match src.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (src, None),
    };
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| DistroError::InvalidName(format!("`{src}` is not an IP address or CIDR")))?;
    if let Some(prefix) = prefix {
        let max = if ip.is_ipv6() { 128 } else { 32 };
        let len: u8 = prefix.parse().map_err(|_| {
            DistroError::InvalidName(format!("`{src}` has a non-numeric prefix length"))
        })?;
        if len > max {
            return Err(DistroError::InvalidName(format!(
                "`{src}` prefix length exceeds /{max}"
            )));
        }
    }
    Ok(())
}

#[async_trait]
pub trait FwBackend: Send + Sync {
    fn name(&self) -> &'static str;

    /// Is the firewall actually running? A panel that reports "port opened" while
    /// the firewall is stopped is lying to its operator.
    async fn is_active(&self) -> Result<bool>;

    async fn open_port(&self, rule: &PortRule) -> Result<()>;
    async fn close_port(&self, rule: &PortRule) -> Result<()>;
    async fn list_rules(&self) -> Result<Vec<PortRule>>;

    /// Add an address to the ban set used by Sentinel (spec §11.9).
    async fn ban_ip(&self, ip: IpAddr, ttl_seconds: Option<u32>) -> Result<()>;
    async fn unban_ip(&self, ip: IpAddr) -> Result<()>;
    async fn list_bans(&self) -> Result<Vec<IpAddr>>;
}

/// RHEL family. Rules are added `--permanent` and then reloaded, so they survive
/// a `firewall-cmd --reload` and a reboot (spec §11.9 AC).
pub struct FirewalldBackend;

impl FirewalldBackend {
    pub fn new() -> Self {
        Self
    }

    fn cmd(&self) -> Cmd {
        Cmd::new("firewall-cmd")
    }
}

impl Default for FirewalldBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FwBackend for FirewalldBackend {
    fn name(&self) -> &'static str {
        "firewalld"
    }

    async fn is_active(&self) -> Result<bool> {
        Ok(self
            .cmd()
            .arg("--state")
            .run()
            .await
            .map(|o| o.success())
            .unwrap_or(false))
    }

    async fn open_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        // TODO(scope): Phase 2 opens ports for remote DB access; Phase 4 owns the
        // firewall UI. Implemented then, against a real firewalld in CI.
        Err(unimplemented_for("firewalld", "open_port"))
    }

    async fn close_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        Err(unimplemented_for("firewalld", "close_port"))
    }

    async fn list_rules(&self) -> Result<Vec<PortRule>> {
        Err(unimplemented_for("firewalld", "list_rules"))
    }

    async fn ban_ip(&self, _ip: IpAddr, _ttl_seconds: Option<u32>) -> Result<()> {
        Err(unimplemented_for("firewalld", "ban_ip"))
    }

    async fn unban_ip(&self, _ip: IpAddr) -> Result<()> {
        Err(unimplemented_for("firewalld", "unban_ip"))
    }

    async fn list_bans(&self) -> Result<Vec<IpAddr>> {
        Err(unimplemented_for("firewalld", "list_bans"))
    }
}

/// Debian family, via nftables in a dedicated `ferrum` table so we never edit
/// rules somebody else owns.
pub struct NftablesBackend;

impl NftablesBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FwBackend for NftablesBackend {
    fn name(&self) -> &'static str {
        "nftables"
    }

    async fn is_active(&self) -> Result<bool> {
        Ok(crate::exec::program_available("nft"))
    }

    async fn open_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        Err(unimplemented_for("nftables", "open_port"))
    }

    async fn close_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        Err(unimplemented_for("nftables", "close_port"))
    }

    async fn list_rules(&self) -> Result<Vec<PortRule>> {
        Err(unimplemented_for("nftables", "list_rules"))
    }

    async fn ban_ip(&self, _ip: IpAddr, _ttl_seconds: Option<u32>) -> Result<()> {
        Err(unimplemented_for("nftables", "ban_ip"))
    }

    async fn unban_ip(&self, _ip: IpAddr) -> Result<()> {
        Err(unimplemented_for("nftables", "unban_ip"))
    }

    async fn list_bans(&self) -> Result<Vec<IpAddr>> {
        Err(unimplemented_for("nftables", "list_bans"))
    }
}

fn unimplemented_for(backend: &str, op: &str) -> DistroError {
    DistroError::CommandFailed {
        cmd: format!("{backend}::{op}"),
        status: -1,
        output:
            "firewall management arrives with Phase 2 (db remote access) and Phase 4 (firewall UI)"
                .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(source: Option<&str>) -> PortRule {
        PortRule {
            port: 3306,
            proto: Proto::Tcp,
            source: source.map(str::to_string),
            comment: "remote mysql".into(),
        }
    }

    #[test]
    fn cidr_validation_accepts_real_networks() {
        for ok in [
            "10.0.0.0/8",
            "203.0.113.4",
            "203.0.113.4/32",
            "2001:db8::/32",
            "::1",
        ] {
            assert!(rule(Some(ok)).validate().is_ok(), "{ok} should be accepted");
        }
    }

    #[test]
    fn cidr_validation_rejects_hostnames_and_nonsense() {
        for bad in [
            "example.com",
            "10.0.0.0/33",
            "2001:db8::/129",
            "10.0.0.0/abc",
            "'; drop",
            "",
        ] {
            assert!(
                rule(Some(bad)).validate().is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn port_zero_is_refused() {
        let mut r = rule(None);
        r.port = 0;
        assert!(r.validate().is_err());
    }

    #[test]
    fn comments_cannot_smuggle_newlines_into_a_ruleset() {
        let mut r = rule(None);
        r.comment = "ok\naccept all".into();
        assert!(r.validate().is_err());
    }
}
