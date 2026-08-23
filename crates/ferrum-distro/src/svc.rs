//! Service lifecycle via systemd (spec §7.2).
//!
//! systemd is a hard requirement (spec §1.3), so there is one implementation —
//! but it still lives behind [`SvcBackend`] because the *unit names* differ
//! between families and no feature module should have to know that.

use async_trait::async_trait;
use ferrum_core::PhpVersion;
use serde::{Deserialize, Serialize};

use crate::detect::Family;
use crate::exec::Cmd;
use crate::{DistroError, Result};

/// A systemd unit name the panel is willing to handle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UnitName(String);

impl UnitName {
    const SUFFIXES: &'static [&'static str] = &[
        ".service", ".socket", ".timer", ".slice", ".target", ".path", ".mount",
    ];

    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() || s.len() > 255 {
            return Err(DistroError::InvalidName(
                "unit name must be 1-255 characters".into(),
            ));
        }
        if !Self::SUFFIXES.iter().any(|suffix| s.ends_with(suffix)) {
            return Err(DistroError::InvalidName(format!(
                "unit `{s}` must end with one of {:?}",
                Self::SUFFIXES
            )));
        }
        if !s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b'\\' | b':')
        }) {
            return Err(DistroError::InvalidName(format!(
                "unit `{s}` contains illegal characters"
            )));
        }
        if s.contains("..") || s.starts_with('-') {
            return Err(DistroError::InvalidName(format!(
                "unit `{s}` is not a plausible unit name"
            )));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for UnitName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl TryFrom<String> for UnitName {
    type Error = DistroError;
    fn try_from(v: String) -> Result<Self> {
        Self::parse(&v)
    }
}
impl From<UnitName> for String {
    fn from(v: UnitName) -> String {
        v.0
    }
}

/// The whitelist of services the panel may act on (spec §5.2).
///
/// An enum rather than a string is the point: `svc.action` can never be talked
/// into restarting an arbitrary unit, because there is no way to express one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "unit")]
pub enum ManagedUnit {
    Nginx,
    PhpFpm {
        version: PhpVersion,
    },
    MariaDb,
    PostgreSql,
    /// Redis or Valkey — the module name stays generic (spec §7.3).
    KvStore,
    Docker,
    Sshd,
    FerrumWeb,
    FerrumAgentd,
}

impl ManagedUnit {
    /// Resolve to the real unit name for this family.
    ///
    /// This is the only function that knows `php8.3-fpm` on Debian is
    /// `php83-php-fpm` on RHEL.
    pub fn unit_name(self, family: Family) -> UnitName {
        let name = match (self, family) {
            (ManagedUnit::Nginx, _) => "nginx.service".to_string(),

            (ManagedUnit::PhpFpm { version }, Family::Debian) => {
                format!("php{}-fpm.service", version.as_str())
            }
            (ManagedUnit::PhpFpm { version }, Family::Rhel) => {
                format!("php{}-php-fpm.service", version.compact())
            }

            (ManagedUnit::MariaDb, _) => "mariadb.service".to_string(),
            // TODO(scope): PGDG ships versioned units on RHEL (postgresql-16).
            // Phase 2 owns PostgreSQL; resolve the installed major then.
            (ManagedUnit::PostgreSql, _) => "postgresql.service".to_string(),

            (ManagedUnit::KvStore, Family::Debian) => "redis-server.service".to_string(),
            (ManagedUnit::KvStore, Family::Rhel) => "redis.service".to_string(),

            (ManagedUnit::Docker, _) => "docker.service".to_string(),

            (ManagedUnit::Sshd, Family::Debian) => "ssh.service".to_string(),
            (ManagedUnit::Sshd, Family::Rhel) => "sshd.service".to_string(),

            (ManagedUnit::FerrumWeb, _) => "ferrum-web.service".to_string(),
            (ManagedUnit::FerrumAgentd, _) => "ferrum-agentd.service".to_string(),
        };
        UnitName(name)
    }

    /// Label for the UI and for task logs.
    pub fn display_name(self) -> String {
        match self {
            ManagedUnit::Nginx => "Nginx".into(),
            ManagedUnit::PhpFpm { version } => format!("PHP {} FPM", version.as_str()),
            ManagedUnit::MariaDb => "MariaDB".into(),
            ManagedUnit::PostgreSql => "PostgreSQL".into(),
            ManagedUnit::KvStore => "Redis".into(),
            ManagedUnit::Docker => "Docker".into(),
            ManagedUnit::Sshd => "OpenSSH".into(),
            ManagedUnit::FerrumWeb => "Ferrum panel".into(),
            ManagedUnit::FerrumAgentd => "Ferrum agent".into(),
        }
    }

    /// Stopping these takes the panel or the serving path down, so the API
    /// refuses `stop` on them and the UI hides the button.
    pub const fn is_critical(self) -> bool {
        matches!(self, ManagedUnit::FerrumAgentd | ManagedUnit::Sshd)
    }
}

/// What to do to a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SvcAction {
    Start,
    Stop,
    Restart,
    /// Re-read config without dropping connections — always preferred over
    /// restart for nginx and php-fpm.
    Reload,
}

impl SvcAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            SvcAction::Start => "start",
            SvcAction::Stop => "stop",
            SvcAction::Restart => "restart",
            SvcAction::Reload => "reload",
        }
    }
}

/// Coarse unit state, mapped from systemd's `ActiveState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitState {
    Active,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    /// The unit is not installed on this machine.
    NotFound,
    Unknown,
}

impl UnitState {
    fn from_systemd(active_state: &str, load_state: &str) -> Self {
        if load_state == "not-found" {
            return UnitState::NotFound;
        }
        match active_state {
            "active" => UnitState::Active,
            "inactive" => UnitState::Inactive,
            "failed" => UnitState::Failed,
            "activating" => UnitState::Activating,
            "deactivating" => UnitState::Deactivating,
            _ => UnitState::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitStatus {
    pub unit: String,
    pub state: UnitState,
    /// systemd's finer-grained `SubState`: `running`, `exited`, `dead`, …
    pub sub_state: String,
    /// `enabled`, `disabled`, `static`, `masked`, …
    pub enabled: Option<String>,
    pub main_pid: Option<u32>,
    /// Resident memory of the unit's cgroup, when systemd reports it.
    pub memory_bytes: Option<u64>,
    /// ISO-8601 timestamp of the last start, as systemd printed it.
    pub since: Option<String>,
}

impl UnitStatus {
    pub fn is_active(&self) -> bool {
        self.state == UnitState::Active
    }
    pub fn is_installed(&self) -> bool {
        self.state != UnitState::NotFound
    }
}

#[async_trait]
pub trait SvcBackend: Send + Sync {
    fn family(&self) -> Family;

    async fn status(&self, unit: &UnitName) -> Result<UnitStatus>;
    async fn action(&self, unit: &UnitName, action: SvcAction) -> Result<()>;
    async fn enable(&self, unit: &UnitName, start_now: bool) -> Result<()>;
    async fn disable(&self, unit: &UnitName, stop_now: bool) -> Result<()>;
    async fn daemon_reload(&self) -> Result<()>;
    /// Last `lines` journal entries for the unit, oldest first.
    async fn journal_tail(&self, unit: &UnitName, lines: u32) -> Result<Vec<String>>;

    /// Convenience: resolve a [`ManagedUnit`] and read its status.
    async fn managed_status(&self, unit: ManagedUnit) -> Result<UnitStatus> {
        self.status(&unit.unit_name(self.family())).await
    }
}

pub struct SystemdBackend {
    family: Family,
}

impl SystemdBackend {
    pub fn new(family: Family) -> Self {
        Self { family }
    }
}

#[async_trait]
impl SvcBackend for SystemdBackend {
    fn family(&self) -> Family {
        self.family
    }

    async fn status(&self, unit: &UnitName) -> Result<UnitStatus> {
        // `systemctl show` is the machine-readable form; `status` is for humans
        // and its output is explicitly not a stable interface.
        let out = Cmd::new("systemctl")
            .args([
                "show",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=UnitFileState",
                "--property=MainPID",
                "--property=MemoryCurrent",
                "--property=ActiveEnterTimestamp",
                "--",
                unit.as_str(),
            ])
            .run()
            .await?;

        Ok(parse_systemctl_show(unit.as_str(), &out.stdout))
    }

    async fn action(&self, unit: &UnitName, action: SvcAction) -> Result<()> {
        let out = Cmd::new("systemctl")
            .arg(action.as_str())
            .arg("--")
            .arg(unit.as_str())
            .run()
            .await?;
        if out.success() {
            return Ok(());
        }
        Err(DistroError::ServiceFailed {
            unit: unit.as_str().to_string(),
            action: action.as_str().to_string(),
            output: out.failure_text(),
        })
    }

    async fn enable(&self, unit: &UnitName, start_now: bool) -> Result<()> {
        let mut cmd = Cmd::new("systemctl").arg("enable");
        if start_now {
            cmd = cmd.arg("--now");
        }
        let out = cmd.arg("--").arg(unit.as_str()).run().await?;
        if out.success() {
            return Ok(());
        }
        Err(DistroError::ServiceFailed {
            unit: unit.as_str().to_string(),
            action: "enable".into(),
            output: out.failure_text(),
        })
    }

    async fn disable(&self, unit: &UnitName, stop_now: bool) -> Result<()> {
        let mut cmd = Cmd::new("systemctl").arg("disable");
        if stop_now {
            cmd = cmd.arg("--now");
        }
        let out = cmd.arg("--").arg(unit.as_str()).run().await?;
        if out.success() {
            return Ok(());
        }
        Err(DistroError::ServiceFailed {
            unit: unit.as_str().to_string(),
            action: "disable".into(),
            output: out.failure_text(),
        })
    }

    async fn daemon_reload(&self) -> Result<()> {
        Cmd::new("systemctl")
            .arg("daemon-reload")
            .run_checked()
            .await?;
        Ok(())
    }

    async fn journal_tail(&self, unit: &UnitName, lines: u32) -> Result<Vec<String>> {
        let lines = lines.clamp(1, 10_000);
        let out = Cmd::new("journalctl")
            .args([
                "--no-pager",
                "--output=short-iso",
                "-n",
                &lines.to_string(),
                "-u",
            ])
            .arg(unit.as_str())
            .run()
            .await?;
        Ok(out.stdout.lines().map(str::to_string).collect())
    }
}

/// Parse `systemctl show` key=value output.
fn parse_systemctl_show(unit: &str, stdout: &str) -> UnitStatus {
    let mut load_state = String::new();
    let mut active_state = String::new();
    let mut sub_state = String::new();
    let mut unit_file_state = String::new();
    let mut main_pid = None;
    let mut memory_bytes = None;
    let mut since = None;

    for line in stdout.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "LoadState" => load_state = v.to_string(),
            "ActiveState" => active_state = v.to_string(),
            "SubState" => sub_state = v.to_string(),
            "UnitFileState" => unit_file_state = v.to_string(),
            "MainPID" => main_pid = v.parse::<u32>().ok().filter(|p| *p != 0),
            // systemd reports `[not set]` (older) or u64::MAX for "no value".
            "MemoryCurrent" => memory_bytes = v.parse::<u64>().ok().filter(|b| *b != u64::MAX),
            "ActiveEnterTimestamp" => {
                since = (!v.is_empty()).then(|| v.to_string());
            }
            _ => {}
        }
    }

    UnitStatus {
        unit: unit.to_string(),
        state: UnitState::from_systemd(&active_state, &load_state),
        sub_state,
        enabled: (!unit_file_state.is_empty()).then_some(unit_file_state),
        main_pid,
        memory_bytes,
        since,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_names_are_constrained() {
        assert!(UnitName::parse("nginx.service").is_ok());
        assert!(UnitName::parse("ferrum-app@7.service").is_ok());
        assert!(UnitName::parse("ferrum-ft_abc.slice").is_ok());
        for bad in [
            "nginx",
            "nginx.service; rm -rf /",
            "../../etc/systemd/system/evil.service",
            "-x.service",
            "a..b.service",
            "nginx.service\nExecStart=/bin/sh",
            "",
        ] {
            assert!(
                UnitName::parse(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn php_fpm_unit_names_differ_by_family() {
        let u = ManagedUnit::PhpFpm {
            version: PhpVersion::V83,
        };
        assert_eq!(u.unit_name(Family::Debian).as_str(), "php8.3-fpm.service");
        assert_eq!(u.unit_name(Family::Rhel).as_str(), "php83-php-fpm.service");
    }

    #[test]
    fn ssh_and_redis_unit_names_differ_by_family() {
        assert_eq!(
            ManagedUnit::Sshd.unit_name(Family::Debian).as_str(),
            "ssh.service"
        );
        assert_eq!(
            ManagedUnit::Sshd.unit_name(Family::Rhel).as_str(),
            "sshd.service"
        );
        assert_eq!(
            ManagedUnit::KvStore.unit_name(Family::Debian).as_str(),
            "redis-server.service"
        );
        assert_eq!(
            ManagedUnit::KvStore.unit_name(Family::Rhel).as_str(),
            "redis.service"
        );
    }

    #[test]
    fn every_managed_unit_resolves_to_a_valid_unit_name_on_both_families() {
        let mut units = vec![
            ManagedUnit::Nginx,
            ManagedUnit::MariaDb,
            ManagedUnit::PostgreSql,
            ManagedUnit::KvStore,
            ManagedUnit::Docker,
            ManagedUnit::Sshd,
            ManagedUnit::FerrumWeb,
            ManagedUnit::FerrumAgentd,
        ];
        units.extend(
            PhpVersion::ALL
                .iter()
                .map(|&v| ManagedUnit::PhpFpm { version: v }),
        );

        for unit in units {
            for family in [Family::Debian, Family::Rhel] {
                let name = unit.unit_name(family);
                assert!(
                    UnitName::parse(name.as_str()).is_ok(),
                    "{unit:?} on {family:?} produced an invalid unit name `{name}`"
                );
            }
        }
    }

    #[test]
    fn managed_unit_deserialises_from_the_op_input_shape() {
        let u: ManagedUnit = serde_json::from_str(r#"{"unit":"php_fpm","version":"8.3"}"#).unwrap();
        assert_eq!(
            u,
            ManagedUnit::PhpFpm {
                version: PhpVersion::V83
            }
        );
        // There is no way to name an arbitrary unit.
        assert!(serde_json::from_str::<ManagedUnit>(r#"{"unit":"evil.service"}"#).is_err());
        assert!(
            serde_json::from_str::<ManagedUnit>(r#"{"unit":"php_fpm","version":"9.9"}"#).is_err()
        );
    }

    #[test]
    fn parses_systemctl_show_output() {
        let out = "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n\
                   MainPID=1234\nMemoryCurrent=52428800\nActiveEnterTimestamp=Sat 2026-08-22 10:00:00 UTC\n";
        let s = parse_systemctl_show("nginx.service", out);
        assert_eq!(s.state, UnitState::Active);
        assert_eq!(s.sub_state, "running");
        assert_eq!(s.enabled.as_deref(), Some("enabled"));
        assert_eq!(s.main_pid, Some(1234));
        assert_eq!(s.memory_bytes, Some(52_428_800));
        assert!(s.is_active());
    }

    #[test]
    fn missing_unit_is_reported_as_not_found_not_inactive() {
        let out =
            "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nMainPID=0\n";
        let s = parse_systemctl_show("nope.service", out);
        assert_eq!(s.state, UnitState::NotFound);
        assert!(!s.is_installed());
        assert_eq!(s.main_pid, None, "pid 0 means no process");
        assert_eq!(s.enabled, None);
    }

    #[test]
    fn unset_memory_is_not_a_giant_number() {
        let out = format!(
            "LoadState=loaded\nActiveState=active\nMemoryCurrent={}\n",
            u64::MAX
        );
        let s = parse_systemctl_show("x.service", &out);
        assert_eq!(s.memory_bytes, None);
    }
}
