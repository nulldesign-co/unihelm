//! Service lifecycle via systemd (spec §7.2).
//!
//! systemd is a hard requirement (spec §1.3), so there is one implementation —
//! but it still lives behind [`SvcBackend`] because the *unit names* differ
//! between families and no feature module should have to know that.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_core::PhpVersion;

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
    Apache,
    PhpFpm {
        version: PhpVersion,
    },
    MariaDb,
    PostgreSql,
    /// Redis or Valkey — the module name stays generic (spec §7.3).
    KvStore,
    Docker,
    Sshd,
    /// The local MTA every runtime on the box hands outbound mail to
    /// (spec §11.18).
    Postfix,
    UnihelmWeb,
    UnihelmAgentd,
}

impl ManagedUnit {
    /// Resolve to the real unit name for this family.
    ///
    /// This is the only function that knows `php8.3-fpm` on Debian is
    /// `php83-php-fpm` on RHEL.
    pub fn unit_name(self, family: Family) -> UnitName {
        let name = match (self, family) {
            (ManagedUnit::Nginx, _) => "nginx.service".to_string(),

            // The one unit name in this table that is not the package name on
            // either side: Debian calls it `apache2`, EL calls it `httpd`, and
            // neither ships the other as an alias.
            (ManagedUnit::Apache, Family::Debian) => "apache2.service".to_string(),
            (ManagedUnit::Apache, Family::Rhel) => "httpd.service".to_string(),

            (ManagedUnit::PhpFpm { version }, Family::Debian) => {
                format!("php{}-fpm.service", version.as_str())
            }
            (ManagedUnit::PhpFpm { version }, Family::Rhel) => {
                format!("php{}-php-fpm.service", version.compact())
            }

            // Both families use `mariadb.service` — the vendor packages ship it
            // and the distro packages alias `mysql.service`/`mysqld.service` to
            // it, so there is nothing to resolve per family.
            (ManagedUnit::MariaDb, _) => "mariadb.service".to_string(),

            // Debian's postgresql-common ships an umbrella `postgresql.service`
            // that pulls up every `postgresql@<major>-<cluster>` instance; PGDG
            // on RHEL ships only versioned units (`postgresql-17.service`) and
            // no umbrella, so the major has to be named here. It comes from the
            // same constant that selects the repository tree (spec §11.4;
            // versioning becomes a config value together with that constant).
            (ManagedUnit::PostgreSql, Family::Debian) => "postgresql.service".to_string(),
            (ManagedUnit::PostgreSql, Family::Rhel) => {
                format!("postgresql-{}.service", crate::repos::POSTGRES_MAJOR)
            }

            (ManagedUnit::KvStore, Family::Debian) => "redis-server.service".to_string(),
            (ManagedUnit::KvStore, Family::Rhel) => "redis.service".to_string(),

            (ManagedUnit::Docker, _) => "docker.service".to_string(),

            (ManagedUnit::Sshd, Family::Debian) => "ssh.service".to_string(),
            (ManagedUnit::Sshd, Family::Rhel) => "sshd.service".to_string(),

            // Checked on 2026-09-09 against both families' packaging, because
            // "they're both called postfix" is exactly the assumption that made
            // `apache2` / `httpd` a bug the first time. Debian's `postfix` ships
            // `/lib/systemd/system/postfix.service` alongside a templated
            // `postfix@.service` for multi-instance setups, and the plain name
            // is the one that drives the default instance; EL's `postfix` ships
            // `postfix.service` and nothing else. So one name really does cover
            // both — but the panel must keep naming `postfix.service` and never
            // `postfix@-.service`, which is the *instance* Debian's wrapper
            // starts and is not a unit that exists on EL at all.
            (ManagedUnit::Postfix, _) => "postfix.service".to_string(),

            (ManagedUnit::UnihelmWeb, _) => "unihelm-web.service".to_string(),
            (ManagedUnit::UnihelmAgentd, _) => "unihelm-agentd.service".to_string(),
        };
        UnitName(name)
    }

    /// Label for the UI and for task logs.
    pub fn display_name(self) -> String {
        match self {
            ManagedUnit::Nginx => "Nginx".into(),
            ManagedUnit::Apache => "Apache".into(),
            ManagedUnit::PhpFpm { version } => format!("PHP {} FPM", version.as_str()),
            ManagedUnit::MariaDb => "MariaDB".into(),
            ManagedUnit::PostgreSql => "PostgreSQL".into(),
            ManagedUnit::KvStore => "Redis".into(),
            ManagedUnit::Docker => "Docker".into(),
            ManagedUnit::Sshd => "OpenSSH".into(),
            ManagedUnit::Postfix => "Postfix".into(),
            ManagedUnit::UnihelmWeb => "Unihelm panel".into(),
            ManagedUnit::UnihelmAgentd => "Unihelm agent".into(),
        }
    }

    /// Stopping these takes the panel or the serving path down, so the API
    /// refuses `stop` on them and the UI hides the button.
    pub const fn is_critical(self) -> bool {
        matches!(self, ManagedUnit::UnihelmAgentd | ManagedUnit::Sshd)
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

/// Which number [`UnitStatus::memory_bytes`] is carrying.
///
/// The two measure different things and are not comparable, so the reading says
/// which one it is instead of leaving every caller to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySource {
    /// `anon` from the unit's own `memory.stat` — the anonymous pages its
    /// processes actually hold. This is what "the service is using X" means.
    Anonymous,
    /// systemd's `MemoryCurrent`, used when the unit's `memory.stat` could not
    /// be read: cgroup v1, a unit with no cgroup because it is not running, or
    /// a `/sys/fs/cgroup` this process cannot see. It is the cgroup's whole
    /// charge, page cache included, so it reads high by however much the unit
    /// happens to have read off disk.
    CgroupTotal,
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
    /// Memory the unit is using, in bytes. Read [`Self::memory_source`] before
    /// putting two of these next to each other; `None` means nothing could be
    /// read at all.
    ///
    /// This doc used to say "resident memory" while the field carried
    /// `MemoryCurrent` verbatim, and that sentence is why the mistake lasted:
    /// under cgroup v2 that charge includes the page cache the unit has
    /// touched, so a database that had just read a large table reported
    /// gigabytes on the dashboard beside Docker's 40 MB, and the two numbers
    /// were being compared as though they measured the same thing.
    pub memory_bytes: Option<u64>,
    /// Which reading [`Self::memory_bytes`] is, so a fallback is visible rather
    /// than silently mixed in with the real thing.
    pub memory_source: Option<MemorySource>,
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
            .arg("show")
            .args(SHOW_PROPERTIES)
            .args(["--", unit.as_str()])
            .run()
            .await?;

        let mut status = parse_systemctl_show(unit.as_str(), &out.stdout);
        // `MemoryCurrent` is the cgroup's charge, not the unit's own memory.
        // The split between the two is in the cgroup's `memory.stat`, and
        // `ControlGroup` is systemd telling us where that cgroup is.
        let memory_stat = show_property(&out.stdout, "ControlGroup").and_then(read_memory_stat);
        apply_memory_stat(&mut status, memory_stat.as_deref());
        Ok(status)
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

/// The properties `status` asks systemd for.
///
/// `ControlGroup` is in this list so the memory reading can find the unit's own
/// `memory.stat`. Dropping it does not fail anything — it silently puts every
/// unit back on the cgroup charge, which is exactly how the page cache came to
/// be reported as memory in the first place.
const SHOW_PROPERTIES: &[&str] = &[
    "--property=LoadState",
    "--property=ActiveState",
    "--property=SubState",
    "--property=UnitFileState",
    "--property=MainPID",
    "--property=MemoryCurrent",
    "--property=ControlGroup",
    "--property=ActiveEnterTimestamp",
];

/// One `key=value` line out of `systemctl show` output. Empty values are `None`:
/// systemd prints the key with nothing after it for a property it has no answer
/// for, such as `ControlGroup` on a unit that is not running.
fn show_property(stdout: &str, key: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k == key && !v.is_empty()).then(|| v.to_string())
    })
}

/// `/sys/fs/cgroup` plus systemd's cgroup path for the unit, cgroup v2 layout.
///
/// systemd reports `ControlGroup` as an absolute path *inside* the hierarchy
/// (`/system.slice/nginx.service`), so the leading slash is trimmed rather than
/// used to join. On a cgroup v1 host nothing exists at the result, which is one
/// of the cases the [`MemorySource::CgroupTotal`] fallback covers.
fn memory_stat_path(control_group: &str) -> Option<PathBuf> {
    let relative = control_group.trim().trim_start_matches('/');
    // The path comes from systemd rather than from a request, but the agent is
    // root: a `..` in it would still open a file under `/sys` that this has no
    // business reading, so it is refused instead of trusted.
    if relative.is_empty() || relative.split('/').any(|seg| seg.is_empty() || seg == "..") {
        return None;
    }
    Some(
        Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("memory.stat"),
    )
}

/// The unit's own `memory.stat`, or `None` if it is not there to be read.
///
/// A blocking read inside an async fn on purpose: cgroup files are answered out
/// of kernel memory with no device behind them, and the container path reads its
/// cgroup the same way. Every failure is a `None` and a visible fallback — a
/// status call must not fail over a memory column.
fn read_memory_stat(control_group: String) -> Option<String> {
    std::fs::read_to_string(memory_stat_path(&control_group)?).ok()
}

/// Replace the cgroup charge with the unit's anonymous memory, when its
/// `memory.stat` could be read.
///
/// When it could not, `MemoryCurrent` stays exactly where it was — still
/// labelled [`MemorySource::CgroupTotal`], so the caller can say so.
fn apply_memory_stat(status: &mut UnitStatus, memory_stat: Option<&str>) {
    if let Some(anon) = memory_stat.and_then(anon_bytes) {
        status.memory_bytes = Some(anon);
        status.memory_source = Some(MemorySource::Anonymous);
    }
}

/// `anon` out of a cgroup v2 `memory.stat`.
///
/// The key is matched whole. The same file carries `anon_thp`, `inactive_anon`
/// and `active_anon`, so a `starts_with`/`contains` test would return whichever
/// of them the kernel happened to print first.
fn anon_bytes(memory_stat: &str) -> Option<u64> {
    memory_stat
        .lines()
        .find_map(|line| match line.split_once(' ') {
            Some(("anon", value)) => value.trim().parse().ok(),
            _ => None,
        })
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
        // What `systemctl show` alone can offer, until `apply_memory_stat` has
        // a better number. Labelled here rather than at the call site so no
        // path can produce a reading with no source on it.
        memory_source: memory_bytes.map(|_| MemorySource::CgroupTotal),
        since,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_names_are_constrained() {
        assert!(UnitName::parse("nginx.service").is_ok());
        assert!(UnitName::parse("unihelm-app@7.service").is_ok());
        assert!(UnitName::parse("unihelm-uh_abc.slice").is_ok());
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
    fn database_unit_names_resolve_per_family() {
        assert_eq!(
            ManagedUnit::MariaDb.unit_name(Family::Debian).as_str(),
            "mariadb.service"
        );
        assert_eq!(
            ManagedUnit::MariaDb.unit_name(Family::Rhel).as_str(),
            "mariadb.service"
        );
        // Debian has the umbrella unit; PGDG on RHEL ships only versioned ones.
        assert_eq!(
            ManagedUnit::PostgreSql.unit_name(Family::Debian).as_str(),
            "postgresql.service"
        );
        assert_eq!(
            ManagedUnit::PostgreSql.unit_name(Family::Rhel).as_str(),
            format!("postgresql-{}.service", crate::repos::POSTGRES_MAJOR)
        );
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
    fn the_mta_is_one_unit_name_on_both_families_and_is_not_the_instance() {
        // Both families really do call it `postfix.service` — verified rather
        // than assumed, since this table already carries `apache2` / `httpd`
        // for a service everyone calls Apache.
        for family in [Family::Debian, Family::Rhel] {
            assert_eq!(
                ManagedUnit::Postfix.unit_name(family).as_str(),
                "postfix.service",
                "{family:?}"
            );
        }
        // Debian additionally ships `postfix@.service`, whose `-` instance is
        // what its wrapper starts. Naming that here would work on Debian and
        // resolve to nothing on EL, so the panel would report a mail system
        // that is `not-found` on half the servers it supports.
        assert!(
            !ManagedUnit::Postfix
                .unit_name(Family::Debian)
                .as_str()
                .contains('@')
        );
        assert_eq!(ManagedUnit::Postfix.display_name(), "Postfix");
        // Mail going down is bad; it is not the panel or the serving path going
        // down, and an operator has to be able to stop it to work on it.
        assert!(!ManagedUnit::Postfix.is_critical());
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
            ManagedUnit::Postfix,
            ManagedUnit::UnihelmWeb,
            ManagedUnit::UnihelmAgentd,
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
        assert_eq!(s.memory_source, Some(MemorySource::CgroupTotal));
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
        assert_eq!(
            s.memory_source, None,
            "no reading means no source to name either"
        );
    }

    /// A real cgroup v2 `memory.stat`, as `mariadb.service` writes it after the
    /// unit has read a table off disk: 1 MiB of anonymous memory, 11 MiB of
    /// page cache. `MemoryCurrent` for this cgroup is the sum plus kernel
    /// overhead, which is the number the panel used to print.
    const MEMORY_STAT_V2: &str = "\
anon 1093632
file 12312576
kernel 1466368
kernel_stack 65536
pagetables 143360
percpu 1440
sock 0
vmalloc 0
shmem 0
file_mapped 4083712
file_dirty 0
file_writeback 0
swapcached 0
anon_thp 2097152
file_thp 0
shmem_thp 0
inactive_anon 4096
active_anon 1089536
inactive_file 8228864
active_file 4083712
unevictable 0
slab_reclaimable 786432
slab_unreclaimable 442368
";

    /// cgroup v1's `memory.stat`, which names the same quantity `rss` and has
    /// no `anon` line at all.
    const MEMORY_STAT_V1: &str = "\
cache 12312576
rss 1093632
rss_huge 0
shmem 0
mapped_file 4083712
dirty 0
writeback 0
pgpgin 4711
pgpgout 1204
inactive_anon 0
active_anon 1093632
inactive_file 8228864
active_file 4083712
";

    fn status_with_memory_current(bytes: u64) -> UnitStatus {
        parse_systemctl_show(
            "mariadb.service",
            &format!(
                "LoadState=loaded\nActiveState=active\nSubState=running\nMemoryCurrent={bytes}\n"
            ),
        )
    }

    #[test]
    fn anon_is_read_whole_and_not_from_a_key_that_merely_contains_anon() {
        assert_eq!(anon_bytes(MEMORY_STAT_V2), Some(1_093_632));
        // `anon_thp` comes before `inactive_anon`/`active_anon` in the file and
        // is the value a prefix match would have taken.
        assert_ne!(anon_bytes(MEMORY_STAT_V2), Some(2_097_152));
        assert_eq!(anon_bytes(MEMORY_STAT_V1), None);
        assert_eq!(anon_bytes(""), None);
        assert_eq!(anon_bytes("anon not-a-number\n"), None);
    }

    #[test]
    fn memory_stat_anon_replaces_the_cgroup_charge_and_the_reading_says_which() {
        let mut s = status_with_memory_current(13_697_024);
        assert_eq!(s.memory_bytes, Some(13_697_024));
        assert_eq!(s.memory_source, Some(MemorySource::CgroupTotal));

        apply_memory_stat(&mut s, Some(MEMORY_STAT_V2));

        // The page cache this unit had touched was twelve times its own memory,
        // and the dashboard was printing the sum next to other units' sums.
        assert_eq!(s.memory_bytes, Some(1_093_632));
        assert_eq!(s.memory_source, Some(MemorySource::Anonymous));
    }

    #[test]
    fn memory_stat_without_an_anon_line_keeps_the_charge_and_stays_labelled_a_charge() {
        let mut s = status_with_memory_current(13_697_024);
        apply_memory_stat(&mut s, Some(MEMORY_STAT_V1));
        assert_eq!(s.memory_bytes, Some(13_697_024));
        assert_eq!(
            s.memory_source,
            Some(MemorySource::CgroupTotal),
            "a fallback the caller cannot see is the same defect with a different number"
        );
    }

    #[test]
    fn an_unreadable_memory_stat_leaves_the_reading_and_its_label_alone() {
        let mut s = status_with_memory_current(13_697_024);
        apply_memory_stat(&mut s, None);
        assert_eq!(s.memory_bytes, Some(13_697_024));
        assert_eq!(s.memory_source, Some(MemorySource::CgroupTotal));

        // A unit with no reading at all gains none from a missing file.
        let mut none =
            parse_systemctl_show("x.service", "LoadState=loaded\nActiveState=inactive\n");
        apply_memory_stat(&mut none, None);
        assert_eq!(none.memory_bytes, None);
        assert_eq!(none.memory_source, None);
    }

    #[test]
    fn status_asks_systemd_for_the_cgroup_the_memory_reading_needs() {
        assert!(
            SHOW_PROPERTIES.contains(&"--property=ControlGroup"),
            "without it every unit falls back to the cgroup charge, silently"
        );
        assert!(SHOW_PROPERTIES.contains(&"--property=MemoryCurrent"));
    }

    #[test]
    fn control_group_is_taken_from_show_output_and_absent_when_systemd_has_none() {
        let running = "MainPID=1234\nControlGroup=/system.slice/nginx.service\nMemoryCurrent=100\n";
        assert_eq!(
            show_property(running, "ControlGroup").as_deref(),
            Some("/system.slice/nginx.service")
        );
        // systemd prints the bare key for a unit that is not running.
        assert_eq!(
            show_property("ControlGroup=\nMainPID=0\n", "ControlGroup"),
            None
        );
        assert_eq!(show_property(running, "MemoryPeak"), None);
    }

    #[test]
    fn memory_stat_path_stays_under_the_cgroup_root() {
        assert_eq!(
            memory_stat_path("/system.slice/nginx.service"),
            Some(PathBuf::from(
                "/sys/fs/cgroup/system.slice/nginx.service/memory.stat"
            ))
        );
        assert_eq!(
            memory_stat_path("/unihelm-uh_abc.slice/unihelm-app-uh_abc-blog.service"),
            Some(PathBuf::from(
                "/sys/fs/cgroup/unihelm-uh_abc.slice/unihelm-app-uh_abc-blog.service/memory.stat"
            ))
        );
        for refused in ["", "/", "   ", "/system.slice/../../../etc/shadow"] {
            assert_eq!(
                memory_stat_path(refused),
                None,
                "expected `{refused}` to be refused"
            );
        }
    }

    #[test]
    fn serialised_status_names_which_memory_number_it_is_carrying() {
        // The dashboard puts these side by side, so the JSON it reads has to
        // carry the distinction the field type makes.
        let mut s = status_with_memory_current(13_697_024);
        let total = serde_json::to_value(&s).unwrap();
        assert_eq!(total["memory_bytes"], 13_697_024_u64);
        assert_eq!(total["memory_source"], "cgroup_total");

        apply_memory_stat(&mut s, Some(MEMORY_STAT_V2));
        let anon = serde_json::to_value(&s).unwrap();
        assert_eq!(anon["memory_bytes"], 1_093_632_u64);
        assert_eq!(anon["memory_source"], "anonymous");
    }
}
