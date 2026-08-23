//! In-memory backends so operations are testable without root and without a
//! distribution (spec §15: "`ferrum-ops` gets a mock distro backend").
//!
//! These fakes also *record* what they were asked to do, which is what makes it
//! possible to assert "this operation opened exactly the port it said it would".

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::detect::{Arch, DistroInfo, Family};
use crate::exec::CmdOutput;
use crate::fw::{FwBackend, PortRule, Proto};
use crate::pkg::{LogSink, PackageName, PackageStatus, PkgBackend, RepoDefinition};
use crate::sec::{FileContext, PortContext, SecModule, SecModuleKind};
use crate::svc::{SvcAction, SvcBackend, UnitName, UnitState, UnitStatus};
use crate::{Distro, DistroError, Result};

/// Everything the mock backends were asked to do, in order.
#[derive(Debug, Clone, Default)]
pub struct Recorder {
    pub installed: Vec<String>,
    pub removed: Vec<String>,
    pub service_actions: Vec<(String, SvcAction)>,
    pub opened_ports: Vec<PortRule>,
    pub closed_ports: Vec<PortRule>,
    pub bans: Vec<IpAddr>,
    pub added_repos: Vec<String>,
    pub removed_repos: Vec<String>,
    pub labelled_paths: Vec<PathBuf>,
    pub log_lines: Vec<String>,
}

pub type SharedRecorder = Arc<Mutex<Recorder>>;

/// A [`LogSink`] that keeps every line, so tests can assert on task output.
pub struct RecordingLog(pub SharedRecorder);

impl LogSink for RecordingLog {
    fn line(&self, line: &str) {
        self.0
            .lock()
            .expect("recorder mutex")
            .log_lines
            .push(line.to_string());
    }
}

pub struct MockPkg {
    rec: SharedRecorder,
    state: Mutex<HashMap<String, PackageStatus>>,
}

impl MockPkg {
    pub fn new(rec: SharedRecorder) -> Self {
        Self {
            rec,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Pretend a package is already present at `version`.
    pub fn preinstall(&self, name: &str, version: &str) {
        self.state.lock().expect("mock pkg state").insert(
            name.to_string(),
            PackageStatus {
                name: name.to_string(),
                installed: true,
                installed_version: Some(version.to_string()),
                candidate_version: Some(version.to_string()),
            },
        );
    }
}

#[async_trait]
impl PkgBackend for MockPkg {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn update_index(&self, log: &dyn LogSink) -> Result<CmdOutput> {
        log.line("mock: index updated");
        Ok(ok_output("mock-update"))
    }

    async fn install(&self, packages: &[PackageName], log: &dyn LogSink) -> Result<CmdOutput> {
        for p in packages {
            // `log` may itself be a RecordingLog writing to `self.rec`, so the
            // recorder lock is never held across a call into the sink.
            log.line(&format!("mock: installing {p}"));
            self.rec
                .lock()
                .expect("recorder mutex")
                .installed
                .push(p.as_str().to_string());
            self.state.lock().expect("mock pkg state").insert(
                p.as_str().to_string(),
                PackageStatus {
                    name: p.as_str().to_string(),
                    installed: true,
                    installed_version: Some("1.0.0-mock".into()),
                    candidate_version: Some("1.0.0-mock".into()),
                },
            );
        }
        Ok(ok_output("mock-install"))
    }

    async fn remove(&self, packages: &[PackageName], log: &dyn LogSink) -> Result<CmdOutput> {
        for p in packages {
            log.line(&format!("mock: removing {p}"));
            self.rec
                .lock()
                .expect("recorder mutex")
                .removed
                .push(p.as_str().to_string());
            self.state
                .lock()
                .expect("mock pkg state")
                .remove(p.as_str());
        }
        Ok(ok_output("mock-remove"))
    }

    async fn query(&self, package: &PackageName) -> Result<PackageStatus> {
        Ok(self
            .state
            .lock()
            .expect("mock pkg state")
            .get(package.as_str())
            .cloned()
            .unwrap_or(PackageStatus {
                name: package.as_str().to_string(),
                installed: false,
                installed_version: None,
                candidate_version: Some("1.0.0-mock".into()),
            }))
    }

    async fn add_repo(
        &self,
        repo: &RepoDefinition,
        key_material: &[u8],
        _options: &[(String, String)],
        log: &dyn LogSink,
    ) -> Result<()> {
        repo.validate()?;
        // The mock must not be laxer than the real backend: an operation that
        // passes here with an unpinned key would pass its tests and fail on a
        // real server, which is the worst possible place to find out.
        let matched = crate::pgp::verify_pinned(key_material, &repo.accepted_fingerprints)?;
        log.line(&format!(
            "mock: added repo {} signed by {}",
            repo.id, matched.fingerprint
        ));
        self.rec
            .lock()
            .expect("recorder mutex")
            .added_repos
            .push(repo.id.clone());
        Ok(())
    }

    async fn remove_repo(&self, repo_id: &str) -> Result<()> {
        self.rec
            .lock()
            .expect("recorder mutex")
            .removed_repos
            .push(repo_id.to_string());
        Ok(())
    }
}

pub struct MockSvc {
    rec: SharedRecorder,
    family: Family,
    state: Mutex<HashMap<String, UnitStatus>>,
}

impl MockSvc {
    pub fn new(rec: SharedRecorder, family: Family) -> Self {
        Self {
            rec,
            family,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Seed a unit as installed and running.
    pub fn set_running(&self, unit: &str) {
        self.state.lock().expect("mock svc state").insert(
            unit.to_string(),
            UnitStatus {
                unit: unit.to_string(),
                state: UnitState::Active,
                sub_state: "running".into(),
                enabled: Some("enabled".into()),
                main_pid: Some(4242),
                memory_bytes: Some(32 * 1024 * 1024),
                since: Some("Sat 2026-08-22 10:00:00 UTC".into()),
            },
        );
    }
}

#[async_trait]
impl SvcBackend for MockSvc {
    fn family(&self) -> Family {
        self.family
    }

    async fn status(&self, unit: &UnitName) -> Result<UnitStatus> {
        Ok(self
            .state
            .lock()
            .expect("mock svc state")
            .get(unit.as_str())
            .cloned()
            .unwrap_or(UnitStatus {
                unit: unit.as_str().to_string(),
                state: UnitState::NotFound,
                sub_state: "dead".into(),
                enabled: None,
                main_pid: None,
                memory_bytes: None,
                since: None,
            }))
    }

    async fn action(&self, unit: &UnitName, action: SvcAction) -> Result<()> {
        self.rec
            .lock()
            .expect("recorder mutex")
            .service_actions
            .push((unit.as_str().to_string(), action));

        let mut state = self.state.lock().expect("mock svc state");
        let entry = state
            .entry(unit.as_str().to_string())
            .or_insert_with(|| UnitStatus {
                unit: unit.as_str().to_string(),
                state: UnitState::Inactive,
                sub_state: "dead".into(),
                enabled: Some("disabled".into()),
                main_pid: None,
                memory_bytes: None,
                since: None,
            });
        match action {
            SvcAction::Start | SvcAction::Restart | SvcAction::Reload => {
                entry.state = UnitState::Active;
                entry.sub_state = "running".into();
                entry.main_pid = Some(4242);
            }
            SvcAction::Stop => {
                entry.state = UnitState::Inactive;
                entry.sub_state = "dead".into();
                entry.main_pid = None;
            }
        }
        Ok(())
    }

    async fn enable(&self, unit: &UnitName, start_now: bool) -> Result<()> {
        self.state
            .lock()
            .expect("mock svc state")
            .entry(unit.as_str().to_string())
            .and_modify(|s| s.enabled = Some("enabled".into()));
        if start_now {
            self.action(unit, SvcAction::Start).await?;
        }
        Ok(())
    }

    async fn disable(&self, unit: &UnitName, stop_now: bool) -> Result<()> {
        self.state
            .lock()
            .expect("mock svc state")
            .entry(unit.as_str().to_string())
            .and_modify(|s| s.enabled = Some("disabled".into()));
        if stop_now {
            self.action(unit, SvcAction::Stop).await?;
        }
        Ok(())
    }

    async fn daemon_reload(&self) -> Result<()> {
        Ok(())
    }

    async fn journal_tail(&self, unit: &UnitName, lines: u32) -> Result<Vec<String>> {
        Ok((0..lines.min(3))
            .map(|i| format!("mock journal line {i} for {unit}"))
            .collect())
    }
}

pub struct MockFw {
    rec: SharedRecorder,
    rules: Mutex<Vec<PortRule>>,
    bans: Mutex<Vec<IpAddr>>,
}

impl MockFw {
    pub fn new(rec: SharedRecorder) -> Self {
        Self {
            rec,
            rules: Mutex::new(Vec::new()),
            bans: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl FwBackend for MockFw {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn is_active(&self) -> Result<bool> {
        Ok(true)
    }

    async fn open_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        self.rec
            .lock()
            .expect("recorder mutex")
            .opened_ports
            .push(rule.clone());
        self.rules.lock().expect("mock fw rules").push(rule.clone());
        Ok(())
    }

    async fn close_port(&self, rule: &PortRule) -> Result<()> {
        rule.validate()?;
        self.rec
            .lock()
            .expect("recorder mutex")
            .closed_ports
            .push(rule.clone());
        self.rules
            .lock()
            .expect("mock fw rules")
            .retain(|r| !(r.port == rule.port && r.proto == rule.proto && r.source == rule.source));
        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<PortRule>> {
        Ok(self.rules.lock().expect("mock fw rules").clone())
    }

    async fn ban_ip(&self, ip: IpAddr, _ttl_seconds: Option<u32>) -> Result<()> {
        self.rec.lock().expect("recorder mutex").bans.push(ip);
        self.bans.lock().expect("mock fw bans").push(ip);
        Ok(())
    }

    async fn unban_ip(&self, ip: IpAddr) -> Result<()> {
        self.bans.lock().expect("mock fw bans").retain(|b| *b != ip);
        Ok(())
    }

    async fn list_bans(&self) -> Result<Vec<IpAddr>> {
        Ok(self.bans.lock().expect("mock fw bans").clone())
    }
}

pub struct MockSec {
    rec: SharedRecorder,
}

impl MockSec {
    pub fn new(rec: SharedRecorder) -> Self {
        Self { rec }
    }
}

#[async_trait]
impl SecModule for MockSec {
    fn kind(&self) -> SecModuleKind {
        SecModuleKind::Selinux
    }

    async fn is_enforcing(&self) -> Result<bool> {
        Ok(true)
    }

    async fn set_file_context(&self, path: &Path, _context: FileContext) -> Result<()> {
        if !path.is_absolute() {
            return Err(DistroError::InvalidName(
                "file context paths must be absolute".into(),
            ));
        }
        self.rec
            .lock()
            .expect("recorder mutex")
            .labelled_paths
            .push(path.to_path_buf());
        Ok(())
    }

    async fn allow_port(&self, _port: u16, _proto: Proto, _context: PortContext) -> Result<()> {
        Ok(())
    }

    async fn set_boolean(&self, _name: &str, _value: bool) -> Result<()> {
        Ok(())
    }
}

/// A fully mocked Debian-family machine plus the recorder its backends write to.
pub fn mock_distro_with_recorder(family: Family) -> (Distro, SharedRecorder) {
    let rec: SharedRecorder = Arc::new(Mutex::new(Recorder::default()));
    let info = DistroInfo {
        id: match family {
            Family::Debian => "debian".into(),
            Family::Rhel => "almalinux".into(),
        },
        version_id: match family {
            Family::Debian => "13".into(),
            Family::Rhel => "10.0".into(),
        },
        codename: match family {
            Family::Debian => "trixie".into(),
            Family::Rhel => String::new(),
        },
        pretty_name: "mock distro".into(),
        family,
        arch: Arch::X86_64,
        has_systemd: true,
        has_cgroups_v2: true,
    };
    let distro = Distro {
        info,
        pkg: Arc::new(MockPkg::new(rec.clone())),
        svc: Arc::new(MockSvc::new(rec.clone(), family)),
        fw: Arc::new(MockFw::new(rec.clone())),
        sec: Arc::new(MockSec::new(rec.clone())),
    };
    (distro, rec)
}

pub fn mock_distro() -> Distro {
    mock_distro_with_recorder(Family::Debian).0
}

fn ok_output(program: &str) -> CmdOutput {
    CmdOutput {
        program: program.to_string(),
        status: 0,
        stdout: String::new(),
        stderr: String::new(),
        duration: std::time::Duration::from_millis(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::svc::ManagedUnit;

    #[tokio::test]
    async fn mock_records_what_operations_asked_for() {
        let (distro, rec) = mock_distro_with_recorder(Family::Debian);
        let log = RecordingLog(rec.clone());

        distro
            .pkg
            .install(&[PackageName::parse("nginx").unwrap()], &log)
            .await
            .unwrap();
        let unit = ManagedUnit::Nginx.unit_name(distro.info.family);
        distro.svc.action(&unit, SvcAction::Restart).await.unwrap();

        let r = rec.lock().unwrap();
        assert_eq!(r.installed, vec!["nginx"]);
        assert_eq!(
            r.service_actions,
            vec![("nginx.service".to_string(), SvcAction::Restart)]
        );
        assert!(r.log_lines.iter().any(|l| l.contains("installing nginx")));
    }

    #[tokio::test]
    async fn mock_service_state_follows_the_actions_taken() {
        let (distro, _) = mock_distro_with_recorder(Family::Rhel);
        let unit = ManagedUnit::Nginx.unit_name(Family::Rhel);

        assert_eq!(
            distro.svc.status(&unit).await.unwrap().state,
            UnitState::NotFound
        );
        distro.svc.action(&unit, SvcAction::Start).await.unwrap();
        assert!(distro.svc.status(&unit).await.unwrap().is_active());
        distro.svc.action(&unit, SvcAction::Stop).await.unwrap();
        assert!(!distro.svc.status(&unit).await.unwrap().is_active());
    }

    #[tokio::test]
    async fn recording_log_does_not_deadlock_the_recorder() {
        // The mock package backend and the log sink share one recorder; holding
        // its lock across a `log.line` call would hang forever.
        let (distro, rec) = mock_distro_with_recorder(Family::Debian);
        let log = RecordingLog(rec.clone());
        let pkgs: Vec<PackageName> = ["nginx", "php8.3-fpm"]
            .iter()
            .map(|p| PackageName::parse(p).unwrap())
            .collect();

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            distro.pkg.install(&pkgs, &log).await.unwrap();
            distro.pkg.remove(&pkgs, &log).await.unwrap();
        })
        .await
        .expect("mock backends must not deadlock against their own recorder");

        assert_eq!(rec.lock().unwrap().removed.len(), 2);
    }

    #[tokio::test]
    async fn mock_firewall_still_validates_rules() {
        let (distro, _) = mock_distro_with_recorder(Family::Debian);
        let bad = PortRule {
            port: 3306,
            proto: Proto::Tcp,
            source: Some("not-an-ip".into()),
            comment: "x".into(),
        };
        assert!(
            distro.fw.open_port(&bad).await.is_err(),
            "mocks must not be laxer than the real thing"
        );
    }
}
