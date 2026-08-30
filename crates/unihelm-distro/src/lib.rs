//! `unihelm-distro` — the **only** place operating-system differences may live
//! (spec §7.2).
//!
//! Feature modules never call `apt`, `dnf`, `systemctl`, `firewall-cmd` or
//! `semanage`. They take a [`Distro`] and call the four traits below. Adding
//! support for another distribution is then a matter of implementing the traits
//! and adding CI images — zero changes anywhere else.
//!
//! - [`PkgBackend`] — packages and GPG-pinned upstream repositories
//! - [`SvcBackend`] — unit lifecycle, enablement, journald
//! - [`FwBackend`]  — ports and IP bans
//! - [`SecModule`]  — SELinux / AppArmor contexts (never `setenforce 0`)

pub mod detect;
pub mod exec;
pub mod fw;
pub mod mock;
pub mod pgp;
pub mod pkg;
pub mod repos;
pub mod sec;
pub mod svc;

pub use detect::{Arch, DistroInfo, Family, SupportStatus};
pub use exec::{Cmd, CmdOutput};
pub use fw::{FwBackend, PortRule, Proto};
pub use pgp::{KeyFingerprint, verify_pinned};
pub use pkg::{PackageName, PkgBackend, RepoDefinition};
pub use repos::{Provenance, ResolvedRepo, catalogue};
pub use sec::{SecModule, SecModuleKind};
pub use svc::{ManagedUnit, SvcBackend, UnitName, UnitState, UnitStatus};

use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum DistroError {
    #[error("unsupported distribution: {0}")]
    UnsupportedDistro(String),

    #[error("could not read /etc/os-release: {0}")]
    OsRelease(String),

    #[error("`{0}` was not found in any trusted system directory")]
    ProgramNotFound(String),

    #[error("could not start `{program}`: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },

    #[error("`{cmd}` exited with status {status}: {output}")]
    CommandFailed {
        cmd: String,
        status: i32,
        output: String,
    },

    #[error("`{cmd}` did not finish within {seconds}s and was killed")]
    Timeout { cmd: String, seconds: u64 },

    #[error("invalid name: {0}")]
    InvalidName(String),

    #[error("service `{unit}` failed to {action}: {output}")]
    ServiceFailed {
        unit: String,
        action: String,
        output: String,
    },

    #[error("package operation failed: {0}")]
    PackageFailed(String),
}

pub type Result<T, E = DistroError> = std::result::Result<T, E>;

/// The four backends for the machine we are running on, resolved once at startup.
#[derive(Clone)]
pub struct Distro {
    pub info: DistroInfo,
    pub pkg: Arc<dyn PkgBackend>,
    pub svc: Arc<dyn SvcBackend>,
    pub fw: Arc<dyn FwBackend>,
    pub sec: Arc<dyn SecModule>,
}

impl Distro {
    /// Detect the running system and wire up the matching backends.
    ///
    /// Refuses anything outside the support matrix (spec §7.1) rather than
    /// limping along and corrupting a config later.
    pub fn detect() -> Result<Self> {
        let info = DistroInfo::detect()?;
        Self::for_info(info)
    }

    /// Build backends for an already-known system — used by the installer's
    /// preflight and by tests.
    pub fn for_info(info: DistroInfo) -> Result<Self> {
        if let SupportStatus::Unsupported(reason) = info.support_status() {
            return Err(DistroError::UnsupportedDistro(reason));
        }

        let pkg: Arc<dyn PkgBackend> = match info.family {
            Family::Debian => Arc::new(pkg::AptBackend::new()),
            Family::Rhel => Arc::new(pkg::DnfBackend::new()),
        };
        let svc: Arc<dyn SvcBackend> = Arc::new(svc::SystemdBackend::new(info.family));
        // By what is installed, not by family. A RHEL box without firewall-cmd
        // must not announce `fw: firewalld` — it did, on a live server.
        let fw: Arc<dyn FwBackend> = fw::detect(info.family);
        let sec: Arc<dyn SecModule> = sec::detect_sec_module(info.family);

        Ok(Self {
            info,
            pkg,
            svc,
            fw,
            sec,
        })
    }

    /// All backends replaced with in-memory fakes, so operations are testable
    /// without root and without a distro (spec §15).
    pub fn mock() -> Self {
        mock::mock_distro()
    }
}

impl std::fmt::Debug for Distro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Distro")
            .field("info", &self.info)
            .field("sec", &self.sec.kind())
            .finish_non_exhaustive()
    }
}
