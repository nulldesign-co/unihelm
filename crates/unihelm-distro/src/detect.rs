//! Distribution detection and the v1 support matrix (spec §7.1).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{DistroError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// Debian, Ubuntu and derivatives — `apt`, `nftables`/`ufw`, AppArmor.
    Debian,
    /// AlmaLinux, Rocky, RHEL — `dnf`, `firewalld`, SELinux.
    Rhel,
}

impl Family {
    pub const fn as_str(self) -> &'static str {
        match self {
            Family::Debian => "debian",
            Family::Rhel => "rhel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    pub fn current() -> Option<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Arch::X86_64),
            "aarch64" | "arm64" => Some(Arch::Aarch64),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }
}

/// Whether we will run here, and why not when we won't.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportStatus {
    Supported,
    /// Right family, untested release — allowed, but surfaced in the UI.
    Untested(String),
    Unsupported(String),
}

/// The parsed identity of the running system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistroInfo {
    /// `ID` from os-release: `debian`, `ubuntu`, `almalinux`, `rocky`, `rhel`.
    pub id: String,
    /// `VERSION_ID`: `13`, `24.04`, `10`.
    pub version_id: String,
    /// `VERSION_CODENAME`: `trixie`, `noble`, `resolute`. Empty on RHEL family.
    ///
    /// Debian-family repositories are addressed by codename, not by number, so
    /// this is not cosmetic — without it we cannot build a sources entry.
    pub codename: String,
    pub pretty_name: String,
    pub family: Family,
    pub arch: Arch,
    /// systemd present — a hard requirement (spec §1.3).
    pub has_systemd: bool,
    /// cgroups v2 unified hierarchy — also a hard requirement.
    pub has_cgroups_v2: bool,
}

impl DistroInfo {
    /// Read and classify `/etc/os-release`.
    pub fn detect() -> Result<Self> {
        let text = std::fs::read_to_string("/etc/os-release")
            .map_err(|e| DistroError::OsRelease(e.to_string()))?;
        let arch = Arch::current().ok_or_else(|| {
            DistroError::UnsupportedDistro(format!(
                "architecture `{}` is not supported (x86_64 and aarch64 only)",
                std::env::consts::ARCH
            ))
        })?;
        Self::from_os_release(&text, arch)
    }

    /// Parse an os-release document. Split out so the support matrix is testable
    /// without a container per distribution.
    pub fn from_os_release(text: &str, arch: Arch) -> Result<Self> {
        let mut id = String::new();
        let mut id_like = String::new();
        let mut version_id = String::new();
        let mut codename = String::new();
        let mut ubuntu_codename = String::new();
        let mut pretty_name = String::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            // os-release values may be quoted; the quotes are not part of the value.
            let value = value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            match key.trim() {
                "ID" => id = value.to_ascii_lowercase(),
                "ID_LIKE" => id_like = value.to_ascii_lowercase(),
                "VERSION_ID" => version_id = value,
                "VERSION_CODENAME" => codename = value.to_ascii_lowercase(),
                // On Ubuntu derivatives (Mint, Pop) VERSION_CODENAME is the
                // derivative's own name and no upstream repository has a suite
                // for it; UBUNTU_CODENAME names the Ubuntu release underneath.
                "UBUNTU_CODENAME" => ubuntu_codename = value.to_ascii_lowercase(),
                "PRETTY_NAME" => pretty_name = value,
                _ => {}
            }
        }

        if id.is_empty() {
            return Err(DistroError::OsRelease("no ID field".into()));
        }

        let family = classify_family(&id, &id_like).ok_or_else(|| {
            DistroError::UnsupportedDistro(format!(
                "`{id}` is neither a Debian-family nor an RHEL-family system"
            ))
        })?;

        if pretty_name.is_empty() {
            pretty_name = format!("{id} {version_id}");
        }

        if !ubuntu_codename.is_empty() {
            codename = ubuntu_codename;
        }

        Ok(Self {
            id,
            version_id,
            codename,
            pretty_name,
            family,
            arch,
            has_systemd: Path::new("/run/systemd/system").exists(),
            has_cgroups_v2: Path::new("/sys/fs/cgroup/cgroup.controls").exists()
                || Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        })
    }

    /// Major version as a number, for range comparisons (`24.04` → 24).
    pub fn major(&self) -> Option<u32> {
        self.version_id.split('.').next()?.parse().ok()
    }

    /// Check against the v1 support matrix (spec §7.1).
    ///
    /// The installer's preflight refuses [`SupportStatus::Unsupported`] with a
    /// clear message rather than failing halfway through provisioning.
    pub fn support_status(&self) -> SupportStatus {
        let Some(major) = self.major() else {
            return SupportStatus::Unsupported(format!(
                "could not parse VERSION_ID `{}`",
                self.version_id
            ));
        };

        match self.id.as_str() {
            "debian" if (12..=13).contains(&major) => SupportStatus::Supported,
            "ubuntu" => match self.version_id.as_str() {
                "22.04" | "24.04" | "26.04" => SupportStatus::Supported,
                other => SupportStatus::Untested(format!("Ubuntu {other} is not an LTS we test")),
            },
            "almalinux" | "rocky" | "rhel" if (9..=10).contains(&major) => SupportStatus::Supported,
            "debian" | "almalinux" | "rocky" | "rhel" => SupportStatus::Untested(format!(
                "{} {} is outside the tested range",
                self.id, self.version_id
            )),
            other => SupportStatus::Untested(format!(
                "`{other}` is a {} derivative we have not tested",
                self.family.as_str()
            )),
        }
    }

    /// Everything the installer preflight must confirm before it touches the disk.
    pub fn preflight(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if let SupportStatus::Unsupported(reason) = self.support_status() {
            problems.push(reason);
        }
        if !self.has_systemd {
            problems.push("systemd is required (no /run/systemd/system)".into());
        }
        if !self.has_cgroups_v2 {
            problems.push(
                "cgroups v2 unified hierarchy is required; boot with systemd.unified_cgroup_hierarchy=1"
                    .into(),
            );
        }
        problems
    }
}

fn classify_family(id: &str, id_like: &str) -> Option<Family> {
    const DEBIAN_IDS: &[&str] = &["debian", "ubuntu", "linuxmint", "pop", "raspbian", "devuan"];
    const RHEL_IDS: &[&str] = &[
        "rhel",
        "almalinux",
        "rocky",
        "centos",
        "fedora",
        "ol",
        "oracle",
        "cloudlinux",
    ];

    if DEBIAN_IDS.contains(&id) {
        return Some(Family::Debian);
    }
    if RHEL_IDS.contains(&id) {
        return Some(Family::Rhel);
    }
    // ID_LIKE is a space-separated list of parent distributions.
    for like in id_like.split_whitespace() {
        if DEBIAN_IDS.contains(&like) {
            return Some(Family::Debian);
        }
        if RHEL_IDS.contains(&like) {
            return Some(Family::Rhel);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<DistroInfo> {
        DistroInfo::from_os_release(text, Arch::X86_64)
    }

    #[test]
    fn debian_13() {
        let info = parse(
            r#"PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
ID=debian"#,
        )
        .unwrap();
        assert_eq!(info.family, Family::Debian);
        assert_eq!(info.major(), Some(13));
        assert_eq!(info.support_status(), SupportStatus::Supported);
    }

    #[test]
    fn ubuntu_lts_versus_interim() {
        let lts = parse("ID=ubuntu\nVERSION_ID=\"24.04\"\nID_LIKE=debian").unwrap();
        assert_eq!(lts.support_status(), SupportStatus::Supported);
        let interim = parse("ID=ubuntu\nVERSION_ID=\"25.10\"\nID_LIKE=debian").unwrap();
        assert!(matches!(
            interim.support_status(),
            SupportStatus::Untested(_)
        ));
    }

    #[test]
    fn almalinux_10() {
        let info = parse(
            r#"NAME="AlmaLinux"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="10.0""#,
        )
        .unwrap();
        assert_eq!(info.family, Family::Rhel);
        assert_eq!(info.major(), Some(10));
        assert_eq!(info.support_status(), SupportStatus::Supported);
    }

    #[test]
    fn rocky_and_rhel_are_the_same_family() {
        for id in ["rocky", "rhel", "centos"] {
            let info = parse(&format!("ID={id}\nVERSION_ID=\"9.4\"")).unwrap();
            assert_eq!(info.family, Family::Rhel, "{id}");
        }
    }

    #[test]
    fn id_like_rescues_an_unknown_derivative() {
        let info = parse("ID=somederivative\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"1\"").unwrap();
        assert_eq!(info.family, Family::Debian);
        assert!(matches!(info.support_status(), SupportStatus::Untested(_)));
    }

    #[test]
    fn truly_unknown_systems_are_rejected() {
        assert!(parse("ID=alpine\nVERSION_ID=\"3.20\"").is_err());
        assert!(parse("ID=arch").is_err_or_untested());
        assert!(
            parse("VERSION_ID=1").is_err(),
            "an os-release with no ID is unusable"
        );
    }

    #[test]
    fn the_codename_is_captured_because_apt_suites_need_it() {
        let info = parse("ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie").unwrap();
        assert_eq!(info.codename, "trixie");
        let info = parse("ID=ubuntu\nVERSION_ID=\"26.04\"\nVERSION_CODENAME=resolute").unwrap();
        assert_eq!(info.codename, "resolute");
    }

    #[test]
    fn an_ubuntu_derivative_uses_the_ubuntu_codename_underneath() {
        // Linux Mint 22 reports VERSION_CODENAME=wilma, but no upstream
        // repository publishes a `wilma` suite — `noble` is the one to use.
        let info = parse(
            "ID=linuxmint\nID_LIKE=ubuntu\nVERSION_ID=\"22\"\nVERSION_CODENAME=wilma\nUBUNTU_CODENAME=noble",
        )
        .unwrap();
        assert_eq!(info.codename, "noble");
    }

    #[test]
    fn quoted_and_unquoted_values_both_parse() {
        let a = parse("ID=debian\nVERSION_ID=13").unwrap();
        let b = parse("ID=\"debian\"\nVERSION_ID=\"13\"").unwrap();
        assert_eq!(a.version_id, b.version_id);
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let info = parse("# a comment\n\nID=debian\nVERSION_ID=13\n\n").unwrap();
        assert_eq!(info.id, "debian");
    }

    #[test]
    fn preflight_reports_every_blocker_at_once() {
        let mut info = parse("ID=debian\nVERSION_ID=13").unwrap();
        info.has_systemd = false;
        info.has_cgroups_v2 = false;
        let problems = info.preflight();
        assert_eq!(
            problems.len(),
            2,
            "preflight should not stop at the first problem"
        );
    }

    // Small helper so the "unknown system" test reads clearly.
    trait ErrOrUntested {
        fn is_err_or_untested(&self) -> bool;
    }
    impl ErrOrUntested for Result<DistroInfo> {
        fn is_err_or_untested(&self) -> bool {
            match self {
                Err(_) => true,
                Ok(i) => !matches!(i.support_status(), SupportStatus::Supported),
            }
        }
    }
}
