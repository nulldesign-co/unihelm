//! Whether this machine is running the software it has installed (spec §7.2).
//!
//! A kernel or glibc update replaces files on disk. The running kernel and the
//! processes already mapped against the old libraries keep going, unchanged,
//! until the machine restarts — so a server can apply every security update it
//! has and still be exposed to the vulnerability those updates closed. The
//! panel used to say nothing about this at all, which meant an operator who
//! installed updates from the Updates page was told the work succeeded and had
//! no way to learn that their kernel patch was not actually running.
//!
//! Each family answers the question its own way, and this is the only place
//! that difference is allowed to live:
//!
//! - **Debian and Ubuntu** write [`DEBIAN_MARKER`], with the packages that
//!   asked for it in [`DEBIAN_MARKER_PKGS`].
//! - **The EL family** answers `needs-restarting -r`, which exits 0 for "no"
//!   and 1 for "yes" and prints what was updated.
//!
//! # Absence is not an answer
//!
//! The marker file is created by `notify-reboot-required`, which ships in
//! `update-notifier-common`. On a machine without that package **nothing ever
//! creates the file**, so reading its absence as "no restart needed" would be a
//! clean bill of health derived from a mechanism that is not installed. That is
//! why [`debian_requirement`] looks for the writer as well as the file, and why
//! `needs-restarting` being absent is [`RebootRequirement::Unknown`] rather
//! than a "no": the panel is allowed to say it could not tell, and is not
//! allowed to say "no" when it could not tell.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use crate::detect::Family;
use crate::exec::Cmd;
use crate::{DistroError, Result};

/// Created by `notify-reboot-required` when a package needs the machine
/// restarted. `/var/run` is a symlink to `/run` on both families.
pub const DEBIAN_MARKER: &str = "/var/run/reboot-required";

/// One package name per line, appended to as more packages ask. Duplicated
/// entries are normal — every kernel upgrade in a run adds its own.
pub const DEBIAN_MARKER_PKGS: &str = "/var/run/reboot-required.pkgs";

/// The script every Debian-family package calls to create [`DEBIAN_MARKER`].
/// Its absence means the marker will never appear, however stale the kernel is.
pub const DEBIAN_NOTIFIER: &str = "/usr/share/update-notifier/notify-reboot-required";

/// `needs-restarting` is not part of dnf; it ships in `dnf-utils`.
const NEEDS_RESTARTING: &str = "needs-restarting";

/// A ceiling on the EL probe. `needs-restarting -r` reads `/proc` and the RPM
/// database and normally answers in under a second; this exists so a wedged
/// rpmdb lock cannot hold a dashboard request open.
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// Whether this machine is waiting for a restart, or whether that could not be
/// established.
///
/// Three states, not two. `Option<bool>` would have worked and would have been
/// the wrong shape: the whole reason this module exists is that "this server
/// does not need rebooting" and "the panel could not tell" must never render as
/// the same sentence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RebootRequirement {
    /// The distribution's own mechanism was consulted and says no.
    NotRequired,
    Required {
        /// What asked for the restart, when the system named it. Empty is
        /// legitimate: the marker file can exist with no `.pkgs` beside it.
        packages: Vec<String>,
        /// What was read or run to establish this, so an operator can check it
        /// by hand rather than take the panel's word.
        evidence: String,
    },
    /// The check could not be run, with what stopped it. Deliberately *not*
    /// the same as [`RebootRequirement::NotRequired`].
    Unknown { reason: String },
}

impl RebootRequirement {
    /// True only for [`RebootRequirement::Required`] — an unknown is not a yes
    /// any more than it is a no.
    pub fn is_required(&self) -> bool {
        matches!(self, RebootRequirement::Required { .. })
    }

    /// The packages that asked for the restart; empty for every other state.
    pub fn packages(&self) -> &[String] {
        match self {
            RebootRequirement::Required { packages, .. } => packages,
            _ => &[],
        }
    }
}

/// Where the Debian-family answer is read from.
///
/// Three paths rather than three constants used directly, so the whole decision
/// table — marker present, marker absent with a writer, marker absent without
/// one — is testable against a temporary directory instead of only on a machine
/// that happens to be in the right state.
#[derive(Debug, Clone)]
pub struct DebianPaths {
    pub marker: PathBuf,
    pub packages: PathBuf,
    pub notifier: PathBuf,
}

impl Default for DebianPaths {
    fn default() -> Self {
        Self {
            marker: PathBuf::from(DEBIAN_MARKER),
            packages: PathBuf::from(DEBIAN_MARKER_PKGS),
            notifier: PathBuf::from(DEBIAN_NOTIFIER),
        }
    }
}

/// Package names from a `reboot-required.pkgs` file.
///
/// One name per line, and repeats are the norm — the file is appended to, so a
/// machine that took two kernel updates before anyone looked lists the same
/// package twice. First-seen order is kept rather than sorted: the package that
/// asked first is usually the kernel, and that is the name an operator needs to
/// see at the front of a sentence.
pub fn parse_reboot_required_pkgs(text: &str) -> Vec<String> {
    let mut seen = Vec::new();
    for line in text.lines() {
        let name = line.trim();
        if name.is_empty() || seen.iter().any(|s| s == name) {
            continue;
        }
        seen.push(name.to_string());
    }
    seen
}

/// Package names from `needs-restarting -r` output.
///
/// The output is a sentence, a bulleted list and another sentence:
///
/// ```text
/// Core libraries or services have been updated since boot-up:
///   * kernel
///   * systemd
///
/// Reboot is required to fully utilize these updates.
/// ```
///
/// Only the bullets are names. Parsed here rather than with a `grep` in a
/// pipeline, so it can be tested (spec §12 rule 2).
pub fn parse_needs_restarting(output: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in output.lines() {
        let Some(rest) = line.trim().strip_prefix('*') else {
            continue;
        };
        let name = rest.trim();
        if name.is_empty() || names.iter().any(|s| s == name) {
            continue;
        }
        names.push(name.to_string());
    }
    names
}

/// Does this `needs-restarting -r` output actually say a reboot is wanted?
///
/// Exit status 1 is documented as "reboot required", but a broken install exits
/// 1 too — a missing Python module produces a traceback and the same status. So
/// the status is corroborated against the sentence the tool prints. Wording has
/// changed between EL releases ("to fully utilize these updates" became "to
/// ensure that your system benefits from these updates"); the stable half is
/// the opening clause, and matching only that is what keeps a future rewording
/// from turning a needed reboot into a confident "no".
fn says_reboot_required(output: &str) -> bool {
    output.to_ascii_lowercase().contains("reboot is required")
}

/// The Debian-family answer, from paths rather than from the filesystem root,
/// so every branch is reachable from a test.
pub fn debian_requirement(paths: &DebianPaths) -> RebootRequirement {
    match std::fs::metadata(&paths.marker) {
        Ok(_) => {
            // The marker is the answer; the package list is detail. A marker
            // with no readable `.pkgs` beside it still means "restart this
            // machine", and dropping the finding because the detail is missing
            // would lose the only signal that matters.
            let packages = std::fs::read_to_string(&paths.packages)
                .map(|text| parse_reboot_required_pkgs(&text))
                .unwrap_or_default();
            RebootRequirement::Required {
                packages,
                evidence: format!("{} exists", paths.marker.display()),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if paths.notifier.exists() {
                RebootRequirement::NotRequired
            } else {
                RebootRequirement::Unknown {
                    reason: format!(
                        "{} is absent, but so is {} — the script every package calls to \
                         create it. Nothing on this machine will ever write that file, so \
                         its absence says nothing about the kernel that is running. \
                         Install `update-notifier-common` to make this check work.",
                        paths.marker.display(),
                        paths.notifier.display()
                    ),
                }
            }
        }
        Err(e) => RebootRequirement::Unknown {
            reason: format!("{} could not be read: {e}", paths.marker.display()),
        },
    }
}

/// The EL-family answer, from `needs-restarting -r`.
pub async fn rhel_requirement() -> RebootRequirement {
    let result = Cmd::new(NEEDS_RESTARTING)
        .arg("-r")
        .timeout(PROBE_TIMEOUT)
        .run()
        .await;

    let out = match result {
        Ok(out) => out,
        // Overwhelmingly this is `dnf-utils` not being installed, and naming
        // the package is the difference between a dead end and a one-line fix.
        Err(e) => {
            return RebootRequirement::Unknown {
                reason: format!(
                    "`{NEEDS_RESTARTING} -r` could not be run: {e}. It ships in \
                     `dnf-utils`; install that and this check starts working."
                ),
            };
        }
    };

    match out.status {
        0 => RebootRequirement::NotRequired,
        1 if says_reboot_required(&out.stdout) => RebootRequirement::Required {
            packages: parse_needs_restarting(&out.stdout),
            evidence: format!("`{NEEDS_RESTARTING} -r` reports a restart is required"),
        },
        status => RebootRequirement::Unknown {
            reason: format!(
                "`{NEEDS_RESTARTING} -r` exited {status} without saying whether a restart \
                 is needed: {}",
                out.failure_text()
            ),
        },
    }
}

/// Ask this machine whether it is waiting for a restart.
///
/// The family decides which mechanism is authoritative; nothing above this
/// module needs to know that Debian keeps a file and EL runs a tool.
pub async fn reboot_requirement(family: Family) -> RebootRequirement {
    match family {
        Family::Debian => debian_requirement(&DebianPaths::default()),
        Family::Rhel => rhel_requirement().await,
    }
}

/// This machine's hostname.
///
/// Read from the kernel rather than from `/etc/hostname`, which is the name the
/// machine was configured with and not necessarily the one it is running under
/// — a DHCP lease or a cloud-init datasource changes the live name without
/// rewriting the file. `gethostname(2)` is what `hostname` prints, and this is
/// where the kernel publishes it.
pub fn hostname() -> Result<String> {
    const PROC_HOSTNAME: &str = "/proc/sys/kernel/hostname";
    let raw = std::fs::read_to_string(Path::new(PROC_HOSTNAME))
        .map_err(|e| DistroError::OsRelease(format!("{PROC_HOSTNAME}: {e}")))?;
    let name = raw.trim();
    if name.is_empty() {
        return Err(DistroError::OsRelease(format!(
            "{PROC_HOSTNAME} is empty, so this machine has no name to confirm against"
        )));
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths_in(dir: &Path) -> DebianPaths {
        DebianPaths {
            marker: dir.join("reboot-required"),
            packages: dir.join("reboot-required.pkgs"),
            notifier: dir.join("notify-reboot-required"),
        }
    }

    #[test]
    fn a_debian_machine_with_the_marker_names_the_packages_that_asked_for_it() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        std::fs::write(&paths.marker, "*** System restart required ***\n").unwrap();
        std::fs::write(
            &paths.packages,
            "linux-image-6.8.0-45-generic\nlinux-base\nlinux-image-6.8.0-45-generic\n",
        )
        .unwrap();

        let found = debian_requirement(&paths);
        assert!(found.is_required());
        assert_eq!(
            found.packages(),
            ["linux-image-6.8.0-45-generic", "linux-base"],
            "duplicates are the norm in that file and must not reach an operator"
        );
    }

    #[test]
    fn a_marker_with_no_package_list_is_still_a_required_reboot() {
        // The `.pkgs` file is written by the same script but is not guaranteed
        // to be there — an operator who deleted it, or a package that called
        // the script with no argument. Losing the finding because the detail is
        // missing would drop the only signal that matters.
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        std::fs::write(&paths.marker, "").unwrap();

        let found = debian_requirement(&paths);
        assert!(found.is_required());
        assert!(found.packages().is_empty());
    }

    #[test]
    fn a_machine_that_cannot_create_the_marker_reports_unknown_rather_than_no() {
        // The defect this whole module exists for, in its quietest form. On a
        // Debian install without `update-notifier-common` nothing ever writes
        // `/var/run/reboot-required`, so reading its absence as "no restart
        // needed" is a clean bill of health from a mechanism that is not
        // installed — the panel telling an operator their kernel patch is live
        // when it is not.
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());

        match debian_requirement(&paths) {
            RebootRequirement::Unknown { reason } => {
                assert!(reason.contains("update-notifier-common"), "{reason}");
            }
            other => panic!("expected unknown without the notifier script, got {other:?}"),
        }
    }

    #[test]
    fn a_machine_with_the_writer_and_no_marker_is_a_real_no() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        std::fs::write(&paths.notifier, "#!/bin/sh\n").unwrap();

        assert_eq!(debian_requirement(&paths), RebootRequirement::NotRequired);
    }

    #[test]
    fn needs_restarting_bullets_are_the_package_names() {
        let output = "Core libraries or services have been updated since boot-up:\n  \
                      * kernel\n  * systemd\n  * kernel\n\n\
                      Reboot is required to fully utilize these updates.\n";
        assert_eq!(parse_needs_restarting(output), ["kernel", "systemd"]);
        assert!(says_reboot_required(output));
    }

    #[test]
    fn the_newer_el_wording_still_reads_as_a_required_reboot() {
        // EL9 rewrote the sentence. Matching the whole of the old one would
        // have turned a needed reboot into a confident "no" on every EL9 box.
        assert!(says_reboot_required(
            "Reboot is required to ensure that your system benefits from these updates.\n"
        ));
    }

    #[test]
    fn output_that_does_not_say_a_reboot_is_needed_is_not_read_as_one() {
        assert!(!says_reboot_required(
            "No core libraries or services have been updated since boot-up.\n"
        ));
        assert!(parse_needs_restarting("").is_empty());
    }

    #[test]
    fn an_unknown_is_neither_required_nor_a_package_list() {
        let unknown = RebootRequirement::Unknown {
            reason: "nothing to read".into(),
        };
        assert!(!unknown.is_required());
        assert!(unknown.packages().is_empty());
    }

    #[test]
    fn the_three_states_serialise_apart() {
        let json = |r: &RebootRequirement| serde_json::to_value(r).unwrap();
        assert_eq!(
            json(&RebootRequirement::NotRequired)["state"],
            "not_required"
        );
        assert_eq!(
            json(&RebootRequirement::Unknown {
                reason: "no".into()
            })["state"],
            "unknown"
        );
        let required = json(&RebootRequirement::Required {
            packages: vec!["kernel".into()],
            evidence: "marker".into(),
        });
        assert_eq!(required["state"], "required");
        assert_eq!(required["packages"][0], "kernel");
    }
}
