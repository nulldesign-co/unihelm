//! The upstream repository catalogue (spec §7.3).
//!
//! Ferrum installs from the vendors' own repositories and nothing else. That is
//! what makes security updates somebody else's job instead of ours, and it is
//! the single biggest operational difference from panels that compile PHP on a
//! customer's server.
//!
//! Every entry pins its signing key by **full fingerprint**. The pin is checked
//! against the key we actually download, before a single line is written to
//! `sources.list.d` or `yum.repos.d`, by [`crate::pgp::verify_pinned`].
//!
//! # Provenance
//!
//! Each entry records where its fingerprint came from and how confident we are.
//! This matters more than it looks: **nginx's own documentation page is stale**.
//! It still tells you to verify `573BFD6B…`, but the key signing the repository
//! today is `8540A6F1…` — pinning only what the docs say would break every
//! install. Entries below carry every key in the vendor's published bundle so a
//! rotation is not an outage.
//!
//! Every pin below has been checked against the key material the vendor is
//! actually serving, by Ferrum's own OpenPGP parser:
//!
//! ```text
//! cargo run -p ferrum-distro --example verify-pins
//! ```
//!
//! That proves the pin matches what is served *today*. It does **not** prove
//! that what is served is the legitimate vendor key — a compromised mirror would
//! serve its own, and we would faithfully pin that. The stronger assurance comes
//! from a fingerprint the vendor publishes somewhere other than the key file
//! itself, and [`UNVERIFIED_PINS`] lists the repositories where no such
//! out-of-band value exists (or, for nginx, where the published value is not the
//! key currently signing). Those want a human to confirm before a public
//! release; the constant keeps that from being a matter of memory.

use crate::detect::{DistroInfo, Family};
use crate::pkg::RepoDefinition;

/// How much a fingerprint has been checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Cross-checked from at least two independent routes (for example the
    /// vendor's published value *and* a signature on live repository metadata).
    Corroborated,
    /// Established once, from the source named in the entry. Usable, but must be
    /// confirmed out of band before shipping.
    SingleSource,
}

/// Repositories where no vendor-published fingerprint corroborates the key we
/// pin, so the pin rests on the key material alone.
///
/// - `nginx` — the docs publish `573BFD6B…`, which is in the bundle but is *not*
///   the key signing the repository today. The active signer has no published
///   value to compare against.
/// - `docker-ce` — Docker removed the fingerprint from its Debian and Ubuntu
///   install docs entirely. (Its RPM fingerprint *is* still published, and
///   matches.)
/// - `php-sury` — the `Signed-By:` field and the keyring `.deb` both agree, but
///   both come from the same origin as the key.
/// - `php-remi` — `KEYS.txt` agrees, and again shares an origin with the key.
///
/// A release checklist item, kept in code so it cannot be forgotten in a wiki.
pub const UNVERIFIED_PINS: &[&str] = &["nginx", "docker-ce", "php-sury", "php-remi"];

/// nginx.org publishes three keys in one file.
///
/// All three are pinned deliberately: the first is the current signer, the
/// second is the legacy key that still verifies older packages, and the third is
/// staged for a future rotation. Pinning the future key now means the rotation
/// will not break installs on servers that have not been updated.
const NGINX_KEYS: &[&str] = &[
    // "nginx signing key <signing-key-2@nginx.com>", RSA-4096, 2024-05-29.
    // Currently signs Release.gpg / repomd.xml.asc on both families.
    "8540A6F18833A80E9C1653A42FD21310B49F6B46",
    // "nginx signing key <signing-key@nginx.com>", RSA-2048, 2011-08-19,
    // expires 2027-05-24. This is the one nginx.org's docs still advertise.
    "573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62",
    // "nginx signing key <signing-key-3@nginx.com>", RSA-4096, 2024-05-29.
    // Not yet signing anything; pinned ahead of the rotation.
    "9E9BE90EACBCDE69FE9B204CBCDCD8A38D88A2B3",
];

/// Docker's deb and rpm repositories use *different* keys.
const DOCKER_DEB_KEY: &str = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88";
const DOCKER_RPM_KEY: &str = "060A61C51B558A7F742B77AAC52FEB6B621E9F35";

/// deb.sury.org. Surý extends this key rather than rotating it, so the
/// fingerprint has been stable since 2019 — but the key *blob* changes on each
/// renewal, which is exactly why we pin the fingerprint and not a file hash.
const SURY_KEY: &str = "15058500A0235D97F5D10063B188E2B695BD4743";

/// Remi's key is chosen per EL major version, not per repository.
fn remi_key(major: u32) -> Option<&'static str> {
    match major {
        9 => Some("B1ABF71E14C9D74897E198A8B19527F1478F8947"), // RPM-GPG-KEY-remi2021
        10 => Some("CF1DF0057CE85DFF5B2F2A37C2FD3B2C2A0948E4"), // RPM-GPG-KEY-remi2024
        _ => None,
    }
}

/// A repository, resolved for one specific machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRepo {
    pub definition: RepoDefinition,
    pub provenance: Provenance,
    /// Where the pinned fingerprint was read from, for the audit trail.
    pub source: String,
    /// Extra `key = value` lines for a `.repo` file (RHEL only).
    pub options: Vec<(String, String)>,
}

/// nginx from nginx.org.
pub fn nginx(info: &DistroInfo) -> Result<ResolvedRepo, String> {
    let fingerprints: Vec<String> = NGINX_KEYS.iter().map(|s| s.to_string()).collect();

    let definition = match info.family {
        Family::Debian => {
            let path = if info.id == "ubuntu" {
                "ubuntu"
            } else {
                "debian"
            };
            RepoDefinition {
                id: "nginx".into(),
                display_name: "nginx.org stable".into(),
                base_url: format!("https://nginx.org/packages/{path}"),
                suite: Some(require_codename(info)?),
                // nginx's component is `nginx`, not `main` — a detail that costs
                // an hour if you assume otherwise.
                components: vec!["nginx".into()],
                gpg_key_url: "https://nginx.org/keys/nginx_signing.key".into(),
                accepted_fingerprints: fingerprints,
            }
        }
        Family::Rhel => {
            let major = require_major(info)?;
            RepoDefinition {
                id: "nginx".into(),
                display_name: "nginx.org stable".into(),
                // AlmaLinux and Rocky both use the `centos` tree; there is no
                // separate almalinux/ path. The major version is substituted
                // here rather than left as `$releasever`, which on RHEL proper
                // can expand to `9.6` and 404.
                base_url: format!(
                    "https://nginx.org/packages/centos/{major}/{}",
                    arch_dir(info)
                ),
                suite: None,
                components: Vec::new(),
                gpg_key_url: "https://nginx.org/keys/nginx_signing.key".into(),
                accepted_fingerprints: fingerprints,
            }
        }
    };

    Ok(ResolvedRepo {
        definition,
        provenance: Provenance::SingleSource,
        source: "key material served at https://nginx.org/keys/nginx_signing.key, \
                 cross-checked against the issuer-fingerprint on live repository signatures"
            .into(),
        options: match info.family {
            // Without this, EL8+ prefers the distribution's own `nginx` module
            // stream and the nginx.org packages are shadowed.
            Family::Rhel => vec![("module_hotfixes".into(), "true".into())],
            Family::Debian => Vec::new(),
        },
    })
}

/// PHP: Sury on the Debian family, Remi on the RHEL family.
pub fn php(info: &DistroInfo) -> Result<ResolvedRepo, String> {
    match info.family {
        Family::Debian => Ok(ResolvedRepo {
            definition: RepoDefinition {
                id: "php-sury".into(),
                display_name: "Ondřej Surý PHP (deb.sury.org)".into(),
                // One repository serves Debian and Ubuntu alike, including
                // Ubuntu 26.04 (`resolute`) — which the ondrej/php PPA does not.
                base_url: "https://packages.sury.org/php".into(),
                suite: Some(require_codename(info)?),
                components: vec!["main".into()],
                gpg_key_url: "https://packages.sury.org/php/apt.gpg".into(),
                accepted_fingerprints: vec![SURY_KEY.to_string()],
            },
            provenance: Provenance::SingleSource,
            source: "the `Signed-By:` field published in \
                     https://packages.sury.org/php/dists/*/Release, corroborated against \
                     the keyring shipped in debsuryorg-archive-keyring.deb"
                .into(),
            options: Vec::new(),
        }),

        Family::Rhel => {
            let major = require_major(info)?;
            let key = remi_key(major).ok_or_else(|| {
                format!(
                    "no Remi signing key is pinned for EL{major}; add one before enabling PHP here"
                )
            })?;
            Ok(ResolvedRepo {
                definition: RepoDefinition {
                    id: "php-remi".into(),
                    display_name: "Remi's RPM repository (safe)".into(),
                    // `safe`, not the full `remi` repository: safe only adds
                    // packages and never replaces a base-OS one, and it carries
                    // the whole php83-*/php84-* set we need anyway.
                    base_url: format!(
                        "https://rpms.remirepo.net/enterprise/{major}/safe/{}",
                        arch_dir(info)
                    ),
                    suite: None,
                    components: Vec::new(),
                    gpg_key_url: format!(
                        "https://rpms.remirepo.net/RPM-GPG-KEY-remi{}",
                        if major >= 10 { "2024" } else { "2021" }
                    ),
                    accepted_fingerprints: vec![key.to_string()],
                },
                provenance: Provenance::SingleSource,
                source: format!(
                    "resolved from remi-release-{major}.rpm, whose \
                     /etc/pki/rpm-gpg/RPM-GPG-KEY-remi.el{major} symlink names the key; \
                     matches the entry in https://rpms.remirepo.net/KEYS.txt"
                ),
                options: Vec::new(),
            })
        }
    }
}

/// Docker CE, installed on demand the first time a container feature is used.
pub fn docker(info: &DistroInfo) -> Result<ResolvedRepo, String> {
    match info.family {
        Family::Debian => {
            let path = if info.id == "ubuntu" {
                "ubuntu"
            } else {
                "debian"
            };
            Ok(ResolvedRepo {
                definition: RepoDefinition {
                    id: "docker-ce".into(),
                    display_name: "Docker CE".into(),
                    base_url: format!("https://download.docker.com/linux/{path}"),
                    suite: Some(require_codename(info)?),
                    // `stable` only. The repository also publishes edge, test and
                    // nightly, none of which belong on a hosting server.
                    components: vec!["stable".into()],
                    gpg_key_url: format!("https://download.docker.com/linux/{path}/gpg"),
                    accepted_fingerprints: vec![DOCKER_DEB_KEY.to_string()],
                },
                provenance: Provenance::SingleSource,
                source: "the key material Docker serves at /linux/{debian,ubuntu}/gpg — \
                         Docker removed the fingerprint from its own install docs, so \
                         there is no vendor-published value to compare against"
                    .into(),
                options: Vec::new(),
            })
        }
        Family::Rhel => {
            let major = require_major(info)?;
            Ok(ResolvedRepo {
                definition: RepoDefinition {
                    id: "docker-ce".into(),
                    display_name: "Docker CE".into(),
                    base_url: format!(
                        "https://download.docker.com/linux/centos/{major}/{}/stable",
                        arch_dir(info)
                    ),
                    suite: None,
                    components: Vec::new(),
                    gpg_key_url: "https://download.docker.com/linux/centos/gpg".into(),
                    // A different key from the deb one. Reusing the deb pin here
                    // would reject every RPM.
                    accepted_fingerprints: vec![DOCKER_RPM_KEY.to_string()],
                },
                provenance: Provenance::Corroborated,
                source: "published verbatim on https://docs.docker.com/engine/install/centos/ \
                         and confirmed against the served key material"
                    .into(),
                options: Vec::new(),
            })
        }
    }
}

/// Every repository Ferrum knows how to add on this machine.
pub fn catalogue(info: &DistroInfo) -> Vec<ResolvedRepo> {
    [nginx(info), php(info), docker(info)]
        .into_iter()
        .flatten()
        .collect()
}

fn require_codename(info: &DistroInfo) -> Result<String, String> {
    if info.codename.is_empty() {
        return Err(format!(
            "{} does not report VERSION_CODENAME, so no apt suite can be determined",
            info.pretty_name
        ));
    }
    Ok(info.codename.clone())
}

fn require_major(info: &DistroInfo) -> Result<u32, String> {
    info.major().ok_or_else(|| {
        format!(
            "could not determine a major version from `{}`",
            info.version_id
        )
    })
}

/// The directory name vendors use for this architecture.
fn arch_dir(info: &DistroInfo) -> &'static str {
    match info.arch {
        crate::detect::Arch::X86_64 => "x86_64",
        crate::detect::Arch::Aarch64 => "aarch64",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Arch;

    fn debian(codename: &str, id: &str, version: &str) -> DistroInfo {
        DistroInfo {
            id: id.into(),
            version_id: version.into(),
            codename: codename.into(),
            pretty_name: format!("{id} {version}"),
            family: Family::Debian,
            arch: Arch::X86_64,
            has_systemd: true,
            has_cgroups_v2: true,
        }
    }

    fn rhel(major: &str, arch: Arch) -> DistroInfo {
        DistroInfo {
            id: "almalinux".into(),
            version_id: format!("{major}.0"),
            codename: String::new(),
            pretty_name: format!("AlmaLinux {major}"),
            family: Family::Rhel,
            arch,
            has_systemd: true,
            has_cgroups_v2: true,
        }
    }

    #[test]
    fn every_pinned_fingerprint_is_a_full_one() {
        // A short key id is forgeable; a pin you can collide is decorative.
        for info in [
            debian("trixie", "debian", "13"),
            rhel("9", Arch::X86_64),
            rhel("10", Arch::Aarch64),
        ] {
            for repo in catalogue(&info) {
                assert!(
                    !repo.definition.accepted_fingerprints.is_empty(),
                    "{} has no pinned key",
                    repo.definition.id
                );
                for fp in &repo.definition.accepted_fingerprints {
                    assert_eq!(
                        fp.len(),
                        40,
                        "{} pin `{fp}` is not 40 hex characters",
                        repo.definition.id
                    );
                    assert!(
                        fp.chars()
                            .all(|c| c.is_ascii_hexdigit() && !c.is_lowercase())
                    );
                }
                repo.definition.validate().unwrap_or_else(|e| {
                    panic!("{} is not a valid definition: {e}", repo.definition.id)
                });
            }
        }
    }

    #[test]
    fn nginx_pins_the_active_signer_not_only_the_documented_one() {
        // nginx.org's docs page still advertises the 2011 key while the
        // repository is signed by the 2024 one. Pinning only the documented
        // value would reject every download.
        let repo = nginx(&debian("trixie", "debian", "13")).unwrap();
        assert!(
            repo.definition
                .accepted_fingerprints
                .contains(&NGINX_KEYS[0].to_string())
        );
        assert!(
            repo.definition
                .accepted_fingerprints
                .contains(&NGINX_KEYS[1].to_string()),
            "the legacy key still verifies older packages"
        );
        assert_eq!(
            repo.definition.accepted_fingerprints.len(),
            3,
            "the whole bundle is pinned"
        );
    }

    #[test]
    fn nginx_components_are_nginx_not_main() {
        let repo = nginx(&debian("bookworm", "debian", "12")).unwrap();
        assert_eq!(repo.definition.components, vec!["nginx".to_string()]);
    }

    #[test]
    fn nginx_on_rhel_uses_the_centos_tree_and_module_hotfixes() {
        let repo = nginx(&rhel("10", Arch::Aarch64)).unwrap();
        assert!(
            repo.definition.base_url.contains("/centos/10/aarch64"),
            "{}",
            repo.definition.base_url
        );
        // Without this the distro's own nginx module shadows these packages.
        assert!(
            repo.options
                .iter()
                .any(|(k, v)| k == "module_hotfixes" && v == "true")
        );
        // The literal dnf variables must not survive: on RHEL proper
        // $releasever can expand to 9.6, which does not exist upstream.
        assert!(!repo.definition.base_url.contains('$'));
    }

    #[test]
    fn remi_keys_are_chosen_per_el_version() {
        let el9 = php(&rhel("9", Arch::X86_64)).unwrap();
        let el10 = php(&rhel("10", Arch::X86_64)).unwrap();
        assert_ne!(
            el9.definition.accepted_fingerprints, el10.definition.accepted_fingerprints,
            "EL9 and EL10 are signed with different Remi keys"
        );
        assert!(el9.definition.gpg_key_url.ends_with("remi2021"));
        assert!(el10.definition.gpg_key_url.ends_with("remi2024"));
    }

    #[test]
    fn an_el_version_with_no_pinned_remi_key_is_refused() {
        // Better to refuse than to install packages signed by a key nobody
        // checked.
        let el11 = php(&rhel("11", Arch::X86_64));
        assert!(el11.is_err());
        assert!(el11.unwrap_err().contains("no Remi signing key is pinned"));
    }

    #[test]
    fn remi_uses_the_safe_repository() {
        let repo = php(&rhel("9", Arch::X86_64)).unwrap();
        assert!(
            repo.definition.base_url.contains("/safe/"),
            "{}",
            repo.definition.base_url
        );
        assert!(!repo.definition.base_url.contains("/remi/"));
    }

    #[test]
    fn sury_serves_ubuntu_too_including_the_newest_lts() {
        // The ondrej/php PPA has no `resolute` suite; packages.sury.org does.
        for (codename, id, version) in [
            ("bookworm", "debian", "12"),
            ("trixie", "debian", "13"),
            ("jammy", "ubuntu", "22.04"),
            ("noble", "ubuntu", "24.04"),
            ("resolute", "ubuntu", "26.04"),
        ] {
            let repo = php(&debian(codename, id, version)).unwrap();
            assert_eq!(repo.definition.base_url, "https://packages.sury.org/php");
            assert_eq!(repo.definition.suite.as_deref(), Some(codename));
        }
    }

    #[test]
    fn docker_uses_a_different_key_per_package_format() {
        let deb = docker(&debian("trixie", "debian", "13")).unwrap();
        let rpm = docker(&rhel("9", Arch::X86_64)).unwrap();
        assert_ne!(
            deb.definition.accepted_fingerprints,
            rpm.definition.accepted_fingerprints
        );
        assert_eq!(deb.definition.components, vec!["stable".to_string()]);
    }

    #[test]
    fn a_machine_with_no_codename_is_refused_rather_than_guessed() {
        let mut info = debian("trixie", "debian", "13");
        info.codename = String::new();
        assert!(nginx(&info).is_err());
        assert!(php(&info).is_err());
    }

    #[test]
    fn every_repository_is_https() {
        for info in [debian("trixie", "debian", "13"), rhel("9", Arch::X86_64)] {
            for repo in catalogue(&info) {
                assert!(repo.definition.base_url.starts_with("https://"));
                assert!(repo.definition.gpg_key_url.starts_with("https://"));
            }
        }
    }

    #[test]
    fn provenance_is_recorded_for_every_entry() {
        // A pin whose origin nobody wrote down is a pin nobody can re-verify.
        for repo in catalogue(&debian("trixie", "debian", "13")) {
            assert!(
                repo.source.len() > 30,
                "{} has no meaningful provenance",
                repo.definition.id
            );
            if repo.provenance == Provenance::SingleSource {
                assert!(
                    UNVERIFIED_PINS.contains(&repo.definition.id.as_str()),
                    "{} is single-sourced but missing from UNVERIFIED_PINS",
                    repo.definition.id
                );
            }
        }
    }
}
