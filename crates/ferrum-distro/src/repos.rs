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

/// Repositories whose pin still rests on the key material alone.
///
/// This list used to hold every repository, because the only check available
/// was "does the pin match the key file this URL serves" — which a compromised
/// mirror passes trivially by serving its own key. `verify-pins` now also reads
/// the issuer fingerprint out of the **signature on live repository metadata**
/// (see [`crate::pgp::signature_issuers`]): a different path, usually a
/// different file, naming the key that actually signs what a machine installs.
///
/// Measured with that second route, every pin below corroborated against its
/// own repository except Docker's:
///
/// ```text
/// nginx     deb + rpm   signed by 8540A6F1…  == pinned primary
/// php-sury  deb         signed by 15058500…  == pinned primary
/// php-remi  rpm         signed by B1ABF71E… / CF1DF005…  == pinned primary
/// mariadb   deb + rpm   signed by 177F4010…  == pinned primary
/// pgdg      deb + rpm   signed by B97B0AFC… / D4BF08AE…  == pinned primary
/// docker-ce deb + rpm   signature carries no issuer fingerprint
/// ```
///
/// So only `docker-ce` remains. Its signatures are v4 but name the signer with
/// the 8-byte issuer key ID (subpacket 16) rather than the fingerprint
/// (subpacket 33), and a key ID is a truncation — colliding ones are cheap to
/// manufacture, so accepting one as identity would weaken the check rather than
/// complete it. Docker also removed the fingerprint from its Debian and Ubuntu
/// install docs, leaving no published value at all for the deb key. The rpm
/// fingerprint *is* still published and matches.
///
/// A release checklist item, kept in code so it cannot be forgotten in a wiki.
pub const UNVERIFIED_PINS: &[&str] = &["docker-ce"];

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

/// The MariaDB series the panel installs. `11.8` is the current long-term
/// support series (maintained until mid-2030), which is what a hosting server
/// wants — rolling releases EOL in one year.
///
/// A constant for now; it becomes a config value when the panel grows per-server
/// engine version selection (spec §11.4 lists engines, not versions). Everything
/// downstream already takes the series as a parameter, so only this default
/// moves.
pub const MARIADB_SERIES: &str = "11.8";

/// The PostgreSQL major the panel installs. 17 is the newest major with a full
/// year of point releases behind it and PGDG coverage on every distro/arch in
/// the v1 support matrix (verified against the live repository trees).
///
/// Like [`MARIADB_SERIES`], a documented constant until engine versioning
/// becomes a config value.
pub const POSTGRES_MAJOR: u32 = 17;

/// "MariaDB Server" signing key, RSA-4096, created 2023. One key signs both the
/// deb and the rpm repositories, served from supplychain.mariadb.com.
///
/// The fingerprint is published in MariaDB's own documentation
/// (mariadb.com/kb/en/gpg/), a different host from the one serving the key —
/// which is what lets this pin count as corroborated.
const MARIADB_KEY: &str = "177F4010FE56CA3336300305F1656F24C74CD1D8";

/// PGDG's apt key ("PostgreSQL Debian Repository"), the long-lived `ACCC4CF8`
/// key whose full fingerprint the PostgreSQL wiki publishes.
const PGDG_DEB_KEY: &str = "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8";

/// PGDG signs its RPM repositories with a *different key per architecture* —
/// pinning only the x86_64 key would reject every package on an arm64 server.
/// The resolver picks by [`DistroInfo::arch`].
const PGDG_RPM_X86_64_KEY: &str = "D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20";
const PGDG_RPM_AARCH64_KEY: &str = "B031F89FC983E98262906B6E177B343BB9738825";

/// Something that must be in place before a repository's packages will resolve.
///
/// Third-party repositories routinely depend on libraries the distribution keeps
/// somewhere other than its default set. Remi's `php8X-php-gd`, for instance,
/// needs `libraqm` and `libimagequant`, which live in EPEL — without it the
/// install fails with a dependency error that says nothing about EPEL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prerequisite {
    /// A package from the distribution's own signed repositories, such as
    /// `epel-release`. No pin needed: it is signed by the distribution.
    DistroPackage(&'static str),
    /// A repository the distribution ships but leaves disabled, such as `crb`.
    ///
    /// Best-effort: its name differs between RHEL and its rebuilds, and a
    /// missing one should not stop an install that might not need it.
    EnableRepo(&'static str),
    /// An AppStream module stream to disable, such as `postgresql`.
    ///
    /// PGDG's own install instructions include `dnf module disable postgresql`:
    /// with the module's default stream active, `dnf` can resolve a bare
    /// dependency on the distribution's build instead of the repository we just
    /// pinned. Best-effort, because EL10 removed modularity entirely — there the
    /// command fails and there is nothing to disable.
    DisableModule(&'static str),
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
    /// What must be enabled first for this repository's packages to resolve.
    pub prerequisites: Vec<Prerequisite>,
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
        provenance: Provenance::Corroborated,
        source: "key material served at https://nginx.org/keys/nginx_signing.key, and \
                 the key that signs live repository metadata, read from its issuer-fingerprint subpacket — 8540A6F1… on Debian, Ubuntu and EL alike"
            .into(),
        options: match info.family {
            // Without this, EL8+ prefers the distribution's own `nginx` module
            // stream and the nginx.org packages are shadowed.
            Family::Rhel => vec![("module_hotfixes".into(), "true".into())],
            Family::Debian => Vec::new(),
        },
        // nginx.org's package is self-contained.
        prerequisites: Vec::new(),
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
            provenance: Provenance::Corroborated,
            source: "the `Signed-By:` field published in \
                     https://packages.sury.org/php/dists/*/Release, the keyring shipped in \
                     debsuryorg-archive-keyring.deb, and the key that signs live repository metadata, read from its issuer-fingerprint subpacket"
                .into(),
            options: Vec::new(),
            prerequisites: Vec::new(),
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
                provenance: Provenance::Corroborated,
                source: format!(
                    "resolved from remi-release-{major}.rpm, whose \
                     /etc/pki/rpm-gpg/RPM-GPG-KEY-remi.el{major} symlink names the key; \
                     matches https://rpms.remirepo.net/KEYS.txt; and the key that signs live repository metadata, read from its issuer-fingerprint subpacket"
                ),
                options: Vec::new(),
                // Remi's own repository header says its dependencies live "in
                // base repository or in EPEL". Without EPEL, php8X-php-gd fails
                // on libraqm/libimagequant with an error that never mentions it.
                prerequisites: vec![
                    Prerequisite::DistroPackage("epel-release"),
                    Prerequisite::EnableRepo("crb"),
                ],
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
                prerequisites: Vec::new(),
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
                prerequisites: Vec::new(),
            })
        }
    }
}

/// MariaDB Server, from MariaDB plc's own repository (spec §7.3).
///
/// `rpm.mariadb.org` and `deb.mariadb.org` — the canonical hostnames — and
/// **not** `dlm.mariadb.com`, which an earlier version of this function used on
/// the strength of a research note. Measured on a live AlmaLinux 9 box:
///
/// ```text
/// 403  https://dlm.mariadb.com/repo/mariadb-server/11.8/yum/rhel/9/x86_64/repodata/repomd.xml
/// 403  https://dlm.mariadb.com/repo/mariadb-server/11.8/repo/debian/dists/bookworm/Release
/// 200  https://rpm.mariadb.org/11.8/rhel/9/x86_64/repodata/repomd.xml
/// 200  https://deb.mariadb.org/11.8/debian/dists/bookworm/Release
/// ```
///
/// `dlm.mariadb.com` is the browser-facing download manager: it answers a plain
/// GET with a redirect into a Google Cloud Storage URL carrying an `Expires=`
/// and a `Signature=`, and that signed URL returns 403 to `dnf` and `apt`. The
/// panel got as far as verifying the signing key and writing the `.repo` file
/// before the install died on it — the whole module was untestable without a
/// real machine, which is why it took one to find.
///
/// Both canonical hosts redirect into MariaDB's mirror network, and that
/// network really does round-robin: four consecutive requests to
/// `deb.mariadb.org` landed on three different volunteer mirrors. The reason
/// that is survivable, also measured, is that the redirect resolves to a
/// **version-pinned snapshot** — `…/11.8/…` becomes `…/mariadb-11.8.9/…` — and
/// every mirror served a byte-identical `Release` (same SHA-256 across three
/// fetches through three mirrors). The mismatch window is therefore only the
/// hours around a point release, while mirrors converge; the repository
/// signature makes even that a failed transaction rather than a wrong one.
pub fn mariadb(info: &DistroInfo, series: &str) -> Result<ResolvedRepo, String> {
    // The series lands in a URL path; refuse anything that is not `NN.N`-shaped
    // rather than trusting a future config value to be well-formed.
    if series.is_empty()
        || !series.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        || series.contains("..")
    {
        return Err(format!("`{series}` is not a plausible MariaDB series"));
    }

    let fingerprints = vec![MARIADB_KEY.to_string()];
    // One key signs both families (unlike Docker), served from a host separate
    // from the repository itself.
    let gpg_key_url = "https://supplychain.mariadb.com/MariaDB-Server-GPG-KEY".to_string();

    let definition = match info.family {
        Family::Debian => {
            let path = if info.id == "ubuntu" {
                "ubuntu"
            } else {
                "debian"
            };
            RepoDefinition {
                id: "mariadb".into(),
                display_name: format!("MariaDB Server {series}"),
                base_url: format!("https://deb.mariadb.org/{series}/{path}"),
                suite: Some(require_codename(info)?),
                components: vec!["main".into()],
                gpg_key_url,
                accepted_fingerprints: fingerprints,
            }
        }
        Family::Rhel => {
            let major = require_major(info)?;
            RepoDefinition {
                id: "mariadb".into(),
                display_name: format!("MariaDB Server {series}"),
                // Major substituted, `$releasever` never written: on RHEL proper
                // it expands to `9.6`, a directory upstream does not have.
                base_url: format!(
                    "https://rpm.mariadb.org/{series}/rhel/{major}/{}",
                    arch_dir(info)
                ),
                suite: None,
                components: Vec::new(),
                gpg_key_url,
                accepted_fingerprints: fingerprints,
            }
        }
    };

    Ok(ResolvedRepo {
        definition,
        provenance: Provenance::Corroborated,
        source: "fingerprint published in MariaDB's documentation \
                 (https://mariadb.com/kb/en/gpg/), confirmed against the key served at \
                 https://supplychain.mariadb.com/MariaDB-Server-GPG-KEY"
            .into(),
        options: match info.family {
            // Verbatim from the `.repo` file mariadb_repo_setup writes. Without
            // it, dnf's modular filtering on EL lets the distribution's own
            // `mariadb` AppStream module shadow this repository's packages, and
            // the install fails with "all matches were filtered out".
            Family::Rhel => vec![("module_hotfixes".into(), "1".into())],
            Family::Debian => Vec::new(),
        },
        prerequisites: Vec::new(),
    })
}

/// PostgreSQL from PGDG — apt.postgresql.org / download.postgresql.org
/// (spec §7.3), for [`POSTGRES_MAJOR`].
pub fn pgdg(info: &DistroInfo) -> Result<ResolvedRepo, String> {
    match info.family {
        Family::Debian => Ok(ResolvedRepo {
            definition: RepoDefinition {
                id: "pgdg".into(),
                display_name: format!("PostgreSQL {POSTGRES_MAJOR} (PGDG)"),
                // One archive serves every suite; the major is selected by
                // package name (`postgresql-17`), not by URL.
                base_url: "https://apt.postgresql.org/pub/repos/apt".into(),
                suite: Some(format!("{}-pgdg", require_codename(info)?)),
                components: vec!["main".into()],
                gpg_key_url: "https://www.postgresql.org/media/keys/ACCC4CF8.asc".into(),
                accepted_fingerprints: vec![PGDG_DEB_KEY.to_string()],
            },
            provenance: Provenance::Corroborated,
            source: "fingerprint published on https://wiki.postgresql.org/wiki/Apt, \
                     confirmed against the key served at \
                     https://www.postgresql.org/media/keys/ACCC4CF8.asc"
                .into(),
            options: Vec::new(),
            prerequisites: Vec::new(),
        }),

        Family::Rhel => {
            let major = require_major(info)?;
            // Per-architecture signing keys: the x86_64 pin rejects every
            // aarch64 package and vice versa, so the arch picks the key.
            let (key_file, fingerprint) = match info.arch {
                crate::detect::Arch::X86_64 => ("PGDG-RPM-GPG-KEY-RHEL", PGDG_RPM_X86_64_KEY),
                crate::detect::Arch::Aarch64 => {
                    ("PGDG-RPM-GPG-KEY-AARCH64-RHEL", PGDG_RPM_AARCH64_KEY)
                }
            };
            Ok(ResolvedRepo {
                definition: RepoDefinition {
                    id: "pgdg".into(),
                    display_name: format!("PostgreSQL {POSTGRES_MAJOR} (PGDG)"),
                    // EL major substituted for the same `$releasever` reason as
                    // nginx and MariaDB.
                    base_url: format!(
                        "https://download.postgresql.org/pub/repos/yum/{POSTGRES_MAJOR}/redhat/rhel-{major}-{}",
                        arch_dir(info)
                    ),
                    suite: None,
                    components: Vec::new(),
                    gpg_key_url: format!(
                        "https://download.postgresql.org/pub/repos/yum/keys/{key_file}"
                    ),
                    accepted_fingerprints: vec![fingerprint.to_string()],
                },
                // PGDG publishes no out-of-band fingerprint for its rpm keys,
                // but the signature on live repodata names the same key, which
                // is a different file on a different path from the key itself.
                provenance: Provenance::Corroborated,
                source: format!(
                    "key material served at \
                     https://download.postgresql.org/pub/repos/yum/keys/{key_file}, and \
                     the key that signs live repository metadata, read from its issuer-fingerprint subpacket"
                ),
                options: Vec::new(),
                // PGDG's own EL9 instructions disable the distro module first;
                // best-effort because EL10 has no modularity (see the variant).
                prerequisites: vec![Prerequisite::DisableModule("postgresql")],
            })
        }
    }
}

/// Every repository Ferrum knows how to add on this machine.
pub fn catalogue(info: &DistroInfo) -> Vec<ResolvedRepo> {
    [
        nginx(info),
        php(info),
        mariadb(info, MARIADB_SERIES),
        pgdg(info),
        docker(info),
    ]
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
    fn remi_declares_the_epel_dependency_that_its_packages_actually_have() {
        // Found the hard way on a real AlmaLinux 9: php83-php-gd needs libgd,
        // which needs libraqm and libimagequant, which are in EPEL. Without this
        // the install fails with a dependency error that never says "EPEL".
        let repo = php(&rhel("9", Arch::X86_64)).unwrap();
        assert!(
            repo.prerequisites
                .contains(&Prerequisite::DistroPackage("epel-release")),
            "Remi needs EPEL: {:?}",
            repo.prerequisites
        );
        assert!(
            repo.prerequisites
                .contains(&Prerequisite::EnableRepo("crb"))
        );

        // The Debian side needs nothing extra.
        assert!(
            php(&debian("trixie", "debian", "13"))
                .unwrap()
                .prerequisites
                .is_empty()
        );
    }

    #[test]
    fn mariadb_uses_the_hosts_that_actually_serve_metadata() {
        // This test used to assert the opposite, and passed the whole time the
        // feature was broken: it enshrined `dlm.mariadb.com`, which answers dnf
        // and apt with a 403. A URL test can only check shape, so the shape it
        // checks has to be the one a real machine confirmed — see the function's
        // own docs for the measurements.
        for info in [
            debian("trixie", "debian", "13"),
            debian("noble", "ubuntu", "24.04"),
            rhel("9", Arch::X86_64),
            rhel("10", Arch::Aarch64),
        ] {
            let url = mariadb(&info, MARIADB_SERIES).unwrap().definition.base_url;
            let expected_host = match info.family {
                Family::Debian => "https://deb.mariadb.org/",
                Family::Rhel => "https://rpm.mariadb.org/",
            };
            assert!(url.starts_with(expected_host), "{url}");
            assert!(
                !url.contains("dlm.mariadb.com"),
                "the download-manager host serves signed redirects that package \
                 managers cannot follow: {url}"
            );
            // A mirror hostname written directly would pin one volunteer mirror
            // and lose the vendor's own redirect.
            assert!(!url.contains("mirror."), "{url}");
        }
    }

    #[test]
    fn the_mariadb_series_still_reaches_the_url_intact() {
        // The series is the one part of these URLs that comes from config, and
        // it is what selects the version-pinned snapshot the mirrors agree on.
        let url = mariadb(&rhel("9", Arch::X86_64), "11.8").unwrap().definition.base_url;
        assert_eq!(url, "https://rpm.mariadb.org/11.8/rhel/9/x86_64");

        let url = mariadb(&debian("bookworm", "debian", "12"), "11.8")
            .unwrap()
            .definition
            .base_url;
        assert_eq!(url, "https://deb.mariadb.org/11.8/debian");
    }

    #[test]
    fn mariadb_pins_one_key_for_both_package_formats() {
        // Unlike Docker, MariaDB signs deb and rpm with the same 2023 key.
        let deb = mariadb(&debian("trixie", "debian", "13"), MARIADB_SERIES).unwrap();
        let rpm = mariadb(&rhel("9", Arch::X86_64), MARIADB_SERIES).unwrap();
        assert_eq!(
            deb.definition.accepted_fingerprints,
            rpm.definition.accepted_fingerprints
        );
        assert_eq!(
            deb.definition.accepted_fingerprints,
            vec![MARIADB_KEY.to_string()]
        );
    }

    #[test]
    fn mariadb_on_rhel_substitutes_the_major_and_sets_module_hotfixes() {
        let repo = mariadb(&rhel("10", Arch::Aarch64), MARIADB_SERIES).unwrap();
        assert!(
            repo.definition
                .base_url
                .ends_with("/rhel/10/aarch64"),
            "{}",
            repo.definition.base_url
        );
        // Without this, the distro's mariadb AppStream module filters the
        // repository's packages out of every transaction.
        assert!(
            repo.options
                .iter()
                .any(|(k, v)| k == "module_hotfixes" && v == "1")
        );
    }

    #[test]
    fn mariadb_debian_and_ubuntu_get_their_own_trees() {
        let deb = mariadb(&debian("trixie", "debian", "13"), MARIADB_SERIES).unwrap();
        assert!(deb.definition.base_url.ends_with("/debian"));
        assert_eq!(deb.definition.suite.as_deref(), Some("trixie"));
        assert_eq!(deb.definition.components, vec!["main".to_string()]);

        let ubu = mariadb(&debian("noble", "ubuntu", "24.04"), MARIADB_SERIES).unwrap();
        assert!(ubu.definition.base_url.ends_with("/ubuntu"));
        assert_eq!(ubu.definition.suite.as_deref(), Some("noble"));
    }

    #[test]
    fn a_hostile_mariadb_series_cannot_reach_a_url() {
        // The series becomes a URL path segment; a config value must not be able
        // to redirect the panel to a different repository tree.
        for bad in ["", "11.8/evil", "../10.6", "11.8 main", "11..8"] {
            assert!(
                mariadb(&debian("trixie", "debian", "13"), bad).is_err(),
                "series `{bad}` should be refused"
            );
        }
    }

    #[test]
    fn pgdg_apt_suite_is_the_codename_with_the_pgdg_suffix() {
        let repo = pgdg(&debian("trixie", "debian", "13")).unwrap();
        assert_eq!(
            repo.definition.base_url,
            "https://apt.postgresql.org/pub/repos/apt"
        );
        assert_eq!(repo.definition.suite.as_deref(), Some("trixie-pgdg"));
        assert_eq!(
            repo.definition.accepted_fingerprints,
            vec![PGDG_DEB_KEY.to_string()]
        );
    }

    #[test]
    fn pgdg_rpm_keys_are_chosen_per_architecture() {
        // PGDG signs each architecture's rpm repository with its own key; the
        // wrong pin would reject every package on that machine.
        let x86 = pgdg(&rhel("9", Arch::X86_64)).unwrap();
        let a64 = pgdg(&rhel("9", Arch::Aarch64)).unwrap();
        assert_ne!(
            x86.definition.accepted_fingerprints,
            a64.definition.accepted_fingerprints
        );
        assert_eq!(
            x86.definition.accepted_fingerprints,
            vec![PGDG_RPM_X86_64_KEY.to_string()]
        );
        assert_eq!(
            a64.definition.accepted_fingerprints,
            vec![PGDG_RPM_AARCH64_KEY.to_string()]
        );
        assert!(x86.definition.gpg_key_url.ends_with("PGDG-RPM-GPG-KEY-RHEL"));
        assert!(
            a64.definition
                .gpg_key_url
                .ends_with("PGDG-RPM-GPG-KEY-AARCH64-RHEL")
        );

        // And neither rpm key is the deb key.
        let deb = pgdg(&debian("trixie", "debian", "13")).unwrap();
        assert_ne!(
            deb.definition.accepted_fingerprints,
            x86.definition.accepted_fingerprints
        );
    }

    #[test]
    fn pgdg_rpm_baseurl_names_the_postgres_major_and_the_el_major() {
        let repo = pgdg(&rhel("10", Arch::X86_64)).unwrap();
        assert_eq!(
            repo.definition.base_url,
            format!(
                "https://download.postgresql.org/pub/repos/yum/{POSTGRES_MAJOR}/redhat/rhel-10-x86_64"
            )
        );
        // The distro's own postgresql module must not shadow PGDG's packages.
        assert!(
            repo.prerequisites
                .contains(&Prerequisite::DisableModule("postgresql"))
        );
    }

    #[test]
    fn no_baseurl_smuggles_a_dnf_variable() {
        // `$releasever` on RHEL proper expands to `9.6`, which upstream trees do
        // not have; every resolver substitutes the major instead. This test is
        // the tripwire for anyone re-introducing the variable.
        for info in [
            debian("trixie", "debian", "13"),
            rhel("9", Arch::X86_64),
            rhel("9", Arch::Aarch64),
            rhel("10", Arch::X86_64),
            rhel("10", Arch::Aarch64),
        ] {
            for repo in catalogue(&info) {
                assert!(
                    !repo.definition.base_url.contains('$'),
                    "{} leaves a dnf variable in `{}`",
                    repo.definition.id,
                    repo.definition.base_url
                );
            }
        }
    }

    #[test]
    fn the_database_repos_are_part_of_the_catalogue() {
        // `verify-pins` and the audit path both walk the catalogue; an entry
        // that resolves but is not listed there is an entry nobody verifies.
        for info in [debian("trixie", "debian", "13"), rhel("9", Arch::X86_64)] {
            let ids: Vec<String> = catalogue(&info)
                .iter()
                .map(|r| r.definition.id.clone())
                .collect();
            assert!(ids.contains(&"mariadb".to_string()), "{ids:?}");
            assert!(ids.contains(&"pgdg".to_string()), "{ids:?}");
        }
    }

    #[test]
    fn only_docker_still_rests_on_its_key_file_alone() {
        // `verify-pins` reads the issuer fingerprint out of the signature on
        // live repository metadata, which is a different file on a different
        // path from the key. Measured, every repository corroborated that way
        // except Docker's, whose v4 signatures name the signer with the 8-byte
        // key ID rather than the fingerprint — and a truncation is not an
        // identity. If a future change corroborates Docker, or breaks one of
        // the others, this is the test that has to be updated deliberately.
        assert_eq!(UNVERIFIED_PINS, &["docker-ce"]);

        // One direction only, and deliberately: the list is keyed by
        // repository id while provenance is per family, and Docker is exactly
        // why that distinction matters — its *rpm* fingerprint is published and
        // corroborates, its *deb* one was removed from the install docs. An
        // `iff` here would force a choice between flagging a corroborated entry
        // and hiding an uncorroborated one.
        for info in [
            debian("trixie", "debian", "13"),
            rhel("9", Arch::X86_64),
            rhel("9", Arch::Aarch64),
        ] {
            for repo in catalogue(&info) {
                if repo.provenance == Provenance::SingleSource {
                    assert!(
                        UNVERIFIED_PINS.contains(&repo.definition.id.as_str()),
                        "{} is single-sourced but the release checklist does not say so",
                        repo.definition.id
                    );
                }
            }
        }

        // The two halves of that Docker asymmetry, pinned so a future edit that
        // flattens them has to say why.
        assert_eq!(
            docker(&debian("trixie", "debian", "13")).unwrap().provenance,
            Provenance::SingleSource
        );
        assert_eq!(
            docker(&rhel("9", Arch::X86_64)).unwrap().provenance,
            Provenance::Corroborated
        );

        // The per-architecture rpm keys are genuinely different keys, and each
        // is corroborated separately — a single check would have missed one.
        assert_ne!(
            pgdg(&rhel("9", Arch::X86_64)).unwrap().definition.accepted_fingerprints,
            pgdg(&rhel("9", Arch::Aarch64)).unwrap().definition.accepted_fingerprints
        );
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
