//! Packages and upstream repositories (spec §7.3).
//!
//! Unihelm installs **only** from official upstream repositories and never
//! compiles on a customer's server (spec §2.3). That is what makes security
//! updates somebody else's job — the single biggest operational difference from
//! the panels that build PHP from source.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::exec::{Cmd, CmdOutput};
use crate::{DistroError, DistroInfo, Family, Result};

/// Somewhere for a long-running command to write progress. Task execution wires
/// this to the live log stream; everything else passes [`NullLog`].
pub trait LogSink: Send + Sync {
    fn line(&self, line: &str);
}

/// Discards output.
pub struct NullLog;

impl LogSink for NullLog {
    fn line(&self, _line: &str) {}
}

/// A package name that is safe to hand to a package manager.
///
/// Restricted to what Debian and RPM naming actually allow, which also means it
/// can never be mistaken for an option (no leading `-`) or a path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PackageName(String);

impl PackageName {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() || s.len() > 128 {
            return Err(DistroError::InvalidName(
                "package name must be 1-128 characters".into(),
            ));
        }
        let first = s.bytes().next().unwrap();
        if !first.is_ascii_alphanumeric() {
            return Err(DistroError::InvalidName(format!(
                "package name `{s}` must start with a letter or digit"
            )));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b':'))
        {
            return Err(DistroError::InvalidName(format!(
                "package name `{s}` contains characters outside [A-Za-z0-9-_.+:]"
            )));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PackageName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl TryFrom<String> for PackageName {
    type Error = DistroError;
    fn try_from(v: String) -> Result<Self> {
        Self::parse(&v)
    }
}
impl From<PackageName> for String {
    fn from(v: PackageName) -> String {
        v.0
    }
}
impl std::str::FromStr for PackageName {
    type Err = DistroError;
    fn from_str(v: &str) -> Result<Self> {
        Self::parse(v)
    }
}

/// An upstream repository, with its signing key pinned by full fingerprint.
///
/// Adding a repository is itself an audited operation (spec §7.3). The pinned
/// fingerprints are compared against the key we actually download, before
/// anything is written to `/etc/apt/sources.list.d` or `/etc/yum.repos.d`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoDefinition {
    /// Short identifier, also the config filename stem: `nginx`, `php-sury`.
    pub id: String,
    pub display_name: String,
    /// Debian: the `deb` URI. RHEL: the `baseurl`.
    pub base_url: String,
    /// Debian only: the suite, which for every vendor we use is the codename.
    pub suite: Option<String>,
    pub components: Vec<String>,
    /// Where the signing key is published.
    pub gpg_key_url: String,
    /// Full 40- or 64-hex-character fingerprints, any of which is acceptable.
    ///
    /// A list rather than one value because vendors publish bundles: nginx
    /// serves three keys, and a rotation between them must not be an outage.
    pub accepted_fingerprints: Vec<String>,
}

impl RepoDefinition {
    pub fn validate(&self) -> Result<()> {
        if self.accepted_fingerprints.is_empty() {
            return Err(DistroError::InvalidName(format!(
                "repo `{}` pins no signing key",
                self.id
            )));
        }
        for raw in &self.accepted_fingerprints {
            let fp = crate::pgp::normalise(raw);
            if (fp.len() != 40 && fp.len() != 64) || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(DistroError::InvalidName(format!(
                    "repo `{}` must pin full fingerprints; `{raw}` is not one",
                    self.id
                )));
            }
        }
        for url in [&self.base_url, &self.gpg_key_url] {
            if !url.starts_with("https://") {
                return Err(DistroError::InvalidName(format!(
                    "repo `{}` must use https, got `{url}`",
                    self.id
                )));
            }
        }
        if self.id.is_empty()
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(DistroError::InvalidName(format!(
                "repo id `{}` must be lowercase letters, digits and hyphens",
                self.id
            )));
        }
        // apt resolves a suite to `<uri>/dists/<suite>/`, and not every vendor
        // puts a bare codename there: MongoDB nests the server series under it,
        // as `noble/mongodb-org/8.0`. So `/` and `.` are allowed — but every
        // segment has to be a real directory name, because an empty, `.` or `..`
        // segment climbs back out of `dists/`, and the byte set keeps the value
        // from carrying a newline into the deb822 file below and inventing a
        // field of its own.
        if let Some(suite) = &self.suite
            && (suite.is_empty()
                || suite
                    .split('/')
                    .any(|seg| seg.is_empty() || seg == "." || seg == "..")
                || !suite.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b'/')
                }))
        {
            return Err(DistroError::InvalidName(format!(
                "repo `{}` has an implausible suite `{suite}`",
                self.id
            )));
        }
        Ok(())
    }

    /// Filename stem for the generated config, guaranteed not to escape its
    /// directory because [`Self::validate`] constrains `id`.
    pub fn file_stem(&self) -> String {
        format!("unihelm-{}", self.id)
    }
}

/// What we know about a package on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageStatus {
    pub name: String,
    pub installed: bool,
    pub installed_version: Option<String>,
    /// Newest version the configured repositories offer.
    pub candidate_version: Option<String>,
}

#[async_trait]
pub trait PkgBackend: Send + Sync {
    /// `apt` or `dnf`.
    fn name(&self) -> &'static str;

    /// Refresh the package index.
    async fn update_index(&self, log: &dyn LogSink) -> Result<CmdOutput>;

    /// Install packages, streaming progress into `log`.
    async fn install(&self, packages: &[PackageName], log: &dyn LogSink) -> Result<CmdOutput>;

    /// Remove packages. Config files are kept: a reinstall should find the
    /// server as it was (spec §11.1 "removing and reinstalling is idempotent").
    async fn remove(&self, packages: &[PackageName], log: &dyn LogSink) -> Result<CmdOutput>;

    /// Installed state and available version for one package.
    async fn query(&self, package: &PackageName) -> Result<PackageStatus>;

    /// Register an upstream repository.
    ///
    /// `key_material` is the raw bytes fetched from the repository's
    /// `gpg_key_url`. Verification against the pinned fingerprints happens
    /// *here*, so it cannot be skipped by a careless caller.
    async fn add_repo(
        &self,
        repo: &RepoDefinition,
        key_material: &[u8],
        options: &[(String, String)],
        log: &dyn LogSink,
    ) -> Result<()>;

    /// Remove a repository we previously added.
    async fn remove_repo(&self, repo_id: &str) -> Result<()>;

    /// Put a repository's prerequisite in place before adding it.
    ///
    /// Third-party repositories depend on libraries the distribution keeps
    /// outside its default set. Satisfying that here, with the reason logged,
    /// is the difference between a working install and a dependency error that
    /// never names what is missing.
    async fn ensure_prerequisite(
        &self,
        prerequisite: &crate::repos::Prerequisite,
        log: &dyn LogSink,
    ) -> Result<()>;

    async fn is_installed(&self, package: &PackageName) -> Result<bool> {
        Ok(self.query(package).await?.installed)
    }
}

// ---------------------------------------------------------------------------
// The nginx ModSecurity connector
// ---------------------------------------------------------------------------

/// A connector package a release genuinely has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorPackage {
    pub package: &'static str,
    /// Where it comes from, named the way an operator would have to enable it —
    /// `universe` and EPEL are not on by default on every image.
    pub repository: &'static str,
    /// The nginx it is compiled against. Recorded because an nginx dynamic
    /// module records its build signature and loads into that nginx and no
    /// other, which is what makes "install the package" the wrong advice on a
    /// server whose nginx came from somewhere else.
    pub built_against: &'static str,
}

/// What a distribution release offers for nginx's ModSecurity connector.
///
/// Three answers, shaped like [`crate::SupportStatus`] on purpose: checked and
/// present, checked and absent, and not checked. The third is not a hedge — it
/// is the only honest answer for a release nobody has looked at, and a caller
/// that renders it as "install this" would be inventing a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "packaging", rename_all = "snake_case")]
pub enum ModsecConnector {
    /// Verified present in a repository this release can reach.
    Packaged(ConnectorPackage),
    /// Verified absent: nothing in this release's repositories provides it.
    /// `checked` names what was searched, so the statement can be re-tested.
    Unpackaged { checked: String },
    /// Not checked for this release. `package` is the name the family uses
    /// where it does exist, offered as somewhere to look and nothing more.
    Unverified {
        package: &'static str,
        release: String,
    },
}

/// Debian and Ubuntu's name for the ModSecurity v3 nginx connector.
const DEB_CONNECTOR: &str = "libnginx-mod-http-modsecurity";
/// Fedora, EPEL and their rebuilds' name for the same thing.
const RPM_CONNECTOR: &str = "nginx-mod-modsecurity";

/// What this release has, checked against the distributions' own package
/// indexes on 2026-09-08.
///
/// | release | connector |
/// |---|---|
/// | Debian 12 (bookworm), 13 (trixie) | `libnginx-mod-http-modsecurity` 1.0.3, `main` |
/// | Ubuntu 24.04 (noble) and later | `libnginx-mod-http-modsecurity` 1.0.3, `universe` |
/// | Ubuntu 22.04 (jammy) | **none** — no such package in any component |
/// | AlmaLinux / Rocky / RHEL 9 | `nginx-mod-modsecurity` 1.0.4-1.el9, EPEL 9 |
/// | AlmaLinux / Rocky / RHEL 10 | **none** — EPEL 10 does not build it |
///
/// Two of those are releases this panel calls *supported* (`support_status`
/// returns `Supported` for Ubuntu 22.04 and for EL 10) and on which no WAF can
/// be made to run without an operator compiling a module themselves. Saying
/// that is the entire point of the `Unpackaged` variant: the alternative is a
/// refusal naming a package the operator will spend an afternoon failing to
/// find. Nothing here installs anything — the connector must match the running
/// nginx's build signature, and only the operator knows where their nginx came
/// from.
///
/// The Core Rule Set is deliberately not in this table. Debian and Ubuntu ship
/// `modsecurity-crs` (3.3.7 on trixie), an older major than the 4.29.0 Unihelm
/// pins, and Unihelm downloads and checksums its own tarball — so the CRS is
/// never the thing a release is missing.
pub fn modsec_connector(info: &DistroInfo) -> ModsecConnector {
    match (info.id.as_str(), info.major()) {
        ("debian", Some(12..=13)) => ModsecConnector::Packaged(ConnectorPackage {
            package: DEB_CONNECTOR,
            repository: "the Debian archive (`main`)",
            built_against: "Debian's own nginx package",
        }),
        // Checked before the `24..` arm below reads as "everything newer", so
        // that a release verified to be missing it can never be answered from a
        // range somebody widened later.
        ("ubuntu", _) if info.version_id == "22.04" => ModsecConnector::Unpackaged {
            checked: "Ubuntu 22.04 (jammy), all four components".into(),
        },
        ("ubuntu", Some(24..)) => ModsecConnector::Packaged(ConnectorPackage {
            package: DEB_CONNECTOR,
            repository: "Ubuntu `universe`",
            built_against: "Ubuntu's own nginx package",
        }),
        ("almalinux" | "rocky" | "rhel" | "centos", Some(9)) => {
            ModsecConnector::Packaged(ConnectorPackage {
                package: RPM_CONNECTOR,
                repository: "EPEL 9",
                built_against: "the EL 9 AppStream nginx",
            })
        }
        ("almalinux" | "rocky" | "rhel" | "centos", Some(10)) => ModsecConnector::Unpackaged {
            checked: "EPEL 10 and the EL 10 AppStream".into(),
        },
        _ => ModsecConnector::Unverified {
            package: match info.family {
                Family::Debian => DEB_CONNECTOR,
                Family::Rhel => RPM_CONNECTOR,
            },
            release: info.pretty_name.clone(),
        },
    }
}

// ---------------------------------------------------------------------------
// The Postfix null client (spec §11.18)
// ---------------------------------------------------------------------------

/// What one family installs to become a Postfix null client.
///
/// Two packages, not one, and the second is the one people forget. Postfix
/// itself contains no SASL mechanisms: `libplain.so` is a Cyrus SASL *plugin*,
/// packaged separately on both families. Without it `smtp_sasl_auth_enable`
/// still turns on, the relay still offers `AUTH PLAIN LOGIN`, and Postfix logs
/// `SASL authentication failed; no mechanism available` — a line an operator
/// reads as a rejected password and spends the afternoon re-pasting the
/// credential over. The package is the fix, and it has to be installed in the
/// same transaction as the MTA so no machine ever exists in the state that
/// produces that message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostfixPackages {
    /// The MTA.
    pub mta: &'static str,
    /// The Cyrus SASL plugin package providing the PLAIN and LOGIN mechanisms.
    pub sasl: &'static str,
    /// Where both come from, named the way an operator would have to enable it
    /// — the same reason [`ConnectorPackage::repository`] carries it.
    pub repository: &'static str,
}

impl PostfixPackages {
    /// The names, in install order.
    pub const fn names(&self) -> [&'static str; 2] {
        [self.mta, self.sasl]
    }

    /// The names as values a package manager will accept.
    ///
    /// Fallible in the type only: every string here is a compile-time constant
    /// and `postfix_packages_are_installable_names` asserts each one parses on
    /// both families. It stays a `Result` so this cannot become the one place
    /// in the crate that reaches a package manager without going through
    /// [`PackageName`].
    pub fn parsed(&self) -> Result<Vec<PackageName>> {
        self.names().iter().map(|n| PackageName::parse(n)).collect()
    }
}

/// What this family calls the MTA and its SASL mechanism plugin.
///
/// Checked against the distributions' own package indexes on 2026-09-09:
///
/// | release | MTA | SASL plugin |
/// |---|---|---|
/// | Debian 13 (trixie) | `postfix` 3.10.13, `main` | `libsasl2-modules` 2.1.28, `main` |
/// | Debian 12 (bookworm) | `postfix` 3.7.11, `main` | `libsasl2-modules` 2.1.28, `main` |
/// | Ubuntu 24.04 (noble) | `postfix` 3.8.6, `main` | `libsasl2-modules` 2.1.28, `main` |
/// | Ubuntu 22.04 (jammy) | `postfix` 3.6.4, `main` | `libsasl2-modules` 2.1.27, `main` |
/// | AlmaLinux / Rocky / RHEL 9 | `postfix` 3.5.25, AppStream | `cyrus-sasl-plain` 2.1.27, BaseOS |
/// | AlmaLinux / Rocky / RHEL 10 | `postfix` 3.8.5, AppStream | `cyrus-sasl-plain` 2.1.28, BaseOS |
///
/// Unlike [`modsec_connector`] there is no `Unverified` case to model here.
/// Every release above answers with the same two names for its family, and both
/// come from a repository that is enabled on a stock install — `main` on the
/// Debian side (not `universe`, which is what made the WAF connector a per
/// release question), BaseOS and AppStream on the EL side. So the answer is a
/// property of the family, and taking [`DistroInfo`] rather than [`Family`]
/// says only that a future release is allowed to disagree.
pub fn postfix_packages(info: &DistroInfo) -> PostfixPackages {
    match info.family {
        Family::Debian => PostfixPackages {
            mta: "postfix",
            sasl: "libsasl2-modules",
            repository: "the distribution's own archive (`main`)",
        },
        Family::Rhel => PostfixPackages {
            mta: "postfix",
            // `cyrus-sasl-plain`, not `cyrus-sasl`: the base package is the
            // library and the daemon, and the mechanisms are split out one
            // subpackage each. Installing `cyrus-sasl` alone gets no PLAIN.
            sasl: "cyrus-sasl-plain",
            repository: "AppStream (postfix) and BaseOS (cyrus-sasl-plain)",
        },
    }
}

/// The debconf answers that must be in place *before* `postfix` is installed on
/// the Debian family.
///
/// # The hang this prevents, and the thing that actually prevents it
///
/// Debian's `postfix.postinst` asks `postfix/main_mailer_type` at debconf
/// priority `high`. Under an interactive frontend that is a full-screen menu,
/// and an unattended install stops dead on it — holding the dpkg lock, so every
/// later package operation on the machine queues behind a question nobody is
/// there to answer. What stops that is the *frontend*, not the answers:
/// `DEBIAN_FRONTEND=noninteractive`, which [`AptBackend::apt`] sets on every
/// invocation, tells debconf never to block and to take a stored answer or the
/// default instead. `a_postfix_install_cannot_stop_on_a_debconf_question`
/// asserts that environment variable is still there, because deleting it is all
/// it would take to bring the hang back.
///
/// # Why preseed at all, then
///
/// Because the default that frontend would take is `Internet Site`, and a
/// Debian postfix configured as an Internet Site comes up with
/// `inet_interfaces = all` — an MTA listening on port 25 on every address of
/// the machine, from the moment `apt-get install` finishes until the panel
/// renders its own `main.cf` and reloads. That window is short and it is real,
/// and an open relay-adjacent listener is not something to leave to a race with
/// a config render. `Local only` produces `inet_interfaces = loopback-only` in
/// the package's own generated configuration, which is the posture the null
/// client wants anyway, so the machine is never reachable on 25 at any point.
///
/// `No configuration` would be the tempting answer — "we write main.cf
/// ourselves" — and it is the wrong one: it makes the postinst skip
/// configuration entirely, and `/etc/postfix` is then missing `master.cf` and
/// the queue directories, which are files the panel does not render and Postfix
/// cannot start without.
pub fn postfix_debconf_selections(mailname: &str) -> Result<String> {
    let name = parse_mailname(mailname)?;
    // One `<package> <question> <type> <value>` line each. Fed to
    // `debconf-set-selections` on stdin, so `name` is not reaching a shell —
    // but it is reaching a line-oriented format, which is why a newline in it
    // is refused above rather than escaped: it would set a question of the
    // sender's choosing, for any package on the machine.
    Ok(format!(
        "postfix postfix/main_mailer_type select Local only\n\
         postfix postfix/mailname string {name}\n"
    ))
}

/// Accept the value for `postfix/mailname`: the machine's own fully-qualified
/// name, and nothing that could be a second debconf line.
fn parse_mailname(input: &str) -> Result<String> {
    let name = input.trim();
    if name.is_empty() || name.len() > 253 {
        return Err(DistroError::InvalidName(
            "the mail name must be 1-253 characters".into(),
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        || name.starts_with(['.', '-'])
        || name.ends_with(['.', '-'])
        || name.contains("..")
    {
        return Err(DistroError::InvalidName(format!(
            "`{name}` is not a plausible host name for postfix/mailname"
        )));
    }
    Ok(name.to_string())
}

/// Store [`postfix_debconf_selections`] so the coming install reads them.
///
/// A no-op on the RHEL family, which has no debconf and asks nothing: rpm
/// scriptlets never prompt, so there is no question to pre-answer and nothing
/// to fail on. Saying so in the log beats a silent skip, because "did the
/// preseed run?" is the first thing to check when an install hangs.
pub async fn preseed_postfix(family: Family, mailname: &str, log: &dyn LogSink) -> Result<()> {
    if family == Family::Rhel {
        log.line("no debconf on this family; postfix's rpm scriptlets ask nothing");
        return Ok(());
    }

    let selections = postfix_debconf_selections(mailname)?;

    // `debconf-set-selections` is in the `debconf` package, which is Essential
    // on every Debian-family release — so its absence is not a machine to carry
    // on installing mail onto. Refusing here beats installing postfix with
    // whatever answers the package picks and reporting mail configured.
    if !crate::exec::program_available("debconf-set-selections") {
        return Err(DistroError::PackageFailed(
            "`debconf-set-selections` is missing, so postfix's install questions cannot be \
             answered in advance; refusing rather than installing an MTA whose listening \
             configuration nobody chose"
                .into(),
        ));
    }

    // On stdin, not in argv and not through a shell: this is the same reason
    // SQL reaches `mariadb` that way (spec §12 rule 2).
    let out = Cmd::new("debconf-set-selections")
        .stdin_data(selections)
        .run()
        .await?;
    if !out.success() {
        return Err(DistroError::PackageFailed(format!(
            "could not pre-answer postfix's install questions: {}",
            out.failure_text()
        )));
    }
    log.line(
        "pre-answered postfix/main_mailer_type as `Local only`, so the package's own \
         configuration binds the loopback and never port 25 on a public address",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Debian family
// ---------------------------------------------------------------------------

/// `apt-get` / `dpkg-query`, run non-interactively and told never to touch a
/// config file a human has edited (`--force-confold`).
pub struct AptBackend {
    timeout: std::time::Duration,
}

impl AptBackend {
    pub fn new() -> Self {
        // Package installs on a small VPS are genuinely slow; the ceiling is here
        // to catch a hung mirror, not to bound normal work.
        Self {
            timeout: std::time::Duration::from_secs(1800),
        }
    }

    fn apt(&self) -> Cmd {
        Cmd::new("apt-get")
            .env("DEBIAN_FRONTEND", "noninteractive")
            .env("NEEDRESTART_MODE", "a")
            // Wait for the dpkg lock instead of dying on it. apt-get's default
            // is to fail immediately, and package work does overlap: two stack
            // components installed at once, an install that meets the backup
            // pass installing restic, or simply an operator running apt in
            // their own ssh session. Every one of those used to fail a task for
            // a package that was perfectly installable. Ten minutes is well
            // inside the command's own half-hour ceiling.
            .args(["-o", "DPkg::Lock::Timeout=600"])
            .timeout(self.timeout)
    }
}

impl Default for AptBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PkgBackend for AptBackend {
    fn name(&self) -> &'static str {
        "apt"
    }

    async fn update_index(&self, log: &dyn LogSink) -> Result<CmdOutput> {
        self.apt()
            .arg("update")
            .run_streaming(|l| log.line(l))
            .await
    }

    async fn install(&self, packages: &[PackageName], log: &dyn LogSink) -> Result<CmdOutput> {
        if packages.is_empty() {
            return Err(DistroError::PackageFailed("no packages given".into()));
        }
        let out = self
            .apt()
            .args([
                "install",
                "-y",
                "--no-install-recommends",
                // Never silently replace a config file the operator edited.
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
            ])
            .args(packages.iter().map(|p| p.as_str()))
            .run_streaming(|l| log.line(l))
            .await?;
        check(out)
    }

    async fn remove(&self, packages: &[PackageName], log: &dyn LogSink) -> Result<CmdOutput> {
        let out = self
            .apt()
            .args(["remove", "-y"])
            .args(packages.iter().map(|p| p.as_str()))
            .run_streaming(|l| log.line(l))
            .await?;
        check(out)
    }

    async fn query(&self, package: &PackageName) -> Result<PackageStatus> {
        let installed = Cmd::new("dpkg-query")
            .args(["-W", "-f=${db:Status-Status}\t${Version}"])
            .arg(package.as_str())
            .run()
            .await?;

        let (is_installed, installed_version) = if installed.success() {
            let line = installed.trimmed_stdout();
            let (status, version) = line.split_once('\t').unwrap_or((line, ""));
            (
                status == "installed",
                (!version.is_empty()).then(|| version.to_string()),
            )
        } else {
            (false, None)
        };

        // `apt-cache policy` prints "  Candidate: 1.2.3" (or "(none)").
        let policy = Cmd::new("apt-cache")
            .arg("policy")
            .arg(package.as_str())
            .run()
            .await?;
        let candidate = policy
            .stdout
            .lines()
            .find_map(|l| l.trim().strip_prefix("Candidate:"))
            .map(str::trim)
            .filter(|v| *v != "(none)")
            .map(str::to_string);

        Ok(PackageStatus {
            name: package.as_str().to_string(),
            installed: is_installed,
            installed_version,
            candidate_version: candidate,
        })
    }

    async fn add_repo(
        &self,
        repo: &RepoDefinition,
        key_material: &[u8],
        _options: &[(String, String)],
        log: &dyn LogSink,
    ) -> Result<()> {
        repo.validate()?;

        // The pin check, before anything reaches the filesystem.
        let matched = crate::pgp::verify_pinned(key_material, &repo.accepted_fingerprints)?;
        log.line(&format!(
            "verified {} signing key {}",
            repo.display_name, matched.fingerprint
        ));

        let suite = repo.suite.clone().ok_or_else(|| {
            DistroError::InvalidName(format!("repo `{}` needs a suite on this family", repo.id))
        })?;

        // The key goes in beside the sources file, scoped to this repository by
        // `Signed-By` below — never through `apt-key`, which is deprecated
        // precisely because it made every key trusted for every repository.
        // `write_apt_key` picks the extension from the bytes; see its docs for
        // why assuming one broke every PHP install.
        let key_path = write_apt_key(Path::new(KEYRING_DIR), &repo.file_stem(), key_material, log)?;

        // deb822 format: it is the one that lets `Signed-By` scope a key to a
        // single repository.
        let sources = format!(
            "# {}\n\
             # Managed by Unihelm. Signing key pinned to {}.\n\
             Types: deb\n\
             URIs: {}\n\
             Suites: {}\n\
             Components: {}\n\
             Architectures: {}\n\
             Signed-By: {}\n",
            repo.display_name,
            matched.fingerprint,
            repo.base_url,
            suite,
            repo.components.join(" "),
            deb_arch(),
            key_path.display(),
        );

        let sources_path =
            PathBuf::from(APT_SOURCES_DIR).join(format!("{}.sources", repo.file_stem()));
        write_root_file(&sources_path, sources.as_bytes(), 0o644)?;
        log.line(&format!("wrote {}", sources_path.display()));

        // A repository that is registered but whose index has not been fetched
        // is a repository that does not work yet.
        self.update_index(log).await?;
        Ok(())
    }

    async fn ensure_prerequisite(
        &self,
        prerequisite: &crate::repos::Prerequisite,
        log: &dyn LogSink,
    ) -> Result<()> {
        // Debian-family repositories we use are self-contained; nothing here
        // needs an extra archive enabled.
        log.line(&format!(
            "no prerequisite needed on this family for {prerequisite:?}"
        ));
        Ok(())
    }

    async fn remove_repo(&self, repo_id: &str) -> Result<()> {
        let stem = format!("unihelm-{repo_id}");
        // Both spellings of the keyring, because `add_repo` writes whichever one
        // the key material called for. Hardcoding `.asc` here left a `.gpg` key
        // in /etc/apt/keyrings forever, for a repository the panel had reported
        // as removed.
        let mut paths = vec![PathBuf::from(APT_SOURCES_DIR).join(format!("{stem}.sources"))];
        paths.extend(apt_key_paths(Path::new(KEYRING_DIR), &stem));
        unlink_all(&paths)
    }
}

// ---------------------------------------------------------------------------
// RHEL family
// ---------------------------------------------------------------------------

/// `dnf` / `rpm`.
pub struct DnfBackend {
    timeout: std::time::Duration,
}

impl DnfBackend {
    pub fn new() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(1800),
        }
    }

    fn dnf(&self) -> Cmd {
        Cmd::new("dnf").arg("-y").timeout(self.timeout)
    }
}

impl Default for DnfBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PkgBackend for DnfBackend {
    fn name(&self) -> &'static str {
        "dnf"
    }

    async fn update_index(&self, log: &dyn LogSink) -> Result<CmdOutput> {
        self.dnf()
            .arg("makecache")
            .run_streaming(|l| log.line(l))
            .await
    }

    async fn install(&self, packages: &[PackageName], log: &dyn LogSink) -> Result<CmdOutput> {
        if packages.is_empty() {
            return Err(DistroError::PackageFailed("no packages given".into()));
        }
        let out = self
            .dnf()
            .arg("install")
            .args(packages.iter().map(|p| p.as_str()))
            .run_streaming(|l| log.line(l))
            .await?;
        check(out)
    }

    async fn remove(&self, packages: &[PackageName], log: &dyn LogSink) -> Result<CmdOutput> {
        let out = self
            .dnf()
            .arg("remove")
            .args(packages.iter().map(|p| p.as_str()))
            .run_streaming(|l| log.line(l))
            .await?;
        check(out)
    }

    async fn query(&self, package: &PackageName) -> Result<PackageStatus> {
        let installed = Cmd::new("rpm")
            .args(["-q", "--qf", "%{VERSION}-%{RELEASE}"])
            .arg(package.as_str())
            .run()
            .await?;
        let installed_version = installed
            .success()
            .then(|| installed.trimmed_stdout().to_string())
            .filter(|s| !s.is_empty());

        let available = Cmd::new("dnf")
            .args([
                "--quiet",
                "repoquery",
                "--queryformat",
                "%{version}-%{release}",
                "--latest-limit",
                "1",
            ])
            .arg(package.as_str())
            .run()
            .await?;
        let candidate = available
            .success()
            .then(|| {
                available
                    .trimmed_stdout()
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
            .filter(|s| !s.is_empty());

        Ok(PackageStatus {
            name: package.as_str().to_string(),
            installed: installed_version.is_some(),
            installed_version,
            candidate_version: candidate,
        })
    }

    async fn add_repo(
        &self,
        repo: &RepoDefinition,
        key_material: &[u8],
        options: &[(String, String)],
        log: &dyn LogSink,
    ) -> Result<()> {
        repo.validate()?;

        let matched = crate::pgp::verify_pinned(key_material, &repo.accepted_fingerprints)?;
        log.line(&format!(
            "verified {} signing key {}",
            repo.display_name, matched.fingerprint
        ));

        let key_path = PathBuf::from(RPM_GPG_DIR).join(format!("RPM-GPG-KEY-{}", repo.file_stem()));
        write_root_file(&key_path, key_material, 0o644)?;

        // Import into rpm's own keyring as well. dnf would do this on first use,
        // but it prompts, and doing it now means the import is an explicit,
        // audited step rather than a surprise inside a package install.
        Cmd::new("rpm")
            .arg("--import")
            .arg(&key_path)
            .run_checked()
            .await?;

        let mut body = format!(
            "# {}\n\
             # Managed by Unihelm. Signing key pinned to {}.\n\
             [{}]\n\
             name={}\n\
             baseurl={}\n\
             enabled=1\n\
             gpgcheck=1\n\
             gpgkey=file://{}\n",
            repo.display_name,
            matched.fingerprint,
            repo.file_stem(),
            repo.display_name,
            repo.base_url,
            key_path.display(),
        );
        for (key, value) in options {
            body.push_str(&format!("{key}={value}\n"));
        }

        let repo_path = PathBuf::from(YUM_REPOS_DIR).join(format!("{}.repo", repo.file_stem()));
        write_root_file(&repo_path, body.as_bytes(), 0o644)?;
        log.line(&format!("wrote {}", repo_path.display()));

        self.update_index(log).await?;
        Ok(())
    }

    async fn ensure_prerequisite(
        &self,
        prerequisite: &crate::repos::Prerequisite,
        log: &dyn LogSink,
    ) -> Result<()> {
        use crate::repos::Prerequisite;

        match prerequisite {
            Prerequisite::DistroPackage(name) => {
                let package = PackageName::parse(name)?;
                // Already there? `dnf install` would be a no-op, but saying so
                // is cheaper and reads better in a task log.
                if self
                    .query(&package)
                    .await
                    .map(|s| s.installed)
                    .unwrap_or(false)
                {
                    log.line(&format!("{name} is already installed"));
                    return Ok(());
                }
                log.line(&format!("installing {name} (required by this repository)"));
                let out = self
                    .dnf()
                    .arg("install")
                    .arg(package.as_str())
                    .run_streaming(|l| log.line(l))
                    .await?;
                check(out).map(|_| ())
            }

            Prerequisite::EnableRepo(name) => {
                // Best effort. The repository is named differently on RHEL
                // proper than on its rebuilds, and an install that does not
                // actually need it should not fail because of a name.
                if !crate::exec::program_available("dnf") {
                    return Ok(());
                }
                let attempt = Cmd::new("dnf")
                    .args(["-y", "config-manager", "--set-enabled"])
                    .arg(name)
                    .run()
                    .await;

                match attempt {
                    Ok(out) if out.success() => {
                        log.line(&format!("enabled the `{name}` repository"));
                    }
                    _ => {
                        // `dnf config-manager` lives in dnf-plugins-core, which a
                        // minimal install may not have.
                        let plugins = PackageName::parse("dnf-plugins-core")?;
                        let _ = self.dnf().arg("install").arg(plugins.as_str()).run().await;
                        let retry = Cmd::new("dnf")
                            .args(["-y", "config-manager", "--set-enabled"])
                            .arg(name)
                            .run()
                            .await;
                        match retry {
                            Ok(out) if out.success() => {
                                log.line(&format!("enabled the `{name}` repository"))
                            }
                            _ => log.line(&format!(
                                "could not enable `{name}`; continuing, since not every \
                                 package needs it"
                            )),
                        }
                    }
                }
                Ok(())
            }

            Prerequisite::DisableModule(name) => {
                // Best effort, deliberately: EL10's dnf5 removed modularity, so
                // `dnf module` is not even a subcommand there — and a module
                // that does not exist needs no disabling. On EL9 this is the
                // step PGDG's own instructions require, so a real failure is
                // still worth a log line the operator can find.
                let attempt = Cmd::new("dnf")
                    .args(["-y", "module", "disable"])
                    .arg(name)
                    .run()
                    .await;
                match attempt {
                    Ok(out) if out.success() => {
                        log.line(&format!("disabled the `{name}` module stream"));
                    }
                    _ => log.line(&format!(
                        "could not disable the `{name}` module stream; continuing — \
                         this distribution may have no modularity at all"
                    )),
                }
                Ok(())
            }
        }
    }

    async fn remove_repo(&self, repo_id: &str) -> Result<()> {
        // rpm keys carry no extension, so there is only ever one name to unlink.
        let stem = format!("unihelm-{repo_id}");
        unlink_all(&[
            PathBuf::from(YUM_REPOS_DIR).join(format!("{stem}.repo")),
            PathBuf::from(RPM_GPG_DIR).join(format!("RPM-GPG-KEY-{stem}")),
        ])
    }
}

/// Where each family expects a third-party signing key and its repository file.
const APT_SOURCES_DIR: &str = "/etc/apt/sources.list.d";
const KEYRING_DIR: &str = "/etc/apt/keyrings";
const YUM_REPOS_DIR: &str = "/etc/yum.repos.d";
const RPM_GPG_DIR: &str = "/etc/pki/rpm-gpg";

/// The architecture name apt uses, which is not the kernel's name for it.
fn deb_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Both names an apt signing key can have.
///
/// `add_repo` writes exactly one of these — which one depends on the key the
/// vendor served — so anything that cleans up after it has to consider both.
fn apt_key_paths(keyring_dir: &Path, stem: &str) -> [PathBuf; 2] {
    [
        keyring_dir.join(format!("{stem}.asc")),
        keyring_dir.join(format!("{stem}.gpg")),
    ]
}

/// Save a repository signing key under the extension its bytes call for.
///
/// apt does not sniff a keyring named in `Signed-By:`; it reads `.asc` as
/// ASCII-armored and `.gpg` as binary, and a mismatch is not a warning but a
/// repository apt refuses as unsigned. This used to hardcode `.asc`, and Surý
/// publishes packages.sury.org/php/apt.gpg as *binary* OpenPGP: the panel
/// verified the key, wrote it, said the repository was added, and every PHP
/// version was then uninstallable with `NO_PUBKEY` on the next `apt update`.
/// The armour check is the whole fix — `Signed-By` interpolates the path this
/// returns, so the sources file follows.
fn write_apt_key(
    keyring_dir: &Path,
    stem: &str,
    key_material: &[u8],
    log: &dyn LogSink,
) -> Result<PathBuf> {
    let armored = crate::pgp::looks_armored(key_material);
    let path = keyring_dir.join(format!("{stem}.{}", if armored { "asc" } else { "gpg" }));
    write_root_file(&path, key_material, 0o644)?;
    log.line(&format!(
        "wrote {} ({})",
        path.display(),
        if armored {
            "ASCII-armored OpenPGP"
        } else {
            "binary OpenPGP"
        }
    ));

    // A vendor that changes format — or a server that was set up by the build
    // that always wrote `.asc` — would otherwise keep an unparseable keyring
    // sitting next to the good one, for the next operator to debug.
    for stale in apt_key_paths(keyring_dir, stem) {
        if stale == path {
            continue;
        }
        match std::fs::remove_file(&stale) {
            Ok(()) => log.line(&format!(
                "removed {}, which held this key in the other format",
                stale.display()
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Not fatal: the key apt will actually read is already in place.
            // Saying so beats a silent leftover.
            Err(e) => log.line(&format!("could not remove {}: {e}", stale.display())),
        }
    }

    Ok(path)
}

/// Unlink managed files, treating "already gone" as done rather than as an
/// error — removing a repository twice is not a failure.
fn unlink_all(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(DistroError::PackageFailed(format!(
                    "{}: {e}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

/// Write a root-owned config file, creating its directory if needed.
fn write_root_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| DistroError::PackageFailed(format!("{}: {e}", dir.display())))?;
    }

    // Same-directory temp plus rename, so a partially written repository file
    // never exists for apt or dnf to read.
    let mut temp = path.to_path_buf();
    temp.as_mut_os_string().push(".unihelm-tmp");

    let write = |temp: &Path| -> std::io::Result<()> {
        let mut file = std::fs::File::create(temp)?;
        file.write_all(contents)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()
    };

    write(&temp).map_err(|e| DistroError::PackageFailed(format!("{}: {e}", temp.display())))?;
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        DistroError::PackageFailed(format!("{}: {e}", path.display()))
    })?;
    Ok(())
}

fn check(out: CmdOutput) -> Result<CmdOutput> {
    if out.success() {
        Ok(out)
    } else {
        Err(DistroError::PackageFailed(out.failure_text()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(fingerprints: &[&str]) -> RepoDefinition {
        RepoDefinition {
            id: "nginx".into(),
            display_name: "nginx.org".into(),
            base_url: "https://nginx.org/packages/debian".into(),
            suite: Some("bookworm".into()),
            components: vec!["nginx".into()],
            gpg_key_url: "https://nginx.org/keys/nginx_signing.key".into(),
            accepted_fingerprints: fingerprints.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn an_apt_invocation_waits_for_the_dpkg_lock_rather_than_failing_on_it() {
        // Two package operations at once are normal on this panel — the stack
        // page, the scheduler's `ensure_restic`, an operator's own ssh session
        // — and without this the second one dies on "Could not get lock
        // /var/lib/dpkg/lock-frontend" and the task is recorded as failed.
        let line = AptBackend::new().apt().display();
        assert!(line.contains("DPkg::Lock::Timeout=600"), "{line}");
    }

    #[test]
    fn package_names_reject_options_and_paths() {
        assert!(PackageName::parse("php8.3-fpm").is_ok());
        assert!(PackageName::parse("php83-php-fpm").is_ok());
        assert!(PackageName::parse("gcc-c++").is_ok());
        for bad in [
            "",
            "-rf",
            "--force-yes",
            "/etc/passwd",
            "a b",
            "pkg;rm -rf /",
            "pkg$(id)",
            "../x",
        ] {
            assert!(
                PackageName::parse(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn a_repo_must_pin_at_least_one_full_fingerprint() {
        assert!(
            repo(&["573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"])
                .validate()
                .is_ok()
        );
        // Spaced and lowercase forms are how vendors publish them.
        assert!(
            repo(&["573B FD6B 3D8F BC64 1079 A6AB ABF5 BD82 7BD9 BF62"])
                .validate()
                .is_ok()
        );
        assert!(
            repo(&[]).validate().is_err(),
            "a repo with no pin must be refused"
        );
        // A short key id is forgeable.
        assert!(repo(&["7BD9BF62"]).validate().is_err());
        assert!(
            repo(&["ZZZZFD6B3D8FBC641079A6ABABF5BD827BD9BF62"])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn a_bundle_of_pins_is_allowed() {
        // nginx ships three keys; all three are legitimate.
        let r = repo(&[
            "8540A6F18833A80E9C1653A42FD21310B49F6B46",
            "573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62",
            "9E9BE90EACBCDE69FE9B204CBCDCD8A38D88A2B3",
        ]);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn repo_requires_https_for_both_urls() {
        let mut r = repo(&["573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"]);
        r.base_url = "http://nginx.org/packages/debian".into();
        assert!(r.validate().is_err());

        let mut r = repo(&["573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"]);
        r.gpg_key_url = "http://nginx.org/keys/nginx_signing.key".into();
        assert!(r.validate().is_err());
    }

    #[test]
    fn a_repo_id_or_suite_cannot_escape_into_a_path() {
        let mut r = repo(&["573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"]);
        r.id = "../../etc/cron.d/evil".into();
        assert!(r.validate().is_err());

        let mut r = repo(&["573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"]);
        r.suite = Some("../../..".into());
        assert!(r.validate().is_err());

        // A suite may carry path segments — MongoDB's is `noble/mongodb-org/8.0`
        // — so the check is per segment rather than "no slashes at all".
        for good in ["bookworm", "trixie-pgdg", "noble/mongodb-org/8.0"] {
            let mut r = repo(&["573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"]);
            r.suite = Some(good.into());
            assert!(r.validate().is_ok(), "`{good}` should be a valid suite");
        }
        for bad in [
            "",
            "/noble",
            "noble/",
            "a//b",
            "noble/../etc",
            "noble/./x",
            // A newline would end `Suites:` and start a deb822 field of the
            // attacker's choosing, `Signed-By` included.
            "noble\nSigned-By: /tmp/theirs.asc",
            "noble mongodb-org",
        ] {
            let mut r = repo(&["573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"]);
            r.suite = Some(bad.into());
            assert!(
                r.validate().is_err(),
                "`{bad}` should be refused as a suite"
            );
        }

        assert_eq!(
            repo(&["573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"]).file_stem(),
            "unihelm-nginx"
        );
    }

    /// Raw binary OpenPGP, the shape packages.sury.org/php/apt.gpg is served in.
    ///
    /// The bytes need only be un-armored: by the time key material reaches the
    /// writer, `verify_pinned` has already decided it is the right key.
    fn binary_key() -> Vec<u8> {
        let mut body = vec![4]; // v4 public key packet
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(1); // RSA
        body.extend_from_slice(&8u16.to_be_bytes());
        body.push(0xAB);
        let mut packet = vec![0xC6, body.len() as u8];
        packet.extend_from_slice(&body);
        packet
    }

    /// The armored form, as PostgreSQL and MongoDB publish it.
    fn armored_key() -> Vec<u8> {
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENBGaSURYBCAC0\n=Ab12\n-----END PGP PUBLIC KEY BLOCK-----\n".to_vec()
    }

    #[test]
    fn a_binary_signing_key_is_stored_as_gpg_and_an_armored_one_as_asc() {
        // apt reads a `Signed-By:` keyring by extension, not by sniffing. When
        // this assumed `.asc`, Surý's binary key was unreadable and every PHP
        // version failed to install with `NO_PUBKEY` — while the panel reported
        // the repository as added.
        let dir = tempfile::tempdir().unwrap();

        let binary =
            write_apt_key(dir.path(), "unihelm-php-sury", &binary_key(), &NullLog).unwrap();
        assert_eq!(
            binary.file_name().unwrap(),
            "unihelm-php-sury.gpg",
            "binary key material must not be given an armored extension"
        );
        assert_eq!(
            std::fs::read(&binary).unwrap(),
            binary_key(),
            "the key is stored verbatim; only its name is chosen"
        );

        let armored = write_apt_key(dir.path(), "unihelm-pgdg", &armored_key(), &NullLog).unwrap();
        assert_eq!(armored.file_name().unwrap(), "unihelm-pgdg.asc");
    }

    #[test]
    fn re_adding_a_repository_in_the_other_format_leaves_no_unreadable_key_behind() {
        // The upgrade path off the broken build: the server already has a `.asc`
        // holding binary bytes, and apt must not be left with two candidate
        // keyrings when the correct one is written.
        let dir = tempfile::tempdir().unwrap();
        let stale =
            write_apt_key(dir.path(), "unihelm-php-sury", &armored_key(), &NullLog).unwrap();
        let fresh = write_apt_key(dir.path(), "unihelm-php-sury", &binary_key(), &NullLog).unwrap();

        assert!(fresh.exists());
        assert!(!stale.exists(), "{} survived the rewrite", stale.display());
    }

    #[test]
    fn removing_a_repository_unlinks_the_keyring_under_either_extension() {
        // Removal used to hardcode `.asc`, so a binary key stayed in
        // /etc/apt/keyrings forever after the panel said the repo was gone.
        for material in [binary_key(), armored_key()] {
            let dir = tempfile::tempdir().unwrap();
            let key = write_apt_key(dir.path(), "unihelm-php-sury", &material, &NullLog).unwrap();
            assert!(key.exists());

            unlink_all(&apt_key_paths(dir.path(), "unihelm-php-sury")).unwrap();
            assert!(!key.exists(), "{} survived removal", key.display());
        }

        // Removing a repository that was never added is not a failure.
        let dir = tempfile::tempdir().unwrap();
        assert!(unlink_all(&apt_key_paths(dir.path(), "unihelm-absent")).is_ok());
    }

    fn os(id: &str, version_id: &str, family: Family) -> DistroInfo {
        DistroInfo {
            id: id.into(),
            version_id: version_id.into(),
            codename: String::new(),
            pretty_name: format!("{id} {version_id}"),
            family,
            arch: crate::Arch::X86_64,
            has_systemd: true,
            has_cgroups_v2: true,
        }
    }

    #[test]
    fn the_releases_that_package_a_modsecurity_connector_are_named_exactly() {
        for (id, version, family, package, repository) in [
            (
                "debian",
                "12",
                Family::Debian,
                "libnginx-mod-http-modsecurity",
                "main",
            ),
            (
                "debian",
                "13",
                Family::Debian,
                "libnginx-mod-http-modsecurity",
                "main",
            ),
            (
                "ubuntu",
                "24.04",
                Family::Debian,
                "libnginx-mod-http-modsecurity",
                "universe",
            ),
            (
                "ubuntu",
                "26.04",
                Family::Debian,
                "libnginx-mod-http-modsecurity",
                "universe",
            ),
            (
                "almalinux",
                "9",
                Family::Rhel,
                "nginx-mod-modsecurity",
                "EPEL 9",
            ),
            (
                "rocky",
                "9",
                Family::Rhel,
                "nginx-mod-modsecurity",
                "EPEL 9",
            ),
        ] {
            match modsec_connector(&os(id, version, family)) {
                ModsecConnector::Packaged(p) => {
                    assert_eq!(p.package, package, "{id} {version}");
                    assert!(
                        p.repository.contains(repository),
                        "{id} {version} must name the component or repository an \
                         operator has to enable, got `{}`",
                        p.repository
                    );
                }
                other => panic!("{id} {version} should be packaged, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_release_with_no_connector_at_all_says_so_rather_than_naming_a_package() {
        // Both of these are releases `support_status` calls Supported, and on
        // neither can a WAF be made to run without compiling a module. Naming
        // `libnginx-mod-http-modsecurity` to a 22.04 operator, or
        // `nginx-mod-modsecurity` to an EL 10 one, sends them looking for a
        // package that has never existed for their release.
        for (id, version, family, checked) in [
            ("ubuntu", "22.04", Family::Debian, "jammy"),
            ("almalinux", "10", Family::Rhel, "EPEL 10"),
            ("rocky", "10", Family::Rhel, "EPEL 10"),
        ] {
            match modsec_connector(&os(id, version, family)) {
                ModsecConnector::Unpackaged { checked: what } => assert!(
                    what.contains(checked),
                    "the refusal has to say what was searched, got `{what}`"
                ),
                // Neither of the other two variants carries a package name that
                // is safe to print here, which is the whole point.
                other => panic!("{id} {version} must be Unpackaged, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_release_nobody_has_checked_is_reported_as_unchecked_not_as_available() {
        // Ubuntu 23.10 and EL 8 are outside the tested matrix. Answering
        // `Packaged` for them would be the panel asserting a fact it does not
        // have; answering `Unpackaged` would be asserting the opposite one.
        for (id, version, family, package) in [
            (
                "ubuntu",
                "23.10",
                Family::Debian,
                "libnginx-mod-http-modsecurity",
            ),
            ("rocky", "8", Family::Rhel, "nginx-mod-modsecurity"),
            (
                "linuxmint",
                "22",
                Family::Debian,
                "libnginx-mod-http-modsecurity",
            ),
        ] {
            match modsec_connector(&os(id, version, family)) {
                ModsecConnector::Unverified { package: p, .. } => assert_eq!(p, package),
                other => panic!("{id} {version} should be unverified, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_packages_a_postfix_null_client_needs_name_the_sasl_plugin_too() {
        // The MTA alone authenticates to nothing: the PLAIN mechanism is a
        // Cyrus SASL plugin in a package of its own on both families, and its
        // absence produces `no mechanism available`, which reads exactly like a
        // wrong password. Every supported release of a family answers the same,
        // which is why this is checked per family rather than per release.
        for (id, version, family, sasl) in [
            ("debian", "12", Family::Debian, "libsasl2-modules"),
            ("debian", "13", Family::Debian, "libsasl2-modules"),
            ("ubuntu", "22.04", Family::Debian, "libsasl2-modules"),
            ("ubuntu", "24.04", Family::Debian, "libsasl2-modules"),
            ("almalinux", "9", Family::Rhel, "cyrus-sasl-plain"),
            ("rocky", "10", Family::Rhel, "cyrus-sasl-plain"),
            ("rhel", "9", Family::Rhel, "cyrus-sasl-plain"),
        ] {
            let packages = postfix_packages(&os(id, version, family));
            assert_eq!(packages.mta, "postfix", "{id} {version}");
            assert_eq!(packages.sasl, sasl, "{id} {version}");
            assert!(
                packages.names().contains(&sasl),
                "{id} {version} would install an MTA that cannot authenticate"
            );
            assert!(
                !packages.repository.is_empty(),
                "an operator has to be told where these come from"
            );
        }

        // `cyrus-sasl` is the library and the daemon; the mechanisms are
        // separate subpackages, so the base name buys no PLAIN at all.
        assert_ne!(
            postfix_packages(&os("almalinux", "9", Family::Rhel)).sasl,
            "cyrus-sasl"
        );
    }

    #[test]
    fn postfix_packages_are_installable_names() {
        for family in [Family::Debian, Family::Rhel] {
            let packages = postfix_packages(&os("x", "1", family));
            let parsed = packages.parsed().expect("a constant that does not parse");
            assert_eq!(parsed.len(), 2);
            assert_eq!(parsed[0].as_str(), packages.mta);
            assert_eq!(parsed[1].as_str(), packages.sasl);
        }
    }

    #[test]
    fn a_postfix_install_cannot_stop_on_a_debconf_question() {
        // Debian's postfix.postinst asks `postfix/main_mailer_type` at priority
        // `high`. Under an interactive frontend that question holds the dpkg
        // lock forever and every later package operation on the machine queues
        // behind it. The frontend is what prevents that, not the preseed — so
        // this asserts the environment variable is still on the invocation.
        // Read out of `Debug` because `Cmd` keeps its environment private and
        // `display()` deliberately shows only the argv.
        let apt = format!("{:?}", AptBackend::new().apt());
        assert!(
            apt.contains("DEBIAN_FRONTEND") && apt.contains("noninteractive"),
            "an install could stop on a debconf prompt: {apt}"
        );
    }

    #[test]
    fn the_preseed_answers_the_question_with_an_mta_that_does_not_open_port_25() {
        // The default the noninteractive frontend would otherwise take is
        // `Internet Site`, whose generated main.cf carries
        // `inet_interfaces = all`: an MTA on port 25 on every address of the
        // machine, from the end of the install until the panel's own main.cf
        // lands. `Local only` generates `loopback-only` instead, so that window
        // never exists.
        let selections = postfix_debconf_selections("mail.example.com").unwrap();
        assert!(
            selections.contains("postfix/main_mailer_type select Local only"),
            "{selections}"
        );
        assert!(
            !selections.contains("Internet Site"),
            "the install would come up listening on every address: {selections}"
        );
        assert!(
            !selections.contains("No configuration"),
            "that answer skips the postinst entirely and leaves /etc/postfix \
             without master.cf, which the panel does not render: {selections}"
        );
        assert!(
            selections.contains("postfix/mailname string mail.example.com"),
            "{selections}"
        );
        // One setting per line, and exactly the two we mean.
        assert_eq!(selections.lines().count(), 2, "{selections}");
    }

    #[tokio::test]
    async fn preseeding_is_a_no_op_on_a_family_with_no_debconf() {
        // rpm scriptlets never prompt, so there is no question to pre-answer —
        // and a `debconf-set-selections` that does not exist must not be the
        // thing that fails a mail install on AlmaLinux.
        preseed_postfix(Family::Rhel, "mail.example.com", &NullLog)
            .await
            .expect("the RHEL family has nothing to preseed");
    }

    #[test]
    fn a_mail_name_cannot_smuggle_a_second_debconf_setting() {
        assert!(postfix_debconf_selections("mail.example.com").is_ok());
        assert!(postfix_debconf_selections("  host-1.example.com  ").is_ok());
        for hostile in [
            "",
            "-lead.example.com",
            "trail.example.com-",
            ".example.com",
            "a..b",
            "host name",
            // The one that matters: a newline ends the mailname line and
            // starts a setting for any package on the machine.
            "mail.example.com\npostfix postfix/main_mailer_type select Internet Site",
            "mail.example.com\ndebconf debconf/frontend select Dialog",
            "mail.example.com; rm -rf /",
            "$(id).example.com",
        ] {
            assert!(
                postfix_debconf_selections(hostile).is_err(),
                "expected `{hostile}` to be refused"
            );
        }
    }

    #[test]
    fn the_apt_architecture_name_is_not_the_kernel_name() {
        // `uname -m` says x86_64; apt wants amd64. Getting this wrong produces a
        // repository that resolves nothing.
        assert!(matches!(deb_arch(), "amd64" | "arm64"));
    }
}
