//! Packages and upstream repositories (spec §7.3).
//!
//! Ferrum installs **only** from official upstream repositories and never
//! compiles on a customer's server (spec §2.3). That is what makes security
//! updates somebody else's job — the single biggest operational difference from
//! the panels that build PHP from source.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::exec::{Cmd, CmdOutput};
use crate::{DistroError, Result};

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
/// Adding a repository is itself an audited operation (spec §7.3); the
/// fingerprint is compared against the downloaded key before anything is written
/// to `/etc/apt/sources.list.d` or `/etc/yum.repos.d`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoDefinition {
    /// Short identifier, also the config filename stem: `nginx`, `sury-php`.
    pub id: String,
    pub display_name: String,
    /// Debian: the `deb` URI. RHEL: the `baseurl`.
    pub base_url: String,
    /// Debian only: suite (`bookworm`) and components (`main`).
    pub suite: Option<String>,
    pub components: Vec<String>,
    /// Where the signing key is published.
    pub gpg_key_url: String,
    /// Full 40-hex-character fingerprint, no spaces. Verified before use.
    pub gpg_fingerprint: String,
}

impl RepoDefinition {
    /// Fingerprints are compared case-insensitively with spaces stripped, since
    /// vendors publish them in the spaced, uppercase form.
    pub fn normalised_fingerprint(&self) -> String {
        self.gpg_fingerprint
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_uppercase()
    }

    pub fn validate(&self) -> Result<()> {
        let fp = self.normalised_fingerprint();
        if fp.len() != 40 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DistroError::InvalidName(format!(
                "repo `{}` must pin a full 40-character GPG fingerprint",
                self.id
            )));
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
        Ok(())
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

    /// Register an upstream repository after verifying its pinned key.
    async fn add_repo(&self, repo: &RepoDefinition, log: &dyn LogSink) -> Result<()>;

    async fn is_installed(&self, package: &PackageName) -> Result<bool> {
        Ok(self.query(package).await?.installed)
    }
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

    async fn add_repo(&self, repo: &RepoDefinition, log: &dyn LogSink) -> Result<()> {
        repo.validate()?;
        // TODO(scope): Phase 1 (Stack Manager) implements key download +
        // fingerprint verification + deb822 source file writing. Landing it here
        // ahead of the module that uses it would be scope invented early, and an
        // unverified key path is worse than none at all.
        log.line(&format!(
            "would register {} from {}",
            repo.id, repo.base_url
        ));
        Err(DistroError::PackageFailed(
            "repository registration lands with the Stack Manager in Phase 1".into(),
        ))
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

    async fn add_repo(&self, repo: &RepoDefinition, log: &dyn LogSink) -> Result<()> {
        repo.validate()?;
        // TODO(scope): see AptBackend::add_repo — Phase 1.
        log.line(&format!(
            "would register {} from {}",
            repo.id, repo.base_url
        ));
        Err(DistroError::PackageFailed(
            "repository registration lands with the Stack Manager in Phase 1".into(),
        ))
    }
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

    #[test]
    fn package_names_reject_options_and_paths() {
        assert!(PackageName::parse("php8.3-fpm").is_ok());
        assert!(PackageName::parse("nginx").is_ok());
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

    fn repo(fp: &str) -> RepoDefinition {
        RepoDefinition {
            id: "nginx".into(),
            display_name: "nginx.org".into(),
            base_url: "https://nginx.org/packages/debian".into(),
            suite: Some("bookworm".into()),
            components: vec!["nginx".into()],
            gpg_key_url: "https://nginx.org/keys/nginx_signing.key".into(),
            gpg_fingerprint: fp.into(),
        }
    }

    #[test]
    fn repo_requires_a_full_pinned_fingerprint() {
        let full = "573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62";
        assert!(repo(full).validate().is_ok());
        // Spaced, uppercase — how vendors publish it.
        assert!(
            repo("573B FD6B 3D8F BC64 1079 A6AB ABF5 BD82 7BD9 BF62")
                .validate()
                .is_ok()
        );
        // A short key id is exactly the thing that makes pinning worthless.
        assert!(repo("7BD9BF62").validate().is_err());
        assert!(repo("").validate().is_err());
        assert!(
            repo("ZZZZFD6B3D8FBC641079A6ABABF5BD827BD9BF62")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn repo_requires_https() {
        let mut r = repo("573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62");
        r.base_url = "http://nginx.org/packages/debian".into();
        assert!(r.validate().is_err());
    }

    #[test]
    fn repo_id_cannot_escape_into_a_filename() {
        let mut r = repo("573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62");
        r.id = "../../etc/cron.d/evil".into();
        assert!(r.validate().is_err());
    }
}
