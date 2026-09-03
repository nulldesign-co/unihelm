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
        if let Some(suite) = &self.suite
            && (suite.is_empty()
                || !suite
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
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

        // apt reads armored keys from a `.asc` given to `Signed-By`, so there is
        // no need to dearmor — and no need for `apt-key`, which is deprecated
        // precisely because it made every key trusted for every repository.
        let key_path = PathBuf::from(KEYRING_DIR).join(format!("{}.asc", repo.file_stem()));
        write_root_file(&key_path, key_material, 0o644)?;

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
        for path in [
            PathBuf::from(APT_SOURCES_DIR).join(format!("{stem}.sources")),
            PathBuf::from(KEYRING_DIR).join(format!("{stem}.asc")),
        ] {
            match std::fs::remove_file(&path) {
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
        let stem = format!("unihelm-{repo_id}");
        for path in [
            PathBuf::from(YUM_REPOS_DIR).join(format!("{stem}.repo")),
            PathBuf::from(RPM_GPG_DIR).join(format!("RPM-GPG-KEY-{stem}")),
        ] {
            match std::fs::remove_file(&path) {
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

        assert_eq!(
            repo(&["573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"]).file_stem(),
            "unihelm-nginx"
        );
    }

    #[test]
    fn the_apt_architecture_name_is_not_the_kernel_name() {
        // `uname -m` says x86_64; apt wants amd64. Getting this wrong produces a
        // repository that resolves nothing.
        assert!(matches!(deb_arch(), "amd64" | "arm64"));
    }
}
