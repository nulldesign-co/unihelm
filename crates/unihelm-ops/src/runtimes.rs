//! Which language runtimes this machine has, and where each one lives.
//!
//! A control panel that only knows how to run PHP is not much use to somebody
//! whose site is a Node app, and one that knows about Node but only the single
//! `node` on `$PATH` is not much use to somebody running two apps that need
//! different major versions. Both were true here: `nodeapp.rs` resolved one
//! absolute `node` at create time and said so in its own header.
//!
//! This module is the discovery half. It reports what is installed, without
//! installing anything or changing a version — the same division as
//! `nginx_survey`, and for the same reason: reading is safe, and a panel has to
//! be able to see a machine before it can be trusted to change it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A language runtime the panel knows how to look for.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
    Node,
    Python,
    Php,
    Ruby,
    Go,
    Deno,
    Bun,
}

impl Runtime {
    pub const ALL: &'static [Runtime] = &[
        Runtime::Node,
        Runtime::Python,
        Runtime::Php,
        Runtime::Ruby,
        Runtime::Go,
        Runtime::Deno,
        Runtime::Bun,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Runtime::Node => "node",
            Runtime::Python => "python",
            Runtime::Php => "php",
            Runtime::Ruby => "ruby",
            Runtime::Go => "go",
            Runtime::Deno => "deno",
            Runtime::Bun => "bun",
        }
    }

    /// How the runtime spells its own name, for a sentence an operator reads.
    pub const fn display_name(self) -> &'static str {
        match self {
            Runtime::Node => "Node.js",
            Runtime::Python => "Python",
            Runtime::Php => "PHP",
            Runtime::Ruby => "Ruby",
            Runtime::Go => "Go",
            Runtime::Deno => "Deno",
            Runtime::Bun => "Bun",
        }
    }

    /// Binary names to look for, most specific first.
    ///
    /// Versioned names matter more than the bare one: a machine with node 18 and
    /// node 22 side by side has `node18`/`node22` or per-version directories,
    /// and the bare `node` is only whichever the distribution or a symlink
    /// happens to point at.
    fn candidates(self) -> &'static [&'static str] {
        match self {
            Runtime::Node => &["node"],
            // `python` alone is absent on modern distributions on purpose.
            Runtime::Python => &["python3", "python"],
            Runtime::Php => &["php"],
            Runtime::Ruby => &["ruby"],
            Runtime::Go => &["go"],
            Runtime::Deno => &["deno"],
            Runtime::Bun => &["bun"],
        }
    }

    /// The argument that makes it print its version.
    fn version_flag(self) -> &'static str {
        match self {
            Runtime::Go => "version",
            _ => "--version",
        }
    }

    /// Directories that hold several versions side by side, and the glob-ish
    /// prefix each version directory starts with.
    fn multi_version_roots(self) -> &'static [(&'static str, &'static str)] {
        match self {
            // fnm and nvm both keep one directory per version.
            Runtime::Node => &[
                ("/usr/local/n/versions/node", ""),
                ("/opt/fnm/node-versions", ""),
                ("/root/.local/share/fnm/node-versions", ""),
                ("/usr/local/nvm/versions/node", ""),
            ],
            // Debian and RHEL both ship `/usr/bin/php8.3` alongside `php`.
            Runtime::Php => &[("/usr/bin", "php")],
            Runtime::Python => &[("/usr/bin", "python3.")],
            _ => &[],
        }
    }
}

/// One installed version of one runtime.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstalledRuntime {
    pub runtime: Runtime,
    /// As the binary reports it, e.g. `22.11.0`.
    pub version: String,
    /// Absolute path, which is what a systemd unit needs.
    pub path: String,
    /// Whether this is the one a bare command name resolves to.
    pub is_default: bool,
}

/// Everything installed, grouped by runtime.
pub async fn survey() -> BTreeMap<Runtime, Vec<InstalledRuntime>> {
    let mut out: BTreeMap<Runtime, Vec<InstalledRuntime>> = BTreeMap::new();

    for &runtime in Runtime::ALL {
        let mut found: Vec<InstalledRuntime> = Vec::new();

        // The one a bare name resolves to. Searched through the same fixed
        // directory list the app runner uses, not $PATH, so a poisoned
        // environment cannot point the panel at something else.
        let mut default_path: Option<PathBuf> = None;
        for name in runtime.candidates() {
            if let Ok(path) = unihelm_distro::exec::resolve_program(name) {
                default_path = Some(path);
                break;
            }
        }

        if let Some(path) = &default_path
            && let Some(version) = probe_version(runtime, path).await
        {
            found.push(InstalledRuntime {
                runtime,
                version,
                path: path.display().to_string(),
                is_default: true,
            });
        }

        for (dir, prefix) in runtime.multi_version_roots() {
            for path in versioned_binaries(runtime, Path::new(dir), prefix) {
                if Some(&path) == default_path.as_ref() {
                    continue;
                }
                if let Some(version) = probe_version(runtime, &path).await {
                    found.push(InstalledRuntime {
                        runtime,
                        version,
                        path: path.display().to_string(),
                        is_default: false,
                    });
                }
            }
        }

        found.sort_by(|a, b| a.version.cmp(&b.version));
        found.dedup_by(|a, b| a.path == b.path);
        if !found.is_empty() {
            out.insert(runtime, found);
        }
    }
    out
}

/// Candidate binaries under a directory that holds several versions.
fn versioned_binaries(runtime: Runtime, dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if path.is_dir() {
            // A version directory: the binary is under bin/.
            let inner = path.join("bin").join(runtime.as_str());
            if inner.is_file() {
                out.push(inner);
            }
        } else if !prefix.is_empty()
            && name.starts_with(prefix)
            && name.len() > prefix.len()
            // `php8.3` yes, `phpize` and `php-config` no.
            // The WHOLE suffix must be a version, not merely start like one.
            // `php8.3` and `phpize` are told apart by the first character, but
            // `python3.12-config` is not: it is the same kind of helper script
            // as `php-config`, and its name carries a real version before the
            // `-config`. A server with it installed offered `3.12` as a version
            // to pin an application to, and the unit that produced would have
            // run `python3.12-config app.py` and died at first start.
            && name[prefix.len()..]
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.')
            && name[prefix.len()..].starts_with(|c: char| c.is_ascii_digit())
        {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Ask a binary what version it is.
async fn probe_version(runtime: Runtime, path: &Path) -> Option<String> {
    let out = unihelm_distro::Cmd::new(path.to_string_lossy().as_ref())
        .arg(runtime.version_flag())
        .timeout(std::time::Duration::from_secs(5))
        .run()
        .await
        .ok()?;

    let text = out.trimmed_stdout().to_string();
    let text = if text.is_empty() {
        out.failure_text()
    } else {
        text
    };
    extract_version(&text)
}

/// Pull `22.11.0` out of whatever the binary printed.
///
/// Every runtime spells this differently — `v22.11.0`, `Python 3.12.3`,
/// `PHP 8.3.6 (cli) (built: …)`, `go version go1.22.2 linux/amd64` — so the
/// first dotted number is taken rather than a per-runtime parser that would
/// need updating whenever one of them changes its banner.
pub fn extract_version(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut dots = 0;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                if bytes[i] == b'.' {
                    dots += 1;
                }
                i += 1;
            }
            let candidate = text[start..i].trim_end_matches('.');
            if dots >= 1 && !candidate.is_empty() {
                return Some(candidate.to_string());
            }
        } else {
            i += 1;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// the operation
// ---------------------------------------------------------------------------

use serde::{Deserialize, Serialize};
use unihelm_core::{ErrorCode, Permission, Result, UnihelmError};
use unihelm_distro::Family;

use crate::registry::{Execution, OpContext, TypedOperation};

#[derive(Debug, Default, serde::Deserialize)]
pub struct ListInput {}

#[derive(Debug, serde::Serialize)]
pub struct ListOutput {
    /// One row per installed version.
    ///
    /// Flat rather than grouped by runtime: the CLI renders a list of objects as
    /// a table and a nested one as a column of names, so grouping here would
    /// have shown an operator the word "node" and hidden the versions — which
    /// are the entire point of asking.
    pub runtimes: Vec<InstalledRuntime>,
}

/// What this machine can run.
pub struct List;

#[async_trait::async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "runtime.list";
    // Read-only, and the read permission: choosing which Node version to run an
    // app on starts with being able to see which ones exist.
    const PERMISSION: Permission = Permission::ServerRead;
    // A handful of `--version` calls with a 5s ceiling each.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, _ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let found = survey().await;
        Ok(ListOutput {
            runtimes: found.into_values().flatten().collect(),
        })
    }
}

/// `runtime.install` — put a language runtime on the machine.
///
/// Node comes from NodeSource, one repository per major line. Python, Go and
/// Ruby come from the **distribution's own repositories**: Debian, Ubuntu and
/// the RHEL rebuilds all ship the three, they are signed by a key the machine
/// already trusts, and their security updates arrive with everything else's.
/// Putting a third-party repository between an operator and packages their
/// distribution already carries would be this panel taking on a supply chain it
/// has no reason to own.
///
/// What that costs is versions, and the honest answer is to say so:
///
/// - Python ships one line per release, plus whatever extra `python3.X`
///   packages the release carries. Asking for one it does not have is answered
///   with what it does have, not with a PPA.
/// - Go and Ruby ship exactly one that lands on `$PATH`. Debian's versioned
///   `golang-1.24` installs under `/usr/lib/go-1.24` with no `go` anywhere a
///   command or a unit would find it, so installing it would mean reporting
///   success for something `runtime.list` cannot see. A pinned version of
///   either is refused with that reason.
///
/// PHP belongs to `stack.install`, which also configures the FPM pool a site
/// runs on. Deno and Bun are single vendor binaries fetched over https with no
/// signed repository behind them, and this panel does not unpack a tarball as
/// root — the operation says that rather than half-supporting them.
/// `runtime.list` reports every one of them once they are there by any means.
///
/// Installing something that is already installed is a no-op that reports so,
/// which is what makes this safe to put behind a button.
pub struct Install;

#[derive(Debug, Deserialize)]
pub struct InstallInput {
    /// Which runtime to install. Absent means Node.
    #[serde(default)]
    pub runtime: Option<Runtime>,
    /// The version wanted, spelled the way that runtime spells it: `22` for
    /// Node, `3.12` for Python. Absent means whatever the distribution's own
    /// package provides, which for Go and Ruby is the only thing on offer.
    #[serde(default)]
    pub version: Option<String>,
    /// Node's major line, the only field this operation used to take.
    ///
    /// Still accepted because none of the operation inputs can use
    /// `deny_unknown_fields` (see `unihelm-cli::parity`): a caller left on the
    /// old spelling would otherwise have its line dropped in silence and be
    /// handed whatever `nodejs` the machine already had.
    #[serde(default)]
    pub major: Option<u32>,
}

impl InstallInput {
    /// Which runtime and which version this is asking for.
    fn resolve(&self) -> Result<(Runtime, Option<String>)> {
        let runtime = self.runtime.unwrap_or(Runtime::Node);
        let version = match (self.version.as_deref(), self.major) {
            // Two spellings of the same field disagreeing is a caller bug, and
            // guessing which one it meant would install a version nobody asked
            // for.
            (Some(version), Some(major)) if version != major.to_string() => {
                return Err(UnihelmError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "this asks for version `{version}` and major {major} at once; \
                         send one of them"
                    ),
                )
                .with_field("version"));
            }
            (Some(version), _) => Some(version.to_string()),
            (None, Some(major)) => Some(major.to_string()),
            (None, None) => None,
        };
        Ok((runtime, version))
    }
}

#[derive(Debug, Serialize)]
pub struct InstallOutput {
    /// Which runtime this is about — the caller may have asked by name only.
    pub runtime: Runtime,
    /// What is installed now, whether this call put it there or found it.
    pub version: String,
    pub path: String,
    /// False when the version was already present and nothing was changed.
    pub installed: bool,
}

/// What an install would do, worked out before anything on the machine is
/// touched.
///
/// Separate from [`Install::run`] so every refusal — a Node line nobody ships,
/// a pinned Go, Bun at all — is a pure function of the request and the family,
/// and can be tested without a server to install onto.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// Add the NodeSource repository for one major line, then install `nodejs`.
    NodeSource { major: u32 },
    /// Install from the repositories the distribution already has configured.
    Distro {
        /// Installed together. A name the distribution does not carry is an
        /// error before apt is reached, not a wall of apt output.
        packages: Vec<String>,
        /// Installed as well *if* the package index has them, and skipped with
        /// a log line if not.
        companions: Vec<String>,
    },
}

/// Work out what installing `runtime` at `version` would mean on this family.
fn plan(runtime: Runtime, version: Option<&str>, family: Family) -> Result<Plan> {
    match runtime {
        Runtime::Node => {
            let Some(version) = version else {
                return Err(UnihelmError::new(
                    ErrorCode::InvalidInput,
                    "Node needs a major line — 20, 22 or 24. The distribution's own \
                     `nodejs` is not what this installs.",
                )
                .with_field("version"));
            };
            let major: u32 = version.parse().map_err(|_| {
                UnihelmError::new(
                    ErrorCode::InvalidInput,
                    format!("`{version}` is not a Node major line; use a number, such as 22."),
                )
                .with_field("version")
            })?;
            // A line nobody ships. Node's even majors are the LTS lines and the
            // odd ones are current; below 18 is out of support everywhere, and a
            // number in the hundreds is a typo that would otherwise become a 404
            // halfway through an apt update.
            if !(18..=40).contains(&major) {
                return Err(UnihelmError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "Node {major} is not a line anyone ships. Use a current major, \
                         such as 22."
                    ),
                )
                .with_field("version"));
            }
            Ok(Plan::NodeSource { major })
        }

        Runtime::Python => {
            let package = python_package(version)?;
            Ok(Plan::Distro {
                companions: match family {
                    // Debian and Ubuntu keep `venv` out of the interpreter
                    // package, so a Python installed without it cannot make the
                    // virtualenv an application is deployed into — and the
                    // failure surfaces later, in somebody's deploy, not here.
                    // A companion rather than a requirement because the name
                    // tracks the interpreter (`python3.12-venv`) and a release
                    // that has not split it out has no such package at all.
                    Family::Debian => vec![format!("{package}-venv")],
                    // EL builds `venv` into the interpreter package.
                    Family::Rhel => Vec::new(),
                },
                packages: vec![package],
            })
        }

        Runtime::Go | Runtime::Ruby => {
            if let Some(version) = version {
                return Err(UnihelmError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "the distribution ships one {}, and this panel installs that one. \
                         Its versioned packages install outside the path a command or a \
                         unit searches, so asking for {version} here would report success \
                         for something `runtime.list` cannot see.",
                        runtime.display_name(),
                    ),
                )
                .with_field("version"));
            }
            Ok(Plan::Distro {
                packages: vec![
                    match (runtime, family) {
                        // `golang-go` is the one that puts /usr/bin/go there;
                        // the `golang` metapackage on Debian pulls the docs and
                        // the source tree with it.
                        (Runtime::Go, Family::Debian) => "golang-go",
                        (Runtime::Go, Family::Rhel) => "golang",
                        // `ruby-full` is Debian's own name for a Ruby with the
                        // headers gems with native extensions need; plain `ruby`
                        // leaves `gem install` failing on a missing ruby.h.
                        (Runtime::Ruby, Family::Debian) => "ruby-full",
                        (Runtime::Ruby, Family::Rhel) => "ruby",
                        _ => unreachable!("only Go and Ruby reach this arm"),
                    }
                    .to_string(),
                ],
                companions: match (runtime, family) {
                    // EL splits the headers out under a name of its own.
                    (Runtime::Ruby, Family::Rhel) => vec!["ruby-devel".to_string()],
                    _ => Vec::new(),
                },
            })
        }

        Runtime::Php => Err(UnihelmError::new(
            ErrorCode::NotImplemented,
            "PHP is installed by `stack.install`, which also sets up the FPM pool a \
             site runs on — installing the packages alone would leave a PHP nothing \
             is serving with. Use the Stack page.",
        )),

        Runtime::Deno | Runtime::Bun => Err(UnihelmError::new(
            ErrorCode::NotImplemented,
            format!(
                "{} is published as a single binary over https, with no signed \
                 repository behind it. This panel installs from signed repositories \
                 only and does not unpack a vendor tarball as root. Put it on the \
                 server yourself and `runtime.list` will report it.",
                runtime.display_name(),
            ),
        )),
    }
}

/// The distribution's package for one Python line.
fn python_package(version: Option<&str>) -> Result<String> {
    let Some(version) = version else {
        return Ok("python3".to_string());
    };
    // The version lands in a package name. Refuse anything that is not a
    // version rather than trusting `PackageName` to be the only guard.
    let plausible = !version.is_empty()
        && version.len() <= 8
        && version.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && !version.contains("..")
        && !version.ends_with('.');
    if !plausible {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!("`{version}` is not a Python version; ask for a line such as 3.12."),
        )
        .with_field("version"));
    }
    // Python 2 reached end of life in 2020 and no supported release ships it.
    // Naming that is more use than an apt error about a package that has not
    // existed for three releases.
    if version == "2" || version.starts_with("2.") {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "Python {version} has been end of life since 2020 and no supported \
                 distribution ships it. Ask for a 3.x line."
            ),
        )
        .with_field("version"));
    }
    // `python3` is the interpreter package's name; `python3.12` is a specific
    // line beside it. `3` alone means the former.
    Ok(if version == "3" {
        "python3".to_string()
    } else {
        format!("python{version}")
    })
}

/// The installed version that satisfies a request, if there is one.
///
/// `None` for `wanted` means any version at all: for Go and Ruby the
/// distribution offers one, so having it is the whole of the answer.
fn satisfied_by<'a>(
    found: &'a BTreeMap<Runtime, Vec<InstalledRuntime>>,
    runtime: Runtime,
    wanted: Option<&str>,
) -> Option<&'a InstalledRuntime> {
    let installed = found.get(&runtime)?;
    match wanted {
        None => installed
            .iter()
            .find(|r| r.is_default)
            .or(installed.first()),
        Some(wanted) => installed
            .iter()
            .find(|r| version_matches(&r.version, wanted)),
    }
}

/// Whether an installed version is the one that was asked for.
///
/// Component-wise, so `3.12` matches `3.12.3` and not `3.1`. A string prefix
/// would call `3.1` a match for `3.12.3`, and the operator who asked for 3.1
/// would be told they already had it.
fn version_matches(installed: &str, wanted: &str) -> bool {
    let mut have = installed.split('.');
    wanted.split('.').all(|part| have.next() == Some(part))
}

#[async_trait::async_trait]
impl TypedOperation for Install {
    type Input = InstallInput;
    type Output = InstallOutput;

    const NAME: &'static str = "runtime.install";
    // Adds an apt repository and installs packages as root. The same permission
    // `stack.install` holds, for the same reason.
    const PERMISSION: Permission = Permission::StackManage;
    // Minutes. Streams the package manager's output rather than showing a
    // spinner, and is safe to re-run.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let (runtime, wanted) = input.resolve()?;
        let distro = ctx.distro().clone();
        // Every refusal happens here, before the machine is read or touched.
        let plan = plan(runtime, wanted.as_deref(), distro.info.family)?;

        // Already there? Say so and change nothing. This is what makes the
        // operation safe to bind to a button somebody may click twice.
        let before = survey().await;
        if let Some(found) = satisfied_by(&before, runtime, wanted.as_deref()) {
            ctx.log(format!(
                "{} {} is already installed at {}",
                runtime.display_name(),
                found.version,
                found.path
            ));
            return Ok(InstallOutput {
                runtime,
                version: found.version.clone(),
                path: found.path.clone(),
                installed: false,
            });
        }

        let log = ctx.log_sink();

        match &plan {
            Plan::NodeSource { major } => {
                let repo = unihelm_distro::repos::nodesource(&distro.info, *major)
                    .map_err(|e| UnihelmError::new(ErrorCode::NotImplemented, e))?;

                for prerequisite in &repo.prerequisites {
                    distro.pkg.ensure_prerequisite(prerequisite, log).await?;
                }

                let key = crate::stack::fetch_key(&repo.definition.gpg_key_url).await?;
                ctx.log(format!("fetched {} bytes of key material", key.len()));
                distro
                    .pkg
                    .add_repo(&repo.definition, &key, &repo.options, log)
                    .await?;

                let packages = vec![
                    unihelm_distro::PackageName::parse("nodejs")
                        .map_err(|e| UnihelmError::internal(e.to_string()))?,
                ];
                distro.pkg.install(&packages, log).await?;
            }

            Plan::Distro {
                packages,
                companions,
            } => {
                // Nothing to add and no key to pin: these repositories are the
                // ones the distribution configured and signed itself, and the
                // panel adding its own copy of them would be inventing a supply
                // chain where there already is one.
                let names =
                    distro_packages(&distro, log, packages, companions, runtime, &before).await?;
                distro.pkg.install(&names, log).await?;
            }
        }

        // Report what actually landed rather than what was asked for: the
        // package manager resolves a line to a point release, and the operator
        // wants to see which one.
        let after = survey().await;
        let found = satisfied_by(&after, runtime, wanted.as_deref()).ok_or_else(|| {
            UnihelmError::new(
                ErrorCode::Internal,
                format!(
                    "the packages installed but no {} binary appeared; check the task \
                     log for what the package manager actually did",
                    runtime.display_name()
                ),
            )
        })?;

        Ok(InstallOutput {
            runtime,
            version: found.version.clone(),
            path: found.path.clone(),
            installed: true,
        })
    }
}

fn parse_package(name: &str) -> Result<unihelm_distro::PackageName> {
    unihelm_distro::PackageName::parse(name).map_err(|e| UnihelmError::internal(e.to_string()))
}

/// The packages to hand the package manager for a [`Plan::Distro`], with the
/// package index refreshed before it is read.
///
/// The refresh is the whole reason this is a function. `apt-cache policy`
/// answers out of `/var/lib/apt/lists`, and that directory is empty on a fresh
/// image, empty after `apt clean`, and months out of date on a server nobody
/// has touched — all of which are ordinary states for a machine this panel is
/// installed onto. Querying it as it stands would let the refusal below say
/// "this release has no `python3.13` package" about a release that ships one:
/// a confident sentence about the server that is really a sentence about a
/// stale file. The NodeSource path gets a refresh for free inside `add_repo`;
/// this path adds no repository, so it asks for one itself.
///
/// The refresh is deliberately not checked for success, which is what the
/// backend already does for `add_repo`. An inherited server with one broken
/// entry in `sources.list.d` makes `apt update` exit non-zero every time, and
/// refusing to install Python because somebody's unrelated PPA is 404ing would
/// be the panel breaking on a mess it did not make. The failure is streamed to
/// the task log, and a package that really is unreachable is caught below.
async fn distro_packages(
    distro: &unihelm_distro::Distro,
    log: &dyn unihelm_distro::pkg::LogSink,
    packages: &[String],
    companions: &[String],
    runtime: Runtime,
    before: &BTreeMap<Runtime, Vec<InstalledRuntime>>,
) -> Result<Vec<unihelm_distro::PackageName>> {
    distro.pkg.update_index(log).await?;

    let mut names = Vec::new();
    for name in packages {
        let package = parse_package(name)?;
        // Asked before the install so a version this release does not carry is
        // a sentence about this machine, rather than forty lines of apt ending
        // in "Unable to locate package".
        let status = distro.pkg.query(&package).await?;
        if !status.installed && status.candidate_version.is_none() {
            return Err(missing_package(distro, runtime, name, before));
        }
        names.push(package);
    }
    for name in companions {
        let package = parse_package(name)?;
        let status = distro.pkg.query(&package).await?;
        if status.installed || status.candidate_version.is_some() {
            names.push(package);
        } else {
            log.line(&format!(
                "{} has no `{name}` package; installing without it",
                distro.info.pretty_name
            ));
        }
    }
    Ok(names)
}

/// The distribution does not carry the package a request resolved to.
///
/// Names what this machine does have, because "no such package" on its own
/// leaves an operator guessing whether they typed it wrong or whether their
/// release simply never shipped that line.
fn missing_package(
    distro: &unihelm_distro::Distro,
    runtime: Runtime,
    package: &str,
    before: &BTreeMap<Runtime, Vec<InstalledRuntime>>,
) -> UnihelmError {
    let here = match before.get(&runtime).and_then(|v| v.first()) {
        Some(found) => format!(
            " The {} on this machine is {} at {}.",
            runtime.display_name(),
            found.version,
            found.path
        ),
        None => String::new(),
    };
    UnihelmError::new(
        ErrorCode::InvalidInput,
        format!(
            "{} has no `{package}` package.{here} This panel installs {} from the \
             distribution's own repositories and will not add a third-party one for a \
             version yours does not ship — install it yourself and `runtime.list` will \
             report it.",
            distro.info.pretty_name,
            runtime.display_name(),
        ),
    )
    .with_field("version")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each runtime spells its version banner differently, and a panel that
    /// cannot read them cannot offer a version to pin to.
    #[test]
    fn a_version_is_read_out_of_every_runtime_banner() {
        let cases = [
            ("v22.11.0", "22.11.0"),
            ("Python 3.12.3", "3.12.3"),
            (
                "PHP 8.3.6 (cli) (built: Apr 15 2024 19:21:47) (NTS)",
                "8.3.6",
            ),
            ("go version go1.22.2 linux/amd64", "1.22.2"),
            (
                "ruby 3.2.3 (2024-01-18 revision 52bb2ac0a6) [x86_64-linux]",
                "3.2.3",
            ),
            ("deno 1.44.4 (release, x86_64-unknown-linux-gnu)", "1.44.4"),
            ("1.1.29", "1.1.29"),
        ];
        for (banner, want) in cases {
            assert_eq!(
                extract_version(banner).as_deref(),
                Some(want),
                "failed on {banner:?}"
            );
        }
        assert_eq!(extract_version("command not found"), None);
        assert_eq!(extract_version(""), None);
    }

    /// A helper script whose name carries a real version.
    ///
    /// Found on a live Ubuntu 24.04 server: `python3.12-config` sits next to
    /// `python3.12` and passed the first-character check, because the character
    /// after `python3.` is the digit `1`. The panel offered `3.12` as a version
    /// to pin an application to, and the unit that produced would have run
    /// `python3.12-config app.py` and died at first start.
    #[test]
    fn a_helper_script_with_a_version_in_its_name_is_not_an_interpreter() {
        let tmp = tempfile::tempdir().unwrap();
        for name in [
            "python3.12",
            "python3.11",
            "python3.12-config",
            "python3-config",
            "python3.12t",
        ] {
            std::fs::write(tmp.path().join(name), "").unwrap();
        }
        let found = versioned_binaries(Runtime::Python, tmp.path(), "python3.");
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["python3.11", "python3.12"], "got {names:?}");
    }

    /// `phpize` and `php-config` sit next to `php8.3` in /usr/bin and are not
    /// interpreters; offering them as a version to run a site on would produce
    /// a unit that fails at first start.
    #[test]
    fn only_versioned_interpreters_are_picked_up() {
        let tmp = tempfile::tempdir().unwrap();
        for name in ["php8.3", "php8.2", "phpize", "php-config", "phpdbg"] {
            std::fs::write(tmp.path().join(name), "").unwrap();
        }
        let found = versioned_binaries(Runtime::Php, tmp.path(), "php");
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["php8.2", "php8.3"], "got {names:?}");
    }

    /// A major line nobody ships must be refused before it becomes a 404
    /// halfway through an apt update, with a message that says what to use.
    #[test]
    fn an_absurd_major_line_is_refused_before_anything_is_touched() {
        for major in ["0", "1", "17", "99", "2024", "22.11", "latest"] {
            let err =
                plan(Runtime::Node, Some(major), Family::Debian).unwrap_err_or_panic("Node", major);
            assert_eq!(err.code, ErrorCode::InvalidInput, "on {major}");
            assert_eq!(err.field.as_deref(), Some("version"), "on {major}");
        }
        for major in ["18", "20", "22", "24", "40"] {
            assert_eq!(
                plan(Runtime::Node, Some(major), Family::Debian).unwrap(),
                Plan::NodeSource {
                    major: major.parse().unwrap()
                }
            );
        }
    }

    /// Python, Go and Ruby come from the distribution, under the names the
    /// distribution actually uses — which differ per family, and getting one
    /// wrong is an install that fails on a package nobody has.
    #[test]
    fn the_distribution_s_own_package_names_are_asked_for() {
        let cases = [
            (
                Runtime::Python,
                None,
                Family::Debian,
                vec!["python3"],
                vec!["python3-venv"],
            ),
            (
                Runtime::Python,
                Some("3.12"),
                Family::Debian,
                vec!["python3.12"],
                vec!["python3.12-venv"],
            ),
            // EL builds venv into the interpreter package, so there is no
            // companion to ask for.
            (
                Runtime::Python,
                Some("3.12"),
                Family::Rhel,
                vec!["python3.12"],
                vec![],
            ),
            (Runtime::Go, None, Family::Debian, vec!["golang-go"], vec![]),
            (Runtime::Go, None, Family::Rhel, vec!["golang"], vec![]),
            (
                Runtime::Ruby,
                None,
                Family::Debian,
                vec!["ruby-full"],
                vec![],
            ),
            (
                Runtime::Ruby,
                None,
                Family::Rhel,
                vec!["ruby"],
                vec!["ruby-devel"],
            ),
        ];
        for (runtime, version, family, packages, companions) in cases {
            let got = plan(runtime, version, family)
                .unwrap_or_else(|e| panic!("{runtime:?} {version:?} on {family:?}: {}", e.detail));
            assert_eq!(
                got,
                Plan::Distro {
                    packages: packages.iter().map(|s| s.to_string()).collect(),
                    companions: companions.iter().map(|s| s.to_string()).collect(),
                },
                "{runtime:?} {version:?} on {family:?}"
            );
        }
    }

    /// Every package name this operation can produce has to be one the package
    /// manager will accept, or the install dies on a name we built ourselves.
    #[test]
    fn every_planned_package_name_is_a_legal_one() {
        for family in [Family::Debian, Family::Rhel] {
            for (runtime, version) in [
                (Runtime::Python, None),
                (Runtime::Python, Some("3.12")),
                (Runtime::Python, Some("3")),
                (Runtime::Go, None),
                (Runtime::Ruby, None),
            ] {
                let Plan::Distro {
                    packages,
                    companions,
                } = plan(runtime, version, family).unwrap()
                else {
                    panic!("{runtime:?} is not a distribution package");
                };
                for name in packages.iter().chain(companions.iter()) {
                    unihelm_distro::PackageName::parse(name)
                        .unwrap_or_else(|e| panic!("`{name}` is not a package name: {e}"));
                }
            }
        }
    }

    /// A version string reaches a package name, so anything that is not a
    /// version has to be refused rather than passed along.
    #[test]
    fn a_python_version_that_is_not_one_never_reaches_a_package_name() {
        for version in [
            "3.12; rm -rf /",
            "../../etc",
            "3..12",
            "3.",
            "",
            "3.12.4.5.6.7.8.9",
            "latest",
            // End of life since 2020, and worth its own sentence.
            "2.7",
        ] {
            let err = python_package(Some(version)).unwrap_err_or_panic("Python", version);
            assert_eq!(err.code, ErrorCode::InvalidInput, "on {version:?}");
        }
        assert_eq!(python_package(Some("3")).unwrap(), "python3");
        assert_eq!(python_package(Some("3.13")).unwrap(), "python3.13");
    }

    /// Bun and Deno are single vendor binaries with no signed repository, and
    /// PHP belongs to `stack.install`. Each has to say which it is: silence, or
    /// a bare "unsupported", is what sends somebody to a curl-to-shell.
    #[test]
    fn a_runtime_this_panel_will_not_install_says_why() {
        for (runtime, expected) in [
            (Runtime::Deno, "single binary"),
            (Runtime::Bun, "single binary"),
            (Runtime::Php, "stack.install"),
        ] {
            let err = plan(runtime, None, Family::Debian)
                .unwrap_err_or_panic("refusal", runtime.as_str());
            assert_eq!(err.code, ErrorCode::NotImplemented, "for {runtime:?}");
            assert!(
                err.detail.contains(expected),
                "{runtime:?} says {:?}, which does not mention {expected:?}",
                err.detail
            );
        }
    }

    /// Debian ships `golang-1.24` under /usr/lib with no `go` on the path.
    /// Installing it would report success for something `runtime.list` cannot
    /// see and no app can be pinned to, so a pinned Go or Ruby is refused.
    #[test]
    fn a_pinned_go_or_ruby_is_refused_rather_than_installed_out_of_sight() {
        for runtime in [Runtime::Go, Runtime::Ruby] {
            let err =
                plan(runtime, Some("1.24"), Family::Debian).unwrap_err_or_panic("pinned", "1.24");
            assert_eq!(err.code, ErrorCode::InvalidInput);
            assert_eq!(err.field.as_deref(), Some("version"));
        }
    }

    /// `3.1` is not `3.12`. A string prefix says it is, and an operator who
    /// asked for 3.1 would be told they already had it and given 3.12.
    #[test]
    fn a_version_matches_component_wise_and_not_by_prefix() {
        assert!(version_matches("3.12.3", "3.12"));
        assert!(version_matches("22.11.0", "22"));
        assert!(version_matches("3.12.3", "3.12.3"));
        assert!(!version_matches("3.12.3", "3.1"));
        assert!(!version_matches("3.1.4", "3.12"));
        assert!(!version_matches("22.11.0", "2"));
        assert!(!version_matches("3.12.3", "3.12.4"));
    }

    /// The version somebody asked for decides whether anything is installed, so
    /// "already installed" has to mean *that* version and not any version.
    #[test]
    fn an_install_is_a_no_op_only_for_the_version_asked_for() {
        let found = BTreeMap::from([(
            Runtime::Python,
            vec![
                InstalledRuntime {
                    runtime: Runtime::Python,
                    version: "3.11.2".into(),
                    path: "/usr/bin/python3".into(),
                    is_default: true,
                },
                InstalledRuntime {
                    runtime: Runtime::Python,
                    version: "3.13.1".into(),
                    path: "/usr/bin/python3.13".into(),
                    is_default: false,
                },
            ],
        )]);

        assert_eq!(
            satisfied_by(&found, Runtime::Python, Some("3.13")).map(|r| r.path.as_str()),
            Some("/usr/bin/python3.13")
        );
        // No version asked for means the distribution's own, which is the one a
        // bare `python3` resolves to.
        assert_eq!(
            satisfied_by(&found, Runtime::Python, None).map(|r| r.path.as_str()),
            Some("/usr/bin/python3")
        );
        assert!(satisfied_by(&found, Runtime::Python, Some("3.12")).is_none());
        assert!(satisfied_by(&found, Runtime::Go, None).is_none());
    }

    /// `major` is what the CLI, the HTTP route and the page all sent before this
    /// operation grew a second runtime. None of the operation inputs can use
    /// `deny_unknown_fields`, so dropping the field would not fail a caller
    /// still sending it — it would quietly install the wrong thing.
    #[test]
    fn the_field_this_operation_started_with_still_asks_for_a_node_line() {
        let old: InstallInput = serde_json::from_value(serde_json::json!({ "major": 22 })).unwrap();
        assert_eq!(old.resolve().unwrap(), (Runtime::Node, Some("22".into())));

        let new: InstallInput =
            serde_json::from_value(serde_json::json!({ "runtime": "python", "version": "3.12" }))
                .unwrap();
        assert_eq!(
            new.resolve().unwrap(),
            (Runtime::Python, Some("3.12".into()))
        );

        let bare: InstallInput =
            serde_json::from_value(serde_json::json!({ "runtime": "go" })).unwrap();
        assert_eq!(bare.resolve().unwrap(), (Runtime::Go, None));

        // Both spellings, disagreeing: guessing would install a version nobody
        // asked for.
        let both: InstallInput =
            serde_json::from_value(serde_json::json!({ "version": "20", "major": 22 })).unwrap();
        assert_eq!(both.resolve().unwrap_err().code, ErrorCode::InvalidInput);
    }

    /// The refusal is decided from the package index, so the index has to be
    /// fetched first.
    ///
    /// A server whose `/var/lib/apt/lists` is empty — a fresh image, anything
    /// after `apt clean`, a machine nobody has updated in a month — answers
    /// every `apt-cache policy` with no candidate. Without the refresh the
    /// operation reads that and tells the operator their release has no
    /// `python3.13`, which is a claim about a stale file dressed up as a claim
    /// about their machine, and then the install that did get past it fetches
    /// archive URLs that have since gone.
    #[tokio::test]
    async fn the_package_index_is_fetched_before_it_is_used_to_refuse() {
        let (distro, recorder) = unihelm_distro::mock::mock_distro_with_recorder(Family::Debian);
        let log = unihelm_distro::mock::RecordingLog(recorder.clone());

        let names = distro_packages(
            &distro,
            &log,
            &["python3.13".to_string()],
            &["python3.13-venv".to_string()],
            Runtime::Python,
            &BTreeMap::new(),
        )
        .await
        .unwrap();
        assert_eq!(names.len(), 2, "got {names:?}");

        let lines = recorder.lock().expect("recorder mutex").log_lines.clone();
        assert!(
            lines.iter().any(|l| l.contains("index updated")),
            "the index was never refreshed: {lines:?}"
        );
    }

    /// `unwrap_err`, with the panic naming what was being planned — the same
    /// failure repeated over a table is otherwise unattributable.
    trait UnwrapErrOrPanic {
        fn unwrap_err_or_panic(self, what: &str, input: &str) -> UnihelmError;
    }

    impl<T: std::fmt::Debug> UnwrapErrOrPanic for Result<T> {
        fn unwrap_err_or_panic(self, what: &str, input: &str) -> UnihelmError {
            match self {
                Err(e) => e,
                Ok(planned) => panic!("{what} `{input}` was accepted: {planned:?}"),
            }
        }
    }

    /// A version manager keeps one directory per version with the binary under
    /// bin/. Anything else in there is not a runtime.
    #[test]
    fn version_directories_resolve_to_their_binary() {
        let tmp = tempfile::tempdir().unwrap();
        for v in ["v20.11.0", "v22.11.0"] {
            let bin = tmp.path().join(v).join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::write(bin.join("node"), "").unwrap();
        }
        // A directory with no binary in it is not a version.
        std::fs::create_dir_all(tmp.path().join("v18.0.0")).unwrap();

        let found = versioned_binaries(Runtime::Node, tmp.path(), "");
        assert_eq!(found.len(), 2, "got {found:?}");
        assert!(found.iter().all(|p| p.ends_with("bin/node")));
    }
}
