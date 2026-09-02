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
            && name[prefix.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
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

use unihelm_core::{Permission, Result};

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
