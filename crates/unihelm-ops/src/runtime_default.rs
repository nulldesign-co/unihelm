//! Which interpreter a bare command name resolves to.
//!
//! Separate from `runtimes`, which reports what is installed and installs more.
//! This changes which of several installed versions answers to `php` — a
//! different question, and one an operator asks for a reason the panel cannot
//! see: a deploy script, a cron line, a colleague's muscle memory.
//!
//! It does **not** change what any site runs. Each site names its own PHP
//! version and gets its own FPM pool, which is the point of running versions
//! side by side; a global default that silently moved sites between them would
//! be the opposite. The operation says so, because "set default" reads like it
//! would.

use serde::{Deserialize, Serialize};
use unihelm_core::{ErrorCode, Permission, Result, UnihelmError};

use crate::registry::{Execution, OpContext, TypedOperation};

/// `runtime.default.set` — point a bare command name at one installed version.
pub struct SetDefault;

#[derive(Debug, Deserialize)]
pub struct SetDefaultInput {
    /// Which runtime's default to move. Only `php` today.
    pub runtime: String,
    /// The version to point at, as `runtime.list` reports it: `8.3`, `8.3.6`.
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct SetDefaultOutput {
    pub runtime: String,
    /// What the bare name resolves to now.
    pub path: String,
    pub version: String,
}

#[async_trait::async_trait]
impl TypedOperation for SetDefault {
    type Input = SetDefaultInput;
    type Output = SetDefaultOutput;

    const NAME: &'static str = "runtime.default.set";
    // Changes a system-wide symlink outside the panel's own tree.
    const PERMISSION: Permission = Permission::StackManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // PHP only, and deliberately.
        //
        // Debian's `update-alternatives` is what owns the `php` symlink, and
        // every PHP the distribution installs registers itself with it. Node
        // from NodeSource installs a real binary at /usr/local/bin/node with no
        // alternatives entry at all, so "set the default Node" would mean this
        // panel moving somebody else's file — a different and much less
        // reversible thing than picking between registered alternatives.
        if input.runtime != "php" {
            return Err(UnihelmError::new(
                ErrorCode::NotImplemented,
                format!(
                    "only `php` has a default this panel can move. {} is installed \
                     as a single binary with no alternatives entry, so there is \
                     nothing to choose between.",
                    input.runtime
                ),
            )
            .with_field("runtime"));
        }

        let target = php_alternative_path(&input.version)?;

        // The alternative has to be registered already. Pointing the symlink at
        // a path update-alternatives does not know about leaves it in manual
        // mode aimed at a file the next package upgrade will not maintain.
        let registered = unihelm_distro::Cmd::new("update-alternatives")
            .args(["--list", "php"])
            .timeout(std::time::Duration::from_secs(10))
            .run()
            .await
            .map_err(|e| UnihelmError::internal(e.to_string()))?;

        let known: Vec<&str> = registered.trimmed_stdout().lines().collect();
        if !known.iter().any(|line| *line == target) {
            return Err(UnihelmError::new(
                ErrorCode::NotFound,
                format!(
                    "PHP {} is not installed, or is not registered with \
                     update-alternatives. Installed: {}",
                    input.version,
                    if known.is_empty() {
                        "none".into()
                    } else {
                        known.join(", ")
                    }
                ),
            )
            .with_field("version"));
        }

        unihelm_distro::Cmd::new("update-alternatives")
            .args(["--set", "php", &target])
            .timeout(std::time::Duration::from_secs(30))
            .run_checked()
            .await
            .map_err(|e| UnihelmError::internal(e.to_string()))?;

        ctx.log(format!("`php` now resolves to {target}"));
        ctx.log(
            "sites are unaffected: each one names its own PHP version and has its own \
             FPM pool",
        );

        Ok(SetDefaultOutput {
            runtime: input.runtime,
            path: target,
            version: input.version,
        })
    }
}

/// The binary `update-alternatives` knows for a PHP version.
///
/// Accepts `8.3` and `8.3.6` alike — `runtime.list` reports the point release
/// and the alternatives entry is named for the series, so an operator copying
/// what the panel showed them would otherwise get a "not installed" for a
/// version that plainly is.
fn php_alternative_path(version: &str) -> Result<String> {
    // Every component, not just the first two. `take(2)` looked only at the
    // start, so `../../bin/sh` split to `` and `` — both "all digits" because
    // the predicate is vacuously true on an empty string — and produced
    // `/usr/bin/php..` on its way to a command line. The emptiness check is
    // what closes that, and the whole-string check is what stops anything
    // after the series from mattering.
    let parts: Vec<&str> = version.split('.').collect();
    let series = &parts[..parts.len().min(2)];
    if series.len() != 2
        || series
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!("`{version}` is not a PHP version. Use one like `8.3`."),
        )
        .with_field("version"));
    }
    Ok(format!("/usr/bin/php{}.{}", series[0], series[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `runtime.list` reports `8.3.6`; the alternatives entry is `php8.3`. An
    /// operator copying what the panel showed them must not be told that
    /// version is not installed.
    #[test]
    fn a_point_release_resolves_to_its_series_binary() {
        assert_eq!(php_alternative_path("8.3").unwrap(), "/usr/bin/php8.3");
        assert_eq!(php_alternative_path("8.3.6").unwrap(), "/usr/bin/php8.3");
        assert_eq!(php_alternative_path("7.4.33").unwrap(), "/usr/bin/php7.4");
    }

    /// Anything that is not a version must be refused before it reaches a
    /// command line.
    #[test]
    fn nonsense_never_reaches_update_alternatives() {
        for bad in [
            "",
            "8",
            "abc",
            "8.x",
            "../../bin/sh",
            "8.3; rm -rf /",
            "-8.3",
        ] {
            assert!(
                php_alternative_path(bad).is_err(),
                "accepted `{bad}` as a version"
            );
        }
    }
}
