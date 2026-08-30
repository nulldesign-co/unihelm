//! The tenant side of a WP-CLI run (spec §11.12, §5.2 rule 3).
//!
//! `unihelm-agentd --wp-helper` re-execs the agent binary, drops to the tenant's
//! uid/gid — through the *same* `drop_privileges` the file-manager helper uses,
//! including its `setuid(0)`-must-fail proof — and only then calls [`run`].
//! Nothing here executes before that drop.
//!
//! # Why this module re-checks what the agent already checked
//!
//! [`crate::wordpress::validate_cli_args`] has already refused every reserved
//! flag by the time an argument vector reaches this process. It is checked
//! again here because *this* is the process boundary where privilege changes:
//! a bug on the agent side that let `--require=/tmp/pwn.php` through would
//! otherwise become arbitrary PHP execution inside the tenant's account. Two
//! copies of a check that must never fail is the correct number when one of
//! them sits on a trust boundary.
//!
//! # The reply
//!
//! One JSON line on stdout — `{"status":N,"stdout":"…","stderr":"…"}` — and
//! exit 0. Anything that stops the helper doing its job is stderr text and a
//! **non-zero exit**, which the parent treats as fatal regardless of what is on
//! stdout. That split is what lets the parent tell "WP-CLI failed" (status in
//! the JSON) from "the helper failed" (exit code), and the second one includes
//! the case that matters most: the privilege drop refusing to proceed.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use unihelm_core::{ErrorCode, Result, UnihelmError};
use unihelm_distro::Cmd;

use super::{MAX_WP_OUTPUT, RESERVED_WP_FLAGS, WpOutput, path_flag};

/// Exit code for a helper that could not run at all, as distinct from a WP-CLI
/// run that failed. WP-CLI itself uses 0, 1 and 255; 120 is outside every
/// meaning it assigns.
pub const HELPER_FAILED: i32 = 120;

/// Entry point after the privilege drop. Returns the process exit code.
///
/// `args` is everything after the `--` on the helper's own command line: the
/// WP-CLI argument vector, `--path` first.
pub fn run(home: &Path, dir: &Path, args: &[OsString]) -> i32 {
    let argv: Vec<String> = match args
        .iter()
        .map(|a| a.to_str().map(str::to_string))
        .collect::<Option<Vec<_>>>()
    {
        Some(v) => v,
        None => {
            eprintln!("wp-helper: WP-CLI arguments must be valid UTF-8");
            return HELPER_FAILED;
        }
    };

    if let Err(message) = check_argv(dir, &argv) {
        eprintln!("wp-helper: {message}");
        return HELPER_FAILED;
    }

    // A current-thread runtime: this process exists to run exactly one child
    // and print one line, and a multi-thread pool would be scaffolding for work
    // that never arrives.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wp-helper: could not start a runtime: {e}");
            return HELPER_FAILED;
        }
    };

    // The parent enforces the real deadline (it kills this process on its own
    // timeout); this one is the backstop that keeps an orphaned helper from
    // living forever if the parent died first.
    match runtime.block_on(run_wp_cli(home, dir, &argv, Duration::from_secs(30 * 60))) {
        Ok(output) => match serde_json::to_string(&output) {
            Ok(line) => {
                println!("{line}");
                0
            }
            Err(e) => {
                eprintln!("wp-helper: could not serialise the reply: {e}");
                HELPER_FAILED
            }
        },
        Err(e) => {
            eprintln!("wp-helper: {}", e.detail);
            HELPER_FAILED
        }
    }
}

/// The privilege-boundary re-check.
///
/// Split out and returning a plain `String` so it can be tested without a
/// process: the interesting behaviour is the refusal.
pub fn check_argv(dir: &Path, argv: &[String]) -> std::result::Result<(), String> {
    if !dir.is_absolute() {
        return Err(format!("--dir must be absolute, got {}", dir.display()));
    }
    let expected = path_flag(dir);
    match argv.first() {
        Some(first) if *first == expected => {}
        Some(first) => {
            return Err(format!(
                "the first WP-CLI argument must be `{expected}`, got `{first}`"
            ));
        }
        None => return Err("no WP-CLI arguments were given".into()),
    }

    for arg in &argv[1..] {
        let Some(rest) = arg.strip_prefix("--") else {
            continue;
        };
        let name = rest.split('=').next().unwrap_or_default();
        let bare = name.strip_prefix("no-").unwrap_or(name);
        if RESERVED_WP_FLAGS.contains(&bare) {
            return Err(format!(
                "`--{bare}` is reserved by the panel and must never reach WP-CLI"
            ));
        }
    }
    Ok(())
}

/// Run PHP against the pinned WP-CLI phar.
///
/// Shared by the helper (as the tenant, after the drop) and by
/// [`crate::wordpress::WpRunner::Local`] (an already-unprivileged agent), so
/// there is one description of how WP-CLI is invoked rather than two that can
/// drift.
pub async fn run_wp_cli(
    home: &Path,
    dir: &Path,
    argv: &[String],
    timeout: Duration,
) -> Result<WpOutput> {
    let phar = unihelm_config::paths::wp_cli_phar();
    if !phar.exists() {
        return Err(UnihelmError::new(
            ErrorCode::NotFound,
            format!(
                "WP-CLI is not installed at {} — run wp.install, which downloads and \
                 verifies the pinned release",
                phar.display()
            ),
        ));
    }
    // Resolved against `unihelm_distro`'s fixed list of trusted directories, so
    // a poisoned PATH cannot redirect `php` — which matters even here, because
    // the tenant controls their own environment and this process is about to
    // execute the panel's phar.
    let php = unihelm_distro::exec::resolve_program("php").map_err(|_| {
        UnihelmError::new(
            ErrorCode::NotFound,
            "no `php` binary was found on this server; install a PHP version from the \
             Stack Manager first — WP-CLI is a PHP program",
        )
    })?;

    let out = Cmd::new(php.to_string_lossy().into_owned())
        .arg(&phar)
        .args(argv)
        // WP-CLI writes a package/download cache and reads a config from
        // `$HOME`. Without these it either warns on every run or falls back to
        // whatever `$HOME` an empty environment implies — which for a
        // privilege-dropped process is nothing useful.
        .env("HOME", home)
        .env("WP_CLI_CACHE_DIR", home.join(".wp-cli").join("cache"))
        // Unihelm's task log is the progress display; WP-CLI's ANSI colouring
        // would only put escape sequences in it.
        .env("NO_COLOR", "1")
        .timeout(timeout)
        .run()
        .await
        .map_err(UnihelmError::from)?;

    // `dir` is already in the argv as `--path`; naming it here keeps the
    // signature honest about what this call operates on.
    let _ = dir;

    Ok(WpOutput {
        status: out.status,
        stdout: truncate(out.stdout),
        stderr: truncate(out.stderr),
    })
}

/// Cap one stream at [`MAX_WP_OUTPUT`], saying so where it was cut.
///
/// A silent truncation would make a half-read plugin list look like a complete
/// one, which is worse than a short answer.
fn truncate(mut text: String) -> String {
    if text.len() <= MAX_WP_OUTPUT {
        return text;
    }
    // Cut on a character boundary; `floor_char_boundary` is still unstable.
    let mut cut = MAX_WP_OUTPUT;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text.push_str("\n… [truncated by Unihelm: WP-CLI produced more than 1 MiB]\n");
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dir() -> PathBuf {
        PathBuf::from("/home/uh_x/sites/example.com/public")
    }

    /// The boundary check exists because it sits *after* the privilege drop: if
    /// the agent side were ever wrong, this is the last thing between a tenant
    /// and `--exec`.
    #[test]
    fn the_helper_refuses_a_reserved_flag_even_though_the_agent_already_did() {
        for hostile in [
            "--require=/tmp/pwn.php",
            "--exec=system('id');",
            "--ssh=root@elsewhere",
            "--path=/etc",
            "--no-path=/etc",
            "--prompt=admin_password",
        ] {
            let argv = vec![path_flag(&dir()), "core".into(), hostile.to_string()];
            assert!(
                check_argv(&dir(), &argv).is_err(),
                "`{hostile}` must be refused at the privilege boundary"
            );
        }
    }

    /// The helper only ever operates on the directory it was told about: an
    /// argument vector whose `--path` disagrees with `--dir` is a bug or an
    /// attack, and either way it does not run.
    #[test]
    fn an_argv_whose_path_disagrees_with_the_dir_is_refused() {
        let argv = vec![
            "--path=/home/someone_else/sites/x/public".to_string(),
            "core".into(),
            "version".into(),
        ];
        assert!(check_argv(&dir(), &argv).is_err());

        let missing = vec!["core".to_string(), "version".into()];
        assert!(check_argv(&dir(), &missing).is_err());
        assert!(check_argv(&dir(), &[]).is_err());
    }

    #[test]
    fn a_relative_dir_is_refused_outright() {
        let rel = PathBuf::from("sites/example.com/public");
        let argv = vec![path_flag(&rel), "core".into(), "version".into()];
        assert!(check_argv(&rel, &argv).is_err());
    }

    #[test]
    fn an_ordinary_argv_passes_the_boundary_check() {
        let argv = vec![
            path_flag(&dir()),
            "plugin".into(),
            "list".into(),
            "--format=json".into(),
            "--skip-plugins".into(),
        ];
        assert_eq!(check_argv(&dir(), &argv), Ok(()));
    }

    /// A truncated stream must say that it was truncated; a silently short
    /// plugin list reads exactly like a complete one.
    #[test]
    fn oversized_output_is_cut_and_says_so() {
        let long = "x".repeat(MAX_WP_OUTPUT + 100);
        let cut = truncate(long);
        assert!(cut.len() < MAX_WP_OUTPUT + 100);
        assert!(cut.contains("truncated by Unihelm"));

        let short = "fine".to_string();
        assert_eq!(truncate(short.clone()), short);
    }

    /// Multi-byte output must not be cut mid-character — a panel that emits
    /// invalid UTF-8 in its JSON reply breaks the parent's parse, not just the
    /// display.
    #[test]
    fn truncation_lands_on_a_character_boundary() {
        let long = "…".repeat(MAX_WP_OUTPUT); // three bytes each
        let cut = truncate(long);
        assert!(cut.is_char_boundary(0));
        // `String` cannot hold invalid UTF-8, so the real assertion is that the
        // truncate loop terminated rather than panicking on a boundary.
        assert!(cut.contains("truncated by Unihelm"));
    }
}
