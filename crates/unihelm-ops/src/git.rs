//! Deploying a site from a Git repository (spec §11.2, the "upload your files"
//! step done from a repository instead of by hand).
//!
//! Attach a repository to a site, clone it into that site's document root, and
//! pull to deploy. That is the whole feature, and the three verbs are separate
//! operations because their refusals are different: cloning is refused when
//! there is already something in the document root, pulling is refused when
//! there is not a checkout, or when the checkout has changes that a merge would
//! throw away.
//!
//! # Public HTTPS only, and it says so
//!
//! [`parse_repository`] accepts `https://` and nothing else. An `ssh://` or
//! `git@host:path` URL is **refused with the reason** rather than attempted,
//! because attempting it means a clone that hangs on a passphrase prompt or
//! dies half-written — and because this panel has nowhere to keep a deploy key
//! that would not be readable by whoever can read the site's files. A URL with
//! a username or token embedded in it is refused for the same reason from the
//! other end: git writes the remote URL into `.git/config` verbatim, so a
//! token in the URL becomes a token in a file inside the tenant's document
//! root, in plain text, for the life of the checkout.
//!
//! When private repositories do land here, the credential needs a home in
//! `unihelm_db::secrets` (sealed with the master key, the way DNS provider
//! credentials are) and a `core.askPass` handoff that keeps it off argv. None
//! of that is in this change, so this change does not pretend to have it.
//!
//! # It runs as the tenant
//!
//! A clone writes hundreds of files into a directory the tenant controls, and
//! `git` runs the repository's own `.gitattributes` filters and reads config
//! from the working tree — so running it as root would hand the tenant the
//! server. Every git invocation is dropped to the site's Linux account first.
//!
//! The drop is `setpriv(1)` rather than the agent's own re-exec helper
//! (`--fs-helper`, `--wp-helper`). The helpers exist to *bound* what the child
//! may do — a closed enum of filesystem verbs, one pinned phar — and there is
//! nothing here for such a protocol to bound that the argv does not already:
//! this module never accepts a git subcommand from a caller, it builds every
//! argument vector itself out of one validated URL and one validated branch
//! name. What is left is the privilege drop, and `setpriv` is the util-linux
//! tool that does exactly that from an argv array, with no shell and no new IPC
//! surface. A server without it is told so ([`GitRunner::command`]) instead of
//! having its git run as root.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use unihelm_core::{ErrorCode, Permission, Result, SiteId, TenantPath, UnihelmError};
use unihelm_db::sites::Site;
use unihelm_db::subscriptions::Subscription;
use unihelm_distro::Cmd;
use unihelm_distro::exec::{self, CmdOutput};

use crate::fsops::FsRunner;
use crate::fsops::proto::{FsData, FsRequest};
use crate::registry::{Execution, OpContext, TypedOperation};

// ---------------------------------------------------------------------------
// where the attachment lives
// ---------------------------------------------------------------------------

/// One settings row per site, keyed by site id.
///
/// The panel's `settings` table takes free-form keys and JSON values, which is
/// what makes a per-site record possible without a schema migration in a wave
/// that owns no migrations. The trade is that nothing joins on it: a site row
/// deleted outside `site.delete` would leave this behind. `site.delete` is the
/// only thing that removes a site, and [`Detach`] is what removes this, so the
/// stale row is a few hundred bytes and never a wrong answer — [`Status`]
/// resolves the site first and reports nothing for a site that is gone.
const ATTACHMENT_KEY_PREFIX: &str = "git.repository.site.";

fn attachment_key(site_id: SiteId) -> String {
    format!("{ATTACHMENT_KEY_PREFIX}{}", site_id.get())
}

/// What the panel knows about the repository behind a site.
///
/// `branch` is optional because the first clone may take the repository's
/// default branch — and when it does, [`Clone`] writes back the branch it
/// actually landed on, so a later deploy fast-forwards the same branch rather
/// than guessing `main` and failing on a `master` repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub repository: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub attached_at: OffsetDateTime,
    /// The commit the panel last put in the document root. `None` until a
    /// clone or a pull has actually happened — an attachment on its own has
    /// deployed nothing, and saying otherwise would be the panel reporting
    /// work it did not do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_commit: Option<String>,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_deployed_at: Option<OffsetDateTime>,
}

// ---------------------------------------------------------------------------
// how git is invoked
// ---------------------------------------------------------------------------

/// Configuration forced onto every invocation, at the highest precedence git
/// has.
///
/// `-c` here is **git's** own `--config` flag. This module starts no shell and
/// assembles no command string; the flag reaches `execve` as one argv element
/// (see the argv discipline in `unihelm_distro::exec`).
///
/// * `protocol.allow=never` with `protocol.https.allow=always` pins the
///   transport to HTTPS *inside git*. [`parse_repository`] has already refused
///   every other scheme, and this is the wall behind it: it also covers the
///   URLs that never pass through that function — a redirect to `git://`, a
///   `.gitmodules` entry, an `insteadOf` rewrite in a config file the tenant
///   owns. `ext::` in particular is a transport that executes a command.
/// * `credential.helper=` empties the helper list, so a private repository
///   fails with "authentication required" instead of reaching into whatever
///   credential store the account happens to have configured.
const GIT_CONFIG: &[&str] = &[
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "credential.helper=",
];

/// Inspection commands answer in milliseconds; this is the hard stop for one
/// that has wedged, not a budget.
const INSPECT_TIMEOUT: Duration = Duration::from_secs(60);

/// A clone of a large repository over a slow link is a genuinely long job, and
/// it runs as a task with a live log.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// How many names a refusal lists before it stops. Enough to recognise what is
/// in the way; not the whole directory.
const MAX_LISTED: usize = 10;

/// The sentence `provision::write_placeholder` puts in the holding page.
///
/// Cloning replaces that page, and only that page — so it has to be identified
/// by content, not by name: `index.html` is also the first file of a hand-built
/// site. If the placeholder's wording ever changes, this stops matching and the
/// document root reads as occupied, which refuses the clone. That is the right
/// way for this check to fail.
const HOLDING_PAGE_MARK: &str = "Upload your files to replace this page.";

/// How one site's git commands get executed. The same shape, and the same
/// reasoning, as [`crate::fsops::FsRunner`] and `wordpress::WpRunner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitRunner {
    /// Drop to this uid/gid before running git. The production path.
    Tenant { uid: u32, gid: u32 },
    /// Run git as the agent's own account — **no privilege drop**.
    ///
    /// Selected only when the agent is already unprivileged (`--dev`, tests):
    /// there is nothing to shed, and the directories involved are throwaway
    /// ones owned by the user already running. A root agent never selects it,
    /// because [`crate::fsops::ops::runner_for`] picks from `geteuid`.
    Local,
}

impl GitRunner {
    /// Reuse the file manager's decision rather than making a second one.
    ///
    /// `runner_for` is where "is this agent root", "does the account exist" and
    /// "does it map to uid 0" are already answered, and two copies of that
    /// answer could disagree — which would mean file operations dropping
    /// privilege while git did not.
    pub fn from_fs(runner: &FsRunner) -> Self {
        match runner {
            FsRunner::Tenant { uid, gid } => GitRunner::Tenant {
                uid: *uid,
                gid: *gid,
            },
            FsRunner::Local => GitRunner::Local,
        }
    }

    /// Build the command for one invocation, privilege drop included.
    fn command(&self, home: &Path, argv: &[OsString], timeout: Duration) -> Result<Cmd> {
        // Resolved against the fixed list of trusted directories, so a poisoned
        // PATH cannot redirect either program — the agent is root when it
        // matters.
        let git = exec::resolve_program("git").map_err(|_| {
            UnihelmError::new(
                ErrorCode::NotFound,
                "no `git` binary was found on this server, so a repository cannot be cloned \
                 or pulled. Install git with the server's package manager and try again.",
            )
        })?;

        let cmd = match self {
            GitRunner::Local => Cmd::new(git.to_string_lossy().into_owned()),
            GitRunner::Tenant { uid, gid } => {
                let setpriv = exec::resolve_program("setpriv").map_err(|_| {
                    UnihelmError::new(
                        ErrorCode::NotFound,
                        "git has to run as the site's own Linux account, and this server has \
                         no `setpriv` (util-linux) to drop privileges with. Nothing was run — \
                         install util-linux, or put the files in place with the file manager.",
                    )
                })?;
                Cmd::new(setpriv.to_string_lossy().into_owned())
                    .args([
                        format!("--reuid={uid}"),
                        format!("--regid={gid}"),
                        // Root's supplementary groups would otherwise survive
                        // the drop, which is not a drop.
                        "--clear-groups".to_string(),
                        "--no-new-privs".to_string(),
                    ])
                    // Ends setpriv's own option parsing before the program it
                    // is asked to exec.
                    .arg("--")
                    .arg(&git)
            }
        };

        Ok(cmd
            .args(argv)
            // git reads `$HOME/.gitconfig` and writes its caches there. With an
            // empty environment (Cmd clears it) there is no HOME at all, and
            // git complains on every run.
            .env("HOME", home)
            // The difference between a clear failure and a hung task: without
            // this, a private repository over HTTPS asks for a username on a
            // terminal that is not there.
            .env("GIT_TERMINAL_PROMPT", "0")
            // The task log is the progress display; git's colouring would only
            // put escape sequences in it.
            .env("NO_COLOR", "1")
            .timeout(timeout))
    }

    async fn run(&self, home: &Path, argv: &[OsString], timeout: Duration) -> Result<CmdOutput> {
        self.command(home, argv, timeout)?
            .run()
            .await
            .map_err(UnihelmError::from)
    }

    /// Run with every output line going to the task log as it appears, so a
    /// four-minute clone is not four minutes of silence (spec §10.1).
    async fn run_logged(
        &self,
        ctx: &OpContext,
        home: &Path,
        argv: &[OsString],
        timeout: Duration,
    ) -> Result<CmdOutput> {
        self.command(home, argv, timeout)?
            .run_streaming(|line| ctx.log(line))
            .await
            .map_err(UnihelmError::from)
    }
}

/// The leading argument vector: where to run, and the pinned configuration.
fn git_argv(root: Option<&Path>) -> Vec<OsString> {
    let mut argv: Vec<OsString> = Vec::new();
    if let Some(root) = root {
        // `-C` instead of a working directory on the command: `Cmd` runs
        // everything from the agent's own cwd by design, and git's own flag is
        // the supported way to say where a repository is.
        argv.push("-C".into());
        argv.push(root.as_os_str().to_os_string());
    }
    argv.push("--no-pager".into());
    argv.extend(GIT_CONFIG.iter().map(OsString::from));
    argv
}

/// `git clone` for one repository into one destination.
///
/// `--` before the URL is the load-bearing part: it ends option parsing, so a
/// repository or destination that begins with a hyphen is a path, never a flag
/// like `--upload-pack=…`. [`parse_repository`] refuses those anyway; this is
/// the wall behind it.
pub fn clone_argv(repository: &str, branch: Option<&str>, dest: &Path) -> Vec<OsString> {
    let mut argv = git_argv(None);
    argv.push("clone".into());
    // A submodule URL is written by whoever wrote the repository, not by
    // whoever attached it, and it is not checked by anything here.
    argv.push("--no-recurse-submodules".into());
    if let Some(branch) = branch {
        argv.push("--branch".into());
        argv.push(branch.into());
        argv.push("--single-branch".into());
    }
    argv.push("--".into());
    argv.push(repository.into());
    argv.push(dest.as_os_str().to_os_string());
    argv
}

/// `git fetch`, updating the remote-tracking branches and pruning the ones that
/// are gone. It changes nothing in the working tree.
pub fn fetch_argv(root: &Path) -> Vec<OsString> {
    let mut argv = git_argv(Some(root));
    argv.push("fetch".into());
    argv.push("--prune".into());
    argv.push("--".into());
    argv.push("origin".into());
    argv
}

/// The deploy itself: fast-forward only.
///
/// **Never `reset --hard`.** A reset is the reason panels lose work: it throws
/// away whatever the checkout had that the remote does not, silently and
/// without a question. `--ff-only` moves the branch when the remote is strictly
/// ahead and refuses when the histories have diverged, which is a sentence the
/// operator can act on. The ref is spelled in full so it cannot be read as
/// anything but a remote-tracking branch.
pub fn fast_forward_argv(root: &Path, branch: &str) -> Vec<OsString> {
    let mut argv = git_argv(Some(root));
    argv.push("merge".into());
    argv.push("--ff-only".into());
    argv.push(format!("refs/remotes/origin/{branch}").into());
    argv
}

// ---------------------------------------------------------------------------
// what a caller is allowed to name
// ---------------------------------------------------------------------------

/// Parse a repository URL, or refuse it with the reason.
///
/// Public HTTPS only. Everything else is named rather than attempted — see the
/// module docs for why a private repository is a refusal and not a half-clone.
pub fn parse_repository(raw: &str) -> Result<String> {
    let url = raw.trim();
    let refuse = |message: String| {
        Err(UnihelmError::new(ErrorCode::InvalidInput, message).with_field("repository"))
    };

    if url.is_empty() {
        return refuse(
            "Enter a repository URL, for example https://github.com/owner/project.git".into(),
        );
    }
    if url.len() > 512 {
        return refuse(format!(
            "A repository URL may be at most 512 characters; this one is {}.",
            url.len()
        ));
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return refuse(
            "A repository URL cannot contain spaces, tabs or control characters.".into(),
        );
    }

    let lower = url.to_ascii_lowercase();

    // Everything that is not an `https://` URL is named rather than attempted,
    // and the order matters: `ext::…` has a colon in it and would otherwise be
    // read as the scp-like form and reported as SSH.
    let Some(rest) = url
        .get("https://".len()..)
        .filter(|_| lower.starts_with("https://"))
    else {
        // The SSH refusal, in either of git's two spellings. This is the one
        // the module exists to make honestly: it is what people paste, and it
        // is the one the panel cannot serve.
        let ssh = || {
            format!(
                "`{url}` is an SSH repository address, and Unihelm clones over HTTPS only. \
                 An SSH remote needs a deploy key, and this panel has nowhere to keep one \
                 that the site's own files could not be read alongside. Use the \
                 repository's https:// address if it is public, or put the files in place \
                 with the file manager."
            )
        };
        if lower.starts_with("ssh://") || lower.starts_with("git+ssh://") {
            return refuse(ssh());
        }
        if let Some((scheme, _)) = lower.split_once("://") {
            return refuse(if scheme == "http" {
                format!(
                    "`{url}` is a plain-HTTP address. Unihelm clones over HTTPS only, \
                     because anything on the way can rewrite the code that ends up on this \
                     server. Use the https:// address of the same repository."
                )
            } else {
                format!(
                    "`{scheme}` repositories are not supported: Unihelm clones over HTTPS \
                     only. Use an https:// address."
                )
            });
        }
        // `<helper>::<address>` is git's transport-helper form, and `ext::` in
        // particular executes a command of the address's choosing.
        if let Some((helper, _)) = lower.split_once("::")
            && !helper.is_empty()
            && helper
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return refuse(format!(
                "`{helper}::` is a git transport helper, not a repository address Unihelm \
                 will use. Clones go over HTTPS only. Use an https:// address."
            ));
        }
        if is_scp_like(url) {
            return refuse(ssh());
        }
        return refuse(format!(
            "`{url}` is not a repository URL. It has to start with https://, like \
             https://github.com/owner/project.git"
        ));
    };

    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return refuse(
            "That URL has no host. A repository URL looks like \
             https://github.com/owner/project.git"
                .into(),
        );
    }
    if authority.contains('@') {
        return refuse(
            "A repository URL with a username or token in it is refused. git writes the \
             remote address into `.git/config` inside the document root, in plain text, \
             where anyone who can read the site's files can read the token. Use a public \
             https:// URL with no credentials in it."
                .into(),
        );
    }

    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if let Some(port) = port
        && (port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()))
    {
        return refuse(format!("`{port}` is not a port number."));
    }
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-']);
    if !host_ok {
        return refuse(format!(
            "`{host}` is not a host name. A repository URL looks like \
             https://github.com/owner/project.git"
        ));
    }

    // `https://github.com` is a website, not a repository, and git's own
    // failure for it arrives four seconds later over the network.
    let path = rest[authority.len()..].trim_start_matches('/');
    if path.is_empty() {
        return refuse(format!(
            "`{url}` names a host but no repository. Add the path, like \
             https://{host}/owner/project.git"
        ));
    }

    Ok(url.to_string())
}

/// Is this the `user@host:path` form git accepts without a scheme?
///
/// git decides this exactly one way: no `://`, and a colon before the first
/// slash. `C:/src/repo` on Windows is the classic false positive and is not a
/// case this panel has.
fn is_scp_like(url: &str) -> bool {
    !url.contains("://")
        && url
            .split_once(':')
            .is_some_and(|(head, _)| !head.contains('/'))
}

/// Parse a branch name, or refuse it.
///
/// A subset of `git check-ref-format`, deliberately stricter than git is: the
/// name reaches an argument vector and a `refs/remotes/origin/…` ref, so
/// anything that could be read as an option, a path traversal or a revision
/// expression is refused rather than escaped.
pub fn parse_branch(raw: &str) -> Result<String> {
    let branch = raw.trim();
    let refuse = |message: String| {
        Err(UnihelmError::new(ErrorCode::InvalidInput, message).with_field("branch"))
    };

    if branch.is_empty() {
        return refuse(
            "Enter a branch name, or leave it empty to use the repository's default branch.".into(),
        );
    }
    if branch.len() > 200 {
        return refuse("A branch name may be at most 200 characters.".into());
    }
    if !branch.is_ascii() || branch.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
        return refuse(format!(
            "`{branch}` is not a usable branch name: only printable ASCII, and no spaces."
        ));
    }
    // `-` first would be read as an option by anything that lost its `--`;
    // the rest are git's own rules, and `..`/`@{` are revision syntax.
    if branch.starts_with(['-', '.', '/'])
        || branch.ends_with(['.', '/'])
        || branch.ends_with(".lock")
        || branch.contains("..")
        || branch.contains("//")
        || branch.contains("@{")
        || branch == "@"
        || branch
            .chars()
            .any(|c| matches!(c, '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
    {
        return refuse(format!(
            "`{branch}` is not a usable branch name. Branch names cannot start with `-`, `.` \
             or `/`, cannot contain `..`, `~`, `^`, `:`, `?`, `*`, `[` or a backslash, and \
             cannot end with `/` or `.lock`."
        ));
    }
    Ok(branch.to_string())
}

// ---------------------------------------------------------------------------
// reading what is actually on disk
// ---------------------------------------------------------------------------

/// What is in the document root, as far as cloning is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootState {
    /// The directory is not there — a site that never finished provisioning.
    Missing,
    /// Nothing in it. A clone can go straight in.
    Empty,
    /// Nothing but the holding page `site.create` wrote. A clone replaces it.
    HoldingPage,
    /// A git checkout already. A clone would be refused; a pull is what this
    /// wants.
    Checkout,
    /// Somebody's files. Not ours to overwrite.
    Occupied,
}

/// Classify from the directory listing alone.
///
/// [`RootState::HoldingPage`] is only *provisional* here — the caller confirms
/// it by reading the file, because a hand-written `index.html` has the same
/// name and must never be replaced by a clone. Split out from the I/O so the
/// decision can be pinned by a test.
fn classify_names(names: &[String]) -> RootState {
    if names.iter().any(|n| n == ".git") {
        return RootState::Checkout;
    }
    if names.is_empty() {
        return RootState::Empty;
    }
    if names.len() == 1 && names[0] == "index.html" {
        return RootState::HoldingPage;
    }
    RootState::Occupied
}

/// The paths `git status --porcelain` reported as changed.
///
/// Called with `--untracked-files=no`, so this only ever sees *tracked* files.
/// That is the point: a deployed application writes uploads, caches and logs
/// into its own directory, and refusing to deploy because `var/cache` exists
/// would make the feature unusable. A fast-forward that would clobber an
/// untracked file is still refused — by git itself, whose message says which
/// file.
pub fn changed_paths(porcelain: &str) -> Vec<String> {
    porcelain
        .lines()
        .filter_map(|line| {
            // `XY <path>`: two status columns and a space. A rename is
            // `R  old -> new`, and the name on disk is the one after the arrow.
            let rest = line.get(3..)?;
            let path = rest.rsplit(" -> ").next().unwrap_or(rest);
            let path = path.trim().trim_matches('"');
            (!path.is_empty()).then(|| path.to_string())
        })
        .collect()
}

/// Turn a failed git run into something an operator can act on.
///
/// git's own stderr is the most accurate description of what happened and is
/// always carried through; these three cases get a sentence in front of it
/// because git's wording for them describes a mechanism rather than a decision
/// the operator can make.
fn explain(out: &CmdOutput, repository: &str, what: &str) -> UnihelmError {
    let text = out.failure_text();
    let lower = text.to_ascii_lowercase();

    if lower.contains("terminal prompts disabled")
        || lower.contains("authentication failed")
        || lower.contains("could not read username")
        || lower.contains("could not read password")
    {
        return UnihelmError::new(
            ErrorCode::PermissionDenied,
            format!(
                "`{repository}` asked for a username and password, which means it is private \
                 or does not exist. Unihelm clones public repositories only — it has nowhere \
                 to keep a credential that could not be read alongside the site's own files. \
                 Nothing was written. ({text})"
            ),
        );
    }
    if lower.contains("repository not found")
        || (lower.contains("not found") && lower.contains("404"))
    {
        return UnihelmError::new(
            ErrorCode::NotFound,
            format!("there is no repository at `{repository}`. Nothing was written. ({text})"),
        );
    }
    if lower.contains("remote branch") && lower.contains("not found") {
        return UnihelmError::new(
            ErrorCode::NotFound,
            format!("`{repository}` has no such branch. Nothing was written. ({text})"),
        );
    }
    UnihelmError::new(
        ErrorCode::CommandFailed,
        format!("{what} failed (exit {}): {text}", out.status),
    )
}

// ---------------------------------------------------------------------------
// resolving whose repository this is
// ---------------------------------------------------------------------------

/// A resolved site: whose account, which directory, which runners.
struct Target {
    site: Site,
    subscription: Subscription,
    home: PathBuf,
    /// The document root, absolute.
    root: PathBuf,
    /// The same directory relative to the home, which is the only spelling the
    /// file helper speaks.
    rel_root: TenantPath,
    fs: FsRunner,
    git: GitRunner,
}

impl Target {
    fn attachment_key(&self) -> String {
        attachment_key(self.site.id)
    }

    async fn attachment(&self, ctx: &OpContext) -> Result<Option<Attachment>> {
        ctx.db()
            .get_setting::<Attachment>(&self.attachment_key())
            .await
            .map_err(UnihelmError::from)
    }

    /// The attachment, or the refusal that names what to do about it.
    async fn require_attachment(&self, ctx: &OpContext) -> Result<Attachment> {
        self.attachment(ctx).await?.ok_or_else(|| {
            UnihelmError::new(
                ErrorCode::NotFound,
                format!(
                    "no repository is attached to {}. Attach one first — the panel needs to \
                     know which repository and which branch this site deploys from.",
                    self.site.domain
                ),
            )
        })
    }

    async fn save(&self, ctx: &OpContext, attachment: &Attachment) -> Result<()> {
        ctx.db()
            .set_setting(&self.attachment_key(), attachment)
            .await
            .map_err(UnihelmError::from)
    }

    /// What is in the document root right now, and the first few names in it.
    async fn root_state(&self) -> Result<(RootState, Vec<String>)> {
        let listed = self
            .fs
            .call(
                &self.home,
                FsRequest::List {
                    path: PathBuf::from(self.rel_root.as_str()),
                    // `.git` is a dotfile, and it is the whole question here.
                    show_hidden: true,
                },
                Vec::new(),
                INSPECT_TIMEOUT,
            )
            .await;

        let entries = match listed {
            Ok((FsData::Entries(entries), _)) => entries,
            Ok((other, _)) => {
                return Err(UnihelmError::internal(format!(
                    "the fs helper answered out of shape: {other:?}"
                )));
            }
            // A document root that is not there is a site whose provisioning
            // did not finish, which is a different sentence from "empty" and
            // has a different fix.
            Err(e) if e.code == ErrorCode::NotFound => {
                return Ok((RootState::Missing, Vec::new()));
            }
            Err(e) => return Err(e),
        };

        let names: Vec<String> = entries.into_iter().map(|e| e.name).collect();
        let state = match classify_names(&names) {
            RootState::HoldingPage if !self.is_holding_page().await => RootState::Occupied,
            other => other,
        };
        Ok((state, names.into_iter().take(MAX_LISTED).collect()))
    }

    /// Is the lone `index.html` the one `site.create` wrote?
    ///
    /// Anything that cannot be read as that page — a directory wearing the
    /// name, a file the helper refuses, bytes that are not text — answers no,
    /// and no means the document root reads as occupied and the clone is
    /// refused. A read failure here must never become permission to delete.
    async fn is_holding_page(&self) -> bool {
        let path = PathBuf::from(self.rel_root.as_str()).join("index.html");
        let read = self
            .fs
            .call(
                &self.home,
                FsRequest::Read {
                    path,
                    // The holding page is under a kilobyte; this is a cap, not
                    // a read size to tune.
                    max_bytes: 8 * 1024,
                    offset: 0,
                },
                Vec::new(),
                INSPECT_TIMEOUT,
            )
            .await;
        match read {
            Ok((_, payload)) => String::from_utf8_lossy(&payload).contains(HOLDING_PAGE_MARK),
            Err(_) => false,
        }
    }

    /// Run git and hand back stdout, or `None` when git said no.
    ///
    /// Used for the inspection commands, where "there is no origin" and "this
    /// is not a repository" are answers rather than failures.
    async fn ask(&self, argv: &[OsString]) -> Result<Option<String>> {
        let out = self.git.run(&self.home, argv, INSPECT_TIMEOUT).await?;
        Ok(out
            .success()
            .then(|| out.trimmed_stdout().to_string())
            .filter(|s| !s.is_empty()))
    }
}

/// Resolve a site the caller's scope can see.
///
/// Scoped read first: a site outside the caller's scope is `not_found` and
/// nothing else is learned about it.
async fn target_for_site(ctx: &OpContext, site_id: i64) -> Result<Target> {
    let site = ctx
        .db()
        .sites(ctx.scope())
        .by_id(SiteId(site_id))
        .await
        .map_err(UnihelmError::from)?
        .ok_or_else(|| UnihelmError::not_found("site"))?;

    // Resolving the subscription globally is safe *because* the site came out
    // of a scoped read: the site is already proof the caller may see this
    // subscription, and a second scoped read could only disagree with the
    // first.
    let subscription = ctx
        .db()
        .subscriptions(&unihelm_core::TenantScope::Global)
        .by_id(site.subscription_id)
        .await
        .map_err(UnihelmError::from)?
        .ok_or_else(|| UnihelmError::not_found("subscription"))?;

    let home = PathBuf::from(&subscription.home_dir);
    let root = PathBuf::from(&site.root_dir);

    // The document root has to be inside the home, or the privilege drop buys
    // nothing — the tenant's uid has no particular rights outside it, and the
    // tenant-relative path the file helper needs cannot be computed at all.
    let rel = root.strip_prefix(&home).map_err(|_| {
        UnihelmError::new(
            ErrorCode::InvalidPath,
            format!(
                "the document root of `{}` ({}) is not inside the tenant home ({}); Git \
                 deployment only manages directories inside a tenant home",
                site.domain,
                root.display(),
                home.display()
            ),
        )
    })?;
    let rel_root = TenantPath::parse(&rel.to_string_lossy())?;

    let fs = crate::fsops::ops::runner_for(&subscription.linux_user)?;
    let git = GitRunner::from_fs(&fs);
    Ok(Target {
        site,
        subscription,
        home,
        root,
        rel_root,
        fs,
        git,
    })
}

// ---------------------------------------------------------------------------
// git.status
// ---------------------------------------------------------------------------

pub struct Status;

#[derive(Debug, Deserialize)]
pub struct StatusInput {
    pub site_id: i64,
}

/// What the checkout on disk says about itself — never what the panel wishes
/// it said. `remote_matches_attachment` is the difference between the two, and
/// it is reported rather than resolved.
#[derive(Debug, Serialize)]
pub struct Checkout {
    pub remote: Option<String>,
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub subject: Option<String>,
    pub committed_at: Option<String>,
    pub dirty: bool,
    /// Tracked files with uncommitted changes, capped at [`MAX_LISTED`].
    pub changed_files: Vec<String>,
    pub remote_matches_attachment: bool,
}

#[derive(Debug, Serialize)]
pub struct StatusOutput {
    pub site_id: i64,
    pub domain: String,
    pub document_root: String,
    pub linux_user: String,
    /// False means every deploy operation on this page will refuse, and the
    /// page can say so before an operator presses anything.
    pub git_installed: bool,
    pub git_version: Option<String>,
    pub attachment: Option<Attachment>,
    pub root_state: RootState,
    /// The first few names in the document root, so a refusal to clone can
    /// show what is in the way.
    pub root_entries: Vec<String>,
    pub checkout: Option<Checkout>,
}

#[async_trait]
impl TypedOperation for Status {
    type Input = StatusInput;
    type Output = StatusOutput;

    const NAME: &'static str = "git.status";
    const PERMISSION: Permission = Permission::SiteRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let target = target_for_site(ctx, input.site_id).await?;
        let attachment = target.attachment(ctx).await?;
        let (root_state, root_entries) = target.root_state().await?;

        let git_installed = exec::program_available("git");
        let git_version = if git_installed {
            let argv = {
                let mut argv = git_argv(None);
                argv.push("--version".into());
                argv
            };
            target.ask(&argv).await.unwrap_or(None)
        } else {
            None
        };

        let checkout = if git_installed && root_state == RootState::Checkout {
            Some(read_checkout(&target, attachment.as_ref()).await?)
        } else {
            None
        };

        Ok(StatusOutput {
            site_id: target.site.id.get(),
            domain: target.site.domain.clone(),
            document_root: target.root.display().to_string(),
            linux_user: target.subscription.linux_user.clone(),
            git_installed,
            git_version,
            attachment,
            root_state,
            root_entries,
            checkout,
        })
    }
}

/// Everything the checkout will tell us, in four cheap questions.
async fn read_checkout(target: &Target, attachment: Option<&Attachment>) -> Result<Checkout> {
    let with = |extra: &[&str]| {
        let mut argv = git_argv(Some(&target.root));
        argv.extend(extra.iter().map(OsString::from));
        argv
    };

    let remote = target.ask(&with(&["remote", "get-url", "origin"])).await?;
    let branch = target
        .ask(&with(&["rev-parse", "--abbrev-ref", "HEAD"]))
        .await?
        // A detached HEAD answers the literal string `HEAD`, which is not a
        // branch and must not be reported as one.
        .filter(|b| b != "HEAD");

    // One process for three facts, in a format with no separator ambiguity.
    let head = target
        .ask(&with(&["log", "-1", "--format=%H%n%s%n%aI"]))
        .await?;
    let mut lines = head.as_deref().unwrap_or_default().lines();
    let commit = lines.next().map(str::to_string).filter(|s| !s.is_empty());
    let subject = lines.next().map(str::to_string).filter(|s| !s.is_empty());
    let committed_at = lines.next().map(str::to_string).filter(|s| !s.is_empty());

    let porcelain = target
        .ask(&with(&["status", "--porcelain", "--untracked-files=no"]))
        .await?
        .unwrap_or_default();
    let changed = changed_paths(&porcelain);

    let remote_matches_attachment = match (attachment, remote.as_deref()) {
        (Some(a), Some(remote)) => a.repository == remote,
        // Nothing attached, or no origin: there is no claim to contradict, so
        // the honest answer is "no mismatch to report".
        _ => true,
    };

    Ok(Checkout {
        remote,
        branch,
        commit,
        subject,
        committed_at,
        dirty: !changed.is_empty(),
        changed_files: changed.into_iter().take(MAX_LISTED).collect(),
        remote_matches_attachment,
    })
}

// ---------------------------------------------------------------------------
// git.attach
// ---------------------------------------------------------------------------

pub struct Attach;

#[derive(Debug, Deserialize)]
pub struct AttachInput {
    pub site_id: i64,
    pub repository: String,
    #[serde(default)]
    pub branch: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AttachOutput {
    pub site_id: i64,
    pub domain: String,
    pub repository: String,
    pub branch: Option<String>,
    pub document_root: String,
    /// The repository this replaced, when it replaced one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced: Option<String>,
}

#[async_trait]
impl TypedOperation for Attach {
    type Input = AttachInput;
    type Output = AttachOutput;

    const NAME: &'static str = "git.attach";
    const PERMISSION: Permission = Permission::SiteManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let target = target_for_site(ctx, input.site_id).await?;
        let repository = parse_repository(&input.repository)?;
        // An empty string from a form field is "I did not fill this in", not a
        // branch named "": the default branch is what that means.
        let branch = match input.branch.as_deref().map(str::trim) {
            Some("") | None => None,
            Some(raw) => Some(parse_branch(raw)?),
        };

        let previous = target.attachment(ctx).await?;
        // Carry the deploy history across only when it still describes this
        // repository. Pointing a site at a different repository and keeping
        // "last deployed commit abc123" would be the panel reporting a state
        // that is no longer true of anything.
        let same_repository = previous
            .as_ref()
            .is_some_and(|p| p.repository == repository);
        let attachment = Attachment {
            repository: repository.clone(),
            branch: branch.clone(),
            attached_at: OffsetDateTime::now_utc(),
            last_commit: previous
                .as_ref()
                .filter(|_| same_repository)
                .and_then(|p| p.last_commit.clone()),
            last_deployed_at: previous
                .as_ref()
                .filter(|_| same_repository)
                .and_then(|p| p.last_deployed_at),
        };
        target.save(ctx, &attachment).await?;

        Ok(AttachOutput {
            site_id: target.site.id.get(),
            domain: target.site.domain.clone(),
            repository,
            branch,
            document_root: target.root.display().to_string(),
            replaced: previous
                .map(|p| p.repository)
                .filter(|r| *r != attachment.repository),
        })
    }
}

// ---------------------------------------------------------------------------
// git.detach
// ---------------------------------------------------------------------------

pub struct Detach;

#[derive(Debug, Deserialize)]
pub struct DetachInput {
    pub site_id: i64,
}

#[derive(Debug, Serialize)]
pub struct DetachOutput {
    pub site_id: i64,
    pub domain: String,
    /// False when there was nothing attached — the intent is satisfied either
    /// way, and the answer says which happened.
    pub detached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Always true, and stated rather than assumed: detaching forgets the
    /// repository, it does not delete the checkout or the site's files.
    pub files_kept: bool,
}

#[async_trait]
impl TypedOperation for Detach {
    type Input = DetachInput;
    type Output = DetachOutput;

    const NAME: &'static str = "git.detach";
    const PERMISSION: Permission = Permission::SiteManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let target = target_for_site(ctx, input.site_id).await?;
        let previous = target.attachment(ctx).await?;
        if previous.is_some() {
            ctx.db()
                .delete_setting(&target.attachment_key())
                .await
                .map_err(UnihelmError::from)?;
        }

        Ok(DetachOutput {
            site_id: target.site.id.get(),
            domain: target.site.domain.clone(),
            detached: previous.is_some(),
            repository: previous.map(|p| p.repository),
            files_kept: true,
        })
    }
}

// ---------------------------------------------------------------------------
// git.clone
// ---------------------------------------------------------------------------

pub struct Clone;

#[derive(Debug, Deserialize)]
pub struct CloneInput {
    pub site_id: i64,
}

#[derive(Debug, Serialize)]
pub struct CloneOutput {
    pub site_id: i64,
    pub domain: String,
    pub document_root: String,
    pub repository: String,
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub subject: Option<String>,
    /// The panel's holding page was in the way and was removed. Said out loud
    /// because it is the one file this operation deletes.
    pub replaced_holding_page: bool,
}

#[async_trait]
impl TypedOperation for Clone {
    type Input = CloneInput;
    type Output = CloneOutput;

    const NAME: &'static str = "git.clone";
    const PERMISSION: Permission = Permission::SiteManage;
    // Not idempotent: a second run meets its own checkout and is refused. Not
    // cancellable either — a clone killed halfway leaves a partial tree that
    // the next run would have to refuse, so the honest button is "wait".
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: false,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let target = target_for_site(ctx, input.site_id).await?;
        let attachment = target.require_attachment(ctx).await?;

        let (state, names) = target.root_state().await?;
        let replaced_holding_page = match state {
            RootState::Checkout => {
                return Err(UnihelmError::new(
                    ErrorCode::Conflict,
                    format!(
                        "{} already holds a Git checkout. Deploy pulls the latest commit into \
                         it; cloning again would mean deleting what is there first.",
                        target.root.display()
                    ),
                ));
            }
            RootState::Occupied => {
                return Err(UnihelmError::new(
                    ErrorCode::Conflict,
                    format!(
                        "{} is not empty — it holds {}. Cloning into it would write over a \
                         live site, so nothing was done. Move or delete those files with the \
                         file manager first, or attach this repository to a new site.",
                        target.root.display(),
                        names.join(", ")
                    ),
                ));
            }
            RootState::Missing => {
                return Err(UnihelmError::new(
                    ErrorCode::NotFound,
                    format!(
                        "{} does not exist, so there is nowhere to clone into. {} has not \
                         finished being set up — run `site.reprovision` (Finish setting it \
                         up) first.",
                        target.root.display(),
                        target.site.domain
                    ),
                ));
            }
            RootState::HoldingPage => {
                // Removed as the tenant, through the file helper, for the same
                // reason `wp-config.php` is written that way: the document root
                // is tenant-controlled, and a root process deleting a path
                // inside it can be aimed somewhere else with a symlink.
                ctx.log(format!(
                    "replacing the holding page in {}",
                    target.root.display()
                ));
                target
                    .fs
                    .call(
                        &target.home,
                        FsRequest::Remove {
                            path: PathBuf::from(target.rel_root.as_str()).join("index.html"),
                        },
                        Vec::new(),
                        INSPECT_TIMEOUT,
                    )
                    .await?;
                true
            }
            RootState::Empty => false,
        };

        ctx.log(format!(
            "cloning {} into {}",
            attachment.repository,
            target.root.display()
        ));
        let argv = clone_argv(
            &attachment.repository,
            attachment.branch.as_deref(),
            &target.root,
        );
        let out = target
            .git
            .run_logged(ctx, &target.home, &argv, TRANSFER_TIMEOUT)
            .await?;
        if !out.success() {
            return Err(explain(&out, &attachment.repository, "the clone"));
        }

        // The branch the clone actually landed on. When the caller named one
        // this confirms it; when they did not, this is how the panel learns
        // what "the default branch" turned out to be, so a later deploy
        // fast-forwards that branch instead of guessing.
        let checkout = read_checkout(&target, Some(&attachment)).await?;
        let saved = Attachment {
            branch: checkout.branch.clone().or(attachment.branch.clone()),
            last_commit: checkout.commit.clone(),
            last_deployed_at: Some(OffsetDateTime::now_utc()),
            ..attachment.clone()
        };
        target.save(ctx, &saved).await?;

        ctx.log(match (&saved.branch, &checkout.commit) {
            (Some(branch), Some(commit)) => {
                format!("{} is at {commit} on {branch}", target.root.display())
            }
            _ => format!("{} is populated", target.root.display()),
        });

        Ok(CloneOutput {
            site_id: target.site.id.get(),
            domain: target.site.domain.clone(),
            document_root: target.root.display().to_string(),
            repository: saved.repository,
            branch: saved.branch,
            commit: checkout.commit,
            subject: checkout.subject,
            replaced_holding_page,
        })
    }
}

// ---------------------------------------------------------------------------
// git.pull
// ---------------------------------------------------------------------------

pub struct Pull;

#[derive(Debug, Deserialize)]
pub struct PullInput {
    pub site_id: i64,
}

#[derive(Debug, Serialize)]
pub struct PullOutput {
    pub site_id: i64,
    pub domain: String,
    pub document_root: String,
    pub repository: String,
    pub branch: String,
    /// False when the checkout was already at the newest commit. A deploy that
    /// moved nothing has to say so, or every deploy looks like a release.
    pub updated: bool,
    pub from_commit: Option<String>,
    pub commit: Option<String>,
    pub subject: Option<String>,
}

#[async_trait]
impl TypedOperation for Pull {
    type Input = PullInput;
    type Output = PullOutput;

    const NAME: &'static str = "git.pull";
    const PERMISSION: Permission = Permission::SiteManage;
    // Idempotent: a second run fast-forwards nothing and says `updated: false`.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let target = target_for_site(ctx, input.site_id).await?;
        let attachment = target.require_attachment(ctx).await?;

        let (state, _) = target.root_state().await?;
        if state != RootState::Checkout {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "there is no Git checkout in {}, so there is nothing to pull into. Clone \
                     {} first.",
                    target.root.display(),
                    attachment.repository
                ),
            ));
        }

        let before = read_checkout(&target, Some(&attachment)).await?;

        // The checkout has to be the repository the panel thinks it is, or a
        // deploy pulls somebody else's code into this site.
        if let Some(remote) = &before.remote
            && *remote != attachment.repository
        {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "the checkout in {} pulls from `{remote}`, but `{}` is attached to {}. \
                     Nothing was pulled. Attach the repository that is really there, or \
                     remove the checkout and clone again.",
                    target.root.display(),
                    attachment.repository,
                    target.site.domain
                ),
            ));
        }

        // A pull over a dirty tree loses work, so it is refused. The safe thing
        // is not a stash — a stash the operator never asked for is work that
        // has moved somewhere they will not look for it.
        if before.dirty {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "{} has uncommitted changes to files Git is tracking ({}). Pulling would \
                     overwrite them, so nothing was changed. Commit them, or undo them, and \
                     deploy again. Files Git does not track — uploads, caches — are not \
                     counted here and are never touched.",
                    target.root.display(),
                    before.changed_files.join(", ")
                ),
            ));
        }

        let Some(branch) = attachment.branch.clone().or_else(|| before.branch.clone()) else {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "the checkout in {} is not on a branch (detached HEAD), so there is no \
                     branch to fast-forward. Check out a branch in it, or remove the checkout \
                     and clone again.",
                    target.root.display()
                ),
            ));
        };

        ctx.log(format!("fetching {} for {}", attachment.repository, branch));
        let out = target
            .git
            .run_logged(
                ctx,
                &target.home,
                &fetch_argv(&target.root),
                TRANSFER_TIMEOUT,
            )
            .await?;
        if !out.success() {
            return Err(explain(&out, &attachment.repository, "the fetch"));
        }

        let out = target
            .git
            .run_logged(
                ctx,
                &target.home,
                &fast_forward_argv(&target.root, &branch),
                TRANSFER_TIMEOUT,
            )
            .await?;
        if !out.success() {
            let text = out.failure_text();
            let lower = text.to_ascii_lowercase();
            if lower.contains("not possible to fast-forward") || lower.contains("diverging") {
                return Err(UnihelmError::new(
                    ErrorCode::Conflict,
                    format!(
                        "{} has commits of its own that `{}` does not, so it cannot be \
                         fast-forwarded to `{branch}`. Nothing was changed — Unihelm never \
                         discards commits to deploy. Reconcile the two histories, or remove \
                         the checkout and clone again. ({text})",
                        target.root.display(),
                        attachment.repository
                    ),
                ));
            }
            return Err(explain(&out, &attachment.repository, "the deploy"));
        }

        let after = read_checkout(&target, Some(&attachment)).await?;
        let saved = Attachment {
            branch: Some(branch.clone()),
            last_commit: after.commit.clone(),
            last_deployed_at: Some(OffsetDateTime::now_utc()),
            ..attachment.clone()
        };
        target.save(ctx, &saved).await?;

        let updated = before.commit != after.commit;
        ctx.log(if updated {
            format!(
                "{} moved to {}",
                target.root.display(),
                after
                    .commit
                    .clone()
                    .unwrap_or_else(|| "the new commit".into())
            )
        } else {
            format!("{} was already up to date", target.root.display())
        });

        Ok(PullOutput {
            site_id: target.site.id.get(),
            domain: target.site.domain.clone(),
            document_root: target.root.display().to_string(),
            repository: saved.repository,
            branch,
            updated,
            from_commit: before.commit,
            commit: after.commit,
            subject: after.subject,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use unihelm_core::{AuthContext, Role, TenantScope, UserId};
    use unihelm_db::Db;
    use unihelm_db::sites::{NewSite, SiteType};
    use unihelm_distro::Distro;

    fn argv_strings(argv: &[OsString]) -> Vec<String> {
        argv.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    // -- what a caller may name ---------------------------------------------

    #[test]
    fn an_ssh_repository_url_is_refused_with_the_credential_reason() {
        for url in [
            "ssh://git@github.com/owner/project.git",
            "git@github.com:owner/project.git",
            "git+ssh://git@example.com/p.git",
        ] {
            let err = parse_repository(url).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{url}");
            assert_eq!(err.field.as_deref(), Some("repository"), "{url}");
            assert!(
                err.detail.contains("HTTPS only") && err.detail.contains("deploy key"),
                "{url}: {}",
                err.detail
            );
        }
    }

    #[test]
    fn a_repository_url_carrying_a_credential_is_refused_before_git_can_write_it_to_disk() {
        // git copies the remote verbatim into .git/config, inside the document
        // root, in plain text — so this refusal is the whole storage story.
        let err = parse_repository("https://user:ghp_secrettoken@github.com/o/p.git").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.detail.contains(".git/config"), "{}", err.detail);
        assert!(
            !err.detail.contains("ghp_secrettoken"),
            "the refusal must not echo the token back: {}",
            err.detail
        );
    }

    #[test]
    fn every_transport_but_https_is_refused_by_name() {
        for (url, expected) in [
            ("http://github.com/o/p.git", "https"),
            ("git://github.com/o/p.git", "git"),
            ("file:///srv/repo", "file"),
            // The `ext::` transport runs a command of the remote's choosing.
            ("ext::curl-the-remote", "ext"),
        ] {
            let err = parse_repository(url).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{url}");
            assert!(
                err.detail.to_ascii_lowercase().contains(expected),
                "{url}: {}",
                err.detail
            );
        }
    }

    #[test]
    fn a_repository_url_that_could_be_read_as_an_option_or_a_shell_word_is_refused() {
        for url in [
            "--upload-pack=/bin/id",
            "https://example.com/a b.git",
            "https://example.com/a\nb.git",
            "https://",
            "https://github.com",
            "https://exa mple.com/p.git",
        ] {
            assert!(parse_repository(url).is_err(), "{url} was accepted");
        }
    }

    #[test]
    fn an_ordinary_public_https_repository_is_accepted_unchanged() {
        for url in [
            "https://github.com/owner/project.git",
            "https://gitlab.example.com:8443/group/sub/project",
            "  https://github.com/owner/project.git  ",
        ] {
            let parsed = parse_repository(url).expect(url);
            assert_eq!(parsed, url.trim());
        }
    }

    #[test]
    fn a_branch_name_that_could_be_read_as_an_option_or_a_revision_is_refused() {
        for branch in [
            "--upload-pack=id",
            "-b",
            "../../etc",
            "main~1",
            "main^",
            "feature:x",
            "main..dev",
            "release.lock",
            "/main",
            "main/",
            "main branch",
            "@",
            "HEAD@{1}",
            "",
        ] {
            let err = parse_branch(branch).unwrap_err();
            assert_eq!(err.field.as_deref(), Some("branch"), "{branch}");
        }
    }

    #[test]
    fn ordinary_branch_names_are_accepted() {
        for branch in ["main", "master", "release/2026-09", "v1.2.3", "feature_x"] {
            assert_eq!(parse_branch(branch).expect(branch), branch);
        }
    }

    // -- the argument vectors -----------------------------------------------

    #[test]
    fn the_clone_argv_pins_the_transport_and_ends_option_parsing_before_the_url() {
        let argv = argv_strings(&clone_argv(
            "https://github.com/o/p.git",
            Some("main"),
            Path::new("/home/uh_a/sites/example.com/public"),
        ));

        assert!(
            argv.contains(&"protocol.allow=never".to_string()),
            "{argv:?}"
        );
        assert!(
            argv.contains(&"protocol.https.allow=always".to_string()),
            "{argv:?}"
        );
        assert!(
            argv.contains(&"credential.helper=".to_string()),
            "no credential helper may be consulted: {argv:?}"
        );
        assert!(
            argv.contains(&"--no-recurse-submodules".to_string()),
            "{argv:?}"
        );

        let end = argv.iter().position(|a| a == "--").expect("a -- separator");
        assert_eq!(argv[end + 1], "https://github.com/o/p.git");
        assert_eq!(argv[end + 2], "/home/uh_a/sites/example.com/public");
        assert!(
            argv[..end].contains(&"--branch".to_string())
                && argv[..end].contains(&"main".to_string()),
            "{argv:?}"
        );
    }

    #[test]
    fn a_clone_without_a_branch_takes_the_repositorys_default() {
        let argv = argv_strings(&clone_argv(
            "https://github.com/o/p.git",
            None,
            Path::new("/srv/p"),
        ));
        assert!(!argv.contains(&"--branch".to_string()), "{argv:?}");
        assert!(!argv.contains(&"--single-branch".to_string()), "{argv:?}");
    }

    #[test]
    fn the_deploy_argv_fast_forwards_and_never_resets() {
        let argv = argv_strings(&fast_forward_argv(Path::new("/srv/p"), "main"));
        assert!(argv.contains(&"merge".to_string()), "{argv:?}");
        assert!(argv.contains(&"--ff-only".to_string()), "{argv:?}");
        assert!(
            argv.contains(&"refs/remotes/origin/main".to_string()),
            "{argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "reset" || a == "--hard"),
            "a deploy must never discard the checkout: {argv:?}"
        );
        assert_eq!(argv[0], "-C");
        assert_eq!(argv[1], "/srv/p");
    }

    // -- reading the document root ------------------------------------------

    #[test]
    fn a_document_root_is_classified_by_what_is_actually_in_it() {
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        assert_eq!(classify_names(&[]), RootState::Empty);
        assert_eq!(
            classify_names(&names(&["index.html"])),
            RootState::HoldingPage
        );
        assert_eq!(
            classify_names(&names(&[".git", "index.php"])),
            RootState::Checkout
        );
        // A `.git` anywhere in the listing wins: a checkout is a checkout even
        // with the tenant's uploads beside it.
        assert_eq!(
            classify_names(&names(&["uploads", ".git", "wp-config.php"])),
            RootState::Checkout
        );
        assert_eq!(
            classify_names(&names(&["index.html", "style.css"])),
            RootState::Occupied
        );
        assert_eq!(classify_names(&names(&["index.php"])), RootState::Occupied);
    }

    #[test]
    fn the_dirty_check_reads_git_porcelain_including_renames() {
        let porcelain = " M src/app.php\nA  new.txt\nR  old.txt -> new/name.txt\n?? ignored\n";
        assert_eq!(
            changed_paths(porcelain),
            vec!["src/app.php", "new.txt", "new/name.txt", "ignored"]
        );
        // Called with --untracked-files=no in practice, so `??` never appears;
        // parsing it anyway keeps the function honest about what it was given.
        assert!(changed_paths("").is_empty());
        assert!(changed_paths("\n").is_empty());
    }

    // -- the operations -----------------------------------------------------

    /// An OpContext over a mock distro and an in-memory database, plus a site
    /// whose subscription and document root exist as rows. Built directly, the
    /// way `cron.rs` does, because these tests never dispatch.
    async fn ctx_with_site() -> (OpContext, Db, Site) {
        let db = Db::open_memory().await.unwrap();
        let customer = db
            .users(&TenantScope::Global)
            .create(unihelm_db::users::NewUser {
                role: Role::Customer,
                email: unihelm_core::Email::parse("c@example.com").unwrap(),
                username: unihelm_core::Username::parse("client").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let sub = db.create_subscription(customer.id).await.unwrap();
        let site = db
            .create_site(NewSite {
                subscription_id: sub.id,
                domain: unihelm_core::Domain::parse("example.com").unwrap(),
                // Static: nothing here renders a pool, and a PHP row would
                // need a version this test has no opinion about.
                site_type: SiteType::Static,
                php_version: None,
                root_dir: format!("{}/sites/example.com/public", sub.home_dir),
                proxy_port: None,
                redirect_target: None,
            })
            .await
            .unwrap();

        let services = Arc::new(
            crate::registry::Services::new(
                Distro::mock(),
                db.clone(),
                unihelm_db::MasterKey::generate(),
            )
            .expect("templates compile"),
        );
        let auth = AuthContext::from_role(UserId(1), Role::Admin, TenantScope::Global, "req-test");
        (OpContext::new(services, auth), db, site)
    }

    #[tokio::test]
    async fn attaching_a_repository_records_it_and_status_reads_it_back() {
        let (ctx, _db, site) = ctx_with_site().await;

        let out = Attach
            .run(
                &ctx,
                AttachInput {
                    site_id: site.id.get(),
                    repository: "https://github.com/owner/project.git".into(),
                    // An empty branch is "use the default", not a branch named "".
                    branch: Some("  ".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(out.repository, "https://github.com/owner/project.git");
        assert_eq!(out.branch, None);
        assert_eq!(out.replaced, None);

        let status = Status
            .run(
                &ctx,
                StatusInput {
                    site_id: site.id.get(),
                },
            )
            .await
            .unwrap();
        let attachment = status.attachment.expect("the attachment is readable back");
        assert_eq!(
            attachment.repository,
            "https://github.com/owner/project.git"
        );
        assert_eq!(
            attachment.last_commit, None,
            "an attachment on its own has deployed nothing"
        );
        assert_eq!(
            status.root_state,
            RootState::Missing,
            "the tenant home only exists as a row in these tests"
        );
    }

    #[tokio::test]
    async fn re_attaching_a_different_repository_forgets_the_commit_it_no_longer_describes() {
        let (ctx, db, site) = ctx_with_site().await;
        let key = attachment_key(site.id);
        db.set_setting(
            &key,
            &Attachment {
                repository: "https://github.com/owner/one.git".into(),
                branch: Some("main".into()),
                attached_at: OffsetDateTime::now_utc(),
                last_commit: Some("1111111111111111111111111111111111111111".into()),
                last_deployed_at: Some(OffsetDateTime::now_utc()),
            },
        )
        .await
        .unwrap();

        let out = Attach
            .run(
                &ctx,
                AttachInput {
                    site_id: site.id.get(),
                    repository: "https://github.com/owner/two.git".into(),
                    branch: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            out.replaced.as_deref(),
            Some("https://github.com/owner/one.git")
        );

        let stored: Attachment = db.get_setting(&key).await.unwrap().unwrap();
        assert_eq!(stored.last_commit, None);
        assert_eq!(stored.last_deployed_at, None);
    }

    #[tokio::test]
    async fn re_attaching_the_same_repository_keeps_what_was_deployed() {
        let (ctx, db, site) = ctx_with_site().await;
        let key = attachment_key(site.id);
        let deployed = OffsetDateTime::now_utc();
        db.set_setting(
            &key,
            &Attachment {
                repository: "https://github.com/owner/one.git".into(),
                branch: Some("main".into()),
                attached_at: deployed,
                last_commit: Some("1111111111111111111111111111111111111111".into()),
                last_deployed_at: Some(deployed),
            },
        )
        .await
        .unwrap();

        Attach
            .run(
                &ctx,
                AttachInput {
                    site_id: site.id.get(),
                    repository: "https://github.com/owner/one.git".into(),
                    branch: Some("release/2026".into()),
                },
            )
            .await
            .unwrap();

        let stored: Attachment = db.get_setting(&key).await.unwrap().unwrap();
        assert_eq!(stored.branch.as_deref(), Some("release/2026"));
        assert_eq!(
            stored.last_commit.as_deref(),
            Some("1111111111111111111111111111111111111111"),
            "the same repository is still described by the commit it deployed"
        );
    }

    #[tokio::test]
    async fn detaching_reports_whether_there_was_anything_to_detach_and_keeps_the_files() {
        let (ctx, _db, site) = ctx_with_site().await;

        let nothing = Detach
            .run(
                &ctx,
                DetachInput {
                    site_id: site.id.get(),
                },
            )
            .await
            .unwrap();
        assert!(!nothing.detached);
        assert!(nothing.files_kept);

        Attach
            .run(
                &ctx,
                AttachInput {
                    site_id: site.id.get(),
                    repository: "https://github.com/owner/project.git".into(),
                    branch: None,
                },
            )
            .await
            .unwrap();

        let removed = Detach
            .run(
                &ctx,
                DetachInput {
                    site_id: site.id.get(),
                },
            )
            .await
            .unwrap();
        assert!(removed.detached);
        assert_eq!(
            removed.repository.as_deref(),
            Some("https://github.com/owner/project.git")
        );
        assert!(removed.files_kept);
    }

    #[tokio::test]
    async fn cloning_or_pulling_without_an_attachment_refuses_and_says_what_to_do() {
        let (ctx, _db, site) = ctx_with_site().await;

        for detail in [
            Clone
                .run(
                    &ctx,
                    CloneInput {
                        site_id: site.id.get(),
                    },
                )
                .await
                .unwrap_err(),
            Pull.run(
                &ctx,
                PullInput {
                    site_id: site.id.get(),
                },
            )
            .await
            .unwrap_err(),
        ] {
            assert_eq!(detail.code, ErrorCode::NotFound);
            assert!(
                detail.detail.contains("no repository is attached")
                    && detail.detail.contains("example.com"),
                "{}",
                detail.detail
            );
        }
    }

    #[tokio::test]
    async fn a_site_outside_the_callers_scope_is_not_found_rather_than_described() {
        let (ctx, _db, site) = ctx_with_site().await;
        let err = Status
            .run(
                &ctx,
                StatusInput {
                    site_id: site.id.get() + 1000,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn a_clone_into_a_document_root_that_is_not_there_refuses_before_running_git() {
        let (ctx, _db, site) = ctx_with_site().await;
        Attach
            .run(
                &ctx,
                AttachInput {
                    site_id: site.id.get(),
                    repository: "https://github.com/owner/project.git".into(),
                    branch: None,
                },
            )
            .await
            .unwrap();

        let err = Clone
            .run(
                &ctx,
                CloneInput {
                    site_id: site.id.get(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(
            err.detail.contains("does not exist") && err.detail.contains("Finish setting it up"),
            "{}",
            err.detail
        );
    }
}
