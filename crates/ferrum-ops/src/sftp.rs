//! Chrooted SFTP access for tenants (spec §6, §5.2).
//!
//! # How the sshd side works
//!
//! One managed drop-in, `/etc/ssh/sshd_config.d/50-ferrum.conf`, carries a
//! single `Match Group ferrum-sftp` block: `ChrootDirectory %h`,
//! `ForceCommand internal-sftp`, forwarding off. Enabling SFTP for a tenant is
//! then a group membership change, not a config change — the drop-in is written
//! once and `sftp.enable` for the second tenant only touches `/etc/group`.
//!
//! Two deliberate absences in that drop-in:
//!
//! - **No `Subsystem` line.** Both families declare `Subsystem sftp …` in their
//!   stock `sshd_config`, and sshd treats a second declaration as a fatal
//!   error — worse, drop-ins are included at the *top* of `sshd_config`, so it
//!   would be the distribution's own later line that turns fatal and takes
//!   sshd down with it. `ForceCommand internal-sftp` does not need it anyway:
//!   the in-process SFTP server is invoked directly, ignoring the subsystem
//!   table *and* the user's shell — which is why a `nologin` tenant (spec
//!   §6.3: no shell unless the plan grants one) can still use SFTP while
//!   remaining unable to log in any other way.
//! - **Nothing after the `Match` block.** A `Match` context runs to the end of
//!   file, and on older sshds could leak past an `Include` boundary into the
//!   stock config. The block is the entire file, and the validator tests the
//!   whole installed tree before anything reloads, so a leak is caught rather
//!   than activated.
//!
//! # The chroot ownership problem
//!
//! sshd refuses `ChrootDirectory` unless every component of the path is owned
//! by root and writable by nobody else ("bad ownership or modes for chroot
//! directory"). But provisioning (provision.rs) gives a tenant their home
//! outright — `tenant:nginx`, mode `0710` — which fails that check.
//!
//! The reconciliation, applied by `sftp.enable` **only** (a tenant who never
//! asks for SFTP keeps the provision layout untouched):
//!
//! - `/home/<user>` becomes `root:root 0755`. World-execute keeps the two
//!   traversals that `0710` existed for — nginx reaching `sites/<domain>/public`
//!   and the tenant's own FPM pool reaching everything — while root ownership
//!   satisfies sshd. Privacy moves one level down: `sites/` stays `0750`
//!   `tenant:nginx`, so another tenant can list the home's entry names but can
//!   enter nothing.
//! - `sites/` and `.trash` stay owned by the tenant, because the chroot root
//!   itself is now unwritable to them — without a tenant-owned subdirectory an
//!   SFTP login could see their files but never upload one.
//!
//! **Loud interaction warning:** `provision::apply_home_permissions` would undo
//! this (it re-asserts `tenant:nginx 0710`). It currently runs only when the
//! Linux account is first created, so the two never fight — but any future
//! re-provisioning path that calls it on an existing account must first check
//! for SFTP membership or it will silently break every chrooted login.
//!
//! `sftp.disable` removes the group membership and nothing else: the files are
//! the tenant's data, and the root-owned home remains perfectly serviceable for
//! a non-SFTP tenant (see above), so flipping ownership back would be churn
//! with no security payoff.
//!
//! # Passwords
//!
//! sshd verifies passwords through PAM against `/etc/shadow`, which speaks
//! crypt(3) formats — it cannot read the panel's argon2 hashes
//! (`ferrum_db::password`). So the hash is computed in-process as sha512-crypt
//! (the `sha-crypt` crate, pure Rust) and installed with `usermod --password`,
//! argv only: [`ferrum_distro::Cmd`] deliberately has no stdin plumbing
//! (`chpasswd` would need it), and through argv the `$6$…` hash is just bytes —
//! no shell ever sees it. The cleartext is never stored or logged anywhere; the
//! one trade-off is that the *hash* is briefly visible in the process table,
//! which is the salted, stretched form `/etc/shadow` holds anyway.

use std::fmt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use ferrum_config::apply::{ApplyRequest, Reloader, Validator};
use ferrum_config::managed::{CommentStyle, ManagedFile};
use ferrum_config::paths;
use ferrum_core::{ErrorCode, FerrumError, LinuxUser, Permission, Result, SubscriptionId};
use ferrum_db::Subscription;
use ferrum_distro::svc::{ManagedUnit, SvcAction};
use ferrum_distro::{Cmd, Distro};
use serde::{Deserialize, Serialize};

use crate::registry::{Execution, OpContext, TypedOperation};

/// The one group the `Match` block keys on. Membership *is* the feature flag.
pub const SFTP_GROUP: &str = "ferrum-sftp";

/// `sftp.enable` — chroot a tenant's home and open SFTP access to it.
pub struct Enable;

#[derive(Deserialize)]
pub struct EnableInput {
    pub subscription_id: i64,
    /// Optional SFTP password. Held only for the duration of this operation:
    /// hashed in-process, installed into `/etc/shadow`, never stored or logged.
    #[serde(default)]
    pub password: Option<String>,
}

// Hand-written so a task log or a debug trace can never leak the cleartext
// (spec §12 rule 6: secrets are never logged in the clear).
impl fmt::Debug for EnableInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnableInput")
            .field("subscription_id", &self.subscription_id)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct EnableOutput {
    pub linux_user: String,
    pub group: String,
    /// False when the drop-in was already on disk and unchanged.
    pub config_changed: bool,
    pub password_set: bool,
}

#[async_trait]
impl TypedOperation for Enable {
    type Input = EnableInput;
    type Output = EnableOutput;

    const NAME: &'static str = "sftp.enable";
    const PERMISSION: Permission = Permission::SshAccess;
    // A task rather than immediate: `sshd -t` plus a unit reload is fast but
    // not reliably inside the IPC round-trip budget, and re-running after an
    // agent restart converges — every step here is idempotent.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let subscription = ctx
            .db()
            .subscriptions(ctx.scope())
            .by_id(SubscriptionId(input.subscription_id))
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("subscription"))?;

        // The plan gate and the password policy come before anything touches
        // the system: a denied or invalid request must leave no trace — in
        // particular it must not grant group membership and *then* fail.
        ensure_plan_allows_sftp(&subscription)?;
        if let Some(password) = &input.password {
            ferrum_db::password::check_strength(password)?;
        }

        let user = LinuxUser::parse(&subscription.linux_user)?;
        let home = verified_home(&subscription, &user)?;

        // SFTP presupposes the account; creating one is provisioning's job
        // (it happens on first site create), not a side effect of an access
        // toggle.
        if !user_exists(&user).await {
            return Err(FerrumError::new(
                ErrorCode::Conflict,
                format!(
                    "the Linux account `{user}` has not been provisioned yet — create a site \
                     under this subscription first"
                ),
            ));
        }

        ensure_sftp_group(ctx).await?;

        // Ownership before config before membership: access only opens once
        // the chroot is provably valid. The intermediate states are safe — a
        // root-owned home works for a non-SFTP tenant, and the Match block
        // without membership matches nobody.
        let group = sites_group(ctx.distro()).await;
        reconcile_chroot_ownership(ctx, &home, &user, &group).await?;

        let config_changed = render_sshd_dropin(ctx).await?;

        Cmd::new("usermod")
            .args(usermod_group_argv(&user))
            .run_checked()
            .await?;
        ctx.log(format!("{user} added to {SFTP_GROUP}"));

        let password_set = match &input.password {
            Some(password) => {
                set_sftp_password(&user, password).await?;
                ctx.log(format!("SFTP password set for {user}"));
                true
            }
            None => false,
        };

        Ok(EnableOutput {
            linux_user: user.as_str().to_string(),
            group: SFTP_GROUP.to_string(),
            config_changed,
            password_set,
        })
    }
}

/// `sftp.disable` — close SFTP access, touching nothing but the group.
pub struct Disable;

#[derive(Debug, Deserialize)]
pub struct DisableInput {
    pub subscription_id: i64,
}

#[derive(Debug, Serialize)]
pub struct DisableOutput {
    pub linux_user: String,
    /// False when the account was not a member (or does not exist) — disabling
    /// twice is not an error.
    pub removed: bool,
}

#[async_trait]
impl TypedOperation for Disable {
    type Input = DisableInput;
    type Output = DisableOutput;

    const NAME: &'static str = "sftp.disable";
    const PERMISSION: Permission = Permission::SshAccess;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let subscription = ctx
            .db()
            .subscriptions(ctx.scope())
            .by_id(SubscriptionId(input.subscription_id))
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("subscription"))?;

        // No plan gate here on purpose: revoking access must always work,
        // including for a subscription whose plan just lost the feature.
        let user = LinuxUser::parse(&subscription.linux_user)?;

        if !is_group_member(&user).await {
            return Ok(DisableOutput {
                linux_user: user.as_str().to_string(),
                removed: false,
            });
        }

        Cmd::new("gpasswd")
            .args(gpasswd_remove_argv(&user))
            .run_checked()
            .await?;

        // Deliberately nothing else: the tenant's files are their data, the
        // drop-in serves every other SFTP tenant, and the root-owned home
        // stays correct for a non-SFTP tenant (module docs). Without the group
        // the Match block no longer applies, and any other entry — shell, sftp
        // subsystem — dies at the account's `nologin` shell.
        Ok(DisableOutput {
            linux_user: user.as_str().to_string(),
            removed: true,
        })
    }
}

// ---------------------------------------------------------------------------
// Plan gate
// ---------------------------------------------------------------------------

/// Does the subscription's *plan* allow shell/SFTP access (`can_ssh`)?
///
/// The actor's `Permission::SshAccess` was already checked by the registry;
/// this is the other half of the rule — the feature has to be granted to the
/// *target* tenant's plan, not just to the caller (spec §6.2).
///
/// Wave-1 note, deliberately fail-closed: the plans repository lands in the
/// parallel `plans-suspension` branch, so a `plan_id` cannot be resolved to
/// its features from here yet. A planned subscription is therefore refused
/// with `PlanFeatureDisabled` until the integrator wires this to
/// `PlanFeatures::can_ssh` — a loud failure the first time anyone tries, where
/// allowing it through would be a silent security hole (an SFTP grant the
/// plan never included). Plan-less subscriptions (Phase 1's implicit ones)
/// carry no feature gates and pass.
fn ensure_plan_allows_sftp(subscription: &Subscription) -> Result<()> {
    match subscription.plan_id {
        None => Ok(()),
        Some(plan_id) => Err(FerrumError::new(
            ErrorCode::PlanFeatureDisabled,
            format!(
                "cannot verify that plan {plan_id} grants shell access: the plan feature \
                 lookup is not wired into sftp.enable yet"
            ),
        )),
    }
}

// ---------------------------------------------------------------------------
// sshd configuration
// ---------------------------------------------------------------------------

/// `sshd -t` — the whole installed tree, not just our fragment.
///
/// The task brief suggests `-t -f <staged>`, but the apply engine's sequence is
/// write → validate → rollback (see `ferrum_config::apply` for why), so by
/// validation time the drop-in *is* part of the installed tree — and testing
/// the tree is strictly stronger: it also catches interactions with the stock
/// config, like a `Match` context leaking across the `Include` boundary, which
/// a fragment-only check cannot see.
struct SshdValidator;

#[async_trait]
impl Validator for SshdValidator {
    fn name(&self) -> &'static str {
        "sshd -t"
    }

    async fn validate(&self) -> std::result::Result<(), String> {
        // Like `nginx -t`, sshd's own words — file and line included — are what
        // an operator needs to see; paraphrasing them helps nobody.
        match Cmd::new("sshd").arg("-t").run().await {
            Ok(out) if out.success() => Ok(()),
            Ok(out) => Err(out.failure_text()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Reload the ssh unit — `ssh.service` on Debian, `sshd.service` on EL
/// ([`ManagedUnit::Sshd`] owns that difference).
///
/// A reload (SIGHUP) re-reads the config without dropping established
/// connections, so enabling tenant three never disconnects tenants one and two.
struct SshdReloader {
    distro: Distro,
}

#[async_trait]
impl Reloader for SshdReloader {
    fn name(&self) -> &'static str {
        "sshd"
    }

    async fn reload(&self) -> std::result::Result<(), String> {
        let unit = ManagedUnit::Sshd.unit_name(self.distro.info.family);

        // Not running is not a failure: writing the drop-in on a machine whose
        // sshd is stopped is legitimate — it is picked up on the next start.
        let status = self
            .distro
            .svc
            .status(&unit)
            .await
            .map_err(|e| e.to_string())?;
        if !status.is_installed() || !status.is_active() {
            tracing::debug!(unit = %unit, "not running; nothing to reload");
            return Ok(());
        }

        self.distro
            .svc
            .action(&unit, SvcAction::Reload)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Render and activate the drop-in. Returns whether anything changed on disk.
async fn render_sshd_dropin(ctx: &OpContext) -> Result<bool> {
    let outcome = ctx
        .config()
        .apply(ApplyRequest {
            file: ManagedFile {
                path: paths::sshd_dropin(),
                // 0600 like the stock sshd_config on both families; only root
                // and sshd itself ever need to read it.
                mode: 0o600,
                comment_style: CommentStyle::Hash,
            },
            template: "ssh/sftp.conf",
            context: serde_json::json!({ "sftp_group": SFTP_GROUP }),
            service: "sshd",
            validator: &SshdValidator,
            reloader: &SshdReloader {
                distro: ctx.distro().clone(),
            },
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await
        .map_err(FerrumError::from)?;

    if outcome.changed {
        ctx.log(format!(
            "{} written and sshd reloaded",
            outcome.path.display()
        ));
    }
    Ok(outcome.changed)
}

// ---------------------------------------------------------------------------
// Group membership
// ---------------------------------------------------------------------------

/// Create [`SFTP_GROUP`] if it is missing. Idempotent-tolerant like `useradd`
/// in provision.rs: the existence check covers the normal case, and exit code
/// 9 ("group already exists") covers the race where two enables run at once.
async fn ensure_sftp_group(ctx: &OpContext) -> Result<()> {
    if group_exists(SFTP_GROUP).await {
        return Ok(());
    }
    let out = Cmd::new("groupadd").args(groupadd_argv()).run().await?;
    if out.success() || out.status == 9 {
        ctx.log(format!("group {SFTP_GROUP} ready"));
        return Ok(());
    }
    Err(FerrumError::new(
        ErrorCode::CommandFailed,
        format!("groupadd {SFTP_GROUP} failed: {}", out.failure_text()),
    ))
}

/// `groupadd --system -- ferrum-sftp`: a system group — no human ever logs in
/// *as* it, it only exists for the `Match` block to key on.
fn groupadd_argv() -> Vec<String> {
    vec!["--system".into(), "--".into(), SFTP_GROUP.into()]
}

/// `usermod --append --groups ferrum-sftp -- <user>`. `--append` is what makes
/// this a grant rather than a replacement of the tenant's supplementary groups.
fn usermod_group_argv(user: &LinuxUser) -> Vec<String> {
    vec![
        "--append".into(),
        "--groups".into(),
        SFTP_GROUP.into(),
        "--".into(),
        user.as_str().into(),
    ]
}

/// `gpasswd --delete <user> -- ferrum-sftp` — the inverse of the grant.
fn gpasswd_remove_argv(user: &LinuxUser) -> Vec<String> {
    vec![
        "--delete".into(),
        user.as_str().into(),
        "--".into(),
        SFTP_GROUP.into(),
    ]
}

async fn is_group_member(user: &LinuxUser) -> bool {
    // `id -nG` prints supplementary group *names*; a missing account is a
    // non-zero exit, which correctly reads as "not a member".
    Cmd::new("id")
        .args(["-nG", "--"])
        .arg(user.as_str())
        .run()
        .await
        .map(|out| out.success() && out.stdout.split_whitespace().any(|g| g == SFTP_GROUP))
        .unwrap_or(false)
}

async fn user_exists(user: &LinuxUser) -> bool {
    Cmd::new("id")
        .args(["-u", "--"])
        .arg(user.as_str())
        .run()
        .await
        .map(|o| o.success())
        .unwrap_or(false)
}

async fn group_exists(group: &str) -> bool {
    Cmd::new("getent")
        .args(["group", "--"])
        .arg(group)
        .run()
        .await
        .map(|o| o.success())
        .unwrap_or(false)
}

/// The group `sites/` should carry: nginx's, so static serving keeps working
/// through the group-execute bit — same fallback as provision.rs when nginx is
/// not installed yet. Empty means "use the tenant's own group" (useradd names
/// the primary group after the account on both families).
async fn sites_group(distro: &Distro) -> String {
    let nginx = crate::provision::nginx_user(distro);
    if group_exists(nginx).await {
        nginx.to_string()
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Chroot ownership reconciliation
// ---------------------------------------------------------------------------

/// One ownership fix, computed before any command runs so tests can assert the
/// exact plan against a scratch tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipStep {
    pub path: PathBuf,
    /// `mkdir -p` first — used when `sites/` does not exist yet, so an SFTP
    /// login always has somewhere writable.
    pub create: bool,
    /// `user:group` exactly as chown will receive it.
    pub owner: String,
    pub mode: u32,
}

/// The home itself: surrendered to root, world-execute for the two traversals
/// that matter (module docs).
fn home_step(home: &Path) -> OwnershipStep {
    OwnershipStep {
        path: home.to_path_buf(),
        create: false,
        owner: "root:root".into(),
        mode: 0o755,
    }
}

/// The tenant-owned islands inside the chroot.
///
/// Only a fixed allowlist is ever touched — `sites/`, `.trash` and `.ssh` — and
/// a symlink where a directory should be is refused outright rather than
/// followed: `chown` through a tenant-planted symlink would hand the tenant
/// ownership of whatever it points at. Everything else under the home is left
/// exactly as the tenant made it.
fn subdir_steps(home: &Path, user: &LinuxUser, sites_group: &str) -> Result<Vec<OwnershipStep>> {
    let tenant = user.as_str();
    let sites_owner = if sites_group.is_empty() {
        format!("{tenant}:{tenant}")
    } else {
        format!("{tenant}:{sites_group}")
    };

    // (name, owner, mode, create-if-missing)
    let wanted: [(&str, String, u32, bool); 3] = [
        // 0750 tenant:nginx — provision.rs's contract for the site tree,
        // re-asserted here because it is now the privacy boundary.
        ("sites", sites_owner, 0o750, true),
        // The recycle bin is the tenant's alone; nginx has no business in it.
        (".trash", format!("{tenant}:{tenant}"), 0o700, false),
        // `ssh.keys.*` writes `~/.ssh/authorized_keys` **as the tenant**, on
        // purpose: root writing into a tenant home is how a symlink turns a key
        // manager into an `/etc/shadow` editor (see terminal::keys). Once the
        // home is root-owned the tenant can no longer create `.ssh` itself, so
        // without this the two features are mutually exclusive and
        // `ssh.keys.add` fails with a bare EACCES. Created for the same reason
        // `sites/` is: a chroot needs its tenant-writable islands to exist.
        // 0700 is what sshd insists on before it will read the file at all.
        (".ssh", format!("{tenant}:{tenant}"), 0o700, true),
    ];

    let mut steps = Vec::new();
    for (name, owner, mode, create) in wanted {
        let path = home.join(name);
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if create {
                    steps.push(OwnershipStep {
                        path,
                        create: true,
                        owner,
                        mode,
                    });
                }
            }
            Err(e) => {
                return Err(FerrumError::internal(format!(
                    "could not inspect {}: {e}",
                    path.display()
                )));
            }
            Ok(md) if md.file_type().is_symlink() => {
                return Err(FerrumError::new(
                    ErrorCode::InvalidPath,
                    format!(
                        "{} is a symlink; refusing to change ownership through it",
                        path.display()
                    ),
                ));
            }
            Ok(md) if md.is_dir() => {
                steps.push(OwnershipStep {
                    path,
                    create: false,
                    owner,
                    mode,
                });
            }
            Ok(_) => {
                return Err(FerrumError::new(
                    ErrorCode::InvalidPath,
                    format!("{} exists but is not a directory", path.display()),
                ));
            }
        }
    }
    Ok(steps)
}

async fn apply_step(step: &OwnershipStep) -> Result<()> {
    if step.create {
        Cmd::new("mkdir")
            .args(["-p", "--"])
            .arg(&step.path)
            .run_checked()
            .await?;
    }
    // `-h` (no-dereference) belt-and-braces on top of the symlink refusal in
    // the plan phase.
    Cmd::new("chown")
        .arg("-h")
        .arg(&step.owner)
        .arg("--")
        .arg(&step.path)
        .run_checked()
        .await?;
    Cmd::new("chmod")
        .arg(format!("{:04o}", step.mode))
        .arg("--")
        .arg(&step.path)
        .run_checked()
        .await?;
    Ok(())
}

/// Make the tenant's home a valid `ChrootDirectory` (module docs).
///
/// Order is the defence: the home is surrendered to root *first*, which
/// revokes the tenant's ability to rename or replace entries directly under
/// it; only then are the subdirectories inspected and fixed. Planning them
/// before the top was locked would leave a window where a tenant-controlled
/// process swaps `sites/` for a symlink between the check and the chown.
async fn reconcile_chroot_ownership(
    ctx: &OpContext,
    home: &Path,
    user: &LinuxUser,
    sites_group: &str,
) -> Result<()> {
    apply_step(&home_step(home)).await?;
    for step in subdir_steps(home, user, sites_group)? {
        apply_step(&step).await?;
    }
    ctx.log(format!(
        "{} is now a valid chroot: root-owned home, tenant-owned sites/",
        home.display()
    ));
    Ok(())
}

/// The home directory, cross-checked against the canonical layout.
///
/// The row normally contains exactly `/home/<user>` (create_subscription
/// builds it that way), so a mismatch means a corrupted or tampered row — and
/// this path is about to be handed to `chown -R`-adjacent operations as root,
/// which is how panels chown `/`.
fn verified_home(subscription: &Subscription, user: &LinuxUser) -> Result<PathBuf> {
    let expected = Path::new("/home").join(user.as_str());
    let stored = Path::new(&subscription.home_dir);
    if stored != expected {
        return Err(FerrumError::internal(format!(
            "subscription {} has home `{}`, expected `{}` — refusing to touch it",
            subscription.id.get(),
            stored.display(),
            expected.display(),
        )));
    }
    Ok(expected)
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

/// Panel policy first, then sha512-crypt at the glibc default cost.
///
/// The strength rules are shared with panel logins on purpose: an SFTP
/// password guards the same files the panel does, so it does not get to be
/// weaker.
fn sftp_password_hash(password: &str) -> Result<String> {
    use rand::RngCore;
    use sha_crypt::PasswordHasher;

    ferrum_db::password::check_strength(password)?;

    // 12 random bytes encode to exactly 16 crypt-base64 characters — the
    // maximum salt length sha512-crypt defines. A longer salt would be
    // *stored* in full but *truncated to 16* by libcrypt when it recomputes
    // the digest at login, so the strings could never compare equal and no
    // login would ever succeed. (The crate truncates the same way when
    // hashing, which is exactly why the bug would be invisible to a
    // round-trip test.)
    let mut salt = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);

    // ShaCrypt::default() is sha512-crypt at 5000 rounds, the same cost glibc
    // and libxcrypt default to; the crate's output matches the reference
    // vectors from the SHA-crypt specification, i.e. what crypt(3) produces.
    sha_crypt::ShaCrypt::default()
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map(|hash| hash.as_str().to_string())
        .map_err(|e| FerrumError::internal(format!("sha512-crypt failed: {e}")))
}

/// `usermod --password <hash> -- <user>`.
fn usermod_password_argv(user: &LinuxUser, hash: &str) -> Vec<String> {
    vec![
        "--password".into(),
        hash.into(),
        "--".into(),
        user.as_str().into(),
    ]
}

async fn set_sftp_password(user: &LinuxUser, password: &str) -> Result<()> {
    let hash = sftp_password_hash(password)?;
    Cmd::new("usermod")
        .args(usermod_password_argv(user, &hash))
        .run_checked()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_config::TemplateSet;

    fn user() -> LinuxUser {
        LinuxUser::parse("ft_abc12345").unwrap()
    }

    // -- template ----------------------------------------------------------

    #[test]
    fn the_match_block_renders_exactly_as_specified() {
        let set = TemplateSet::load().unwrap();
        let rendered = set
            .render(
                "ssh/sftp.conf",
                &serde_json::json!({ "sftp_group": SFTP_GROUP }),
            )
            .unwrap();
        assert_eq!(
            rendered,
            "Match Group ferrum-sftp\n\
             \x20   ChrootDirectory %h\n\
             \x20   ForceCommand internal-sftp\n\
             \x20   AllowTcpForwarding no\n\
             \x20   X11Forwarding no\n"
        );
    }

    #[test]
    fn the_dropin_never_redeclares_the_sftp_subsystem() {
        // Both families ship `Subsystem sftp …` in the stock sshd_config, and a
        // second declaration is fatal — because drop-ins are included first, it
        // would be the *distribution's* line that errors and sshd would not
        // start. ForceCommand internal-sftp makes a declaration unnecessary.
        let set = TemplateSet::load().unwrap();
        let rendered = set
            .render(
                "ssh/sftp.conf",
                &serde_json::json!({ "sftp_group": SFTP_GROUP }),
            )
            .unwrap();
        assert!(
            !rendered.to_ascii_lowercase().contains("subsystem"),
            "the drop-in must not redeclare the sftp subsystem:\n{rendered}"
        );
    }

    #[test]
    fn nothing_follows_the_match_block() {
        // A Match context runs to end of file; on older sshds it could leak
        // past the Include boundary. Keeping the block last (and alone) means
        // there is nothing of ours for it to swallow.
        let set = TemplateSet::load().unwrap();
        let rendered = set
            .render(
                "ssh/sftp.conf",
                &serde_json::json!({ "sftp_group": SFTP_GROUP }),
            )
            .unwrap();
        let match_line = rendered
            .lines()
            .position(|l| l.starts_with("Match "))
            .expect("a Match line");
        for line in rendered.lines().skip(match_line + 1) {
            assert!(
                line.starts_with("    "),
                "`{line}` after the Match block would apply to matched \
                 connections only — or leak"
            );
        }
    }

    // -- argv snapshots ----------------------------------------------------

    #[test]
    fn group_management_argv_is_exactly_what_the_tools_expect() {
        assert_eq!(groupadd_argv(), vec!["--system", "--", "ferrum-sftp"]);
        assert_eq!(
            usermod_group_argv(&user()),
            vec!["--append", "--groups", "ferrum-sftp", "--", "ft_abc12345"],
            "--append is what makes this a grant, not a replacement of the \
             tenant's supplementary groups"
        );
        assert_eq!(
            gpasswd_remove_argv(&user()),
            vec!["--delete", "ft_abc12345", "--", "ferrum-sftp"]
        );
    }

    #[test]
    fn the_password_argv_carries_a_hash_never_the_cleartext() {
        let argv = usermod_password_argv(&user(), "$6$salt$hash");
        assert_eq!(
            argv,
            vec!["--password", "$6$salt$hash", "--", "ft_abc12345"]
        );
        assert!(
            argv.iter().all(|a| a != "correct horse battery staple"),
            "cleartext must never appear in argv"
        );
    }

    // -- passwords ---------------------------------------------------------

    #[test]
    fn the_hash_is_sha512_crypt_that_crypt3_can_verify() {
        use sha_crypt::{PasswordVerifier, ShaCrypt};

        let hash = sftp_password_hash("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$6$"), "not sha512-crypt: {hash}");

        let parsed: sha_crypt::PasswordHash = hash.parse().unwrap();
        ShaCrypt::default()
            .verify_password(b"correct horse battery staple", &parsed)
            .expect("the hash must verify against its own password");
        assert!(
            ShaCrypt::default()
                .verify_password(b"wrong password entirely", &parsed)
                .is_err(),
            "a wrong password must not verify"
        );
    }

    #[test]
    fn the_salt_never_exceeds_what_libcrypt_will_read_back() {
        // sha512-crypt reads at most 16 salt characters at login but we store
        // the string in full — a longer salt would brick every login while
        // still passing a round-trip test (the crate truncates the same way).
        let hash = sftp_password_hash("correct horse battery staple").unwrap();
        // "$6$rounds=5000$<salt>$<digest>" — the salt is the second-to-last
        // field regardless of whether a rounds field is present.
        let fields: Vec<&str> = hash.split('$').collect();
        let salt = fields[fields.len() - 2];
        assert!(
            salt.len() <= 16,
            "salt `{salt}` is {} chars; libcrypt reads at most 16",
            salt.len()
        );
    }

    #[test]
    fn every_hash_is_freshly_salted() {
        let a = sftp_password_hash("correct horse battery staple").unwrap();
        let b = sftp_password_hash("correct horse battery staple").unwrap();
        assert_ne!(a, b, "equal hashes mean a fixed salt");
    }

    #[test]
    fn weak_sftp_passwords_are_rejected_by_the_panel_policy() {
        // The SFTP password guards the same files the panel password does; it
        // does not get to be weaker.
        let err = sftp_password_hash("short").unwrap_err();
        assert_eq!(err.code, ErrorCode::PasswordTooWeak);
    }

    #[test]
    fn the_cleartext_never_appears_in_debug_output() {
        let input = EnableInput {
            subscription_id: 7,
            password: Some("correct horse battery staple".into()),
        };
        let debug = format!("{input:?}");
        assert!(!debug.contains("correct horse"), "leaked: {debug}");
        assert!(debug.contains("<redacted>"));
    }

    // -- chroot ownership reconciliation -----------------------------------

    #[test]
    fn the_home_is_surrendered_to_root_with_world_traverse() {
        let step = home_step(Path::new("/home/ft_abc12345"));
        assert_eq!(step.owner, "root:root", "sshd refuses a non-root chroot");
        assert_eq!(
            step.mode, 0o755,
            "world-execute is what keeps nginx and the tenant's own FPM pool \
             able to traverse into sites/"
        );
        assert!(!step.create);
    }

    #[test]
    fn tenant_keeps_ownership_of_sites_trash_and_ssh_inside_the_chroot() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sites")).unwrap();
        std::fs::create_dir(dir.path().join(".trash")).unwrap();
        std::fs::create_dir(dir.path().join(".ssh")).unwrap();

        let steps = subdir_steps(dir.path(), &user(), "nginx").unwrap();
        assert_eq!(steps.len(), 3);

        let sites = &steps[0];
        assert_eq!(sites.path, dir.path().join("sites"));
        assert_eq!(
            sites.owner, "ft_abc12345:nginx",
            "sites keeps provision.rs's tenant:nginx contract — it is now the \
             privacy boundary"
        );
        assert_eq!(sites.mode, 0o750);

        let trash = &steps[1];
        assert_eq!(trash.path, dir.path().join(".trash"));
        assert_eq!(trash.owner, "ft_abc12345:ft_abc12345");
        assert_eq!(trash.mode, 0o700, "nginx has no business in the trash");

        let ssh = &steps[2];
        assert_eq!(ssh.path, dir.path().join(".ssh"));
        assert_eq!(ssh.owner, "ft_abc12345:ft_abc12345");
        assert_eq!(
            ssh.mode, 0o700,
            "sshd reads authorized_keys only out of a 0700 directory"
        );
    }

    #[test]
    fn a_missing_sites_directory_is_created_so_the_login_has_somewhere_writable() {
        // The chroot root is root-owned, so without a tenant-owned sites/ an
        // SFTP session could look but never upload.
        let dir = tempfile::tempdir().unwrap();
        let steps = subdir_steps(dir.path(), &user(), "").unwrap();
        assert_eq!(
            steps.len(),
            2,
            "sites/ and .ssh are created; no .trash step when .trash is absent"
        );
        assert!(steps.iter().all(|s| s.create));
        assert_eq!(steps[0].path, dir.path().join("sites"));
        assert_eq!(
            steps[1].path,
            dir.path().join(".ssh"),
            "ssh.keys.* writes as the tenant, so the tenant must own somewhere              to write it"
        );
        assert_eq!(
            steps[0].owner, "ft_abc12345:ft_abc12345",
            "without an nginx group the tenant's own group is the fallback, \
             exactly like provision.rs"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_subdirectory_is_refused_not_chowned() {
        // The attack: a tenant-controlled process plants
        // `/home/<user>/sites -> /etc`, and a chown that follows it hands the
        // tenant ownership of the target. The plan phase refuses; `chown -h`
        // in the executor is the second layer.
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc", dir.path().join("sites")).unwrap();

        let err = subdir_steps(dir.path(), &user(), "nginx").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidPath);
        assert!(err.detail.contains("symlink"), "{}", err.detail);
    }

    #[test]
    fn a_plain_file_where_a_directory_should_be_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".trash"), b"not a dir").unwrap();
        let err = subdir_steps(dir.path(), &user(), "").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidPath);
    }

    #[test]
    fn unknown_entries_under_the_home_are_left_exactly_alone() {
        // Reconciliation touches a fixed allowlist, never "everything under
        // the home" — a tenant's own directories are not ours to re-own.
        //
        // `.ssh` used to be one of the examples here. It is on the allowlist
        // now, deliberately: the panel already manages the *contents* of
        // `~/.ssh/authorized_keys` through `ssh.keys.*`, and that operation
        // writes as the tenant, so inside a root-owned chroot the directory has
        // to be tenant-owned or the write cannot happen at all. A dotfile the
        // panel does not manage, like `.bashrc`, is still none of its business.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sites")).unwrap();
        std::fs::create_dir(dir.path().join("my-backups")).unwrap();
        std::fs::create_dir(dir.path().join(".config")).unwrap();
        std::fs::write(dir.path().join(".bashrc"), b"export PS1=x").unwrap();

        let steps = subdir_steps(dir.path(), &user(), "nginx").unwrap();
        let touched: Vec<_> = steps.iter().map(|s| s.path.clone()).collect();
        assert!(!touched.contains(&dir.path().join("my-backups")));
        assert!(!touched.contains(&dir.path().join(".config")));
        assert!(!touched.contains(&dir.path().join(".bashrc")));
    }

    #[test]
    fn a_corrupted_home_row_is_refused_before_any_chown() {
        // The stored home is about to be chowned as root; anything but the
        // canonical `/home/<user>` means a corrupted or tampered row.
        let good = Subscription {
            id: SubscriptionId(1),
            customer_id: ferrum_core::UserId(1),
            plan_id: None,
            linux_user: "ft_abc12345".into(),
            home_dir: "/home/ft_abc12345".into(),
            status: ferrum_db::SubscriptionStatus::Active,
            suspended_reason: None,
            suspended_at: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        assert_eq!(
            verified_home(&good, &user()).unwrap(),
            PathBuf::from("/home/ft_abc12345")
        );

        for evil in [
            "/",
            "/home",
            "/etc",
            "/home/ft_abc12345/../..",
            "/home/other",
        ] {
            let bad = Subscription {
                home_dir: evil.into(),
                ..good.clone()
            };
            assert!(
                verified_home(&bad, &user()).is_err(),
                "`{evil}` must be refused"
            );
        }
    }

    // -- reloader ----------------------------------------------------------

    #[tokio::test]
    async fn the_reloader_reloads_the_right_unit_per_family() {
        use ferrum_distro::Family;
        use ferrum_distro::mock::mock_distro_with_recorder;

        for (family, unit) in [
            (Family::Debian, "ssh.service"),
            (Family::Rhel, "sshd.service"),
        ] {
            let (distro, recorder) = mock_distro_with_recorder(family);
            distro
                .svc
                .action(
                    &ferrum_distro::svc::UnitName::parse(unit).unwrap(),
                    SvcAction::Start,
                )
                .await
                .unwrap();

            SshdReloader {
                distro: distro.clone(),
            }
            .reload()
            .await
            .unwrap();

            let actions = &recorder.lock().unwrap().service_actions;
            assert!(
                actions
                    .iter()
                    .any(|(u, a)| u == unit && *a == SvcAction::Reload),
                "{family:?}: expected a reload of {unit}, got {actions:?}"
            );
            assert!(
                !actions.iter().any(|(_, a)| *a == SvcAction::Restart),
                "a restart would drop every tenant's live SFTP session"
            );
        }
    }

    #[tokio::test]
    async fn a_stopped_sshd_is_not_a_reload_failure() {
        // Writing the drop-in on a machine whose sshd is stopped is legitimate;
        // the config is picked up on the next start.
        let distro = Distro::mock();
        assert!(SshdReloader { distro }.reload().await.is_ok());
    }

    // -- the ops through the registry --------------------------------------

    #[tokio::test]
    async fn enabling_sftp_for_a_missing_subscription_is_not_found() {
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let (reg, admin, _) = registry().await;
        let err = reg
            .dispatch(
                "sftp.enable",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "subscription_id": 999 }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn a_customer_without_ssh_access_cannot_reach_either_op() {
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let (reg, _, customer) = registry().await;
        for op in ["sftp.enable", "sftp.disable"] {
            let err = reg
                .dispatch(
                    op,
                    &auth_for(customer, Role::Customer),
                    serde_json::json!({ "subscription_id": 1 }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::PermissionDenied,
                "{op} must require Permission::SshAccess, which the customer \
                 role does not carry by default"
            );
        }
    }

    #[tokio::test]
    async fn a_planned_subscription_is_refused_until_the_plans_module_is_wired() {
        // Fail-closed on purpose: silently allowing it through would grant
        // SFTP that the plan may never have included. The integrator replaces
        // ensure_plan_allows_sftp's stub with a PlanFeatures::can_ssh lookup.
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let (reg, admin, customer) = registry().await;
        let sub = reg
            .services()
            .db
            .default_subscription_for(customer)
            .await
            .unwrap();
        sqlx::query("UPDATE subscriptions SET plan_id = 42 WHERE id = ?1")
            .bind(sub.id.get())
            .execute(reg.services().db.pool())
            .await
            .unwrap();

        let err = reg
            .dispatch(
                "sftp.enable",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "subscription_id": sub.id.get() }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PlanFeatureDisabled);
    }

    #[tokio::test]
    async fn enabling_before_the_account_is_provisioned_is_a_clean_conflict() {
        // The subscription row exists but no Linux account does (provisioning
        // happens on first site create). The op must refuse before touching
        // the system rather than half-configuring a ghost.
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let (reg, admin, customer) = registry().await;
        let sub = reg
            .services()
            .db
            .default_subscription_for(customer)
            .await
            .unwrap();

        let err = reg
            .dispatch(
                "sftp.enable",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "subscription_id": sub.id.get() }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("provisioned"), "{}", err.detail);
    }

    #[tokio::test]
    async fn disable_is_a_noop_for_a_non_member_and_leaves_files_untouched() {
        // "Disable removes membership but leaves files": the account here does
        // not even exist on the test machine, so membership reads as false and
        // the op must succeed without running a single mutating command — and
        // without going anywhere near the filesystem.
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::Role;

        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("sites")).unwrap();
        std::fs::write(home.path().join("sites/keep.txt"), b"tenant data").unwrap();
        let before = std::fs::metadata(home.path().join("sites/keep.txt")).unwrap();

        let (reg, admin, customer) = registry().await;
        let sub = reg
            .services()
            .db
            .default_subscription_for(customer)
            .await
            .unwrap();

        let out = reg
            .dispatch(
                "sftp.disable",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "subscription_id": sub.id.get() }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["removed"], serde_json::json!(false));

        let after = std::fs::metadata(home.path().join("sites/keep.txt")).unwrap();
        assert_eq!(
            std::fs::read(home.path().join("sites/keep.txt")).unwrap(),
            b"tenant data"
        );
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    }

    #[tokio::test]
    async fn a_permission_override_cannot_grant_ssh_access_to_a_customer() {
        // `effective_permissions` intersects overrides with the role's
        // defaults — an override only ever takes away (spec §6.1). Until the
        // plans module wires `can_ssh` into the auth context, no customer can
        // hold ssh_access at all, even with a hand-edited override row and a
        // forged frame claiming it.
        use crate::registry::testing::{auth_for, registry};
        use ferrum_core::{Role, TenantScope};

        let (reg, _, customer) = registry().await;
        reg.services()
            .db
            .users(&TenantScope::Global)
            .set_permissions(
                customer,
                Some(&[Permission::SshAccess, Permission::SiteRead]),
            )
            .await
            .unwrap();
        let mut forged = auth_for(customer, Role::Customer);
        forged.permissions.insert(Permission::SshAccess);

        let err = reg
            .dispatch(
                "sftp.disable",
                &forged,
                serde_json::json!({ "subscription_id": 1 }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn a_tenant_cannot_toggle_sftp_on_someone_elses_subscription() {
        // The world after plans wire in: a customer legitimately holding
        // SshAccess. The tenant scope on the subscription lookup is what
        // fences them — another customer's subscription reads as not-found.
        // Exercised at the op level because the registry (correctly) refuses
        // to hand a customer this permission today; see the test above.
        use crate::registry::testing::registry;
        use ferrum_core::{AuthContext, Role, TenantScope};
        use ferrum_db::users::NewUser;
        use std::sync::Arc;

        let (reg, _, customer_a) = registry().await;
        let db = &reg.services().db;

        let other = db
            .users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Customer,
                email: ferrum_core::Email::parse("other@example.com").unwrap(),
                username: ferrum_core::Username::parse("other").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let foreign_sub = db.default_subscription_for(other.id).await.unwrap();

        let mut auth = AuthContext::from_role(
            customer_a,
            Role::Customer,
            TenantScope::Customer {
                customer_id: customer_a,
            },
            "req-test",
        );
        auth.permissions.insert(Permission::SshAccess);

        let ctx = crate::registry::OpContext::new(Arc::clone(reg.services()), auth);
        let err = Disable
            .run(
                &ctx,
                DisableInput {
                    subscription_id: foreign_sub.id.get(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound, "{}", err.detail);
    }
}
