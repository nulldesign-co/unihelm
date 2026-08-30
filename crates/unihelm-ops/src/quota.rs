//! Per-tenant disk quotas (spec §6.2, §6.3).
//!
//! The spec's ladder is: **XFS project quotas preferred; ext4 user quotas
//! fallback; a `du`-style scan as the last resort** — and the installer (or
//! `GET /api/server/quota-backend`) reports honestly which rung this server
//! landed on, because a tenant limit that is merely *displayed* is decoration,
//! not isolation (spec §2: "multi-tenant honesty").
//!
//! Detection is two independent facts, and both are required:
//!
//! 1. the filesystem `/home` sits on, read from the `statfs(2)` magic number —
//!    the kernel's answer, not a guess from a config file;
//! 2. whether that mount was *mounted with quota accounting on*, read from the
//!    options column of `/proc/self/mounts`. An XFS filesystem without
//!    `prjquota` in its mount options will accept every `xfs_quota` command
//!    and enforce none of them, which is the worst possible outcome: a panel
//!    that believes limits exist while tenants fill the disk. Hence a
//!    filesystem that *could* do quotas but was not mounted for them drops to
//!    the du fallback, and the API says so.
//!
//! Everything that runs is an argv array (spec §12 rule 2). `xfs_quota -c`
//! takes a sub-command string, but that string is split by `xfs_quota` itself
//! on whitespace — no shell is involved — and every value interpolated into it
//! is either a number we generated or a path built from a validated
//! [`LinuxUser`], with a belt-and-braces whitespace refusal in the builder.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_config::paths;
use unihelm_core::{ErrorCode, LinuxUser, Permission, Result, SubscriptionId, UnihelmError};

use crate::registry::{Execution, OpContext, TypedOperation};

// ---------------------------------------------------------------------------
// Detection: what filesystem is /home, and was it mounted for quotas?
// ---------------------------------------------------------------------------

/// The filesystem `/home` lives on, per the `statfs(2)` magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FsKind {
    Xfs,
    /// The shared ext2/3/4 magic. `setquota` handles all three identically,
    /// so the distinction does not matter here.
    Ext4,
    Other,
}

impl FsKind {
    /// `f_type` values from `statfs(2)`. These are ABI constants, stable since
    /// the filesystems were merged; see `man 2 statfs`.
    pub fn from_magic(magic: u64) -> Self {
        const XFS_SUPER_MAGIC: u64 = 0x5846_5342; // "XFSB"
        const EXT_SUPER_MAGIC: u64 = 0xEF53; // ext2/ext3/ext4 share it
        match magic {
            XFS_SUPER_MAGIC => FsKind::Xfs,
            EXT_SUPER_MAGIC => FsKind::Ext4,
            _ => FsKind::Other,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            FsKind::Xfs => "xfs",
            FsKind::Ext4 => "ext4",
            FsKind::Other => "other",
        }
    }
}

/// One line of `/proc/self/mounts`, parsed — never shelled out for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub device: String,
    pub mount_point: PathBuf,
    pub fs_type: String,
    pub options: Vec<String>,
}

impl MountEntry {
    fn has_option(&self, name: &str) -> bool {
        // Exact match on the comma-split list: a substring test would let
        // `noprjquota` (or any future negated option) read as `prjquota`.
        self.options.iter().any(|o| o == name)
    }

    /// XFS project quota accounting was requested at mount time.
    pub fn xfs_project_quota_on(&self) -> bool {
        // `prjquota` is the canonical spelling; `pquota` the accepted alias.
        self.has_option("prjquota") || self.has_option("pquota")
    }

    /// User quota accounting was requested at mount time (ext4 family).
    pub fn user_quota_on(&self) -> bool {
        self.has_option("usrquota")
            || self.has_option("quota")
            // Journaled quota names its file instead: usrjquota=aquota.user.
            || self.options.iter().any(|o| o.starts_with("usrjquota="))
    }
}

/// Parse the text of `/proc/self/mounts` (`fstab(5)` format).
///
/// The mount point field octal-escapes whitespace (`\040` for a space), so a
/// hostile or merely unusual mount point cannot desynchronise the columns.
pub fn parse_mounts(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_ascii_whitespace();
            let device = f.next()?;
            let mount_point = f.next()?;
            let fs_type = f.next()?;
            let options = f.next()?;
            Some(MountEntry {
                device: decode_mount_field(device),
                mount_point: PathBuf::from(decode_mount_field(mount_point)),
                fs_type: fs_type.to_string(),
                options: options.split(',').map(str::to_string).collect(),
            })
        })
        .collect()
}

/// Undo the `\040`-style octal escapes the kernel writes into mount fields.
fn decode_mount_field(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = &field[i + 1..i + 4];
            if let Ok(v) = u8::from_str_radix(oct, 8) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The mount that actually contains `path`: the entry whose mount point is the
/// longest path-component prefix. `/` matches everything, `/home` beats it for
/// `/home/uh_x`, and `/homework` never matches `/home` (component comparison,
/// not string prefix).
pub fn mount_for<'a>(entries: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    entries
        .iter()
        .filter(|e| path.starts_with(&e.mount_point))
        .max_by_key(|e| e.mount_point.components().count())
}

/// Which enforcement level this server gets (spec §6.3 filesystem row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    XfsProject,
    Ext4User,
    DuFallback,
}

impl BackendKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            BackendKind::XfsProject => "xfs_project",
            BackendKind::Ext4User => "ext4_user",
            BackendKind::DuFallback => "du_fallback",
        }
    }

    /// Does the kernel refuse writes at the limit, or do we merely measure?
    pub const fn enforced(self) -> bool {
        !matches!(self, BackendKind::DuFallback)
    }
}

/// Pick the rung of the ladder. Both facts must agree: the right filesystem
/// *and* the matching quota mount option, otherwise commands would succeed
/// while enforcing nothing (see module docs).
pub fn choose_backend(fs: FsKind, entry: Option<&MountEntry>) -> BackendKind {
    match (fs, entry) {
        (FsKind::Xfs, Some(e)) if e.xfs_project_quota_on() => BackendKind::XfsProject,
        (FsKind::Ext4, Some(e)) if e.user_quota_on() => BackendKind::Ext4User,
        _ => BackendKind::DuFallback,
    }
}

/// Everything detection concluded, kept together so the op that reports it and
/// the ops that act on it cannot disagree.
#[derive(Debug, Clone)]
pub struct Detection {
    pub backend: BackendKind,
    pub fs: FsKind,
    pub mount: Option<MountEntry>,
}

/// Ask the running kernel. Never available to tests — see [`current_detection`].
pub fn detect_live() -> Detection {
    let home = paths::home_root();
    let text = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let entries = parse_mounts(&text);
    let mount = mount_for(&entries, &home).cloned();
    Detection {
        backend: choose_backend(fs_kind_of(&home), mount.as_ref()),
        fs: fs_kind_of(&home),
        mount,
    }
}

/// The detection the quota ops act on.
///
/// Under `cfg(test)` this is pinned to the du fallback: a test suite whose
/// outcome depends on what filesystem the build machine's `/home` uses — and
/// which would then shell out to a real `xfs_quota` as root — is not a test
/// suite. The XFS and ext4 paths are covered directly with a recording runner.
fn current_detection() -> Detection {
    #[cfg(test)]
    {
        Detection {
            backend: BackendKind::DuFallback,
            fs: FsKind::Other,
            mount: None,
        }
    }
    #[cfg(not(test))]
    {
        detect_live()
    }
}

/// `statfs(2)` on Linux; everything else is [`FsKind::Other`], which lands on
/// the du fallback — correct for the macOS dev instance.
#[cfg(target_os = "linux")]
fn fs_kind_of(path: &Path) -> FsKind {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return FsKind::Other;
    };
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated C string and `buf` is a properly
    // sized, writable statfs struct; statfs writes only into it.
    if unsafe { libc::statfs(c.as_ptr(), &mut buf) } != 0 {
        return FsKind::Other;
    }
    // `f_type`'s width and signedness vary by arch/libc; the magics fit u64.
    #[allow(clippy::unnecessary_cast)]
    FsKind::from_magic(buf.f_type as u64)
}

#[cfg(not(target_os = "linux"))]
fn fs_kind_of(_path: &Path) -> FsKind {
    FsKind::Other
}

// ---------------------------------------------------------------------------
// Argv builders — pure, so the exact command lines are snapshot-testable.
// ---------------------------------------------------------------------------

/// Refuse any path that would split inside an `xfs_quota -c` sub-command.
///
/// `xfs_quota` tokenises the `-c` string on whitespace itself (no shell), so a
/// path containing whitespace would become two arguments. Every path we build
/// comes from a validated [`LinuxUser`] under `/home`, so this can only fire
/// on a corrupted database row — but "cannot happen" plus a check is cheaper
/// than "cannot happen" alone (spec §12 rule 3).
fn reject_whitespace(path: &Path) -> Result<&str> {
    let s = path.to_str().ok_or_else(|| {
        UnihelmError::new(ErrorCode::InvalidPath, "quota path is not valid UTF-8")
    })?;
    if s.chars().any(|c| c.is_whitespace()) || s.is_empty() {
        return Err(UnihelmError::new(
            ErrorCode::InvalidPath,
            format!("`{s}` cannot be used in a quota command"),
        ));
    }
    Ok(s)
}

/// `xfs_quota -x -c 'project -s -p <home> <id>' <mount>` — tag the tree.
///
/// `-s` sets the project id and the inherit bit recursively, so files a tenant
/// creates later inherit the id and stay counted. The mapping is given inline
/// with `-p`; we deliberately do not maintain `/etc/projects`, because the
/// database's `quota_projects` table is the single source of truth and a
/// second on-disk copy would drift.
pub fn xfs_project_setup_argv(
    project_id: i64,
    home: &Path,
    mount: &Path,
) -> Result<(String, Vec<String>)> {
    let home = reject_whitespace(home)?;
    let mount = reject_whitespace(mount)?;
    Ok((
        "xfs_quota".into(),
        vec![
            "-x".into(),
            "-c".into(),
            format!("project -s -p {home} {project_id}"),
            mount.into(),
        ],
    ))
}

/// `xfs_quota -x -c 'limit -p bsoft=<soft>m bhard=<hard>m <id>' <mount>`.
pub fn xfs_limit_argv(
    project_id: i64,
    soft_mb: u64,
    hard_mb: u64,
    mount: &Path,
) -> Result<(String, Vec<String>)> {
    let mount = reject_whitespace(mount)?;
    Ok((
        "xfs_quota".into(),
        vec![
            "-x".into(),
            "-c".into(),
            format!("limit -p bsoft={soft_mb}m bhard={hard_mb}m {project_id}"),
            mount.into(),
        ],
    ))
}

/// `xfs_quota -x -c 'quota -p -N -b <id>' <mount>` — one machine-readable
/// line: `-N` drops the header, `-b` asks for blocks (KiB).
pub fn xfs_usage_argv(project_id: i64, mount: &Path) -> Result<(String, Vec<String>)> {
    let mount = reject_whitespace(mount)?;
    Ok((
        "xfs_quota".into(),
        vec![
            "-x".into(),
            "-c".into(),
            format!("quota -p -N -b {project_id}"),
            mount.into(),
        ],
    ))
}

/// `setquota -u <user> <bsoft> <bhard> 0 0 <mount>` — block limits in KiB,
/// inode limits left at 0 (unlimited; `inode_count` on plans is a later
/// enforcement, spec §6.2).
pub fn setquota_argv(
    user: &LinuxUser,
    soft_mb: u64,
    hard_mb: u64,
    mount: &Path,
) -> Result<(String, Vec<String>)> {
    let mount = reject_whitespace(mount)?;
    Ok((
        "setquota".into(),
        vec![
            "-u".into(),
            user.as_str().into(),
            (soft_mb * 1024).to_string(),
            (hard_mb * 1024).to_string(),
            "0".into(),
            "0".into(),
            mount.into(),
        ],
    ))
}

/// `quota -w -u <user>` — `-w` folds each filesystem onto one line so the
/// output parses the same whether or not the device name is long.
pub fn user_quota_usage_argv(user: &LinuxUser) -> (String, Vec<String>) {
    (
        "quota".into(),
        vec!["-w".into(), "-u".into(), user.as_str().into()],
    )
}

// ---------------------------------------------------------------------------
// Output parsers — pure, tested against captured output shapes.
// ---------------------------------------------------------------------------

/// Used/soft/hard in KiB from a quota report line.
///
/// Both `xfs_quota quota -N -b` and `quota -w` print
/// `<device> <blocks> <soft> <hard> ...` — the columns after differ (warn/grace
/// vs files) but the first four are common, which is all we read. A value can
/// carry a `*` or `+` marker when the soft limit is exceeded; that is display
/// decoration, not data.
fn parse_quota_columns(line: &str) -> Option<(u64, u64, u64)> {
    let fields: Vec<&str> = line.split_ascii_whitespace().collect();
    if fields.len() < 4 || !fields[0].starts_with('/') {
        return None;
    }
    let num = |s: &str| s.trim_end_matches(['*', '+']).parse::<u64>().ok();
    Some((num(fields[1])?, num(fields[2])?, num(fields[3])?))
}

/// The first parseable report line, optionally pinned to one device.
///
/// A user can hold quotas on several filesystems; pinning to the device that
/// backs `/home` keeps another mount's numbers from being reported as the
/// tenant's. `None` when the output holds no quota line at all — a tenant
/// that never had a limit set.
pub fn parse_quota_report(stdout: &str, device: Option<&str>) -> Option<(u64, u64, u64)> {
    stdout
        .lines()
        .filter(|l| match device {
            Some(dev) => l.split_ascii_whitespace().next() == Some(dev),
            None => true,
        })
        .find_map(parse_quota_columns)
}

/// KiB of usage → whole MiB, rounding up so a tenant one byte over never
/// displays as exactly at the limit.
fn kib_to_mb_ceil(kib: u64) -> u64 {
    kib.div_ceil(1024)
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// What a backend measures or enforces against: one subscription's identity
/// on disk. `project_id` is present only when the XFS backend is in play.
#[derive(Debug, Clone)]
pub struct QuotaTarget {
    pub linux_user: LinuxUser,
    pub home_dir: PathBuf,
    pub project_id: Option<i64>,
}

/// A measurement, in the units the API speaks (MB).
///
/// `limit_mb` is the limit *the kernel reports it is enforcing* — `None` from
/// the du fallback, which enforces nothing. The op layer overlays the stored
/// plan limit for display; keeping the two apart is what lets the UI say
/// "limit 500 MB (not enforced on this server)" truthfully.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct QuotaUsage {
    pub used_mb: u64,
    pub limit_mb: Option<u64>,
}

/// One rung of the enforcement ladder (spec §6.3).
#[async_trait]
pub trait QuotaBackend: Send + Sync {
    fn kind(&self) -> BackendKind;
    /// Apply soft/hard limits (MB) for the target.
    async fn set(&self, target: &QuotaTarget, soft_mb: u64, hard_mb: u64) -> Result<()>;
    /// Measure the target's current usage.
    async fn usage(&self, target: &QuotaTarget) -> Result<QuotaUsage>;
}

/// Executes an argv array. One seam, so the backends' exact command lines are
/// assertable in tests without an XFS filesystem or root.
#[async_trait]
pub trait QuotaRunner: Send + Sync {
    async fn run(&self, program: &str, args: &[String]) -> Result<RunOutput>;
}

#[derive(Debug, Clone)]
pub struct RunOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl RunOutput {
    fn checked(self, what: &str) -> Result<Self> {
        if self.status == 0 {
            Ok(self)
        } else {
            let detail = if self.stderr.trim().is_empty() {
                self.stdout.trim().to_string()
            } else {
                self.stderr.trim().to_string()
            };
            Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                format!("{what} failed (exit {}): {detail}", self.status),
            ))
        }
    }
}

/// The real thing: [`unihelm_distro::Cmd`], argv arrays, trusted-dir binary
/// resolution, scrubbed environment.
pub struct SystemRunner;

#[async_trait]
impl QuotaRunner for SystemRunner {
    async fn run(&self, program: &str, args: &[String]) -> Result<RunOutput> {
        // `project -s` walks the whole home tree tagging inodes; on a tenant
        // with very many files that can outlive the default two minutes.
        let out = unihelm_distro::Cmd::new(program)
            .args(args)
            .timeout(std::time::Duration::from_secs(600))
            .run()
            .await
            .map_err(UnihelmError::from)?;
        Ok(RunOutput {
            status: out.status,
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }
}

/// XFS project quotas — the preferred rung: per-directory accounting the
/// kernel enforces, immune to a tenant `chown`ing files around (a uid quota
/// follows the owner; a project follows the tree).
pub struct XfsProjectBackend {
    runner: Arc<dyn QuotaRunner>,
    /// The mount point of the filesystem holding `/home` — `xfs_quota`
    /// addresses filesystems, not directories.
    mount: PathBuf,
}

impl XfsProjectBackend {
    pub fn new(runner: Arc<dyn QuotaRunner>, mount: PathBuf) -> Self {
        Self { runner, mount }
    }

    fn project_id(target: &QuotaTarget) -> Result<i64> {
        target
            .project_id
            .ok_or_else(|| UnihelmError::internal("the XFS backend needs an allocated project id"))
    }
}

#[async_trait]
impl QuotaBackend for XfsProjectBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::XfsProject
    }

    async fn set(&self, target: &QuotaTarget, soft_mb: u64, hard_mb: u64) -> Result<()> {
        let id = Self::project_id(target)?;
        // Setup first, limit second: a limit on an untagged tree limits
        // nothing. Setup is idempotent — re-tagging an already-tagged tree is
        // how a re-applied plan repairs drift.
        let (prog, args) = xfs_project_setup_argv(id, &target.home_dir, &self.mount)?;
        self.runner
            .run(&prog, &args)
            .await?
            .checked("xfs_quota project setup")?;

        let (prog, args) = xfs_limit_argv(id, soft_mb, hard_mb, &self.mount)?;
        self.runner
            .run(&prog, &args)
            .await?
            .checked("xfs_quota limit")?;
        Ok(())
    }

    async fn usage(&self, target: &QuotaTarget) -> Result<QuotaUsage> {
        let id = Self::project_id(target)?;
        let (prog, args) = xfs_usage_argv(id, &self.mount)?;
        let out = self
            .runner
            .run(&prog, &args)
            .await?
            .checked("xfs_quota quota")?;
        // No line for the project means no blocks were ever charged to it.
        let (used_kib, _soft, hard_kib) =
            parse_quota_report(&out.stdout, None).unwrap_or((0, 0, 0));
        Ok(QuotaUsage {
            used_mb: kib_to_mb_ceil(used_kib),
            // 0 is xfs_quota's spelling of "no limit".
            limit_mb: (hard_kib > 0).then(|| kib_to_mb_ceil(hard_kib)),
        })
    }
}

/// ext4 user quotas — the middle rung. Keyed by uid, so a subscription's
/// entire home counts against its Linux account. Weaker than a project quota
/// (files the tenant somehow owns elsewhere also count) but still enforced by
/// the kernel at write time.
pub struct Ext4UserBackend {
    runner: Arc<dyn QuotaRunner>,
    mount: PathBuf,
    /// The device backing the mount, to pin `quota -w` output to the right
    /// filesystem when the user holds quotas on several.
    device: Option<String>,
}

impl Ext4UserBackend {
    pub fn new(runner: Arc<dyn QuotaRunner>, mount: PathBuf, device: Option<String>) -> Self {
        Self {
            runner,
            mount,
            device,
        }
    }
}

#[async_trait]
impl QuotaBackend for Ext4UserBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Ext4User
    }

    async fn set(&self, target: &QuotaTarget, soft_mb: u64, hard_mb: u64) -> Result<()> {
        let (prog, args) = setquota_argv(&target.linux_user, soft_mb, hard_mb, &self.mount)?;
        self.runner.run(&prog, &args).await?.checked("setquota")?;
        Ok(())
    }

    async fn usage(&self, target: &QuotaTarget) -> Result<QuotaUsage> {
        let (prog, args) = user_quota_usage_argv(&target.linux_user);
        // Not `checked`: quota(1) exits non-zero for a user *over* quota, and
        // that is precisely a case we must report, not error on.
        let out = self.runner.run(&prog, &args).await?;
        match parse_quota_report(&out.stdout, self.device.as_deref()) {
            Some((used_kib, _soft, hard_kib)) => Ok(QuotaUsage {
                used_mb: kib_to_mb_ceil(used_kib),
                limit_mb: (hard_kib > 0).then(|| kib_to_mb_ceil(hard_kib)),
            }),
            // No report line: the user has no quota record yet. Zero usage is
            // the honest reading of "the kernel is not accounting this user".
            None => Ok(QuotaUsage {
                used_mb: 0,
                limit_mb: None,
            }),
        }
    }
}

/// The last rung: measure by walking the tree, enforce nothing.
///
/// **Inaccurate by design**, in every direction at once: it reads apparent
/// file sizes (sparse files over-count, filesystem overhead under-counts),
/// counts a hard-linked file once per link, races against a writing tenant,
/// and skips anything it cannot read. It exists so that "no quota support" is
/// still "the panel can tell you roughly what a tenant uses" — the nightly
/// scan the spec asks for (§6.3) reuses this walk. `set` records nothing at
/// the OS level because there is nothing to record; the stored limit is
/// display-only and the API's `enforced: false` says so.
pub struct DuFallback;

/// Apparent size in bytes of every regular file under `dir`, without ever
/// following a symlink: a tenant-writable tree gets to describe itself, not to
/// point the walker at another tenant's home (or `/proc`) and have that
/// counted or even traversed.
pub fn walk_usage_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue; // unreadable directory: skip, by the contract above
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file()
                && let Ok(meta) = entry.metadata()
            {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

#[async_trait]
impl QuotaBackend for DuFallback {
    fn kind(&self) -> BackendKind {
        BackendKind::DuFallback
    }

    async fn set(&self, _target: &QuotaTarget, _soft_mb: u64, _hard_mb: u64) -> Result<()> {
        // Nothing to enforce; the op stores the limit for display and the
        // backend report tells the operator the truth about this server.
        Ok(())
    }

    async fn usage(&self, target: &QuotaTarget) -> Result<QuotaUsage> {
        let dir = target.home_dir.clone();
        // A tenant home can hold millions of entries; keep the walk off the
        // async runtime's threads.
        let bytes = tokio::task::spawn_blocking(move || walk_usage_bytes(&dir))
            .await
            .map_err(|e| UnihelmError::internal(format!("usage walk panicked: {e}")))?;
        Ok(QuotaUsage {
            used_mb: bytes.div_ceil(1024 * 1024),
            limit_mb: None, // nothing is enforced, so no kernel limit exists
        })
    }
}

/// The backend for a detection result, wired to the real system runner.
pub fn backend_for(detection: &Detection) -> Box<dyn QuotaBackend> {
    let runner: Arc<dyn QuotaRunner> = Arc::new(SystemRunner);
    // Both kernel backends address the filesystem by its mount point; if
    // detection somehow chose them without a mount entry, home_root is the
    // only sensible address.
    let mount = detection
        .mount
        .as_ref()
        .map(|m| m.mount_point.clone())
        .unwrap_or_else(paths::home_root);
    match detection.backend {
        BackendKind::XfsProject => Box::new(XfsProjectBackend::new(runner, mount)),
        BackendKind::Ext4User => Box::new(Ext4UserBackend::new(
            runner,
            mount,
            detection.mount.as_ref().map(|m| m.device.clone()),
        )),
        BackendKind::DuFallback => Box::new(DuFallback),
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Largest accepted quota: 16 TB in MB. Not a real ceiling on hardware, a
/// sanity bound that keeps `soft_mb * 1024` far from overflow and catches a
/// bytes-vs-megabytes confusion at the API boundary.
const MAX_QUOTA_MB: u64 = 16 * 1024 * 1024;

/// `quota.set` — apply disk limits to a subscription (spec §6.2).
pub struct Set;

#[derive(Debug, Deserialize)]
pub struct SetInput {
    pub subscription_id: i64,
    pub soft_mb: u64,
    pub hard_mb: u64,
}

#[derive(Debug, Serialize)]
pub struct SetOutput {
    pub subscription_id: i64,
    pub soft_mb: u64,
    pub hard_mb: u64,
    pub backend: &'static str,
    /// `false` means the du fallback: the limit is recorded and displayed but
    /// the kernel will not stop the tenant at it.
    pub enforced: bool,
}

#[async_trait]
impl TypedOperation for Set {
    type Input = SetInput;
    type Output = SetOutput;

    const NAME: &'static str = "quota.set";
    // Limits are plan machinery: admins and resellers hold this, customers do
    // not — a tenant must not be able to raise their own ceiling.
    const PERMISSION: Permission = Permission::PlanManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        if input.hard_mb == 0 {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "hard_mb must be at least 1 (use suspension, not a zero quota, to stop a tenant)",
            )
            .with_field("hard_mb"));
        }
        if input.soft_mb > input.hard_mb {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "soft_mb cannot exceed hard_mb",
            )
            .with_field("soft_mb"));
        }
        if input.hard_mb > MAX_QUOTA_MB {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                format!("hard_mb exceeds the {MAX_QUOTA_MB} MB bound — is the value in bytes?"),
            )
            .with_field("hard_mb"));
        }

        // Scoped lookup: a reseller reaches only its own customers'
        // subscriptions, and learns nothing but "not found" about the rest.
        let sub = ctx
            .db()
            .subscriptions(ctx.scope())
            .by_id(SubscriptionId(input.subscription_id))
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("subscription"))?;

        let detection = current_detection();
        let mut target = QuotaTarget {
            linux_user: LinuxUser::parse(&sub.linux_user)?,
            home_dir: PathBuf::from(&sub.home_dir),
            project_id: None,
        };
        if detection.backend == BackendKind::XfsProject {
            let project = ctx
                .db()
                .quota_project_for(sub.id, &sub.home_dir)
                .await
                .map_err(UnihelmError::from)?;
            target.project_id = Some(project.project_id);
        }

        // Enforce first, record second: the database must never claim a limit
        // the kernel refused (same ordering discipline as cert issuance —
        // files on disk before the row says "active").
        backend_for(&detection)
            .set(&target, input.soft_mb, input.hard_mb)
            .await?;

        ctx.db()
            .set_quota_limits(sub.id, input.soft_mb as i64, input.hard_mb as i64)
            .await
            .map_err(UnihelmError::from)?;

        ctx.log(format!(
            "quota for subscription {} set to {}/{} MB via {}",
            sub.id.get(),
            input.soft_mb,
            input.hard_mb,
            detection.backend.as_str()
        ));

        Ok(SetOutput {
            subscription_id: input.subscription_id,
            soft_mb: input.soft_mb,
            hard_mb: input.hard_mb,
            backend: detection.backend.as_str(),
            enforced: detection.backend.enforced(),
        })
    }
}

/// `quota.usage` — how much of its quota a subscription is using.
pub struct Usage;

#[derive(Debug, Deserialize)]
pub struct UsageInput {
    pub subscription_id: i64,
}

#[derive(Debug, Serialize)]
pub struct UsageOutput {
    pub subscription_id: i64,
    pub used_mb: u64,
    /// The limit the kernel is enforcing right now, if any.
    pub limit_mb: Option<u64>,
    /// The limits stored on the subscription (what the plan promised).
    pub soft_mb: Option<i64>,
    pub hard_mb: Option<i64>,
    pub backend: &'static str,
    pub enforced: bool,
}

#[async_trait]
impl TypedOperation for Usage {
    type Input = UsageInput;
    type Output = UsageOutput;

    const NAME: &'static str = "quota.usage";
    // Owner-readable: every role holds SiteRead, and the scoped subscription
    // lookup below confines a customer to their own numbers.
    const PERMISSION: Permission = Permission::SiteRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let sub = ctx
            .db()
            .subscriptions(ctx.scope())
            .by_id(SubscriptionId(input.subscription_id))
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("subscription"))?;

        let limits = ctx
            .db()
            .quota_limits(sub.id)
            .await
            .map_err(UnihelmError::from)?
            .unwrap_or(unihelm_db::QuotaLimits {
                quota_soft_mb: None,
                quota_hard_mb: None,
            });

        let mut detection = current_detection();
        let mut target = QuotaTarget {
            linux_user: LinuxUser::parse(&sub.linux_user)?,
            home_dir: PathBuf::from(&sub.home_dir),
            project_id: None,
        };
        if detection.backend == BackendKind::XfsProject {
            // Reads must not allocate: an id assigned on a GET would tag
            // nothing and still burn a slot. A subscription that never had
            // `quota.set` run simply has no project — measure it by walking.
            match ctx
                .db()
                .quota_project(sub.id)
                .await
                .map_err(UnihelmError::from)?
            {
                Some(project) => target.project_id = Some(project.project_id),
                None => detection.backend = BackendKind::DuFallback,
            }
        }

        let usage = backend_for(&detection).usage(&target).await?;

        Ok(UsageOutput {
            subscription_id: input.subscription_id,
            used_mb: usage.used_mb,
            limit_mb: usage.limit_mb,
            soft_mb: limits.quota_soft_mb,
            hard_mb: limits.quota_hard_mb,
            backend: detection.backend.as_str(),
            enforced: detection.backend.enforced(),
        })
    }
}

/// `quota.backend` — which rung of the enforcement ladder this server is on.
///
/// The spec's installer "detects & reports which level you got" (§6.3); this
/// is that report at runtime, for `GET /api/server/quota-backend`.
pub struct Backend;

#[derive(Debug, Deserialize)]
pub struct BackendInput {}

#[derive(Debug, Serialize)]
pub struct BackendOutput {
    pub backend: &'static str,
    pub fs: &'static str,
    pub mount_point: Option<String>,
    pub enforced: bool,
}

#[async_trait]
impl TypedOperation for Backend {
    type Input = BackendInput;
    type Output = BackendOutput;

    const NAME: &'static str = "quota.backend";
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, _ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let detection = current_detection();
        Ok(BackendOutput {
            backend: detection.backend.as_str(),
            fs: detection.fs.as_str(),
            mount_point: detection
                .mount
                .map(|m| m.mount_point.to_string_lossy().into_owned()),
            enforced: detection.backend.enforced(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // -- detection ----------------------------------------------------------

    const XFS_PRJQUOTA: &str = "\
/dev/vda1 / ext4 rw,relatime 0 0
/dev/vda2 /home xfs rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0";

    const EXT4_USRQUOTA: &str = "\
/dev/sda1 /home ext4 rw,relatime,usrquota 0 0";

    const EXT4_PLAIN: &str = "\
/dev/sda1 / ext4 rw,relatime 0 0";

    fn home() -> PathBuf {
        PathBuf::from("/home")
    }

    #[test]
    fn xfs_mounted_with_prjquota_selects_the_project_backend() {
        let entries = parse_mounts(XFS_PRJQUOTA);
        let entry = mount_for(&entries, &home());
        assert_eq!(entry.unwrap().fs_type, "xfs");
        assert_eq!(choose_backend(FsKind::Xfs, entry), BackendKind::XfsProject);
    }

    #[test]
    fn ext4_mounted_with_usrquota_selects_the_user_backend() {
        let entries = parse_mounts(EXT4_USRQUOTA);
        let entry = mount_for(&entries, &home());
        assert_eq!(choose_backend(FsKind::Ext4, entry), BackendKind::Ext4User);
    }

    #[test]
    fn ext4_without_quota_mount_options_falls_back_to_du() {
        // The filesystem could do quotas, but it was not mounted for them:
        // setquota would fail (or worse, silently not enforce), so the honest
        // answer is the fallback.
        let entries = parse_mounts(EXT4_PLAIN);
        let entry = mount_for(&entries, &home());
        assert_eq!(choose_backend(FsKind::Ext4, entry), BackendKind::DuFallback);
    }

    #[test]
    fn xfs_without_prjquota_falls_back_to_du_not_to_user_quotas() {
        // An XFS mount without prjquota accepts xfs_quota commands and
        // enforces none of them — the decoration outcome the module docs
        // forbid. It must land on du, and never on the ext4 path.
        let entries = parse_mounts("/dev/vda2 /home xfs rw,relatime,inode64 0 0");
        let entry = mount_for(&entries, &home());
        assert_eq!(choose_backend(FsKind::Xfs, entry), BackendKind::DuFallback);
    }

    #[test]
    fn the_pquota_alias_also_counts_as_project_quota() {
        let entries = parse_mounts("/dev/vda2 /home xfs rw,pquota 0 0");
        assert_eq!(
            choose_backend(FsKind::Xfs, mount_for(&entries, &home())),
            BackendKind::XfsProject
        );
    }

    #[test]
    fn journaled_quota_options_count_as_user_quota() {
        let entries = parse_mounts("/dev/sda1 /home ext4 rw,usrjquota=aquota.user,jqfmt=vfsv1 0 0");
        assert_eq!(
            choose_backend(FsKind::Ext4, mount_for(&entries, &home())),
            BackendKind::Ext4User
        );
    }

    #[test]
    fn a_negated_or_lookalike_option_does_not_enable_a_backend() {
        // Substring matching would read `noprjquota` as `prjquota`; the parser
        // must compare whole options.
        let entries = parse_mounts("/dev/vda2 /home xfs rw,noprjquota 0 0");
        assert_eq!(
            choose_backend(FsKind::Xfs, mount_for(&entries, &home())),
            BackendKind::DuFallback
        );
    }

    #[test]
    fn the_longest_matching_mount_point_wins() {
        // `/` is ext4, `/home` is xfs: a tenant under /home belongs to the
        // /home entry, and string-prefix matching must not let `/homework`
        // shadow it.
        let entries = parse_mounts(XFS_PRJQUOTA);
        let entry = mount_for(&entries, Path::new("/home/uh_abc/sites")).unwrap();
        assert_eq!(entry.mount_point, PathBuf::from("/home"));
        let root = mount_for(&entries, Path::new("/homework")).unwrap();
        assert_eq!(root.mount_point, PathBuf::from("/"));
    }

    #[test]
    fn octal_escaped_mount_points_are_decoded() {
        // The kernel writes a space in a mount point as \040. If we did not
        // decode it, the entry would never match and quotas would silently
        // fall back on such systems.
        let entries = parse_mounts("/dev/sdb1 /mnt/big\\040disk ext4 rw,usrquota 0 0");
        assert_eq!(entries[0].mount_point, PathBuf::from("/mnt/big disk"));
    }

    #[test]
    fn statfs_magics_map_to_the_right_filesystems() {
        assert_eq!(FsKind::from_magic(0x5846_5342), FsKind::Xfs);
        assert_eq!(FsKind::from_magic(0xEF53), FsKind::Ext4);
        assert_eq!(FsKind::from_magic(0x01021994 /* tmpfs */), FsKind::Other);
    }

    // -- argv snapshots -----------------------------------------------------

    fn user() -> LinuxUser {
        LinuxUser::parse("uh_a1b2c3d4").unwrap()
    }

    #[test]
    fn xfs_argv_snapshots() {
        let mount = Path::new("/home");
        let home = Path::new("/home/uh_a1b2c3d4");
        let (prog, args) = xfs_project_setup_argv(101, home, mount).unwrap();
        assert_eq!(prog, "xfs_quota");
        assert_eq!(
            args,
            vec!["-x", "-c", "project -s -p /home/uh_a1b2c3d4 101", "/home"]
        );

        let (prog, args) = xfs_limit_argv(101, 500, 550, mount).unwrap();
        assert_eq!(prog, "xfs_quota");
        assert_eq!(
            args,
            vec!["-x", "-c", "limit -p bsoft=500m bhard=550m 101", "/home"]
        );

        let (prog, args) = xfs_usage_argv(101, mount).unwrap();
        assert_eq!(prog, "xfs_quota");
        assert_eq!(args, vec!["-x", "-c", "quota -p -N -b 101", "/home"]);
    }

    #[test]
    fn setquota_argv_snapshot_converts_mb_to_kib_blocks() {
        let (prog, args) = setquota_argv(&user(), 500, 550, Path::new("/home")).unwrap();
        assert_eq!(prog, "setquota");
        // setquota takes 1 KiB blocks: 500 MB = 512000, 550 MB = 563200.
        // Inode limits stay 0 (unlimited) until plans enforce inode_count.
        assert_eq!(
            args,
            vec!["-u", "uh_a1b2c3d4", "512000", "563200", "0", "0", "/home"]
        );
    }

    #[test]
    fn user_quota_usage_argv_snapshot() {
        let (prog, args) = user_quota_usage_argv(&user());
        assert_eq!(prog, "quota");
        assert_eq!(args, vec!["-w", "-u", "uh_a1b2c3d4"]);
    }

    #[test]
    fn a_path_with_whitespace_is_refused_not_interpolated() {
        // xfs_quota splits its -c string on whitespace itself; a path with a
        // space would become two arguments. LinuxUser validation makes this
        // unreachable, but a corrupted home_dir row must fail closed.
        let err =
            xfs_project_setup_argv(101, Path::new("/home/ft x"), Path::new("/home")).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidPath);
        let err = setquota_argv(&user(), 1, 2, Path::new("/ho me")).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidPath);
    }

    // -- backends over a recording runner -----------------------------------

    /// Records every argv and replays canned outputs, so the exact commands a
    /// backend would run are assertable without root or an XFS filesystem.
    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        outputs: Mutex<Vec<RunOutput>>,
    }

    impl RecordingRunner {
        fn new(outputs: Vec<RunOutput>) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                outputs: Mutex::new(outputs),
            })
        }

        fn ok() -> RunOutput {
            RunOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            }
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl QuotaRunner for RecordingRunner {
        async fn run(&self, program: &str, args: &[String]) -> Result<RunOutput> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            let mut outputs = self.outputs.lock().unwrap();
            Ok(if outputs.is_empty() {
                RecordingRunner::ok()
            } else {
                outputs.remove(0)
            })
        }
    }

    fn target(project: Option<i64>) -> QuotaTarget {
        QuotaTarget {
            linux_user: user(),
            home_dir: PathBuf::from("/home/uh_a1b2c3d4"),
            project_id: project,
        }
    }

    #[tokio::test]
    async fn the_xfs_backend_tags_the_tree_before_limiting_it() {
        let rec = RecordingRunner::new(vec![]);
        let backend = XfsProjectBackend::new(rec.clone(), PathBuf::from("/home"));
        backend.set(&target(Some(101)), 500, 550).await.unwrap();

        let calls = rec.calls();
        assert_eq!(calls.len(), 2);
        // Order matters: a limit on an untagged tree limits nothing.
        assert_eq!(calls[0].1[2], "project -s -p /home/uh_a1b2c3d4 101");
        assert_eq!(calls[1].1[2], "limit -p bsoft=500m bhard=550m 101");
    }

    #[tokio::test]
    async fn the_xfs_backend_refuses_to_run_without_a_project_id() {
        // Running with a made-up id would tag the tenant into some other
        // project's accounting; the allocation table is the only source.
        let rec = RecordingRunner::new(vec![]);
        let backend = XfsProjectBackend::new(rec.clone(), PathBuf::from("/home"));
        assert!(backend.set(&target(None), 1, 2).await.is_err());
        assert!(rec.calls().is_empty(), "no command may run without an id");
    }

    #[tokio::test]
    async fn xfs_usage_parses_the_report_line() {
        let rec = RecordingRunner::new(vec![RunOutput {
            status: 0,
            stdout: "/dev/vda2 1536 512000 563200 00 [--------] /home\n".into(),
            stderr: String::new(),
        }]);
        let backend = XfsProjectBackend::new(rec, PathBuf::from("/home"));
        let usage = backend.usage(&target(Some(101))).await.unwrap();
        // 1536 KiB rounds *up* to 2 MB; 563200 KiB is exactly 550 MB.
        assert_eq!(usage.used_mb, 2);
        assert_eq!(usage.limit_mb, Some(550));
    }

    #[tokio::test]
    async fn xfs_usage_with_no_report_line_is_zero_not_an_error() {
        let rec = RecordingRunner::new(vec![RecordingRunner::ok()]);
        let backend = XfsProjectBackend::new(rec, PathBuf::from("/home"));
        let usage = backend.usage(&target(Some(101))).await.unwrap();
        assert_eq!(usage.used_mb, 0);
        assert_eq!(usage.limit_mb, None);
    }

    #[tokio::test]
    async fn a_failed_xfs_command_surfaces_its_own_diagnostics() {
        let rec = RecordingRunner::new(vec![RunOutput {
            status: 1,
            stdout: String::new(),
            stderr: "xfs_quota: cannot set limits: Operation not permitted".into(),
        }]);
        let backend = XfsProjectBackend::new(rec, PathBuf::from("/home"));
        let err = backend.set(&target(Some(101)), 1, 2).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::CommandFailed);
        assert!(err.detail.contains("not permitted"));
    }

    #[tokio::test]
    async fn the_ext4_backend_runs_setquota_with_kib_blocks() {
        let rec = RecordingRunner::new(vec![]);
        let backend = Ext4UserBackend::new(rec.clone(), PathBuf::from("/home"), None);
        backend.set(&target(None), 500, 550).await.unwrap();
        assert_eq!(
            rec.calls(),
            vec![(
                "setquota".to_string(),
                vec![
                    "-u".to_string(),
                    "uh_a1b2c3d4".to_string(),
                    "512000".to_string(),
                    "563200".to_string(),
                    "0".to_string(),
                    "0".to_string(),
                    "/home".to_string(),
                ]
            )]
        );
    }

    #[tokio::test]
    async fn ext4_usage_reads_an_over_quota_report_despite_the_nonzero_exit() {
        // quota(1) exits non-zero for a user over their soft limit and marks
        // the blocks column with `*`. Both are data, not failures.
        let rec = RecordingRunner::new(vec![RunOutput {
            status: 1,
            stdout: "Disk quotas for user uh_a1b2c3d4 (uid 1001):\n\
                     Filesystem blocks quota limit grace files quota limit grace\n\
                     /dev/sda1 524288* 512000 563200 6days 12 0 0\n"
                .into(),
            stderr: String::new(),
        }]);
        let backend = Ext4UserBackend::new(rec, PathBuf::from("/home"), Some("/dev/sda1".into()));
        let usage = backend.usage(&target(None)).await.unwrap();
        assert_eq!(usage.used_mb, 512);
        assert_eq!(usage.limit_mb, Some(550));
    }

    #[tokio::test]
    async fn ext4_usage_is_pinned_to_the_home_device() {
        // The user also holds a quota on another filesystem; its numbers must
        // not be reported as the tenant's.
        let rec = RecordingRunner::new(vec![RunOutput {
            status: 0,
            stdout: "Disk quotas for user uh_a1b2c3d4 (uid 1001):\n\
                     Filesystem blocks quota limit grace files quota limit grace\n\
                     /dev/sdb9 999999 0 0 3 0 0\n\
                     /dev/sda1 1024 512000 563200 5 0 0\n"
                .into(),
            stderr: String::new(),
        }]);
        let backend = Ext4UserBackend::new(rec, PathBuf::from("/home"), Some("/dev/sda1".into()));
        let usage = backend.usage(&target(None)).await.unwrap();
        assert_eq!(usage.used_mb, 1);
        assert_eq!(usage.limit_mb, Some(550));
    }

    #[tokio::test]
    async fn ext4_usage_for_a_user_with_no_quota_record_is_zero() {
        let rec = RecordingRunner::new(vec![RunOutput {
            status: 0,
            stdout: "Disk quotas for user uh_a1b2c3d4 (uid 1001): none\n".into(),
            stderr: String::new(),
        }]);
        let backend = Ext4UserBackend::new(rec, PathBuf::from("/home"), None);
        let usage = backend.usage(&target(None)).await.unwrap();
        assert_eq!(usage.used_mb, 0);
        assert_eq!(usage.limit_mb, None);
    }

    // -- du fallback on a real directory ------------------------------------

    #[tokio::test]
    async fn the_du_fallback_measures_a_real_tree_rounding_up() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sites/example.com")).unwrap();
        std::fs::write(
            dir.path().join("sites/example.com/blob"),
            vec![0u8; 2 * 1024 * 1024],
        )
        .unwrap();
        std::fs::write(dir.path().join("note.txt"), b"hello").unwrap();

        let mut t = target(None);
        t.home_dir = dir.path().to_path_buf();
        let usage = DuFallback.usage(&t).await.unwrap();
        // 2 MiB + 5 bytes rounds up to 3 MB: a tenant slightly over never
        // shows as exactly at a boundary.
        assert_eq!(usage.used_mb, 3);
        // Nothing is enforced, so there is no kernel limit to report.
        assert_eq!(usage.limit_mb, None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_du_walk_never_follows_symlinks_out_of_the_home() {
        // A tenant controls their own tree, so a symlink is a tenant-supplied
        // pointer. Following it would let them count (or make the panel scan)
        // files outside their home.
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("big"), vec![0u8; 4 * 1024 * 1024]).unwrap();

        let home = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path().join("big"), home.path().join("link")).unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join("dir_link")).unwrap();

        assert_eq!(walk_usage_bytes(home.path()), 0);
    }

    #[tokio::test]
    async fn a_missing_home_counts_as_empty_not_as_an_error() {
        // Usage may be asked for before provisioning finished; "0 MB" is the
        // truthful answer for a home that does not exist yet.
        let mut t = target(None);
        t.home_dir = PathBuf::from("/nonexistent/unihelm-test-home");
        let usage = DuFallback.usage(&t).await.unwrap();
        assert_eq!(usage.used_mb, 0);
    }

    // -- the ops through dispatch (permissions, scope, validation) ----------

    use crate::registry::testing::{auth_for, registry};
    use unihelm_core::{Role, TenantScope};

    #[tokio::test]
    async fn a_customer_cannot_set_their_own_quota() {
        let (reg, _, customer) = registry().await;
        let sub = reg
            .services()
            .db
            .default_subscription_for(customer)
            .await
            .unwrap();
        let err = reg
            .dispatch(
                "quota.set",
                &auth_for(customer, Role::Customer),
                serde_json::json!({
                    "subscription_id": sub.id.get(), "soft_mb": 1, "hard_mb": 999999
                }),
                None,
            )
            .await
            .unwrap_err();
        // PlanManage is what stands between a tenant and raising their own
        // ceiling; customers never hold it.
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn setting_and_reading_a_quota_round_trips_through_dispatch() {
        let (reg, admin, customer) = registry().await;
        let sub = reg
            .services()
            .db
            .default_subscription_for(customer)
            .await
            .unwrap();

        let set = reg
            .dispatch(
                "quota.set",
                &auth_for(admin, Role::Admin),
                serde_json::json!({
                    "subscription_id": sub.id.get(), "soft_mb": 500, "hard_mb": 550
                }),
                None,
            )
            .await
            .unwrap();
        // Tests pin detection to the du fallback, and the API must admit that
        // nothing is enforced there.
        assert_eq!(set["enforced"], false);
        assert_eq!(set["backend"], "du_fallback");

        // The owner reads their own numbers back.
        let usage = reg
            .dispatch(
                "quota.usage",
                &auth_for(customer, Role::Customer),
                serde_json::json!({ "subscription_id": sub.id.get() }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(usage["soft_mb"], 500);
        assert_eq!(usage["hard_mb"], 550);
        assert_eq!(usage["used_mb"], 0); // the home does not exist yet
        assert_eq!(usage["enforced"], false);
    }

    #[tokio::test]
    async fn a_soft_limit_above_the_hard_limit_is_invalid() {
        let (reg, admin, customer) = registry().await;
        let sub = reg
            .services()
            .db
            .default_subscription_for(customer)
            .await
            .unwrap();
        let err = reg
            .dispatch(
                "quota.set",
                &auth_for(admin, Role::Admin),
                serde_json::json!({
                    "subscription_id": sub.id.get(), "soft_mb": 600, "hard_mb": 500
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn a_zero_hard_limit_is_refused_as_the_wrong_tool() {
        let (reg, admin, customer) = registry().await;
        let sub = reg
            .services()
            .db
            .default_subscription_for(customer)
            .await
            .unwrap();
        let err = reg
            .dispatch(
                "quota.set",
                &auth_for(admin, Role::Admin),
                serde_json::json!({
                    "subscription_id": sub.id.get(), "soft_mb": 0, "hard_mb": 0
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.detail.contains("suspension"));
    }

    #[tokio::test]
    async fn one_customer_cannot_read_another_tenants_usage() {
        let (reg, _, customer) = registry().await;
        let db = &reg.services().db;

        // Another customer with their own subscription.
        let other = db
            .users(&TenantScope::Global)
            .create(unihelm_db::users::NewUser {
                role: Role::Customer,
                email: unihelm_core::Email::parse("other@example.com").unwrap(),
                username: unihelm_core::Username::parse("other").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let theirs = db.default_subscription_for(other.id).await.unwrap();

        let err = reg
            .dispatch(
                "quota.usage",
                &auth_for(customer, Role::Customer),
                serde_json::json!({ "subscription_id": theirs.id.get() }),
                None,
            )
            .await
            .unwrap_err();
        // Not-found, not forbidden: the caller must not even learn that the
        // subscription exists (spec §6.1).
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn the_backend_report_is_admin_visible_and_honest() {
        let (reg, admin, customer) = registry().await;
        let report = reg
            .dispatch(
                "quota.backend",
                &auth_for(admin, Role::Admin),
                serde_json::json!({}),
                None,
            )
            .await
            .unwrap();
        assert_eq!(report["backend"], "du_fallback");
        assert_eq!(report["enforced"], false);

        // ServerRead is not in the customer's default set.
        let err = reg
            .dispatch(
                "quota.backend",
                &auth_for(customer, Role::Customer),
                serde_json::json!({}),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }
}
