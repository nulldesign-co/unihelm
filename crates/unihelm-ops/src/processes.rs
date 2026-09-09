//! The process table, and the one dangerous thing that can be done to it
//! (spec §11.11; issue 46).
//!
//! # Why this exists
//!
//! `metrics.snapshot` says the machine is at 96% CPU. It does not say *what* is
//! at 96% CPU, and until this module existed nothing in the panel did — the
//! operator's only move on a slow server was to open an SSH session and run
//! `top`. A control panel that can say the house is on fire but not which room
//! is half a panel.
//!
//! # Read first, and honestly
//!
//! [`List`] is the feature. [`Kill`] is a small, heavily fenced addition to it,
//! and the ordering is deliberate: an honest monitor is worth more than a kill
//! button that takes the machine down.
//!
//! Three things this module refuses to guess at:
//!
//! **The memory column is the same quantity the service view reports.**
//! [`unihelm_distro::svc`] learned the hard way that a cgroup's `MemoryCurrent`
//! is not the memory a unit is using — it carries the page cache that unit
//! happened to touch, so a database that had just read a table reported
//! gigabytes beside Docker's 40 MB and the two were compared as though they
//! measured the same thing. The service view now reports `anon` out of the
//! unit's own `memory.stat`. The per-process form of that number is `RssAnon`
//! from `/proc/<pid>/status`, so that is what this reports, and
//! [`MemorySource`] says so on every row. A kernel too old to split the RSS
//! falls back to `VmRSS` — labelled, never quietly mixed in.
//!
//! **CPU is a rate over a window, and the window is stated.** The cheap number —
//! total CPU time over process lifetime — is an average since boot: a process
//! that pinned a core for an hour last night and is idle now would sit at the
//! top of a page whose entire purpose is "what is using this server *right
//! now*". So a percentage here is always two samples divided, and
//! [`ListOutput::cpu_window_ms`] says how far apart they were. A process with
//! nothing to diff against reports `null`, not `0`.
//!
//! **Nothing here polls faster than the data changes.** The kernel accounts CPU
//! in clock ticks (100 a second on both supported families), and a sweep reads
//! four small files per process, so a sub-second refresh buys noise at a real
//! cost. [`ListOutput::refresh_seconds`] is the interval the server asks the
//! client to use, so the page and the agent cannot drift apart about it.
//!
//! # Who this is for
//!
//! The operator, and only the operator. Both operations refuse any caller whose
//! [`unihelm_core::TenantScope`] is narrower than the whole machine — see
//! [`require_whole_machine_scope`], which the 0.8.0 review added after finding
//! that `ServerRead` alone let one reseller read every other tenant's command
//! lines. Permission says what kind of account; scope says whose machine.
//!
//! # The kill, and what it will not do
//!
//! Killing the wrong process takes the machine down. So [`Kill`] refuses three
//! whole categories rather than trusting a caller to aim (see [`protection`]),
//! it does not accept a bare pid as consent (see [`KillInput`]), and it never
//! claims the process exited — it reports the signal it sent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_core::{ErrorCode, Permission, Result, SubscriptionId, UnihelmError};
use unihelm_distro::Family;
use unihelm_distro::svc::ManagedUnit;

use crate::registry::{Execution, OpContext, TypedOperation};

/// How many rows a listing returns when the caller does not say.
///
/// Enough to hold everything worth looking at on a busy machine, few enough
/// that the answer is a page rather than a download.
const DEFAULT_LIMIT: usize = 40;
const MAX_LIMIT: usize = 200;

/// The first uid an ordinary account gets.
///
/// `UID_MIN` in `/etc/login.defs` is 1000 on Debian and on EL, and the panel's
/// own tenants are created above it. Everything below is a system account: root,
/// `www-data`, `mysql`, `redis`, the panel's own service users. A constant
/// rather than a read of `login.defs`, because being wrong in the safe direction
/// — a machine with a lower `UID_MIN`, where the panel then declines to signal a
/// few accounts it could have — costs an operator one shell command, and being
/// wrong in the other direction costs them nginx.
const FIRST_ORDINARY_UID: u32 = 1_000;

/// How far apart two CPU samples must be before their difference means
/// anything.
///
/// At 100 ticks a second, a 100 ms window resolves to 10% of a core per tick: a
/// process using 4% would be drawn as either 0% or 10%. Just under a second is
/// the same floor `unihelm_metrics` uses, for the same reason.
const MIN_CPU_WINDOW: Duration = Duration::from_millis(900);

/// Past this, the previous sample is not "the last poll" any more — it is a tab
/// somebody left open over lunch, and averaging a minute of history into a
/// "right now" column is the defect this module exists to avoid.
const MAX_CPU_WINDOW: Duration = Duration::from_secs(60);

/// How long the *first* listing waits between its own two samples.
///
/// Paid only when there is no usable previous sample: a page that was just
/// opened, or one left alone past [`MAX_CPU_WINDOW`]. Every later poll diffs
/// against the one before it and waits for nothing.
const SETTLE: Duration = Duration::from_millis(250);

/// The refresh interval the server asks clients to use, and the one this module
/// is built around: two polls of a page are then at least [`MIN_CPU_WINDOW`]
/// apart, so no client pays [`SETTLE`] twice.
const REFRESH_SECONDS: u32 = 5;

/// A command line longer than this is cut, with an ellipsis so the row does not
/// claim to be the whole thing. Java and Node argv run to kilobytes routinely,
/// and forty of those is a megabyte of JSON for a column nobody reads past the
/// first line of.
const MAX_CMDLINE_CHARS: usize = 200;

// ---------------------------------------------------------------------------
// What one process looks like
// ---------------------------------------------------------------------------

/// One process's CPU counter, and the start time that says it is still the same
/// process.
///
/// Pids are recycled. Without `start_ticks`, a pid that died and was reused
/// between two samples would have its successor's counter diffed against its
/// predecessor's, which produces either a wild percentage or a negative one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTicks {
    /// Field 22 of `/proc/<pid>/stat`: when this process started, in clock
    /// ticks since boot. Constant for the life of the process.
    pub start_ticks: u64,
    /// `utime + stime`: CPU time this process has used, in clock ticks.
    pub cpu_ticks: u64,
}

/// Every process's [`CpuTicks`], by pid.
pub type CpuSample = HashMap<u32, CpuTicks>;

/// What one sweep of the process table reads, before anything is interpreted.
#[derive(Debug, Clone)]
pub struct RawProcess {
    pub pid: u32,
    pub ppid: u32,
    /// `comm`: the executable name, capped at 15 characters by the kernel.
    pub comm: String,
    /// The full argv, NULs replaced by spaces. `None` for a kernel thread and
    /// for a zombie, neither of which has one.
    pub cmdline: Option<String>,
    pub uid: u32,
    /// The single-letter state from `/proc/<pid>/stat`.
    pub state: char,
    /// `RssAnon` in bytes: the anonymous resident pages this process holds.
    /// `None` on a kernel that does not split the RSS (before 4.5).
    pub rss_anon_bytes: Option<u64>,
    /// `VmRSS` in bytes: the whole resident set, file-backed pages included.
    pub rss_bytes: Option<u64>,
    pub cpu: CpuTicks,
    /// The cgroup path systemd put this process in, if any.
    pub cgroup: Option<String>,
}

/// Which number [`ProcessView::memory_bytes`] is carrying.
///
/// The same distinction [`unihelm_distro::svc::MemorySource`] draws, for the
/// same reason: two memory readings that measure different things must not
/// share a column without saying which is which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySource {
    /// `RssAnon` — the anonymous resident pages the process actually holds.
    /// This is the per-process form of the `anon` the service view reports, so
    /// the two can be read against each other.
    Anonymous,
    /// `VmRSS` — the whole resident set, which includes file-backed pages shared
    /// with every other process mapping the same library. Used only where the
    /// kernel does not publish `RssAnon`; it reads high, by however much the
    /// process happens to have mapped.
    Resident,
}

/// A process's state, as the kernel spells it, in a word the UI can badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Running,
    Sleeping,
    /// Uninterruptible sleep — waiting on I/O that cannot be interrupted. Worth
    /// its own word on a page about a slow server: a pile of these is a disk
    /// problem rather than a CPU one, and killing helps with neither.
    DiskSleep,
    Stopped,
    /// Exited, and still in the table because its parent has not reaped it. It
    /// holds no memory and uses no CPU, and signalling it does nothing.
    Zombie,
    Idle,
    Unknown,
}

impl ProcessState {
    fn from_stat(c: char) -> Self {
        match c {
            'R' => ProcessState::Running,
            'S' => ProcessState::Sleeping,
            'D' => ProcessState::DiskSleep,
            'T' | 't' => ProcessState::Stopped,
            'Z' => ProcessState::Zombie,
            'I' => ProcessState::Idle,
            _ => ProcessState::Unknown,
        }
    }
}

/// The tenant a process belongs to, where that could be established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tenant {
    pub subscription_id: SubscriptionId,
    /// The Linux account the panel provisioned for that subscription.
    pub linux_user: String,
}

/// Which rule stops the panel signalling a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionRule {
    /// pid 1.
    Init,
    /// The panel's own units, or the agent's own process.
    Panel,
    /// Owned by root or by another system account.
    SystemAccount,
}

/// Why a process will not be signalled, in the words the refusal uses.
///
/// Carried on the row as well as returned by the refusal, out of one function,
/// so a page can disable the button *and* say why before anybody presses
/// anything — and so the sentence on the row is the sentence the API would
/// give.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Protected {
    pub rule: ProtectionRule,
    pub explanation: String,
}

/// One row of the process table.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessView {
    pub pid: u32,
    pub ppid: u32,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    pub uid: u32,
    /// The account name from `passwd`, or `None` for a uid with no entry — which
    /// happens, and printing the bare number is more honest than inventing a
    /// name for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub state: ProcessState,
    /// True for `kthreadd` and its children. A kernel thread has no address
    /// space of its own, so its memory reads as nothing — a fact about kernel
    /// threads rather than a failed measurement.
    pub kernel_thread: bool,
    /// Read [`MemorySource`] before putting this beside another number.
    pub memory_bytes: Option<u64>,
    pub memory_source: Option<MemorySource>,
    /// Percent of **one** core over [`ListOutput::cpu_window_ms`], the way `top`
    /// reports it: a process on four busy threads reads about 400. `null` when
    /// there was nothing to diff against.
    pub cpu_pct: Option<f32>,
    /// The systemd unit or scope this process is in, from its cgroup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<Tenant>,
    /// Present when [`Kill`] would refuse this process, absent when it would
    /// not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<Protected>,
}

// ---------------------------------------------------------------------------
// The machine, behind a trait
// ---------------------------------------------------------------------------

/// The four things these operations ask of the machine they run on.
///
/// A trait for the reason `server::Machine` is one: what is worth testing here
/// is the refusals, the ordering and the honesty of the arithmetic, and none of
/// it is testable if exercising it needs a Linux `/proc` and a live process the
/// test is willing to have killed.
#[async_trait]
pub trait ProcessTable: Send + Sync {
    /// Everything about every process, in one pass.
    async fn sweep(&self) -> Result<Vec<RawProcess>>;

    /// Only the CPU counters.
    ///
    /// The second half of a two-sample measurement needs nothing else, and this
    /// reads one file per process instead of four. Defaulted, so an
    /// implementation provides it only where the saving is worth having.
    async fn cpu_sample(&self) -> Result<CpuSample> {
        Ok(self
            .sweep()
            .await?
            .into_iter()
            .map(|p| (p.pid, p.cpu))
            .collect())
    }

    /// `sysconf(_SC_CLK_TCK)`: how many of a process's CPU ticks make a second.
    fn ticks_per_second(&self) -> u64;

    /// The account name for a uid, from `passwd`.
    fn user_name(&self, uid: u32) -> Option<String>;

    /// Send `signal` to `pid`. Returns once the signal is *delivered*, which is
    /// not the same as the process having exited — see [`KillOutput::note`].
    fn signal(&self, pid: u32, signal: KillSignal) -> Result<()>;
}

/// The real machine: `/proc`, `passwd` and `kill(2)`.
pub struct ProcFs;

#[async_trait]
impl ProcessTable for ProcFs {
    async fn sweep(&self) -> Result<Vec<RawProcess>> {
        // On a blocking thread rather than inline. `svc::read_memory_stat` reads
        // one cgroup file inline and explains why that is fine; this is four
        // reads times every process on the machine, and a thousand procfs reads
        // on the agent's runtime thread stall every other operation behind them.
        tokio::task::spawn_blocking(sweep_procfs)
            .await
            .map_err(|e| UnihelmError::internal(format!("the process sweep panicked: {e}")))?
    }

    async fn cpu_sample(&self) -> Result<CpuSample> {
        tokio::task::spawn_blocking(cpu_sample_procfs)
            .await
            .map_err(|e| UnihelmError::internal(format!("the CPU sample panicked: {e}")))?
    }

    fn ticks_per_second(&self) -> u64 {
        // SAFETY: `sysconf` reads a static system parameter and touches nothing
        // this process owns.
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        // A non-positive answer means the value is unavailable, not that a tick
        // is free. 100 is the value on every kernel this panel supports.
        if ticks > 0 { ticks as u64 } else { 100 }
    }

    fn user_name(&self, uid: u32) -> Option<String> {
        // SAFETY: `getpwuid` returns a pointer into a static buffer libc owns;
        // the one field wanted is copied out immediately, before anything else
        // can call into the same buffer. The shape `appcontainer` uses for
        // `getpwnam`.
        unsafe {
            let pw = libc::getpwuid(uid);
            if pw.is_null() || (*pw).pw_name.is_null() {
                return None;
            }
            Some(
                std::ffi::CStr::from_ptr((*pw).pw_name)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }

    fn signal(&self, pid: u32, signal: KillSignal) -> Result<()> {
        let target = signalable_pid(pid)?;
        // SAFETY: `kill` takes two integers and returns one. `target` has been
        // through `signalable_pid`, so it is a real pid and never one of the
        // values `kill` reads as "a process group" or "everything".
        let sent = unsafe { libc::kill(target, signal.number()) };
        if sent == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            format!(
                "{} could not be sent to pid {pid}: {error}. The process is still running.",
                signal.as_str()
            ),
        ))
    }
}

// ---------------------------------------------------------------------------
// Reading /proc
// ---------------------------------------------------------------------------

fn proc_unavailable(e: &std::io::Error) -> UnihelmError {
    UnihelmError::new(
        ErrorCode::ServiceUnavailable,
        format!(
            "the process table could not be read: /proc could not be opened ({e}). Every \
             figure on this page comes from /proc, so there is nothing to show rather than \
             something to doubt."
        ),
    )
}

/// One pass over `/proc`, reading everything a row needs.
fn sweep_procfs() -> Result<Vec<RawProcess>> {
    let entries = std::fs::read_dir("/proc").map_err(|e| proc_unavailable(&e))?;
    let mut rows = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        // A process that exits between the readdir and these reads is ordinary
        // rather than a failure: it is dropped, instead of failing a sweep of
        // three hundred processes over one that ended.
        if let Some(row) = read_process(pid) {
            rows.push(row);
        }
    }
    Ok(rows)
}

/// The CPU counters alone, for the second half of a measurement.
fn cpu_sample_procfs() -> Result<CpuSample> {
    let entries = std::fs::read_dir("/proc").map_err(|e| proc_unavailable(&e))?;
    let mut sample = CpuSample::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            && let Some(parsed) = parse_stat(&stat)
        {
            sample.insert(pid, parsed.cpu);
        }
    }
    Ok(sample)
}

fn read_process(pid: u32) -> Option<RawProcess> {
    let stat = parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)?;
    let status = parse_status(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?);
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|raw| join_cmdline(&raw));
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|raw| cgroup_path(&raw));

    Some(RawProcess {
        pid,
        ppid: stat.ppid,
        comm: stat.comm,
        cmdline,
        // A `status` with no `Uid:` line is not a thing a running kernel
        // produces; root is the assumption that refuses the kill rather than
        // allowing it.
        uid: status.uid.unwrap_or(0),
        state: stat.state,
        rss_anon_bytes: status.rss_anon_bytes,
        rss_bytes: status.rss_bytes,
        cpu: stat.cpu,
        cgroup,
    })
}

struct StatFields {
    comm: String,
    state: char,
    ppid: u32,
    cpu: CpuTicks,
}

/// `/proc/<pid>/stat`, which is one line and cannot be split on whitespace.
///
/// Field 2 is the executable name in parentheses, and it is whatever the process
/// called itself: `(Web Content)` has a space in it and `(a) b (c)` is a legal
/// name. Splitting on whitespace puts every later field at the wrong index for
/// exactly those processes — which is why the fields after the name are counted
/// from the **last** `)` in the line rather than the first.
fn parse_stat(line: &str) -> Option<StatFields> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    let comm = line.get(open + 1..close)?.to_string();

    // Everything after the name. Field 3 (`state`) is index 0 here, so field N
    // is at index N - 3.
    let rest: Vec<&str> = line.get(close + 1..)?.split_whitespace().collect();
    let field = |n: usize| rest.get(n - 3).copied();

    Some(StatFields {
        comm,
        state: field(3)?.chars().next()?,
        ppid: field(4)?.parse().ok()?,
        cpu: CpuTicks {
            start_ticks: field(22)?.parse().ok()?,
            // utime + stime. Children's time (fields 16 and 17) is deliberately
            // left out: it is charged to a parent only once a child has been
            // reaped, so counting it makes a shell that just ran a build look
            // like it is burning a core.
            cpu_ticks: field(14)?.parse::<u64>().ok()? + field(15)?.parse::<u64>().ok()?,
        },
    })
}

#[derive(Default)]
struct StatusFields {
    uid: Option<u32>,
    rss_anon_bytes: Option<u64>,
    rss_bytes: Option<u64>,
}

/// The three lines of `/proc/<pid>/status` a row needs.
///
/// `Uid:` carries four values — real, effective, saved and filesystem. The real
/// uid is the one taken: it names the account that owns the process, which is
/// what both the tenant lookup and the refusal in [`protection`] are about, and
/// it is the one a process that dropped privileges cannot get back.
fn parse_status(text: &str) -> StatusFields {
    let mut fields = StatusFields::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key {
            "Uid" => fields.uid = value.split_whitespace().next().and_then(|v| v.parse().ok()),
            "RssAnon" => fields.rss_anon_bytes = kib_value(value),
            "VmRSS" => fields.rss_bytes = kib_value(value),
            _ => {}
        }
    }
    fields
}

/// `      1234 kB` — the only unit `/proc/<pid>/status` writes memory in.
fn kib_value(value: &str) -> Option<u64> {
    let mut parts = value.split_whitespace();
    let number: u64 = parts.next()?.parse().ok()?;
    // The unit is checked rather than assumed. A value in some other unit read
    // as kilobytes is wrong by a factor of a thousand, in the one column an
    // operator uses to decide what to stop.
    match parts.next() {
        Some("kB") => number.checked_mul(1024),
        _ => None,
    }
}

/// `/proc/<pid>/cmdline` is NUL-separated and NUL-terminated.
///
/// Empty for a kernel thread and for a zombie, and `None` is the honest answer
/// there — an empty string in that column reads as a command with no name.
fn join_cmdline(raw: &str) -> Option<String> {
    let joined = raw
        .split('\0')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if joined.is_empty() {
        return None;
    }
    if joined.chars().count() <= MAX_CMDLINE_CHARS {
        return Some(joined);
    }
    // Cut on a character boundary, and say that it was cut: a silently
    // truncated command line is a row claiming to be a whole command.
    let cut: String = joined.chars().take(MAX_CMDLINE_CHARS).collect();
    Some(format!("{cut}…"))
}

/// The cgroup path out of `/proc/<pid>/cgroup`.
///
/// cgroup v2 — the only hierarchy the installer permits (spec §7.1) — writes one
/// line, `0::/system.slice/nginx.service`. The v1 layout is parsed too, because
/// this code also runs on a developer's older machine, and there the systemd
/// hierarchy is the `name=systemd` line rather than the unified one.
fn cgroup_path(text: &str) -> Option<String> {
    let mut v1 = None;
    for line in text.lines() {
        let mut parts = line.splitn(3, ':');
        let (hierarchy, controllers, path) = (parts.next()?, parts.next()?, parts.next()?);
        if hierarchy == "0" && controllers.is_empty() {
            return Some(path.to_string());
        }
        if controllers == "name=systemd" {
            v1 = Some(path.to_string());
        }
    }
    v1
}

/// The systemd unit a cgroup path belongs to.
///
/// The deepest `.service` or `.scope` segment: `/system.slice/nginx.service` is
/// nginx, and `/user.slice/user-1000.slice/session-3.scope` is that login
/// session. A path with neither reports its deepest slice instead, so a process
/// parked directly in a tenant's slice still says where it is.
fn unit_of(path: &str) -> Option<String> {
    let segments = || path.split('/').filter(|s| !s.is_empty());
    segments()
        .rev()
        .find(|s| s.ends_with(".service") || s.ends_with(".scope"))
        .or_else(|| segments().rev().find(|s| s.ends_with(".slice")))
        .map(str::to_string)
}

/// The tenant account named by a `unihelm-<user>.slice` segment, if there is
/// one.
///
/// `slices::slice_file_name` escapes a hyphen in the account name to `\x2d`,
/// because in a slice name a bare `-` is a nesting separator. This is that
/// escape read back; anything else in the path is not a tenant slice.
fn tenant_slice_user(path: &str) -> Option<String> {
    path.split('/')
        .filter_map(|segment| segment.strip_suffix(".slice"))
        .find_map(|segment| segment.strip_prefix("unihelm-"))
        .map(|user| user.replace("\\x2d", "-"))
}

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

/// A pid, as a number `kill(2)` will treat as one process.
///
/// `kill` reads its first argument as a signed integer with three special cases:
/// `0` is every process in the caller's process group, `-1` is every process the
/// caller may signal at all, and any other negative number is a process group.
/// The agent runs as root, so `kill(-1, …)` from here is the whole machine — and
/// `pid` arrives as an unsigned number out of JSON, where `4294967295` casts
/// straight to `-1`. Both ends are refused here, before any of it reaches libc.
fn signalable_pid(pid: u32) -> Result<i32> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "{pid} is not a process id. The panel signals one process at a time, named by \
                 its pid; 0 and negative values mean whole process groups to the kernel, and \
                 are refused here."
            ),
        )
        .with_field("pid"));
    }
    Ok(pid as i32)
}

/// The panel's own processes, by both of the names they answer to.
///
/// A unit is the reliable one on an installed machine, and it catches a second
/// copy of the panel started some other way. Pids are the fallback for a
/// development install, which runs outside any unit: the agent knows its own,
/// and the web process passes its own in — the same arrangement
/// `metrics.snapshot` uses, because the agent has no way to identify the web
/// process on its own.
struct PanelProcesses {
    units: Vec<String>,
    agent_pid: u32,
    /// What the caller said the panel's web process is. It can only ever *add*
    /// a refusal, never remove one, so a wrong or absent value costs an
    /// operator a refusal they could have avoided rather than a machine.
    web_pid: Option<u32>,
}

impl PanelProcesses {
    /// The panel's unit names on this family, plus the agent's own pid.
    fn here(family: Family, web_pid: Option<u32>) -> Self {
        Self {
            units: [ManagedUnit::UnihelmWeb, ManagedUnit::UnihelmAgentd]
                .iter()
                .map(|unit| unit.unit_name(family).as_str().to_string())
                .collect(),
            agent_pid: std::process::id(),
            web_pid,
        }
    }
}

/// What the panel will not signal, and why.
///
/// Three rules, each of them a machine somebody lost:
///
/// 1. **pid 1.** Killing init panics the kernel. There is no version of that the
///    operator meant.
/// 2. **The panel's own processes.** The agent killing itself leaves the request
///    half-done with nothing left to report it, and nothing running to start it
///    again; the web process is the surface the click came from. See
///    [`PanelProcesses`] for how each is recognised.
/// 3. **System accounts.** Everything below [`FIRST_ORDINARY_UID`] — root,
///    `www-data`, `mysql`, `redis`, `sshd` — is part of a service. A service is
///    stopped by its service manager, which the panel already offers and which
///    puts it back the way it was found. Killing a worker out from under nginx
///    or MariaDB instead is how a page of statistics takes a site down.
///
/// What is left is exactly what this page is for: an ordinary account's runaway
/// — a tenant's PHP script, a Node app, a cron job that will not end.
fn protection(
    pid: u32,
    uid: u32,
    user: Option<&str>,
    unit: Option<&str>,
    command: &str,
    panel: &PanelProcesses,
) -> Option<Protected> {
    if pid == 1 {
        return Some(Protected {
            rule: ProtectionRule::Init,
            explanation: format!(
                "pid 1 is this machine's init system (`{command}`). Killing it panics the \
                 kernel and takes the server down, so the panel refuses."
            ),
        });
    }

    if pid == panel.agent_pid {
        return Some(Protected {
            rule: ProtectionRule::Panel,
            explanation: format!(
                "pid {pid} is the Unihelm agent itself — the process being asked to send the \
                 signal. It would die mid-request with nothing left to tell you it had, and \
                 nothing running to start it again. Restart it from a shell with \
                 `systemctl restart unihelm-agentd`."
            ),
        });
    }

    if Some(pid) == panel.web_pid {
        return Some(Protected {
            rule: ProtectionRule::Panel,
            explanation: format!(
                "pid {pid} is the Unihelm web process — the one serving the page this request \
                 came from. Killing it takes the panel off the air, and nothing would be left \
                 to tell you it had. Restart it from a shell with \
                 `systemctl restart unihelm-web`."
            ),
        });
    }

    if let Some(unit) = unit.filter(|u| panel.units.iter().any(|name| name == u)) {
        return Some(Protected {
            rule: ProtectionRule::Panel,
            explanation: format!(
                "pid {pid} belongs to `{unit}` — the panel itself. Stopping the panel from \
                 inside the panel leaves nothing to report that it happened. Restart it from \
                 a shell with `systemctl restart {unit}`."
            ),
        });
    }

    if uid < FIRST_ORDINARY_UID {
        let owner = match user {
            Some(name) => format!("`{name}` (uid {uid})"),
            None => format!("uid {uid}"),
        };
        let service = match unit {
            Some(unit) => format!("Stop or restart `{unit}` instead"),
            None => "Stop or restart the service it belongs to instead".to_string(),
        };
        return Some(Protected {
            rule: ProtectionRule::SystemAccount,
            explanation: format!(
                "pid {pid} (`{command}`) runs as {owner}, a system account. The panel signals \
                 only processes belonging to ordinary accounts: a system process is part of a \
                 service, and killing one worker out from under it takes sites down without \
                 restarting anything. {service} — from the Stack page, or with `systemctl`."
            ),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// process.list
// ---------------------------------------------------------------------------

/// What to put at the top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sort {
    /// The default, because "the server is slow" is a CPU question until it
    /// turns out not to be.
    #[default]
    Cpu,
    Memory,
}

/// `process.list` — what is running, what it is using, and whose it is.
pub struct List {
    source: Arc<dyn ProcessTable>,
    /// The previous sample, so a poll costs one sweep and the percentage is
    /// still a rate.
    baseline: Mutex<Option<Baseline>>,
}

#[derive(Clone)]
struct Baseline {
    at: Instant,
    ticks: CpuSample,
}

impl List {
    pub fn live() -> Self {
        Self::over(Arc::new(ProcFs))
    }

    fn over(source: Arc<dyn ProcessTable>) -> Self {
        Self {
            source,
            baseline: Mutex::new(None),
        }
    }

    /// The previous sample, cloned out from under the lock rather than borrowed
    /// across the await that follows: a few hundred pid/tick pairs is a cheap
    /// copy, and a lock held across an await is a deadlock waiting for a second
    /// dashboard to open.
    fn previous(&self) -> Option<Baseline> {
        self.baseline
            // A poisoned lock means an earlier call panicked while holding it.
            // What is inside is still a valid CPU sample, and refusing to list
            // processes over a stale number would take the page down for the
            // operator who most needs it.
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn remember(&self, at: Instant, ticks: CpuSample) {
        *self.baseline.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(Baseline { at, ticks });
    }
}

#[derive(Debug, Deserialize)]
pub struct ListInput {
    #[serde(default)]
    pub sort: Sort,
    /// How many rows to return. Clamped to 200.
    #[serde(default)]
    pub limit: Option<usize>,
    /// Case-insensitive substring of the command, its arguments, the owning
    /// account or the unit.
    ///
    /// Applied **before** the sort and the limit, on purpose: filtering the
    /// forty rows that came back would report "no matches" for a process
    /// sitting at rank two hundred, which is a page lying about the machine.
    #[serde(default)]
    pub search: Option<String>,
    /// The pid of the panel's web process, so its row says it is protected.
    /// See [`PanelProcesses`]; `metrics.snapshot` takes the same field for the
    /// same reason.
    #[serde(default)]
    pub web_pid: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub processes: Vec<ProcessView>,
    /// Every process on the machine, before `search` and `limit`.
    pub total: usize,
    /// How many `search` matched — equal to `total` when nothing was searched
    /// for, and the number a page needs to say "40 of 312".
    pub matched: usize,
    /// The machine's core count, from the same collector the dashboard reads, so
    /// "300%" here and "3 cores busy" there are the same fact.
    pub cpu_cores: u32,
    /// How far apart the two CPU samples were. Every `cpu_pct` below is a rate
    /// over this window and nothing longer.
    pub cpu_window_ms: u64,
    /// How often the client should ask again. Here rather than in the client, so
    /// a page cannot poll faster than the numbers change.
    pub refresh_seconds: u32,
    pub sort: Sort,
    pub limit: usize,
    /// Why no row carries a tenant, when the panel's own database could not be
    /// asked. The rows are still true; the tenant column is simply blank, and a
    /// blank column with no explanation reads as "these belong to nobody".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_lookup_error: Option<String>,
}

/// Refuse anyone whose scope is not the whole machine.
///
/// **The 0.8.0 review found this missing.** `ServerRead` reads like an
/// administrator's permission and is not one: `Role::Reseller` holds it by
/// default (`unihelm_core::rbac`), a reseller is a tenant — `TenantScope::Reseller`
/// on a white-label panel with peers on the same box — and `Processes` is an
/// ungated link in the sidebar. So every reseller could `GET /api/processes` and
/// read, for the whole machine: verbatim `cmdline` for every process, which
/// routinely carries a password (`mysql -p…`, `wp --dbpass=…`, a cron script
/// with a token); every other tenant's Linux account name and `/home/uh_…`
/// paths; and, through `attribute_tenants`, the subscription id behind each of
/// them. `search` is applied to the whole sweep before the row limit, so
/// `?search=uh_` enumerated every tenant on the box and `?search=mysql` went
/// looking for the passwords. That is precisely the reseller-to-reseller
/// isolation this panel documents as a defended property.
///
/// # Why a refusal and not a filtered list
///
/// There is no honest tenant-scoped process table. Most of what runs is nobody's
/// tenant — kernel threads, nginx as `www-data` serving every site, the
/// database, the panel itself — and the numbers that make the page worth having
/// (`total`, `matched`, `cpu_cores`, the busiest-first ordering) are facts about
/// the machine. Filtering the rows and keeping the totals would report a
/// machine-wide fact to somebody shown a tenant-wide list; recomputing the
/// totals over the filtered rows would answer "what is at 96%" with "nothing you
/// own", which is the question the page exists to answer and a worse lie. The
/// operation was written for the operator — the comment on `PERMISSION` said as
/// much and only the permission disagreed — so it stays the operator's, and a
/// tenant gets a refusal that says whose machine it is.
///
/// The operator is not narrowed by this. `TenantScope::Global` is every
/// administrator, including one whose account has been narrowed to `server.read`
/// with no `server.manage`: that account still reads the table and still cannot
/// signal anything, which is the split `Kill` exists to make.
fn require_whole_machine_scope(ctx: &OpContext) -> Result<()> {
    if ctx.scope().is_global() {
        return Ok(());
    }
    Err(UnihelmError::new(
        ErrorCode::TenantScopeViolation,
        "the process table, and the signals that act on it, belong to the whole machine — \
         every tenant's programs, the command lines they were started with and the accounts \
         they run as — so they are offered only to an account whose scope is the whole \
         machine. Your own sites and what they are using are on the Sites page; if one of \
         them is slow and you cannot see why, ask the server operator.",
    ))
}

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "process.list";
    // Read, like `metrics.snapshot`: the same question the dashboard asks,
    // broken down. `ServerRead` says *what kind* of account this is for — one
    // that watches the machine rather than one that changes it — and
    // `require_whole_machine_scope` says *whose* machine. The permission alone
    // was the 0.8.0 defect: see the guard's comment.
    const PERMISSION: Permission = Permission::ServerRead;
    // One sweep of /proc against a sample the previous poll left behind. The
    // first call of a session also waits `SETTLE` for a second sample, which is
    // the one path here that approaches the immediate budget — and the reason
    // `refresh_seconds` is in the answer.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // First, before /proc is read at all: there is no partial answer to give
        // a tenant here, so there is no work worth doing for one.
        require_whole_machine_scope(ctx)?;

        let sweep = self.source.sweep().await?;
        let taken_at = Instant::now();

        // Two samples, one way or the other. A previous poll inside the usable
        // window is free; otherwise this pays `SETTLE` once, rather than report
        // an average-since-boot as a live percentage.
        let usable = self
            .previous()
            .filter(|p| (MIN_CPU_WINDOW..=MAX_CPU_WINDOW).contains(&taken_at.duration_since(p.at)));

        let Some(previous) = usable else {
            let first: CpuSample = sweep.iter().map(|p| (p.pid, p.cpu)).collect();
            tokio::time::sleep(SETTLE).await;
            let second = self.source.cpu_sample().await?;
            let ended = Instant::now();
            self.remember(ended, second.clone());
            // The rows keep the identity and the memory read a quarter-second
            // ago; only the CPU counters are re-read, because they are the only
            // ones that mean nothing on their own.
            return Ok(self
                .assemble(
                    ctx,
                    &input,
                    sweep,
                    &first,
                    Some(second),
                    ended.duration_since(taken_at),
                )
                .await);
        };

        let window = taken_at.duration_since(previous.at);
        let latest: CpuSample = sweep.iter().map(|p| (p.pid, p.cpu)).collect();
        self.remember(taken_at, latest);
        Ok(self
            .assemble(ctx, &input, sweep, &previous.ticks, None, window)
            .await)
    }
}

impl List {
    /// Turn one sweep and two CPU samples into the answer.
    ///
    /// `later` is the second sample where one was taken; without it, the sweep's
    /// own counters are the later reading.
    async fn assemble(
        &self,
        ctx: &OpContext,
        input: &ListInput,
        sweep: Vec<RawProcess>,
        baseline: &CpuSample,
        later: Option<CpuSample>,
        window: Duration,
    ) -> ListOutput {
        let total = sweep.len();
        let ticks_per_second = self.source.ticks_per_second();
        let window_secs = window.as_secs_f64();

        let needle = input
            .search
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);

        let panel = PanelProcesses::here(ctx.distro().info.family, input.web_pid);

        let mut rows: Vec<ProcessView> = Vec::with_capacity(sweep.len());
        for raw in sweep {
            let unit = raw.cgroup.as_deref().and_then(unit_of);
            let user = self.source.user_name(raw.uid);
            if let Some(needle) = needle.as_deref()
                && !matches_search(&raw, user.as_deref(), unit.as_deref(), needle)
            {
                continue;
            }

            let now = later
                .as_ref()
                .and_then(|sample| sample.get(&raw.pid).copied())
                .unwrap_or(raw.cpu);

            let (memory_bytes, memory_source) = memory_reading(&raw);
            rows.push(ProcessView {
                cpu_pct: cpu_percent(baseline.get(&raw.pid), now, ticks_per_second, window_secs),
                protected: protection(
                    raw.pid,
                    raw.uid,
                    user.as_deref(),
                    unit.as_deref(),
                    &raw.comm,
                    &panel,
                ),
                // Every kernel thread is a child of `kthreadd`, which is pid 2.
                kernel_thread: raw.pid == 2 || raw.ppid == 2,
                // Filled in below, for the rows that survive the limit: a
                // database round trip per process on the machine would cost more
                // than everything else on this page put together.
                tenant: None,
                memory_bytes,
                memory_source,
                pid: raw.pid,
                ppid: raw.ppid,
                uid: raw.uid,
                state: ProcessState::from_stat(raw.state),
                command: raw.comm,
                cmdline: raw.cmdline,
                user,
                unit,
            });
        }

        let matched = rows.len();
        sort_rows(&mut rows, input.sort);
        let limit = input.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        rows.truncate(limit);

        let tenant_lookup_error = attribute_tenants(ctx, &mut rows).await.err();

        ListOutput {
            processes: rows,
            total,
            matched,
            cpu_cores: ctx.metrics().snapshot().await.cpu.cores,
            cpu_window_ms: window.as_millis() as u64,
            refresh_seconds: REFRESH_SECONDS,
            sort: input.sort,
            limit,
            tenant_lookup_error,
        }
    }
}

/// The memory figure for a row, and what it is.
///
/// `RssAnon` where the kernel publishes it, because that is the quantity the
/// service view reports as `anon` and the only one the two pages can be read
/// against each other on. `VmRSS` otherwise — labelled, so a reader can see the
/// fallback rather than take it for the same number.
fn memory_reading(raw: &RawProcess) -> (Option<u64>, Option<MemorySource>) {
    match (raw.rss_anon_bytes, raw.rss_bytes) {
        (Some(anon), _) => (Some(anon), Some(MemorySource::Anonymous)),
        (None, Some(rss)) => (Some(rss), Some(MemorySource::Resident)),
        (None, None) => (None, None),
    }
}

/// Percent of one core between two readings of the same process.
///
/// `None` rather than `0` in every case where there is nothing to measure: no
/// earlier reading, a pid reused since (the start time moved), or a window too
/// short to divide by. A zero there would be a claim that the process is idle.
fn cpu_percent(
    before: Option<&CpuTicks>,
    now: CpuTicks,
    ticks_per_second: u64,
    window_secs: f64,
) -> Option<f32> {
    let before = before?;
    if before.start_ticks != now.start_ticks || window_secs <= 0.0 || ticks_per_second == 0 {
        return None;
    }
    // Saturating: a counter that went backwards means a pid reused inside one
    // tick of the same start time, and a negative percentage is worse than a
    // zero one.
    let used = now.cpu_ticks.saturating_sub(before.cpu_ticks) as f64;
    let pct = used / ticks_per_second as f64 / window_secs * 100.0;
    Some(((pct * 10.0).round() / 10.0) as f32)
}

/// Does this process match what the operator typed?
fn matches_search(raw: &RawProcess, user: Option<&str>, unit: Option<&str>, needle: &str) -> bool {
    [Some(raw.comm.as_str()), raw.cmdline.as_deref(), user, unit]
        .into_iter()
        .flatten()
        .any(|field| field.to_lowercase().contains(needle))
}

/// Biggest first, with a deterministic tail.
///
/// An unknown CPU figure sorts below a known zero: "this could not be measured"
/// is not evidence of idleness, and floating it to the top of a page about what
/// is busy would be exactly that claim in reverse.
fn sort_rows(rows: &mut [ProcessView], sort: Sort) {
    let cpu = |row: &ProcessView| row.cpu_pct.unwrap_or(-1.0);
    let memory = |row: &ProcessView| row.memory_bytes.unwrap_or(0);
    rows.sort_by(|a, b| {
        let primary = match sort {
            Sort::Cpu => cpu(b)
                .partial_cmp(&cpu(a))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| memory(b).cmp(&memory(a))),
            Sort::Memory => memory(b).cmp(&memory(a)).then_with(|| {
                cpu(b)
                    .partial_cmp(&cpu(a))
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
        };
        // Pid last, so two otherwise identical rows do not swap places between
        // polls — on a live page that reads as movement that means something.
        primary.then_with(|| a.pid.cmp(&b.pid))
    });
}

/// Fill in the tenant on the rows being returned.
///
/// A process is a tenant's when the account it runs as is a subscription's Linux
/// account, or when systemd put it in that subscription's slice. Both are
/// checked because neither covers everything: a Node app service carries
/// `Slice=unihelm-<user>.slice` and a tenant cron job deliberately does not (see
/// `slices`), while a PHP-FPM worker or an SSH session is attributable by its
/// account alone. Nothing is inferred from a document root — nginx serves every
/// tenant's site as `www-data`, and guessing there would put one customer's name
/// on another customer's traffic.
async fn attribute_tenants(
    ctx: &OpContext,
    rows: &mut [ProcessView],
) -> std::result::Result<(), String> {
    let mut candidates: Vec<String> = rows
        .iter()
        .flat_map(|row| {
            row.user
                .clone()
                .into_iter()
                .chain(row.unit.as_deref().and_then(tenant_slice_user))
        })
        .collect();
    candidates.sort();
    candidates.dedup();

    let mut found: HashMap<String, Tenant> = HashMap::new();
    for candidate in candidates {
        // The unscoped lookup on `Db`, the one `site::provision` uses: it
        // resolves a Linux account to a subscription anywhere on the machine, so
        // it must only ever run for a caller entitled to the whole machine.
        //
        // What used to stand here said this was safe because such a listing "is
        // not one a customer can reach". True of `Role::Customer` and false of
        // `Role::Reseller`, which also holds `server.read` — and that mistake is
        // what handed one reseller another reseller's customers' subscription
        // ids and Linux usernames. The premise is now enforced rather than
        // assumed: `List::run` refuses anything but `TenantScope::Global` before
        // a single row is built (`require_whole_machine_scope`), which is why an
        // admin looking at a slow server can still see whose process is eating
        // it. Do not call this function from anywhere that guard does not cover.
        let subscription = ctx
            .db()
            .subscription_by_linux_user(&candidate)
            .await
            .map_err(|e| {
                format!(
                    "processes could not be matched to their tenants: the panel database did \
                     not answer ({e}). Everything else on this page is current."
                )
            })?;
        if let Some(subscription) = subscription {
            found.insert(
                candidate,
                Tenant {
                    subscription_id: subscription.id,
                    linux_user: subscription.linux_user,
                },
            );
        }
    }

    for row in rows.iter_mut() {
        row.tenant = row
            .user
            .as_deref()
            .and_then(|user| found.get(user))
            .or_else(|| {
                row.unit
                    .as_deref()
                    .and_then(tenant_slice_user)
                    .and_then(|user| found.get(&user))
            })
            .cloned();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// process.kill
// ---------------------------------------------------------------------------

/// What to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSignal {
    /// SIGTERM: asks the process to shut down. The default, and the only one
    /// that lets a database flush or a worker finish the request it is on.
    #[default]
    Term,
    /// SIGKILL: the kernel stops the process where it stands. Nothing is flushed
    /// and nothing is cleaned up.
    Kill,
}

impl KillSignal {
    pub const fn as_str(self) -> &'static str {
        match self {
            KillSignal::Term => "SIGTERM",
            KillSignal::Kill => "SIGKILL",
        }
    }

    const fn number(self) -> libc::c_int {
        match self {
            KillSignal::Term => libc::SIGTERM,
            KillSignal::Kill => libc::SIGKILL,
        }
    }
}

/// `process.kill` — signal one process, having been told which one twice.
pub struct Kill {
    source: Arc<dyn ProcessTable>,
}

impl Kill {
    pub fn live() -> Self {
        Self::over(Arc::new(ProcFs))
    }

    fn over(source: Arc<dyn ProcessTable>) -> Self {
        Self { source }
    }
}

#[derive(Debug, Deserialize)]
pub struct KillInput {
    pub pid: u32,
    /// The command name the caller was shown for this pid.
    ///
    /// Not a checkbox and not a flag. A pid names a process only for as long as
    /// that process lives: the list is a poll, the operator reads a row, and by
    /// the time they press the button the pid may belong to something else
    /// entirely. Echoing back the command and the owner turns that race into a
    /// refusal instead of a kill — and it is why this operation cannot be driven
    /// from a row click, because a client that has not shown a human both fields
    /// has nothing to put in them.
    pub confirm_command: String,
    /// The account the caller was shown as this process's owner. `""` names a
    /// uid with no `passwd` entry, which is what the row shows for one too.
    pub confirm_user: String,
    #[serde(default)]
    pub signal: KillSignal,
    /// The pid of the panel's web process, refused like the agent's own. See
    /// [`PanelProcesses`]: leaving it out only loses a refusal that a
    /// development install would otherwise get, never adds a kill.
    #[serde(default)]
    pub web_pid: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct KillOutput {
    pub pid: u32,
    pub command: String,
    pub user: Option<String>,
    pub signal: &'static str,
    /// The sentence a caller must not be left to infer. A signal is sent, not
    /// obeyed.
    pub note: String,
}

#[async_trait]
impl TypedOperation for Kill {
    type Input = KillInput;
    type Output = KillOutput;

    const NAME: &'static str = "process.kill";
    // The same permission as stopping a service, and for the same reason: both
    // take something off this machine, and neither is scoped to one tenant.
    const PERMISSION: Permission = Permission::ServerManage;
    // A sweep and one syscall. A task would outlive the answer it exists to give
    // and would leave a pid in a log that a later reader takes for a current one.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // `ServerManage` is an administrator's permission today, so this guard
        // refuses nobody `require`. It is here anyway: the pid namespace is the
        // machine's, and the day somebody widens `ServerManage` the answer to
        // "may a tenant signal another tenant's worker" must already be no.
        require_whole_machine_scope(ctx)?;

        // Refused before the table is read, so a caller sending `0` or a value
        // that wraps to `-1` never reaches a lookup that might match something.
        signalable_pid(input.pid)?;

        let sweep = self.source.sweep().await?;
        let target = sweep
            .into_iter()
            .find(|row| row.pid == input.pid)
            .ok_or_else(|| {
                UnihelmError::new(
                    ErrorCode::NotFound,
                    format!(
                        "there is no process {} on this machine. Nothing was signalled — it \
                         had already exited, or the list you are looking at is stale.",
                        input.pid
                    ),
                )
                .with_field("pid")
            })?;

        let user = self.source.user_name(target.uid);
        let unit = target.cgroup.as_deref().and_then(unit_of);
        if let Some(refused) = protection(
            target.pid,
            target.uid,
            user.as_deref(),
            unit.as_deref(),
            &target.comm,
            &PanelProcesses::here(ctx.distro().info.family, input.web_pid),
        ) {
            return Err(
                UnihelmError::new(ErrorCode::Conflict, refused.explanation).with_field("pid")
            );
        }

        // The identity check comes after the refusals and before the signal: a
        // caller who named a protected process learns that it is protected,
        // rather than being sent to refresh a list that will not help them.
        let owner = user.clone().unwrap_or_default();
        if input.confirm_command.trim() != target.comm || input.confirm_user.trim() != owner {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                format!(
                    "pid {} is `{}` owned by `{}`, not `{}` owned by `{}`. Nothing was \
                     signalled. Pids are reused, so the panel signals a process only while the \
                     command and owner it was asked about are still the ones running under \
                     that pid — refresh the list and try again.",
                    target.pid,
                    target.comm,
                    owner,
                    input.confirm_command.trim(),
                    input.confirm_user.trim(),
                ),
            )
            .with_field("confirm_command"));
        }

        ctx.log(format!(
            "sending {} to pid {} ({}) owned by {}",
            input.signal.as_str(),
            target.pid,
            target.comm,
            if owner.is_empty() {
                "an account with no passwd entry"
            } else {
                &owner
            }
        ));
        self.source.signal(target.pid, input.signal)?;

        let note = match input.signal {
            KillSignal::Term => format!(
                "SIGTERM was sent to pid {} (`{}`). That asks the process to shut down; it may \
                 take a moment, and a process that ignores the signal keeps running. Refresh \
                 the list to see whether it is gone.",
                target.pid, target.comm
            ),
            KillSignal::Kill => format!(
                "SIGKILL was sent to pid {} (`{}`). The kernel stops it where it stands — \
                 nothing it held is written out. It leaves the list on the next refresh, \
                 unless it is stuck in uninterruptible I/O, which SIGKILL cannot end either.",
                target.pid, target.comm
            ),
        };

        Ok(KillOutput {
            pid: target.pid,
            command: target.comm,
            user,
            signal: input.signal.as_str(),
            note,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use std::collections::VecDeque;
    use unihelm_core::Role;

    /// A machine whose process table is whatever the test says it is.
    struct FakeTable {
        /// Sweeps, in the order they are handed out. The last one repeats.
        sweeps: Mutex<VecDeque<Vec<RawProcess>>>,
        users: HashMap<u32, String>,
        signalled: Mutex<Vec<(u32, KillSignal)>>,
    }

    impl FakeTable {
        fn with(rows: Vec<RawProcess>) -> Arc<Self> {
            Self::sweeping(vec![rows])
        }

        fn sweeping(sweeps: Vec<Vec<RawProcess>>) -> Arc<Self> {
            Arc::new(Self {
                sweeps: Mutex::new(sweeps.into()),
                users: HashMap::from([
                    (0, "root".to_string()),
                    (33, "www-data".to_string()),
                    (1000, "uh_abc123".to_string()),
                    (1001, "deploy".to_string()),
                ]),
                signalled: Mutex::new(Vec::new()),
            })
        }

        fn signalled(&self) -> Vec<(u32, KillSignal)> {
            self.signalled.lock().expect("test lock").clone()
        }
    }

    #[async_trait]
    impl ProcessTable for FakeTable {
        async fn sweep(&self) -> Result<Vec<RawProcess>> {
            let mut sweeps = self.sweeps.lock().expect("test lock");
            if sweeps.len() > 1 {
                return Ok(sweeps.pop_front().unwrap_or_default());
            }
            Ok(sweeps.front().cloned().unwrap_or_default())
        }

        fn ticks_per_second(&self) -> u64 {
            100
        }

        fn user_name(&self, uid: u32) -> Option<String> {
            self.users.get(&uid).cloned()
        }

        fn signal(&self, pid: u32, signal: KillSignal) -> Result<()> {
            signalable_pid(pid)?;
            self.signalled
                .lock()
                .expect("test lock")
                .push((pid, signal));
            Ok(())
        }
    }

    fn process(pid: u32, comm: &str, uid: u32) -> RawProcess {
        RawProcess {
            pid,
            ppid: 1,
            comm: comm.to_string(),
            cmdline: Some(format!("/usr/bin/{comm}")),
            uid,
            state: 'S',
            rss_anon_bytes: Some(1_048_576),
            rss_bytes: Some(12_582_912),
            cpu: CpuTicks {
                start_ticks: 900,
                cpu_ticks: 0,
            },
            cgroup: None,
        }
    }

    async fn context() -> OpContext {
        let (reg, admin, _) = registry().await;
        OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin))
    }

    fn listing(sort: Sort, limit: Option<usize>, search: Option<&str>) -> ListInput {
        ListInput {
            sort,
            limit,
            search: search.map(str::to_string),
            web_pid: None,
        }
    }

    // -- parsing ------------------------------------------------------------

    /// A real `/proc/<pid>/stat`, with a name containing spaces and a bracket.
    /// Firefox's content processes are called exactly this.
    const STAT_WITH_A_HOSTILE_NAME: &str = "4123 (Web Content (1)) S 4000 4000 0 0 -1 4194304 \
9000 0 12 0 340 60 0 0 20 0 30 0 987654 3000000000 40000 18446744073709551615 1 2 3 4 5 6 7";

    #[test]
    fn a_process_name_with_spaces_and_brackets_does_not_shift_every_later_field() {
        // Splitting this line on whitespace puts `utime` three fields early and
        // reports somebody else's number as Firefox's CPU.
        let stat = parse_stat(STAT_WITH_A_HOSTILE_NAME).expect("a real stat line parses");
        assert_eq!(stat.comm, "Web Content (1)");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.ppid, 4000);
        assert_eq!(stat.cpu.cpu_ticks, 400, "utime 340 + stime 60");
        assert_eq!(stat.cpu.start_ticks, 987_654);
    }

    #[test]
    fn a_truncated_stat_line_is_no_reading_at_all_rather_than_a_partial_one() {
        assert!(parse_stat("4123 (php) S 1").is_none());
        assert!(parse_stat("").is_none());
        assert!(parse_stat("no brackets here").is_none());
    }

    #[test]
    fn memory_is_the_anonymous_resident_set_and_the_reading_says_which_it_is() {
        // The defect this page must not reintroduce. `MemoryCurrent` counts the
        // page cache a unit has touched and `VmRSS` counts every file-backed
        // page a process has mapped; `RssAnon` is the quantity the service view
        // reports as `anon`, and so the only one the two can be read against
        // each other on.
        let status = "Name:\tphp-fpm\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t   30000 kB\n\
                      RssAnon:\t    8000 kB\nRssFile:\t   22000 kB\n";
        let fields = parse_status(status);
        assert_eq!(fields.uid, Some(1000));
        assert_eq!(fields.rss_anon_bytes, Some(8_000 * 1024));
        assert_eq!(fields.rss_bytes, Some(30_000 * 1024));

        let raw = RawProcess {
            rss_anon_bytes: fields.rss_anon_bytes,
            rss_bytes: fields.rss_bytes,
            ..process(4123, "php-fpm", 1000)
        };
        assert_eq!(
            memory_reading(&raw),
            (Some(8_000 * 1024), Some(MemorySource::Anonymous)),
            "the 22 MB of mapped libraries is not memory this process is using"
        );
    }

    #[test]
    fn the_real_uid_is_taken_and_not_whichever_of_the_four_comes_last() {
        // A process that dropped privileges has an effective uid it can change
        // and a real uid it cannot. The owner of the process is the real one.
        let fields = parse_status("Uid:\t1000\t0\t0\t0\n");
        assert_eq!(fields.uid, Some(1000));
    }

    #[tokio::test]
    async fn a_kernel_without_rss_anon_falls_back_and_the_row_says_that_it_fell_back() {
        // A fallback the caller cannot see is the same defect with a different
        // number — the sentence `svc::MemorySource` was written for.
        let ctx = context().await;
        let source = FakeTable::with(vec![RawProcess {
            rss_anon_bytes: None,
            rss_bytes: Some(30_000 * 1024),
            ..process(4123, "php-fpm", 1000)
        }]);
        let out = List::over(source)
            .run(&ctx, listing(Sort::Cpu, None, None))
            .await
            .unwrap();

        let row = &out.processes[0];
        assert_eq!(row.memory_bytes, Some(30_000 * 1024));
        assert_eq!(row.memory_source, Some(MemorySource::Resident));
        let json = serde_json::to_value(row).unwrap();
        assert_eq!(json["memory_source"], "resident");
    }

    #[test]
    fn a_memory_line_in_an_unexpected_unit_is_not_read_as_kilobytes() {
        assert_eq!(kib_value("\t   30000 kB"), Some(30_000 * 1024));
        assert_eq!(kib_value("\t   30000 MB"), None);
        assert_eq!(kib_value("\t   30000"), None);
        assert_eq!(kib_value("\tnonsense kB"), None);
    }

    #[test]
    fn a_command_line_that_was_cut_says_so() {
        let long = "x".repeat(MAX_CMDLINE_CHARS + 50);
        let cut = join_cmdline(&long).expect("a long command line still has a value");
        assert!(cut.ends_with('…'), "a silent truncation claims to be whole");
        assert_eq!(cut.chars().count(), MAX_CMDLINE_CHARS + 1);

        assert_eq!(
            join_cmdline("/usr/bin/php\0-f\0app.php\0"),
            Some("/usr/bin/php -f app.php".into())
        );
        assert_eq!(
            join_cmdline(""),
            None,
            "a kernel thread has no command line"
        );
        assert_eq!(join_cmdline("\0\0"), None);
    }

    #[test]
    fn a_cgroup_path_yields_its_unit_on_both_hierarchies() {
        assert_eq!(
            cgroup_path("0::/system.slice/nginx.service\n").as_deref(),
            Some("/system.slice/nginx.service")
        );
        // cgroup v1 writes a line per controller; only the systemd one names the
        // unit.
        assert_eq!(
            cgroup_path("12:pids:/user.slice\n1:name=systemd:/system.slice/nginx.service\n")
                .as_deref(),
            Some("/system.slice/nginx.service")
        );
        assert_eq!(cgroup_path(""), None);

        assert_eq!(
            unit_of("/system.slice/nginx.service").as_deref(),
            Some("nginx.service")
        );
        assert_eq!(
            unit_of("/user.slice/user-1000.slice/session-3.scope").as_deref(),
            Some("session-3.scope")
        );
        // Nothing but slices: the deepest one still says where the process is.
        assert_eq!(
            unit_of("/unihelm-uh_abc123.slice").as_deref(),
            Some("unihelm-uh_abc123.slice")
        );
        assert_eq!(unit_of("/"), None);
    }

    #[test]
    fn a_tenant_slice_is_read_back_through_systemds_own_escaping() {
        // `slices::slice_file_name` escapes `-` to `\x2d`, because a bare `-` in
        // a slice name is a nesting level. Reading the name back without
        // unescaping it attributes `uh-abc`'s processes to nobody.
        assert_eq!(
            tenant_slice_user("/unihelm-uh_abc123.slice/unihelm-app-uh_abc123-blog.service")
                .as_deref(),
            Some("uh_abc123")
        );
        assert_eq!(
            tenant_slice_user("/unihelm-uh\\x2dabc.slice").as_deref(),
            Some("uh-abc")
        );
        assert_eq!(tenant_slice_user("/system.slice/nginx.service"), None);
    }

    // -- the CPU window -----------------------------------------------------

    #[test]
    fn cpu_is_a_rate_over_the_window_and_not_an_average_since_boot() {
        let before = CpuTicks {
            start_ticks: 900,
            cpu_ticks: 1_000,
        };
        // Half a core for one second: 50 ticks at 100 ticks a second.
        let now = CpuTicks {
            start_ticks: 900,
            cpu_ticks: 1_050,
        };
        assert_eq!(cpu_percent(Some(&before), now, 100, 1.0), Some(50.0));
        // The same counters over five seconds are a fifth of the load.
        assert_eq!(cpu_percent(Some(&before), now, 100, 5.0), Some(10.0));
    }

    #[test]
    fn a_process_with_nothing_to_measure_against_reports_unknown_and_never_zero() {
        let now = CpuTicks {
            start_ticks: 900,
            cpu_ticks: 5_000,
        };
        // Appeared after the baseline sample.
        assert_eq!(cpu_percent(None, now, 100, 1.0), None);
        // The pid was reused: same number, different process.
        let recycled = CpuTicks {
            start_ticks: 100,
            cpu_ticks: 4_000,
        };
        assert_eq!(cpu_percent(Some(&recycled), now, 100, 1.0), None);
        // A window of nothing divides by nothing.
        assert_eq!(cpu_percent(Some(&now), now, 100, 0.0), None);
    }

    #[tokio::test]
    async fn the_first_listing_takes_its_own_second_sample_rather_than_a_lifetime_average() {
        // A process that burned an hour of CPU last night and is idle now would
        // sit at the top of a "what is using this server" page for the rest of
        // its life, if the column were total time over lifetime.
        let ctx = context().await;
        let idle_but_old = RawProcess {
            cpu: CpuTicks {
                start_ticks: 100,
                cpu_ticks: 360_000,
            },
            ..process(4123, "java", 1000)
        };
        let source = FakeTable::sweeping(vec![vec![idle_but_old.clone()], vec![idle_but_old]]);
        let out = List::over(source)
            .run(&ctx, listing(Sort::Cpu, None, None))
            .await
            .unwrap();

        assert_eq!(out.processes[0].cpu_pct, Some(0.0));
        assert!(
            out.cpu_window_ms >= SETTLE.as_millis() as u64,
            "the answer has to say how far apart the two samples were: {}",
            out.cpu_window_ms
        );
    }

    // -- the listing --------------------------------------------------------

    #[tokio::test]
    async fn the_busiest_process_is_first_and_an_unmeasurable_one_never_outranks_an_idle_one() {
        let ctx = context().await;
        let busy = process(300, "busy", 1000);
        let idle = process(100, "idle", 1000);
        let recycled = RawProcess {
            cpu: CpuTicks {
                start_ticks: 100,
                cpu_ticks: 50,
            },
            ..process(400, "recycled", 1000)
        };

        let first = vec![busy.clone(), idle.clone(), recycled];
        let second = vec![
            RawProcess {
                cpu: CpuTicks {
                    start_ticks: 900,
                    cpu_ticks: 500,
                },
                ..busy
            },
            idle,
            // Same pid, different process: it started at a different time.
            RawProcess {
                cpu: CpuTicks {
                    start_ticks: 999,
                    cpu_ticks: 3,
                },
                ..process(400, "recycled", 1000)
            },
        ];
        let source = FakeTable::sweeping(vec![first, second]);
        let out = List::over(source)
            .run(&ctx, listing(Sort::Cpu, None, None))
            .await
            .unwrap();

        let order: Vec<u32> = out.processes.iter().map(|p| p.pid).collect();
        assert_eq!(order, [300, 100, 400], "busiest first, unmeasured last");
        assert!(out.processes[0].cpu_pct.unwrap_or(0.0) > 0.0);
        assert_eq!(out.processes[1].cpu_pct, Some(0.0));
        assert_eq!(
            out.processes[2].cpu_pct, None,
            "a pid that was reused between the samples is unknown, not idle"
        );
    }

    #[tokio::test]
    async fn sorting_by_memory_puts_the_largest_first() {
        let ctx = context().await;
        let source = FakeTable::with(vec![
            process(100, "small", 1000),
            RawProcess {
                rss_anon_bytes: Some(4_000_000_000),
                ..process(200, "large", 1000)
            },
        ]);
        let out = List::over(source)
            .run(&ctx, listing(Sort::Memory, None, None))
            .await
            .unwrap();

        assert_eq!(out.processes[0].pid, 200);
        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["sort"], "memory");
    }

    #[tokio::test]
    async fn a_search_filters_the_whole_machine_before_the_limit_cuts_the_list() {
        // Filtering the forty rows that came back would report "no matches" for
        // a process sitting at rank two hundred.
        let ctx = context().await;
        let mut rows: Vec<RawProcess> =
            (0..60).map(|i| process(1000 + i, "filler", 1000)).collect();
        rows.push(RawProcess {
            cmdline: Some("/usr/bin/php /home/uh_abc123/sites/shop/cron.php".into()),
            ..process(9999, "php", 1000)
        });

        let source = FakeTable::with(rows);
        let out = List::over(source)
            .run(&ctx, listing(Sort::Cpu, Some(5), Some("CRON.php")))
            .await
            .unwrap();

        assert_eq!(out.total, 61, "the machine's whole table is still counted");
        assert_eq!(out.matched, 1);
        assert_eq!(out.processes.len(), 1);
        assert_eq!(out.processes[0].pid, 9999);
    }

    #[tokio::test]
    async fn the_answer_states_the_interval_it_expects_to_be_asked_again_on() {
        let ctx = context().await;
        let out = List::over(FakeTable::with(vec![process(100, "sh", 1000)]))
            .run(&ctx, listing(Sort::Cpu, None, None))
            .await
            .unwrap();
        assert_eq!(
            out.refresh_seconds, REFRESH_SECONDS,
            "the client must not have to invent a poll interval"
        );
        assert!(out.cpu_cores >= 1);
    }

    #[tokio::test]
    async fn a_row_carries_the_refusal_before_anybody_presses_anything() {
        // A page can only disable a button honestly if the reason travels with
        // the row, and it has to be the reason the kill itself would give.
        let ctx = context().await;
        let source = FakeTable::with(vec![
            process(1, "systemd", 0),
            process(500, "nginx", 33),
            process(900, "php", 1000),
        ]);
        let out = List::over(source)
            .run(&ctx, listing(Sort::Cpu, None, None))
            .await
            .unwrap();

        let by_pid = |pid: u32| {
            out.processes
                .iter()
                .find(|p| p.pid == pid)
                .expect("row present")
        };
        assert_eq!(
            by_pid(1).protected.as_ref().map(|p| p.rule),
            Some(ProtectionRule::Init)
        );
        assert_eq!(
            by_pid(500).protected.as_ref().map(|p| p.rule),
            Some(ProtectionRule::SystemAccount)
        );
        assert!(by_pid(900).protected.is_none(), "a tenant's own process");
    }

    #[tokio::test]
    async fn a_tenants_process_is_attributed_to_their_subscription_and_nginx_is_not() {
        let (reg, admin, customer) = registry().await;
        let subscription = reg
            .services()
            .db
            .create_subscription(customer)
            .await
            .unwrap();
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));

        let source = Arc::new(FakeTable {
            sweeps: Mutex::new(
                vec![vec![process(900, "php", 1000), process(500, "nginx", 33)]].into(),
            ),
            users: HashMap::from([
                (33, "www-data".to_string()),
                (1000, subscription.linux_user.clone()),
            ]),
            signalled: Mutex::new(Vec::new()),
        });

        let out = List::over(source)
            .run(&ctx, listing(Sort::Cpu, None, None))
            .await
            .unwrap();
        let tenant = out
            .processes
            .iter()
            .find(|p| p.pid == 900)
            .and_then(|p| p.tenant.clone())
            .expect("a process running as a tenant's account belongs to that tenant");
        assert_eq!(tenant.subscription_id, subscription.id);
        assert_eq!(tenant.linux_user, subscription.linux_user);

        assert!(
            out.processes
                .iter()
                .find(|p| p.pid == 500)
                .and_then(|p| p.tenant.as_ref())
                .is_none(),
            "nginx serves every tenant as www-data; naming one of them would be a guess"
        );
        assert!(out.tenant_lookup_error.is_none());
    }

    #[tokio::test]
    async fn a_reseller_is_not_shown_another_resellers_command_lines() {
        // The 0.8.0 release blocker. `Role::Reseller` holds `server_read` by
        // default and the Processes link is in the sidebar for everyone, so this
        // whole table — verbatim argv, other tenants' Linux accounts, and the
        // subscription id behind each of them — was one ordinary GET away from
        // every reseller on a shared machine.
        //
        // Seeded so that the leak is concrete: the row at pid 900 runs as a
        // subscription that belongs to nobody in the reseller's tree, and its
        // command line carries a password the way a real one does.
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let subscription = db.create_subscription(customer).await.unwrap();
        let reseller = db
            .users(&unihelm_core::TenantScope::Global)
            .create(unihelm_db::users::NewUser {
                role: Role::Reseller,
                email: unihelm_core::Email::parse("peer@example.com").unwrap(),
                username: unihelm_core::Username::parse("peer").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();

        let secret = "/usr/bin/mysql -uroot -pTHE-ROOT-PASSWORD";
        let rows = vec![RawProcess {
            cmdline: Some(secret.to_string()),
            ..process(900, "mysql", 1000)
        }];
        let source = Arc::new(FakeTable {
            sweeps: Mutex::new(vec![rows.clone()].into()),
            users: HashMap::from([(1000, subscription.linux_user.clone())]),
            signalled: Mutex::new(Vec::new()),
        });

        // The seeded table first, because that is where the leak is visible: a
        // reseller with no claim on this subscription asking with the search
        // term that used to enumerate every tenant account on the box. Before
        // the guard this returned `Ok` with the row below — argv and all.
        for tenant in [
            auth_for(reseller.id, Role::Reseller),
            auth_for(customer, Role::Customer),
        ] {
            let ctx = OpContext::new(reg.services().clone(), tenant);
            let err = List::over(source.clone())
                .run(&ctx, listing(Sort::Cpu, None, Some("uh_")))
                .await
                .expect_err("no search term makes this table theirs");
            assert_eq!(err.code, ErrorCode::TenantScopeViolation);
            assert!(
                err.detail.contains("whole machine"),
                "the refusal has to say whose table this is: {}",
                err.detail
            );
        }

        // And through `dispatch`, the hop the HTTP route takes: it re-derives
        // the caller from the users table and checks the permission — a
        // permission this reseller genuinely holds, which is why the refusal
        // cannot come from there. `dispatch` builds `List` over the live `/proc`
        // reader, so before the guard this got as far as sweeping the real
        // machine; the assertion is that it no longer gets that far.
        assert!(auth_for(reseller.id, Role::Reseller).has(Permission::ServerRead));
        let err = reg
            .dispatch(
                "process.list",
                &auth_for(reseller.id, Role::Reseller),
                serde_json::json!({}),
                None,
            )
            .await
            .expect_err("a reseller is a tenant, not the operator of this machine");
        assert_eq!(err.code, ErrorCode::TenantScopeViolation);

        // And the operator still gets the answer the page exists for — argv,
        // the tenant behind it, and all of it.
        let admin_ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let out = List::over(source)
            .run(&admin_ctx, listing(Sort::Cpu, None, None))
            .await
            .unwrap();
        let row = out
            .processes
            .iter()
            .find(|p| p.pid == 900)
            .expect("the operator sees the machine");
        assert_eq!(row.cmdline.as_deref(), Some(secret));
        assert_eq!(
            row.tenant.as_ref().map(|t| t.subscription_id),
            Some(subscription.id)
        );
    }

    #[tokio::test]
    async fn a_tenant_cannot_signal_a_process_either() {
        // `ServerManage` already keeps every tenant out of `process.kill`, so
        // this asserts the second lock rather than the first: if that permission
        // is ever widened, the pid namespace is still the machine's.
        let (reg, _admin, customer) = registry().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(customer, Role::Customer));
        let source = FakeTable::with(vec![process(900, "php", 1000)]);
        let err = Kill::over(source.clone())
            .run(&ctx, kill_input(900, "php", "uh_abc123"))
            .await
            .expect_err("a tenant does not signal processes on a shared machine");

        assert_eq!(err.code, ErrorCode::TenantScopeViolation);
        assert!(
            source.signalled().is_empty(),
            "a refused caller must not have signalled anything"
        );
    }

    // -- the kill -----------------------------------------------------------

    fn kill_input(pid: u32, command: &str, user: &str) -> KillInput {
        KillInput {
            pid,
            confirm_command: command.to_string(),
            confirm_user: user.to_string(),
            signal: KillSignal::Term,
            web_pid: None,
        }
    }

    #[tokio::test]
    async fn pid_one_is_refused_and_the_refusal_says_what_it_is() {
        let ctx = context().await;
        let source = FakeTable::with(vec![process(1, "systemd", 0)]);
        let err = Kill::over(source.clone())
            .run(&ctx, kill_input(1, "systemd", "root"))
            .await
            .expect_err("killing init panics the kernel");

        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("pid 1"), "{}", err.detail);
        assert!(err.detail.contains("kernel"), "{}", err.detail);
        assert!(source.signalled().is_empty());
    }

    #[tokio::test]
    async fn the_panels_own_units_are_refused_by_unit_name() {
        let ctx = context().await;
        // Owned by an ordinary account on purpose: the uid rule must not be what
        // is doing the work here. The cgroup file is parsed on the way in, so
        // the fake carries the path `cgroup_path` would already have produced.
        let source = FakeTable::with(vec![RawProcess {
            cgroup: Some("/system.slice/unihelm-web.service".into()),
            ..process(700, "unihelm-web", 1001)
        }]);
        let err = Kill::over(source.clone())
            .run(&ctx, kill_input(700, "unihelm-web", "deploy"))
            .await
            .expect_err("the panel must not stop the panel");

        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("unihelm-web.service"), "{}", err.detail);
        assert!(source.signalled().is_empty());
    }

    #[tokio::test]
    async fn the_agent_and_the_web_process_are_refused_by_pid_where_there_is_no_unit() {
        // A development install runs both outside systemd, so neither has a
        // cgroup for the unit rule to match, and both may be an ordinary
        // account's — which is every rule above this one missing at once.
        let ctx = context().await;
        let agent = std::process::id();
        let source = FakeTable::with(vec![
            process(agent, "unihelm-agentd", 1001),
            process(7001, "unihelm-web", 1001),
        ]);

        let err = Kill::over(source.clone())
            .run(&ctx, kill_input(agent, "unihelm-agentd", "deploy"))
            .await
            .expect_err("the agent must not be asked to kill itself");
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("agent itself"), "{}", err.detail);

        let err = Kill::over(source.clone())
            .run(
                &ctx,
                KillInput {
                    web_pid: Some(7001),
                    ..kill_input(7001, "unihelm-web", "deploy")
                },
            )
            .await
            .expect_err("the web process is the surface the request arrived on");
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("web process"), "{}", err.detail);
        assert!(source.signalled().is_empty());

        // And the row says so before anybody presses anything.
        let out = List::over(source)
            .run(
                &ctx,
                ListInput {
                    web_pid: Some(7001),
                    ..listing(Sort::Cpu, None, None)
                },
            )
            .await
            .unwrap();
        for pid in [agent, 7001] {
            assert_eq!(
                out.processes
                    .iter()
                    .find(|p| p.pid == pid)
                    .and_then(|p| p.protected.as_ref())
                    .map(|p| p.rule),
                Some(ProtectionRule::Panel),
                "pid {pid}"
            );
        }
    }

    #[tokio::test]
    async fn a_system_account_is_refused_and_the_refusal_names_it_and_the_way_out() {
        let ctx = context().await;
        let source = FakeTable::with(vec![RawProcess {
            cgroup: Some("/system.slice/nginx.service".into()),
            ..process(500, "nginx", 33)
        }]);
        let err = Kill::over(source.clone())
            .run(&ctx, kill_input(500, "nginx", "www-data"))
            .await
            .expect_err("killing an nginx worker takes sites down and restarts nothing");

        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("www-data"), "{}", err.detail);
        assert!(err.detail.contains("nginx.service"), "{}", err.detail);
        assert!(source.signalled().is_empty());

        // And root, which is the same rule.
        let root = FakeTable::with(vec![process(600, "sshd", 0)]);
        assert_eq!(
            Kill::over(root)
                .run(&ctx, kill_input(600, "sshd", "root"))
                .await
                .expect_err("root is a system account")
                .code,
            ErrorCode::Conflict
        );
    }

    #[tokio::test]
    async fn a_pid_that_would_reach_the_kernel_as_a_process_group_is_refused_before_any_lookup() {
        // `kill(0, …)` is every process in this process group and `kill(-1, …)`
        // is every process on the machine. `4294967295` is how the second one
        // arrives through JSON.
        let ctx = context().await;
        for pid in [0, u32::MAX, i32::MAX as u32 + 1] {
            let source = FakeTable::with(vec![process(pid, "anything", 1000)]);
            let err = Kill::over(source.clone())
                .run(&ctx, kill_input(pid, "anything", "uh_abc123"))
                .await
                .expect_err("a process-group target must never reach kill(2)");
            assert_eq!(err.code, ErrorCode::InvalidInput, "pid {pid}");
            assert_eq!(err.field.as_deref(), Some("pid"));
            assert!(source.signalled().is_empty(), "pid {pid}");
        }
    }

    #[tokio::test]
    async fn a_confirmation_naming_a_different_process_is_refused_because_pids_are_reused() {
        // The race this exists for: the operator read the row, the process
        // exited, the pid came back as something else, and the click arrives.
        let ctx = context().await;
        let source = FakeTable::with(vec![process(4123, "postgres", 1001)]);
        let err = Kill::over(source.clone())
            .run(&ctx, kill_input(4123, "php", "uh_abc123"))
            .await
            .expect_err("the pid no longer names the process the operator agreed to");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("confirm_command"));
        assert!(err.detail.contains("postgres"), "{}", err.detail);
        assert!(err.detail.contains("php"), "{}", err.detail);
        assert!(source.signalled().is_empty());

        // The owner is half of the identity: same command, different account.
        let err = Kill::over(source.clone())
            .run(&ctx, kill_input(4123, "postgres", "somebody-else"))
            .await
            .expect_err("the owner is part of what was agreed to");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(source.signalled().is_empty());
    }

    #[tokio::test]
    async fn a_pid_that_has_already_gone_is_reported_as_gone_and_nothing_is_signalled() {
        let ctx = context().await;
        let source = FakeTable::with(vec![process(4123, "php", 1000)]);
        let err = Kill::over(source.clone())
            .run(&ctx, kill_input(9999, "php", "uh_abc123"))
            .await
            .expect_err("a pid with no process behind it is not a kill");

        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(err.detail.contains("9999"), "{}", err.detail);
        assert!(source.signalled().is_empty());
    }

    #[tokio::test]
    async fn a_confirmed_kill_signals_the_process_and_does_not_claim_it_exited() {
        let ctx = context().await;
        let source = FakeTable::with(vec![process(4123, "php", 1000)]);
        let out = Kill::over(source.clone())
            // Surrounding whitespace forgiven, as `server::confirms_hostname`
            // forgives it: a pasted value carries it, and refusing that is a
            // puzzle rather than a guard.
            .run(&ctx, kill_input(4123, " php ", "uh_abc123\n"))
            .await
            .unwrap();

        assert_eq!(source.signalled(), [(4123, KillSignal::Term)]);
        assert_eq!(out.signal, "SIGTERM");
        assert_eq!(out.user.as_deref(), Some("uh_abc123"));
        assert!(
            out.note.contains("may take a moment"),
            "a signal is sent, not obeyed: {}",
            out.note
        );
        assert!(
            !out.note.contains("has been stopped"),
            "the panel must not report an exit it did not observe: {}",
            out.note
        );
    }

    #[tokio::test]
    async fn a_forced_kill_says_what_it_costs_and_what_it_still_cannot_end() {
        let ctx = context().await;
        let source = FakeTable::with(vec![process(4123, "php", 1000)]);
        let out = Kill::over(source.clone())
            .run(
                &ctx,
                KillInput {
                    signal: KillSignal::Kill,
                    ..kill_input(4123, "php", "uh_abc123")
                },
            )
            .await
            .unwrap();

        assert_eq!(source.signalled(), [(4123, KillSignal::Kill)]);
        assert_eq!(out.signal, "SIGKILL");
        assert!(out.note.contains("nothing it held is written out"));
        assert!(out.note.contains("uninterruptible I/O"));
    }

    #[tokio::test]
    async fn reading_the_process_table_needs_less_than_signalling_something_in_it() {
        // Split for the reason `server.reboot.status` is split from
        // `server.reboot`: the person who needs to see what is eating the
        // machine is not always the account allowed to kill it.
        assert_eq!(<List as TypedOperation>::PERMISSION, Permission::ServerRead);
        assert_eq!(
            <Kill as TypedOperation>::PERMISSION,
            Permission::ServerManage
        );
    }

    #[tokio::test]
    async fn neither_operation_becomes_a_task() {
        // A task id for a kill would leave a pid in a log that a later reader
        // takes for a current one.
        assert!(!<List as TypedOperation>::EXECUTION.is_task());
        assert!(!<Kill as TypedOperation>::EXECUTION.is_task());
    }
}
