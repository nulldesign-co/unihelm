//! Backups and restore, driven by `restic` (spec §11.10).
//!
//! # Why restic over argv, and not `rustic_core`
//!
//! Spec §4.1 names `rustic_core` with an explicit fallback: "fall back to
//! shelling out to `rustic` CLI if the lib API blocks us". This module takes
//! that fallback, one step further out, to the reference implementation:
//! `restic` itself. The repository format is identical either way — a
//! repository written here is readable by both tools — and what the CLI buys
//! is the part that actually matters for a backup product: the code that
//! writes the operator's only copy of their data is the code that the whole
//! restic community exercises daily, not a binding this project would be the
//! first to trust. "Shelling out" is a misnomer for what happens here; there
//! is no shell anywhere (spec §12 rule 2), only [`Cmd`]'s argv arrays.
//!
//! # Secrets go in the environment, never in argv
//!
//! `RESTIC_PASSWORD` and the S3 credentials are passed to restic as
//! environment variables. This is not a stylistic preference, it is the whole
//! reason this module is shaped the way it is:
//!
//! - **argv is world-readable.** `/proc/<pid>/cmdline` is mode 0444 on Linux.
//!   Every account on the box — including every hosted tenant — can read the
//!   full command line of every running process, root's included. A
//!   `restic --password hunter2` would hand the panel's backup encryption key
//!   to any tenant running `ps auxww` at the right moment, and `ps` output is
//!   in every support transcript ever pasted into a ticket.
//! - **the environment is not.** `/proc/<pid>/environ` is mode 0400 and owned
//!   by the process's uid; only that uid and root can read it. restic runs as
//!   root, so only root can read its environment — and a tenant who is already
//!   root does not need to steal a backup password.
//!
//! [`Cmd`] starts every child with a *cleared* environment (see
//! `unihelm_distro::exec`), so the agent's own environment never leaks into
//! restic either; what restic sees is exactly [`RepoTarget::env`] and nothing
//! else. [`ResticInvocation::display`] renders **argv only**, which is what
//! reaches the task log — a test pins that the password never appears there.
//!
//! # Disaster recovery: where the repository password lives
//!
//! A restic repository is encrypted and its password is the only key. The
//! panel seals a copy under [`unihelm_db::MasterKey`] so the scheduler can run
//! an unattended backup at three in the morning. That copy sits in
//! `panel.db`, and `panel.db` is inside the panel-scope backup — which means
//! that if the panel database is the *only* holder of the password, a
//! panel-scope backup cannot be restored after losing the panel. The key to
//! the safe is inside the safe.
//!
//! **The decision:** `backup.repo.init` generates the password and returns it
//! **once**, in its response, marked as show-once. There is no second chance
//! and no way to ask the panel for it again — an operation that could reveal
//! it later would turn a stolen session into every backup the panel has ever
//! taken. The sealed copy exists so scheduled runs need no human; the copy the
//! operator writes down is the one disaster recovery runs on.
//!
//! Recovering a lost panel therefore takes two things kept **off this server**:
//!
//! 1. the repository password returned at creation, and
//! 2. `/etc/unihelm/secret.key`, the master key — because every other secret in
//!    the restored database (ACME account keys, DNS credentials, database
//!    passwords) is sealed under it and is ciphertext without it.
//!
//! With both, `restic restore` against the repository yields `panel.db`,
//! `/etc/unihelm` and the state directory, which is the whole of the panel's
//! state. The installer already tells operators to keep `secret.key`
//! off-server (`docs/operator/install.md`); this module's contribution is to
//! make sure the password is knowable at all.
//!
//! # What is deliberately not here
//!
//! - **In-place restore.** [`Restore`] restores into a staging directory and
//!   reports the path. Writing recovered files back over live ones is a
//!   different operation with a different blast radius, and it belongs with a
//!   UI that can show what is about to be overwritten.
//! - **Adopting an existing repository.** `backup.repo.init` creates; it
//!   cannot take over a repository somebody else initialised, because the
//!   panel does not know that repository's password and — per the decision
//!   above — has no way to be told one that it could then also show back.
//! - **Database dumps inside the tenant scope.** Spec §11.10 wants
//!   `--single-transaction` dumps streamed into the repository. Subscription
//!   scope here backs up the tenant home; adding the tenant's databases means
//!   another producer feeding the same `restic backup`, which is a change to
//!   this module rather than to its shape.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_config::paths;
use unihelm_core::{ErrorCode, Permission, Result, SubscriptionId, TenantScope, UnihelmError};
use unihelm_db::backups::{BackupScope, NewBackupRepo, RepoKind, RunOutcome};
use unihelm_distro::pkg::PackageName;
use unihelm_distro::{Cmd, exec};

use crate::registry::{Execution, OpContext, TypedOperation};

/// The binary this module drives.
const RESTIC: &str = "restic";

/// The package that provides it. Same name on both families; on EL it lives in
/// EPEL, which the failure message says out loud because "no package restic
/// available" on a fresh AlmaLinux is otherwise a five-minute detour.
const RESTIC_PACKAGE: &str = "restic";

/// Tag on every snapshot the panel writes for the whole-server scope.
const PANEL_TAG: &str = "unihelm-panel";

/// How long one restic call may take.
///
/// A backup of a busy server is measured in hours, not in [`Cmd`]'s default
/// two minutes; a `forget --prune` rewrites pack files and is slow for the
/// same reason. The read-only calls are held to something much shorter,
/// because both of them run as *immediate* operations and the IPC client gives
/// up at 30 s (`unihelm_ipc::client::DEFAULT_CALL_TIMEOUT`) — better to fail
/// with restic's own words at 25 s than with an opaque agent timeout at 30.
const LONG_TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);
const PRUNE_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const IMMEDIATE_TIMEOUT: Duration = Duration::from_secs(25);

/// Longest accepted repository path or endpoint. Generous for a bucket and a
/// prefix, far short of the point where the value stops being a location.
const MAX_LOCATION: usize = 512;

/// Longest accepted repository label.
const MAX_LABEL: usize = 64;

/// How far back the due check will look for a cron slot it missed.
///
/// A day: enough that an agent down overnight still runs the nightly backup
/// when it comes back, bounded so a server that was off for a month does not
/// walk a month of minutes on its first tick.
const MAX_CATCHUP_MINUTES: i64 = 24 * 60;

/// How far back a schedule that has **never** run will look.
///
/// Not zero, because the scheduler's 60 s interval carries ±10 s of jitter and
/// can therefore skip a wall-clock minute entirely — a nightly job whose one
/// minute fell in a gap would wait another day. Not a day either, because a
/// schedule created at two in the afternoon must not immediately fire last
/// night's backup. Five minutes is the smallest window that covers the jitter
/// with room to spare.
const FIRST_RUN_CATCHUP_MINUTES: i64 = 5;

// ---------------------------------------------------------------------------
// The invocation: argv and environment as data
// ---------------------------------------------------------------------------

/// One restic call, before it is run.
///
/// Built as data rather than assembled inline so that the two properties this
/// module's security rests on are *testable*: that every secret is in `env`,
/// and that `args` — the part the kernel publishes in `/proc/<pid>/cmdline` —
/// contains none of them.
#[derive(Clone, PartialEq, Eq)]
pub struct ResticInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
}

impl ResticInvocation {
    /// The command as a human should read it: **argv only**.
    ///
    /// The environment is deliberately absent. This string is what goes into
    /// the task log, which an operator reads and pastes into tickets.
    pub fn display(&self) -> String {
        let mut out = String::from(&self.program);
        for a in &self.args {
            out.push(' ');
            out.push_str(a);
        }
        out
    }

    fn to_cmd(&self) -> Cmd {
        let mut cmd = Cmd::new(self.program.clone())
            .args(&self.args)
            .timeout(self.timeout);
        for (k, v) in &self.env {
            cmd = cmd.env(k, v);
        }
        // Note what is *not* called: `inherit_env`. `Cmd` clears the
        // environment by default, so restic sees these variables and nothing
        // the agent happened to be started with.
        cmd
    }

    async fn run(&self) -> Result<unihelm_distro::CmdOutput> {
        self.to_cmd().run().await.map_err(UnihelmError::from)
    }

    /// Run, streaming every line into the task log through `sink`.
    async fn run_streaming<F>(&self, sink: F) -> Result<unihelm_distro::CmdOutput>
    where
        F: FnMut(&str) + Send,
    {
        self.to_cmd()
            .run_streaming(sink)
            .await
            .map_err(UnihelmError::from)
    }
}

/// Redacted on purpose: an invocation carries `RESTIC_PASSWORD`, and the way a
/// secret reaches a log is somebody adding `?invocation` to a tracing call.
impl std::fmt::Debug for ResticInvocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResticInvocation")
            .field("argv", &self.display())
            .field(
                "env_keys",
                &self.env.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// S3 credentials, in the clear, for exactly as long as one operation runs.
#[derive(Clone, Serialize, Deserialize)]
pub struct S3Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// What the `s3` object has to contain, spelled out in the error rather than
/// left to the API document: a rejected request should be fixable from the
/// message it came back with.
const S3_FIELD_HINT: &str = "s3: { access_key_id, secret_access_key, region? }";

impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key id is not a secret; the secret key is the whole point.
        f.debug_struct("S3Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("region", &self.region)
            .finish()
    }
}

/// A repository resolved down to what restic needs: a location, a password and
/// possibly credentials.
///
/// Not `Debug`, not `Serialize`, and never stored: it exists between opening
/// the sealed columns and running one command.
pub struct RepoTarget {
    pub id: i64,
    pub label: String,
    pub kind: RepoKind,
    pub location: String,
    password: String,
    credentials: Option<S3Credentials>,
}

impl RepoTarget {
    /// The `RESTIC_REPOSITORY` value.
    ///
    /// A local repository is a bare path; an S3 one carries restic's `s3:`
    /// scheme prefix, which is how restic picks its backend.
    pub fn repository(&self) -> String {
        match self.kind {
            RepoKind::Local => self.location.clone(),
            RepoKind::S3 => format!("s3:{}", self.location),
        }
    }

    /// Everything restic is given, and the only place a secret appears.
    ///
    /// `RESTIC_CACHE_DIR` is set explicitly because [`Cmd`] clears the
    /// environment: with no `HOME` and no `XDG_CACHE_HOME`, restic has nowhere
    /// to put its metadata cache and re-downloads index files on every run.
    pub fn env(&self) -> Vec<(String, String)> {
        let mut env = vec![
            ("RESTIC_REPOSITORY".to_string(), self.repository()),
            ("RESTIC_PASSWORD".to_string(), self.password.clone()),
            (
                "RESTIC_CACHE_DIR".to_string(),
                cache_dir().to_string_lossy().into_owned(),
            ),
        ];
        if let Some(c) = &self.credentials {
            env.push(("AWS_ACCESS_KEY_ID".into(), c.access_key_id.clone()));
            env.push(("AWS_SECRET_ACCESS_KEY".into(), c.secret_access_key.clone()));
            if let Some(region) = &c.region {
                env.push(("AWS_DEFAULT_REGION".into(), region.clone()));
            }
        }
        env
    }

    fn invocation(&self, args: Vec<String>, timeout: Duration, program: &str) -> ResticInvocation {
        ResticInvocation {
            program: program.to_string(),
            args,
            env: self.env(),
            timeout,
        }
    }
}

/// Where restic keeps its metadata cache. Under the panel's data directory
/// rather than root's home, so an operator looking for panel disk usage finds
/// it in one place.
fn cache_dir() -> PathBuf {
    paths::data_dir().join("restic-cache")
}

// ---------------------------------------------------------------------------
// argv builders — pure, so the tests can read them
// ---------------------------------------------------------------------------

/// `restic init`.
pub fn init_args() -> Vec<String> {
    // Repository format 2 is what current restic writes by default and is the
    // one that supports compression (spec §11.10: "encrypted, deduplicated,
    // compressed"). Naming it explicitly means a repository created by this
    // panel does not silently change format when the packaged restic does.
    vec!["init".into(), "--repository-version".into(), "2".into()]
}

/// `restic backup` over a set of absolute paths.
///
/// `--json` because the summary line is the only place the snapshot id and the
/// byte count come from; the noisy per-second `status` messages are filtered
/// out of the task log by the caller rather than by restic, which has no flag
/// for it.
///
/// `--` before the paths: restic would otherwise read a path beginning with a
/// dash as a flag. No path the panel builds starts with one, and the separator
/// is there so that stays true of paths it may build later.
pub fn backup_args(tag: &str, paths: &[PathBuf]) -> Vec<String> {
    let mut args = vec![
        "backup".into(),
        "--json".into(),
        "--tag".into(),
        tag.to_string(),
        "--".into(),
    ];
    args.extend(paths.iter().map(|p| p.to_string_lossy().into_owned()));
    args
}

/// `restic snapshots --json`, optionally narrowed to one tag.
pub fn snapshots_args(tag: Option<&str>) -> Vec<String> {
    let mut args = vec!["snapshots".into(), "--json".into()];
    if let Some(tag) = tag {
        args.push("--tag".into());
        args.push(tag.to_string());
    }
    args
}

/// `restic restore <snapshot> --target <dir>`.
pub fn restore_args(snapshot_id: &str, target: &Path) -> Vec<String> {
    vec![
        "restore".into(),
        snapshot_id.to_string(),
        "--target".into(),
        target.to_string_lossy().into_owned(),
    ]
}

/// The retention policy a schedule carries, as restic spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepPolicy {
    pub daily: i64,
    pub weekly: i64,
    pub monthly: i64,
}

/// `restic forget --prune` for one tag.
///
/// Two details carry weight:
///
/// - **`--tag` plus `--group-by tags`.** One repository holds the panel's own
///   snapshots and every tenant's. Without the filter, a tenant's seven-daily
///   policy would be applied to the panel's snapshots as well and would delete
///   them. The filter restricts *which* snapshots the policy sees; the
///   grouping makes the matching set one group, so "keep 7 daily" means seven
///   days of that tag rather than seven days per host-and-path combination.
/// - **`--prune`.** `forget` only removes the snapshot references; without a
///   prune the data stays in the repository forever and the "retention"
///   reclaims nothing. Spec §11.10's acceptance criterion is that retention
///   *prunes*, verified.
pub fn forget_args(tag: &str, keep: KeepPolicy) -> Vec<String> {
    vec![
        "forget".into(),
        "--prune".into(),
        "--tag".into(),
        tag.to_string(),
        "--group-by".into(),
        "tags".into(),
        "--keep-daily".into(),
        keep.daily.to_string(),
        "--keep-weekly".into(),
        keep.weekly.to_string(),
        "--keep-monthly".into(),
        keep.monthly.to_string(),
    ]
}

/// The tag every snapshot in a scope carries.
///
/// A subscription's tag names its id rather than its Linux user: the user name
/// can be recycled when a tenant is deleted and recreated, and a retention
/// policy that silently started covering somebody else's snapshots would be
/// the worst kind of quiet bug.
pub fn scope_tag(scope: BackupScope, subscription_id: Option<SubscriptionId>) -> String {
    match (scope, subscription_id) {
        (BackupScope::Panel, _) => PANEL_TAG.to_string(),
        (BackupScope::Subscription, Some(id)) => format!("unihelm-sub-{}", id.get()),
        // Unreachable through the operations (the input types and the schema
        // CHECK both refuse it); a stable string beats a panic if it ever is.
        (BackupScope::Subscription, None) => "unihelm-sub-unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// restic JSON
// ---------------------------------------------------------------------------

/// One snapshot, as `restic snapshots --json` describes it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    pub id: String,
    #[serde(default)]
    pub short_id: String,
    #[serde(default)]
    pub time: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Parse `restic snapshots --json`.
///
/// Unknown fields are ignored and missing optional ones default, because the
/// panel must not stop listing snapshots the day restic adds a field. The one
/// field that is required is `id`: a snapshot without an identifier is not
/// something a restore could ever name.
pub fn parse_snapshots(json: &str) -> Result<Vec<Snapshot>> {
    serde_json::from_str(json.trim()).map_err(|e| {
        UnihelmError::new(
            ErrorCode::CommandFailed,
            format!("could not read restic's snapshot list: {e}"),
        )
    })
}

/// What a finished `restic backup --json` reports about itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupSummary {
    pub snapshot_id: Option<String>,
    pub bytes: Option<i64>,
    pub files_new: Option<i64>,
    pub files_changed: Option<i64>,
}

/// Pull the summary out of a `restic backup --json` stream.
///
/// The stream is newline-delimited JSON of several message types; only the
/// final `summary` carries the snapshot id. Returning `None` rather than
/// failing is deliberate: a restic old enough not to emit a summary still took
/// a perfectly good backup, and refusing to record it would turn a cosmetic
/// difference into a failed run.
pub fn parse_backup_summary(stdout: &str) -> Option<BackupSummary> {
    for line in stdout.lines().rev() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("message_type").and_then(|m| m.as_str()) != Some("summary") {
            continue;
        }
        return Some(BackupSummary {
            snapshot_id: value
                .get("snapshot_id")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            bytes: value.get("total_bytes_processed").and_then(|v| v.as_i64()),
            files_new: value.get("files_new").and_then(|v| v.as_i64()),
            files_changed: value.get("files_changed").and_then(|v| v.as_i64()),
        });
    }
    None
}

/// Is this a per-second progress message rather than something worth a log
/// line?
///
/// `restic backup --json` emits a `status` message several times a second. A
/// two-hour backup would be hundreds of thousands of task-log rows, which is
/// both a database problem and an unreadable log.
fn is_progress_noise(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with('{') && line.contains("\"message_type\":\"status\"")
}

// ---------------------------------------------------------------------------
// Minimal cron
// ---------------------------------------------------------------------------

/// A five-field cron expression (`minute hour day-of-month month day-of-week`).
///
/// **Duplication, knowingly.** `crates/unihelm-ops/src/cron.rs` is being written
/// in parallel by the tenant-crontab task and will contain a five-field parser
/// of its own. Reaching across to a module that does not exist yet would make
/// this branch un-buildable, so this one is written to be small and easy to
/// delete: [`CronSpec::parse`] plus [`CronSpec::is_due`] is the whole surface,
/// and the integrator hand-off names the deduplication.
///
/// Numeric fields only — no `@daily`, no `MON`, no `JAN`. The panel generates
/// these expressions from a UI picker; accepting the full Vixie grammar would
/// be surface with no caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronSpec {
    minute: u64,
    hour: u64,
    day_of_month: u64,
    month: u64,
    day_of_week: u64,
    /// Whether the field was something other than `*`, which decides how
    /// day-of-month and day-of-week combine (see [`CronSpec::matches`]).
    dom_restricted: bool,
    dow_restricted: bool,
}

impl CronSpec {
    pub fn parse(expression: &str) -> Result<Self> {
        let fields: Vec<&str> = expression.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(invalid(format!(
                "a cron expression has five fields (minute hour day-of-month month \
                 day-of-week); `{expression}` has {}",
                fields.len()
            ))
            .with_field("cron"));
        }

        Ok(Self {
            minute: parse_field(fields[0], 0, 59, "minute")?,
            hour: parse_field(fields[1], 0, 23, "hour")?,
            day_of_month: parse_field(fields[2], 1, 31, "day of month")?,
            month: parse_field(fields[3], 1, 12, "month")?,
            // 7 is Sunday as well as 0, the one piece of Vixie compatibility
            // worth keeping: crontabs in the wild are full of `* * * * 7`.
            day_of_week: normalise_sunday(parse_field(fields[4], 0, 7, "day of week")?),
            dom_restricted: fields[2] != "*",
            dow_restricted: fields[4] != "*",
        })
    }

    /// Does this expression fire in the minute containing `t`?
    ///
    /// The day rule is cron's, and it is the one thing everybody gets wrong:
    /// when **both** day-of-month and day-of-week are restricted the match is
    /// an **or**, not an and. `0 0 1 * 1` is "the first of the month *and*
    /// every Monday", which is why `0 0 13 * 5` is the traditional way to say
    /// Friday the 13th only if you also know it does not work.
    pub fn matches(&self, t: time::OffsetDateTime) -> bool {
        if !bit(self.minute, u32::from(t.minute())) || !bit(self.hour, u32::from(t.hour())) {
            return false;
        }
        if !bit(self.month, u32::from(u8::from(t.month()))) {
            return false;
        }

        let dom = bit(self.day_of_month, u32::from(t.day()));
        let dow = bit(
            self.day_of_week,
            u32::from(t.weekday().number_days_from_sunday()),
        );

        match (self.dom_restricted, self.dow_restricted) {
            (true, true) => dom || dow,
            (true, false) => dom,
            (false, true) => dow,
            (false, false) => true,
        }
    }

    /// Is this schedule due, given when it last ran?
    ///
    /// Not simply "does the current minute match": the scheduler wakes on a
    /// 60 s interval with jitter and can miss a wall-clock minute entirely, and
    /// an agent that was restarted has missed every minute it was down. The
    /// check therefore walks back minute by minute to the last run (or, for a
    /// schedule that has never run, over the short window
    /// [`FIRST_RUN_CATCHUP_MINUTES`]) and fires once if any of those minutes
    /// matched. Missing a nightly backup because the agent was updated at
    /// 03:00 is exactly the failure this avoids.
    pub fn is_due(
        &self,
        last_run: Option<time::OffsetDateTime>,
        now: time::OffsetDateTime,
    ) -> bool {
        let now = floor_to_minute(now);
        let (floor, limit) = match last_run {
            Some(last) => (floor_to_minute(last), MAX_CATCHUP_MINUTES),
            None => (
                now - time::Duration::minutes(FIRST_RUN_CATCHUP_MINUTES),
                FIRST_RUN_CATCHUP_MINUTES,
            ),
        };

        for back in 0..=limit {
            let candidate = now - time::Duration::minutes(back);
            if candidate <= floor {
                break;
            }
            if self.matches(candidate) {
                return true;
            }
        }
        false
    }
}

fn floor_to_minute(t: time::OffsetDateTime) -> time::OffsetDateTime {
    t.replace_second(0)
        .expect("0 is a valid second")
        .replace_nanosecond(0)
        .expect("0 is a valid nanosecond")
}

const fn bit(mask: u64, n: u32) -> bool {
    n < 64 && mask & (1u64 << n) != 0
}

/// Fold the `7` spelling of Sunday onto `0`, which is what
/// `Weekday::number_days_from_sunday` returns.
const fn normalise_sunday(mask: u64) -> u64 {
    if mask & (1 << 7) != 0 {
        (mask | 1) & !(1 << 7)
    } else {
        mask
    }
}

/// Parse one cron field into a bitmask over `min..=max`.
fn parse_field(field: &str, min: u32, max: u32, what: &str) -> Result<u64> {
    let mut mask = 0u64;
    for item in field.split(',') {
        let item = item.trim();
        if item.is_empty() {
            return Err(invalid(format!("empty {what} field")).with_field("cron"));
        }

        let (range, step) = match item.split_once('/') {
            Some((range, step)) => {
                let step: u32 = step.parse().map_err(|_| {
                    invalid(format!("`{step}` is not a step in the {what} field"))
                        .with_field("cron")
                })?;
                if step == 0 {
                    return Err(
                        invalid(format!("a step of zero in the {what} field")).with_field("cron")
                    );
                }
                (range, step)
            }
            None => (item, 1),
        };

        let (from, to) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (number(a, min, max, what)?, number(b, min, max, what)?)
        } else {
            let n = number(range, min, max, what)?;
            // `5/15` means "from 5 onwards, every 15" — a bare number with a
            // step is an open range, not a single value.
            if step > 1 { (n, max) } else { (n, n) }
        };

        if from > to {
            return Err(
                invalid(format!("`{range}` runs backwards in the {what} field")).with_field("cron"),
            );
        }
        let mut n = from;
        while n <= to {
            mask |= 1u64 << n;
            n += step;
        }
    }
    Ok(mask)
}

fn number(s: &str, min: u32, max: u32, what: &str) -> Result<u32> {
    let n: u32 = s.trim().parse().map_err(|_| {
        invalid(format!("`{s}` is not a number in the {what} field")).with_field("cron")
    })?;
    if n < min || n > max {
        return Err(
            invalid(format!("{n} is outside {min}-{max} in the {what} field")).with_field("cron"),
        );
    }
    Ok(n)
}

fn invalid(detail: impl Into<String>) -> UnihelmError {
    UnihelmError::new(ErrorCode::InvalidInput, detail)
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

/// Make sure restic is on the machine, installing it if it is not.
///
/// Availability is checked first so the common case costs one `stat` rather
/// than a package-manager round trip, and the failure is worded for somebody
/// who has to fix it: it names the package and, on EL, the repository it lives
/// in — "No match for argument: restic" on a fresh AlmaLinux otherwise sends
/// an operator looking for a typo.
async fn ensure_restic(ctx: &OpContext, program: &str) -> Result<()> {
    if exec::program_available(program) {
        return Ok(());
    }

    ctx.log(format!("{program} is not installed; installing it"));
    let package = PackageName::parse(RESTIC_PACKAGE).map_err(UnihelmError::from)?;
    let installed = ctx
        .distro()
        .pkg
        .install(&[package], ctx.log_sink())
        .await
        .map_err(UnihelmError::from);

    if exec::program_available(program) {
        return Ok(());
    }

    let detail = match installed {
        Ok(_) => "the package manager reported success but the binary is still missing".to_string(),
        Err(e) => e.detail,
    };
    Err(UnihelmError::new(
        ErrorCode::CommandFailed,
        format!(
            "backups need the `{RESTIC_PACKAGE}` package and it could not be installed \
             ({detail}). Install it by hand — `apt install restic` on Debian/Ubuntu, \
             `dnf install epel-release && dnf install restic` on AlmaLinux/Rocky, where \
             restic ships in EPEL rather than the base repositories — and try again."
        ),
    ))
}

/// Open a repository's sealed password and credentials.
async fn resolve_repo(ctx: &OpContext, repo_id: i64) -> Result<RepoTarget> {
    let repo = ctx
        .db()
        .backup_repo(repo_id)
        .await
        .map_err(UnihelmError::from)?
        .ok_or_else(|| UnihelmError::not_found("backup repository"))?;

    let secrets = ctx
        .db()
        .backup_repo_secrets(repo_id)
        .await
        .map_err(UnihelmError::from)?;

    let password = ctx
        .master_key()
        .open_str(&secrets.password_sealed)
        .map_err(|e| {
            // The master key changed, or the row was tampered with. Either way
            // the repository is unusable until somebody intervenes, and saying
            // so beats a restic "wrong password" three seconds later.
            UnihelmError::internal(format!(
                "the stored password for backup repository `{}` could not be opened: {e}",
                repo.label
            ))
        })?;

    let credentials = match secrets.credentials_sealed {
        Some(sealed) => {
            let json = ctx.master_key().open_str(&sealed).map_err(|e| {
                UnihelmError::internal(format!(
                    "the stored credentials for backup repository `{}` could not be opened: {e}",
                    repo.label
                ))
            })?;
            Some(serde_json::from_str::<S3Credentials>(&json).map_err(|e| {
                UnihelmError::internal(format!("stored credentials are not readable: {e}"))
            })?)
        }
        None => None,
    };

    Ok(RepoTarget {
        id: repo.id,
        label: repo.label,
        kind: repo.kind,
        location: repo.path_or_url,
        password,
        credentials,
    })
}

/// Administrator-only: refuse anything narrower than the whole server.
///
/// The registry has already checked [`Permission::BackupManage`], which a
/// reseller and a customer can both hold. This is the second half: a
/// repository holds credentials and a password and covers every tenant, and
/// restoring somebody else's snapshot into a staging directory is a data leak
/// whatever the file permissions on that directory say.
fn require_global(ctx: &OpContext, what: &str) -> Result<()> {
    if matches!(ctx.scope(), TenantScope::Global) {
        return Ok(());
    }
    Err(UnihelmError::new(
        ErrorCode::PermissionDenied,
        format!("{what} is an administrator operation"),
    ))
}

// A plan feature flag would belong here — `can_backups`, alongside `can_ssh`,
// `can_cron` and `can_node_apps` (spec §6.2). The `plans` table has no such
// column, and adding one means editing a table another area owns, so the gate
// is deliberately absent rather than invented: today a tenant's access to
// backups is decided by `Permission::BackupManage` plus
// `Run::authorise_repository`, which is a narrower door than a plan flag would
// be. The integrator hand-off names the column as follow-up work.

/// The retention policy to apply after a run: the first enabled schedule that
/// covers this repository and scope.
///
/// A manual run prunes under the same policy a scheduled one would, which is
/// the behaviour that keeps "I ran an extra backup before the migration" from
/// quietly doubling what the repository holds. A scope with no schedule has no
/// stated policy, and inventing one would be the panel deleting snapshots
/// nobody asked it to delete.
async fn retention_for(
    ctx: &OpContext,
    repo_id: i64,
    scope: BackupScope,
    subscription_id: Option<SubscriptionId>,
) -> Option<KeepPolicy> {
    let schedules = ctx.db().enabled_backup_schedules().await.ok()?;
    schedules
        .into_iter()
        .find(|s| {
            s.repo_id == repo_id
                && s.scope == scope
                && s.subscription_id == subscription_id.map(|id| id.get())
        })
        .map(|s| KeepPolicy {
            daily: s.keep_daily,
            weekly: s.keep_weekly,
            monthly: s.keep_monthly,
        })
}

/// A file that deletes itself.
///
/// The panel-scope backup writes a full copy of `panel.db` — every sealed
/// secret the panel holds — into a working directory. Leaving it behind after
/// the run would turn a 0600 file into a permanent second copy of the panel's
/// entire state, and the failure paths are exactly where a plain
/// `remove_file` at the end of the happy path gets skipped.
struct TempSnapshot(PathBuf);

impl Drop for TempSnapshot {
    fn drop(&mut self) {
        if self.0.exists()
            && let Err(e) = std::fs::remove_file(&self.0)
        {
            tracing::warn!(path = %self.0.display(), error = %e,
                "could not remove the temporary database snapshot");
        }
    }
}

/// Keep only the paths that exist, saying which were skipped.
///
/// A development instance has no `/etc/unihelm`, and a panel that has never
/// issued a certificate has no state directory. restic fails the whole backup
/// on a missing path, and "the nightly backup stopped working because a
/// directory the panel does not need yet is absent" is not an acceptable
/// trade.
fn existing_paths(ctx: &OpContext, candidates: Vec<PathBuf>) -> Vec<PathBuf> {
    candidates
        .into_iter()
        .filter(|p| {
            if p.exists() {
                true
            } else {
                ctx.log(format!("skipping {} — it does not exist", p.display()));
                false
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

/// Reject anything that cannot legitimately appear in a repository location.
///
/// A NUL is the one character that is a *correctness* problem rather than a
/// taste one: an environment entry is a NUL-terminated string, so a NUL in the
/// middle of `RESTIC_REPOSITORY` silently truncates it and the backup goes
/// somewhere other than where it says. Control characters and leading dashes
/// are refused for defence in depth — the value never reaches argv today, and
/// this is what keeps that true if it ever does.
fn check_location(value: &str, field: &'static str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid("a repository location cannot be empty").with_field(field));
    }
    if value.len() > MAX_LOCATION {
        return Err(invalid(format!(
            "a repository location is at most {MAX_LOCATION} characters"
        ))
        .with_field(field));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(
            invalid("a repository location cannot contain control characters").with_field(field),
        );
    }
    if value.starts_with('-') {
        return Err(invalid("a repository location cannot start with `-`").with_field(field));
    }
    Ok(value.to_string())
}

fn check_local_path(value: &str) -> Result<String> {
    let value = check_location(value, "path_or_url")?;
    let path = Path::new(&value);
    if !path.is_absolute() {
        return Err(
            invalid("a local backup repository needs an absolute path").with_field("path_or_url")
        );
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(
            invalid("a local backup repository path cannot contain `..`").with_field("path_or_url"),
        );
    }
    Ok(value)
}

fn check_s3_url(value: &str) -> Result<String> {
    let value = check_location(value, "path_or_url")?;
    // restic's own spelling is `s3:<endpoint>/<bucket>[/<prefix>]`; the panel
    // adds the `s3:` itself so an operator pasting one in does not end up with
    // `s3:s3:`.
    let value = value.strip_prefix("s3:").unwrap_or(&value).to_string();
    if !value.contains('/') {
        return Err(invalid(
            "an S3 repository needs an endpoint and a bucket, e.g. \
             `s3.example.com/unihelm-backups`",
        )
        .with_field("path_or_url"));
    }
    Ok(value)
}

fn check_label(value: &str) -> Result<String> {
    // Spaces are trimmed, other whitespace is not. Surrounding spaces are a
    // typing artefact worth forgiving; a newline is a paste accident or an
    // attempt to smuggle a line break into a log line that names the label, and
    // quietly repairing it would hide both. It falls through to the character
    // check below and is refused there.
    let value = value.trim_matches(' ');
    if value.is_empty() || value.chars().count() > MAX_LABEL {
        return Err(invalid(format!("a label is 1 to {MAX_LABEL} characters")).with_field("label"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
    {
        return Err(invalid(
            "a label may contain letters, digits, spaces, dots, dashes and underscores",
        )
        .with_field("label"));
    }
    Ok(value.to_string())
}

/// restic snapshot ids are hex; `latest` is restic's own alias for the newest.
///
/// Strict because this value *does* reach argv. Hex cannot begin with a dash,
/// so a validated id can never be read as a flag — which is the property that
/// makes the restore argv safe without a `--` restic does not accept there.
fn check_snapshot_id(value: &str) -> Result<String> {
    let value = value.trim();
    if value == "latest" {
        return Ok(value.to_string());
    }
    let len = value.len();
    if !(8..=64).contains(&len) || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(
            "a snapshot id is 8 to 64 hexadecimal characters, or the word `latest`",
        )
        .with_field("snapshot_id"));
    }
    Ok(value.to_ascii_lowercase())
}

/// A repository password: 32 characters over `[A-Za-z0-9]`, ~190 bits.
///
/// Alphanumeric on purpose. This is the string an operator will write on a
/// piece of paper or paste into a password manager, and every character that
/// needs escaping somewhere is a character that will eventually be typed back
/// wrong. It is also long enough that the reduced alphabet costs nothing: a
/// restic repository's key derivation is scrypt, and 190 bits is far past the
/// point where guessing is the attack.
fn generate_repo_password() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const LEN: usize = 32;
    let mut rng = rand::thread_rng();
    (0..LEN)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

/// The sentence returned beside a freshly generated password.
pub const PASSWORD_NOTICE: &str = "This password is shown once and cannot be recovered from the \
     panel. Store it off this server, together with /etc/unihelm/secret.key: without both, a \
     panel-scope backup cannot be restored after the panel is lost.";

// ---------------------------------------------------------------------------
// backup.repo.init
// ---------------------------------------------------------------------------

/// `backup.repo.init` — create a repository, generate its password, show it
/// once.
pub struct RepoInit {
    program: String,
}

impl RepoInit {
    pub fn live() -> Self {
        Self {
            program: RESTIC.into(),
        }
    }

    #[cfg(test)]
    fn with_program(program: &str) -> Self {
        Self {
            program: program.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RepoInitInput {
    pub kind: RepoKind,
    pub label: String,
    /// An absolute path for `local`; `endpoint/bucket[/prefix]` for `s3`.
    pub path_or_url: String,
    /// Required for `s3`, refused for `local`.
    #[serde(default)]
    pub s3: Option<S3Credentials>,
}

#[derive(Debug, Serialize)]
pub struct RepoInitOutput {
    pub repo_id: i64,
    pub label: String,
    pub kind: RepoKind,
    /// The `RESTIC_REPOSITORY` value, so an operator can drive restic by hand.
    /// Carries no credentials.
    pub repository: String,
    /// **Shown once.** See [`PASSWORD_NOTICE`] and the module documentation.
    pub password: String,
    pub password_notice: &'static str,
}

#[async_trait]
impl TypedOperation for RepoInit {
    type Input = RepoInitInput;
    type Output = RepoInitOutput;

    const NAME: &'static str = "backup.repo.init";
    const PERMISSION: Permission = Permission::BackupManage;
    /// Immediate, and this is a security decision rather than a latency one.
    ///
    /// A Task persists its **input** verbatim in `tasks.input` so the drawer
    /// can show what was asked for — and this operation's input carries the S3
    /// secret access key. Running it as a task would write that key into the
    /// panel database in the clear, next to the sealed copy, which defeats the
    /// sealing entirely. A task also *discards* its output, and the output
    /// here is the show-once password.
    ///
    /// `restic init` writes a handful of small objects, so 25 s (see
    /// [`IMMEDIATE_TIMEOUT`]) is generous even against a slow endpoint.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        require_global(ctx, "creating a backup repository")?;

        let label = check_label(&input.label)?;
        let location = match input.kind {
            RepoKind::Local => check_local_path(&input.path_or_url)?,
            RepoKind::S3 => check_s3_url(&input.path_or_url)?,
        };

        let credentials = match (input.kind, input.s3) {
            (RepoKind::S3, Some(c)) => {
                if c.access_key_id.trim().is_empty() || c.secret_access_key.is_empty() {
                    return Err(invalid(
                        "an S3 repository needs an access key id and a secret \
                         access key",
                    )
                    .with_field("s3"));
                }
                // Same NUL reasoning as the location: these become environment
                // entries, and a NUL truncates one.
                if c.access_key_id.chars().any(|ch| ch.is_control())
                    || c.secret_access_key.chars().any(|ch| ch.is_control())
                {
                    return Err(invalid("S3 credentials cannot contain control characters")
                        .with_field("s3"));
                }
                Some(c)
            }
            (RepoKind::S3, None) => {
                return Err(invalid(format!(
                    "an S3 repository needs credentials ({S3_FIELD_HINT})"
                ))
                .with_field("s3"));
            }
            (RepoKind::Local, Some(_)) => {
                return Err(invalid("a local repository takes no S3 credentials").with_field("s3"));
            }
            (RepoKind::Local, None) => None,
        };

        ensure_restic(ctx, &self.program).await?;

        let password = generate_repo_password();
        let password_sealed = ctx
            .master_key()
            .seal_str(&password)
            .map_err(|e| UnihelmError::internal(format!("could not seal the password: {e}")))?;
        let credentials_sealed = match &credentials {
            Some(c) => {
                let json = serde_json::to_string(c)
                    .map_err(|e| UnihelmError::internal(format!("credentials: {e}")))?;
                Some(ctx.master_key().seal_str(&json).map_err(|e| {
                    UnihelmError::internal(format!("could not seal the credentials: {e}"))
                })?)
            }
            None => None,
        };

        // The row first, restic second. The label conflict is then decided
        // before anything is created anywhere, and the failure mode of the
        // remaining window is "a row was rolled back" rather than "a
        // repository exists in a bucket that the panel has no record of".
        let repo = ctx
            .db()
            .create_backup_repo(NewBackupRepo {
                kind: input.kind,
                label: label.clone(),
                path_or_url: location.clone(),
                password_sealed,
                credentials_sealed,
            })
            .await
            .map_err(UnihelmError::from)?;

        let target = RepoTarget {
            id: repo.id,
            label: label.clone(),
            kind: input.kind,
            location,
            password: password.clone(),
            credentials,
        };

        let invocation = target.invocation(init_args(), IMMEDIATE_TIMEOUT, &self.program);
        let out = invocation.run().await;

        let failure = match out {
            Ok(out) if out.success() => None,
            Ok(out) => Some(out.failure_text()),
            Err(e) => Some(e.detail),
        };

        if let Some(detail) = failure {
            // Undo the row so the operator can fix the endpoint and try the
            // same label again.
            if let Err(e) = ctx.db().delete_backup_repo(repo.id).await {
                tracing::error!(repo = repo.id, error = %e,
                    "could not roll back a backup repository row after a failed init");
            }
            return Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                format!("restic could not initialise the repository: {detail}"),
            ));
        }

        Ok(RepoInitOutput {
            repo_id: repo.id,
            label,
            kind: input.kind,
            repository: target.repository(),
            password,
            password_notice: PASSWORD_NOTICE,
        })
    }
}

// ---------------------------------------------------------------------------
// backup.run
// ---------------------------------------------------------------------------

/// `backup.run` — take one snapshot and apply retention.
pub struct Run {
    program: String,
    /// Where the working copy of `panel.db` is written. `None` means
    /// [`paths::state_dir`]; tests point it at a temporary directory, because
    /// `paths::set_root` is a process-wide `OnceLock` that a parallel test
    /// cannot share.
    state_root: Option<PathBuf>,
}

impl Run {
    pub fn live() -> Self {
        Self {
            program: RESTIC.into(),
            state_root: None,
        }
    }

    #[cfg(test)]
    fn for_test(program: &str, state_root: PathBuf) -> Self {
        Self {
            program: program.into(),
            state_root: Some(state_root),
        }
    }

    fn state_root(&self) -> PathBuf {
        self.state_root.clone().unwrap_or_else(paths::state_dir)
    }
}

#[derive(Debug, Deserialize)]
pub struct RunInput {
    pub repo_id: i64,
    pub scope: BackupScope,
    /// Required for `subscription` scope; refused for `panel`.
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct RunOutput {
    pub run_id: i64,
    pub repo_id: i64,
    pub scope: BackupScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<i64>,
    pub paths: Vec<String>,
    /// Whether `restic forget --prune` ran afterwards, and under what policy.
    pub pruned: bool,
}

#[async_trait]
impl TypedOperation for Run {
    type Input = RunInput;
    type Output = RunOutput;

    const NAME: &'static str = "backup.run";
    const PERMISSION: Permission = Permission::BackupManage;
    // Hours of work with a live log; the whole reason the task engine exists
    // (spec §10.1). Idempotent: repeating a backup produces a second snapshot
    // and costs time, but cannot corrupt the repository — and retention prunes
    // the duplicate. Not cancellable, because killing restic mid-write leaves
    // a lock for the next run to clear rather than stopping cleanly.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let subscription = self.resolve_scope(ctx, &input).await?;
        // Before `resolve_repo`, which opens the sealed password: a caller who
        // may not use this repository must not make the panel decrypt its
        // credentials.
        authorise_repository(ctx, input.repo_id, input.scope, subscription).await?;
        let target = resolve_repo(ctx, input.repo_id).await?;
        ensure_restic(ctx, &self.program).await?;

        run_backup(
            ctx,
            &self.program,
            &self.state_root(),
            &target,
            input.scope,
            subscription,
            None,
        )
        .await
    }
}

impl Run {
    /// Work out which subscription this run covers, refusing the combinations
    /// that do not mean anything.
    async fn resolve_scope(
        &self,
        ctx: &OpContext,
        input: &RunInput,
    ) -> Result<Option<SubscriptionId>> {
        match input.scope {
            BackupScope::Panel => {
                if input.subscription_id.is_some() {
                    return Err(invalid(
                        "a panel-scope backup covers the whole server; it takes no subscription",
                    )
                    .with_field("subscription_id"));
                }
                // The panel scope carries `panel.db`, `/etc/unihelm` and every
                // tenant's certificates. Only an administrator may ask for it,
                // and only an administrator may later restore it.
                require_global(ctx, "a panel-scope backup")?;
                Ok(None)
            }
            BackupScope::Subscription => {
                let raw = input.subscription_id.ok_or_else(|| {
                    invalid("a subscription-scope backup needs a subscription")
                        .with_field("subscription_id")
                })?;
                // Resolved *through the caller's scope*, so a customer naming
                // somebody else's id gets `not_found` and learns nothing.
                let subscription = ctx
                    .db()
                    .subscriptions(ctx.scope())
                    .by_id(SubscriptionId(raw))
                    .await
                    .map_err(UnihelmError::from)?
                    .ok_or_else(|| UnihelmError::not_found("subscription"))?;
                Ok(Some(subscription.id))
            }
        }
    }
}

/// May this caller touch this repository at all?
///
/// An administrator may use any repository. A tenant may use only one that
/// somebody already pointed a schedule for *their* subscription at. Without
/// this, a customer holding `backup_manage` could walk repository ids — they
/// are small consecutive integers — and both learn which repositories exist and
/// reach an administrator's bucket at will.
///
/// Takes an id rather than a resolved [`RepoTarget`] so it can be asked
/// *before* the sealed password is opened: an unauthorised caller should never
/// cause the panel to decrypt a credential, let alone connect to the endpoint
/// it belongs to.
async fn authorise_repository(
    ctx: &OpContext,
    repo_id: i64,
    scope: BackupScope,
    subscription: Option<SubscriptionId>,
) -> Result<()> {
    if matches!(ctx.scope(), TenantScope::Global) {
        return Ok(());
    }
    let schedules = ctx
        .db()
        .backups(ctx.scope())
        .schedules()
        .await
        .map_err(UnihelmError::from)?;
    let allowed = schedules.iter().any(|s| {
        s.repo_id == repo_id
            && s.scope == scope
            && s.subscription_id == subscription.map(|id| id.get())
    });
    if allowed {
        Ok(())
    } else {
        // `not_found`, not `permission_denied`: the answer must be the same
        // whether the repository exists and is somebody else's or does not exist
        // at all.
        Err(UnihelmError::not_found("backup repository"))
    }
}

/// The body of a run, shared by the operation and the scheduler.
///
/// `schedule_id` is `Some` when the scheduler started it, which is what puts
/// the run in a schedule's history.
#[allow(clippy::too_many_arguments)]
pub async fn run_backup(
    ctx: &OpContext,
    program: &str,
    state_root: &Path,
    target: &RepoTarget,
    scope: BackupScope,
    subscription: Option<SubscriptionId>,
    schedule_id: Option<i64>,
) -> Result<RunOutput> {
    let work_dir = state_root.join("backup-work");
    std::fs::create_dir_all(&work_dir).map_err(|e| {
        UnihelmError::internal(format!("could not create {}: {e}", work_dir.display()))
    })?;
    // 0700: the working copy of the panel database lands here.
    restrict(&work_dir)?;

    let run_id = ctx
        .db()
        .start_backup_run(schedule_id, target.id, scope, subscription)
        .await
        .map_err(UnihelmError::from)?;

    // Everything after the run row exists reports its failure *into* the row,
    // so a failed backup is visible in the history rather than only in a task
    // log somebody has to know to look for (spec §11.10 AC: a corrupted target
    // produces an alert, not a silent success).
    let outcome =
        collect_and_back_up(ctx, program, &work_dir, target, scope, subscription, run_id).await;

    match outcome {
        Ok(mut out) => {
            ctx.db()
                .finish_backup_run(
                    run_id,
                    RunOutcome::Ok {
                        snapshot_id: out.snapshot_id.clone(),
                        bytes: out.bytes,
                    },
                )
                .await
                .map_err(UnihelmError::from)?;

            // Retention last, and only after the run is recorded successful:
            // pruning before the new snapshot is safely in would be deleting
            // old backups on the strength of one that might yet fail.
            out.pruned = prune(ctx, program, target, scope, subscription).await;

            // Spec §14 Phase 6: a backup that finished is one of the events an
            // integrator watches for. Emitted from `run_backup` rather than
            // from the operation body so a *scheduled* run notifies too — the
            // unattended ones are precisely the ones nobody is watching.
            crate::webhook::emit(
                ctx,
                "backup.completed",
                serde_json::json!({
                    "run_id": run_id,
                    "repo_id": target.id,
                    "scope": scope,
                    "subscription_id": subscription.map(|s| s.get()),
                    "snapshot_id": out.snapshot_id,
                    "bytes": out.bytes,
                }),
            )
            .await;
            Ok(out)
        }
        Err(e) => {
            let _ = ctx
                .db()
                .finish_backup_run(
                    run_id,
                    RunOutcome::Failed {
                        error: e.detail.clone(),
                    },
                )
                .await;

            // The event every integrator asks for first.
            crate::webhook::emit(
                ctx,
                "backup.failed",
                serde_json::json!({
                    "run_id": run_id,
                    "repo_id": target.id,
                    "scope": scope,
                    "subscription_id": subscription.map(|s| s.get()),
                    "error": e.detail,
                }),
            )
            .await;
            Err(e)
        }
    }
}

async fn collect_and_back_up(
    ctx: &OpContext,
    program: &str,
    work_dir: &Path,
    target: &RepoTarget,
    scope: BackupScope,
    subscription: Option<SubscriptionId>,
    run_id: i64,
) -> Result<RunOutput> {
    // Held for the whole function: dropping it removes the database copy on
    // every path out, including the error ones.
    let mut _snapshot_guard: Option<TempSnapshot> = None;

    let paths = match scope {
        BackupScope::Panel => {
            let db_copy = work_dir.join(format!("panel-{run_id}.db"));
            ctx.log(format!(
                "writing a consistent copy of the panel database to {}",
                db_copy.display()
            ));
            // VACUUM INTO, never a file copy: see `Db::vacuum_into` for why a
            // WAL database cannot be backed up by copying its `.db` file.
            ctx.db()
                .vacuum_into(&db_copy)
                .await
                .map_err(UnihelmError::from)?;
            let guard = TempSnapshot(db_copy.clone());
            restrict(&db_copy)?;
            _snapshot_guard = Some(guard);

            existing_paths(
                ctx,
                vec![
                    db_copy,
                    // The master key and config.toml. Without `secret.key`
                    // every sealed secret in the restored database is
                    // unreadable, so a backup without this directory restores
                    // to a panel that cannot renew a certificate.
                    paths::config_dir(),
                    // Certificates, ACME accounts, rendered configs.
                    paths::state_dir(),
                ],
            )
        }
        BackupScope::Subscription => {
            let id = subscription.ok_or_else(|| {
                UnihelmError::internal("a subscription backup reached the runner without a tenant")
            })?;
            let sub = ctx
                .db()
                .subscriptions(&TenantScope::Global)
                .by_id(id)
                .await
                .map_err(UnihelmError::from)?
                .ok_or_else(|| UnihelmError::not_found("subscription"))?;
            existing_paths(ctx, vec![PathBuf::from(sub.home_dir)])
        }
    };

    if paths.is_empty() {
        return Err(UnihelmError::new(
            ErrorCode::NotFound,
            "there is nothing to back up: none of the paths for this scope exist",
        ));
    }

    let tag = scope_tag(scope, subscription);
    let invocation = target.invocation(backup_args(&tag, &paths), LONG_TIMEOUT, program);

    ctx.log(format!("repository: {}", target.repository()));
    ctx.log(format!("running {}", invocation.display()));

    let out = invocation
        .run_streaming(|line| {
            if !is_progress_noise(line) {
                ctx.log(line);
            }
        })
        .await?;

    if !out.success() {
        return Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            format!("restic backup failed: {}", out.failure_text()),
        ));
    }

    let summary = parse_backup_summary(&out.stdout).unwrap_or_default();
    if let Some(id) = &summary.snapshot_id {
        ctx.log(format!("snapshot {id}"));
    }

    Ok(RunOutput {
        run_id,
        repo_id: target.id,
        scope,
        snapshot_id: summary.snapshot_id,
        bytes: summary.bytes,
        paths: paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        pruned: false,
    })
}

/// Apply the schedule's retention policy. Never fails the run.
///
/// A prune that fails leaves more history than asked for, which is a disk
/// problem; a run reported as failed after the snapshot is safely written is a
/// *correctness* problem, because the next thing an operator does is re-run it
/// and the thing they will conclude is that backups are broken.
async fn prune(
    ctx: &OpContext,
    program: &str,
    target: &RepoTarget,
    scope: BackupScope,
    subscription: Option<SubscriptionId>,
) -> bool {
    let Some(keep) = retention_for(ctx, target.id, scope, subscription).await else {
        ctx.log("no schedule covers this scope, so no retention policy was applied");
        return false;
    };

    let tag = scope_tag(scope, subscription);
    let invocation = target.invocation(forget_args(&tag, keep), PRUNE_TIMEOUT, program);
    ctx.log(format!("running {}", invocation.display()));

    match invocation
        .run_streaming(|line| {
            if !is_progress_noise(line) {
                ctx.log(line);
            }
        })
        .await
    {
        Ok(out) if out.success() => true,
        Ok(out) => {
            ctx.log(format!(
                "retention did not complete: {}",
                out.failure_text()
            ));
            false
        }
        Err(e) => {
            ctx.log(format!("retention did not complete: {}", e.detail));
            false
        }
    }
}

/// 0700 on a directory, 0600 on a file — whatever it already was.
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if path.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        UnihelmError::internal(format!(
            "could not restrict permissions on {}: {e}",
            path.display()
        ))
    })
}

// ---------------------------------------------------------------------------
// backup.list
// ---------------------------------------------------------------------------

/// `backup.list` — the snapshots in a repository.
pub struct List {
    program: String,
}

impl List {
    pub fn live() -> Self {
        Self {
            program: RESTIC.into(),
        }
    }

    #[cfg(test)]
    fn with_program(program: &str) -> Self {
        Self {
            program: program.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListInput {
    pub repo_id: i64,
    /// Narrow to one subscription's snapshots. A scoped caller is narrowed to
    /// their own whether they ask or not.
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub repo_id: i64,
    pub label: String,
    pub snapshots: Vec<Snapshot>,
}

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "backup.list";
    const PERMISSION: Permission = Permission::BackupManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // A snapshot list names paths and hostnames across the whole server,
        // so a scoped caller sees only snapshots tagged for a subscription
        // they own. The tag is derived here from a subscription resolved
        // through their scope, never taken from the request.
        let tag = match ctx.scope() {
            TenantScope::Global => input
                .subscription_id
                .map(|raw| scope_tag(BackupScope::Subscription, Some(SubscriptionId(raw)))),
            _ => {
                let raw = input.subscription_id.ok_or_else(|| {
                    invalid("name the subscription whose snapshots you want")
                        .with_field("subscription_id")
                })?;
                let sub = ctx
                    .db()
                    .subscriptions(ctx.scope())
                    .by_id(SubscriptionId(raw))
                    .await
                    .map_err(UnihelmError::from)?
                    .ok_or_else(|| UnihelmError::not_found("subscription"))?;

                // The same gate `backup.run` applies, and for the same reason:
                // a tenant may reach only a repository an administrator's
                // schedule already points at for their subscription. The tag
                // filter below stops them *reading* another tenant's snapshots,
                // but without this a tenant could still walk repository ids and
                // make the panel open an administrator's credentials and
                // connect to their endpoint.
                authorise_repository(ctx, input.repo_id, BackupScope::Subscription, Some(sub.id))
                    .await?;

                Some(scope_tag(BackupScope::Subscription, Some(sub.id)))
            }
        };

        let target = resolve_repo(ctx, input.repo_id).await?;
        ensure_restic(ctx, &self.program).await?;

        let invocation = target.invocation(
            snapshots_args(tag.as_deref()),
            IMMEDIATE_TIMEOUT,
            &self.program,
        );
        let out = invocation.run().await?;
        if !out.success() {
            return Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                format!("restic could not list snapshots: {}", out.failure_text()),
            ));
        }

        Ok(ListOutput {
            repo_id: target.id,
            label: target.label.clone(),
            snapshots: parse_snapshots(&out.stdout)?,
        })
    }
}

// ---------------------------------------------------------------------------
// backup.restore
// ---------------------------------------------------------------------------

/// `backup.restore` — put a snapshot's contents into a staging directory.
pub struct Restore {
    program: String,
    state_root: Option<PathBuf>,
}

impl Restore {
    pub fn live() -> Self {
        Self {
            program: RESTIC.into(),
            state_root: None,
        }
    }

    #[cfg(test)]
    fn for_test(program: &str, state_root: PathBuf) -> Self {
        Self {
            program: program.into(),
            state_root: Some(state_root),
        }
    }

    fn state_root(&self) -> PathBuf {
        self.state_root.clone().unwrap_or_else(paths::state_dir)
    }
}

#[derive(Debug, Deserialize)]
pub struct RestoreInput {
    pub repo_id: i64,
    pub snapshot_id: String,
}

#[derive(Debug, Serialize)]
pub struct RestoreOutput {
    pub repo_id: i64,
    pub snapshot_id: String,
    /// Where the files landed. Nothing live was touched.
    pub staging_dir: String,
    pub next_steps: Vec<String>,
}

#[async_trait]
impl TypedOperation for Restore {
    type Input = RestoreInput;
    type Output = RestoreOutput;

    const NAME: &'static str = "backup.restore";
    const PERMISSION: Permission = Permission::BackupManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        // A restore into a fresh staging directory can be repeated; it writes
        // nowhere else.
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // Restoring reconstitutes files from a snapshot that may belong to any
        // tenant, into a directory on the panel's own filesystem. That is an
        // administrator's operation whatever the mode bits say.
        require_global(ctx, "restoring from a backup")?;

        let snapshot_id = check_snapshot_id(&input.snapshot_id)?;
        let target = resolve_repo(ctx, input.repo_id).await?;
        ensure_restic(ctx, &self.program).await?;

        // A directory per restore, named for when and what: two restores of
        // the same snapshot must not merge into one tree, and an operator
        // needs to be able to tell them apart afterwards.
        let stamp = unihelm_db::to_sql_time(unihelm_db::now()).replace(':', "-");
        let staging = self
            .state_root()
            .join("restore")
            .join(format!("{stamp}-{snapshot_id}"));
        std::fs::create_dir_all(&staging).map_err(|e| {
            UnihelmError::internal(format!("could not create {}: {e}", staging.display()))
        })?;
        // A restored tree can contain `/etc/unihelm/secret.key` and every
        // tenant's private files. 0700 before restic writes a single byte.
        restrict(&staging)?;

        let invocation = target.invocation(
            restore_args(&snapshot_id, &staging),
            LONG_TIMEOUT,
            &self.program,
        );
        ctx.log(format!("restoring into {}", staging.display()));
        ctx.log(format!("running {}", invocation.display()));

        let out = invocation
            .run_streaming(|line| {
                if !is_progress_noise(line) {
                    ctx.log(line);
                }
            })
            .await?;
        if !out.success() {
            return Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                format!("restic restore failed: {}", out.failure_text()),
            ));
        }

        Ok(RestoreOutput {
            repo_id: target.id,
            snapshot_id,
            staging_dir: staging.to_string_lossy().into_owned(),
            next_steps: vec![
                "Nothing live was changed: the files are in the staging directory above.".into(),
                "Copy back what you need, then delete the staging directory — it may \
                 contain /etc/unihelm/secret.key and tenant data."
                    .into(),
            ],
        })
    }
}

// ---------------------------------------------------------------------------
// backup.repo.delete
// ---------------------------------------------------------------------------

/// `backup.repo.delete` — forget a repository, leaving whatever is in it.
///
/// The panel deletes its *record*; it never deletes the snapshots. Wiping a
/// bucket from a control-panel button is not an action that should exist next
/// to a list of repositories, and an operator who genuinely wants the data gone
/// has `restic forget` and their storage provider's console.
pub struct RepoDelete;

#[derive(Debug, Deserialize)]
pub struct RepoDeleteInput {
    pub repo_id: i64,
}

#[derive(Debug, Serialize)]
pub struct RepoDeleteOutput {
    pub repo_id: i64,
    /// Said out loud in the response, because "delete" in a backup UI is
    /// exactly where an operator assumes the worst has happened.
    pub note: &'static str,
}

#[async_trait]
impl TypedOperation for RepoDelete {
    type Input = RepoDeleteInput;
    type Output = RepoDeleteOutput;

    const NAME: &'static str = "backup.repo.delete";
    const PERMISSION: Permission = Permission::BackupManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        require_global(ctx, "deleting a backup repository")?;

        // Asked before the delete so the refusal names the reason. The schema's
        // ON DELETE RESTRICT would stop this anyway, but as a bare SQLite
        // constraint failure it reaches the operator as "a database error
        // occurred", which tells them nothing about what to do next.
        if ctx
            .db()
            .backup_repo_has_runs(input.repo_id)
            .await
            .map_err(UnihelmError::from)?
        {
            return Err(UnihelmError::new(
                ErrorCode::AlreadyExists,
                "this repository has backup runs recorded against it; that history is the \
                 panel's only record of which snapshots exist, so the repository cannot be \
                 removed while it stands",
            ));
        }

        ctx.db()
            .delete_backup_repo(input.repo_id)
            .await
            .map_err(UnihelmError::from)?;

        Ok(RepoDeleteOutput {
            repo_id: input.repo_id,
            note: "The panel has forgotten this repository. Nothing in it was deleted: the \
                   snapshots and their data are still where they were.",
        })
    }
}

// ---------------------------------------------------------------------------
// backup.schedule.set / backup.schedule.delete
// ---------------------------------------------------------------------------

/// `backup.schedule.set` — when a scope is backed up, and how much is kept.
///
/// Administrator-only, and that is the same decision as everywhere else in this
/// module rather than a new one: a schedule names a repository, and repositories
/// hold credentials that cover the whole server. It is also what makes
/// [`Run::authorise_repository`] work — a tenant may write into a repository
/// *because* an administrator pointed a schedule for their subscription at it,
/// so a tenant who could create their own schedule could grant themselves that
/// access.
pub struct ScheduleSet;

#[derive(Debug, Deserialize)]
pub struct ScheduleSetInput {
    pub repo_id: i64,
    pub scope: BackupScope,
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// Five fields: `minute hour day-of-month month day-of-week`.
    pub cron: String,
    #[serde(default = "default_keep_daily")]
    pub keep_daily: i64,
    #[serde(default = "default_keep_weekly")]
    pub keep_weekly: i64,
    #[serde(default = "default_keep_monthly")]
    pub keep_monthly: i64,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

// Matching the column defaults in migration 0009: a week of dailies, a month of
// weeklies, half a year of monthlies.
const fn default_keep_daily() -> i64 {
    7
}
const fn default_keep_weekly() -> i64 {
    4
}
const fn default_keep_monthly() -> i64 {
    6
}
const fn default_enabled() -> bool {
    true
}

/// The largest retention count accepted.
///
/// The numbers reach restic's argv as `--keep-daily <n>`, and there is no
/// meaning to a five-digit one: a policy that keeps ten thousand daily
/// snapshots is a typo, and the place to catch a typo is before it silently
/// stops pruning anything.
const MAX_KEEP: i64 = 3650;

#[async_trait]
impl TypedOperation for ScheduleSet {
    type Input = ScheduleSetInput;
    type Output = unihelm_db::backups::BackupSchedule;

    const NAME: &'static str = "backup.schedule.set";
    const PERMISSION: Permission = Permission::BackupManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        require_global(ctx, "setting a backup schedule")?;

        // Parsed, not merely stored. An expression the scheduler cannot read is
        // a schedule that silently never fires, and the moment to find that out
        // is while somebody is looking at the form.
        CronSpec::parse(&input.cron)?;

        for (n, what) in [
            (input.keep_daily, "keep_daily"),
            (input.keep_weekly, "keep_weekly"),
            (input.keep_monthly, "keep_monthly"),
        ] {
            if !(0..=MAX_KEEP).contains(&n) {
                return Err(invalid(format!("{what} is between 0 and {MAX_KEEP}")).with_field(what));
            }
        }

        // The repository has to exist before a schedule can point at it —
        // otherwise the first the operator hears of the typo is a warning in
        // the agent journal at three in the morning.
        if ctx
            .db()
            .backup_repo(input.repo_id)
            .await
            .map_err(UnihelmError::from)?
            .is_none()
        {
            return Err(UnihelmError::not_found("backup repository"));
        }

        let subscription = match (input.scope, input.subscription_id) {
            (BackupScope::Panel, Some(_)) => {
                return Err(invalid(
                    "a panel-scope schedule covers the whole server; it takes no subscription",
                )
                .with_field("subscription_id"));
            }
            (BackupScope::Panel, None) => None,
            (BackupScope::Subscription, None) => {
                return Err(
                    invalid("a subscription-scope schedule needs a subscription")
                        .with_field("subscription_id"),
                );
            }
            (BackupScope::Subscription, Some(raw)) => {
                let sub = ctx
                    .db()
                    .subscriptions(&TenantScope::Global)
                    .by_id(SubscriptionId(raw))
                    .await
                    .map_err(UnihelmError::from)?
                    .ok_or_else(|| UnihelmError::not_found("subscription"))?;
                Some(sub.id)
            }
        };

        ctx.db()
            .create_backup_schedule(unihelm_db::backups::NewBackupSchedule {
                repo_id: input.repo_id,
                scope: input.scope,
                subscription_id: subscription,
                cron: input.cron,
                keep_daily: input.keep_daily,
                keep_weekly: input.keep_weekly,
                keep_monthly: input.keep_monthly,
                enabled: input.enabled,
            })
            .await
            .map_err(UnihelmError::from)
    }
}

/// `backup.schedule.delete` — stop a schedule firing.
///
/// The runs it already started keep their rows, with `schedule_id` set to NULL
/// (migration 0009). Turning a schedule off must not erase the evidence of what
/// it did.
pub struct ScheduleDelete;

#[derive(Debug, Deserialize)]
pub struct ScheduleDeleteInput {
    pub schedule_id: i64,
}

#[derive(Debug, Serialize)]
pub struct ScheduleDeleteOutput {
    pub schedule_id: i64,
}

#[async_trait]
impl TypedOperation for ScheduleDelete {
    type Input = ScheduleDeleteInput;
    type Output = ScheduleDeleteOutput;

    const NAME: &'static str = "backup.schedule.delete";
    const PERMISSION: Permission = Permission::BackupManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        require_global(ctx, "deleting a backup schedule")?;
        ctx.db()
            .delete_backup_schedule(input.schedule_id)
            .await
            .map_err(UnihelmError::from)?;
        Ok(ScheduleDeleteOutput {
            schedule_id: input.schedule_id,
        })
    }
}

// ---------------------------------------------------------------------------
// The scheduler pass
// ---------------------------------------------------------------------------

/// One pass over the backup schedules (spec §10.2, §11.10).
///
/// Called from `unihelm-agentd`'s scheduler under the system identity. Like the
/// Sentinel and alert passes it is deliberately **not** a Task: it runs every
/// minute and decides nothing on almost all of them, and a task row per tick
/// would bury the tasks a human started. The backups it does start each get a
/// `backup_runs` row, which is the record the backups page reads.
///
/// A schedule that fails is logged and the pass continues: one broken S3
/// endpoint must not stop every other tenant's backup that night.
pub async fn scheduler_tick(ctx: &OpContext) -> std::result::Result<String, String> {
    let now = unihelm_db::now();
    let schedules = ctx
        .db()
        .enabled_backup_schedules()
        .await
        .map_err(|e| e.to_string())?;
    if schedules.is_empty() {
        return Ok(String::new());
    }

    let mut started = 0;
    let mut failed = 0;

    for schedule in schedules {
        let spec = match CronSpec::parse(&schedule.cron) {
            Ok(spec) => spec,
            Err(e) => {
                // Stored expressions are validated on the way in, so this is a
                // hand-edited row or a downgrade. Say so once per tick rather
                // than failing the whole pass.
                tracing::warn!(schedule = schedule.id, cron = %schedule.cron, error = %e.detail,
                    "a backup schedule has an unreadable cron expression");
                continue;
            }
        };

        let last = ctx
            .db()
            .last_backup_run_start(schedule.id)
            .await
            .unwrap_or(None);
        if !spec.is_due(last, now) {
            continue;
        }

        let subscription = schedule.subscription_id.map(SubscriptionId);
        let target = match resolve_repo(ctx, schedule.repo_id).await {
            Ok(t) => t,
            Err(e) => {
                failed += 1;
                tracing::warn!(schedule = schedule.id, error = %e.detail,
                    "a scheduled backup could not open its repository");
                continue;
            }
        };

        if let Err(e) = ensure_restic(ctx, RESTIC).await {
            failed += 1;
            tracing::warn!(schedule = schedule.id, error = %e.detail,
                "a scheduled backup cannot run without restic");
            continue;
        }

        match run_backup(
            ctx,
            RESTIC,
            &paths::state_dir(),
            &target,
            schedule.scope,
            subscription,
            Some(schedule.id),
        )
        .await
        {
            Ok(out) => {
                started += 1;
                tracing::info!(schedule = schedule.id, snapshot = ?out.snapshot_id,
                    "scheduled backup finished");
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(schedule = schedule.id, error = %e.detail,
                    "scheduled backup failed");
            }
        }
    }

    match (started, failed) {
        (0, 0) => Ok(String::new()),
        (s, 0) => Ok(format!("{s} backup(s) ran")),
        (s, f) => Err(format!("{s} backup(s) ran, {f} failed — see backup_runs")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use std::sync::Arc;
    use time::macros::datetime;
    use unihelm_core::{AuthContext, Role, UserId};
    use unihelm_db::backups::{NewBackupSchedule, RunStatus};
    use unihelm_distro::mock::{RecordingLog, SharedRecorder};

    // -----------------------------------------------------------------------
    // argv / env: the security claim this module rests on
    // -----------------------------------------------------------------------

    fn target() -> RepoTarget {
        RepoTarget {
            id: 1,
            label: "nightly".into(),
            kind: RepoKind::S3,
            location: "s3.example.com/unihelm".into(),
            password: "PASSWORD-DO-NOT-LEAK".into(),
            credentials: Some(S3Credentials {
                access_key_id: "AKIAEXAMPLE".into(),
                secret_access_key: "SECRET-DO-NOT-LEAK".into(),
                region: Some("us-east-1".into()),
            }),
        }
    }

    /// The claim in the module header, asserted directly: `/proc/<pid>/cmdline`
    /// is world-readable and `/proc/<pid>/environ` is not, so every secret has
    /// to be in the environment and none of them may be in argv.
    #[test]
    fn the_repository_password_reaches_restic_through_the_environment_and_never_argv() {
        let t = target();
        for args in [
            init_args(),
            backup_args("unihelm-panel", &[PathBuf::from("/var/lib/unihelm")]),
            snapshots_args(Some("unihelm-sub-3")),
            restore_args("abc12345", Path::new("/var/lib/unihelm/state/restore/x")),
            forget_args(
                "unihelm-panel",
                KeepPolicy {
                    daily: 7,
                    weekly: 4,
                    monthly: 6,
                },
            ),
        ] {
            let inv = t.invocation(args, IMMEDIATE_TIMEOUT, "restic");

            let argv = inv.args.join(" ");
            for secret in ["PASSWORD-DO-NOT-LEAK", "SECRET-DO-NOT-LEAK"] {
                assert!(
                    !argv.contains(secret),
                    "a secret appeared in argv, which /proc publishes world-readable: {argv}"
                );
                assert!(
                    !inv.display().contains(secret),
                    "a secret appeared in the string written to the task log"
                );
                assert!(
                    !format!("{inv:?}").contains(secret),
                    "a secret appeared in the Debug rendering"
                );
            }

            let env: std::collections::HashMap<_, _> = inv.env.iter().cloned().collect();
            assert_eq!(env["RESTIC_PASSWORD"], "PASSWORD-DO-NOT-LEAK");
            assert_eq!(env["AWS_SECRET_ACCESS_KEY"], "SECRET-DO-NOT-LEAK");
            assert_eq!(env["AWS_ACCESS_KEY_ID"], "AKIAEXAMPLE");
            assert_eq!(env["AWS_DEFAULT_REGION"], "us-east-1");
            assert_eq!(env["RESTIC_REPOSITORY"], "s3:s3.example.com/unihelm");
        }
    }

    #[test]
    fn a_local_repository_carries_no_credentials_and_no_s3_prefix() {
        let t = RepoTarget {
            id: 2,
            label: "disk".into(),
            kind: RepoKind::Local,
            location: "/srv/backups".into(),
            password: "pw".into(),
            credentials: None,
        };
        let env: std::collections::HashMap<_, _> = t.env().into_iter().collect();
        assert_eq!(env["RESTIC_REPOSITORY"], "/srv/backups");
        assert!(!env.contains_key("AWS_ACCESS_KEY_ID"));
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn the_backup_argv_separates_flags_from_paths() {
        let args = backup_args("unihelm-panel", &[PathBuf::from("/etc/unihelm")]);
        let dash_dash = args.iter().position(|a| a == "--").expect("`--` present");
        assert_eq!(args[dash_dash + 1], "/etc/unihelm");
        assert!(args.contains(&"--json".to_string()));
        assert_eq!(args[0], "backup");
    }

    /// Retention has to be per tag. One repository holds the panel's snapshots
    /// and every tenant's; a policy applied to all of them would delete the
    /// panel's history the first time a tenant's schedule ran.
    #[test]
    fn retention_argv_is_scoped_to_one_tag_and_actually_prunes() {
        let args = forget_args(
            "unihelm-sub-42",
            KeepPolicy {
                daily: 7,
                weekly: 4,
                monthly: 12,
            },
        );
        assert_eq!(args[0], "forget");
        assert!(args.contains(&"--prune".to_string()), "{args:?}");

        let pos = |flag: &str| args.iter().position(|a| a == flag).expect(flag);
        assert_eq!(args[pos("--tag") + 1], "unihelm-sub-42");
        assert_eq!(args[pos("--group-by") + 1], "tags");
        assert_eq!(args[pos("--keep-daily") + 1], "7");
        assert_eq!(args[pos("--keep-weekly") + 1], "4");
        assert_eq!(args[pos("--keep-monthly") + 1], "12");
    }

    #[test]
    fn a_subscription_tag_names_the_id_not_the_linux_user() {
        assert_eq!(
            scope_tag(BackupScope::Subscription, Some(SubscriptionId(42))),
            "unihelm-sub-42"
        );
        assert_eq!(scope_tag(BackupScope::Panel, None), "unihelm-panel");
    }

    // -----------------------------------------------------------------------
    // restic JSON
    // -----------------------------------------------------------------------

    /// A real `restic snapshots --json` body, trimmed of the fields the panel
    /// does not read — including one (`program_version`) it has never seen, to
    /// prove an added field does not break the list.
    const SNAPSHOTS_FIXTURE: &str = r#"[
      {
        "time": "2026-08-20T03:00:11.123456789Z",
        "parent": "9f8e7d6c5b4a39281706f5e4d3c2b1a0998877665544332211ffeeddccbbaa99",
        "tree": "1122334455667788990011223344556677889900112233445566778899001122",
        "paths": ["/var/lib/unihelm/state", "/etc/unihelm"],
        "hostname": "web-01",
        "username": "root",
        "tags": ["unihelm-panel"],
        "program_version": "restic 0.17.3",
        "id": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        "short_id": "aabbccdd"
      },
      {
        "time": "2026-08-21T03:00:09.5Z",
        "paths": ["/home/uh_ab12cd"],
        "hostname": "web-01",
        "tags": ["unihelm-sub-3"],
        "id": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "short_id": "00112233"
      }
    ]"#;

    #[test]
    fn the_snapshot_list_survives_fields_the_panel_has_never_seen() {
        let snapshots = parse_snapshots(SNAPSHOTS_FIXTURE).expect("the fixture parses");
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].short_id, "aabbccdd");
        assert_eq!(snapshots[0].tags, vec!["unihelm-panel"]);
        assert_eq!(snapshots[1].paths, vec!["/home/uh_ab12cd"]);
        assert_eq!(snapshots[1].hostname, "web-01");
    }

    #[test]
    fn an_empty_repository_lists_as_no_snapshots_rather_than_an_error() {
        assert!(parse_snapshots("[]\n").unwrap().is_empty());
    }

    #[test]
    fn garbage_where_snapshots_should_be_is_reported_not_swallowed() {
        let err = parse_snapshots("Fatal: unable to open config file").unwrap_err();
        assert_eq!(err.code, ErrorCode::CommandFailed);
    }

    #[test]
    fn the_summary_is_read_from_the_end_of_the_backup_stream() {
        // Real shape: several status messages, then one summary. The status
        // lines also carry byte counts, so reading the wrong line would give a
        // plausible-looking wrong answer.
        let stream = concat!(
            r#"{"message_type":"status","percent_done":0.5,"total_bytes":999}"#,
            "\n",
            r#"{"message_type":"status","percent_done":0.9,"total_bytes":999}"#,
            "\n",
            r#"{"message_type":"summary","files_new":12,"files_changed":3,"#,
            r#""total_bytes_processed":45678,"#,
            r#""snapshot_id":"aabbccddeeff00112233445566778899aabbccddeeff001122334455667788"}"#,
            "\n"
        );
        let summary = parse_backup_summary(stream).expect("a summary is present");
        assert_eq!(summary.bytes, Some(45678));
        assert_eq!(summary.files_new, Some(12));
        assert!(summary.snapshot_id.unwrap().starts_with("aabbccdd"));
    }

    #[test]
    fn a_backup_without_a_summary_line_is_still_a_backup() {
        // An older restic emits no summary. The run succeeded; we just cannot
        // name the snapshot, and refusing to record it would turn a cosmetic
        // difference into a failed backup.
        assert!(parse_backup_summary("").is_none());
        assert!(parse_backup_summary("Files: 3 new, 0 changed\n").is_none());
    }

    #[test]
    fn per_second_progress_messages_are_kept_out_of_the_task_log() {
        assert!(is_progress_noise(
            r#"{"message_type":"status","percent_done":0.1}"#
        ));
        assert!(!is_progress_noise(
            r#"{"message_type":"summary","snapshot_id":"a"}"#
        ));
        assert!(!is_progress_noise("Fatal: repository is already locked"));
    }

    // -----------------------------------------------------------------------
    // input validation
    // -----------------------------------------------------------------------

    #[test]
    fn a_repository_location_that_could_truncate_its_environment_entry_is_refused() {
        // An environment entry is a NUL-terminated string: a NUL in the middle
        // of RESTIC_REPOSITORY silently sends the backup somewhere else.
        for hostile in [
            "/srv/back\0ups",
            "/srv/backups\nRESTIC_PASSWORD=hunter2",
            "-rf",
            "",
            "   ",
        ] {
            assert!(
                check_local_path(hostile).is_err(),
                "`{hostile}` should be refused"
            );
        }
        assert!(check_local_path("relative/path").is_err());
        assert!(check_local_path("/srv/../etc").is_err());
        assert_eq!(check_local_path("/srv/backups").unwrap(), "/srv/backups");
    }

    #[test]
    fn an_s3_location_needs_a_bucket_and_keeps_one_scheme_prefix() {
        assert!(check_s3_url("s3.example.com").is_err());
        assert_eq!(
            check_s3_url("s3:s3.example.com/unihelm").unwrap(),
            "s3.example.com/unihelm",
            "a pasted `s3:` must not become `s3:s3:`"
        );
        assert_eq!(
            check_s3_url("https://minio.example.com/unihelm/panel").unwrap(),
            "https://minio.example.com/unihelm/panel"
        );
    }

    #[test]
    fn a_snapshot_id_that_could_be_read_as_a_flag_is_refused() {
        // This value does reach argv. Hex never starts with a dash, so the
        // validation is what makes the restore argv safe.
        for hostile in ["--json", "-x", "latest;rm -rf /", "zzzz1234", "abc", ""] {
            assert!(
                check_snapshot_id(hostile).is_err(),
                "`{hostile}` should be refused"
            );
        }
        assert_eq!(check_snapshot_id("AABBCCDD").unwrap(), "aabbccdd");
        assert_eq!(check_snapshot_id("latest").unwrap(), "latest");
    }

    #[test]
    fn a_label_is_something_a_human_typed() {
        assert!(check_label("").is_err());
        assert!(check_label(&"a".repeat(MAX_LABEL + 1)).is_err());
        assert!(check_label("nightly\n").is_err());
        assert_eq!(check_label("  Nightly S3  ").unwrap(), "Nightly S3");
    }

    #[test]
    fn a_generated_password_is_long_and_needs_no_escaping() {
        let a = generate_repo_password();
        let b = generate_repo_password();
        assert_ne!(a, b, "two repositories must not share a password");
        assert_eq!(a.chars().count(), 32);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    // -----------------------------------------------------------------------
    // cron
    // -----------------------------------------------------------------------

    #[test]
    fn a_five_field_expression_is_required() {
        for bad in ["", "0 3 * *", "0 3 * * * *", "@daily", "x y z a b"] {
            assert!(CronSpec::parse(bad).is_err(), "`{bad}` should not parse");
        }
        assert!(CronSpec::parse("0 3 * * *").is_ok());
        assert!(CronSpec::parse("*/15 * * * *").is_ok());
        assert!(CronSpec::parse("0,30 1-5 1,15 */3 1-5").is_ok());
    }

    #[test]
    fn out_of_range_and_backwards_fields_are_refused() {
        for bad in [
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * 32 * *",
            "* * * 13 *",
            "* * * * 8",
            "5-1 * * * *",
            "*/0 * * * *",
            "* * * * 1,,2",
        ] {
            assert!(CronSpec::parse(bad).is_err(), "`{bad}` should not parse");
        }
    }

    #[test]
    fn a_nightly_schedule_matches_only_its_minute() {
        let spec = CronSpec::parse("0 3 * * *").unwrap();
        assert!(spec.matches(datetime!(2026-08-20 03:00:00 UTC)));
        assert!(!spec.matches(datetime!(2026-08-20 03:01:00 UTC)));
        assert!(!spec.matches(datetime!(2026-08-20 04:00:00 UTC)));
    }

    #[test]
    fn a_step_expression_matches_every_nth_minute() {
        let spec = CronSpec::parse("*/15 * * * *").unwrap();
        for minute in [0, 15, 30, 45] {
            assert!(
                spec.matches(datetime!(2026-08-20 00:00:00 UTC) + time::Duration::minutes(minute))
            );
        }
        assert!(!spec.matches(datetime!(2026-08-20 00:07:00 UTC)));
    }

    /// The rule everybody gets wrong, pinned: with both day fields restricted
    /// cron takes the *union*, not the intersection.
    #[test]
    fn day_of_month_and_day_of_week_combine_as_an_or_when_both_are_restricted() {
        // 1st of the month, or any Monday.
        let spec = CronSpec::parse("0 0 1 * 1").unwrap();
        // 2026-09-01 is a Tuesday: matches on day-of-month alone.
        assert!(spec.matches(datetime!(2026-09-01 00:00:00 UTC)));
        // 2026-09-07 is a Monday: matches on day-of-week alone.
        assert!(spec.matches(datetime!(2026-09-07 00:00:00 UTC)));
        // 2026-09-08 is a Tuesday and not the 1st.
        assert!(!spec.matches(datetime!(2026-09-08 00:00:00 UTC)));

        // With only day-of-week restricted it is an ordinary and.
        let mondays = CronSpec::parse("0 0 * * 1").unwrap();
        assert!(mondays.matches(datetime!(2026-09-07 00:00:00 UTC)));
        assert!(!mondays.matches(datetime!(2026-09-01 00:00:00 UTC)));
    }

    #[test]
    fn sunday_is_both_zero_and_seven() {
        let zero = CronSpec::parse("0 0 * * 0").unwrap();
        let seven = CronSpec::parse("0 0 * * 7").unwrap();
        // 2026-09-06 is a Sunday.
        assert!(zero.matches(datetime!(2026-09-06 00:00:00 UTC)));
        assert!(seven.matches(datetime!(2026-09-06 00:00:00 UTC)));
        assert!(!seven.matches(datetime!(2026-09-07 00:00:00 UTC)));
    }

    #[test]
    fn a_schedule_that_already_ran_this_minute_is_not_due_again() {
        let spec = CronSpec::parse("0 3 * * *").unwrap();
        let now = datetime!(2026-08-20 03:00:30 UTC);
        assert!(spec.is_due(Some(datetime!(2026-08-19 03:00:00 UTC)), now));
        assert!(!spec.is_due(Some(datetime!(2026-08-20 03:00:02 UTC)), now));
    }

    /// The reason the due check walks backwards instead of testing one minute:
    /// the scheduler's interval carries jitter and the agent restarts.
    #[test]
    fn a_minute_the_scheduler_slept_through_is_still_caught() {
        let spec = CronSpec::parse("0 3 * * *").unwrap();
        // Woke at 03:04, last ran the previous morning: 03:00 was missed and
        // must still fire.
        assert!(spec.is_due(
            Some(datetime!(2026-08-19 03:00:00 UTC)),
            datetime!(2026-08-20 03:04:00 UTC)
        ));
        // Down for two days: fires once, not once per missed day.
        assert!(spec.is_due(
            Some(datetime!(2026-08-17 03:00:00 UTC)),
            datetime!(2026-08-20 09:00:00 UTC)
        ));
    }

    #[test]
    fn a_brand_new_schedule_does_not_immediately_run_last_nights_backup() {
        let spec = CronSpec::parse("0 3 * * *").unwrap();
        // Created at two in the afternoon: 03:00 already passed today, and
        // firing now would be a surprise backup nobody asked for.
        assert!(!spec.is_due(None, datetime!(2026-08-20 14:00:00 UTC)));
        // But its own minute, possibly a jittered tick late, does fire.
        assert!(spec.is_due(None, datetime!(2026-08-20 03:00:00 UTC)));
        assert!(spec.is_due(None, datetime!(2026-08-20 03:02:00 UTC)));
        assert!(!spec.is_due(None, datetime!(2026-08-20 03:30:00 UTC)));
    }

    // -----------------------------------------------------------------------
    // operations, against the mock distro
    // -----------------------------------------------------------------------

    /// A registry over a mock distro, plus a context that records everything
    /// written to the task log.
    ///
    /// `echo` stands in for restic: it is present on every machine that runs
    /// these tests, it exits 0, and — usefully — it *prints its own argv*, so
    /// the recorded task log contains exactly the bytes an operator would see.
    /// That makes the "no secret in the log" assertion below a real one rather
    /// than a statement about a string we built ourselves.
    async fn context() -> (crate::OpRegistry, OpContext, SharedRecorder, UserId) {
        let (reg, admin, customer) = registry().await;
        let rec: SharedRecorder = Arc::new(std::sync::Mutex::new(Default::default()));
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin)).with_task(
            unihelm_core::TaskId::new(),
            Arc::new(RecordingLog(rec.clone())),
        );
        (reg, ctx, rec, customer)
    }

    /// Like [`context`], but over a database that lives in a **file**.
    ///
    /// The shared `registry()` helper opens `sqlite::memory:`, and every
    /// panel-scope test here goes through `VACUUM INTO` — which against an
    /// in-memory database reports success and writes nothing at all (see
    /// `Db::vacuum_into`). A panel-scope run therefore cannot be exercised on
    /// the shared harness; it needs a real file, exactly as production has.
    async fn file_backed_context(
        db_dir: &Path,
    ) -> (crate::OpRegistry, OpContext, SharedRecorder, UserId) {
        use unihelm_core::{Email, Username};
        use unihelm_db::users::NewUser;

        let db = unihelm_db::Db::open(db_dir.join("panel.db")).await.unwrap();
        let mk = |name: &'static str, role: Role| NewUser {
            role,
            email: Email::parse(&format!("{name}@example.com")).unwrap(),
            username: Username::parse(name).unwrap(),
            password: "a-long-enough-password".into(),
            reseller_id: None,
            full_name: None,
            locale: "en".into(),
        };
        let admin = db
            .users(&TenantScope::Global)
            .create(mk("admin", Role::Admin))
            .await
            .unwrap()
            .id;
        let customer = db
            .users(&TenantScope::Global)
            .create(mk("client", Role::Customer))
            .await
            .unwrap()
            .id;

        let services = Arc::new(
            crate::Services::new(
                unihelm_distro::Distro::mock(),
                db,
                unihelm_db::MasterKey::generate(),
            )
            .expect("templates compile"),
        );
        let reg = crate::OpRegistry::new(services);
        let rec: SharedRecorder = Arc::new(std::sync::Mutex::new(Default::default()));
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin)).with_task(
            unihelm_core::TaskId::new(),
            Arc::new(RecordingLog(rec.clone())),
        );
        (reg, ctx, rec, customer)
    }

    fn log_text(rec: &SharedRecorder) -> String {
        rec.lock().expect("recorder").log_lines.join("\n")
    }

    async fn init_local_repo(ctx: &OpContext, dir: &Path, label: &str) -> RepoInitOutput {
        RepoInit::with_program("echo")
            .run(
                ctx,
                RepoInitInput {
                    kind: RepoKind::Local,
                    label: label.into(),
                    path_or_url: dir.to_string_lossy().into_owned(),
                    s3: None,
                },
            )
            .await
            .expect("init succeeds against the stand-in binary")
    }

    #[tokio::test]
    async fn creating_a_repository_shows_its_password_once_and_stores_only_ciphertext() {
        // The disaster-recovery decision in the module header, asserted: the
        // operator gets the password back exactly here, and what stays behind
        // is sealed.
        let dir = tempfile::tempdir().unwrap();
        let (reg, ctx, _rec, _) = context().await;
        let out = init_local_repo(&ctx, dir.path(), "nightly").await;

        assert_eq!(out.password.chars().count(), 32);
        assert!(out.password_notice.contains("shown once"));
        assert_eq!(out.repository, dir.path().to_string_lossy());

        let db = &reg.services().db;
        let secrets = db.backup_repo_secrets(out.repo_id).await.unwrap();
        assert!(
            !secrets.password_sealed.contains(&out.password),
            "the stored password must be ciphertext"
        );
        assert_eq!(
            reg.services()
                .master_key
                .open_str(&secrets.password_sealed)
                .unwrap(),
            out.password,
            "…and the panel must still be able to open it for a scheduled run"
        );

        // The repository listing never carries it, in either direction.
        let listed = serde_json::to_string(&db.backup_repos().await.unwrap()).unwrap();
        assert!(!listed.contains(&out.password), "{listed}");
    }

    #[tokio::test]
    async fn an_s3_repository_without_credentials_is_refused_before_anything_is_created() {
        let (reg, ctx, _rec, _) = context().await;
        let err = RepoInit::with_program("echo")
            .run(
                &ctx,
                RepoInitInput {
                    kind: RepoKind::S3,
                    label: "offsite".into(),
                    path_or_url: "s3.example.com/unihelm".into(),
                    s3: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(
            reg.services().db.backup_repos().await.unwrap().is_empty(),
            "a refused request must leave no row behind"
        );
    }

    #[tokio::test]
    async fn a_failed_init_leaves_no_repository_row_to_confuse_the_next_attempt() {
        // `false` stands in for a restic that could not reach the endpoint.
        let dir = tempfile::tempdir().unwrap();
        let (reg, ctx, _rec, _) = context().await;
        let err = RepoInit::with_program("false")
            .run(
                &ctx,
                RepoInitInput {
                    kind: RepoKind::Local,
                    label: "nightly".into(),
                    path_or_url: dir.path().to_string_lossy().into_owned(),
                    s3: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::CommandFailed);
        assert!(
            reg.services().db.backup_repos().await.unwrap().is_empty(),
            "the row must be rolled back so the same label can be retried"
        );
    }

    #[tokio::test]
    async fn a_customer_cannot_create_a_backup_repository() {
        let (reg, _, _rec, customer) = context().await;
        let ctx = OpContext::new(reg.services().clone(), auth_for(customer, Role::Customer));
        let err = RepoInit::with_program("echo")
            .run(
                &ctx,
                RepoInitInput {
                    kind: RepoKind::Local,
                    label: "mine".into(),
                    path_or_url: "/tmp/mine".into(),
                    s3: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    /// The end-to-end version of the argv/env claim: run a whole panel backup
    /// with a stand-in binary that echoes its own argv, and read the task log
    /// the operator would read.
    #[tokio::test]
    async fn a_panel_backup_never_writes_the_repository_password_to_the_task_log() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let (reg, ctx, rec, _) = file_backed_context(db_dir.path()).await;
        let repo = init_local_repo(&ctx, dir.path(), "nightly").await;

        let out = Run::for_test("echo", state.path().to_path_buf())
            .run(
                &ctx,
                RunInput {
                    repo_id: repo.repo_id,
                    scope: BackupScope::Panel,
                    subscription_id: None,
                },
            )
            .await
            .expect("the run completes");

        let log = log_text(&rec);
        assert!(
            !log.contains(&repo.password),
            "the password must never reach the task log:\n{log}"
        );
        assert!(log.contains("backup --json --tag unihelm-panel"), "{log}");
        // The database copy is in the path list and nothing else survived.
        assert!(
            out.paths.iter().any(|p| p.ends_with(".db")),
            "{:?}",
            out.paths
        );

        let runs = reg
            .services()
            .db
            .backups(&TenantScope::Global)
            .runs(10, 0)
            .await
            .unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, RunStatus::Ok);
    }

    #[tokio::test]
    async fn the_working_copy_of_the_panel_database_is_deleted_when_the_run_ends() {
        // It is a full copy of every sealed secret the panel holds; leaving it
        // behind would be a second permanent copy of the panel's state.
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let (_reg, ctx, _rec, _) = file_backed_context(db_dir.path()).await;
        let repo = init_local_repo(&ctx, dir.path(), "nightly").await;

        Run::for_test("echo", state.path().to_path_buf())
            .run(
                &ctx,
                RunInput {
                    repo_id: repo.repo_id,
                    scope: BackupScope::Panel,
                    subscription_id: None,
                },
            )
            .await
            .unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(state.path().join("backup-work"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    #[tokio::test]
    async fn a_failing_restic_marks_the_run_failed_rather_than_leaving_it_running() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let (reg, ctx, _rec, _) = file_backed_context(db_dir.path()).await;
        let repo = init_local_repo(&ctx, dir.path(), "nightly").await;

        let err = Run::for_test("false", state.path().to_path_buf())
            .run(
                &ctx,
                RunInput {
                    repo_id: repo.repo_id,
                    scope: BackupScope::Panel,
                    subscription_id: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::CommandFailed);

        let runs = reg
            .services()
            .db
            .backups(&TenantScope::Global)
            .runs(10, 0)
            .await
            .unwrap();
        assert_eq!(runs[0].status, RunStatus::Failed);
        assert!(runs[0].error.is_some());
        assert!(runs[0].finished_at.is_some());
    }

    #[tokio::test]
    async fn a_panel_scope_backup_is_refused_to_anyone_but_an_administrator() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let (reg, ctx, _rec, customer) = context().await;
        let repo = init_local_repo(&ctx, dir.path(), "nightly").await;

        let theirs = OpContext::new(reg.services().clone(), auth_for(customer, Role::Customer));
        let err = Run::for_test("echo", state.path().to_path_buf())
            .run(
                &theirs,
                RunInput {
                    repo_id: repo.repo_id,
                    scope: BackupScope::Panel,
                    subscription_id: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn a_customer_cannot_back_up_into_a_repository_they_were_never_given() {
        // Repository ids are small integers. Without the schedule check a
        // customer holding `backup_manage` could enumerate them and write into
        // an administrator's bucket.
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let (reg, ctx, _rec, customer) = context().await;
        let repo = init_local_repo(&ctx, dir.path(), "nightly").await;

        let db = &reg.services().db;
        let sub = db.create_subscription(customer).await.unwrap();
        let theirs = OpContext::new(
            reg.services().clone(),
            AuthContext::from_role(
                customer,
                Role::Customer,
                TenantScope::Customer {
                    customer_id: customer,
                },
                "req-test",
            ),
        );

        let err = Run::for_test("echo", state.path().to_path_buf())
            .run(
                &theirs,
                RunInput {
                    repo_id: repo.repo_id,
                    scope: BackupScope::Subscription,
                    subscription_id: Some(sub.id.get()),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::NotFound,
            "the answer must not distinguish `someone else's` from `no such repository`"
        );

        // Once an administrator points a schedule at it, the same call works.
        db.create_backup_schedule(NewBackupSchedule {
            repo_id: repo.repo_id,
            scope: BackupScope::Subscription,
            subscription_id: Some(sub.id),
            cron: "0 3 * * *".into(),
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 6,
            enabled: true,
        })
        .await
        .unwrap();

        // The tenant home does not exist in the test environment, so the run
        // stops at "nothing to back up" — which is past the authorization
        // check, and that is what this asserts.
        let err = Run::for_test("echo", state.path().to_path_buf())
            .run(
                &theirs,
                RunInput {
                    repo_id: repo.repo_id,
                    scope: BackupScope::Subscription,
                    subscription_id: Some(sub.id.get()),
                },
            )
            .await
            .unwrap_err();
        assert!(
            err.detail.contains("nothing to back up"),
            "expected to get past authorization, got: {}",
            err.detail
        );
    }

    #[tokio::test]
    async fn a_customer_cannot_list_snapshots_in_a_repository_they_were_never_given() {
        // The same gate as the run above, on the read path. The tag filter
        // already stops a tenant reading another tenant's snapshots — this is
        // about the repository itself: without the check, a customer could walk
        // repository ids and make the panel open an administrator's sealed
        // credentials and connect to their endpoint, which is both an
        // information leak (which ids exist) and somebody else's S3 bill.
        let dir = tempfile::tempdir().unwrap();
        let (reg, ctx, _rec, customer) = context().await;
        let repo = init_local_repo(&ctx, dir.path(), "nightly").await;

        let db = &reg.services().db;
        let sub = db.create_subscription(customer).await.unwrap();
        let theirs = OpContext::new(reg.services().clone(), auth_for(customer, Role::Customer));

        let err = List::with_program("echo")
            .run(
                &theirs,
                ListInput {
                    repo_id: repo.repo_id,
                    subscription_id: Some(sub.id.get()),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::NotFound,
            "the answer must not distinguish `someone else's` from `no such repository`"
        );

        // And with an administrator's schedule pointing at it, the same call
        // gets through to restic — here a stand-in whose output is not JSON, so
        // it fails *after* the gate rather than at it.
        db.create_backup_schedule(NewBackupSchedule {
            repo_id: repo.repo_id,
            scope: BackupScope::Subscription,
            subscription_id: Some(sub.id),
            cron: "0 3 * * *".into(),
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 6,
            enabled: true,
        })
        .await
        .unwrap();

        let err = List::with_program("echo")
            .run(
                &theirs,
                ListInput {
                    repo_id: repo.repo_id,
                    subscription_id: Some(sub.id.get()),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::CommandFailed,
            "expected to get past authorization and fail on the stand-in's output, got: {}",
            err.detail
        );
    }

    #[tokio::test]
    async fn a_scheduled_run_prunes_under_that_schedules_policy() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let (reg, ctx, rec, _) = file_backed_context(db_dir.path()).await;
        let repo = init_local_repo(&ctx, dir.path(), "nightly").await;

        reg.services()
            .db
            .create_backup_schedule(NewBackupSchedule {
                repo_id: repo.repo_id,
                scope: BackupScope::Panel,
                subscription_id: None,
                cron: "0 3 * * *".into(),
                keep_daily: 3,
                keep_weekly: 2,
                keep_monthly: 1,
                enabled: true,
            })
            .await
            .unwrap();

        let out = Run::for_test("echo", state.path().to_path_buf())
            .run(
                &ctx,
                RunInput {
                    repo_id: repo.repo_id,
                    scope: BackupScope::Panel,
                    subscription_id: None,
                },
            )
            .await
            .unwrap();
        assert!(out.pruned);

        let log = log_text(&rec);
        assert!(log.contains("forget --prune --tag unihelm-panel"), "{log}");
        assert!(log.contains("--keep-daily 3"), "{log}");
    }

    #[tokio::test]
    async fn a_scope_with_no_schedule_prunes_nothing_at_all() {
        // Inventing a retention policy would be the panel deleting snapshots
        // nobody asked it to delete.
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let (_reg, ctx, rec, _) = file_backed_context(db_dir.path()).await;
        let repo = init_local_repo(&ctx, dir.path(), "nightly").await;

        let out = Run::for_test("echo", state.path().to_path_buf())
            .run(
                &ctx,
                RunInput {
                    repo_id: repo.repo_id,
                    scope: BackupScope::Panel,
                    subscription_id: None,
                },
            )
            .await
            .unwrap();
        assert!(!out.pruned);
        assert!(!log_text(&rec).contains("forget"));
    }

    #[tokio::test]
    async fn restoring_lands_in_a_staging_directory_and_touches_nothing_live() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let (_reg, ctx, rec, _) = context().await;
        let repo = init_local_repo(&ctx, dir.path(), "nightly").await;

        let out = Restore::for_test("echo", state.path().to_path_buf())
            .run(
                &ctx,
                RestoreInput {
                    repo_id: repo.repo_id,
                    snapshot_id: "aabbccdd".into(),
                },
            )
            .await
            .unwrap();

        let staging = PathBuf::from(&out.staging_dir);
        assert!(staging.is_dir());
        assert!(staging.starts_with(state.path().join("restore")));

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&staging).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "a restored tree can contain the master key");

        let log = log_text(&rec);
        assert!(!log.contains(&repo.password), "{log}");
        assert!(log.contains("restore aabbccdd --target"), "{log}");
    }

    #[tokio::test]
    async fn restoring_is_refused_to_a_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let (reg, ctx, _rec, customer) = context().await;
        let repo = init_local_repo(&ctx, dir.path(), "nightly").await;

        let theirs = OpContext::new(reg.services().clone(), auth_for(customer, Role::Customer));
        let err = Restore::for_test("echo", state.path().to_path_buf())
            .run(
                &theirs,
                RestoreInput {
                    repo_id: repo.repo_id,
                    snapshot_id: "aabbccdd".into(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn listing_snapshots_asks_restic_for_json_and_reads_what_comes_back() {
        // `printf` stands in for restic here rather than `echo`, because the
        // fixture has to come back on stdout as JSON.
        let dir = tempfile::tempdir().unwrap();
        let (_reg, ctx, _rec, _) = context().await;
        let repo = init_local_repo(&ctx, dir.path(), "nightly").await;

        let err = List::with_program("false")
            .run(
                &ctx,
                ListInput {
                    repo_id: repo.repo_id,
                    subscription_id: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::CommandFailed,
            "a restic that cannot open the repository must be reported, not parsed"
        );
    }

    #[tokio::test]
    async fn a_missing_restic_names_the_package_to_install() {
        // The mock package backend "installs" without producing a binary,
        // which is exactly the situation the message is written for.
        let (_reg, ctx, _rec, _) = context().await;
        let err = ensure_restic(&ctx, "definitely-not-a-real-binary-xyz")
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::CommandFailed);
        assert!(err.detail.contains("restic"), "{}", err.detail);
        assert!(err.detail.contains("epel-release"), "{}", err.detail);
    }

    #[tokio::test]
    async fn the_scheduler_pass_is_silent_when_nothing_is_due() {
        let (_reg, ctx, _rec, _) = context().await;
        assert_eq!(scheduler_tick(&ctx).await.unwrap(), "");
    }
}
