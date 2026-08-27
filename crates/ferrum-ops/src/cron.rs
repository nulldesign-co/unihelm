//! Per-subscription cron jobs (spec §11.8).
//!
//! A tenant's crontab is a **rendering of the panel database**, never a file
//! the panel edits in place. Every change re-renders the whole thing from
//! `cron_jobs` and installs it with `crontab -u <user> -` on stdin. Two
//! properties follow from that, and both are the reason for the design:
//!
//! * **Deterministic.** The same set of jobs always produces byte-identical
//!   output (sorted by schedule, then command, then id — see
//!   [`ferrum_db::Db::cron_jobs_for_render`]), so "save a job that did not
//!   change" really does write the same file.
//! * **No line surgery.** A crontab line has no identity. Editing one in place
//!   would mean finding "the line that used to be this job" by string match —
//!   and a job whose *command* changed is exactly the case where that finds the
//!   wrong line, or none.
//!
//! # What may reach a crontab line
//!
//! Everything a caller sends is validated by the pure functions at the top of
//! this module before it is stored, and validated *again* by
//! [`render_crontab`] on the way out, so a hand-edited database cannot turn
//! into a crontab line either. The rules that matter:
//!
//! * **A command may contain no control characters at all.** The one that
//!   makes this a security boundary rather than a tidiness rule is `\n`: a
//!   newline inside a command is a second crontab line, i.e. a second job on a
//!   schedule and with a command that nobody approved. `\0` is refused for the
//!   same class of reason — it truncates the line at whatever consumed it
//!   first. See `a_newline_in_a_command_cannot_smuggle_a_second_job`.
//! * **`%` is escaped, not passed through.** In both Vixie cron and cronie an
//!   unescaped `%` in the command field becomes a newline, and everything after
//!   the first one is fed to the command as *stdin*. A tenant writing
//!   `date +%F` would otherwise silently run `date +` — so every `%` is
//!   rendered as `\%`, which cron turns back into a literal `%`.
//! * **`@reboot` and the other `@` aliases are refused outright.** Not for
//!   tidiness: a tenant `@reboot` job runs when cron starts at boot, which is
//!   before `ferrum-agentd` has re-applied the tenant's systemd slice and disk
//!   quota. A job in that window runs with no memory ceiling, no CPU quota and
//!   no quota accounting — the exact window where a runaway job is unbounded.
//!   Every alias (`@daily`, `@hourly`, …) is expressible in five fields, so
//!   refusing them costs a tenant nothing.
//!
//! # Why not the config engine
//!
//! Everything else the panel owns goes through `ferrum_config::apply` and its
//! hash-in-the-header drift detection (spec §10.4). A crontab cannot: the file
//! lives in cron's spool directory (`/var/spool/cron/crontabs/<user>` on
//! Debian, `/var/spool/cron/<user>` on RHEL), its permissions and its mtime are
//! cron's business, and writing it directly is how you get a crontab cron never
//! reloads. The `crontab` binary is the supported way in, so it is the way this
//! module goes in.
//!
//! What does carry over is §10.4 rule 2 — never clobber a human's file. Before
//! the first install, the account's existing crontab is read and, if it is not
//! one of ours, the operation **refuses** instead of overwriting it
//! ([`ensure_crontab_is_ours`]). Beyond that first check the panel does own the
//! file, and the header says so in as many words.
//!
//! # Slices
//!
//! Tenant cron jobs do **not** run inside `ferrum-<user>.slice`. That is a real
//! gap, not an oversight, and it is written up in [`crate::slices`] — the short
//! version is that the crontab line is executed by cron *as the tenant*, and an
//! unprivileged process cannot place itself into a system slice.

use std::sync::Arc;

use async_trait::async_trait;
use ferrum_core::{
    ErrorCode, FerrumError, LinuxUser, Permission, Result, SubscriptionId, TenantScope,
};
use ferrum_db::cron::{CronJob, CronJobUpdate, NewCronJob};
use ferrum_db::subscriptions::Subscription;
use ferrum_distro::Cmd;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::registry::{Execution, OpContext, TypedOperation};

/// The longest command one job may carry.
///
/// Cron implementations impose their own line limits (Vixie's `MAX_COMMAND` is
/// 1000 in some builds, larger in others) and a line that is truncated *by the
/// cron daemon* is the worst possible outcome: a command that runs, but not the
/// one that was saved. 1024 characters is comfortably inside every
/// implementation's budget once the schedule is prepended, and a command longer
/// than that belongs in a script file the job invokes.
pub const MAX_COMMAND_CHARS: usize = 1024;

/// A sanity bound on the schedule text before it is even split into fields, so
/// a megabyte of commas cannot become a megabyte of parser work.
const MAX_SCHEDULE_CHARS: usize = 256;

/// The first line of every crontab this panel writes, and the token
/// [`is_ferrum_crontab`] recognises.
const MANAGED_MARKER: &str = "# FERRUM-MANAGED cron";

/// `crontab` reads a file and exits; it has no work to do that could take
/// longer than this, and a hang here would hold an IPC round trip open.
const CRONTAB_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Schedule validation — pure functions
// ---------------------------------------------------------------------------

/// One of the five schedule fields and the range it accepts.
struct FieldSpec {
    name: &'static str,
    min: u32,
    max: u32,
}

/// Minute, hour, day-of-month, month, day-of-week — in crontab order.
///
/// Day-of-week runs to 7 rather than 6 because both Vixie cron and cronie
/// accept 7 as a second spelling of Sunday, and a tenant who writes `7`
/// meaning Sunday is right. Names (`sun`, `jan`) are *not* accepted: they are
/// an implementation extension, they collide with nothing useful, and every
/// one of them has a number.
const FIELDS: [FieldSpec; 5] = [
    FieldSpec {
        name: "minute",
        min: 0,
        max: 59,
    },
    FieldSpec {
        name: "hour",
        min: 0,
        max: 23,
    },
    FieldSpec {
        name: "day of month",
        min: 1,
        max: 31,
    },
    FieldSpec {
        name: "month",
        min: 1,
        max: 12,
    },
    FieldSpec {
        name: "day of week",
        min: 0,
        max: 7,
    },
];

fn invalid_schedule(detail: impl Into<String>) -> FerrumError {
    FerrumError::new(ErrorCode::InvalidInput, detail).with_field("schedule")
}

/// Validate a five-field cron schedule and return its canonical spelling.
///
/// Canonical means: the five fields, separated by exactly one space. Storing
/// the canonical form is what stops `"0  3 * * *"` and `"0\t3 * * *"` from
/// being two different rows that render two different crontabs.
///
/// The grammar accepted, per field, is deliberately small:
///
/// ```text
/// field := item ("," item)*
/// item  := "*" [ "/" step ]
///        | number [ "-" number [ "/" step ] ]
/// ```
///
/// What is *not* accepted, and why: `@aliases` (see the module docs), names,
/// `n/step` (Vixie reads it as `n-max/step`, which almost nobody means and
/// cronie has spelled differently in the past), and a step of zero or one
/// wider than its own range.
pub fn validate_schedule(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(invalid_schedule("a schedule is required"));
    }
    if trimmed.chars().count() > MAX_SCHEDULE_CHARS {
        return Err(invalid_schedule(format!(
            "a schedule may be at most {MAX_SCHEDULE_CHARS} characters"
        )));
    }

    // Every alias cron knows starts with `@`, so one check covers `@reboot`,
    // `@daily`, `@midnight` and any extension a particular cron happens to
    // add. `@reboot` is the one that matters (it runs before the tenant's slice
    // and quota are applied — see the module docs); the rest are refused with
    // it so there is one rule to learn rather than a special case to remember.
    if trimmed.starts_with('@') {
        return Err(invalid_schedule(
            "`@`-style schedules are not available to tenants — `@reboot` would \
             run before the panel has applied this tenant's resource limits, and \
             every other alias has a five-field spelling (`@daily` is `0 0 * * *`)",
        ));
    }

    let fields: Vec<&str> = trimmed.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(invalid_schedule(format!(
            "a schedule has exactly five fields (minute hour day-of-month month \
             day-of-week); got {}",
            fields.len()
        )));
    }

    for (field, spec) in fields.iter().zip(FIELDS.iter()) {
        validate_field(field, spec)?;
    }

    Ok(fields.join(" "))
}

/// One field: a comma-separated list of items, at least one, none empty.
fn validate_field(field: &str, spec: &FieldSpec) -> Result<()> {
    // An empty item is what `1,,2`, `,1` and `1,` all produce, and cron's own
    // parsers disagree about each of them. Refusing is one rule for all three.
    for item in field.split(',') {
        validate_item(item, spec)?;
    }
    Ok(())
}

fn validate_item(item: &str, spec: &FieldSpec) -> Result<()> {
    let bad = |detail: String| invalid_schedule(format!("{} field: {detail}", spec.name));

    if item.is_empty() {
        return Err(bad("empty list entry".into()));
    }

    // Split the optional step off first: it applies to whatever is left of it.
    let (base, step) = match item.split_once('/') {
        Some((base, step)) => (base, Some(step)),
        None => (item, None),
    };

    let width = match base {
        "*" => spec.max - spec.min + 1,
        _ => {
            let (lo, hi) = match base.split_once('-') {
                Some((lo, hi)) => (parse_value(lo, spec)?, parse_value(hi, spec)?),
                None => {
                    let value = parse_value(base, spec)?;
                    (value, value)
                }
            };
            if lo > hi {
                return Err(bad(format!("`{lo}-{hi}` runs backwards")));
            }
            // A step on a bare number is Vixie's `n-max/step`. It is a coin
            // flip whether the author meant that or `*/step`, so it is refused
            // rather than guessed at.
            if step.is_some() && !base.contains('-') {
                return Err(bad(format!(
                    "a step needs a range to walk: write `*/{}` or `{lo}-{}/{}`",
                    step.unwrap_or_default(),
                    spec.max,
                    step.unwrap_or_default()
                )));
            }
            hi - lo + 1
        }
    };

    if let Some(step) = step {
        let step = parse_number(step).ok_or_else(|| bad(format!("`{step}` is not a step")))?;
        if step == 0 {
            return Err(bad("a step of 0 selects nothing".into()));
        }
        if step > width {
            return Err(bad(format!(
                "a step of {step} is wider than the {width} value(s) it walks"
            )));
        }
    }
    Ok(())
}

/// A field value: one or two ASCII digits, inside the field's own range.
fn parse_value(text: &str, spec: &FieldSpec) -> Result<u32> {
    let value = parse_number(text).ok_or_else(|| {
        invalid_schedule(format!("{} field: `{text}` is not a number", spec.name))
    })?;
    if value < spec.min || value > spec.max {
        return Err(invalid_schedule(format!(
            "{} field: {value} is outside {}–{}",
            spec.name, spec.min, spec.max
        )));
    }
    Ok(value)
}

/// One or two ASCII digits, and nothing else.
///
/// Hand-rolled rather than `str::parse`, which would happily accept `+5`,
/// Unicode digits and a leading `-` that a range split has already given a
/// different meaning to.
fn parse_number(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 2 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

// ---------------------------------------------------------------------------
// Command validation — pure functions
// ---------------------------------------------------------------------------

fn invalid_command(detail: impl Into<String>) -> FerrumError {
    FerrumError::new(ErrorCode::InvalidInput, detail).with_field("command")
}

/// Validate a job's command and return it trimmed.
///
/// The command is *not* parsed — it is a shell command line, which is what a
/// crontab command field is, and cron hands it to the tenant's own shell under
/// the tenant's own uid. What is checked is everything that would change the
/// meaning of the crontab **file**: a control character.
pub fn validate_command(raw: &str) -> Result<String> {
    let command = raw.trim();
    if command.is_empty() {
        return Err(invalid_command("a command is required"));
    }
    if command.chars().count() > MAX_COMMAND_CHARS {
        return Err(invalid_command(format!(
            "a command may be at most {MAX_COMMAND_CHARS} characters; put a longer \
             one in a script and run the script"
        )));
    }

    for ch in command.chars() {
        if !ch.is_control() {
            continue;
        }
        // Named individually because the two named ones are attacks and the
        // rest are merely nonsense, and an operator reading the audit log
        // should be able to tell which they are looking at.
        return Err(invalid_command(match ch {
            '\n' | '\r' => {
                "a command may not contain a newline: a crontab line ends at the \
                 newline, so this would add a second job with its own schedule"
            }
            '\0' => {
                "a command may not contain a NUL byte: it truncates the crontab \
                 line at whatever reads it first"
            }
            _ => "a command may not contain control characters",
        }));
    }

    // Nothing in cron makes a trailing backslash mean "continued on the next
    // line", but implementations have differed about what it *does* mean when
    // the next character is the newline we append. A command ending in one is
    // a typo far more often than it is a plan.
    if command.ends_with('\\') {
        return Err(invalid_command(
            "a command may not end with a backslash — cron and the shell disagree \
             about what it escapes at the end of a line",
        ));
    }

    Ok(command.to_string())
}

/// Escape a command for the crontab command field.
///
/// One rule: `%` becomes `\%`. Cron turns an unescaped `%` into a newline and
/// feeds everything after the first one to the command on stdin, so `date +%F`
/// would otherwise run as `date +` with `F` piped in. Cron turns `\%` back into
/// a literal `%`, and a `%` the caller had already escaped survives too: `\%`
/// becomes `\\%`, which cron reads as a literal `\` followed by a literal `%` —
/// the same two characters the shell would have seen without any of this.
fn escape_command(command: &str) -> String {
    command.replace('%', "\\%")
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render a subscription's whole crontab.
///
/// Every row is re-validated here rather than trusted: these strings were
/// validated when they were stored, but the renderer is the last place before
/// text becomes a line cron executes, and "the database said so" is not a thing
/// this module is willing to write a crontab on. A row that does not pass is a
/// named error, not a skipped line — silently dropping a job the tenant can see
/// in the panel would be worse than refusing to write the file.
///
/// Disabled jobs are rendered as comments. They are part of what the tenant
/// configured, and an operator reading the file should see the same list the
/// panel shows.
pub fn render_crontab(subscription_id: SubscriptionId, jobs: &[CronJob]) -> Result<String> {
    // Deliberately pure ASCII, unlike the rest of this codebase's prose. The
    // file is handed to `crontab` and then read by the cron daemon, and there
    // is no reason to find out on somebody's server which of them is the one
    // that does not like a UTF-8 comment.
    let mut out = String::with_capacity(256 + jobs.len() * 96);
    out.push_str(MANAGED_MARKER);
    out.push_str(" -- generated by the Ferrum panel (spec 11.8).\n");
    out.push_str("#\n");
    out.push_str(&format!(
        "# Rendered from the panel database for subscription {}.\n",
        subscription_id.get()
    ));
    out.push_str("# Edits made here are replaced the next time a job is saved in the\n");
    out.push_str("# panel. Change jobs there; this file is not the source of truth.\n");
    out.push_str("#\n");
    out.push_str("# Jobs are sorted by schedule, then command, so the same set of jobs\n");
    out.push_str("# always renders the same file.\n");

    for job in jobs {
        let schedule = validate_schedule(&job.schedule).map_err(|e| {
            FerrumError::internal(format!(
                "cron job {} has an unusable schedule and will not be written to a \
                 crontab: {}",
                job.id, e.detail
            ))
        })?;
        let command = validate_command(&job.command).map_err(|e| {
            FerrumError::internal(format!(
                "cron job {} has an unusable command and will not be written to a \
                 crontab: {}",
                job.id, e.detail
            ))
        })?;
        let line = format!("{schedule} {}", escape_command(&command));

        out.push('\n');
        if job.enabled {
            out.push_str(&format!("# job {}\n", job.id));
            out.push_str(&line);
        } else {
            out.push_str(&format!("# job {} (disabled in the panel)\n", job.id));
            out.push_str("# ");
            out.push_str(&line);
        }
        // Cron has historically required a final newline on every line,
        // including the last one, or it drops the entry without a word.
        out.push('\n');
    }

    Ok(out)
}

/// Does this crontab text belong to the panel?
///
/// The rule: our marker must appear **before any line that is not a comment**.
///
/// Not "is the very first line", because some `crontab` implementations write a
/// banner of their own above whatever you install (`# DO NOT EDIT THIS FILE`,
/// historically three lines) and hand it back on `crontab -l`. Insisting on
/// line one would make the panel refuse the very file it had just written, on
/// exactly the systems that add the banner.
///
/// Not "contains the marker anywhere", either: a crontab whose first real line
/// is somebody's `MAILTO=` or a job of their own, with our header further down,
/// is a file we half-own — and half-owning is precisely the state that ends
/// with a re-render throwing away somebody's work.
///
/// A crontab that is empty, blank, or nothing but comments counts as ours:
/// there is no schedule in it to destroy.
pub fn is_ferrum_crontab(existing: &str) -> bool {
    for line in existing.lines() {
        let line = line.trim_start();
        if line.starts_with(MANAGED_MARKER) {
            return true;
        }
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        // A real crontab entry (or a `NAME=value` setting) that we did not
        // write, reached before any marker of ours.
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Talking to the crontab binary
// ---------------------------------------------------------------------------

/// Reading and writing one account's crontab.
///
/// A trait so the operations can be tested without a `crontab` binary, a cron
/// spool, or root — the same seam `plan::VhostSwitcher` uses, and for the same
/// reason: the interesting behaviour (refusing a foreign crontab, rendering
/// deterministically) is not the subprocess.
#[async_trait]
pub trait CrontabIo: Send + Sync {
    /// The account's current crontab, or `None` if it has none.
    async fn read(&self, user: &LinuxUser) -> Result<Option<String>>;

    /// Replace the account's crontab with `content`.
    async fn install(&self, user: &LinuxUser, content: &str) -> Result<()>;
}

pub struct LiveCrontab;

#[async_trait]
impl CrontabIo for LiveCrontab {
    async fn read(&self, user: &LinuxUser) -> Result<Option<String>> {
        let out = Cmd::new("crontab")
            .args(["-u", user.as_str(), "-l"])
            .timeout(CRONTAB_TIMEOUT)
            .run()
            .await
            .map_err(FerrumError::from)?;

        if out.success() {
            return Ok(Some(out.stdout));
        }
        // Exit 1 is how both Vixie cron and cronie say "this user has no
        // crontab", and neither offers a machine-readable way to say it — the
        // wording of the message differs between them and between locales, so
        // sniffing stderr would be worse than this. Exit 1 for an *unknown*
        // account also lands here; that is fine, because the install that
        // follows fails on the same account with a message that says so, and
        // guessing at the difference from a string would be the fragile half.
        if out.status == 1 {
            return Ok(None);
        }
        Err(FerrumError::new(
            ErrorCode::CommandFailed,
            format!(
                "could not read the crontab for `{}` (exit {}): {}",
                user.as_str(),
                out.status,
                out.failure_text()
            ),
        ))
    }

    async fn install(&self, user: &LinuxUser, content: &str) -> Result<()> {
        // The content goes in on **stdin**, not through a temporary file: a
        // file would need a path only this tenant may read, a cleanup on every
        // failure path, and a window where a job's command sits on disk under
        // whatever umask the agent happens to have.
        Cmd::new("crontab")
            .args(["-u", user.as_str(), "-"])
            .stdin_data(content.as_bytes().to_vec())
            .timeout(CRONTAB_TIMEOUT)
            .run_checked()
            .await
            .map_err(FerrumError::from)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared lookups and the apply path
// ---------------------------------------------------------------------------

/// Which subscription owns the job — the caller's own by default, or a named
/// one the caller's scope can actually see (same contract as `fs.*` and
/// `app.create`, so a subscription outside the scope is `not_found` and not a
/// hint that it exists).
async fn resolve_subscription(ctx: &OpContext, id: Option<i64>) -> Result<Subscription> {
    let db = ctx.db();
    match id {
        Some(raw) => db
            .subscriptions(ctx.scope())
            .by_id(SubscriptionId(raw))
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("subscription")),
        None => db
            .default_subscription_for(ctx.auth().actor_user_id)
            .await
            .map_err(FerrumError::from),
    }
}

/// Does the subscription's *plan* grant cron (`can_cron`, spec §6.2)?
///
/// The registry already checked that the **caller** holds
/// [`Permission::CronManage`]. This is the other half: the feature has to be
/// granted to the **target tenant's** plan, which is a different question
/// whenever an admin or reseller edits a customer's jobs.
///
/// A subscription with no plan is unlimited — the same Phase 1 behaviour
/// `ensure_plan_allows_node_apps` keeps, because a plan-less subscription
/// predates the feature flags and refusing it would break every existing
/// install on upgrade.
async fn ensure_plan_allows_cron(ctx: &OpContext, subscription: &Subscription) -> Result<()> {
    let Some(plan) = ctx
        .db()
        .plan_of_subscription(subscription.id)
        .await
        .map_err(FerrumError::from)?
    else {
        return Ok(());
    };
    if !plan.can_cron {
        return Err(FerrumError::new(
            ErrorCode::PlanFeatureDisabled,
            format!("plan `{}` does not include cron jobs", plan.name),
        ));
    }
    Ok(())
}

/// Refuse to touch a crontab the panel did not write (spec §10.4 rule 2).
///
/// Checked before the row is written, not after, so a refusal leaves the
/// database exactly as it found it. It is re-checked on every apply rather than
/// only on the first: the panel's ownership of the file is a fact about the
/// file, and somebody who runs `crontab -e` after the first install has taken
/// it back.
async fn ensure_crontab_is_ours(io: &dyn CrontabIo, user: &LinuxUser) -> Result<()> {
    let Some(existing) = io.read(user).await? else {
        return Ok(());
    };
    if is_ferrum_crontab(&existing) {
        return Ok(());
    }
    Err(FerrumError::new(
        ErrorCode::Conflict,
        format!(
            "`{}` already has a crontab that Ferrum did not write, and the panel \
             will not overwrite it. Save a copy (`crontab -u {} -l`), remove it \
             (`crontab -u {} -r`), then add the jobs here.",
            user.as_str(),
            user.as_str(),
            user.as_str()
        ),
    ))
}

/// Re-render this subscription's crontab from the database and install it.
///
/// Returns how many jobs are actually scheduled (disabled ones are rendered as
/// comments, so they are in the file but not in the count).
///
/// On failure the reason is recorded on every job of the subscription, because
/// that is what failed: the crontab installs as one file, so when it does not
/// install, *no* job in it took effect. On success the record is cleared.
async fn install_from_db(
    ctx: &OpContext,
    io: &dyn CrontabIo,
    subscription: &Subscription,
) -> Result<usize> {
    let user = LinuxUser::parse(&subscription.linux_user)?;
    let jobs = ctx
        .db()
        .cron_jobs_for_render(subscription.id)
        .await
        .map_err(FerrumError::from)?;
    let content = render_crontab(subscription.id, &jobs)?;

    match io.install(&user, &content).await {
        Ok(()) => {
            ctx.db()
                .set_cron_last_error(subscription.id, None)
                .await
                .map_err(FerrumError::from)?;
            let scheduled = jobs.iter().filter(|j| j.enabled).count();
            ctx.log(format!(
                "installed {scheduled} cron job(s) for {}",
                user.as_str()
            ));
            Ok(scheduled)
        }
        Err(error) => {
            // Recorded on a best-effort basis: the install failure is the one
            // worth reporting, and losing it behind a second failure while
            // trying to write it down would be a poor trade.
            if let Err(e) = ctx
                .db()
                .set_cron_last_error(subscription.id, Some(&error.detail))
                .await
            {
                tracing::warn!(error = %e, "could not record the cron apply failure");
            }
            Err(error)
        }
    }
}

// ---------------------------------------------------------------------------
// cron.list
// ---------------------------------------------------------------------------

pub struct List;

#[derive(Debug, Deserialize)]
pub struct ListInput {
    /// Narrow to one subscription. Resolved through the caller's scope, so an
    /// id the caller cannot see is `not_found` rather than an empty list.
    #[serde(default)]
    pub subscription_id: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub jobs: Vec<CronJob>,
    /// The per-subscription ceiling, so the UI can say "97 of 100" without
    /// hard-coding a number that lives in the database layer.
    pub max_jobs_per_subscription: i64,
}

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "cron.list";
    const PERMISSION: Permission = Permission::CronManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let jobs = match input.subscription_id {
            Some(raw) => {
                // Resolve first so an invisible subscription answers
                // `not_found`; then list within that subscription's own scope
                // rather than the caller's, which is narrower by construction.
                let subscription = resolve_subscription(ctx, Some(raw)).await?;
                ctx.db()
                    .cron_jobs(&TenantScope::Subscription {
                        subscription_id: subscription.id,
                        customer_id: subscription.customer_id,
                    })
                    .list(input.limit.unwrap_or(200), input.offset.unwrap_or(0))
                    .await
            }
            None => {
                ctx.db()
                    .cron_jobs(ctx.scope())
                    .list(input.limit.unwrap_or(200), input.offset.unwrap_or(0))
                    .await
            }
        }
        .map_err(FerrumError::from)?;

        Ok(ListOutput {
            jobs,
            max_jobs_per_subscription: ferrum_db::cron::MAX_JOBS_PER_SUBSCRIPTION,
        })
    }
}

// ---------------------------------------------------------------------------
// cron.set
// ---------------------------------------------------------------------------

/// `cron.set` — create a job, or update the one named by `id`, then re-render
/// and install the subscription's crontab.
pub struct Set {
    io: Arc<dyn CrontabIo>,
}

impl Set {
    pub fn live() -> Self {
        Self {
            io: Arc::new(LiveCrontab),
        }
    }

    #[cfg(test)]
    fn with_io(io: Arc<dyn CrontabIo>) -> Self {
        Self { io }
    }
}

#[derive(Debug, Deserialize)]
pub struct SetInput {
    /// Update this job. Absent creates a new one.
    #[serde(default)]
    pub id: Option<i64>,
    /// Which subscription owns it. Defaults to the caller's own. On an update
    /// it may be omitted or repeated, but never *changed*: see below.
    #[serde(default)]
    pub subscription_id: Option<i64>,
    pub schedule: String,
    pub command: String,
    /// A disabled job keeps its row and renders as a comment. Default `true`.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

const fn default_enabled() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct SetOutput {
    pub job: CronJob,
    /// How many jobs the installed crontab actually schedules.
    pub scheduled: usize,
    pub linux_user: String,
}

#[async_trait]
impl TypedOperation for Set {
    type Input = SetInput;
    type Output = SetOutput;

    const NAME: &'static str = "cron.set";
    const PERMISSION: Permission = Permission::CronManage;
    // One `crontab` invocation over a payload bounded by
    // `MAX_JOBS_PER_SUBSCRIPTION` — well inside the immediate budget, and a
    // task id for something this fast would only make the UI wait twice.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // The job being updated decides whose subscription this is: a job may
        // not move between tenants, so an explicit `subscription_id` that
        // disagrees is a mistake worth naming rather than silently ignoring.
        let existing = match input.id {
            Some(id) => Some(
                ctx.db()
                    .cron_jobs(ctx.scope())
                    .by_id(id)
                    .await
                    .map_err(FerrumError::from)?
                    .ok_or_else(|| FerrumError::not_found("cron job"))?,
            ),
            None => None,
        };

        let subscription = match &existing {
            Some(job) => {
                if let Some(named) = input.subscription_id
                    && named != job.subscription_id.get()
                {
                    return Err(FerrumError::new(
                        ErrorCode::InvalidInput,
                        "a cron job cannot be moved to another subscription; delete \
                         it and create it where it belongs",
                    )
                    .with_field("subscription_id"));
                }
                // Already proven visible through the caller's scope by the
                // lookup above, so this read only has to find the row.
                ctx.db()
                    .subscriptions(&TenantScope::Global)
                    .by_id(job.subscription_id)
                    .await
                    .map_err(FerrumError::from)?
                    .ok_or_else(|| FerrumError::internal("the job's subscription is missing"))?
            }
            None => resolve_subscription(ctx, input.subscription_id).await?,
        };

        if !subscription.status.can_serve() {
            return Err(FerrumError::new(
                ErrorCode::AccountSuspended,
                "this subscription is suspended and cannot run cron jobs",
            ));
        }
        ensure_plan_allows_cron(ctx, &subscription).await?;

        // Parsing is the validation (spec §12 rule 3), and both refusals name
        // their field so a form can highlight it.
        let schedule = validate_schedule(&input.schedule)?;
        let command = validate_command(&input.command)?;

        // Before the row is written: a refusal here must leave the database
        // exactly as it found it.
        let user = LinuxUser::parse(&subscription.linux_user)?;
        ensure_crontab_is_ours(self.io.as_ref(), &user).await?;

        let job = match existing {
            Some(job) => ctx
                .db()
                .cron_jobs(ctx.scope())
                .update(
                    job.id,
                    CronJobUpdate {
                        schedule: Some(schedule),
                        command: Some(command),
                        enabled: Some(input.enabled),
                    },
                )
                .await
                .map_err(FerrumError::from)?,
            None => ctx
                .db()
                .create_cron_job(NewCronJob {
                    subscription_id: subscription.id,
                    schedule,
                    command,
                    enabled: input.enabled,
                })
                .await
                .map_err(FerrumError::from)?,
        };

        let scheduled = install_from_db(ctx, self.io.as_ref(), &subscription).await?;

        // Re-read so the answer carries the cleared `last_error` rather than
        // whatever the write returned a moment before the install.
        let job = ctx
            .db()
            .cron_jobs(ctx.scope())
            .by_id(job.id)
            .await
            .map_err(FerrumError::from)?
            .unwrap_or(job);

        Ok(SetOutput {
            job,
            scheduled,
            linux_user: subscription.linux_user,
        })
    }
}

// ---------------------------------------------------------------------------
// cron.delete
// ---------------------------------------------------------------------------

/// `cron.delete` — remove a job and re-render the subscription's crontab.
pub struct Delete {
    io: Arc<dyn CrontabIo>,
}

impl Delete {
    pub fn live() -> Self {
        Self {
            io: Arc::new(LiveCrontab),
        }
    }

    #[cfg(test)]
    fn with_io(io: Arc<dyn CrontabIo>) -> Self {
        Self { io }
    }
}

#[derive(Debug, Deserialize)]
pub struct DeleteInput {
    pub id: i64,
}

#[derive(Debug, Serialize)]
pub struct DeleteOutput {
    pub id: i64,
    pub subscription_id: i64,
    pub scheduled: usize,
}

#[async_trait]
impl TypedOperation for Delete {
    type Input = DeleteInput;
    type Output = DeleteOutput;

    const NAME: &'static str = "cron.delete";
    const PERMISSION: Permission = Permission::CronManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let job = ctx
            .db()
            .cron_jobs(ctx.scope())
            .by_id(input.id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("cron job"))?;

        let subscription = ctx
            .db()
            .subscriptions(&TenantScope::Global)
            .by_id(job.subscription_id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::internal("the job's subscription is missing"))?;

        // Neither the plan flag nor the suspension check applies here. Removing
        // a job is de-escalation: a tenant whose plan lost `can_cron`, or whose
        // subscription was suspended, must still be able to take their jobs
        // out — refusing would strand exactly the schedules an operator most
        // wants gone.
        let user = LinuxUser::parse(&subscription.linux_user)?;
        ensure_crontab_is_ours(self.io.as_ref(), &user).await?;

        ctx.db()
            .cron_jobs(ctx.scope())
            .delete(input.id)
            .await
            .map_err(FerrumError::from)?;

        let scheduled = install_from_db(ctx, self.io.as_ref(), &subscription).await?;
        Ok(DeleteOutput {
            id: input.id,
            subscription_id: job.subscription_id.get(),
            scheduled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use ferrum_core::{AuthContext, Role, UserId};
    use ferrum_db::Db;
    use ferrum_distro::Distro;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // -- a crontab that lives in memory -------------------------------------

    /// Records every install and answers reads from what was installed, so a
    /// test can assert on the exact bytes that would have reached `crontab`.
    #[derive(Default)]
    struct FakeCrontab {
        state: Mutex<HashMap<String, String>>,
        installs: Mutex<Vec<(String, String)>>,
        fail_install_with: Option<String>,
    }

    impl FakeCrontab {
        fn with_existing(user: &str, content: &str) -> Self {
            let me = Self::default();
            me.state
                .lock()
                .unwrap()
                .insert(user.to_string(), content.to_string());
            me
        }

        fn failing(detail: &str) -> Self {
            Self {
                fail_install_with: Some(detail.to_string()),
                ..Self::default()
            }
        }

        fn installed_for(&self, user: &str) -> Option<String> {
            self.state.lock().unwrap().get(user).cloned()
        }

        fn install_count(&self) -> usize {
            self.installs.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl CrontabIo for FakeCrontab {
        async fn read(&self, user: &LinuxUser) -> Result<Option<String>> {
            Ok(self.state.lock().unwrap().get(user.as_str()).cloned())
        }

        async fn install(&self, user: &LinuxUser, content: &str) -> Result<()> {
            if let Some(detail) = &self.fail_install_with {
                return Err(FerrumError::new(ErrorCode::CommandFailed, detail.clone()));
            }
            self.installs
                .lock()
                .unwrap()
                .push((user.as_str().to_string(), content.to_string()));
            self.state
                .lock()
                .unwrap()
                .insert(user.as_str().to_string(), content.to_string());
            Ok(())
        }
    }

    fn job_row(id: i64, schedule: &str, command: &str, enabled: bool) -> CronJob {
        CronJob {
            id,
            subscription_id: SubscriptionId(7),
            schedule: schedule.into(),
            command: command.into(),
            enabled,
            last_error: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    // -- schedule grammar ---------------------------------------------------

    #[test]
    fn every_shape_of_valid_schedule_is_accepted_and_canonicalised() {
        // Table-driven: (input, canonical form).
        let cases = [
            ("* * * * *", "* * * * *"),
            ("0 3 * * *", "0 3 * * *"),
            ("  0   3  *  *  * ", "0 3 * * *"),
            ("0\t3 * * *", "0 3 * * *"),
            ("*/5 * * * *", "*/5 * * * *"),
            ("0-30/10 * * * *", "0-30/10 * * * *"),
            ("0,15,30,45 * * * *", "0,15,30,45 * * * *"),
            ("0 0 1 1 0", "0 0 1 1 0"),
            // 7 is Sunday's second spelling; both cron implementations take it.
            ("0 0 * * 7", "0 0 * * 7"),
            ("59 23 31 12 6", "59 23 31 12 6"),
            ("0 0 1-7,15 */2 1-5", "0 0 1-7,15 */2 1-5"),
            ("00 03 * * *", "00 03 * * *"),
            // A step exactly as wide as its own range: the first value only.
            ("*/60 * * * *", "*/60 * * * *"),
        ];
        for (input, canonical) in cases {
            let got = validate_schedule(input)
                .unwrap_or_else(|e| panic!("`{input}` should parse: {}", e.detail));
            assert_eq!(got, canonical, "for `{input}`");
        }
    }

    #[test]
    fn hostile_and_malformed_schedules_are_refused_with_the_field_named() {
        let cases = [
            // Structure.
            ("", "empty"),
            ("   ", "whitespace"),
            ("* * * *", "four fields"),
            ("* * * * * *", "six fields — the sixth would be a command"),
            ("* * * * * /bin/rm -rf /", "a command smuggled into the schedule"),
            // Ranges and values.
            ("60 * * * *", "minute 60"),
            ("* 24 * * *", "hour 24"),
            ("* * 0 * *", "day-of-month 0"),
            ("* * 32 * *", "day-of-month 32"),
            ("* * * 0 *", "month 0"),
            ("* * * 13 *", "month 13"),
            ("* * * * 8", "day-of-week 8"),
            ("30-10 * * * *", "backwards range"),
            ("-5 * * * *", "leading dash"),
            ("5- * * * *", "dangling dash"),
            ("+5 * * * *", "signed number"),
            ("005 * * * *", "three digits"),
            // Steps.
            ("*/0 * * * *", "zero step"),
            ("*/61 * * * *", "step wider than the range"),
            ("*/ * * * *", "empty step"),
            ("5/5 * * * *", "step on a bare number"),
            ("*/-1 * * * *", "negative step"),
            // Lists.
            (",1 * * * *", "leading comma"),
            ("1, * * * *", "trailing comma"),
            ("1,,2 * * * *", "empty list entry"),
            // Names and aliases.
            ("@reboot", "the alias that runs before limits are applied"),
            ("@REBOOT", "the same alias, shouted"),
            ("@daily", "an alias with a five-field spelling"),
            ("@every_minute", "an unknown alias"),
            ("0 0 * jan *", "a month name"),
            ("0 0 * * mon", "a day name"),
            // Injection shapes.
            ("* * * * *\n0 0 * * * /bin/sh", "a newline in the schedule"),
            ("* * * * *\0", "a NUL"),
            ("* * * * * # comment", "a trailing comment"),
        ];
        for (input, why) in cases {
            let err = validate_schedule(input)
                .expect_err(&format!("`{input}` must be refused ({why})"));
            assert_eq!(err.code, ErrorCode::InvalidInput, "{why}: {err:?}");
            assert_eq!(err.field.as_deref(), Some("schedule"), "{why}");
        }
    }

    #[test]
    fn the_reboot_refusal_explains_itself() {
        // The refusal has to teach, because "@reboot is not allowed" reads as
        // an arbitrary panel rule when it is in fact a resource-limit hole:
        // cron starts before the agent has re-applied slices and quotas.
        let err = validate_schedule("@reboot").unwrap_err();
        assert!(err.detail.contains("@reboot"), "{}", err.detail);
        assert!(err.detail.contains("resource limits"), "{}", err.detail);
        assert!(err.detail.contains("0 0 * * *"), "{}", err.detail);
    }

    #[test]
    fn a_schedule_longer_than_the_cap_is_refused_before_it_is_parsed() {
        let huge = format!("{} * * * *", "1,".repeat(400));
        let err = validate_schedule(&huge).unwrap_err();
        assert!(err.detail.contains("256"), "{}", err.detail);
    }

    // -- command rules ------------------------------------------------------

    #[test]
    fn a_newline_in_a_command_cannot_smuggle_a_second_job() {
        // The attack: a crontab line ends at the newline, so a command
        // carrying one appends a whole extra job — its own schedule, its own
        // command, approved by nobody.
        for payload in [
            "/usr/bin/php cron.php\n* * * * * /tmp/backdoor",
            "ok\n@reboot /tmp/rootkit",
            "ok\r\n* * * * * /tmp/backdoor",
            "ok\rmalicious",
            "ok\u{0b}* * * * * /tmp/backdoor",
        ] {
            assert!(
                validate_command(payload).is_err(),
                "{payload:?} must be refused"
            );
        }

        let err = validate_command("/usr/bin/php cron.php\n* * * * * /tmp/backdoor").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("command"));
        assert!(err.detail.contains("second job"), "{}", err.detail);

        // And the same payload cannot get in through the renderer either: the
        // row is re-validated on the way out.
        let err = render_crontab(
            SubscriptionId(7),
            &[job_row(1, "* * * * *", "ok\n* * * * * /bin/sh -i", true)],
        )
        .unwrap_err();
        assert!(err.detail.contains("cron job 1"), "{}", err.detail);
    }

    #[test]
    fn a_nul_byte_in_a_command_is_refused() {
        let err = validate_command("/usr/bin/php\0 cron.php").unwrap_err();
        assert_eq!(err.field.as_deref(), Some("command"));
        assert!(err.detail.contains("NUL"), "{}", err.detail);
    }

    #[test]
    fn commands_are_capped_at_1024_characters() {
        let at_cap = "a".repeat(MAX_COMMAND_CHARS);
        assert_eq!(validate_command(&at_cap).unwrap().len(), MAX_COMMAND_CHARS);

        let over = "a".repeat(MAX_COMMAND_CHARS + 1);
        let err = validate_command(&over).unwrap_err();
        assert_eq!(err.field.as_deref(), Some("command"));
        assert!(err.detail.contains("1024"), "{}", err.detail);
    }

    #[test]
    fn ordinary_shell_commands_survive_validation_unchanged() {
        // The command field *is* a shell command line — cron hands it to the
        // tenant's own shell under the tenant's own uid. Refusing pipes and
        // redirects would break the feature, and would protect nothing: the
        // tenant can already run any command they like as themselves.
        for command in [
            "/usr/bin/php /home/ft_a/cron.php",
            "cd /home/ft_a/site && ./run.sh >> log 2>&1",
            "/usr/bin/curl -fsS https://example.com/ping | /usr/bin/logger",
            "test -f /tmp/x; echo $?",
        ] {
            assert_eq!(validate_command(command).unwrap(), command);
        }
        assert_eq!(validate_command("   spaced   ").unwrap(), "spaced");
    }

    #[test]
    fn a_command_ending_in_a_backslash_is_refused() {
        let err = validate_command("echo hi \\").unwrap_err();
        assert!(err.detail.contains("backslash"), "{}", err.detail);
    }

    #[test]
    fn a_tab_inside_a_command_is_refused_like_any_other_control_character() {
        // Pinned deliberately: a tab is harmless to cron, but "no control
        // characters" is one rule rather than a list of the dangerous ones,
        // and a rule with exceptions is a rule somebody will add to.
        let err = validate_command("echo\ta\tb").unwrap_err();
        assert_eq!(err.field.as_deref(), Some("command"));
        assert!(err.detail.contains("control characters"), "{}", err.detail);
    }

    // -- rendering ----------------------------------------------------------

    #[test]
    fn a_rendered_crontab_is_marked_managed_and_ends_every_line_with_a_newline() {
        let body = render_crontab(
            SubscriptionId(7),
            &[job_row(1, "0 3 * * *", "/usr/bin/php cron.php", true)],
        )
        .unwrap();

        assert!(body.starts_with(MANAGED_MARKER), "{body}");
        assert!(body.contains("subscription 7"), "{body}");
        assert!(body.contains("\n# job 1\n0 3 * * * /usr/bin/php cron.php\n"), "{body}");
        assert!(body.ends_with('\n'), "cron drops a final line with no newline");
        assert!(is_ferrum_crontab(&body));
    }

    #[test]
    fn a_disabled_job_is_rendered_as_a_comment_not_dropped() {
        let body = render_crontab(
            SubscriptionId(7),
            &[
                job_row(1, "0 3 * * *", "enabled.sh", true),
                job_row(2, "0 4 * * *", "disabled.sh", false),
            ],
        )
        .unwrap();
        assert!(body.contains("\n0 3 * * * enabled.sh\n"), "{body}");
        assert!(body.contains("# job 2 (disabled in the panel)"), "{body}");
        assert!(body.contains("\n# 0 4 * * * disabled.sh\n"), "{body}");
        // Nothing that cron would read as a live line.
        assert!(
            !body.lines().any(|l| l.trim_start().starts_with("0 4")),
            "{body}"
        );
    }

    #[test]
    fn a_percent_in_a_command_is_escaped_so_cron_does_not_turn_it_into_stdin() {
        // Unescaped, cron rewrites the first `%` to a newline and pipes the
        // rest to the command — `date +%F` would run as `date +` with `F` on
        // stdin, which is a silently different command.
        let body = render_crontab(
            SubscriptionId(7),
            &[job_row(1, "0 3 * * *", "echo $(date +%Y-%m-%d) 50%", true)],
        )
        .unwrap();
        let line = body
            .lines()
            .find(|l| l.starts_with("0 3"))
            .expect("the job line");
        assert_eq!(line, "0 3 * * * echo $(date +\\%Y-\\%m-\\%d) 50\\%");
        assert!(
            !line.replace("\\%", "").contains('%'),
            "every % must be escaped: {line}"
        );
    }

    #[test]
    fn rendering_is_a_pure_function_of_the_job_set() {
        let jobs = vec![
            job_row(1, "0 3 * * *", "a.sh", true),
            job_row(2, "0 4 * * *", "b.sh", false),
        ];
        let once = render_crontab(SubscriptionId(7), &jobs).unwrap();
        let twice = render_crontab(SubscriptionId(7), &jobs).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn an_empty_job_list_renders_a_valid_but_empty_managed_crontab() {
        let body = render_crontab(SubscriptionId(7), &[]).unwrap();
        assert!(is_ferrum_crontab(&body));
        assert!(
            body.lines().all(|l| l.starts_with('#')),
            "no schedule lines: {body}"
        );
    }

    // -- ownership ----------------------------------------------------------

    #[test]
    fn a_crontab_counts_as_ours_only_when_our_marker_precedes_every_real_line() {
        // Nothing to destroy.
        assert!(is_ferrum_crontab(""));
        assert!(is_ferrum_crontab("   \n\n"));
        assert!(is_ferrum_crontab("# somebody's notes, no jobs\n"));

        // What we write, and what we get back on a system whose `crontab`
        // prepends its own banner — the case that would otherwise make the
        // panel refuse the very file it had just installed.
        assert!(is_ferrum_crontab(&render_crontab(SubscriptionId(1), &[]).unwrap()));
        assert!(is_ferrum_crontab(
            "# DO NOT EDIT THIS FILE - edit the master and reinstall.\n\
             # (/tmp/crontab.XX installed on Mon Jan  1 00:00:00 2035)\n\
             # (Cron version -- $Id$)\n\
             # FERRUM-MANAGED cron -- anything\n\
             0 3 * * * x\n"
        ));

        // Somebody else's crontab, in the shapes it actually turns up in.
        assert!(!is_ferrum_crontab("0 3 * * * /home/me/backup.sh\n"));
        assert!(
            !is_ferrum_crontab("MAILTO=me@example.com\n# FERRUM-MANAGED cron\n"),
            "a setting we did not write comes before the marker"
        );
        assert!(
            !is_ferrum_crontab("# my notes\n@reboot /home/me/start.sh\n# FERRUM-MANAGED cron\n"),
            "a file we half-own is not a file we may re-render"
        );
    }

    // -- the operations -----------------------------------------------------

    /// An OpContext over a mock distro and an in-memory database, plus the
    /// customer and their subscription. Built directly, as `nodeapp.rs` does,
    /// because these tests inject a fake crontab rather than dispatching.
    async fn ctx_with_tenant() -> (OpContext, Db, Subscription) {
        let db = Db::open_memory().await.unwrap();
        let customer = db
            .users(&TenantScope::Global)
            .create(ferrum_db::users::NewUser {
                role: Role::Customer,
                email: ferrum_core::Email::parse("c@example.com").unwrap(),
                username: ferrum_core::Username::parse("client").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let sub = db.create_subscription(customer.id).await.unwrap();
        let services = Arc::new(
            crate::registry::Services::new(
                Distro::mock(),
                db.clone(),
                ferrum_db::MasterKey::generate(),
            )
            .expect("templates compile"),
        );
        let auth = AuthContext::from_role(UserId(1), Role::Admin, TenantScope::Global, "req-test");
        (OpContext::new(services, auth), db, sub)
    }

    fn set_input(schedule: &str, command: &str, sub: &Subscription) -> SetInput {
        SetInput {
            id: None,
            subscription_id: Some(sub.id.get()),
            schedule: schedule.into(),
            command: command.into(),
            enabled: true,
        }
    }

    #[tokio::test]
    async fn a_saved_job_reaches_the_tenants_crontab() {
        let (ctx, db, sub) = ctx_with_tenant().await;
        let io = Arc::new(FakeCrontab::default());

        let out = Set::with_io(io.clone())
            .run(&ctx, set_input("*/5 * * * *", "/usr/bin/php cron.php", &sub))
            .await
            .unwrap();

        assert_eq!(out.scheduled, 1);
        assert_eq!(out.job.schedule, "*/5 * * * *");
        assert_eq!(out.linux_user, sub.linux_user);

        let installed = io.installed_for(&sub.linux_user).expect("a crontab");
        assert!(installed.contains("*/5 * * * * /usr/bin/php cron.php"), "{installed}");
        assert_eq!(db.cron_jobs_for_render(sub.id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_foreign_crontab_is_never_overwritten_and_no_row_is_written() {
        // Spec §10.4 rule 2: the panel does not throw away a file it did not
        // write. The refusal has to happen *before* the row, or the panel and
        // the machine end up disagreeing about what is scheduled.
        let (ctx, db, sub) = ctx_with_tenant().await;
        let theirs = "0 2 * * * /home/me/my-own-backup.sh\n";
        let io = Arc::new(FakeCrontab::with_existing(&sub.linux_user, theirs));

        let err = Set::with_io(io.clone())
            .run(&ctx, set_input("0 3 * * *", "panel-job.sh", &sub))
            .await
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("did not write"), "{}", err.detail);
        assert!(err.detail.contains(&sub.linux_user), "{}", err.detail);
        assert_eq!(
            io.installed_for(&sub.linux_user).as_deref(),
            Some(theirs),
            "the tenant's own crontab must be untouched"
        );
        assert_eq!(io.install_count(), 0);
        assert!(
            db.cron_jobs_for_render(sub.id).await.unwrap().is_empty(),
            "a refused save must leave no row behind"
        );
    }

    #[tokio::test]
    async fn a_crontab_the_panel_wrote_is_re_rendered_without_complaint() {
        let (ctx, _db, sub) = ctx_with_tenant().await;
        let io = Arc::new(FakeCrontab::with_existing(
            &sub.linux_user,
            &render_crontab(sub.id, &[]).unwrap(),
        ));
        Set::with_io(io.clone())
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap();
        assert_eq!(io.install_count(), 1);
    }

    #[tokio::test]
    async fn a_plan_without_cron_refuses_the_feature_for_that_tenant() {
        // The caller's permission is not the whole rule: an admin editing a
        // customer's jobs must still respect the customer's plan (spec §6.2).
        let (ctx, db, sub) = ctx_with_tenant().await;
        let plan = db
            .plans(&TenantScope::Global)
            .create(ferrum_db::NewPlan {
                owner_user_id: None,
                name: "No Cron".into(),
                max_sites: 5,
                max_dbs: 5,
                storage_mb: 1024,
                can_ssh: false,
                can_cron: false,
                can_node_apps: false,
            })
            .await
            .unwrap();
        db.assign_plan(sub.id, plan.id).await.unwrap();

        let io = Arc::new(FakeCrontab::default());
        let err = Set::with_io(io.clone())
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PlanFeatureDisabled);
        assert!(err.detail.contains("No Cron"), "{}", err.detail);
        assert_eq!(io.install_count(), 0);
        assert!(db.cron_jobs_for_render(sub.id).await.unwrap().is_empty());

        // Turning the flag on lifts the refusal — the gate is the flag, not
        // the presence of a plan.
        db.plans(&TenantScope::Global)
            .update(
                plan.id,
                ferrum_db::PlanUpdate {
                    can_cron: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        Set::with_io(io.clone())
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap();
        assert_eq!(io.install_count(), 1);
    }

    #[tokio::test]
    async fn a_suspended_subscription_cannot_gain_a_job_but_can_lose_one() {
        let (ctx, db, sub) = ctx_with_tenant().await;
        let io = Arc::new(FakeCrontab::default());
        let created = Set::with_io(io.clone())
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap();

        db.set_subscription_status(
            sub.id,
            ferrum_db::SubscriptionStatus::Suspended,
            Some("non-payment"),
        )
        .await
        .unwrap();

        let err = Set::with_io(io.clone())
            .run(&ctx, set_input("0 4 * * *", "another.sh", &sub))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::AccountSuspended);

        // Removal still works: refusing it would strand exactly the schedules
        // an operator suspending an account most wants gone.
        let removed = Delete::with_io(io.clone())
            .run(
                &ctx,
                DeleteInput {
                    id: created.job.id,
                },
            )
            .await
            .unwrap();
        assert_eq!(removed.scheduled, 0);
        assert!(db.cron_jobs_for_render(sub.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_install_failure_is_recorded_on_the_job_and_reported() {
        let (ctx, db, sub) = ctx_with_tenant().await;
        let io = Arc::new(FakeCrontab::failing("crontab: installing new crontab: EPERM"));

        let err = Set::with_io(io)
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::CommandFailed);

        // The row survives — it is the panel's *intent*, and `cron.set` is
        // convergent, so a re-run after the machine is fixed installs it.
        let jobs = db.cron_jobs_for_render(sub.id).await.unwrap();
        assert_eq!(jobs.len(), 1);
        assert!(
            jobs[0].last_error.as_deref().unwrap_or_default().contains("EPERM"),
            "{:?}",
            jobs[0].last_error
        );
    }

    #[tokio::test]
    async fn a_successful_install_clears_an_earlier_failure() {
        let (ctx, db, sub) = ctx_with_tenant().await;
        let created = Set::with_io(Arc::new(FakeCrontab::default()))
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap();
        db.set_cron_last_error(sub.id, Some("an earlier failure"))
            .await
            .unwrap();

        let out = Set::with_io(Arc::new(FakeCrontab::default()))
            .run(
                &ctx,
                SetInput {
                    id: Some(created.job.id),
                    subscription_id: None,
                    schedule: "0 5 * * *".into(),
                    command: "job.sh".into(),
                    enabled: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(out.job.last_error, None);
        assert_eq!(out.job.schedule, "0 5 * * *");
        assert_eq!(out.job.id, created.job.id, "an update must not create a row");
    }

    #[tokio::test]
    async fn a_job_cannot_be_moved_to_another_subscription() {
        let (ctx, db, sub) = ctx_with_tenant().await;
        let other = db
            .users(&TenantScope::Global)
            .create(ferrum_db::users::NewUser {
                role: Role::Customer,
                email: ferrum_core::Email::parse("d@example.com").unwrap(),
                username: ferrum_core::Username::parse("other").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let other_sub = db.create_subscription(other.id).await.unwrap();

        let created = Set::with_io(Arc::new(FakeCrontab::default()))
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap();

        let err = Set::with_io(Arc::new(FakeCrontab::default()))
            .run(
                &ctx,
                SetInput {
                    id: Some(created.job.id),
                    subscription_id: Some(other_sub.id.get()),
                    schedule: "0 3 * * *".into(),
                    command: "job.sh".into(),
                    enabled: true,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("subscription_id"));
    }

    #[tokio::test]
    async fn a_disabled_job_leaves_the_crontab_with_nothing_scheduled() {
        let (ctx, _db, sub) = ctx_with_tenant().await;
        let io = Arc::new(FakeCrontab::default());
        let out = Set::with_io(io.clone())
            .run(
                &ctx,
                SetInput {
                    enabled: false,
                    ..set_input("0 3 * * *", "job.sh", &sub)
                },
            )
            .await
            .unwrap();

        assert_eq!(out.scheduled, 0);
        let installed = io.installed_for(&sub.linux_user).unwrap();
        assert!(installed.contains("# 0 3 * * * job.sh"), "{installed}");
    }

    #[tokio::test]
    async fn a_customer_cannot_see_or_touch_another_tenants_job_through_the_registry() {
        // End to end through dispatch, so the permission check, the scope and
        // the input parsing are all on the path a real request takes.
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let admin_sub = db.create_subscription(admin).await.unwrap();
        let alien = db
            .create_cron_job(NewCronJob {
                subscription_id: admin_sub.id,
                schedule: "0 3 * * *".into(),
                command: "admin-job.sh".into(),
                enabled: true,
            })
            .await
            .unwrap();

        let listed = reg
            .dispatch(
                "cron.list",
                &auth_for(customer, Role::Customer),
                json!({}),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            listed["jobs"].as_array().map(Vec::len),
            Some(0),
            "another tenant's jobs must not be listed"
        );

        let err = reg
            .dispatch(
                "cron.delete",
                &auth_for(customer, Role::Customer),
                json!({ "id": alien.id }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);

        // Still there.
        assert!(
            db.cron_jobs(&TenantScope::Global)
                .by_id(alien.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_bad_schedule_or_command_is_refused_before_anything_is_written() {
        let (reg, admin, _) = registry().await;
        let db = reg.services().db.clone();
        db.create_subscription(admin).await.unwrap();

        for input in [
            json!({ "schedule": "@reboot", "command": "job.sh" }),
            json!({ "schedule": "* * * *", "command": "job.sh" }),
            json!({ "schedule": "0 3 * * *", "command": "a\n* * * * * b" }),
            json!({ "schedule": "0 3 * * *", "command": "" }),
        ] {
            let err = reg
                .dispatch("cron.set", &auth_for(admin, Role::Admin), input, None)
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{err:?}");
        }
        assert!(
            db.cron_jobs(&TenantScope::Global)
                .list(100, 0)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cron_list_reports_the_job_limit_alongside_the_jobs() {
        let (reg, admin, _) = registry().await;
        reg.services()
            .db
            .create_subscription(admin)
            .await
            .unwrap();
        let listed = reg
            .dispatch("cron.list", &auth_for(admin, Role::Admin), json!({}), None)
            .await
            .unwrap();
        assert_eq!(
            listed["max_jobs_per_subscription"],
            json!(ferrum_db::cron::MAX_JOBS_PER_SUBSCRIPTION)
        );
    }
}
