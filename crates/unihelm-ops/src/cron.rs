//! Per-subscription cron jobs (spec §11.8).
//!
//! A tenant's crontab is a **rendering of the panel database**, never a file
//! the panel edits in place. Every change re-renders the whole thing from
//! `cron_jobs` and installs it as `/etc/cron.d/unihelm-<user>`. Two
//! properties follow from that, and both are the reason for the design:
//!
//! * **Deterministic.** The same set of jobs always produces byte-identical
//!   output (sorted by schedule, then command, then id — see
//!   [`unihelm_db::Db::cron_jobs_for_render`]), so "save a job that did not
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
//!   before `unihelm-agentd` has re-applied the tenant's systemd slice and disk
//!   quota. A job in that window runs with no memory ceiling, no CPU quota and
//!   no quota accounting — the exact window where a runaway job is unbounded.
//!   Every alias (`@daily`, `@hourly`, …) is expressible in five fields, so
//!   refusing them costs a tenant nothing.
//!
//! # Every job runs inside its tenant's slice
//!
//! Until this was fixed the jobs were installed in the tenant's *spool*
//! crontab (`crontab -u <user> -`), and that is what let a scheduled job escape
//! the plan: a spool line is executed by cron **as the tenant**, and an
//! unprivileged process cannot put itself into a system slice —
//! `systemd-run --slice=` needs authorisation the tenant does not have, and
//! `systemd-run --user` lands in `user-<uid>.slice`, a different cgroup with
//! none of the plan's limits on it. So every tenant's jobs ran in
//! `cron.service`'s own cgroup under `system.slice`: one customer's runaway
//! loop with the whole machine's memory and CPU, which is the exact failure
//! `unihelm_ops::slices` exists to prevent, on the one code path that had
//! opted out of it.
//!
//! The jobs therefore live in `/etc/cron.d/unihelm-<user>` instead, whose lines
//! carry a **user field** — and that field is `root`, because placing a process
//! in a system slice is a privileged operation and cron is the only privileged
//! thing in the picture. Each enabled job renders as:
//!
//! ```text
//! <schedule> root systemd-run --quiet --collect --wait --pipe
//!     --slice='unihelm-<user>.slice' --uid=<user>
//!     --working-directory=<home> -- /bin/sh%<command>
//! ```
//!
//! Every piece of that is load-bearing:
//!
//! * `--slice=` is the fix. The transient unit is created inside the tenant's
//!   slice, so `MemoryMax`, `CPUQuota` and `TasksMax` bind the job the same way
//!   they bind the tenant's Node apps.
//! * `--uid=` keeps the job the tenant's own. systemd sets `User=` from it, and
//!   with it `$USER`, `$LOGNAME`, `$HOME` and `$SHELL` out of the passwd entry;
//!   `--working-directory=` reproduces cron's own `cd $HOME`. The one thing
//!   that does differ from a spool crontab is `$PATH`: it is systemd's default
//!   rather than cron's `/usr/bin:/bin`, which is a superset, so a command that
//!   resolved before still resolves.
//! * `--wait --pipe` is why a failing job is still reported exactly as before:
//!   the job's exit status becomes `systemd-run`'s, and its output goes to
//!   cron's pipes rather than into the journal, so cron mails it to the
//!   `MAILTO=` at the top of the file (see below for what that is). `--quiet`
//!   keeps the "Running as unit …" banner out of that mail and `--collect`
//!   reaps the transient unit afterwards, including when it failed.
//! * `%<command>` is cron's own convention, and it is what makes this safe.
//!   Both cron implementations turn the first unescaped `%` in the command
//!   field into a newline and feed **everything after it to the command on
//!   standard input**. So the root shell that starts `systemd-run` parses only
//!   panel-written text, and the tenant's command arrives at `/bin/sh` as
//!   *data* on a pipe. There is no quoting step, and therefore no quoting bug
//!   that could let a command break out of the wrapper and run as root. (The
//!   `%`s inside the command itself are still escaped to `\%`, as they always
//!   were, so they stay literal instead of ending the command early.)
//!
//! Two things this is **not**:
//!
//! * It is not retroactive. A job installed before this change is a line in
//!   that tenant's spool crontab, and it keeps running outside the slice until
//!   the panel next re-renders that subscription — at which point the install
//!   writes the `/etc/cron.d` file and then removes the spool crontab it had
//!   written, so the jobs move rather than doubling up.
//! * It is not a claim about jobs the panel did not write. A tenant with shell
//!   access can still run `crontab -e`, and those lines run under
//!   `system.slice` like any other user's. The panel refuses to manage cron for
//!   an account whose spool crontab it did not write ([`ensure_crontab_is_ours`])
//!   and the refusal says so, which is the most an out-of-band file allows.
//!
//! A tenant whose slice unit does not exist has no ceiling to run in, so
//! [`resolve_placement`] **refuses** rather than rendering a line that would run
//! unconstrained: silently dropping `--slice=` would be the panel reporting a
//! confined job it had not confined.
//!
//! # Where a job's output goes, and why `MAILTO=` is an email address
//!
//! This file has always written a `MAILTO=` line, and until the panel grew a
//! local MTA nothing ever delivered what cron addressed to it: mail was a PHP
//! pool setting (`sendmail_path`, per site), so a machine with no PHP had no
//! way to send anything at all and a machine with PHP only had one for its
//! sites. Every failing job's output has gone nowhere since the feature
//! shipped.
//!
//! The MTA fixes the delivery. It does **not** make the old address work. It is
//! a null client — an empty `mydestination`, so the machine delivers nothing
//! locally and forwards everything upstream — and against one of those a bare
//! `MAILTO=uh_abc12345` is completed to `uh_abc12345@<this host>` and relayed to
//! the operator's provider, where no such mailbox exists. That is a bounce into
//! a queue nobody reads, which is the same nothing as before with a support
//! cost attached.
//!
//! So [`CronMail`] resolves the address of the account that owns the
//! subscription — the person who would act on a backup script that started
//! failing — and that is what goes in the file. When there is no usable address
//! the line is `MAILTO=""`, which is cron's own spelling of "mail nothing", and
//! the task log says why. Both outcomes are "the tenant is not emailed"; only
//! one of them also pours bounces into the operator's relay, and it is not this
//! one.
//!
//! # Why not the config engine
//!
//! Everything else the panel owns goes through `unihelm_config::apply` and its
//! hash-in-the-header drift detection (spec §10.4). This file does not, for one
//! reason: its content is a rendering of *rows*, each of which is re-validated
//! in Rust on the way out (see [`render_crontab`]), and the engine's contract is
//! a template plus a JSON context. What the engine would add here is revision
//! history, not safety.
//!
//! The part of §10.4 that does carry over is rule 2 — never clobber a human's
//! file — and it is enforced directly, on **both** files this module touches:
//! the `/etc/cron.d` file it writes and the spool crontab it retires. Either
//! one that does not carry the panel's marker makes the operation **refuse**
//! instead of overwriting it. The check runs on every apply rather than only
//! the first: ownership is a fact about the file, and somebody who ran
//! `crontab -e` after the first install has taken it back.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use unihelm_config::paths;
use unihelm_core::{
    Email, ErrorCode, LinuxUser, Permission, Result, SubscriptionId, TenantScope, UnihelmError,
};
use unihelm_db::cron::{CronJob, CronJobUpdate, NewCronJob};
use unihelm_db::subscriptions::Subscription;
use unihelm_distro::Cmd;

use crate::registry::{Execution, OpContext, TypedOperation};

/// The longest command one job may carry.
///
/// Cron implementations impose their own line limits (Vixie's `MAX_COMMAND` is
/// 1000 in some builds, larger in others) and a line that is truncated *by the
/// cron daemon* is the worst possible outcome: a command that runs, but not the
/// one that was saved. 1024 characters is comfortably inside every
/// implementation's budget once the schedule is prepended, and a command longer
/// than that belongs in a script file the job invokes.
///
/// This is the bound on what may be *stored*. What actually reaches cron is the
/// whole line, wrapper included, and [`MAX_CRONTAB_LINE_CHARS`] is the bound on
/// that — a command near this cap is refused before it is stored, with a message
/// saying by how much it overruns.
pub const MAX_COMMAND_CHARS: usize = 1024;

/// The longest line this module will hand to cron, wrapper and schedule
/// included.
///
/// `MAX_COMMAND` is 1000 in both Vixie cron and cronie, and a longer line is
/// dropped or truncated by the daemon — either way the tenant's job silently
/// stops being the job they saved. Placing the job in its slice costs ~150
/// characters of that budget, which is exactly why this check exists: without
/// it, adding the wrapper would have turned a legal 1000-character job into a
/// truncated one with no error anywhere.
const MAX_CRONTAB_LINE_CHARS: usize = 1000;

/// A sanity bound on the schedule text before it is even split into fields, so
/// a megabyte of commas cannot become a megabyte of parser work.
const MAX_SCHEDULE_CHARS: usize = 256;

/// The first line of every crontab this panel writes, and the token
/// [`is_unihelm_crontab`] recognises.
const MANAGED_MARKER: &str = "# UNIHELM-MANAGED cron";

/// `crontab` reads a file and exits; it has no work to do that could take
/// longer than this, and a hang here would hold an IPC round trip open.
const CRONTAB_TIMEOUT: Duration = Duration::from_secs(30);

/// Mode of the `/etc/cron.d` file the panel writes.
///
/// Not the 0644 that packaged cron.d files usually carry: a command field can
/// hold an API token (`curl -H "Authorization: …"`), and the spool crontab this
/// file replaces was 0600. Only root reads `/etc/cron.d`, and both cron
/// implementations check the file is root-owned and not group- or
/// other-*writable* — neither requires it to be readable by anyone else.
const CRON_D_MODE: u32 = 0o600;

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

fn invalid_schedule(detail: impl Into<String>) -> UnihelmError {
    UnihelmError::new(ErrorCode::InvalidInput, detail).with_field("schedule")
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

fn invalid_command(detail: impl Into<String>) -> UnihelmError {
    UnihelmError::new(ErrorCode::InvalidInput, detail).with_field("command")
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
// Slice placement
// ---------------------------------------------------------------------------

/// Where one subscription's jobs run: the tenant's slice, uid and home.
///
/// Resolved once per apply and then handed to the renderer, so every line in a
/// file is placed identically and no code path can render a job without having
/// first proven there is a ceiling to put it in. Public because
/// [`render_crontab`] takes one; deliberately not constructible from outside
/// this module, because [`resolve_placement`] is the only thing that has
/// checked the slice actually exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlicePlacement {
    /// `unihelm-<user>.slice`, as [`crate::slices::slice_file_name`] spells it.
    slice_unit: String,
    linux_user: String,
    /// The job's working directory, matching cron's own `cd $HOME`.
    home: String,
}

/// The tenant's placement, or a refusal naming what is missing.
///
/// The precondition is the slice **unit file**, the same thing
/// `appcontainer` checks before it passes `--cgroup-parent`. The difference is
/// what happens when it is absent: a container without a slice still serves the
/// tenant's site, so that path degrades; a cron job without a slice is the
/// unbounded job this whole arrangement exists to prevent, so this path refuses.
/// `provision::ensure_tenant_user` writes the unit when the account is created,
/// so the only way to reach this refusal is an account provisioned before slices
/// existed or a unit somebody removed by hand — both fixable, and the message
/// says how.
async fn resolve_placement(host: &dyn CronHost, user: &LinuxUser) -> Result<SlicePlacement> {
    let slice_unit = crate::slices::slice_file_name(user);
    if !host.slice_unit_exists(&slice_unit).await? {
        return Err(UnihelmError::new(
            ErrorCode::Conflict,
            format!(
                "`{}` has no resource-limit slice on this host: {} is missing, so a \
                 cron job for this subscription could only run with the whole \
                 machine's memory and CPU. The panel will not schedule it \
                 unconfined. Re-provision this subscription to write the slice \
                 unit, then save the job again.",
                user.as_str(),
                paths::systemd_unit(&slice_unit).display()
            ),
        ));
    }
    Ok(SlicePlacement {
        slice_unit,
        linux_user: user.as_str().to_string(),
        home: paths::tenant_home(user.as_str()).display().to_string(),
    })
}

// ---------------------------------------------------------------------------
// Where the output is mailed
// ---------------------------------------------------------------------------

/// What goes after `MAILTO=` in the crontab.
///
/// Two states, and the type exists so the second one cannot be reached by
/// accident. [`CronMail::Nobody`] renders `MAILTO=""` — cron reads an empty
/// value as "do not mail this crontab's output anywhere" — and is only ever
/// chosen deliberately, with a line in the task log saying so.
///
/// The address is held as a validated [`Email`], not a `String`, because this
/// value is written verbatim into a file cron parses line by line: an address
/// carrying a newline would be a second cron setting, or a job, appearing in a
/// file the panel believes it wrote every line of. `Email::parse` already
/// rejects control characters, spaces, commas and semicolons, which is exactly
/// the set that matters here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CronMail {
    To(Email),
    Nobody,
}

impl CronMail {
    /// The `MAILTO=` value, quoted where cron needs it to be.
    fn value(&self) -> String {
        match self {
            // Unquoted: cron implementations differ on whether the quotes are
            // stripped from a value, and an address that arrived as
            // `"me@example.com"` would be undeliverable. An `Email` cannot
            // contain a space, so there is nothing here to protect.
            CronMail::To(address) => address.as_str().to_string(),
            // Quoted, because this one *is* the empty string and a bare
            // `MAILTO=` is the spelling cronie's parser is least sure about.
            CronMail::Nobody => "\"\"".to_string(),
        }
    }
}

/// The address a subscription's cron output should go to.
///
/// The owning account's, because a subscription is somebody's, and a failing
/// job is theirs to see. Never fails the operation: an account that has gone
/// missing, or an address the panel would not accept today, is a reason to mail
/// nobody and say so — not a reason to refuse to schedule a job, or to write an
/// address the panel has not checked into a file cron parses.
async fn resolve_cron_mail(ctx: &OpContext, subscription: &Subscription) -> Result<CronMail> {
    let owner = ctx
        .db()
        .users(&TenantScope::Global)
        .by_id(subscription.customer_id)
        .await
        .map_err(UnihelmError::from)?;

    let Some(owner) = owner else {
        ctx.log(format!(
            "subscription {} has no owning account, so its cron output is mailed nowhere \
             (MAILTO=\"\"). Job failures will only be visible in the panel.",
            subscription.id.get()
        ));
        return Ok(CronMail::Nobody);
    };

    // Re-parsed rather than trusted, for the same reason every row this module
    // renders is re-validated: the database read is not the last place this
    // string is checked before it becomes a line in a file cron executes.
    match Email::parse(owner.email.as_str()) {
        Ok(address) => Ok(CronMail::To(address)),
        Err(e) => {
            ctx.log(format!(
                "the address on the account owning subscription {} is not one the panel \
                 will write into a crontab ({}), so its cron output is mailed nowhere \
                 (MAILTO=\"\").",
                subscription.id.get(),
                e.detail
            ));
            Ok(CronMail::Nobody)
        }
    }
}

/// Everything on a job line between the schedule and the tenant's own command.
///
/// Assembled in one place because it is the security boundary: every character
/// of it is panel-written, and the tenant's command is appended *after* the `%`
/// that cron turns into "the rest is stdin". See the module docs for what each
/// flag is doing there.
fn slice_wrapper(placement: &SlicePlacement) -> String {
    // The slice name is the one value here that can contain a backslash: a
    // hyphen in a Linux account (legal, and what a cPanel import brings in) is
    // escaped to `\x2d` by `slices::slice_file_name`, because in a *slice* name
    // a hyphen is a nesting level. The shell that cron hands this line to would
    // eat that backslash and ask systemd for a slice nobody has — a job that
    // never runs, under a panel that said it had scheduled one. Single quotes
    // stop that, and they are airtight here: a Linux account name cannot
    // contain a quote, so nothing in this value can end them.
    format!(
        "root systemd-run --quiet --collect --wait --pipe --slice='{}' --uid={} \
         --working-directory={} -- /bin/sh",
        placement.slice_unit, placement.linux_user, placement.home
    )
}

/// One job's crontab line, wrapper included.
///
/// Shared by the renderer and by `cron.set`'s pre-write check so that a command
/// which cannot be written is refused *before* it becomes a row, rather than
/// after — a row that no longer renders would take the tenant's other jobs down
/// with it on every later apply.
fn job_line(schedule: &str, command: &str, placement: &SlicePlacement) -> Result<String> {
    let wrapper = slice_wrapper(placement);
    // No space around the `%`: it is cron's command/stdin separator, and the
    // command begins at the character after it.
    let line = format!("{schedule} {wrapper}%{}", escape_command(command));

    let length = line.chars().count();
    if length > MAX_CRONTAB_LINE_CHARS {
        return Err(invalid_command(format!(
            "this job's crontab line would be {length} characters and cron drops \
             or truncates a line over {MAX_CRONTAB_LINE_CHARS}; shorten the \
             command by {} characters, or move it into a script the job calls. \
             ({} characters of the budget place the job inside `{}`, which is not \
             optional.)",
            length - MAX_CRONTAB_LINE_CHARS,
            wrapper.chars().count() + 1,
            placement.slice_unit,
        )));
    }
    Ok(line)
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
///
/// The `placement` is not optional and not defaulted: a caller that has not
/// resolved the tenant's slice cannot render a line, which is what keeps
/// "the job runs inside the plan's ceiling" true of every line in the file
/// rather than of the lines somebody remembered to wrap. `mail` is not
/// defaulted either, and for the same shape of reason: see [`CronMail`].
pub fn render_crontab(
    subscription_id: SubscriptionId,
    jobs: &[CronJob],
    placement: &SlicePlacement,
    mail: &CronMail,
) -> Result<String> {
    // Deliberately pure ASCII, unlike the rest of this codebase's prose. The
    // file is read by the cron daemon, and there is no reason to find out on
    // somebody's server whether this build of it likes a UTF-8 comment.
    let mut out = String::with_capacity(512 + jobs.len() * 224);
    out.push_str(MANAGED_MARKER);
    out.push_str(" -- generated by the Unihelm panel (spec 11.8).\n");
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
    out.push_str("#\n");
    out.push_str(&format!(
        "# Each job runs as {} inside {},\n",
        placement.linux_user, placement.slice_unit
    ));
    out.push_str("# so a runaway job is bounded by this subscription's plan and not by\n");
    out.push_str("# the machine. The command itself reaches /bin/sh on standard input\n");
    out.push_str("# (cron's % convention), so no part of it is ever parsed by the root\n");
    out.push_str("# shell that starts systemd-run.\n");
    // Output and exit status still belong to the tenant, not to root: `--pipe`
    // hands the job's output back to cron, and this is where cron sends it.
    // Without it every failing job would mail root instead of the customer.
    //
    // The value used to be `placement.linux_user`. A local account name is not
    // deliverable through a null-client MTA — it is completed to
    // `<user>@<this host>` and relayed to a provider that has never heard of it
    // — so this is the owning account's real address, or `""` for "mail
    // nobody" when there isn't one. See the module docs.
    out.push_str(&format!("MAILTO={}\n", mail.value()));

    for job in jobs {
        let schedule = validate_schedule(&job.schedule).map_err(|e| {
            UnihelmError::internal(format!(
                "cron job {} has an unusable schedule and will not be written to a \
                 crontab: {}",
                job.id, e.detail
            ))
        })?;
        let command = validate_command(&job.command).map_err(|e| {
            UnihelmError::internal(format!(
                "cron job {} has an unusable command and will not be written to a \
                 crontab: {}",
                job.id, e.detail
            ))
        })?;
        let line = job_line(&schedule, &command, placement).map_err(|e| {
            UnihelmError::internal(format!(
                "cron job {} cannot be written to a crontab: {}",
                job.id, e.detail
            ))
        })?;

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
pub fn is_unihelm_crontab(existing: &str) -> bool {
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
// The host side: cron's files and the tenant's slice unit
// ---------------------------------------------------------------------------

/// `/etc/cron.d/unihelm-<user>` — the file this module owns for one tenant.
///
/// The name carries no dot, which both cron implementations skip over (Debian's
/// cron wants `[A-Za-z0-9_-]+` outright; cronie ignores `.` and `~`). That is
/// also what makes the `.tmp` file the install renames from safe: cron will not
/// pick it up in the moment it exists.
fn cron_d_file(user: &LinuxUser) -> PathBuf {
    cron_d_dir().join(format!("unihelm-{}", user.as_str()))
}

fn cron_d_dir() -> PathBuf {
    paths::root().join("etc/cron.d")
}

/// Everything on the machine that scheduling a job touches.
///
/// A trait so the operations can be tested without a `crontab` binary, an
/// `/etc/cron.d`, or root — the same seam `plan::VhostSwitcher` uses, and for
/// the same reason: the interesting behaviour (refusing a foreign crontab,
/// refusing a tenant with no slice, rendering deterministically) is not the
/// subprocess. The slice-unit check lives here rather than reading the
/// filesystem directly for exactly that reason — `paths::set_root` is a
/// process-wide `OnceLock`, so a parallel test binary has no other way to say
/// "this host has no slice for that tenant".
#[async_trait]
pub trait CronHost: Send + Sync {
    /// The account's own spool crontab (`crontab -u <user> -l`), or `None`.
    ///
    /// Read on every apply even though the panel no longer writes it: a job
    /// the panel installed before jobs moved into the slice still lives there,
    /// and a crontab somebody else wrote is a refusal.
    async fn read_user_crontab(&self, user: &LinuxUser) -> Result<Option<String>>;

    /// Drop the account's spool crontab (`crontab -u <user> -r`).
    ///
    /// Only ever called for a crontab this module has just recognised as its
    /// own, and only after the replacement file is in place.
    async fn remove_user_crontab(&self, user: &LinuxUser) -> Result<()>;

    /// The panel's `/etc/cron.d` file for this tenant, or `None`.
    async fn read_managed(&self, user: &LinuxUser) -> Result<Option<String>>;

    /// Replace the panel's `/etc/cron.d` file for this tenant with `content`.
    async fn install(&self, user: &LinuxUser, content: &str) -> Result<()>;

    /// Does this host have the tenant's slice unit?
    async fn slice_unit_exists(&self, unit_file_name: &str) -> Result<bool>;
}

pub struct LiveCronHost;

#[async_trait]
impl CronHost for LiveCronHost {
    async fn read_user_crontab(&self, user: &LinuxUser) -> Result<Option<String>> {
        let out = Cmd::new("crontab")
            .args(["-u", user.as_str(), "-l"])
            .timeout(CRONTAB_TIMEOUT)
            .run()
            .await
            .map_err(UnihelmError::from)?;

        if out.success() {
            return Ok(Some(out.stdout));
        }
        // Exit 1 is how both Vixie cron and cronie say "this user has no
        // crontab", and neither offers a machine-readable way to say it — the
        // wording of the message differs between them and between locales, so
        // sniffing stderr would be worse than this. Exit 1 for an *unknown*
        // account also lands here; that is fine, because there is then nothing
        // to retire and the install fails on the same account with a message
        // that says so.
        if out.status == 1 {
            return Ok(None);
        }
        Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            format!(
                "could not read the crontab for `{}` (exit {}): {}",
                user.as_str(),
                out.status,
                out.failure_text()
            ),
        ))
    }

    async fn remove_user_crontab(&self, user: &LinuxUser) -> Result<()> {
        let out = Cmd::new("crontab")
            .args(["-u", user.as_str(), "-r"])
            .timeout(CRONTAB_TIMEOUT)
            .run()
            .await
            .map_err(UnihelmError::from)?;
        // Exit 1 again means "no crontab", which is the state this call was
        // trying to reach: somebody removed it between the read and here.
        if out.success() || out.status == 1 {
            return Ok(());
        }
        Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            format!(
                "the jobs for `{}` now run in their slice, but their old crontab \
                 could not be removed (exit {}): {}. Both copies will run until \
                 `crontab -u {} -r` succeeds.",
                user.as_str(),
                out.status,
                out.failure_text(),
                user.as_str()
            ),
        ))
    }

    async fn read_managed(&self, user: &LinuxUser) -> Result<Option<String>> {
        match tokio::fs::read_to_string(cron_d_file(user)).await {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                format!("could not read {}: {e}", cron_d_file(user).display()),
            )),
        }
    }

    async fn install(&self, user: &LinuxUser, content: &str) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = cron_d_dir();
        // Not created if missing. A host with no /etc/cron.d has no cron
        // daemon reading it, and conjuring the directory would let the panel
        // report jobs as scheduled that nothing on the machine will ever run.
        if !dir.is_dir() {
            return Err(UnihelmError::new(
                ErrorCode::ServiceUnavailable,
                format!(
                    "{} does not exist, so there is nowhere for cron to read this \
                     subscription's jobs from — install a cron daemon (`cron` on \
                     Debian, `cronie` on RHEL) and save the job again.",
                    dir.display()
                ),
            ));
        }

        let path = cron_d_file(user);
        // Written beside the target and renamed over it: cron scans the
        // directory on its own clock, and a partially written file it reads
        // mid-write is a partial schedule. The temporary name carries a dot,
        // which is precisely the shape cron skips.
        let tmp = dir.join(format!("unihelm-{}.tmp", user.as_str()));
        let write = async {
            tokio::fs::write(&tmp, content).await?;
            tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(CRON_D_MODE)).await?;
            tokio::fs::rename(&tmp, &path).await
        };
        if let Err(e) = write.await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(UnihelmError::new(
                ErrorCode::CommandFailed,
                format!("could not write {}: {e}", path.display()),
            ));
        }
        Ok(())
    }

    async fn slice_unit_exists(&self, unit_file_name: &str) -> Result<bool> {
        Ok(paths::systemd_unit(unit_file_name).exists())
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
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("subscription")),
        None => db
            .default_subscription_for(ctx.auth().actor_user_id)
            .await
            .map_err(UnihelmError::from),
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
        .map_err(UnihelmError::from)?
    else {
        return Ok(());
    };
    if !plan.can_cron {
        return Err(UnihelmError::new(
            ErrorCode::PlanFeatureDisabled,
            format!("plan `{}` does not include cron jobs", plan.name),
        ));
    }
    Ok(())
}

/// Refuse to touch a crontab the panel did not write (spec §10.4 rule 2).
///
/// Returns whether the account still has a **panel-written** spool crontab, i.e.
/// jobs from before they moved into the slice, which the install retires once
/// the replacement is in place.
///
/// Checked before the row is written, not after, so a refusal leaves the
/// database exactly as it found it. It is re-checked on every apply rather than
/// only on the first: the panel's ownership of the file is a fact about the
/// file, and somebody who runs `crontab -e` after the first install has taken
/// it back.
///
/// The refusal outlives the move to `/etc/cron.d`, where nothing of the
/// tenant's is at risk of being overwritten, because the *other* half of it
/// still holds: a crontab the panel did not write is a set of jobs the panel
/// cannot see, running outside the tenant's slice, and managing cron alongside
/// it would mean showing an operator a job list that is not the whole list.
async fn ensure_crontab_is_ours(host: &dyn CronHost, user: &LinuxUser) -> Result<bool> {
    let Some(existing) = host.read_user_crontab(user).await? else {
        return Ok(false);
    };
    if is_unihelm_crontab(&existing) {
        // Blank or comment-only counts as ours (see `is_unihelm_crontab`), and
        // there is then nothing to retire — but removing it anyway is harmless
        // and one less state to reason about, so presence is the answer.
        return Ok(true);
    }
    Err(UnihelmError::new(
        ErrorCode::Conflict,
        format!(
            "`{}` already has a crontab that Unihelm did not write. Its jobs run \
             outside this subscription's resource limits and the panel cannot \
             show or replace them. Save a copy (`crontab -u {} -l`), remove it \
             (`crontab -u {} -r`), then add the jobs here.",
            user.as_str(),
            user.as_str(),
            user.as_str()
        ),
    ))
}

/// The panel's own `/etc/cron.d` file, if a human has not taken it over.
///
/// The same rule as the spool crontab, applied to the file this module now
/// writes: an operator who hand-edited `/etc/cron.d/unihelm-<user>` gets a
/// refusal rather than a silent overwrite.
async fn ensure_managed_file_is_ours(host: &dyn CronHost, user: &LinuxUser) -> Result<()> {
    let Some(existing) = host.read_managed(user).await? else {
        return Ok(());
    };
    if is_unihelm_crontab(&existing) {
        return Ok(());
    }
    Err(UnihelmError::new(
        ErrorCode::Conflict,
        format!(
            "{} exists and Unihelm did not write it, so the panel will not replace \
             it. Move it aside, then save the job again.",
            cron_d_file(user).display()
        ),
    ))
}

/// What the apply path proved about the host before anything was written.
///
/// Resolved once, before the database is touched, so that every refusal in it —
/// a foreign crontab, a missing slice — leaves the panel and the machine
/// agreeing about what is scheduled.
struct CronTarget {
    placement: SlicePlacement,
    /// Where cron mails what the jobs print. Resolved here rather than in the
    /// renderer because it is a database read, and the renderer is a pure
    /// function of what it is handed.
    mail: CronMail,
    /// The tenant still has the panel's pre-slice spool crontab. Removed after
    /// the `/etc/cron.d` file is in place, so the jobs move rather than run
    /// twice.
    legacy_spool_crontab: bool,
}

async fn prepare(
    ctx: &OpContext,
    host: &dyn CronHost,
    subscription: &Subscription,
) -> Result<CronTarget> {
    let user = LinuxUser::parse(&subscription.linux_user)?;
    let legacy_spool_crontab = ensure_crontab_is_ours(host, &user).await?;
    ensure_managed_file_is_ours(host, &user).await?;
    let placement = resolve_placement(host, &user).await?;
    let mail = resolve_cron_mail(ctx, subscription).await?;
    Ok(CronTarget {
        placement,
        mail,
        legacy_spool_crontab,
    })
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
    host: &dyn CronHost,
    subscription: &Subscription,
    target: &CronTarget,
) -> Result<usize> {
    let user = LinuxUser::parse(&subscription.linux_user)?;
    let jobs = ctx
        .db()
        .cron_jobs_for_render(subscription.id)
        .await
        .map_err(UnihelmError::from)?;
    let content = render_crontab(subscription.id, &jobs, &target.placement, &target.mail)?;

    match host.install(&user, &content).await {
        Ok(()) => {
            ctx.db()
                .set_cron_last_error(subscription.id, None)
                .await
                .map_err(UnihelmError::from)?;
            let scheduled = jobs.iter().filter(|j| j.enabled).count();
            ctx.log(format!(
                "installed {scheduled} cron job(s) for {} in {}",
                user.as_str(),
                target.placement.slice_unit
            ));

            // Only now, with the replacement in place: the other order leaves a
            // window in which the tenant has no jobs at all, and a failed write
            // in that window would lose them. This order can run a job twice in
            // the moment between the two calls, which is the cheaper mistake.
            if target.legacy_spool_crontab {
                host.remove_user_crontab(&user).await?;
                ctx.log(format!(
                    "removed the pre-slice crontab for {}; its jobs now run inside {}",
                    user.as_str(),
                    target.placement.slice_unit
                ));
            }
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
        .map_err(UnihelmError::from)?;

        Ok(ListOutput {
            jobs,
            max_jobs_per_subscription: unihelm_db::cron::MAX_JOBS_PER_SUBSCRIPTION,
        })
    }
}

// ---------------------------------------------------------------------------
// cron.set
// ---------------------------------------------------------------------------

/// `cron.set` — create a job, or update the one named by `id`, then re-render
/// and install the subscription's crontab.
pub struct Set {
    host: Arc<dyn CronHost>,
}

impl Set {
    pub fn live() -> Self {
        Self {
            host: Arc::new(LiveCronHost),
        }
    }

    #[cfg(test)]
    fn with_host(host: Arc<dyn CronHost>) -> Self {
        Self { host }
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
                    .map_err(UnihelmError::from)?
                    .ok_or_else(|| UnihelmError::not_found("cron job"))?,
            ),
            None => None,
        };

        let subscription = match &existing {
            Some(job) => {
                if let Some(named) = input.subscription_id
                    && named != job.subscription_id.get()
                {
                    return Err(UnihelmError::new(
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
                    .map_err(UnihelmError::from)?
                    .ok_or_else(|| UnihelmError::internal("the job's subscription is missing"))?
            }
            None => resolve_subscription(ctx, input.subscription_id).await?,
        };

        if !subscription.status.can_serve() {
            return Err(UnihelmError::new(
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
        // exactly as it found it. That now covers the tenant's slice as well as
        // their crontab — a job the panel cannot confine is refused rather than
        // stored and then scheduled with the whole machine underneath it.
        let target = prepare(ctx, self.host.as_ref(), &subscription).await?;

        // The wrapper costs ~150 characters of cron's line budget, so a command
        // that fits `MAX_COMMAND_CHARS` may still not fit a line. Checked here,
        // against the exact line that would be written, rather than after the
        // row exists: a stored row that cannot render would break every later
        // apply for this subscription, not just this job.
        job_line(&schedule, &command, &target.placement)?;

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
                .map_err(UnihelmError::from)?,
            None => ctx
                .db()
                .create_cron_job(NewCronJob {
                    subscription_id: subscription.id,
                    schedule,
                    command,
                    enabled: input.enabled,
                })
                .await
                .map_err(UnihelmError::from)?,
        };

        let scheduled = install_from_db(ctx, self.host.as_ref(), &subscription, &target).await?;

        // Re-read so the answer carries the cleared `last_error` rather than
        // whatever the write returned a moment before the install.
        let job = ctx
            .db()
            .cron_jobs(ctx.scope())
            .by_id(job.id)
            .await
            .map_err(UnihelmError::from)?
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
    host: Arc<dyn CronHost>,
}

impl Delete {
    pub fn live() -> Self {
        Self {
            host: Arc::new(LiveCronHost),
        }
    }

    #[cfg(test)]
    fn with_host(host: Arc<dyn CronHost>) -> Self {
        Self { host }
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
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("cron job"))?;

        let subscription = ctx
            .db()
            .subscriptions(&TenantScope::Global)
            .by_id(job.subscription_id)
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::internal("the job's subscription is missing"))?;

        // Neither the plan flag nor the suspension check applies here. Removing
        // a job is de-escalation: a tenant whose plan lost `can_cron`, or whose
        // subscription was suspended, must still be able to take their jobs
        // out — refusing would strand exactly the schedules an operator most
        // wants gone.
        // Resolved before the row goes, for the same reason as on the way in: if
        // the file cannot be rewritten, the job is still on the machine, and a
        // panel that had already forgotten the row would be showing a schedule
        // that is not the one running.
        let target = prepare(ctx, self.host.as_ref(), &subscription).await?;

        ctx.db()
            .cron_jobs(ctx.scope())
            .delete(input.id)
            .await
            .map_err(UnihelmError::from)?;

        let scheduled = install_from_db(ctx, self.host.as_ref(), &subscription, &target).await?;
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
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use unihelm_core::{AuthContext, Role, UserId};
    use unihelm_db::Db;
    use unihelm_distro::Distro;

    // -- a host that lives in memory ----------------------------------------

    /// The machine, in a HashMap: the panel's `/etc/cron.d` file, the tenant's
    /// own spool crontab, and whether their slice unit exists. Records every
    /// install so a test can assert on the exact bytes cron would have read.
    struct FakeHost {
        /// What `crontab -u <user> -l` answers.
        spool: Mutex<HashMap<String, String>>,
        /// What is at `/etc/cron.d/unihelm-<user>`.
        managed: Mutex<HashMap<String, String>>,
        installs: Mutex<Vec<(String, String)>>,
        retired_spool: Mutex<Vec<String>>,
        fail_install_with: Option<String>,
        /// A provisioned tenant always has one, so the default says yes and the
        /// tests that care say otherwise explicitly.
        slice_unit_exists: bool,
    }

    impl Default for FakeHost {
        fn default() -> Self {
            Self {
                spool: Mutex::new(HashMap::new()),
                managed: Mutex::new(HashMap::new()),
                installs: Mutex::new(Vec::new()),
                retired_spool: Mutex::new(Vec::new()),
                fail_install_with: None,
                slice_unit_exists: true,
            }
        }
    }

    impl FakeHost {
        /// An account whose spool crontab already holds `content`.
        fn with_spool_crontab(user: &str, content: &str) -> Self {
            let me = Self::default();
            me.spool
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

        /// A tenant provisioned before slices existed, or whose unit somebody
        /// removed by hand.
        fn without_slice_unit() -> Self {
            Self {
                slice_unit_exists: false,
                ..Self::default()
            }
        }

        fn installed_for(&self, user: &str) -> Option<String> {
            self.managed.lock().unwrap().get(user).cloned()
        }

        fn spool_for(&self, user: &str) -> Option<String> {
            self.spool.lock().unwrap().get(user).cloned()
        }

        fn install_count(&self) -> usize {
            self.installs.lock().unwrap().len()
        }

        fn retired_spool_for(&self, user: &str) -> bool {
            self.retired_spool.lock().unwrap().iter().any(|u| u == user)
        }
    }

    #[async_trait]
    impl CronHost for FakeHost {
        async fn read_user_crontab(&self, user: &LinuxUser) -> Result<Option<String>> {
            Ok(self.spool.lock().unwrap().get(user.as_str()).cloned())
        }

        async fn remove_user_crontab(&self, user: &LinuxUser) -> Result<()> {
            self.spool.lock().unwrap().remove(user.as_str());
            self.retired_spool
                .lock()
                .unwrap()
                .push(user.as_str().to_string());
            Ok(())
        }

        async fn read_managed(&self, user: &LinuxUser) -> Result<Option<String>> {
            Ok(self.managed.lock().unwrap().get(user.as_str()).cloned())
        }

        async fn install(&self, user: &LinuxUser, content: &str) -> Result<()> {
            if let Some(detail) = &self.fail_install_with {
                return Err(UnihelmError::new(ErrorCode::CommandFailed, detail.clone()));
            }
            self.installs
                .lock()
                .unwrap()
                .push((user.as_str().to_string(), content.to_string()));
            self.managed
                .lock()
                .unwrap()
                .insert(user.as_str().to_string(), content.to_string());
            Ok(())
        }

        async fn slice_unit_exists(&self, _unit_file_name: &str) -> Result<bool> {
            Ok(self.slice_unit_exists)
        }
    }

    /// The placement of the tenant every rendering test uses.
    fn placement() -> SlicePlacement {
        SlicePlacement {
            slice_unit: "unihelm-uh_abc12345.slice".into(),
            linux_user: "uh_abc12345".into(),
            home: "/home/uh_abc12345".into(),
        }
    }

    /// The address of the account that owns the fixture subscription.
    fn mail() -> CronMail {
        CronMail::To(Email::parse("owner@example.com").unwrap())
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
            (
                "* * * * * /bin/rm -rf /",
                "a command smuggled into the schedule",
            ),
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
            let err =
                validate_schedule(input).expect_err(&format!("`{input}` must be refused ({why})"));
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
            &placement(),
            &mail(),
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
            "/usr/bin/php /home/uh_a/cron.php",
            "cd /home/uh_a/site && ./run.sh >> log 2>&1",
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
            &placement(),
            &mail(),
        )
        .unwrap();

        assert!(body.starts_with(MANAGED_MARKER), "{body}");
        assert!(body.contains("subscription 7"), "{body}");
        assert!(
            body.contains(
                "\n# job 1\n0 3 * * * root systemd-run --quiet --collect --wait --pipe \
                 --slice='unihelm-uh_abc12345.slice' --uid=uh_abc12345 \
                 --working-directory=/home/uh_abc12345 -- /bin/sh%/usr/bin/php cron.php\n"
            ),
            "{body}"
        );
        assert!(
            body.ends_with('\n'),
            "cron drops a final line with no newline"
        );
        assert!(is_unihelm_crontab(&body));
    }

    #[test]
    fn a_disabled_job_is_rendered_as_a_comment_not_dropped() {
        let body = render_crontab(
            SubscriptionId(7),
            &[
                job_row(1, "0 3 * * *", "enabled.sh", true),
                job_row(2, "0 4 * * *", "disabled.sh", false),
            ],
            &placement(),
            &mail(),
        )
        .unwrap();
        assert!(body.contains("\n0 3 * * * root systemd-run "), "{body}");
        assert!(body.contains("%enabled.sh\n"), "{body}");
        assert!(body.contains("# job 2 (disabled in the panel)"), "{body}");
        assert!(body.contains("\n# 0 4 * * * root systemd-run "), "{body}");
        assert!(body.contains("%disabled.sh\n"), "{body}");
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
            &placement(),
            &mail(),
        )
        .unwrap();
        let line = body
            .lines()
            .find(|l| l.starts_with("0 3"))
            .expect("the job line");
        let (wrapper, command) = line.split_once('%').expect("the command separator");
        assert_eq!(command, "echo $(date +\\%Y-\\%m-\\%d) 50\\%");
        assert!(
            !command.replace("\\%", "").contains('%'),
            "every % of the tenant's must be escaped, or cron would cut the \
             command short at it: {line}"
        );
        assert!(
            !wrapper.contains('%'),
            "the wrapper owns the one unescaped %, and it is the last character \
             of it: {line}"
        );
    }

    #[test]
    fn rendering_is_a_pure_function_of_the_job_set() {
        let jobs = vec![
            job_row(1, "0 3 * * *", "a.sh", true),
            job_row(2, "0 4 * * *", "b.sh", false),
        ];
        let once = render_crontab(SubscriptionId(7), &jobs, &placement(), &mail()).unwrap();
        let twice = render_crontab(SubscriptionId(7), &jobs, &placement(), &mail()).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn an_empty_job_list_renders_a_valid_but_empty_managed_crontab() {
        let body = render_crontab(SubscriptionId(7), &[], &placement(), &mail()).unwrap();
        assert!(is_unihelm_crontab(&body));
        assert!(
            body.lines()
                .all(|l| l.starts_with('#') || l.starts_with("MAILTO=")),
            "no schedule lines: {body}"
        );
    }

    // -- where the output is mailed -----------------------------------------

    #[test]
    fn the_crontab_is_mailed_to_an_address_and_never_to_a_bare_local_account_name() {
        // This line used to be `MAILTO=uh_abc12345`, which delivered nothing:
        // the host MTA is a null client with an empty `mydestination`, so a
        // bare local name is completed to `uh_abc12345@<this host>` and handed
        // to the operator's relay, which has no such mailbox. Every failing
        // job's output became a bounce.
        let body = render_crontab(SubscriptionId(7), &[], &placement(), &mail()).unwrap();

        assert!(body.contains("\nMAILTO=owner@example.com\n"), "{body}");
        assert!(
            !body.contains("MAILTO=uh_abc12345"),
            "a Linux account name is not an address: {body}"
        );
        // Unquoted, because some cron implementations keep the quotes as part
        // of the value and `"me@example.com"` is not deliverable.
        assert!(!body.contains("MAILTO=\"owner"), "{body}");
    }

    #[test]
    fn a_subscription_with_no_usable_address_mails_nobody_rather_than_somewhere_undeliverable() {
        // `MAILTO=""` is cron's own "send nothing". It is the honest end of a
        // choice between two kinds of nothing: this one does not also fill the
        // operator's relay with bounces addressed to accounts nobody hosts.
        let body = render_crontab(SubscriptionId(7), &[], &placement(), &CronMail::Nobody).unwrap();

        assert!(body.contains("\nMAILTO=\"\"\n"), "{body}");
        assert!(!body.contains("uh_abc12345@"), "{body}");
    }

    // -- slice placement ----------------------------------------------------

    #[test]
    fn a_rendered_job_line_places_the_job_in_its_tenants_own_slice() {
        // The whole point of the issue this fixes: a line that does not name
        // the slice is a job with the machine's resources instead of the
        // plan's, and one runaway loop takes every other tenant down with it.
        let body = render_crontab(
            SubscriptionId(7),
            &[job_row(1, "*/5 * * * *", "/usr/bin/php cron.php", true)],
            &placement(),
            &mail(),
        )
        .unwrap();
        let line = body
            .lines()
            .find(|l| l.starts_with("*/5"))
            .expect("the job line");

        assert!(
            line.contains("--slice='unihelm-uh_abc12345.slice'"),
            "the job must land in the tenant's own slice: {line}"
        );
        // Placed by root, because putting a process into a system slice is a
        // privileged operation — and run as the tenant, because it is their
        // job. Both halves, or the line is either powerless or dangerous.
        assert!(line.starts_with("*/5 * * * * root systemd-run "), "{line}");
        assert!(line.contains("--uid=uh_abc12345"), "{line}");
        assert!(
            line.contains("--working-directory=/home/uh_abc12345"),
            "cron runs a job from the tenant's home; so must this: {line}"
        );
        // A failing job is still the tenant's to hear about: --wait carries the
        // exit status back to cron, --pipe carries the output, and MAILTO sends
        // it to them rather than to root.
        assert!(line.contains("--wait"), "{line}");
        assert!(line.contains("--pipe"), "{line}");
        assert!(body.contains("\nMAILTO=owner@example.com\n"), "{body}");
    }

    #[test]
    fn the_tenants_command_reaches_the_shell_on_stdin_and_never_the_root_line() {
        // The line is run by cron *as root*, so a command that could reach the
        // shell parsing it would be a root shell the tenant controls. It never
        // does: everything before the `%` is panel text, and cron feeds
        // everything after it to /bin/sh on standard input.
        for command in [
            "cd /home/uh_abc12345/site && ./run.sh >> log 2>&1",
            "echo 'quoted'; id > /tmp/x",
            "curl -fsS https://example.com/ping | logger",
            "x=$(whoami); echo \"$x\" `hostname`",
        ] {
            let body = render_crontab(
                SubscriptionId(7),
                &[job_row(1, "0 3 * * *", command, true)],
                &placement(),
                &mail(),
            )
            .unwrap();
            let line = body
                .lines()
                .find(|l| l.starts_with("0 3"))
                .expect("the job line");
            let (wrapper, stdin) = line.split_once('%').expect("the command separator");

            assert_eq!(stdin, command, "the command reaches the shell verbatim");
            assert_eq!(
                wrapper,
                &format!("0 3 * * * {}", slice_wrapper(&placement())),
                "nothing of the tenant's may appear before the % : {line}"
            );
            assert!(wrapper.ends_with("/bin/sh"), "{line}");
        }
    }

    #[test]
    fn a_hyphenated_account_still_names_the_slice_the_panel_actually_wrote() {
        // A hyphen is legal in a Linux account and arrives with every cPanel
        // import. In a *slice* name it is a nesting level, so `slices.rs`
        // escapes it to `\x2d` — and the shell cron hands this line to would
        // swallow that backslash, leaving systemd-run asking for a slice that
        // does not exist. The job would then never run at all, under a panel
        // that had just reported it scheduled.
        let user = LinuxUser::parse("uh-legacy").unwrap();
        let placement = SlicePlacement {
            slice_unit: crate::slices::slice_file_name(&user),
            linux_user: user.as_str().to_string(),
            home: "/home/uh-legacy".into(),
        };
        let line = job_line("0 3 * * *", "job.sh", &placement).unwrap();

        assert!(
            line.contains("--slice='unihelm-uh\\x2dlegacy.slice'"),
            "the escaped name must reach systemd intact: {line}"
        );
    }

    #[test]
    fn a_job_line_that_would_overflow_crons_budget_is_refused_not_truncated() {
        // A command inside `MAX_COMMAND_CHARS` can still overflow a cron line
        // once the wrapper is on it, and a line cron truncates runs *something
        // else* than what was saved. The refusal names the shortfall.
        let long = "a".repeat(MAX_COMMAND_CHARS);
        let err = job_line("0 3 * * *", &long, &placement()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("command"));
        assert!(err.detail.contains("shorten the command"), "{}", err.detail);
        assert!(
            err.detail.contains("unihelm-uh_abc12345.slice"),
            "the operator has to be able to tell what is eating the budget: {}",
            err.detail
        );

        // What fits, still fits.
        let ok = "a".repeat(700);
        assert!(job_line("0 3 * * *", &ok, &placement()).is_ok());
    }

    // -- ownership ----------------------------------------------------------

    #[test]
    fn a_crontab_counts_as_ours_only_when_our_marker_precedes_every_real_line() {
        // Nothing to destroy.
        assert!(is_unihelm_crontab(""));
        assert!(is_unihelm_crontab("   \n\n"));
        assert!(is_unihelm_crontab("# somebody's notes, no jobs\n"));

        // What we write, and what we get back on a system whose `crontab`
        // prepends its own banner — the case that would otherwise make the
        // panel refuse the very file it had just installed.
        assert!(is_unihelm_crontab(
            &render_crontab(SubscriptionId(1), &[], &placement(), &mail()).unwrap()
        ));
        assert!(is_unihelm_crontab(
            "# DO NOT EDIT THIS FILE - edit the master and reinstall.\n\
             # (/tmp/crontab.XX installed on Mon Jan  1 00:00:00 2035)\n\
             # (Cron version -- $Id$)\n\
             # UNIHELM-MANAGED cron -- anything\n\
             0 3 * * * x\n"
        ));

        // Somebody else's crontab, in the shapes it actually turns up in.
        assert!(!is_unihelm_crontab("0 3 * * * /home/me/backup.sh\n"));
        assert!(
            !is_unihelm_crontab("MAILTO=me@example.com\n# UNIHELM-MANAGED cron\n"),
            "a setting we did not write comes before the marker"
        );
        assert!(
            !is_unihelm_crontab("# my notes\n@reboot /home/me/start.sh\n# UNIHELM-MANAGED cron\n"),
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
        let services = Arc::new(
            crate::registry::Services::new(
                Distro::mock(),
                db.clone(),
                unihelm_db::MasterKey::generate(),
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
        let host = Arc::new(FakeHost::default());

        let out = Set::with_host(host.clone())
            .run(
                &ctx,
                set_input("*/5 * * * *", "/usr/bin/php cron.php", &sub),
            )
            .await
            .unwrap();

        assert_eq!(out.scheduled, 1);
        assert_eq!(out.job.schedule, "*/5 * * * *");
        assert_eq!(out.linux_user, sub.linux_user);

        let installed = host.installed_for(&sub.linux_user).expect("a crontab");
        assert!(
            installed.contains(&format!(
                "*/5 * * * * root systemd-run --quiet --collect --wait --pipe \
                 --slice='unihelm-{user}.slice' --uid={user} \
                 --working-directory=/home/{user} -- /bin/sh%/usr/bin/php cron.php",
                user = sub.linux_user
            )),
            "{installed}"
        );
        assert_eq!(db.cron_jobs_for_render(sub.id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_saved_job_mails_its_output_to_the_owning_accounts_address() {
        // End to end, because the address is a database read and the renderer
        // only writes what it is handed: the account that owns the
        // subscription is the person who has to see a backup script start
        // failing, and before this the file named their Linux account instead.
        let (ctx, _db, sub) = ctx_with_tenant().await;
        let host = Arc::new(FakeHost::default());

        Set::with_host(host.clone())
            .run(&ctx, set_input("0 3 * * *", "backup.sh", &sub))
            .await
            .unwrap();

        let installed = host.installed_for(&sub.linux_user).expect("a crontab");
        assert!(
            installed.contains("\nMAILTO=c@example.com\n"),
            "{installed}"
        );
        assert!(
            !installed.contains(&format!("MAILTO={}", sub.linux_user)),
            "{installed}"
        );
    }

    #[tokio::test]
    async fn a_foreign_crontab_is_never_overwritten_and_no_row_is_written() {
        // Spec §10.4 rule 2: the panel does not throw away a file it did not
        // write. The refusal has to happen *before* the row, or the panel and
        // the machine end up disagreeing about what is scheduled.
        let (ctx, db, sub) = ctx_with_tenant().await;
        let theirs = "0 2 * * * /home/me/my-own-backup.sh\n";
        let host = Arc::new(FakeHost::with_spool_crontab(&sub.linux_user, theirs));

        let err = Set::with_host(host.clone())
            .run(&ctx, set_input("0 3 * * *", "panel-job.sh", &sub))
            .await
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("did not write"), "{}", err.detail);
        assert!(err.detail.contains(&sub.linux_user), "{}", err.detail);
        assert_eq!(
            host.spool_for(&sub.linux_user).as_deref(),
            Some(theirs),
            "the tenant's own crontab must be untouched"
        );
        assert_eq!(
            host.installed_for(&sub.linux_user),
            None,
            "and nothing of ours may be scheduled beside it"
        );
        assert_eq!(host.install_count(), 0);
        assert!(
            db.cron_jobs_for_render(sub.id).await.unwrap().is_empty(),
            "a refused save must leave no row behind"
        );
    }

    #[tokio::test]
    async fn the_panels_own_pre_slice_crontab_is_retired_once_the_jobs_are_in_the_slice() {
        // The upgrade path. A tenant provisioned before jobs moved into the
        // slice has the panel's old file in their spool, and it keeps running
        // outside the slice until something rewrites it — so the first apply
        // after the upgrade writes the new file and then takes the old one
        // away. Leaving it would run every job twice.
        let (ctx, _db, sub) = ctx_with_tenant().await;
        let user = LinuxUser::parse(&sub.linux_user).unwrap();
        let legacy =
            format!("{MANAGED_MARKER} -- an install from before slices\n0 3 * * * job.sh\n");
        let host = Arc::new(FakeHost::with_spool_crontab(&sub.linux_user, &legacy));

        Set::with_host(host.clone())
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap();

        assert_eq!(host.install_count(), 1);
        let installed = host
            .installed_for(&sub.linux_user)
            .expect("the cron.d file");
        assert!(
            installed.contains(&format!(
                "--slice='{}'",
                crate::slices::slice_file_name(&user)
            )),
            "{installed}"
        );
        assert!(
            host.retired_spool_for(&sub.linux_user),
            "the old crontab has to go, or the job runs twice — once confined \
             and once not"
        );
        assert_eq!(host.spool_for(&sub.linux_user), None);
    }

    #[tokio::test]
    async fn a_tenant_with_no_slice_is_refused_rather_than_given_an_unconfined_job() {
        // The refusal that matters most: with no slice unit there is no ceiling
        // to run in, and rendering the line without `--slice=` would schedule a
        // job the panel had just told the operator was confined.
        let (ctx, db, sub) = ctx_with_tenant().await;
        let host = Arc::new(FakeHost::without_slice_unit());

        let err = Set::with_host(host.clone())
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains(&sub.linux_user), "{}", err.detail);
        assert!(err.detail.contains(".slice"), "{}", err.detail);
        assert!(
            err.detail.contains("Re-provision"),
            "a refusal has to say what to do about it: {}",
            err.detail
        );

        assert_eq!(host.install_count(), 0, "nothing may be scheduled");
        assert!(
            db.cron_jobs_for_render(sub.id).await.unwrap().is_empty(),
            "and the refusal must leave no row the panel would show as active"
        );
    }

    #[tokio::test]
    async fn a_job_too_long_to_survive_the_wrapper_is_refused_before_it_is_stored() {
        // Storing it would be worse than refusing it: the row would fail to
        // render on every later apply, taking this subscription's *other* jobs
        // with it.
        let (ctx, db, sub) = ctx_with_tenant().await;
        let host = Arc::new(FakeHost::default());

        let err = Set::with_host(host.clone())
            .run(
                &ctx,
                set_input("0 3 * * *", &"a".repeat(MAX_COMMAND_CHARS), &sub),
            )
            .await
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("command"));
        assert_eq!(host.install_count(), 0);
        assert!(db.cron_jobs_for_render(sub.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_plan_without_cron_refuses_the_feature_for_that_tenant() {
        // The caller's permission is not the whole rule: an admin editing a
        // customer's jobs must still respect the customer's plan (spec §6.2).
        let (ctx, db, sub) = ctx_with_tenant().await;
        let plan = db
            .plans(&TenantScope::Global)
            .create(unihelm_db::NewPlan {
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

        let host = Arc::new(FakeHost::default());
        let err = Set::with_host(host.clone())
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PlanFeatureDisabled);
        assert!(err.detail.contains("No Cron"), "{}", err.detail);
        assert_eq!(host.install_count(), 0);
        assert!(db.cron_jobs_for_render(sub.id).await.unwrap().is_empty());

        // Turning the flag on lifts the refusal — the gate is the flag, not
        // the presence of a plan.
        db.plans(&TenantScope::Global)
            .update(
                plan.id,
                unihelm_db::PlanUpdate {
                    can_cron: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        Set::with_host(host.clone())
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap();
        assert_eq!(host.install_count(), 1);
    }

    #[tokio::test]
    async fn a_suspended_subscription_cannot_gain_a_job_but_can_lose_one() {
        let (ctx, db, sub) = ctx_with_tenant().await;
        let host = Arc::new(FakeHost::default());
        let created = Set::with_host(host.clone())
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap();

        db.set_subscription_status(
            sub.id,
            unihelm_db::SubscriptionStatus::Suspended,
            Some("non-payment"),
        )
        .await
        .unwrap();

        let err = Set::with_host(host.clone())
            .run(&ctx, set_input("0 4 * * *", "another.sh", &sub))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::AccountSuspended);

        // Removal still works: refusing it would strand exactly the schedules
        // an operator suspending an account most wants gone.
        let removed = Delete::with_host(host.clone())
            .run(&ctx, DeleteInput { id: created.job.id })
            .await
            .unwrap();
        assert_eq!(removed.scheduled, 0);
        assert!(db.cron_jobs_for_render(sub.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_install_failure_is_recorded_on_the_job_and_reported() {
        let (ctx, db, sub) = ctx_with_tenant().await;
        let host = Arc::new(FakeHost::failing("crontab: installing new crontab: EPERM"));

        let err = Set::with_host(host)
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::CommandFailed);

        // The row survives — it is the panel's *intent*, and `cron.set` is
        // convergent, so a re-run after the machine is fixed installs it.
        let jobs = db.cron_jobs_for_render(sub.id).await.unwrap();
        assert_eq!(jobs.len(), 1);
        assert!(
            jobs[0]
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("EPERM"),
            "{:?}",
            jobs[0].last_error
        );
    }

    #[tokio::test]
    async fn a_successful_install_clears_an_earlier_failure() {
        let (ctx, db, sub) = ctx_with_tenant().await;
        let created = Set::with_host(Arc::new(FakeHost::default()))
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap();
        db.set_cron_last_error(sub.id, Some("an earlier failure"))
            .await
            .unwrap();

        let out = Set::with_host(Arc::new(FakeHost::default()))
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
        assert_eq!(
            out.job.id, created.job.id,
            "an update must not create a row"
        );
    }

    #[tokio::test]
    async fn a_job_cannot_be_moved_to_another_subscription() {
        let (ctx, db, sub) = ctx_with_tenant().await;
        let other = db
            .users(&TenantScope::Global)
            .create(unihelm_db::users::NewUser {
                role: Role::Customer,
                email: unihelm_core::Email::parse("d@example.com").unwrap(),
                username: unihelm_core::Username::parse("other").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let other_sub = db.create_subscription(other.id).await.unwrap();

        let created = Set::with_host(Arc::new(FakeHost::default()))
            .run(&ctx, set_input("0 3 * * *", "job.sh", &sub))
            .await
            .unwrap();

        let err = Set::with_host(Arc::new(FakeHost::default()))
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
        let host = Arc::new(FakeHost::default());
        let out = Set::with_host(host.clone())
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
        let installed = host.installed_for(&sub.linux_user).unwrap();
        assert!(
            installed.contains("\n# 0 3 * * * root systemd-run "),
            "{installed}"
        );
        assert!(installed.contains("%job.sh\n"), "{installed}");
        assert!(
            !installed.lines().any(|l| l.starts_with("0 3")),
            "a disabled job must not be a live line: {installed}"
        );
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
        reg.services().db.create_subscription(admin).await.unwrap();
        let listed = reg
            .dispatch("cron.list", &auth_for(admin, Role::Admin), json!({}), None)
            .await
            .unwrap();
        assert_eq!(
            listed["max_jobs_per_subscription"],
            json!(unihelm_db::cron::MAX_JOBS_PER_SUBSCRIPTION)
        );
    }
}
