//! Restarting the machine itself (spec §11.11).
//!
//! # Why the panel has to offer this
//!
//! A kernel or glibc update writes new files and leaves the running system on
//! the old ones. An operator who installs updates from the Updates page is told
//! the work succeeded — which is true — and their kernel patch is still not the
//! code executing on that machine. Until this existed the panel read neither
//! distribution's restart-pending signal and offered no way to act on one, so
//! the one thing an operator needed to hear, it never said.
//!
//! [`RebootStatus`] answers "is this machine waiting for a restart, what asked
//! for it, and what stops if I do it". [`Reboot`] does it.
//!
//! # Three promises this module keeps
//!
//! **It never says "no" when it means "I could not tell."** The detection lives
//! in [`unihelm_distro::os`], which has three states rather than two, and both
//! operations pass that third state through untouched.
//!
//! **It names what goes down before it goes down.** Every site on the machine
//! stops, and so does the panel. [`RebootStatusOutput::sites`] is that list,
//! and it hangs off the *read* operation so a confirmation can show it before
//! anybody agrees to anything — the same reason `webserver.gaps` exists apart
//! from `webserver.switch`.
//!
//! **It does not claim the machine came back.** The panel dies with it. A task
//! would be the natural shape for slow work and would be a lie here:
//! `reconcile_interrupted_tasks` marks everything running at agent start as
//! *"the agent restarted before this task finished"*, so a successful reboot
//! would be recorded as a failure and an aborted one would look identical. So
//! this is immediate, it answers before the machine goes down, and the answer
//! says out loud that the panel cannot tell the operator when the server is
//! back.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_core::{ErrorCode, Permission, Result, UnihelmError};
use unihelm_distro::os::{self, RebootRequirement};
use unihelm_distro::{Cmd, Family};

use crate::registry::{Execution, OpContext, TypedOperation};

/// How long after the operation answers the machine goes down.
///
/// Not zero. `systemctl reboot` starts tearing down units inside the same
/// second, which cuts the IPC reply and the HTTP response above it off
/// mid-flight — the operator sees a network error and cannot tell whether their
/// request was even received. One minute is `shutdown`'s smallest unit, it is
/// long enough for the answer to arrive and be read, and it leaves a window in
/// which `shutdown -c` on the server still calls the whole thing off.
const REBOOT_DELAY_MINUTES: u32 = 1;

/// The three things these operations ask of the machine they run on.
///
/// A trait rather than three direct calls, for the same reason `plan::Suspend`
/// takes a `VhostSwitcher`: the confirmation guard and the honesty of the
/// answer are the parts worth testing, and neither is testable if exercising
/// them restarts the machine running the test.
#[async_trait]
pub trait Machine: Send + Sync {
    /// The name the operator has to type back before anything happens.
    fn hostname(&self) -> Result<String>;

    /// Is a restart pending, or could that not be established?
    async fn reboot_requirement(&self, family: Family) -> RebootRequirement;

    /// Schedule the restart `minutes` from now. Returns once it is *scheduled*,
    /// not once it has happened — nothing here outlives the reboot.
    async fn schedule_reboot(&self, minutes: u32) -> Result<()>;
}

/// The real machine.
struct LiveMachine;

#[async_trait]
impl Machine for LiveMachine {
    fn hostname(&self) -> Result<String> {
        os::hostname().map_err(|e| {
            UnihelmError::new(
                ErrorCode::ServiceUnavailable,
                format!(
                    "this server's hostname could not be read ({e}), and the panel asks for \
                     it typed back before it restarts a machine. Restart from a shell with \
                     `systemctl reboot`."
                ),
            )
        })
    }

    async fn reboot_requirement(&self, family: Family) -> RebootRequirement {
        os::reboot_requirement(family).await
    }

    async fn schedule_reboot(&self, minutes: u32) -> Result<()> {
        let delay = format!("+{minutes}");
        // `shutdown` rather than `systemctl reboot`, only for the delay: the
        // reply and the HTTP response above it have to reach the operator
        // before the network stack goes away. The wall message is a fixed
        // literal — nothing from the request reaches argv (spec §12 rule 2).
        let out = Cmd::new("shutdown")
            .arg("-r")
            .arg(&delay)
            .arg("Restarting from the Unihelm panel.")
            .run()
            .await
            .map_err(|e| {
                UnihelmError::new(
                    ErrorCode::ServiceUnavailable,
                    format!(
                        "the restart could not be scheduled: {e}. Nothing has been stopped. \
                         Restart from a shell with `systemctl reboot`."
                    ),
                )
            })?;

        if out.success() {
            return Ok(());
        }
        // Refuse loudly rather than answer "restarting" for a command that did
        // not take. An operator told their server is going down who finds it up
        // an hour later has learned not to believe the panel.
        Err(UnihelmError::new(
            ErrorCode::ServiceUnavailable,
            format!(
                "the restart was not scheduled: `shutdown -r {delay}` exited {} ({}). \
                 Nothing has been stopped. Restart from a shell with `systemctl reboot`.",
                out.status,
                out.failure_text()
            ),
        ))
    }
}

/// Has the operator retyped this machine's name?
///
/// Surrounding whitespace is forgiven because a copy-paste picks it up; nothing
/// else is. A `bool` would have been the obvious input shape and is the wrong
/// one, for the reason `db.drop` gives about its own confirmation: a flag is
/// something a client can default to `true`, and this takes every site on the
/// server offline.
fn confirms_hostname(typed: &str, hostname: &str) -> bool {
    typed.trim() == hostname
}

/// Every domain this machine serves, sorted.
///
/// `all_sites` rather than the caller's scope: a restart is server-wide, and a
/// list that quietly omitted another tenant's sites would understate the cost
/// of the very thing being confirmed. Both operations here require `server.*`
/// permissions, which no customer holds.
async fn serving_domains(ctx: &OpContext) -> Result<Vec<String>> {
    let mut domains: Vec<String> = ctx
        .db()
        .all_sites()
        .await
        .map_err(UnihelmError::from)?
        .into_iter()
        .map(|site| site.domain)
        .collect();
    domains.sort();
    Ok(domains)
}

// ---------------------------------------------------------------------------
// server.reboot.status
// ---------------------------------------------------------------------------

/// `server.reboot.status` — is a restart pending, and what would one cost?
pub struct RebootStatus {
    machine: Arc<dyn Machine>,
}

impl RebootStatus {
    pub fn live() -> Self {
        Self {
            machine: Arc::new(LiveMachine),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RebootStatusInput {}

#[derive(Debug, Serialize)]
pub struct RebootStatusOutput {
    /// Required, not required, or — when the check could not be run — unknown,
    /// carrying the reason it could not.
    pub requirement: RebootRequirement,
    /// The hostname [`Reboot`] wants typed back, so a confirmation can ask for
    /// it. `None` when it could not be read, which is also the state in which
    /// the reboot refuses; [`RebootStatusOutput::hostname_error`] then says
    /// why, rather than leaving a caller to infer a reason from a null.
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname_error: Option<String>,
    /// Every site that stops for the duration.
    pub sites: Vec<String>,
    /// `sites.len()`, so a caller rendering "N sites go down" does not have to
    /// hold the whole list to count it.
    pub site_count: usize,
}

#[async_trait]
impl TypedOperation for RebootStatus {
    type Input = RebootStatusInput;
    type Output = RebootStatusOutput;

    const NAME: &'static str = "server.reboot.status";
    // Read, not manage, for the reason `security.posture` uses the same one:
    // being told the running kernel is not the installed one is how an operator
    // comes to act on it, and nothing here is disclosed that `/api/sites` would
    // not already show the same account.
    const PERMISSION: Permission = Permission::ServerRead;
    // A file read on Debian, one short command on EL, one query for the sites.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let sites = serving_domains(ctx).await?;
        let (hostname, hostname_error) = match self.machine.hostname() {
            Ok(name) => (Some(name), None),
            Err(e) => (None, Some(e.detail)),
        };

        Ok(RebootStatusOutput {
            requirement: self
                .machine
                .reboot_requirement(ctx.distro().info.family)
                .await,
            hostname,
            hostname_error,
            site_count: sites.len(),
            sites,
        })
    }
}

// ---------------------------------------------------------------------------
// server.reboot
// ---------------------------------------------------------------------------

/// `server.reboot` — restart the machine, on purpose and with the cost stated.
pub struct Reboot {
    machine: Arc<dyn Machine>,
}

impl Reboot {
    pub fn live() -> Self {
        Self {
            machine: Arc::new(LiveMachine),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RebootInput {
    /// This machine's hostname, retyped. See [`confirms_hostname`].
    pub confirm_hostname: String,
}

#[derive(Debug, Serialize)]
pub struct RebootOutput {
    pub hostname: String,
    /// How long from now the machine goes down.
    pub in_seconds: u64,
    /// The sites that stop, named — the same list the confirmation showed, so
    /// the audit record of this operation carries what it actually cost.
    pub sites_stopping: Vec<String>,
    /// The one sentence a caller must not have to infer. The panel restarts
    /// with the machine and cannot observe it coming back, so it says so rather
    /// than implying otherwise by handing over something to watch.
    pub note: String,
}

#[async_trait]
impl TypedOperation for Reboot {
    type Input = RebootInput;
    type Output = RebootOutput;

    const NAME: &'static str = "server.reboot";
    // The heaviest thing on the machine short of deleting it: every site, every
    // database and the panel itself stop.
    const PERMISSION: Permission = Permission::ServerManage;
    // See the module docs: a task would be recorded as failed by the agent's
    // own restart reconciliation, which is the panel reporting a failure for
    // work that succeeded.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let hostname = self.machine.hostname()?;
        if !confirms_hostname(&input.confirm_hostname, &hostname) {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                format!(
                    "type this server's hostname (`{hostname}`) to confirm restarting it. \
                     Every site on this machine stops until it is back, and the panel goes \
                     down with it."
                ),
            )
            .with_field("confirm_hostname"));
        }

        // Read before the machine is committed to going down: after
        // `schedule_reboot` the database may be gone at any moment, and an
        // answer that could not name what it stopped is not worth having.
        let sites_stopping = serving_domains(ctx).await?;
        self.machine.schedule_reboot(REBOOT_DELAY_MINUTES).await?;

        let in_seconds = u64::from(REBOOT_DELAY_MINUTES) * 60;
        ctx.log(format!(
            "{hostname} restarts in {in_seconds}s; {} site(s) stop",
            sites_stopping.len()
        ));

        Ok(RebootOutput {
            hostname,
            in_seconds,
            sites_stopping,
            note: format!(
                "This server restarts in about {in_seconds} seconds. The panel restarts with \
                 it, so it cannot tell you when the machine is back — reload the page in a \
                 few minutes. To call it off before it starts, run `shutdown -c` on the \
                 server."
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use std::sync::Mutex;
    use unihelm_core::Role;

    /// A machine that records what it was asked to do instead of doing it.
    struct FakeMachine {
        hostname: Result<String>,
        requirement: RebootRequirement,
        scheduled: Mutex<Vec<u32>>,
    }

    impl FakeMachine {
        fn named(hostname: &str) -> Arc<Self> {
            Arc::new(Self {
                hostname: Ok(hostname.to_string()),
                requirement: RebootRequirement::NotRequired,
                scheduled: Mutex::new(Vec::new()),
            })
        }

        fn scheduled(&self) -> Vec<u32> {
            self.scheduled.lock().expect("test lock").clone()
        }
    }

    #[async_trait]
    impl Machine for FakeMachine {
        fn hostname(&self) -> Result<String> {
            self.hostname.clone()
        }

        async fn reboot_requirement(&self, _family: Family) -> RebootRequirement {
            self.requirement.clone()
        }

        async fn schedule_reboot(&self, minutes: u32) -> Result<()> {
            self.scheduled.lock().expect("test lock").push(minutes);
            Ok(())
        }
    }

    /// An operation context over the mock distro and an in-memory database.
    async fn context() -> OpContext {
        let (reg, admin, _) = registry().await;
        OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin))
    }

    #[tokio::test]
    async fn an_unknown_restart_state_is_reported_as_unknown_and_never_as_no() {
        // The defect in one assertion. A machine whose restart flag could not
        // be read must not serialise as `not_required`: an operator reading
        // that has been told their kernel patch is running when nobody checked.
        let machine = Arc::new(FakeMachine {
            hostname: Ok("web-01".into()),
            requirement: RebootRequirement::Unknown {
                reason: "update-notifier-common is not installed".into(),
            },
            scheduled: Mutex::new(Vec::new()),
        });
        let ctx = context().await;
        let out = RebootStatus {
            machine: machine.clone(),
        }
        .run(&ctx, RebootStatusInput {})
        .await
        .unwrap();

        assert!(!out.requirement.is_required());
        let json = serde_json::to_value(&out.requirement).unwrap();
        assert_eq!(json["state"], "unknown");
        assert_eq!(json["reason"], "update-notifier-common is not installed");
    }

    #[tokio::test]
    async fn the_status_names_the_packages_that_asked_for_the_restart() {
        // "Reboot required" moves nobody. "The kernel was updated and this
        // server is still running the old one" does, and the package list is
        // what lets the panel say the second sentence.
        let machine = Arc::new(FakeMachine {
            hostname: Ok("web-01".into()),
            requirement: RebootRequirement::Required {
                packages: vec!["linux-image-6.8.0-45-generic".into()],
                evidence: "/var/run/reboot-required exists".into(),
            },
            scheduled: Mutex::new(Vec::new()),
        });
        let ctx = context().await;
        let out = RebootStatus { machine }
            .run(&ctx, RebootStatusInput {})
            .await
            .unwrap();

        assert!(out.requirement.is_required());
        assert_eq!(out.requirement.packages(), ["linux-image-6.8.0-45-generic"]);
        assert_eq!(out.hostname.as_deref(), Some("web-01"));
        assert_eq!(out.site_count, out.sites.len());
    }

    #[tokio::test]
    async fn a_machine_with_no_readable_hostname_says_why_instead_of_offering_a_restart() {
        let machine = Arc::new(FakeMachine {
            hostname: Err(UnihelmError::new(
                ErrorCode::ServiceUnavailable,
                "/proc/sys/kernel/hostname could not be read",
            )),
            requirement: RebootRequirement::NotRequired,
            scheduled: Mutex::new(Vec::new()),
        });
        let ctx = context().await;
        let out = RebootStatus {
            machine: machine.clone(),
        }
        .run(&ctx, RebootStatusInput {})
        .await
        .unwrap();

        assert!(out.hostname.is_none());
        assert!(
            out.hostname_error
                .as_deref()
                .is_some_and(|e| e.contains("hostname")),
            "a null hostname without a reason leaves a caller guessing: {:?}",
            out.hostname_error
        );
    }

    #[tokio::test]
    async fn a_mistyped_hostname_stops_the_restart_and_says_what_to_type() {
        let machine = FakeMachine::named("web-01");
        let ctx = context().await;
        let err = Reboot {
            machine: machine.clone(),
        }
        .run(
            &ctx,
            RebootInput {
                confirm_hostname: "web-02".into(),
            },
        )
        .await
        .expect_err("a mistyped confirmation must not restart a server");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("confirm_hostname"));
        assert!(err.detail.contains("web-01"), "{}", err.detail);
        assert!(
            machine.scheduled().is_empty(),
            "a refused confirmation must not have scheduled anything"
        );
    }

    #[tokio::test]
    async fn an_empty_confirmation_is_not_a_confirmation() {
        // The shape a client sends when somebody wires a button straight to the
        // endpoint: no dialog, no typing, no consent.
        let machine = FakeMachine::named("web-01");
        let ctx = context().await;
        let err = Reboot {
            machine: machine.clone(),
        }
        .run(
            &ctx,
            RebootInput {
                confirm_hostname: String::new(),
            },
        )
        .await
        .expect_err("an empty confirmation must not restart a server");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(machine.scheduled().is_empty());
    }

    #[tokio::test]
    async fn a_confirmed_restart_is_scheduled_and_answers_without_claiming_it_came_back() {
        let machine = FakeMachine::named("web-01");
        let ctx = context().await;
        let out = Reboot {
            machine: machine.clone(),
        }
        // Trailing whitespace forgiven: a pasted hostname carries it, and
        // refusing that would be a puzzle rather than a guard.
        .run(
            &ctx,
            RebootInput {
                confirm_hostname: " web-01\n".into(),
            },
        )
        .await
        .unwrap();

        assert_eq!(machine.scheduled(), [REBOOT_DELAY_MINUTES]);
        assert_eq!(out.hostname, "web-01");
        assert!(out.in_seconds >= 60, "the answer must reach the operator");
        assert!(
            out.note
                .contains("cannot tell you when the machine is back"),
            "the panel goes down with the machine and has to say so: {}",
            out.note
        );
    }

    #[tokio::test]
    async fn the_status_is_readable_without_the_right_to_restart_anything() {
        // Split deliberately: "your kernel patch is not running" has to reach
        // the person who will act on it, and that is not always the account
        // allowed to take the machine down.
        assert_eq!(
            <RebootStatus as TypedOperation>::PERMISSION,
            Permission::ServerRead
        );
        assert_eq!(
            <Reboot as TypedOperation>::PERMISSION,
            Permission::ServerManage
        );
    }

    #[tokio::test]
    async fn neither_operation_becomes_a_task() {
        // A task would be marked failed by the agent's own restart
        // reconciliation the moment the machine came back — the panel recording
        // a failure for work that succeeded.
        assert!(!<Reboot as TypedOperation>::EXECUTION.is_task());
        assert!(!<RebootStatus as TypedOperation>::EXECUTION.is_task());
    }
}
