//! The internal scheduler (spec §10.2).
//!
//! A cron-like loop inside the agent, with its schedule in SQLite so a restart
//! resumes rather than forgets. Everything it runs is an ordinary operation with
//! an ordinary Task, so a renewal that happens at four in the morning leaves the
//! same log an operator would have seen if they had clicked the button.
//!
//! The job that matters most is certificate renewal. Without it every
//! certificate the panel issues expires ninety days later, silently, and the
//! first anyone hears about it is a browser warning.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use time::Duration;
use unihelm_core::{AuthContext, TaskId};
use unihelm_db::tasks::NewTask;
use unihelm_db::{Db, ScheduledJob};
use unihelm_distro::pkg::LogSink;
use unihelm_ipc::frame::{EventFrame, EventKind};
use unihelm_ops::registry::TypedOperation;
use unihelm_ops::{OpContext, OpRegistry};

use crate::tasks::TaskBus;

/// How often the loop wakes to look for due work.
///
/// Short enough that a job scheduled for "now" runs promptly, long enough that
/// an idle panel is not spending measurable CPU on an empty query — the metrics
/// collector's 1% budget applies to the whole agent, not just to metrics.
const TICK: StdDuration = StdDuration::from_secs(30);

/// How long a shutdown waits for the passes that are already running.
///
/// Passes run in tasks of their own, and a task is dropped — killing whatever
/// child it was waiting on, `Cmd` sets `kill_on_drop` — the moment the runtime
/// goes away. Without a wait here, every `systemctl restart` would cut short an
/// ACME order or a webhook flush that was about to finish, which the old
/// inline loop never did. A nightly restic run will not finish inside this and
/// is not meant to: it dies at `systemctl stop` either way, and the deadline is
/// what stops the agent from spending the unit's whole stop timeout finding
/// that out and being SIGKILLed anyway.
const SHUTDOWN_DRAIN: StdDuration = StdDuration::from_secs(20);

/// How often the drain looks again. Short enough that a pass finishing does not
/// then wait on this, long enough to be free.
const DRAIN_POLL: StdDuration = StdDuration::from_millis(100);

/// A certificate is renewed once it is inside this window.
const RENEW_WINDOW: Duration = Duration::days(30);

/// At most this many certificates per tick, so a server with three hundred sites
/// spreads its renewals instead of opening three hundred ACME orders at once.
const RENEWALS_PER_TICK: i64 = 5;

/// The built-in schedule.
///
/// Jitter matters more than it looks: a hundred panels installed from the same
/// image would otherwise hit Let's Encrypt in the same second every day.
const JOBS: &[(&str, Duration, Duration)] = &[
    // Hourly, because `RENEWALS_PER_TICK` is a hard ceiling and not a target:
    // twice a day capped the whole panel at ten renewals a day, which a
    // six-hundred-site box needs *all* of just to stand still and which no
    // amount of bulk provisioning can ever catch up from. The pass is cheap
    // when nothing is due — one indexed query that returns nothing.
    ("cert.renew", Duration::hours(1), Duration::hours(1)),
    // So the dashboard stops calling an expired certificate active.
    (
        "cert.expire-stale",
        Duration::hours(1),
        Duration::minutes(5),
    ),
    ("session.purge", Duration::hours(24), Duration::hours(1)),
    ("audit.purge", Duration::hours(24), Duration::hours(1)),
    // Sentinel, the brute-force defence (spec §11.9). A minute is the slowest
    // cadence that still stops a password spray before it finishes: at the
    // default six failures in ten minutes, a scan a minute means the attacker
    // gets at most one extra minute of guesses after crossing the line.
    //
    // The job is registered unconditionally, and it is *disabled* by default —
    // `sentinel.enabled` is false on a fresh install, and `sentinel_tick`
    // returns before reading anything while it is. Registering it either way
    // means turning Sentinel on in the UI takes effect on the next tick rather
    // than needing an agent restart.
    ("sentinel.scan", Duration::seconds(60), Duration::seconds(5)),
    // Alert evaluation (spec §11.11). A minute is the coarsest interval that
    // still meets the acceptance criterion of "killing mariadb produces an
    // alert in under 30 s" once the 30 s `TICK` is accounted for, and the pass
    // is cheap: it reads the collector's existing snapshot rather than
    // sampling, and touches the network only on a state *change*.
    (
        "alerts.evaluate",
        Duration::minutes(1),
        Duration::seconds(10),
    ),
    // Backup schedules (spec §11.10). A minute, because the schedules are
    // five-field cron expressions whose finest granularity is one minute: a
    // slower job would silently skip the minute a nightly backup asked for. The
    // pass is cheap when nothing is due — it reads the enabled schedules and
    // returns at once when there are none.
    (
        "backup.scheduler",
        Duration::seconds(60),
        Duration::seconds(10),
    ),
    // Webhook delivery (spec §14 Phase 6). Thirty seconds is the finest the
    // 30 s `TICK` can actually honour, and it matters: the first retry after a
    // failed delivery waits thirty seconds, so a slower job would turn every
    // transient failure into a minutes-long delay for an integration that is
    // watching for "backup failed". The pass is cheap when the queue is empty —
    // one indexed query that returns nothing.
    (
        "webhook.deliver",
        Duration::seconds(30),
        Duration::seconds(5),
    ),
];

/// The jobs that are running in a task of their own right now.
///
/// `finish_job` is what moves a job's `next_run_at`, and it only runs when the
/// pass ends — so a pass that outlives a tick is still due on the next one.
/// Without this a nightly backup would be started again every thirty seconds
/// for as long as the first one took, each new pass racing the last over the
/// same restic repository.
#[derive(Clone, Default)]
struct InFlight(Arc<Mutex<HashSet<String>>>);

impl InFlight {
    /// Claim `name`, or `None` while an earlier pass still holds it. The claim
    /// is released when the returned guard is dropped — including when the task
    /// holding it is dropped at shutdown, so a restart never inherits a latch.
    fn claim(&self, name: &str) -> Option<Claim> {
        self.0
            .lock()
            .unwrap()
            .insert(name.to_string())
            .then(|| Claim {
                jobs: self.clone(),
                name: name.to_string(),
            })
    }

    /// Wait for the passes still running to end, or `budget` to expire.
    ///
    /// Returns the names of whatever was still running when it gave up, so the
    /// caller can say what it is about to cut short.
    async fn drain(&self, budget: StdDuration) -> Vec<String> {
        let deadline = Instant::now() + budget;
        loop {
            let running = self.running();
            if running.is_empty() || Instant::now() >= deadline {
                return running;
            }
            tokio::time::sleep(DRAIN_POLL).await;
        }
    }

    fn running(&self) -> Vec<String> {
        let mut names: Vec<String> = self.0.lock().unwrap().iter().cloned().collect();
        names.sort();
        names
    }
}

struct Claim {
    jobs: InFlight,
    name: String,
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.jobs.0.lock().unwrap().remove(&self.name);
    }
}

#[derive(Clone)]
pub struct Scheduler {
    registry: Arc<OpRegistry>,
    bus: TaskBus,
    in_flight: InFlight,
}

impl Scheduler {
    pub fn new(registry: Arc<OpRegistry>, bus: TaskBus) -> Self {
        Self {
            registry,
            bus,
            in_flight: InFlight::default(),
        }
    }

    fn db(&self) -> &Db {
        &self.registry.services().db
    }

    /// Register the built-in jobs. Idempotent, so it runs on every start.
    pub async fn register(&self) -> Result<(), String> {
        for (name, interval, jitter) in JOBS {
            self.db()
                .register_job(name, *interval, *jitter)
                .await
                .map_err(|e| format!("could not register `{name}`: {e}"))?;
        }
        Ok(())
    }

    /// The scheduler loop. Runs until `shutdown` resolves.
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()> + Send) {
        if let Err(e) = self.register().await {
            tracing::error!(error = %e, "scheduler could not register its jobs");
            return;
        }
        tracing::info!(jobs = JOBS.len(), "scheduler started");

        tokio::pin!(shutdown);
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("scheduler shutting down");
                    break;
                }
                _ = ticker.tick() => self.tick().await,
            }
        }

        let abandoned = self.in_flight.drain(SHUTDOWN_DRAIN).await;
        if !abandoned.is_empty() {
            // Worth a line at warn: a restic run cut off here leaves a lock in
            // the repository that the next backup has to be told to break.
            tracing::warn!(jobs = ?abandoned, "exiting with scheduled passes still running");
        }
    }

    async fn tick(&self) {
        let due = match self.db().due_jobs().await {
            Ok(jobs) => jobs,
            Err(e) => {
                tracing::error!(error = %e, "scheduler could not read its own schedule");
                return;
            }
        };

        for job in due {
            let Some(claim) = self.in_flight.claim(&job.name) else {
                tracing::debug!(
                    job = %job.name,
                    "still running from an earlier tick; not starting a second pass"
                );
                continue;
            };

            // Its own task, never awaited here: a pass is allowed to be slow —
            // a nightly restic run is permitted twelve hours, and five ACME
            // orders are minutes each. Awaited inline that is time in which
            // Sentinel does not scan for a brute force and alerts are not
            // evaluated, and, because the loop polls the shutdown future only
            // between ticks, `systemctl stop` hangs until systemd gives up and
            // SIGKILLs the agent in the middle of the backup.
            let scheduler = self.clone();
            tokio::spawn(async move {
                let _claim = claim;
                scheduler.run_to_completion(&job).await;
            });
        }
    }

    /// Run one job and record what it did.
    async fn run_to_completion(&self, job: &ScheduledJob) {
        let started = Instant::now();
        let outcome = self.run_job(job).await;
        let elapsed = started.elapsed();

        match &outcome {
            Ok(summary) if !summary.is_empty() => {
                tracing::info!(job = %job.name, ?elapsed, summary, "scheduled job finished");
            }
            Ok(_) => tracing::debug!(job = %job.name, "scheduled job had nothing to do"),
            Err(e) => tracing::warn!(job = %job.name, error = %e, "scheduled job failed"),
        }

        // Record and reschedule whatever happened. A job that stops
        // rescheduling after one bad day is a job that stops forever.
        if let Err(e) = self
            .db()
            .finish_job(&job.name, outcome.clone().map(|_| ()), elapsed)
            .await
        {
            tracing::error!(job = %job.name, error = %e, "could not record a job result");
        }
    }

    async fn run_job(&self, job: &ScheduledJob) -> Result<String, String> {
        match job.name.as_str() {
            "cert.renew" => self.renew_certificates().await,
            "cert.expire-stale" => self.expire_stale_certificates().await,
            "session.purge" => self.purge_sessions().await,
            "audit.purge" => self.purge_audit().await,
            "sentinel.scan" => self.sentinel_scan().await,
            "alerts.evaluate" => self.evaluate_alerts().await,
            "backup.scheduler" => self.run_due_backups().await,
            "webhook.deliver" => self.deliver_webhooks().await,
            // A job left in the database by an older version. Not an error; it
            // simply has no handler any more.
            other => {
                tracing::debug!(job = other, "no handler for this job; ignoring");
                Ok(String::new())
            }
        }
    }

    // -----------------------------------------------------------------------
    // certificates
    // -----------------------------------------------------------------------

    /// Renew certificates inside the thirty-day window.
    ///
    /// Each renewal is a real Task, so its progress and its failure reason show
    /// up in the task drawer exactly as a manual issuance would.
    async fn renew_certificates(&self) -> Result<String, String> {
        let db = self.db().clone();
        let due = db
            .certificates_to_renew(RENEW_WINDOW, RENEWALS_PER_TICK)
            .await
            .map_err(|e| e.to_string())?;

        if due.is_empty() {
            return Ok(String::new());
        }

        let mut renewed = 0;
        let mut failed = 0;

        for certificate in due {
            let Some(site_id) = certificate.site_id else {
                // The panel's own certificate has no site; it renews through
                // `panel.tls.issue`, which re-renders the panel vhost and
                // reloads nginx (spec §11.5).
                match self.renew_panel(&certificate).await {
                    Ok(true) => renewed += 1,
                    Ok(false) => {}
                    Err(()) => failed += 1,
                }
                continue;
            };

            let days = certificate.days_remaining().unwrap_or(0);
            tracing::info!(
                certificate = certificate.id,
                domains = ?certificate.domains,
                days_remaining = days,
                "renewing"
            );

            let attempt = if covers_a_wildcard(&certificate.domains) {
                self.issue_wildcard(site_id, &certificate.domains).await
            } else {
                self.issue(site_id, &certificate.domains).await
            };

            match attempt {
                Ok(()) => renewed += 1,
                Err(e) => {
                    failed += 1;
                    // Back off before trying again. Let's Encrypt allows five
                    // failed validations per identifier per hour, so a site with
                    // a broken DNS record must not retry in a loop.
                    let backoff = unihelm_ops::cert::renewal_backoff(certificate.failure_count);
                    let next = unihelm_db::now() + backoff;
                    let _ = db.set_certificate_next_attempt(certificate.id, next).await;
                    let _ = db.certificate_failed(certificate.id, &e).await;

                    tracing::warn!(
                        certificate = certificate.id,
                        error = %e,
                        retry_in_minutes = backoff.whole_minutes(),
                        "renewal failed"
                    );
                }
            }
        }

        match (renewed, failed) {
            (0, 0) => Ok(String::new()),
            (r, 0) => Ok(format!("renewed {r} certificate(s)")),
            (r, f) => Err(format!(
                "renewed {r}, failed {f} — see the task log for each"
            )),
        }
    }

    /// Run one renewal as a Task under the system identity.
    async fn issue(&self, site_id: unihelm_core::SiteId, domains: &[String]) -> Result<(), String> {
        let db = self.db().clone();
        let task_id = TaskId::new();

        db.create_task(NewTask {
            id: task_id,
            op: "cert.issue".into(),
            input: serde_json::json!({ "site_id": site_id.get(), "renewal": true }),
            // No user did this; the audit trail says so.
            actor_user_id: None,
            subscription_id: None,
            cancellable: false,
            // Safe to run again: a duplicate order costs rate-limit budget but
            // cannot corrupt anything.
            idempotent: true,
            request_id: Some(format!("scheduler-renew-{}", domains.join(","))),
        })
        .await
        .map_err(|e| e.to_string())?;

        db.start_task(task_id).await.map_err(|e| e.to_string())?;

        let log: Arc<dyn LogSink> = Arc::new(TaskLog {
            db: db.clone(),
            task_id,
            bus: self.bus.clone(),
        });

        let ctx = OpContext::new(
            self.registry.services().clone(),
            AuthContext::system("cert.renew"),
        )
        .with_task(task_id, log);

        let result = unihelm_ops::cert::Issue
            .run(
                &ctx,
                unihelm_ops::cert::IssueInput {
                    site_id: site_id.get(),
                    staging: false,
                    contact_email: None,
                },
            )
            .await;

        match result {
            Ok(_) => {
                let _ = db.finish_task_ok(task_id).await;
                Ok(())
            }
            Err(e) => {
                let _ = db.finish_task_failed(task_id, &e).await;
                Err(e.detail)
            }
        }
    }

    /// Renew a wildcard certificate through DNS-01, as a real Task under the
    /// system identity.
    ///
    /// A separate path from [`Scheduler::issue`] because `cert.issue` cannot
    /// produce this certificate: it rebuilds its names from the site's
    /// `server_names`, and no alias can hold a `*` label. Renewing a wildcard
    /// through it therefore replaces `*.example.com` with a certificate for the
    /// apex alone, reloads nginx onto it, and reports success — every host under
    /// the wildcard then fails on a name mismatch.
    ///
    /// A missing DNS credential is a failed renewal like any other, with the
    /// usual backoff. Falling back to `cert.issue` would be exactly the silent
    /// downgrade this exists to prevent.
    async fn issue_wildcard(
        &self,
        site_id: unihelm_core::SiteId,
        domains: &[String],
    ) -> Result<(), String> {
        let db = self.db().clone();
        let task_id = TaskId::new();

        db.create_task(NewTask {
            id: task_id,
            op: "cert.issue_wildcard".into(),
            input: serde_json::json!({ "site_id": site_id.get(), "renewal": true }),
            // No user did this; the audit trail says so.
            actor_user_id: None,
            subscription_id: None,
            cancellable: false,
            // Not re-run on its own after a crash, matching what the operation
            // declares: DNS-01 publishes a TXT record in a zone the panel does
            // not own and takes it down again on the way out.
            idempotent: false,
            request_id: Some(format!("scheduler-renew-wildcard-{}", domains.join(","))),
        })
        .await
        .map_err(|e| e.to_string())?;

        db.start_task(task_id).await.map_err(|e| e.to_string())?;

        let log: Arc<dyn LogSink> = Arc::new(TaskLog {
            db: db.clone(),
            task_id,
            bus: self.bus.clone(),
        });

        let ctx = OpContext::new(
            self.registry.services().clone(),
            AuthContext::system("cert.renew"),
        )
        .with_task(task_id, log);

        let result = unihelm_ops::dns::IssueWildcard
            .run(
                &ctx,
                unihelm_ops::dns::IssueWildcardInput {
                    site_id: site_id.get(),
                    staging: false,
                    contact_email: None,
                },
            )
            .await;

        match result {
            Ok(_) => {
                let _ = db.finish_task_ok(task_id).await;
                Ok(())
            }
            Err(e) => {
                let _ = db.finish_task_failed(task_id, &e).await;
                Err(e.detail)
            }
        }
    }

    /// Renew the panel's own certificate (site_id NULL) through
    /// `panel.tls.issue`, as a real Task under the system identity.
    ///
    /// `Ok(true)` renewed, `Ok(false)` skipped on purpose, `Err(())` failed —
    /// with the backoff bookkeeping already done, so the caller only counts.
    async fn renew_panel(&self, certificate: &unihelm_db::Certificate) -> Result<bool, ()> {
        let db = self.db().clone();

        // The domain of record is the setting, not the row. If an operator
        // re-pointed the panel since this row was issued, renewing the old
        // name would spend rate-limit budget on a domain the panel no longer
        // uses — and the new domain already has its own row.
        let stored: Option<String> = db
            .get_setting(unihelm_db::panel::DOMAIN_KEY)
            .await
            .ok()
            .flatten();
        let domain = match (stored, certificate.domains.first()) {
            (Some(setting), Some(row)) if setting != *row => {
                tracing::info!(
                    certificate = certificate.id,
                    row_domain = %row,
                    panel_domain = %setting,
                    "panel domain changed; retiring the old certificate from renewal"
                );
                let _ = db.set_certificate_auto_renew(certificate.id, false).await;
                return Ok(false);
            }
            (Some(setting), _) => setting,
            // No setting but a live NULL-site LE row: keep the working
            // certificate alive rather than letting it lapse over lost state.
            (None, Some(row)) => row.clone(),
            (None, None) => {
                tracing::warn!(
                    certificate = certificate.id,
                    "a panel certificate with no domains cannot be renewed"
                );
                let _ = db.set_certificate_auto_renew(certificate.id, false).await;
                return Ok(false);
            }
        };

        // Parse before any task exists: a corrupt stored domain is a renewal
        // failure like any other, with the same backoff.
        let parsed = match unihelm_core::Domain::parse(&domain) {
            Ok(d) => d,
            Err(e) => {
                self.panel_renewal_failed(certificate, &e.detail).await;
                return Err(());
            }
        };

        let task_id = TaskId::new();
        let created = db
            .create_task(NewTask {
                id: task_id,
                op: "panel.tls.issue".into(),
                input: serde_json::json!({ "domain": domain, "renewal": true }),
                // No user did this; the audit trail says so.
                actor_user_id: None,
                subscription_id: None,
                cancellable: false,
                // Safe to run again: a duplicate order costs rate-limit budget
                // but cannot corrupt anything.
                idempotent: true,
                request_id: Some(format!("scheduler-renew-panel-{domain}")),
            })
            .await;
        if let Err(e) = created {
            tracing::warn!(error = %e, "could not create the panel renewal task");
            return Err(());
        }
        if let Err(e) = db.start_task(task_id).await {
            tracing::warn!(error = %e, "could not start the panel renewal task");
            return Err(());
        }

        let log: Arc<dyn LogSink> = Arc::new(TaskLog {
            db: db.clone(),
            task_id,
            bus: self.bus.clone(),
        });

        let ctx = OpContext::new(
            self.registry.services().clone(),
            AuthContext::system("cert.renew"),
        )
        .with_task(task_id, log);

        let result = unihelm_ops::panel::Issue
            .run(
                &ctx,
                unihelm_ops::panel::IssueInput {
                    domain: parsed,
                    contact_email: None,
                    staging: false,
                },
            )
            .await;

        match result {
            Ok(_) => {
                let _ = db.finish_task_ok(task_id).await;
                Ok(true)
            }
            Err(e) => {
                let _ = db.finish_task_failed(task_id, &e).await;
                self.panel_renewal_failed(certificate, &e.detail).await;
                Err(())
            }
        }
    }

    /// Backoff bookkeeping for a failed panel renewal — on the row that is
    /// actually due, not the fresh attempt row `panel.tls.issue` recorded its
    /// own failure on.
    async fn panel_renewal_failed(&self, certificate: &unihelm_db::Certificate, error: &str) {
        let db = self.db();
        let backoff = unihelm_ops::cert::renewal_backoff(certificate.failure_count);
        let next = unihelm_db::now() + backoff;
        let _ = db.set_certificate_next_attempt(certificate.id, next).await;
        let _ = db.certificate_failed(certificate.id, error).await;

        tracing::warn!(
            certificate = certificate.id,
            error = %error,
            retry_in_minutes = backoff.whole_minutes(),
            "panel certificate renewal failed"
        );
    }

    async fn expire_stale_certificates(&self) -> Result<String, String> {
        let n = self
            .db()
            .expire_stale_certificates()
            .await
            .map_err(|e| e.to_string())?;
        Ok(if n == 0 {
            String::new()
        } else {
            format!("marked {n} certificate(s) expired")
        })
    }

    // -----------------------------------------------------------------------
    // alerting
    // -----------------------------------------------------------------------

    /// Evaluate the alert rules and notify on every state transition
    /// (spec §11.11).
    ///
    /// Deliberately *not* a Task, unlike the renewals above. This runs 1,440
    /// times a day and almost always decides nothing has changed; giving each
    /// pass a row in the task drawer would bury the tasks an operator actually
    /// wants to read under a wall of "alerts.evaluate — ok". The transitions
    /// that do happen are recorded in `alert_events`, which is the record the
    /// alerts page reads.
    ///
    /// The summary counts transitions rather than firing alerts, so a quiet
    /// server logs nothing at all (`tick` treats an empty summary as "had
    /// nothing to do").
    async fn evaluate_alerts(&self) -> Result<String, String> {
        let ctx = OpContext::new(
            self.registry.services().clone(),
            AuthContext::system("alerts.evaluate"),
        );

        let raised = unihelm_ops::alerts::evaluate(&ctx)
            .await
            .map_err(|e| e.detail)?;
        if raised.is_empty() {
            return Ok(String::new());
        }

        let (opened, closed): (Vec<_>, Vec<_>) = raised
            .iter()
            .partition(|r| r.state == unihelm_ops::alerts::AlertState::Raised);
        Ok(format!(
            "{} alert(s) raised, {} resolved",
            opened.len(),
            closed.len()
        ))
    }

    // -----------------------------------------------------------------------
    // backups
    // -----------------------------------------------------------------------

    /// Start whatever backup schedules are due (spec §11.10).
    ///
    /// Deliberately not a Task, for the same reason as the Sentinel and alert
    /// passes above: it wakes every minute and decides nothing on almost all of
    /// them. The backups it *does* start each get a `backup_runs` row with a
    /// start time, an end time and — on failure — restic's own words, which is
    /// the history the backups page reads and the record an operator needs when
    /// the question is "when did this stop working".
    async fn run_due_backups(&self) -> Result<String, String> {
        let ctx = OpContext::new(
            self.registry.services().clone(),
            AuthContext::system("backup.scheduler"),
        );
        unihelm_ops::backup::scheduler_tick(&ctx).await
    }

    // -----------------------------------------------------------------------
    // webhooks
    // -----------------------------------------------------------------------

    /// Drain whatever webhook deliveries are due (spec §14 Phase 6).
    ///
    /// Not a Task, for the same reason as the alert and backup passes above: it
    /// wakes twice a minute and decides there is nothing to send on almost all
    /// of them. What a delivery *did* is recorded on its `webhook_deliveries`
    /// row — attempts, last error, response status — which is the history the
    /// webhooks page reads and the record an integrator needs when the question
    /// is "did you ever send it".
    async fn deliver_webhooks(&self) -> Result<String, String> {
        let ctx = OpContext::new(
            self.registry.services().clone(),
            AuthContext::system("webhook.deliver"),
        );
        unihelm_ops::webhook::delivery_tick(&ctx).await
    }

    // -----------------------------------------------------------------------
    // retention
    // -----------------------------------------------------------------------

    async fn purge_sessions(&self) -> Result<String, String> {
        let db = self.db();
        let sessions = db
            .purge_expired_sessions()
            .await
            .map_err(|e| e.to_string())?;
        // Keep a fortnight of login history: enough for the rate limiter and for
        // somebody investigating an incident, not enough to grow forever.
        let attempts = db
            .purge_login_attempts(Duration::days(14))
            .await
            .map_err(|e| e.to_string())?;

        Ok(if sessions == 0 && attempts == 0 {
            String::new()
        } else {
            format!("purged {sessions} session(s) and {attempts} login attempt(s)")
        })
    }

    async fn purge_audit(&self) -> Result<String, String> {
        let db = self.db();
        // Configurable, defaulting to the 180 days in spec §10.3.
        let days = db
            .get_setting_or(unihelm_db::settings::keys::AUDIT_RETENTION_DAYS, 180i64)
            .await;
        let n = db.purge_audit(days).await.map_err(|e| e.to_string())?;

        // Resolved alert events age out on the same retention setting and in
        // the same daily sweep — an alert history is the same kind of record as
        // an audit trail, and a panel that has been up for two years should not
        // still be holding the disk-full events of its first week. Only
        // *resolved* rows are eligible: an open event is current state, however
        // old it is (spec §11.11).
        let alerts = db
            .purge_alert_events(days)
            .await
            .map_err(|e| e.to_string())?;

        // Terminal webhook deliveries age out on the same sweep and the same
        // setting. The queue is a queue, not a history: a panel that has been
        // up for two years should not still be carrying the delivered rows of
        // its first week (spec §14 Phase 6). Pending rows are never touched —
        // they are current state, however old they are.
        let deliveries = db.purge_deliveries(days).await.map_err(|e| e.to_string())?;

        Ok(if n == 0 && alerts == 0 && deliveries == 0 {
            String::new()
        } else {
            format!(
                "purged {n} audit row(s), {alerts} resolved alert(s) and \
                 {deliveries} finished webhook deliver(ies)"
            )
        })
    }

    // -----------------------------------------------------------------------
    // Sentinel
    // -----------------------------------------------------------------------

    /// One Sentinel pass (spec §11.9).
    ///
    /// No task row and no `TaskLog`, unlike a renewal: this runs every minute
    /// and is silent on the overwhelming majority of ticks, so giving each one
    /// a task would bury the tasks a human actually started under a thousand
    /// empty rows a day. The bans it *does* place are recorded in
    /// `sentinel_bans` and in the audit trail, which is where somebody looking
    /// for "why was this address blocked" would go anyway.
    ///
    /// While `sentinel.enabled` is false — the default on a fresh install —
    /// this returns immediately without reading the journal at all, so the job
    /// existing in the schedule costs a settings lookup and nothing more.
    async fn sentinel_scan(&self) -> Result<String, String> {
        let ctx = OpContext::new(
            self.registry.services().clone(),
            AuthContext::system("sentinel.scan"),
        );
        unihelm_ops::fwops::sentinel_tick(&ctx)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Does this certificate cover a wildcard name?
///
/// It decides which operation renews the row, and the two are not
/// interchangeable: only `cert.issue_wildcard` can ask for `*.example.com`,
/// because it is the only one that proves the name over DNS-01.
fn covers_a_wildcard(domains: &[String]) -> bool {
    domains.iter().any(|d| d.starts_with("*."))
}

/// Persists a scheduled task's output and pushes it to anyone watching.
///
/// The same two destinations a user-initiated task writes to, so a renewal that
/// ran overnight can be read the next morning exactly like one somebody clicked.
struct TaskLog {
    db: Db,
    task_id: TaskId,
    bus: TaskBus,
}

impl LogSink for TaskLog {
    fn line(&self, line: &str) {
        let db = self.db.clone();
        let bus = self.bus.clone();
        let task_id = self.task_id;
        let line = line.to_string();

        // The sink is synchronous and called from inside operation code, so the
        // write is handed to the runtime rather than blocking the caller.
        tokio::spawn(async move {
            if let Ok(seq) = db.append_task_log(task_id, &line).await {
                bus.publish(EventFrame::new(EventKind::TaskLog { task_id, seq, line }));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(name: &str) -> (Duration, Duration) {
        let (_, interval, jitter) = JOBS
            .iter()
            .find(|(n, ..)| *n == name)
            .unwrap_or_else(|| panic!("`{name}` is not in the built-in schedule"));
        (*interval, *jitter)
    }

    #[test]
    fn a_slow_pass_is_not_started_a_second_time_while_the_first_is_still_running() {
        // The backup job stays due until it finishes, because `finish_job` is
        // what moves `next_run_at` — so every tick during a ten-minute backup
        // offers it again.
        let jobs = InFlight::default();
        let running = jobs.claim("backup.scheduler").expect("the first pass runs");
        assert!(
            jobs.claim("backup.scheduler").is_none(),
            "a second pass would race the first over the same restic repository"
        );
        // A different job is unaffected: one slow backup must not stop Sentinel.
        assert!(jobs.claim("sentinel.scan").is_some());

        drop(running);
        assert!(
            jobs.claim("backup.scheduler").is_some(),
            "the next tick after a pass ends must be able to start one"
        );
    }

    #[tokio::test]
    async fn shutdown_waits_for_a_running_pass_but_not_for_a_backup() {
        // Passes run in their own task now, and a task is killed outright when
        // the runtime goes away — so without a wait, every upgrade would cut
        // off an ACME order or a webhook flush that was one second from done,
        // which the old inline loop never did. The wait has to be bounded, or
        // the nightly backup puts the hang straight back.
        let jobs = InFlight::default();
        let finishing = jobs.claim("webhook.deliver").expect("the pass runs");
        tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(50)).await;
            drop(finishing);
        });
        assert!(
            jobs.drain(StdDuration::from_secs(30)).await.is_empty(),
            "a pass that ends must be waited for, not killed"
        );

        let _backup = jobs.claim("backup.scheduler").expect("the pass runs");
        let started = Instant::now();
        assert_eq!(
            jobs.drain(StdDuration::from_millis(200)).await,
            vec!["backup.scheduler".to_string()],
            "a pass that outlasts the budget is reported, not waited on"
        );
        assert!(
            started.elapsed() < StdDuration::from_secs(5),
            "the wait must be bounded: systemd SIGKILLs the agent if it is not"
        );
    }

    #[test]
    fn a_wildcard_certificate_is_renewed_through_dns_and_not_as_a_plain_one() {
        // `cert.issue` rebuilds its names from the site's server_names, which
        // can never hold a `*` label — so sending this row there replaces the
        // wildcard with a certificate that matches none of the hosts it covered.
        assert!(covers_a_wildcard(&[
            "example.com".into(),
            "*.example.com".into()
        ]));
        assert!(!covers_a_wildcard(&[
            "example.com".into(),
            "www.example.com".into()
        ]));
        assert!(!covers_a_wildcard(&[]));
    }

    #[test]
    fn renewals_keep_up_with_the_estate_the_panel_is_sold_for() {
        let (interval, jitter) = job("cert.renew");
        // Worst case the jitter always lands at its maximum.
        let slowest = interval + jitter;
        let per_day =
            RENEWALS_PER_TICK * (Duration::days(1).whole_seconds() / slowest.whole_seconds());

        // A Let's Encrypt certificate lives ninety days and is renewed once it
        // is inside the window, so each one comes back every sixty days: an
        // estate of this size costs SITES/60 renewals a day just to stand
        // still, and several times that to drain the backlog a bulk
        // provisioning leaves behind before the oldest of them lapses.
        const SITES: i64 = 600;
        const LIFETIME: Duration = Duration::days(90);
        let standing_still = SITES / (LIFETIME - RENEW_WINDOW).whole_days();
        assert!(
            per_day >= standing_still * 4,
            "{per_day} renewals a day cannot carry {SITES} certificates: \
             standing still already costs {standing_still} a day"
        );
    }
}
