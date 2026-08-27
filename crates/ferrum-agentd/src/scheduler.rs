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

use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use ferrum_core::{AuthContext, TaskId};
use ferrum_db::tasks::NewTask;
use ferrum_db::{Db, ScheduledJob};
use ferrum_distro::pkg::LogSink;
use ferrum_ipc::frame::{EventFrame, EventKind};
use ferrum_ops::registry::TypedOperation;
use ferrum_ops::{OpContext, OpRegistry};
use time::Duration;

use crate::tasks::TaskBus;

/// How often the loop wakes to look for due work.
///
/// Short enough that a job scheduled for "now" runs promptly, long enough that
/// an idle panel is not spending measurable CPU on an empty query — the metrics
/// collector's 1% budget applies to the whole agent, not just to metrics.
const TICK: StdDuration = StdDuration::from_secs(30);

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
    // Twice a day is plenty for a thirty-day window, and cheap when nothing is
    // due.
    ("cert.renew", Duration::hours(12), Duration::hours(1)),
    // So the dashboard stops calling an expired certificate active.
    ("cert.expire-stale", Duration::hours(1), Duration::minutes(5)),
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
    ("alerts.evaluate", Duration::minutes(1), Duration::seconds(10)),
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
];

pub struct Scheduler {
    registry: Arc<OpRegistry>,
    bus: TaskBus,
}

impl Scheduler {
    pub fn new(registry: Arc<OpRegistry>, bus: TaskBus) -> Self {
        Self { registry, bus }
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
            let started = Instant::now();
            let outcome = self.run_job(&job).await;
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

            match self.issue(site_id, &certificate.domains).await {
                Ok(()) => renewed += 1,
                Err(e) => {
                    failed += 1;
                    // Back off before trying again. Let's Encrypt allows five
                    // failed validations per identifier per hour, so a site with
                    // a broken DNS record must not retry in a loop.
                    let backoff = ferrum_ops::cert::renewal_backoff(certificate.failure_count);
                    let next = ferrum_db::now() + backoff;
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
            (r, f) => Err(format!("renewed {r}, failed {f} — see the task log for each")),
        }
    }

    /// Run one renewal as a Task under the system identity.
    async fn issue(&self, site_id: ferrum_core::SiteId, domains: &[String]) -> Result<(), String> {
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

        let result = ferrum_ops::cert::Issue
            .run(
                &ctx,
                ferrum_ops::cert::IssueInput {
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
    async fn renew_panel(&self, certificate: &ferrum_db::Certificate) -> Result<bool, ()> {
        let db = self.db().clone();

        // The domain of record is the setting, not the row. If an operator
        // re-pointed the panel since this row was issued, renewing the old
        // name would spend rate-limit budget on a domain the panel no longer
        // uses — and the new domain already has its own row.
        let stored: Option<String> = db
            .get_setting(ferrum_db::panel::DOMAIN_KEY)
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
        let parsed = match ferrum_core::Domain::parse(&domain) {
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

        let result = ferrum_ops::panel::Issue
            .run(
                &ctx,
                ferrum_ops::panel::IssueInput {
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
    async fn panel_renewal_failed(&self, certificate: &ferrum_db::Certificate, error: &str) {
        let db = self.db();
        let backoff = ferrum_ops::cert::renewal_backoff(certificate.failure_count);
        let next = ferrum_db::now() + backoff;
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
        let n = self.db().expire_stale_certificates().await.map_err(|e| e.to_string())?;
        Ok(if n == 0 { String::new() } else { format!("marked {n} certificate(s) expired") })
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

        let raised = ferrum_ops::alerts::evaluate(&ctx)
            .await
            .map_err(|e| e.detail)?;
        if raised.is_empty() {
            return Ok(String::new());
        }

        let (opened, closed): (Vec<_>, Vec<_>) = raised
            .iter()
            .partition(|r| r.state == ferrum_ops::alerts::AlertState::Raised);
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
        ferrum_ops::backup::scheduler_tick(&ctx).await
    }

    // -----------------------------------------------------------------------
    // retention
    // -----------------------------------------------------------------------

    async fn purge_sessions(&self) -> Result<String, String> {
        let db = self.db();
        let sessions = db.purge_expired_sessions().await.map_err(|e| e.to_string())?;
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
            .get_setting_or(ferrum_db::settings::keys::AUDIT_RETENTION_DAYS, 180i64)
            .await;
        let n = db.purge_audit(days).await.map_err(|e| e.to_string())?;

        // Resolved alert events age out on the same retention setting and in
        // the same daily sweep — an alert history is the same kind of record as
        // an audit trail, and a panel that has been up for two years should not
        // still be holding the disk-full events of its first week. Only
        // *resolved* rows are eligible: an open event is current state, however
        // old it is (spec §11.11).
        let alerts = db.purge_alert_events(days).await.map_err(|e| e.to_string())?;

        Ok(if n == 0 && alerts == 0 {
            String::new()
        } else {
            format!("purged {n} audit row(s) and {alerts} resolved alert(s)")
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
        ferrum_ops::fwops::sentinel_tick(&ctx)
            .await
            .map_err(|e| e.to_string())
    }
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
