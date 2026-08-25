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
                // The panel's own certificate has no site; it is renewed by its
                // own path once that exists.
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

    async fn expire_stale_certificates(&self) -> Result<String, String> {
        let n = self.db().expire_stale_certificates().await.map_err(|e| e.to_string())?;
        Ok(if n == 0 { String::new() } else { format!("marked {n} certificate(s) expired") })
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
        Ok(if n == 0 { String::new() } else { format!("purged {n} audit row(s)") })
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
