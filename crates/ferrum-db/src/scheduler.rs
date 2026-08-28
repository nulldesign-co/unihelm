//! The internal scheduler's persisted state (spec §10.2).
//!
//! Jobs live in the database rather than in memory because the agent restarts:
//! a schedule held in a process is a schedule that silently stops after a crash,
//! and the certificate renewal that stops silently is the one nobody notices for
//! ninety days.

use serde::Serialize;
use time::Duration;

use crate::{Db, Result, from_sql_time, now, to_sql_time};

#[derive(Debug, Clone, Serialize)]
pub struct ScheduledJob {
    pub name: String,
    pub interval_seconds: i64,
    pub jitter_seconds: i64,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_run_at: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub next_run_at: time::OffsetDateTime,
    pub last_status: Option<String>,
    pub last_error: Option<String>,
    pub last_duration_ms: Option<i64>,
    pub run_count: i64,
    pub failure_count: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScheduledJobRow {
    pub name: String,
    pub interval_seconds: i64,
    pub jitter_seconds: i64,
    pub enabled: i64,
    pub last_run_at: Option<String>,
    pub next_run_at: String,
    pub last_status: Option<String>,
    pub last_error: Option<String>,
    pub last_duration_ms: Option<i64>,
    pub run_count: i64,
    pub failure_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<ScheduledJobRow> for ScheduledJob {
    type Error = crate::DbError;

    fn try_from(r: ScheduledJobRow) -> Result<Self> {
        Ok(ScheduledJob {
            name: r.name,
            interval_seconds: r.interval_seconds,
            jitter_seconds: r.jitter_seconds,
            enabled: r.enabled != 0,
            last_run_at: r.last_run_at.as_deref().map(from_sql_time).transpose()?,
            next_run_at: from_sql_time(&r.next_run_at)?,
            last_status: r.last_status,
            last_error: r.last_error,
            last_duration_ms: r.last_duration_ms,
            run_count: r.run_count,
            failure_count: r.failure_count,
        })
    }
}

impl Db {
    /// Register a job, or refresh an existing registration's interval.
    ///
    /// Idempotent on purpose: the agent registers its jobs on every start, and
    /// doing so must not reset a schedule or lose a job's history. Only the
    /// interval and jitter are refreshed, so changing them in code takes effect
    /// on upgrade.
    pub async fn register_job(
        &self,
        name: &str,
        interval: Duration,
        jitter: Duration,
    ) -> Result<()> {
        let ts = to_sql_time(now());
        // A newly registered job is due almost immediately, but jittered —
        // otherwise every job registered at boot fires in the same instant.
        let first_run = to_sql_time(now() + jitter_offset(jitter));

        sqlx::query(
            "INSERT INTO scheduler_jobs
                 (name, interval_seconds, jitter_seconds, next_run_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT (name) DO UPDATE SET
                 interval_seconds = ?2,
                 jitter_seconds   = ?3,
                 updated_at       = ?5",
        )
        .bind(name)
        .bind(interval.whole_seconds().max(1))
        .bind(jitter.whole_seconds().max(0))
        .bind(first_run)
        .bind(&ts)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Jobs whose time has come.
    ///
    /// A job that fell due while the agent was down comes back due rather than
    /// being skipped — which is the whole reason the schedule is persisted.
    pub async fn due_jobs(&self) -> Result<Vec<ScheduledJob>> {
        let rows = sqlx::query_as::<_, ScheduledJobRow>(
            "SELECT * FROM scheduler_jobs WHERE enabled = 1 AND next_run_at <= ?1
             ORDER BY next_run_at ASC",
        )
        .bind(to_sql_time(now()))
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(ScheduledJob::try_from).collect()
    }

    /// Record the outcome and schedule the next run.
    pub async fn finish_job(
        &self,
        name: &str,
        outcome: std::result::Result<(), String>,
        duration: std::time::Duration,
    ) -> Result<()> {
        let Some(job) = self.job(name).await? else {
            return Ok(());
        };

        let interval = Duration::seconds(job.interval_seconds);
        let jitter = Duration::seconds(job.jitter_seconds);
        let next = now() + interval + jitter_offset(jitter);

        let (status, error) = match &outcome {
            Ok(()) => ("ok", None),
            Err(e) => ("failed", Some(truncate(e, 2000))),
        };

        sqlx::query(
            "UPDATE scheduler_jobs SET
                 last_run_at      = ?2,
                 next_run_at      = ?3,
                 last_status      = ?4,
                 last_error       = ?5,
                 last_duration_ms = ?6,
                 run_count        = run_count + 1,
                 failure_count    = CASE WHEN ?4 = 'failed' THEN failure_count + 1 ELSE 0 END,
                 updated_at       = ?2
             WHERE name = ?1",
        )
        .bind(name)
        .bind(to_sql_time(now()))
        .bind(to_sql_time(next))
        .bind(status)
        .bind(error)
        .bind(duration.as_millis() as i64)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn job(&self, name: &str) -> Result<Option<ScheduledJob>> {
        let row =
            sqlx::query_as::<_, ScheduledJobRow>("SELECT * FROM scheduler_jobs WHERE name = ?1")
                .bind(name)
                .fetch_optional(self.pool())
                .await?;
        row.map(ScheduledJob::try_from).transpose()
    }

    pub async fn jobs(&self) -> Result<Vec<ScheduledJob>> {
        let rows =
            sqlx::query_as::<_, ScheduledJobRow>("SELECT * FROM scheduler_jobs ORDER BY name ASC")
                .fetch_all(self.pool())
                .await?;
        rows.into_iter().map(ScheduledJob::try_from).collect()
    }

    /// Move a job's next run, for tests and for an operator deferring one.
    pub async fn defer_job(&self, name: &str, by: Duration) -> Result<()> {
        sqlx::query("UPDATE scheduler_jobs SET next_run_at = ?2 WHERE name = ?1")
            .bind(name)
            .bind(to_sql_time(now() + by))
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

/// A random offset in `[0, jitter]`.
///
/// A hundred servers installed from the same image would otherwise hit Let's
/// Encrypt in the same second every day.
fn jitter_offset(jitter: Duration) -> Duration {
    use rand::Rng;
    let seconds = jitter.whole_seconds();
    if seconds <= 0 {
        return Duration::ZERO;
    }
    Duration::seconds(rand::thread_rng().gen_range(0..=seconds))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> Db {
        Db::open_memory().await.unwrap()
    }

    #[tokio::test]
    async fn a_registered_job_becomes_due() {
        let db = db().await;
        db.register_job("cert.renew", Duration::hours(12), Duration::ZERO)
            .await
            .unwrap();

        let due = db.due_jobs().await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].name, "cert.renew");
        assert_eq!(due[0].run_count, 0);
    }

    #[tokio::test]
    async fn registering_twice_does_not_reset_the_schedule_or_the_history() {
        // The agent registers its jobs on every start; doing so must not lose a
        // job's history or make everything due again.
        let db = db().await;
        db.register_job("cert.renew", Duration::hours(12), Duration::ZERO)
            .await
            .unwrap();
        db.finish_job("cert.renew", Ok(()), std::time::Duration::from_millis(5))
            .await
            .unwrap();

        db.register_job("cert.renew", Duration::hours(12), Duration::ZERO)
            .await
            .unwrap();

        let job = db.job("cert.renew").await.unwrap().unwrap();
        assert_eq!(job.run_count, 1, "history must survive re-registration");
        assert!(
            job.next_run_at > now(),
            "the schedule must not be reset to now"
        );
        assert!(db.due_jobs().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn changing_the_interval_in_code_takes_effect_on_upgrade() {
        let db = db().await;
        db.register_job("metrics.rollup", Duration::hours(1), Duration::ZERO)
            .await
            .unwrap();
        db.register_job("metrics.rollup", Duration::minutes(5), Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(
            db.job("metrics.rollup")
                .await
                .unwrap()
                .unwrap()
                .interval_seconds,
            300
        );
    }

    #[tokio::test]
    async fn finishing_a_job_schedules_the_next_run_and_records_the_outcome() {
        let db = db().await;
        db.register_job("audit.purge", Duration::hours(24), Duration::ZERO)
            .await
            .unwrap();
        db.finish_job("audit.purge", Ok(()), std::time::Duration::from_millis(120))
            .await
            .unwrap();

        let job = db.job("audit.purge").await.unwrap().unwrap();
        assert_eq!(job.last_status.as_deref(), Some("ok"));
        assert_eq!(job.last_duration_ms, Some(120));
        assert_eq!(job.run_count, 1);
        assert!(job.last_run_at.is_some());
        let ahead = (job.next_run_at - now()).whole_seconds();
        assert!(
            (86_000..=86_400).contains(&ahead),
            "next run is {ahead}s away"
        );
    }

    #[tokio::test]
    async fn a_failure_is_recorded_and_the_job_still_reschedules() {
        // A job that stops rescheduling after one bad day is a job that stops
        // forever.
        let db = db().await;
        db.register_job("cert.renew", Duration::hours(12), Duration::ZERO)
            .await
            .unwrap();
        db.finish_job(
            "cert.renew",
            Err("the CA was unreachable".into()),
            std::time::Duration::ZERO,
        )
        .await
        .unwrap();

        let job = db.job("cert.renew").await.unwrap().unwrap();
        assert_eq!(job.last_status.as_deref(), Some("failed"));
        assert!(job.last_error.unwrap().contains("unreachable"));
        assert_eq!(job.failure_count, 1);
        assert!(
            job.next_run_at > now(),
            "a failed job must still be scheduled again"
        );
    }

    #[tokio::test]
    async fn a_success_clears_the_failure_streak() {
        let db = db().await;
        db.register_job("cert.renew", Duration::hours(12), Duration::ZERO)
            .await
            .unwrap();
        db.finish_job("cert.renew", Err("x".into()), std::time::Duration::ZERO)
            .await
            .unwrap();
        db.finish_job("cert.renew", Err("x".into()), std::time::Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(
            db.job("cert.renew").await.unwrap().unwrap().failure_count,
            2
        );

        db.finish_job("cert.renew", Ok(()), std::time::Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(
            db.job("cert.renew").await.unwrap().unwrap().failure_count,
            0
        );
    }

    #[tokio::test]
    async fn a_job_that_fell_due_while_the_agent_was_down_comes_back_due() {
        // The whole reason the schedule is persisted.
        let db = db().await;
        db.register_job("cert.renew", Duration::hours(12), Duration::ZERO)
            .await
            .unwrap();
        db.finish_job("cert.renew", Ok(()), std::time::Duration::ZERO)
            .await
            .unwrap();
        assert!(db.due_jobs().await.unwrap().is_empty());

        db.defer_job("cert.renew", -Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(db.due_jobs().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn jitter_spreads_the_first_run_without_ever_being_negative() {
        // A hundred servers from one image must not hit the CA in the same
        // second — but nor may a job be scheduled in the past and fire twice.
        let db = db().await;
        for i in 0..20 {
            db.register_job(
                &format!("job{i}"),
                Duration::hours(12),
                Duration::minutes(30),
            )
            .await
            .unwrap();
        }
        let jobs = db.jobs().await.unwrap();
        let offsets: Vec<i64> = jobs
            .iter()
            .map(|j| (j.next_run_at - now()).whole_seconds())
            .collect();
        assert!(
            offsets.iter().all(|o| (0..=1800).contains(o)),
            "offsets: {offsets:?}"
        );
        assert!(
            offsets
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                > 1,
            "no jitter was applied"
        );
    }

    #[tokio::test]
    async fn a_certificate_in_its_backoff_window_is_not_retried() {
        use crate::CertKind;
        let db = db().await;
        let cert = db
            .create_certificate(None, CertKind::Le, &["a.example".into()], "/certs/a")
            .await
            .unwrap();
        db.certificate_issued(
            cert.id,
            "LE",
            now() - Duration::days(80),
            now() + Duration::days(10),
        )
        .await
        .unwrap();

        assert_eq!(
            db.certificates_to_renew(Duration::days(30), 10)
                .await
                .unwrap()
                .len(),
            1
        );

        // A failure pushes the next attempt out; the scheduler must respect it,
        // or a broken vhost burns the five-failures-per-hour budget.
        db.set_certificate_next_attempt(cert.id, now() + Duration::hours(1))
            .await
            .unwrap();
        assert!(
            db.certificates_to_renew(Duration::days(30), 10)
                .await
                .unwrap()
                .is_empty()
        );

        db.set_certificate_next_attempt(cert.id, now() - Duration::minutes(1))
            .await
            .unwrap();
        assert_eq!(
            db.certificates_to_renew(Duration::days(30), 10)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn an_expired_certificate_is_still_offered_for_renewal() {
        // Past its expiry is the most urgent case, not a reason to give up.
        use crate::CertKind;
        let db = db().await;
        let cert = db
            .create_certificate(None, CertKind::Le, &["a.example".into()], "/certs/a")
            .await
            .unwrap();
        db.certificate_issued(
            cert.id,
            "LE",
            now() - Duration::days(95),
            now() - Duration::days(5),
        )
        .await
        .unwrap();
        assert_eq!(
            db.certificates_to_renew(Duration::days(30), 10)
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
