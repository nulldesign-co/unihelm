//! Alert rules, notifier channels and the alert-event state machine
//! (spec §11.11).
//!
//! Everything here is server-global rather than tenant-scoped, and deliberately
//! so: an alert about a full disk or a stopped nginx is about the machine, not
//! about a subscription. The permission that guards it is `ServerManage`, which
//! only an admin holds — so there is no [`unihelm_core::TenantScope`] parameter
//! to forget, because there is no per-tenant view to leak across.
//!
//! The one idea worth carrying out of this module is that an alert **event is a
//! span, not a point**. `raise_alert` is idempotent while an event is open, and
//! that is what stops a disk sitting at 90% from producing a message a minute.
//! The uniqueness is enforced by a partial index (migration 0011), not by a
//! read-then-write in the evaluator, so two evaluation passes cannot race a
//! duplicate into existence.

use serde::{Deserialize, Serialize};

use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// What a rule watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// Percentage of a filesystem in use.
    DiskPct,
    /// Percentage of RAM in use.
    MemPct,
    /// One-minute load average.
    Load,
    /// A managed unit that should be running is not.
    ServiceDown,
    /// Days until a certificate expires.
    CertExpiryDays,
}

impl AlertKind {
    pub const ALL: &'static [AlertKind] = &[
        AlertKind::DiskPct,
        AlertKind::MemPct,
        AlertKind::Load,
        AlertKind::ServiceDown,
        AlertKind::CertExpiryDays,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            AlertKind::DiskPct => "disk_pct",
            AlertKind::MemPct => "mem_pct",
            AlertKind::Load => "load",
            AlertKind::ServiceDown => "service_down",
            AlertKind::CertExpiryDays => "cert_expiry_days",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "disk_pct" => AlertKind::DiskPct,
            "mem_pct" => AlertKind::MemPct,
            "load" => AlertKind::Load,
            "service_down" => AlertKind::ServiceDown,
            "cert_expiry_days" => AlertKind::CertExpiryDays,
            other => {
                return Err(DbError::Corrupt {
                    field: "alert_rules.kind",
                    detail: format!("unknown kind `{other}`"),
                });
            }
        })
    }

    /// Does a *rising* value breach this kind, or a falling one?
    ///
    /// Disk, memory and load alert when they get too big; certificate lifetime
    /// alerts when it gets too small. `service_down` is boolean and modelled as
    /// rising (1.0 = down) so it needs no third case.
    pub const fn rises(self) -> bool {
        !matches!(self, AlertKind::CertExpiryDays)
    }
}

/// Where a notification goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Webhook,
    Telegram,
}

impl ChannelKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ChannelKind::Webhook => "webhook",
            ChannelKind::Telegram => "telegram",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "webhook" => ChannelKind::Webhook,
            "telegram" => ChannelKind::Telegram,
            other => {
                return Err(DbError::Corrupt {
                    field: "notify_channels.kind",
                    detail: format!("unknown kind `{other}`"),
                });
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AlertRule {
    pub id: i64,
    pub kind: AlertKind,
    /// `None` = every subject of this kind.
    pub target: Option<String>,
    pub threshold: f64,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

impl AlertRule {
    /// How the rule is named in a notification and in the UI.
    pub fn label(&self) -> String {
        match &self.target {
            Some(t) => format!("{}:{t}", self.kind.as_str()),
            None => self.kind.as_str().to_string(),
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AlertRuleRow {
    pub id: i64,
    pub kind: String,
    pub target: Option<String>,
    pub threshold: f64,
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<AlertRuleRow> for AlertRule {
    type Error = DbError;

    fn try_from(r: AlertRuleRow) -> Result<Self> {
        Ok(AlertRule {
            id: r.id,
            kind: AlertKind::parse(&r.kind)?,
            target: r.target,
            threshold: r.threshold,
            enabled: r.enabled != 0,
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

/// A notifier channel, **without** its configuration.
///
/// `config_sealed` is `#[serde(skip)]` rather than simply private: this struct
/// is what `alert.channels.list` returns, and a sealed blob in an API response
/// is still a ciphertext an attacker can take away and work on offline. The
/// only code that ever sees it is the notifier, which asks for it explicitly.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NotifyChannel {
    pub id: i64,
    pub kind: ChannelKind,
    pub label: String,
    pub enabled: bool,
    #[serde(skip)]
    pub config_sealed: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NotifyChannelRow {
    pub id: i64,
    pub kind: String,
    pub label: String,
    pub config_sealed: String,
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<NotifyChannelRow> for NotifyChannel {
    type Error = DbError;

    fn try_from(r: NotifyChannelRow) -> Result<Self> {
        Ok(NotifyChannel {
            id: r.id,
            kind: ChannelKind::parse(&r.kind)?,
            label: r.label,
            enabled: r.enabled != 0,
            config_sealed: r.config_sealed,
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

/// One span during which a rule's condition held for one subject.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AlertEvent {
    pub id: i64,
    pub rule_id: i64,
    pub subject: String,
    pub message: String,
    pub value: Option<f64>,
    #[serde(with = "time::serde::rfc3339")]
    pub raised_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub resolved_at: Option<time::OffsetDateTime>,
    pub notified: i64,
}

impl AlertEvent {
    pub fn is_open(&self) -> bool {
        self.resolved_at.is_none()
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AlertEventRow {
    pub id: i64,
    pub rule_id: i64,
    pub subject: String,
    pub message: String,
    pub value: Option<f64>,
    pub raised_at: String,
    pub resolved_at: Option<String>,
    pub notified: i64,
}

impl TryFrom<AlertEventRow> for AlertEvent {
    type Error = DbError;

    fn try_from(r: AlertEventRow) -> Result<Self> {
        Ok(AlertEvent {
            id: r.id,
            rule_id: r.rule_id,
            subject: r.subject,
            message: r.message,
            value: r.value,
            raised_at: from_sql_time(&r.raised_at)?,
            resolved_at: r.resolved_at.as_deref().map(from_sql_time).transpose()?,
            notified: r.notified,
        })
    }
}

impl Db {
    // -----------------------------------------------------------------------
    // rules
    // -----------------------------------------------------------------------

    /// Every rule, enabled or not — the configuration screen's list.
    pub async fn alert_rules(&self) -> Result<Vec<AlertRule>> {
        let rows = sqlx::query_as::<_, AlertRuleRow>(
            "SELECT * FROM alert_rules ORDER BY kind ASC, COALESCE(target, '') ASC",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(AlertRule::try_from).collect()
    }

    /// The rules an evaluation pass should actually apply.
    pub async fn enabled_alert_rules(&self) -> Result<Vec<AlertRule>> {
        let rows = sqlx::query_as::<_, AlertRuleRow>(
            "SELECT * FROM alert_rules WHERE enabled = 1
             ORDER BY kind ASC, COALESCE(target, '') ASC",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(AlertRule::try_from).collect()
    }

    /// Create or update the rule for `(kind, target)`.
    ///
    /// Upsert rather than insert: `(kind, target)` is the rule's identity, so
    /// "watch disks at 85% instead of 90%" must edit the existing rule. Creating
    /// a second one would leave both live, and the operator would get two
    /// notifications for one full disk.
    pub async fn set_alert_rule(
        &self,
        kind: AlertKind,
        target: Option<&str>,
        threshold: f64,
        enabled: bool,
    ) -> Result<AlertRule> {
        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, AlertRuleRow>(
            "INSERT INTO alert_rules (kind, target, threshold, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT (kind, COALESCE(target, '')) DO UPDATE SET
                 threshold  = ?3,
                 enabled    = ?4,
                 updated_at = ?5
             RETURNING *",
        )
        .bind(kind.as_str())
        .bind(target)
        .bind(threshold)
        .bind(i64::from(enabled))
        .bind(&ts)
        .fetch_one(self.pool())
        .await?;
        AlertRule::try_from(row)
    }

    // -----------------------------------------------------------------------
    // events — the debounce state machine
    // -----------------------------------------------------------------------

    /// Open an event, unless one is already open for this `(rule, subject)`.
    ///
    /// `Ok(None)` means "already raised, say nothing" — the ordinary case for a
    /// condition that has been true for an hour. The uniqueness lives in the
    /// partial index `alert_events_open_uq`, so this is safe against two
    /// evaluation passes overlapping.
    pub async fn raise_alert(
        &self,
        rule_id: i64,
        subject: &str,
        message: &str,
        value: Option<f64>,
    ) -> Result<Option<AlertEvent>> {
        let row = sqlx::query_as::<_, AlertEventRow>(
            "INSERT INTO alert_events (rule_id, subject, message, value, raised_at, notified)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)
             ON CONFLICT (rule_id, subject) WHERE resolved_at IS NULL DO NOTHING
             RETURNING *",
        )
        .bind(rule_id)
        .bind(subject)
        .bind(message)
        .bind(value)
        .bind(to_sql_time(now()))
        .fetch_optional(self.pool())
        .await?;
        row.map(AlertEvent::try_from).transpose()
    }

    /// Close an open event. `Ok(None)` when it was already closed — again the
    /// benign case, and again it means "say nothing".
    pub async fn resolve_alert(&self, event_id: i64) -> Result<Option<AlertEvent>> {
        let row = sqlx::query_as::<_, AlertEventRow>(
            "UPDATE alert_events SET resolved_at = ?2
             WHERE id = ?1 AND resolved_at IS NULL
             RETURNING *",
        )
        .bind(event_id)
        .bind(to_sql_time(now()))
        .fetch_optional(self.pool())
        .await?;
        row.map(AlertEvent::try_from).transpose()
    }

    /// Everything currently happening.
    pub async fn open_alert_events(&self) -> Result<Vec<AlertEvent>> {
        let rows = sqlx::query_as::<_, AlertEventRow>(
            "SELECT * FROM alert_events WHERE resolved_at IS NULL ORDER BY raised_at ASC",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(AlertEvent::try_from).collect()
    }

    /// The history page: newest first, open events included.
    pub async fn recent_alert_events(&self, limit: i64) -> Result<Vec<AlertEvent>> {
        let rows = sqlx::query_as::<_, AlertEventRow>(
            "SELECT * FROM alert_events ORDER BY raised_at DESC, id DESC LIMIT ?1",
        )
        .bind(limit.clamp(1, 500))
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(AlertEvent::try_from).collect()
    }

    /// Record that a state-transition notification was delivered for this
    /// event. Counts rather than flags: a raise and a resolve are two separate
    /// deliveries against the same row.
    pub async fn mark_alert_notified(&self, event_id: i64) -> Result<()> {
        sqlx::query("UPDATE alert_events SET notified = notified + 1 WHERE id = ?1")
            .bind(event_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Delete resolved events older than `days`. Called from the same retention
    /// sweep as the audit log so the table cannot grow without bound.
    pub async fn purge_alert_events(&self, days: i64) -> Result<u64> {
        let cutoff = to_sql_time(now() - time::Duration::days(days.max(1)));
        let done = sqlx::query(
            "DELETE FROM alert_events WHERE resolved_at IS NOT NULL AND resolved_at < ?1",
        )
        .bind(cutoff)
        .execute(self.pool())
        .await?;
        Ok(done.rows_affected())
    }

    // -----------------------------------------------------------------------
    // inputs the evaluator needs that no other repository answers
    // -----------------------------------------------------------------------

    /// Every certificate the expiry rules should watch.
    ///
    /// Not [`Db::certificates_for`], which answers a different question: that
    /// one lists what a *tenant* may see, so it joins through `sites` and
    /// therefore drops the panel's own certificate (`site_id IS NULL`). For
    /// alerting that omission is exactly backwards — the panel's certificate
    /// expiring is the worst case of the lot, because it locks the operator out
    /// of the tool they would use to fix it (spec §11.5, §11.11).
    ///
    /// Only `active` rows: a superseded or failed certificate is history, and a
    /// warning about a file nginx no longer reads is noise.
    pub async fn certificates_for_alerting(&self) -> Result<Vec<crate::Certificate>> {
        let rows = sqlx::query_as::<_, crate::certificates::CertificateRow>(
            "SELECT * FROM certificates
             WHERE status = 'active' AND not_after IS NOT NULL
             ORDER BY not_after ASC",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(crate::Certificate::try_from).collect()
    }

    // -----------------------------------------------------------------------
    // channels
    // -----------------------------------------------------------------------

    pub async fn notify_channels(&self) -> Result<Vec<NotifyChannel>> {
        let rows =
            sqlx::query_as::<_, NotifyChannelRow>("SELECT * FROM notify_channels ORDER BY id ASC")
                .fetch_all(self.pool())
                .await?;
        rows.into_iter().map(NotifyChannel::try_from).collect()
    }

    pub async fn enabled_notify_channels(&self) -> Result<Vec<NotifyChannel>> {
        let rows = sqlx::query_as::<_, NotifyChannelRow>(
            "SELECT * FROM notify_channels WHERE enabled = 1 ORDER BY id ASC",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(NotifyChannel::try_from).collect()
    }

    pub async fn notify_channel(&self, id: i64) -> Result<Option<NotifyChannel>> {
        let row =
            sqlx::query_as::<_, NotifyChannelRow>("SELECT * FROM notify_channels WHERE id = ?1")
                .bind(id)
                .fetch_optional(self.pool())
                .await?;
        row.map(NotifyChannel::try_from).transpose()
    }

    /// Add a channel. `config_sealed` must already be sealed — this layer never
    /// sees plaintext, so there is no path by which it could log one.
    pub async fn create_notify_channel(
        &self,
        kind: ChannelKind,
        label: &str,
        config_sealed: &str,
        enabled: bool,
    ) -> Result<NotifyChannel> {
        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, NotifyChannelRow>(
            "INSERT INTO notify_channels (kind, label, config_sealed, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             RETURNING *",
        )
        .bind(kind.as_str())
        .bind(label)
        .bind(config_sealed)
        .bind(i64::from(enabled))
        .bind(&ts)
        .fetch_one(self.pool())
        .await
        .map_err(unique_label)?;
        NotifyChannel::try_from(row)
    }

    /// Edit a channel. `config_sealed = None` keeps the stored configuration —
    /// so an operator can rename or disable a Telegram channel without having to
    /// paste the bot token again (and without the UI ever holding it).
    pub async fn update_notify_channel(
        &self,
        id: i64,
        label: Option<&str>,
        config_sealed: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<NotifyChannel> {
        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, NotifyChannelRow>(
            "UPDATE notify_channels SET
                 label         = COALESCE(?2, label),
                 config_sealed = COALESCE(?3, config_sealed),
                 enabled       = COALESCE(?4, enabled),
                 updated_at    = ?5
             WHERE id = ?1
             RETURNING *",
        )
        .bind(id)
        .bind(label)
        .bind(config_sealed)
        .bind(enabled.map(i64::from))
        .bind(&ts)
        .fetch_optional(self.pool())
        .await
        .map_err(unique_label)?
        .ok_or(DbError::NotFound {
            what: "notify channel",
        })?;
        NotifyChannel::try_from(row)
    }

    pub async fn delete_notify_channel(&self, id: i64) -> Result<bool> {
        let done = sqlx::query("DELETE FROM notify_channels WHERE id = ?1")
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(done.rows_affected() > 0)
    }
}

/// Turn the label index's violation into the conflict the API should report,
/// rather than a generic internal error.
///
/// SQLite names the *column* in the message (`notify_channels.label`), not the
/// index, which is why the match is on that and not on `..._label_uq`. Same
/// shape as `users.rs::unique_violation`.
fn unique_label(e: sqlx::Error) -> DbError {
    if let sqlx::Error::Database(db) = &e
        && db.message().contains("UNIQUE constraint failed")
        && db.message().contains("notify_channels.label")
    {
        return DbError::Conflict {
            what: "a channel with that label",
        };
    }
    DbError::Sqlx(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> Db {
        Db::open_memory().await.unwrap()
    }

    #[tokio::test]
    async fn the_migration_seeds_the_three_default_rules_enabled() {
        // Spec §11.11: a fresh install is already watching the three things
        // that actually take servers down.
        let db = db().await;
        let rules = db.enabled_alert_rules().await.unwrap();

        let disk = rules
            .iter()
            .find(|r| r.kind == AlertKind::DiskPct)
            .expect("a disk rule");
        assert_eq!(disk.threshold, 90.0);
        assert_eq!(disk.target, None, "the default covers every filesystem");

        let cert = rules
            .iter()
            .find(|r| r.kind == AlertKind::CertExpiryDays)
            .expect("a certificate rule");
        assert_eq!(cert.threshold, 14.0);

        let svc = rules
            .iter()
            .find(|r| r.kind == AlertKind::ServiceDown)
            .expect("a service rule");
        assert_eq!(svc.target.as_deref(), Some("nginx"));

        assert!(rules.iter().all(|r| r.enabled));
    }

    #[tokio::test]
    async fn seeded_timestamps_parse_as_the_panels_own_format() {
        // `strftime` in the migration has to agree with `to_sql_time`, or every
        // read of a seeded row is a Corrupt error.
        let db = db().await;
        let rules = db.alert_rules().await.unwrap();
        assert!(!rules.is_empty());
        for rule in rules {
            assert_eq!(rule.created_at.offset(), time::UtcOffset::UTC);
        }
    }

    #[tokio::test]
    async fn a_rule_is_updated_in_place_rather_than_duplicated() {
        let db = db().await;
        let before = db.alert_rules().await.unwrap().len();

        let a = db
            .set_alert_rule(AlertKind::DiskPct, None, 85.0, true)
            .await
            .unwrap();
        let b = db
            .set_alert_rule(AlertKind::DiskPct, None, 80.0, false)
            .await
            .unwrap();

        assert_eq!(a.id, b.id, "same (kind, target) must be the same rule");
        assert_eq!(b.threshold, 80.0);
        assert!(!b.enabled);
        assert_eq!(db.alert_rules().await.unwrap().len(), before);
    }

    #[tokio::test]
    async fn rules_with_different_targets_are_different_rules() {
        let db = db().await;
        let a = db
            .set_alert_rule(AlertKind::ServiceDown, Some("nginx"), 1.0, true)
            .await
            .unwrap();
        let b = db
            .set_alert_rule(AlertKind::ServiceDown, Some("mariadb"), 1.0, true)
            .await
            .unwrap();
        assert_ne!(a.id, b.id);
        // ...and the nginx one is the seeded row, updated, not a new one.
        assert_eq!(
            db.alert_rules()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.kind == AlertKind::ServiceDown)
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn an_unknown_rule_kind_cannot_be_stored() {
        let db = db().await;
        let err = sqlx::query(
            "INSERT INTO alert_rules (kind, threshold, enabled, created_at, updated_at)
             VALUES ('rm_rf_slash', 1.0, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .execute(db.pool())
        .await;
        assert!(
            err.is_err(),
            "the CHECK constraint must hold in storage too"
        );
    }

    #[tokio::test]
    async fn raising_the_same_alert_twice_only_opens_one_event() {
        // The heart of the debounce: a condition that stays true says nothing
        // after the first time.
        let db = db().await;
        let rule = db
            .set_alert_rule(AlertKind::DiskPct, None, 90.0, true)
            .await
            .unwrap();

        let first = db
            .raise_alert(rule.id, "/", "disk / at 91%", Some(91.0))
            .await
            .unwrap();
        assert!(first.is_some());

        for _ in 0..20 {
            assert!(
                db.raise_alert(rule.id, "/", "disk / at 91%", Some(91.0))
                    .await
                    .unwrap()
                    .is_none(),
                "an already-open event must not be raised again"
            );
        }
        assert_eq!(db.open_alert_events().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn two_subjects_of_one_rule_get_their_own_events() {
        // Without a per-subject key, a second filesystem filling up would be
        // swallowed by the first one's debounce.
        let db = db().await;
        let rule = db
            .set_alert_rule(AlertKind::DiskPct, None, 90.0, true)
            .await
            .unwrap();

        assert!(
            db.raise_alert(rule.id, "/", "a", None)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            db.raise_alert(rule.id, "/var", "b", None)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(db.open_alert_events().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn resolving_closes_the_event_once_and_reopening_is_then_allowed() {
        let db = db().await;
        let rule = db
            .set_alert_rule(AlertKind::DiskPct, None, 90.0, true)
            .await
            .unwrap();
        let event = db
            .raise_alert(rule.id, "/", "full", Some(95.0))
            .await
            .unwrap()
            .unwrap();

        assert!(db.resolve_alert(event.id).await.unwrap().is_some());
        assert!(
            db.resolve_alert(event.id).await.unwrap().is_none(),
            "a second resolve must not produce a second message"
        );
        assert!(db.open_alert_events().await.unwrap().is_empty());

        // The condition can come back — and that is a new event, not a revival.
        let again = db
            .raise_alert(rule.id, "/", "full again", Some(96.0))
            .await
            .unwrap()
            .expect("a resolved event no longer blocks a new raise");
        assert_ne!(again.id, event.id);
    }

    #[tokio::test]
    async fn deleting_a_rule_takes_its_events_with_it() {
        let db = db().await;
        let rule = db
            .set_alert_rule(AlertKind::MemPct, None, 95.0, true)
            .await
            .unwrap();
        db.raise_alert(rule.id, "memory", "tight", Some(96.0))
            .await
            .unwrap();

        sqlx::query("DELETE FROM alert_rules WHERE id = ?1")
            .bind(rule.id)
            .execute(db.pool())
            .await
            .unwrap();
        assert!(db.open_alert_events().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn notification_deliveries_are_counted_per_event() {
        let db = db().await;
        let rule = db
            .set_alert_rule(AlertKind::Load, None, 8.0, true)
            .await
            .unwrap();
        let event = db
            .raise_alert(rule.id, "load", "busy", Some(9.0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.notified, 0);

        db.mark_alert_notified(event.id).await.unwrap();
        db.mark_alert_notified(event.id).await.unwrap();
        let latest = db.recent_alert_events(10).await.unwrap();
        assert_eq!(latest[0].notified, 2, "one raise plus one resolve");
    }

    #[tokio::test]
    async fn retention_removes_resolved_events_and_keeps_open_ones() {
        let db = db().await;
        let rule = db
            .set_alert_rule(AlertKind::Load, None, 8.0, true)
            .await
            .unwrap();
        let old = db
            .raise_alert(rule.id, "load", "busy", None)
            .await
            .unwrap()
            .unwrap();
        db.resolve_alert(old.id).await.unwrap();
        sqlx::query("UPDATE alert_events SET resolved_at = '2020-01-01T00:00:00Z' WHERE id = ?1")
            .bind(old.id)
            .execute(db.pool())
            .await
            .unwrap();

        let still_open = db
            .raise_alert(rule.id, "load", "busy again", None)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(db.purge_alert_events(30).await.unwrap(), 1);
        let left = db.recent_alert_events(10).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, still_open.id);
    }

    #[tokio::test]
    async fn certificate_alerting_sees_the_panels_own_certificate() {
        // `certificates_for` joins through sites and would miss this row —
        // which is the one whose expiry locks the operator out of the panel.
        let db = db().await;
        let cert = db
            .create_certificate(
                None,
                crate::CertKind::Le,
                &["panel.example.com".to_string()],
                "/etc/unihelm/certs/panel.example.com",
            )
            .await
            .unwrap();
        let t = now();
        db.certificate_issued(cert.id, "Test CA", t, t + time::Duration::days(3))
            .await
            .unwrap();

        let watched = db.certificates_for_alerting().await.unwrap();
        assert_eq!(watched.len(), 1);
        assert_eq!(watched[0].domains, vec!["panel.example.com".to_string()]);
        assert_eq!(
            db.certificates_for(&unihelm_core::TenantScope::Global)
                .await
                .unwrap()
                .len(),
            0,
            "the tenant-visibility query really does omit it"
        );
    }

    #[tokio::test]
    async fn certificate_alerting_ignores_rows_that_are_not_being_served() {
        let db = db().await;
        // A pending row: requested, never issued.
        db.create_certificate(None, crate::CertKind::Le, &["a.test".into()], "/tmp/a")
            .await
            .unwrap();
        // A failed one.
        let failed = db
            .create_certificate(None, crate::CertKind::Le, &["b.test".into()], "/tmp/b")
            .await
            .unwrap();
        db.certificate_failed(failed.id, "dns did not resolve")
            .await
            .unwrap();

        assert!(db.certificates_for_alerting().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_channels_sealed_config_never_leaves_through_serde() {
        // `alert.channels.list` serialises this struct straight into an API
        // response; a ciphertext in that response is a ciphertext an attacker
        // can take home.
        let db = db().await;
        let channel = db
            .create_notify_channel(ChannelKind::Telegram, "ops room", "deadbeefcafe", true)
            .await
            .unwrap();
        assert_eq!(channel.config_sealed, "deadbeefcafe");

        let json = serde_json::to_string(&channel).unwrap();
        assert!(!json.contains("deadbeef"), "{json}");
        assert!(!json.contains("config_sealed"), "{json}");
        assert!(json.contains("ops room"));
    }

    #[tokio::test]
    async fn two_channels_cannot_share_a_label() {
        let db = db().await;
        db.create_notify_channel(ChannelKind::Webhook, "ops", "aa", true)
            .await
            .unwrap();
        let err = db
            .create_notify_channel(ChannelKind::Webhook, "ops", "bb", true)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DbError::Conflict { .. }),
            "expected a conflict, got {err:?}"
        );
    }

    #[tokio::test]
    async fn updating_a_channel_without_a_config_keeps_the_stored_secret() {
        let db = db().await;
        let channel = db
            .create_notify_channel(ChannelKind::Telegram, "ops", "sealed-token", true)
            .await
            .unwrap();

        let renamed = db
            .update_notify_channel(channel.id, Some("night shift"), None, Some(false))
            .await
            .unwrap();
        assert_eq!(renamed.label, "night shift");
        assert!(!renamed.enabled);
        assert_eq!(
            renamed.config_sealed, "sealed-token",
            "renaming must not require re-entering the credential"
        );
        assert!(db.enabled_notify_channels().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn updating_a_channel_that_does_not_exist_is_not_found() {
        let db = db().await;
        let err = db
            .update_notify_channel(4242, Some("x"), None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::NotFound { .. }), "{err:?}");
        assert!(!db.delete_notify_channel(4242).await.unwrap());
    }
}
