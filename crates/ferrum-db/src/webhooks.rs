//! Outbound webhooks and their delivery queue (spec §9, §2.4, §14 Phase 6).
//!
//! Two tables and one rule that shapes both of them: **the queue is durable and
//! bounded**. Durable because the agent restarts, and a "backup failed" message
//! that only existed in a process is a message nobody ever receives; bounded
//! because a dead endpoint must not be able to turn a retry policy into an
//! unbounded queue (spec §14 Phase 6 asks for webhooks *maturity*, and this is
//! what separates a mature one from a `tokio::spawn` in a loop).
//!
//! The interesting decisions live one level up in `ferrum_ops::webhook` — the
//! signature scheme, the backoff curve, the failure threshold — because they
//! are about what a receiver can verify, not about storage. What this module
//! owns is that a caller only ever reaches the hooks their [`TenantScope`] can
//! see, and that the secret never leaves it in the clear.

use ferrum_core::{TenantScope, UserId};
use serde::Serialize;

use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// How many hooks one account may register.
///
/// Not a plan limit — a sanity bound. Every hook multiplies every event by one
/// more HTTP request, so the fan-out of a single `site.created` is exactly this
/// number in the worst case, and an unbounded fan-out is a way to make the
/// panel attack something on an attacker's behalf.
pub const MAX_HOOKS_PER_OWNER: i64 = 20;

/// A registered endpoint.
///
/// Note what is **not** `Serialize`d: the sealed secret. Serialising it would
/// put a signing key in an API response, a log line and a task record, and the
/// only moment a secret is ever shown is when `webhook.set` mints one.
#[derive(Debug, Clone, Serialize)]
pub struct Webhook {
    pub id: i64,
    pub owner_user_id: UserId,
    pub url: String,
    /// Still sealed. Open it with [`crate::MasterKey`].
    #[serde(skip)]
    pub secret_sealed: String,
    /// Event names this hook wants. `["*"]` means every event.
    pub events: Vec<String>,
    pub active: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_delivery_at: Option<time::OffsetDateTime>,
    pub last_status: Option<i64>,
    /// Consecutive failures; any 2xx resets it to zero.
    pub failure_count: i64,
    /// Why the panel switched this hook off, or `None`.
    pub disabled_reason: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebhookRow {
    pub id: i64,
    pub owner_user_id: i64,
    pub url: String,
    pub secret_sealed: String,
    pub events_json: String,
    pub active: i64,
    pub last_delivery_at: Option<String>,
    pub last_status: Option<i64>,
    pub failure_count: i64,
    pub disabled_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<WebhookRow> for Webhook {
    type Error = DbError;

    fn try_from(r: WebhookRow) -> Result<Self> {
        let events: Vec<String> =
            serde_json::from_str(&r.events_json).map_err(|e| DbError::Corrupt {
                field: "webhooks.events_json",
                detail: e.to_string(),
            })?;
        Ok(Webhook {
            id: r.id,
            owner_user_id: UserId(r.owner_user_id),
            url: r.url,
            secret_sealed: r.secret_sealed,
            events,
            active: r.active != 0,
            last_delivery_at: r
                .last_delivery_at
                .as_deref()
                .map(from_sql_time)
                .transpose()?,
            last_status: r.last_status,
            failure_count: r.failure_count,
            disabled_reason: r.disabled_reason,
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

/// A hook to create. Every field is already validated by the operation layer;
/// `secret_sealed` arrives sealed and is never opened here.
#[derive(Debug, Clone)]
pub struct NewWebhook {
    pub owner_user_id: UserId,
    pub url: String,
    pub secret_sealed: String,
    pub events: Vec<String>,
    pub active: bool,
}

/// One queued POST.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookDelivery {
    pub id: i64,
    pub webhook_id: i64,
    pub event: String,
    /// The exact bytes that were signed. Frozen at emit time so a retry is a
    /// redelivery rather than a fresh message wearing the same name.
    pub payload_json: String,
    pub attempts: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub next_attempt_at: time::OffsetDateTime,
    pub status: String,
    pub last_error: Option<String>,
    pub response_status: Option<i64>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebhookDeliveryRow {
    pub id: i64,
    pub webhook_id: i64,
    pub event: String,
    pub payload_json: String,
    pub attempts: i64,
    pub next_attempt_at: String,
    pub status: String,
    pub last_error: Option<String>,
    pub response_status: Option<i64>,
    pub created_at: String,
    #[allow(dead_code)]
    pub updated_at: String,
}

impl TryFrom<WebhookDeliveryRow> for WebhookDelivery {
    type Error = DbError;

    fn try_from(r: WebhookDeliveryRow) -> Result<Self> {
        Ok(WebhookDelivery {
            id: r.id,
            webhook_id: r.webhook_id,
            event: r.event,
            payload_json: r.payload_json,
            attempts: r.attempts,
            next_attempt_at: from_sql_time(&r.next_attempt_at)?,
            status: r.status,
            last_error: r.last_error,
            response_status: r.response_status,
            created_at: from_sql_time(&r.created_at)?,
        })
    }
}

/// A due delivery joined to everything sending it needs.
///
/// One row rather than a delivery plus a second lookup, because the delivery
/// loop reads a batch and a per-row second query is the shape that turns a
/// backlog into an N+1.
#[derive(Debug, Clone)]
pub struct DueDelivery {
    pub delivery: WebhookDelivery,
    pub url: String,
    /// Still sealed.
    pub secret_sealed: String,
    pub owner_user_id: UserId,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct DueDeliveryRow {
    #[sqlx(flatten)]
    delivery: WebhookDeliveryRow,
    url: String,
    secret_sealed: String,
    owner_user_id: i64,
}

pub struct WebhookRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn webhooks(&self, scope: &TenantScope) -> WebhookRepo<'_> {
        WebhookRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }
}

impl WebhookRepo<'_> {
    /// Hooks this scope can see.
    ///
    /// The scope resolves through `users.reseller_id`, exactly as the user
    /// repository does: an admin sees everything, a reseller sees its own hooks
    /// and its customers', a customer sees only its own. A hook belonging to
    /// somebody else is not "empty" — it is invisible, and the operations built
    /// on this answer `not_found` for it.
    pub async fn list(&self) -> Result<Vec<Webhook>> {
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, WebhookRow>("SELECT * FROM webhooks ORDER BY id DESC")
                    .fetch_all(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, WebhookRow>(
                    "SELECT w.* FROM webhooks w
                     JOIN users u ON u.id = w.owner_user_id
                     WHERE u.reseller_id = ?1 OR u.id = ?1
                     ORDER BY w.id DESC",
                )
                .bind(reseller_id)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) | ScopeFilter::Subscription { customer_id, .. } => {
                sqlx::query_as::<_, WebhookRow>(
                    "SELECT * FROM webhooks WHERE owner_user_id = ?1 ORDER BY id DESC",
                )
                .bind(customer_id)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(Webhook::try_from).collect()
    }

    /// One hook, if this scope can see it.
    pub async fn by_id(&self, id: i64) -> Result<Option<Webhook>> {
        let rows = self.list().await?;
        Ok(rows.into_iter().find(|w| w.id == id))
    }

    /// Create a hook, refusing past [`MAX_HOOKS_PER_OWNER`].
    ///
    /// The cap is enforced inside the INSERT rather than as a read-then-write,
    /// so two concurrent creates cannot both see "19 hooks" and both insert.
    pub async fn create(&self, new: NewWebhook) -> Result<Webhook> {
        let ts = to_sql_time(now());
        let events_json = serde_json::to_string(&new.events).map_err(|e| DbError::Corrupt {
            field: "webhooks.events_json",
            detail: e.to_string(),
        })?;

        let row = sqlx::query_as::<_, WebhookRow>(
            "INSERT INTO webhooks
                 (owner_user_id, url, secret_sealed, events_json, active,
                  failure_count, created_at, updated_at)
             SELECT ?1, ?2, ?3, ?4, ?5, 0, ?6, ?6
             WHERE (SELECT COUNT(*) FROM webhooks WHERE owner_user_id = ?1) < ?7
             RETURNING *",
        )
        .bind(new.owner_user_id.get())
        .bind(&new.url)
        .bind(&new.secret_sealed)
        .bind(&events_json)
        .bind(i64::from(new.active))
        .bind(&ts)
        .bind(MAX_HOOKS_PER_OWNER)
        .fetch_optional(self.db.pool())
        .await?;

        // A `WHERE` that excludes every candidate row inserts nothing and
        // returns nothing — which is the cap, not a missing account.
        row.ok_or(DbError::Conflict {
            what: "webhook (this account is at its hook limit)",
        })
        .and_then(Webhook::try_from)
    }

    /// Replace a hook's URL, event list and active flag.
    ///
    /// Re-enabling clears the failure bookkeeping. That is the point of the
    /// verb: an operator who fixed their endpoint and switched the hook back on
    /// has said the previous failures are history, and leaving the counter at
    /// its threshold would disable the hook again on the first hiccup.
    pub async fn update(
        &self,
        id: i64,
        url: &str,
        events: &[String],
        active: bool,
        secret_sealed: Option<&str>,
    ) -> Result<Webhook> {
        // Scope first: a hook this caller cannot see must not be updatable by
        // guessing its id.
        if self.by_id(id).await?.is_none() {
            return Err(DbError::NotFound { what: "webhook" });
        }
        let ts = to_sql_time(now());
        let events_json = serde_json::to_string(events).map_err(|e| DbError::Corrupt {
            field: "webhooks.events_json",
            detail: e.to_string(),
        })?;

        let row = match secret_sealed {
            Some(secret) => {
                sqlx::query_as::<_, WebhookRow>(
                    "UPDATE webhooks SET url = ?2, events_json = ?3, active = ?4,
                         secret_sealed = ?5, failure_count = 0, disabled_reason = NULL,
                         updated_at = ?6
                     WHERE id = ?1 RETURNING *",
                )
                .bind(id)
                .bind(url)
                .bind(&events_json)
                .bind(i64::from(active))
                .bind(secret)
                .bind(&ts)
                .fetch_optional(self.db.pool())
                .await?
            }
            None => {
                sqlx::query_as::<_, WebhookRow>(
                    "UPDATE webhooks SET url = ?2, events_json = ?3, active = ?4,
                         failure_count = 0, disabled_reason = NULL, updated_at = ?5
                     WHERE id = ?1 RETURNING *",
                )
                .bind(id)
                .bind(url)
                .bind(&events_json)
                .bind(i64::from(active))
                .bind(&ts)
                .fetch_optional(self.db.pool())
                .await?
            }
        };

        row.ok_or(DbError::NotFound { what: "webhook" })
            .and_then(Webhook::try_from)
    }

    /// Delete a hook and, by cascade, everything still queued for it.
    pub async fn delete(&self, id: i64) -> Result<()> {
        if self.by_id(id).await?.is_none() {
            return Err(DbError::NotFound { what: "webhook" });
        }
        sqlx::query("DELETE FROM webhooks WHERE id = ?1")
            .bind(id)
            .execute(self.db.pool())
            .await?;
        Ok(())
    }
}

impl Db {
    /// Every active hook subscribed to `event`.
    ///
    /// Deliberately unscoped: the fan-out runs under the system identity from
    /// inside the agent, and an event that only reached the hooks of whoever
    /// happened to trigger it would be a silently partial notification. The
    /// *payload* is what carries tenant information, and the operations that
    /// emit choose what goes in it.
    ///
    /// Matching is exact or `*`. No prefix globbing: `site.*` reads as
    /// "everything about sites" to a human and as an invitation to
    /// accidentally subscribe to a future event to a program, and a receiver
    /// that gets an event it has never seen is a receiver that breaks.
    pub async fn webhooks_subscribed_to(&self, event: &str) -> Result<Vec<Webhook>> {
        let rows = sqlx::query_as::<_, WebhookRow>("SELECT * FROM webhooks WHERE active = 1")
            .fetch_all(self.pool())
            .await?;
        let hooks: Vec<Webhook> = rows
            .into_iter()
            .map(Webhook::try_from)
            .collect::<Result<Vec<_>>>()?;
        Ok(hooks
            .into_iter()
            .filter(|h| h.events.iter().any(|e| e == "*" || e == event))
            .collect())
    }

    /// Queue one POST. Returns the delivery id, which travels in the
    /// `X-Ferrum-Delivery` header and is what a receiver de-duplicates on.
    pub async fn enqueue_delivery(
        &self,
        webhook_id: i64,
        event: &str,
        payload_json: &str,
        due_at: time::OffsetDateTime,
    ) -> Result<i64> {
        let ts = to_sql_time(now());
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO webhook_deliveries
                 (webhook_id, event, payload_json, attempts, next_attempt_at,
                  status, created_at, updated_at)
             VALUES (?1, ?2, ?3, 0, ?4, 'pending', ?5, ?5)
             RETURNING id",
        )
        .bind(webhook_id)
        .bind(event)
        .bind(payload_json)
        .bind(to_sql_time(due_at))
        .bind(&ts)
        .fetch_one(self.pool())
        .await?;
        Ok(row.0)
    }

    /// Rewrite a queued delivery's body, before it has ever been sent.
    ///
    /// The one caller is the emitter, which needs the row's own id *inside*
    /// the payload so a receiver that logs only bodies can still de-duplicate —
    /// and the id does not exist until the insert has happened. Guarded on
    /// `attempts = 0` so this can never rewrite a body somebody has already
    /// received and verified a signature over.
    pub async fn set_delivery_payload(&self, delivery_id: i64, payload_json: &str) -> Result<()> {
        sqlx::query(
            "UPDATE webhook_deliveries SET payload_json = ?2, updated_at = ?3
             WHERE id = ?1 AND attempts = 0 AND status = 'pending'",
        )
        .bind(delivery_id)
        .bind(payload_json)
        .bind(to_sql_time(now()))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Record the outcome of a `webhook.test` probe on the hook itself.
    ///
    /// A probe has no delivery row — it is not queued and is never retried —
    /// but it *is* a real POST to a real endpoint, so it moves the same
    /// bookkeeping a queued delivery would: a success clears the failure
    /// streak, a failure extends it. Testing a hook twenty times against a dead
    /// host teaches the panel exactly what twenty failed deliveries would.
    pub async fn set_webhook_probe_result(
        &self,
        webhook_id: i64,
        status: Option<i64>,
        ok: bool,
    ) -> Result<()> {
        let ts = to_sql_time(now());
        if ok {
            sqlx::query(
                "UPDATE webhooks SET failure_count = 0, last_delivery_at = ?2,
                     last_status = ?3, updated_at = ?2
                 WHERE id = ?1",
            )
            .bind(webhook_id)
            .bind(&ts)
            .bind(status)
            .execute(self.pool())
            .await?;
        } else {
            sqlx::query(
                "UPDATE webhooks SET failure_count = failure_count + 1,
                     last_delivery_at = ?2, last_status = ?3, updated_at = ?2
                 WHERE id = ?1",
            )
            .bind(webhook_id)
            .bind(&ts)
            .bind(status)
            .execute(self.pool())
            .await?;
        }
        Ok(())
    }

    /// Pending deliveries whose time has come, oldest first.
    ///
    /// `limit` bounds one tick's work: a panel that comes back from an outage
    /// with a thousand queued deliveries drains them over several ticks rather
    /// than opening a thousand connections in one.
    pub async fn due_deliveries(&self, limit: i64) -> Result<Vec<DueDelivery>> {
        let rows = sqlx::query_as::<_, DueDeliveryRow>(
            "SELECT d.*, w.url AS url, w.secret_sealed AS secret_sealed,
                    w.owner_user_id AS owner_user_id
             FROM webhook_deliveries d
             JOIN webhooks w ON w.id = d.webhook_id
             WHERE d.status = 'pending' AND d.next_attempt_at <= ?1 AND w.active = 1
             ORDER BY d.next_attempt_at ASC, d.id ASC
             LIMIT ?2",
        )
        .bind(to_sql_time(now()))
        .bind(limit)
        .fetch_all(self.pool())
        .await?;

        rows.into_iter()
            .map(|r| {
                Ok(DueDelivery {
                    delivery: WebhookDelivery::try_from(r.delivery)?,
                    url: r.url,
                    secret_sealed: r.secret_sealed,
                    owner_user_id: UserId(r.owner_user_id),
                })
            })
            .collect()
    }

    /// Record a successful delivery and clear the hook's failure streak.
    pub async fn delivery_succeeded(
        &self,
        delivery_id: i64,
        webhook_id: i64,
        status: u16,
    ) -> Result<()> {
        let ts = to_sql_time(now());
        let mut tx = self.begin().await?;
        sqlx::query(
            "UPDATE webhook_deliveries
             SET status = 'delivered', attempts = attempts + 1, response_status = ?2,
                 last_error = NULL, updated_at = ?3
             WHERE id = ?1",
        )
        .bind(delivery_id)
        .bind(i64::from(status))
        .bind(&ts)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE webhooks
             SET failure_count = 0, last_delivery_at = ?2, last_status = ?3, updated_at = ?2
             WHERE id = ?1",
        )
        .bind(webhook_id)
        .bind(&ts)
        .bind(i64::from(status))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Record a failed attempt.
    ///
    /// `retry_at` of `None` means the delivery has exhausted its attempts and
    /// is terminal. The hook's consecutive-failure counter goes up either way —
    /// it counts attempts that did not land, and a delivery that gave up counts
    /// once, not once per attempt, because each attempt already counted.
    pub async fn delivery_failed(
        &self,
        delivery_id: i64,
        webhook_id: i64,
        error: &str,
        status: Option<u16>,
        retry_at: Option<time::OffsetDateTime>,
    ) -> Result<i64> {
        let ts = to_sql_time(now());
        // The error is a remote endpoint's words. Bound it before it becomes a
        // database row somebody has to read.
        let error: String = error.chars().take(500).collect();

        let mut tx = self.begin().await?;
        match retry_at {
            Some(at) => {
                sqlx::query(
                    "UPDATE webhook_deliveries
                     SET attempts = attempts + 1, next_attempt_at = ?2, last_error = ?3,
                         response_status = ?4, updated_at = ?5
                     WHERE id = ?1",
                )
                .bind(delivery_id)
                .bind(to_sql_time(at))
                .bind(&error)
                .bind(status.map(i64::from))
                .bind(&ts)
                .execute(&mut *tx)
                .await?;
            }
            None => {
                sqlx::query(
                    "UPDATE webhook_deliveries
                     SET status = 'failed', attempts = attempts + 1, last_error = ?2,
                         response_status = ?3, updated_at = ?4
                     WHERE id = ?1",
                )
                .bind(delivery_id)
                .bind(&error)
                .bind(status.map(i64::from))
                .bind(&ts)
                .execute(&mut *tx)
                .await?;
            }
        }

        let row: (i64,) = sqlx::query_as(
            "UPDATE webhooks
             SET failure_count = failure_count + 1, last_delivery_at = ?2,
                 last_status = ?3, updated_at = ?2
             WHERE id = ?1
             RETURNING failure_count",
        )
        .bind(webhook_id)
        .bind(&ts)
        .bind(status.map(i64::from))
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.0)
    }

    /// Switch a hook off with a reason, and abandon everything still queued for
    /// it.
    ///
    /// Abandoning the queue is the whole point: leaving the rows pending would
    /// mean that re-enabling a hook months later replays a flood of stale
    /// events at an endpoint that has moved on.
    pub async fn disable_webhook(&self, webhook_id: i64, reason: &str) -> Result<()> {
        let ts = to_sql_time(now());
        let mut tx = self.begin().await?;
        sqlx::query(
            "UPDATE webhooks SET active = 0, disabled_reason = ?2, updated_at = ?3 WHERE id = ?1",
        )
        .bind(webhook_id)
        .bind(reason)
        .bind(&ts)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE webhook_deliveries
             SET status = 'failed', last_error = ?2, updated_at = ?3
             WHERE webhook_id = ?1 AND status = 'pending'",
        )
        .bind(webhook_id)
        .bind(reason)
        .bind(&ts)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The most recent deliveries for one hook, for the "why is this failing"
    /// view.
    pub async fn recent_deliveries(
        &self,
        webhook_id: i64,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>> {
        let rows = sqlx::query_as::<_, WebhookDeliveryRow>(
            "SELECT * FROM webhook_deliveries WHERE webhook_id = ?1
             ORDER BY id DESC LIMIT ?2",
        )
        .bind(webhook_id)
        .bind(limit)
        .fetch_all(self.pool())
        .await?;
        rows.into_iter().map(WebhookDelivery::try_from).collect()
    }

    /// Drop terminal deliveries older than `days`.
    ///
    /// The queue is a queue, not a history: without this, a panel that has been
    /// up for two years is still carrying the delivered rows of its first week.
    pub async fn purge_deliveries(&self, days: i64) -> Result<u64> {
        let cutoff = to_sql_time(now() - time::Duration::days(days.max(1)));
        let result = sqlx::query(
            "DELETE FROM webhook_deliveries
             WHERE status IN ('delivered', 'failed') AND updated_at < ?1",
        )
        .bind(cutoff)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::NewUser;
    use ferrum_core::{Email, Role, Username};

    async fn seed() -> (Db, UserId, UserId) {
        let db = Db::open_memory().await.unwrap();
        let mk = |name: &str, role: Role, reseller: Option<UserId>| NewUser {
            role,
            email: Email::parse(&format!("{name}@example.com")).unwrap(),
            username: Username::parse(name).unwrap(),
            password: "a-long-enough-password".into(),
            reseller_id: reseller,
            full_name: None,
            locale: "en".into(),
        };
        let reseller = db
            .users(&TenantScope::Global)
            .create(mk("agency", Role::Reseller, None))
            .await
            .unwrap();
        let customer = db
            .users(&TenantScope::Global)
            .create(mk("client", Role::Customer, Some(reseller.id)))
            .await
            .unwrap();
        (db, reseller.id, customer.id)
    }

    fn new_hook(owner: UserId, events: &[&str]) -> NewWebhook {
        NewWebhook {
            owner_user_id: owner,
            url: "https://example.com/hook".into(),
            secret_sealed: "sealed-placeholder".into(),
            events: events.iter().map(|e| (*e).to_string()).collect(),
            active: true,
        }
    }

    #[tokio::test]
    async fn a_customer_cannot_see_another_accounts_webhook() {
        let (db, reseller, customer) = seed().await;
        let theirs = db
            .webhooks(&TenantScope::Global)
            .create(new_hook(reseller, &["*"]))
            .await
            .unwrap();

        let scoped = db.webhooks(&TenantScope::Customer {
            customer_id: customer,
        });
        assert!(scoped.list().await.unwrap().is_empty());
        assert!(scoped.by_id(theirs.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_customer_cannot_update_or_delete_a_hook_it_cannot_see() {
        let (db, reseller, customer) = seed().await;
        let theirs = db
            .webhooks(&TenantScope::Global)
            .create(new_hook(reseller, &["*"]))
            .await
            .unwrap();

        let scoped = db.webhooks(&TenantScope::Customer {
            customer_id: customer,
        });
        // Guessing the id must not be a way in: both verbs resolve through the
        // scope before they touch the row.
        assert!(matches!(
            scoped
                .update(theirs.id, "https://evil.example/x", &[], true, None)
                .await,
            Err(DbError::NotFound { .. })
        ));
        assert!(matches!(
            scoped.delete(theirs.id).await,
            Err(DbError::NotFound { .. })
        ));
        // And the row is untouched.
        let after = db
            .webhooks(&TenantScope::Global)
            .by_id(theirs.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.url, "https://example.com/hook");
    }

    #[tokio::test]
    async fn a_reseller_sees_its_customers_hooks_but_not_a_strangers() {
        let (db, reseller, customer) = seed().await;
        let stranger = db
            .users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Customer,
                email: Email::parse("outsider@example.com").unwrap(),
                username: Username::parse("outsider").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();

        let global = db.webhooks(&TenantScope::Global);
        global.create(new_hook(customer, &["*"])).await.unwrap();
        global.create(new_hook(stranger.id, &["*"])).await.unwrap();

        let seen = db
            .webhooks(&TenantScope::Reseller {
                reseller_id: reseller,
            })
            .list()
            .await
            .unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].owner_user_id, customer);
    }

    #[tokio::test]
    async fn the_signing_secret_is_never_serialised() {
        let (db, reseller, _) = seed().await;
        let hook = db
            .webhooks(&TenantScope::Global)
            .create(new_hook(reseller, &["*"]))
            .await
            .unwrap();
        let json = serde_json::to_string(&hook).unwrap();
        assert!(
            !json.contains("sealed-placeholder") && !json.contains("secret"),
            "a webhook must not carry its signing key into an API response: {json}"
        );
    }

    #[tokio::test]
    async fn an_owner_cannot_register_more_hooks_than_the_cap() {
        let (db, reseller, _) = seed().await;
        let repo = db.webhooks(&TenantScope::Global);
        for _ in 0..MAX_HOOKS_PER_OWNER {
            repo.create(new_hook(reseller, &["*"])).await.unwrap();
        }
        assert!(matches!(
            repo.create(new_hook(reseller, &["*"])).await,
            Err(DbError::Conflict { .. })
        ));
    }

    #[tokio::test]
    async fn only_subscribed_and_active_hooks_are_selected_for_an_event() {
        let (db, reseller, customer) = seed().await;
        let repo = db.webhooks(&TenantScope::Global);
        let wildcard = repo.create(new_hook(reseller, &["*"])).await.unwrap();
        let exact = repo
            .create(new_hook(customer, &["site.created"]))
            .await
            .unwrap();
        let other = repo
            .create(new_hook(customer, &["backup.failed"]))
            .await
            .unwrap();
        let inactive = repo.create(new_hook(customer, &["*"])).await.unwrap();
        repo.update(inactive.id, &inactive.url, &["*".into()], false, None)
            .await
            .unwrap();

        let chosen: Vec<i64> = db
            .webhooks_subscribed_to("site.created")
            .await
            .unwrap()
            .into_iter()
            .map(|h| h.id)
            .collect();
        assert!(chosen.contains(&wildcard.id));
        assert!(chosen.contains(&exact.id));
        assert!(!chosen.contains(&other.id));
        assert!(
            !chosen.contains(&inactive.id),
            "an inactive hook is not a subscriber"
        );
    }

    /// The prefix a human would expect to work must not silently work: a hook
    /// asking for `site.*` gets nothing, which is visible, rather than getting
    /// future events it has never been tested against.
    #[tokio::test]
    async fn a_glob_that_is_not_a_bare_star_matches_nothing() {
        let (db, reseller, _) = seed().await;
        db.webhooks(&TenantScope::Global)
            .create(new_hook(reseller, &["site.*"]))
            .await
            .unwrap();
        assert!(
            db.webhooks_subscribed_to("site.created")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_success_clears_the_failure_streak() {
        let (db, reseller, _) = seed().await;
        let hook = db
            .webhooks(&TenantScope::Global)
            .create(new_hook(reseller, &["*"]))
            .await
            .unwrap();
        let d1 = db
            .enqueue_delivery(hook.id, "site.created", "{}", now())
            .await
            .unwrap();

        let streak = db
            .delivery_failed(d1, hook.id, "connection refused", None, Some(now()))
            .await
            .unwrap();
        assert_eq!(streak, 1);

        let d2 = db
            .enqueue_delivery(hook.id, "site.created", "{}", now())
            .await
            .unwrap();
        db.delivery_succeeded(d2, hook.id, 200).await.unwrap();

        let after = db
            .webhooks(&TenantScope::Global)
            .by_id(hook.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.failure_count, 0);
        assert_eq!(after.last_status, Some(200));
    }

    #[tokio::test]
    async fn disabling_a_hook_abandons_everything_still_queued_for_it() {
        let (db, reseller, _) = seed().await;
        let hook = db
            .webhooks(&TenantScope::Global)
            .create(new_hook(reseller, &["*"]))
            .await
            .unwrap();
        for _ in 0..3 {
            db.enqueue_delivery(hook.id, "site.created", "{}", now())
                .await
                .unwrap();
        }

        db.disable_webhook(hook.id, "too many consecutive failures")
            .await
            .unwrap();

        assert!(
            db.due_deliveries(50).await.unwrap().is_empty(),
            "a disabled hook must not keep a retry queue alive"
        );
        let history = db.recent_deliveries(hook.id, 10).await.unwrap();
        assert!(history.iter().all(|d| d.status == "failed"));
    }

    #[tokio::test]
    async fn a_future_delivery_is_not_due_yet() {
        let (db, reseller, _) = seed().await;
        let hook = db
            .webhooks(&TenantScope::Global)
            .create(new_hook(reseller, &["*"]))
            .await
            .unwrap();
        db.enqueue_delivery(
            hook.id,
            "site.created",
            "{}",
            now() + time::Duration::minutes(5),
        )
        .await
        .unwrap();
        assert!(db.due_deliveries(50).await.unwrap().is_empty());

        db.enqueue_delivery(hook.id, "site.created", "{}", now())
            .await
            .unwrap();
        let due = db.due_deliveries(50).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].url, "https://example.com/hook");
        assert_eq!(due[0].owner_user_id, reseller);
    }

    #[tokio::test]
    async fn the_payload_is_frozen_so_a_retry_is_a_redelivery() {
        let (db, reseller, _) = seed().await;
        let hook = db
            .webhooks(&TenantScope::Global)
            .create(new_hook(reseller, &["*"]))
            .await
            .unwrap();
        let payload = r#"{"event":"site.created","data":{"domain":"a.example"}}"#;
        let id = db
            .enqueue_delivery(hook.id, "site.created", payload, now())
            .await
            .unwrap();
        db.delivery_failed(id, hook.id, "502", Some(502), Some(now()))
            .await
            .unwrap();

        let due = db.due_deliveries(50).await.unwrap();
        assert_eq!(due[0].delivery.payload_json, payload);
        assert_eq!(due[0].delivery.attempts, 1);
        assert_eq!(due[0].delivery.id, id, "a retry keeps its delivery id");
    }

    #[tokio::test]
    async fn deleting_a_hook_takes_its_queue_with_it() {
        let (db, reseller, _) = seed().await;
        let repo = db.webhooks(&TenantScope::Global);
        let hook = repo.create(new_hook(reseller, &["*"])).await.unwrap();
        db.enqueue_delivery(hook.id, "site.created", "{}", now())
            .await
            .unwrap();
        repo.delete(hook.id).await.unwrap();
        assert!(db.recent_deliveries(hook.id, 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn only_terminal_deliveries_are_purged() {
        let (db, reseller, _) = seed().await;
        let hook = db
            .webhooks(&TenantScope::Global)
            .create(new_hook(reseller, &["*"]))
            .await
            .unwrap();
        let pending = db
            .enqueue_delivery(hook.id, "site.created", "{}", now())
            .await
            .unwrap();
        let done = db
            .enqueue_delivery(hook.id, "site.created", "{}", now())
            .await
            .unwrap();
        db.delivery_succeeded(done, hook.id, 204).await.unwrap();

        // Age both rows past the cutoff.
        let old = to_sql_time(now() - time::Duration::days(90));
        sqlx::query("UPDATE webhook_deliveries SET updated_at = ?1")
            .bind(&old)
            .execute(db.pool())
            .await
            .unwrap();

        assert_eq!(db.purge_deliveries(30).await.unwrap(), 1);
        let left = db.recent_deliveries(hook.id, 10).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, pending, "a pending delivery is not history yet");
    }
}
