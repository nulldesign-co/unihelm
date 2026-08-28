//! The outbound SMTP relay (spec §11.18).
//!
//! v1 is **relay-only**. This table holds the address of somebody else's
//! submission server and the credential to use with it; the panel runs no MTA,
//! accepts no inbound mail and owns no mailboxes. The full Stalwart stack is
//! Phase 5 and optional, and nothing here is a step towards it — a schema that
//! implied otherwise would be advertising a feature that does not exist.
//!
//! Exactly one row, id 1. A relay is a property of the server, like the
//! firewall backend, not of a tenant: PHP's `mail()` runs as the tenant user,
//! so any credential the shim can read is a credential that tenant can read,
//! and issuing one per tenant would multiply the secrets on disk without
//! changing who can read the one that matters to them. That exposure is
//! inherent to relay-only mail and is documented rather than hidden — see
//! `ferrum_ops::mail`.
//!
//! The password is sealed with the panel master key before it reaches this
//! module and is never opened here. This file's entire knowledge of the secret
//! is that it is an opaque string, which is what keeps it out of a query log,
//! a `Debug` line, and a `sqlite3` session over a restored backup.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// How the connection to the relay is protected.
///
/// Three states rather than a boolean, because "encrypted" is not one thing:
/// `starttls` starts in the clear and upgrades, `implicit` is encrypted from
/// the first byte, and the difference decides which port works and what an
/// interceptor can do. The client refuses to send credentials over `none`
/// (`ferrum_ops::mail::smtp`), which is the only reason `none` is safe to
/// offer at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Plaintext. Only defensible to a relay on localhost or a private LAN,
    /// and never with a username and password.
    None,
    /// Connect in the clear on 587, then `STARTTLS`. A failed upgrade aborts
    /// the send; it never falls back to plaintext.
    Starttls,
    /// TLS from the first byte — SMTPS, conventionally port 465.
    Implicit,
}

impl TlsMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            TlsMode::None => "none",
            TlsMode::Starttls => "starttls",
            TlsMode::Implicit => "implicit",
        }
    }

    /// Does this mode encrypt the session before any credential is sent?
    ///
    /// The one question the SMTP client asks before authenticating.
    pub const fn is_encrypted(self) -> bool {
        matches!(self, TlsMode::Starttls | TlsMode::Implicit)
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "none" => Ok(TlsMode::None),
            "starttls" => Ok(TlsMode::Starttls),
            "implicit" => Ok(TlsMode::Implicit),
            other => Err(DbError::Corrupt {
                field: "mail_relay.tls_mode",
                detail: format!("`{other}` is not a TLS mode"),
            }),
        }
    }
}

/// The stored relay.
///
/// `password_sealed` is not `Serialize`d: this is an internal record, and the
/// operation layer projects it into an output type that has no credential
/// field at all. A sealed value is still a secret — publishing it hands an
/// attacker everything except the master key.
#[derive(Debug, Clone)]
pub struct MailRelay {
    pub host: String,
    pub port: u16,
    pub tls_mode: TlsMode,
    pub username: Option<String>,
    /// Still sealed. Open it with [`crate::MasterKey`].
    pub password_sealed: Option<String>,
    pub from_address: String,
    pub from_name: Option<String>,
    pub enabled: bool,
    pub updated_at: OffsetDateTime,
}

impl MailRelay {
    /// Is this relay in a state where mail could actually leave?
    ///
    /// Configured *and* switched on. The pool renderer asks this, not
    /// `enabled` alone, so "there is a row" never becomes "mail works".
    pub const fn is_live(&self) -> bool {
        self.enabled
    }
}

/// A relay on its way in, before it has a timestamp.
#[derive(Debug, Clone)]
pub struct NewMailRelay {
    pub host: String,
    pub port: u16,
    pub tls_mode: TlsMode,
    pub username: Option<String>,
    /// Already sealed by the caller. `None` clears the stored password.
    pub password_sealed: Option<String>,
    pub from_address: String,
    pub from_name: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, sqlx::FromRow)]
struct MailRelayRow {
    host: String,
    port: i64,
    tls_mode: String,
    username: Option<String>,
    password_sealed: Option<String>,
    from_address: String,
    from_name: Option<String>,
    enabled: i64,
    updated_at: String,
}

impl TryFrom<MailRelayRow> for MailRelay {
    type Error = DbError;

    fn try_from(r: MailRelayRow) -> Result<Self> {
        Ok(MailRelay {
            host: r.host,
            // The schema CHECKs the range, so this cannot truncate on a row
            // this panel wrote — but a row edited by hand can, and silently
            // sending to port 0 would be worse than saying the column is bad.
            port: u16::try_from(r.port).map_err(|_| DbError::Corrupt {
                field: "mail_relay.port",
                detail: format!("`{}` is not a TCP port", r.port),
            })?,
            tls_mode: TlsMode::parse(&r.tls_mode)?,
            username: r.username,
            password_sealed: r.password_sealed,
            from_address: r.from_address,
            from_name: r.from_name,
            enabled: r.enabled != 0,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

const SELECT_RELAY: &str = "SELECT host, port, tls_mode, username, password_sealed, \
     from_address, from_name, enabled, updated_at FROM mail_relay WHERE id = 1";

impl Db {
    /// The configured relay, or `None` if one was never set.
    pub async fn mail_relay(&self) -> Result<Option<MailRelay>> {
        let row = sqlx::query_as::<_, MailRelayRow>(SELECT_RELAY)
            .fetch_optional(self.pool())
            .await?;
        row.map(MailRelay::try_from).transpose()
    }

    /// Store or replace the relay.
    ///
    /// An upsert on the single row rather than delete-then-insert: a crash
    /// between the two would leave the panel with no relay at all, and "my
    /// sites stopped sending mail because I changed the port" is a bad way to
    /// find that out.
    pub async fn save_mail_relay(&self, relay: NewMailRelay) -> Result<MailRelay> {
        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, MailRelayRow>(
            "INSERT INTO mail_relay (id, host, port, tls_mode, username, password_sealed, \
                 from_address, from_name, enabled, updated_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (id) DO UPDATE SET
                 host = ?1, port = ?2, tls_mode = ?3, username = ?4,
                 password_sealed = ?5, from_address = ?6, from_name = ?7,
                 enabled = ?8, updated_at = ?9
             RETURNING host, port, tls_mode, username, password_sealed, \
                 from_address, from_name, enabled, updated_at",
        )
        .bind(&relay.host)
        .bind(i64::from(relay.port))
        .bind(relay.tls_mode.as_str())
        .bind(&relay.username)
        .bind(&relay.password_sealed)
        .bind(&relay.from_address)
        .bind(&relay.from_name)
        .bind(i64::from(relay.enabled))
        .bind(&ts)
        .fetch_one(self.pool())
        .await?;
        MailRelay::try_from(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay() -> NewMailRelay {
        NewMailRelay {
            host: "smtp.example.net".into(),
            port: 587,
            tls_mode: TlsMode::Starttls,
            username: Some("panel@example.com".into()),
            password_sealed: Some("deadbeef".into()),
            from_address: "noreply@example.com".into(),
            from_name: Some("Example Hosting".into()),
            enabled: true,
        }
    }

    #[tokio::test]
    async fn a_fresh_panel_has_no_relay() {
        let db = Db::open_memory().await.unwrap();
        assert!(db.mail_relay().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_relay_round_trips() {
        let db = Db::open_memory().await.unwrap();
        let saved = db.save_mail_relay(relay()).await.unwrap();
        assert_eq!(saved.host, "smtp.example.net");
        assert_eq!(saved.port, 587);
        assert_eq!(saved.tls_mode, TlsMode::Starttls);

        let read = db.mail_relay().await.unwrap().unwrap();
        assert_eq!(read.username.as_deref(), Some("panel@example.com"));
        assert_eq!(read.password_sealed.as_deref(), Some("deadbeef"));
        assert!(read.is_live());
    }

    #[tokio::test]
    async fn saving_twice_replaces_rather_than_accumulating() {
        // The relay is a single row by construction. A second insert must not
        // be able to create a shadow relay nothing reads.
        let db = Db::open_memory().await.unwrap();
        db.save_mail_relay(relay()).await.unwrap();
        let mut second = relay();
        second.host = "smtp2.example.net".into();
        second.port = 465;
        second.tls_mode = TlsMode::Implicit;
        db.save_mail_relay(second).await.unwrap();

        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM mail_relay")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 1);
        assert_eq!(db.mail_relay().await.unwrap().unwrap().host, "smtp2.example.net");
    }

    #[tokio::test]
    async fn a_relay_can_be_disabled_without_losing_its_credential() {
        // Switching mail off must not force an operator to re-type an SMTP
        // password they can no longer read anywhere.
        let db = Db::open_memory().await.unwrap();
        db.save_mail_relay(relay()).await.unwrap();
        let mut off = relay();
        off.enabled = false;
        db.save_mail_relay(off).await.unwrap();

        let read = db.mail_relay().await.unwrap().unwrap();
        assert!(!read.is_live());
        assert_eq!(read.password_sealed.as_deref(), Some("deadbeef"));
    }

    #[tokio::test]
    async fn an_unauthenticated_relay_is_a_valid_configuration() {
        // Most in-datacentre relays authorise by source IP and reject AUTH.
        let db = Db::open_memory().await.unwrap();
        let saved = db
            .save_mail_relay(NewMailRelay {
                username: None,
                password_sealed: None,
                tls_mode: TlsMode::None,
                port: 25,
                ..relay()
            })
            .await
            .unwrap();
        assert!(saved.username.is_none());
        assert!(saved.password_sealed.is_none());
    }

    #[tokio::test]
    async fn a_second_relay_row_is_refused_by_the_schema() {
        // The CHECK is what makes "the relay" a singular noun in the rest of
        // the codebase; without it every reader would need an ORDER BY.
        let db = Db::open_memory().await.unwrap();
        db.save_mail_relay(relay()).await.unwrap();
        let err = sqlx::query(
            "INSERT INTO mail_relay (id, host, port, tls_mode, from_address, enabled, updated_at)
             VALUES (2, 'evil.example', 25, 'none', 'a@b.c', 1, '2026-01-01T00:00:00Z')",
        )
        .execute(db.pool())
        .await;
        assert!(err.is_err(), "id must be pinned to 1");
    }

    #[tokio::test]
    async fn an_unknown_tls_mode_in_the_column_is_corruption_not_a_default() {
        // Silently reading an unparseable mode as `none` would downgrade a
        // configured relay to plaintext, which is the one failure mode this
        // whole enum exists to prevent.
        assert!(TlsMode::parse("ssl").is_err());
        assert!(TlsMode::parse("").is_err());
        assert_eq!(TlsMode::parse("implicit").unwrap(), TlsMode::Implicit);
    }

    #[test]
    fn only_the_two_tls_modes_that_encrypt_report_that_they_do() {
        assert!(!TlsMode::None.is_encrypted());
        assert!(TlsMode::Starttls.is_encrypted());
        assert!(TlsMode::Implicit.is_encrypted());
    }
}
