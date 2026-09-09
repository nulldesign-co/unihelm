//! Outbound mail: a host service, not a PHP feature (spec §11.18).
//!
//! # What this is, and firmly what it is not
//!
//! Unihelm runs **no mail server**. It stores the address of somebody else's
//! submission service, runs a local MTA that hands every message on this
//! machine to it, and can send one test message to prove the whole path works.
//! There are no mailboxes, no inbound mail, no domains and no aliases. The full
//! Stalwart stack is Phase 5 and explicitly optional; nothing here is a partial
//! version of it.
//!
//! That boundary is the honest one to hold. A panel that ships "email" and
//! means "an SMTP client" is why operators end up debugging why their customer
//! cannot receive anything.
//!
//! # The design this replaced, and what it cost
//!
//! Mail used to be delivered by giving every site its own msmtp:
//!
//! ```text
//! PHP-FPM (as the tenant) → php_admin_value[sendmail_path] = msmtp --file=…/<domain>.msmtprc -t
//!                         → msmtp runs as the tenant
//!                         → so that file has to be tenant-readable
//!                         → so every tenant holds the upstream relay credential
//! ```
//!
//! Two things were wrong with it at once, and neither was fixable within it:
//!
//! 1. **Every tenant could read the credential the server itself sends with.**
//!    One relay row for the whole machine, one credential, copied into every
//!    site's file. A customer who read their own copy could send as the
//!    operator — a spam-blacklist event that takes every other customer's mail
//!    down with it.
//! 2. **Nothing but PHP could send at all.** `sendmail_path` is an FPM pool
//!    directive. Node applications had no mail path, containers had none, and a
//!    server with no PHP installed — an ordinary configuration for a panel that
//!    runs its databases as containers — had no mail whatsoever, while
//!    `cron.rs` had been writing a `MAILTO=` line into every tenant crontab for
//!    a mail system that did not exist.
//!
//! [`mta`] is what replaces it: a Postfix null client that holds the credential
//! as root in a `0600` map, accepts messages from `/usr/sbin/sendmail` and from
//! `127.0.0.1:25`, and relays them upstream. The tenant hands over a message
//! and never sees a credential. This module keeps the relay row, the DNS
//! advisory and the SMTP test; the MTA itself, and every file it reads, is next
//! door.
//!
//! # SPF, DKIM and DMARC are *guidance*
//!
//! The panel does not manage them and does not claim to. `mail.relay.get`
//! returns the records the configured relay needs, in the same advisory shape
//! `dns.check` uses — a structured record, a purpose, and a sentence — and
//! every one of them carries `managed: false`. DKIM in particular cannot be
//! generated here at all: the key pair belongs to the relay, and only the relay
//! can say what the selector is. Printing a made-up DKIM record would be worse
//! than printing none.
//!
//! # Migration is part of this module, not an afterthought
//!
//! Somebody is running the old design right now, with a `.msmtprc` per site and
//! FPM pools naming it. `mail.mta.install` is the order that gets them across
//! without a window where mail stops:
//!
//! 1. verify the relay actually accepts the credential — before anything on the
//!    machine is touched, so a rejection leaves the old wiring exactly as it
//!    was and still delivering;
//! 2. install and configure the MTA, and prove it is running;
//! 3. only then re-render each site's pool, which is what drops the old
//!    `sendmail_path` directive;
//! 4. and only after *that site's* pool re-rendered, delete that site's
//!    credential file.
//!
//! Every step is safe to interrupt: a machine stopped between 3 and 4 has some
//! sites on the MTA and some still on msmtp, and both kinds deliver. What is
//! never safe is the reverse order — deleting the credential file while the
//! pool still names it takes that site's mail down — so it is not available in
//! this module in either direction.
//!
//! That is also why [`PoolWriter`] and [`rewire_all_sites`] are still here now
//! that a pool has no mail configuration in it. They no longer *write* mail
//! wiring; re-rendering a pool is how the directive an older panel wrote gets
//! removed from a machine that has one, and it is the step the credential file
//! deletion is sequenced behind.

pub mod mta;
pub mod smtp;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_config::paths;
use unihelm_core::{ErrorCode, LinuxUser, Permission, Result, TenantScope, UnihelmError};
use unihelm_db::{MailRelay, NewMailRelay, TlsMode};
use unihelm_distro::Family;

use crate::registry::{Execution, OpContext, TypedOperation};

/// The relay client the design this replaced ran once per site.
///
/// Still named here for one reason: a machine upgrading from 0.7 has these
/// files on disk and its pools pointing at them, and the panel has to be able
/// to talk about what it is retiring. Nothing renders a new one.
pub const LEGACY_AGENT: &str = "msmtp";

/// Largest value any single relay field may take.
///
/// These strings are rendered into a configuration file and into an SMTP
/// conversation; unbounded ones are a way to make either unreadable.
const MAX_FIELD: usize = 255;

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

/// Accept a relay hostname or IP literal.
///
/// Deliberately stricter than DNS: the value is rendered into a configuration
/// file whose grammar is line-oriented and whitespace-separated, so a space or
/// a newline in it is not a formatting problem but a way to add a directive.
/// Everything outside `[A-Za-z0-9.:_-]` is refused rather than escaped.
pub fn parse_relay_host(input: &str) -> Result<String> {
    let host = input.trim();
    if host.is_empty() || host.len() > MAX_FIELD {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "the relay host must be between 1 and 255 characters",
        )
        .with_field("host"));
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "the relay host may contain only letters, digits, dots, hyphens, underscores \
             and colons",
        )
        .with_field("host"));
    }
    Ok(host.to_ascii_lowercase())
}

/// Accept an email address, conservatively.
///
/// Not an RFC 5322 parser: a full one accepts quoted local parts with spaces
/// and comments, none of which any relay in practice wants and all of which
/// would have to survive a trip through a config file and an SMTP command. One
/// `@`, no whitespace, no control characters, a dot in the domain.
pub fn parse_email(field: &'static str, input: &str) -> Result<String> {
    let value = input.trim();
    let invalid = |detail: &str| {
        UnihelmError::new(ErrorCode::InvalidInput, detail.to_string()).with_field(field)
    };
    if value.is_empty() || value.len() > MAX_FIELD {
        return Err(invalid(
            "an email address is required, at most 255 characters",
        ));
    }
    let Some((local, domain)) = value.split_once('@') else {
        return Err(invalid("an email address needs exactly one `@`"));
    };
    if domain.contains('@') {
        return Err(invalid("an email address needs exactly one `@`"));
    }
    if local.is_empty() || domain.is_empty() {
        return Err(invalid(
            "an email address needs something either side of the `@`",
        ));
    }
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return Err(invalid(
            "the domain part of an email address needs a dot in it",
        ));
    }
    if value
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '<' || c == '>' || c == ',')
    {
        return Err(invalid(
            "an email address may not contain whitespace, angle brackets or commas",
        ));
    }
    Ok(value.to_string())
}

/// Accept a free-text display name.
///
/// Control characters are refused rather than stripped: in both the config file
/// and the message header a newline ends the current line and starts a
/// directive or a header the operator did not write.
pub fn parse_display_name(field: &'static str, input: &str) -> Result<String> {
    let value = input.trim();
    if value.len() > MAX_FIELD {
        return Err(
            UnihelmError::new(ErrorCode::InvalidInput, "at most 255 characters").with_field(field),
        );
    }
    if let Err(detail) = smtp::reject_control_characters(field, value) {
        return Err(UnihelmError::new(ErrorCode::InvalidInput, detail).with_field(field));
    }
    Ok(value.to_string())
}

/// Where the distribution keeps its trusted CA bundle.
///
/// Postfix needs a path for `smtp_tls_CAfile`; it has no compiled-in root
/// store. Getting this wrong does not silently disable verification — with
/// `smtp_tls_security_level = secure` the delivery fails — so the failure mode
/// of a bad guess here is "mail does not send", never "mail sends unverified".
pub const fn tls_trust_file(family: Family) -> &'static str {
    match family {
        Family::Rhel => "/etc/pki/tls/certs/ca-bundle.crt",
        Family::Debian => "/etc/ssl/certs/ca-certificates.crt",
    }
}

// ---------------------------------------------------------------------------
// the files the old design left behind
// ---------------------------------------------------------------------------

/// Every per-site msmtp credential file still on disk, with the domain it
/// belongs to.
///
/// Each one holds the server's upstream relay password where that site's tenant
/// can read it; while any of them exist the defect this change removes has
/// survived the fix. Listing them is how the panel can say how many there are,
/// and deleting them is [`retire_legacy_relay_file`] — deliberately separate,
/// because a file may only go *after* the pool that names it has been
/// re-rendered without it.
///
/// The directory is a parameter rather than a call to `paths::mail_dir()` for
/// the same reason the old `prepare_mail_dir` took one: `paths::set_root` is a
/// process-wide `OnceLock` a parallel test cannot claim, and a sweep hard-wired
/// to `/etc/unihelm/mail` would delete a live server's mail configuration the
/// first time somebody ran the test suite as root on one.
///
/// A directory that does not exist is not an error: it is the ordinary state of
/// a machine that never ran the old design.
pub fn legacy_relay_files(dir: &std::path::Path) -> Vec<(String, std::path::PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Only the files the old design named. `/etc/unihelm/mail` now also
        // holds the Postfix maps, and deleting one of those would take the
        // whole machine's mail down.
        if let Some(domain) = name.strip_suffix(".msmtprc") {
            found.push((domain.to_string(), path));
        }
    }
    found.sort();
    found
}

/// Delete one site's msmtp credential file, and say whether it was there.
///
/// The caller must have re-rendered that site's pool first. A pool that still
/// carries `sendmail_path = msmtp --file=<this file>` next to a file that is
/// gone is a site whose mail fails at the next message — worse than the leak
/// this removes — so the order is fixed inside [`rewire_all_sites`] rather than
/// left to each caller to remember.
pub fn retire_legacy_relay_file(dir: &std::path::Path, domain: &str) -> Result<bool> {
    let path = dir.join(format!("{domain}.msmtprc"));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(UnihelmError::internal(format!(
            "could not remove {}: {e}",
            path.display()
        ))),
    }
}

// ---------------------------------------------------------------------------
// re-rendering every pool
// ---------------------------------------------------------------------------

/// The seam between "decide which sites have to be re-rendered" and "write
/// files under /etc and reload PHP-FPM".
///
/// Exists for the same reason `plan::VhostSwitcher` does: the deciding half is
/// worth testing and the writing half cannot be, in a unit test, on a machine
/// with no PHP-FPM.
///
/// It no longer carries a relay, because a pool has no mail configuration in it
/// any more. Re-rendering one is purely how the `sendmail_path` directive an
/// older panel wrote gets removed from a machine that still has it — and it is
/// the step the credential-file deletion below is sequenced behind.
#[async_trait]
pub trait PoolWriter: Send + Sync {
    async fn rewrite(
        &self,
        ctx: &OpContext,
        site: &unihelm_db::Site,
        linux_user: &LinuxUser,
    ) -> Result<()>;
}

pub struct LivePools;

#[async_trait]
impl PoolWriter for LivePools {
    async fn rewrite(
        &self,
        ctx: &OpContext,
        site: &unihelm_db::Site,
        linux_user: &LinuxUser,
    ) -> Result<()> {
        let Some(version) = site.php_version else {
            return Ok(());
        };
        crate::site::render_pool(ctx, site, linux_user, version).await
    }
}

/// Take the old per-site mail wiring off every site, one site at a time.
///
/// Two things happen per site and the order between them is the whole point:
/// the pool is re-rendered first — which is what stops PHP running msmtp — and
/// only if that succeeded is the credential file deleted. A site whose pool
/// failed to render keeps both its directive and its file, and keeps sending.
///
/// Every site is attempted even when one fails: stopping at the first failure
/// would leave the rest both un-migrated *and* untried. The tally comes back
/// with the first error, and because the whole operation is idempotent a re-run
/// converges the stragglers — the same shape as `plan::switch_all_vhosts`, and
/// for the same reason.
pub async fn rewire_all_sites(
    ctx: &OpContext,
    pools: &dyn PoolWriter,
    legacy_dir: &std::path::Path,
) -> Result<RewireTally> {
    let sites = ctx
        .db()
        .sites(&TenantScope::Global)
        .list(500, 0)
        .await
        .map_err(UnihelmError::from)?;

    let mut tally = RewireTally::default();
    let mut first_error: Option<UnihelmError> = None;

    for site in sites {
        if site.php_version.is_none() {
            // Not PHP, so it never had a pool and never had a directive.
            // Whatever file the old design left for it is swept below, where
            // nothing can be pointing at it.
            tally.skipped_not_php += 1;
            continue;
        }
        let subscription = ctx
            .db()
            .subscriptions(&TenantScope::Global)
            .by_id(site.subscription_id)
            .await
            .map_err(UnihelmError::from)?;
        let Some(subscription) = subscription else {
            // A site whose subscription vanished is already broken in ways
            // mail cannot fix; skipping it is more useful than failing here.
            tally.skipped_no_subscription += 1;
            continue;
        };
        let linux_user = LinuxUser::parse(&subscription.linux_user)?;

        match pools.rewrite(ctx, &site, &linux_user).await {
            Ok(()) => {
                tally.rewired += 1;
                // Now, and not before: the pool that named this file has just
                // stopped naming it.
                match retire_legacy_relay_file(legacy_dir, &site.domain) {
                    Ok(true) => {
                        tally.retired_files += 1;
                        ctx.log(format!(
                            "{}: pool re-rendered without sendmail_path, and this site's copy \
                             of the relay credential deleted",
                            site.domain
                        ));
                    }
                    Ok(false) => ctx.log(format!("{}: pool re-rendered", site.domain)),
                    Err(e) => {
                        // The pool is already right, so this site still sends.
                        // What is left behind is the credential file, and that
                        // is worth naming loudly rather than failing over.
                        ctx.log(format!(
                            "{}: pool re-rendered, but its old credential file could not be \
                             deleted: {e}. It still holds the relay password where that \
                             tenant can read it.",
                            site.domain
                        ));
                    }
                }
            }
            Err(e) => {
                tally.failed += 1;
                ctx.log(format!(
                    "could not re-render the pool for {}: {e}. It keeps the old msmtp wiring \
                     and keeps sending; re-run this operation to try again.",
                    site.domain
                ));
                first_error.get_or_insert(e);
            }
        }
    }

    // Whatever is left belongs to a site that is not PHP, or to one deleted
    // since — nothing names those files, so nothing breaks when they go, and
    // each one is a copy of the relay password.
    if tally.failed == 0 {
        for (domain, path) in legacy_relay_files(legacy_dir) {
            match retire_legacy_relay_file(legacy_dir, &domain) {
                Ok(true) => {
                    tally.retired_files += 1;
                    ctx.log(format!(
                        "removed {}: nothing points at it any more",
                        path.display()
                    ));
                }
                Ok(false) => {}
                Err(e) => ctx.log(format!("could not remove {}: {e}", path.display())),
            }
        }
    } else {
        ctx.log(
            "some pools could not be re-rendered, so the credential files of the sites that \
             were not reached are being left alone: a pool that still names one needs it to \
             keep sending",
        );
    }

    match first_error {
        Some(e) if tally.rewired == 0 => Err(e),
        _ => Ok(tally),
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct RewireTally {
    pub rewired: usize,
    pub failed: usize,
    pub skipped_not_php: usize,
    pub skipped_no_subscription: usize,
    /// Per-site msmtp credential files deleted. The number that matters: while
    /// it is short of the number that existed, the leak is still there.
    pub retired_files: usize,
}

/// Every domain this server hosts, for the sender-rewriting map.
///
/// Aliases are deliberately not gathered: `main.cf` pairs the map with a
/// `static:` entry, so a sender the map has never heard of is still rewritten
/// to something the relay accepts. The map is the readable record, not the
/// guarantee.
async fn hosted_domains(ctx: &OpContext) -> Result<Vec<String>> {
    let sites = ctx
        .db()
        .sites(&TenantScope::Global)
        .list(500, 0)
        .await
        .map_err(UnihelmError::from)?;
    let mut domains: Vec<String> = sites.into_iter().map(|s| s.domain).collect();
    domains.sort();
    domains.dedup();
    Ok(domains)
}

// ---------------------------------------------------------------------------
// the DNS advisory (spec §11.18: guidance, never management)
// ---------------------------------------------------------------------------

/// One record an operator should publish, in the advisory shape `dns.check`
/// established: structured enough to copy, annotated enough to understand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdvisoryRecord {
    /// The owner name, with `{domain}` left as a placeholder when the record
    /// belongs to whichever domain the operator sends as.
    pub name: String,
    pub record_type: &'static str,
    /// The value to publish, or `None` when only the provider can supply it.
    pub value: Option<String>,
    /// Always false. The panel surfaces these; it does not publish or verify
    /// them, and a field that could ever read `true` would be an invitation to
    /// believe otherwise.
    pub managed: bool,
    /// What the record is for, and what happens without it.
    pub purpose: String,
}

/// Everything to say about a relay's DNS, including the sentence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsAdvisory {
    pub records: Vec<AdvisoryRecord>,
    pub advice: String,
}

/// The SPF mechanism a known provider publishes for its customers.
///
/// A short table of the relays people actually configure, matched on the host
/// they tell you to use. Everything else falls through to `a:<host>`, which is
/// *a* correct answer for a single-host relay and an incomplete one for a
/// provider with a fleet — hence the sentence that goes with it, which says to
/// check the provider's own published mechanism.
fn spf_mechanism(host: &str) -> (String, bool) {
    let known = [
        ("email-smtp.", "include:amazonses.com"),
        ("smtp.postmarkapp.com", "include:spf.mtasv.net"),
        ("smtp.mailgun.org", "include:mailgun.org"),
        ("smtp.eu.mailgun.org", "include:eu.mailgun.org"),
        ("smtp.sendgrid.net", "include:sendgrid.net"),
        ("smtp-relay.brevo.com", "include:spf.brevo.com"),
        ("smtp.sendinblue.com", "include:spf.sendinblue.com"),
        ("smtp.resend.com", "include:amazonses.com"),
        ("smtp.gmail.com", "include:_spf.google.com"),
        ("smtp-relay.gmail.com", "include:_spf.google.com"),
        ("smtp.office365.com", "include:spf.protection.outlook.com"),
        ("smtp.mailtrap.io", "include:_spf.mailtrap.io"),
    ];
    for (needle, mechanism) in known {
        if host == needle || host.starts_with(needle) {
            return (mechanism.to_string(), true);
        }
    }
    (format!("a:{host}"), false)
}

/// The records the configured relay needs, and the sentence that goes with
/// them.
///
/// A pure function so the wording is testable and the UI does not keep a second
/// copy of the decision table — copied deliberately from `dns::advice_for`.
pub fn dns_advisory(relay: Option<&MailRelay>) -> DnsAdvisory {
    let Some(relay) = relay else {
        return DnsAdvisory {
            records: Vec::new(),
            advice: "No relay is configured, so there is nothing to publish yet. Configure the \
                     relay first; the records it needs depend on which provider it is."
                .into(),
        };
    };

    let domain = relay
        .from_address
        .split_once('@')
        .map(|(_, d)| d.to_string())
        .unwrap_or_else(|| "{domain}".into());
    let (mechanism, recognised) = spf_mechanism(&relay.host);

    let records = vec![
        AdvisoryRecord {
            name: domain.clone(),
            record_type: "TXT",
            value: Some(format!("v=spf1 {mechanism} ~all")),
            managed: false,
            purpose: "SPF: says which servers may send as this domain. Without it most \
                      recipients treat the mail as unauthenticated. If the domain already has \
                      an SPF record, merge this mechanism into it — two SPF records is a \
                      permanent error and worse than none."
                .into(),
        },
        AdvisoryRecord {
            name: format!("<selector>._domainkey.{domain}"),
            record_type: "TXT",
            // Deliberately absent. The key pair belongs to the relay and only
            // the relay knows the selector; inventing a value would be a lie
            // the operator would publish.
            value: None,
            managed: false,
            purpose: "DKIM: the relay signs the mail and publishes the public half here. Unihelm \
                      does not sign and cannot generate this — copy the selector and value from \
                      the relay provider's dashboard."
                .into(),
        },
        AdvisoryRecord {
            name: format!("_dmarc.{domain}"),
            record_type: "TXT",
            value: Some(format!(
                "v=DMARC1; p=none; rua=mailto:{}",
                relay.from_address
            )),
            managed: false,
            purpose: "DMARC: tells recipients what to do when SPF and DKIM disagree, and where \
                      to send reports. `p=none` is the safe starting policy — it changes no \
                      delivery decision while the reports show whether tightening it would."
                .into(),
        },
    ];

    let advice = if recognised {
        format!(
            "These records are for `{domain}`, the domain the relay sends as — and the domain \
             every message leaves this server as, because the local MTA rewrites the envelope \
             sender to it. The SPF mechanism is the one `{}` publishes for its customers. DKIM \
             comes from the relay's dashboard; Unihelm neither signs nor manages any of these.",
            relay.host
        )
    } else {
        format!(
            "These records are for `{domain}`, the domain the relay sends as. `{}` is not a \
             relay Unihelm recognises, so the SPF mechanism below points at that host directly — \
             correct for a single-host relay, and incomplete for a provider with a fleet. Use \
             the mechanism the provider publishes if it has one. Unihelm neither signs nor \
             manages any of these.",
            relay.host
        )
    };

    DnsAdvisory { records, advice }
}

// ---------------------------------------------------------------------------
// sending, and proving the relay works
// ---------------------------------------------------------------------------

/// Open the stored relay password, or say why it could not be opened.
///
/// The plaintext exists only for the length of the call that asked for it: the
/// render, or one SMTP conversation.
async fn open_password(ctx: &OpContext, relay: &MailRelay) -> Result<Option<String>> {
    match &relay.password_sealed {
        Some(sealed) => Ok(Some(ctx.master_key().open_str(sealed).map_err(|e| {
            UnihelmError::internal(format!(
                "the stored relay password could not be opened: {e}"
            ))
        })?)),
        None => Ok(None),
    }
}

/// What the panel calls itself in `EHLO`.
///
/// The domain of the envelope sender, which is the identity the relay is being
/// asked to accept mail for anyway. Falling back to `localhost` would be
/// rejected outright by several providers.
pub fn ehlo_name(relay: &MailRelay) -> String {
    relay
        .from_address
        .split_once('@')
        .map(|(_, domain)| domain.to_string())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

/// Hand one message to the relay.
///
/// One function so `mail.relay.test` and the install-time verification cannot
/// drift into testing different things: a check that takes a shortcut the real
/// delivery does not is a check that passes for a relay which will refuse
/// everything.
async fn send_through_relay(
    relay: &MailRelay,
    password: Option<&str>,
    to: &str,
    subject: String,
    body: String,
) -> smtp::SendReport {
    let credentials = match (&relay.username, password) {
        (Some(user), Some(secret)) => Some(smtp::Credentials::new(user, secret)),
        _ => None,
    };
    smtp::send(
        &smtp::Endpoint {
            host: relay.host.clone(),
            port: relay.port,
            tls_mode: relay.tls_mode,
        },
        credentials.as_ref(),
        &smtp::Message {
            from: relay.from_address.clone(),
            from_name: relay.from_name.clone(),
            to: to.to_string(),
            subject,
            body,
        },
        &ehlo_name(relay),
    )
    .await
}

/// Ask the relay whether it will actually take a message from this server.
///
/// A seam, for the same reason [`PoolWriter`] is one: the install operation's
/// whole value is that it refuses to reconfigure a machine's mail on the
/// strength of a credential the relay rejects, and asserting that in a test
/// must not require a relay.
#[async_trait]
pub trait RelayProbe: Send + Sync {
    async fn probe(
        &self,
        ctx: &OpContext,
        relay: &MailRelay,
        password: Option<&str>,
    ) -> smtp::SendReport;
}

pub struct LiveProbe;

#[async_trait]
impl RelayProbe for LiveProbe {
    async fn probe(
        &self,
        ctx: &OpContext,
        relay: &MailRelay,
        password: Option<&str>,
    ) -> smtp::SendReport {
        let panel_name: String = ctx
            .db()
            .get_setting_or(
                unihelm_db::settings::keys::PANEL_NAME,
                "Unihelm".to_string(),
            )
            .await;
        // Addressed to the relay's own `from_address`: the one recipient a
        // relay is certainly willing to accept mail from and usually willing to
        // deliver to. And a real message, through `DATA` — a check that stopped
        // at `RCPT TO` would prove the relay accepts a conversation, not that
        // it accepts mail.
        let to = relay.from_address.clone();
        send_through_relay(
            relay,
            password,
            &to,
            format!("{panel_name}: relay verification"),
            verification_body(relay, &panel_name),
        )
        .await
    }
}

fn verification_body(relay: &MailRelay, panel_name: &str) -> String {
    format!(
        "This is a verification message from {panel_name}.\n\
         \n\
         It was sent before this server's local mail transfer agent was pointed at {}:{}, to \
         prove the host, the port, the TLS mode and the credential all work. Receiving it \
         means the panel did not write a configuration for a credential the relay would have \
         rejected.\n\
         \n\
         It does not prove that mail from this server reaches inboxes — that depends on SPF, \
         DKIM and DMARC, which the panel surfaces as guidance and does not manage.\n",
        relay.host, relay.port,
    )
}

// ---------------------------------------------------------------------------
// `mail.relay.get`
// ---------------------------------------------------------------------------

/// What comes back. Note what is absent: there is no field here, and none on
/// the path from the agent to the browser, that could carry the password.
#[derive(Debug, Clone, Serialize)]
pub struct RelayView {
    pub configured: bool,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub tls_mode: Option<&'static str>,
    pub username: Option<String>,
    /// Whether a password is stored, never which one.
    pub has_password: bool,
    pub from_address: Option<String>,
    pub from_name: Option<String>,
    pub enabled: bool,
    /// Whether this server can hand a message over at all: the MTA is installed
    /// *and* the panel has written its configuration. `false` means nothing can
    /// send however well the relay is configured, which is worth its own field
    /// rather than a note buried in a message.
    pub agent_installed: bool,
    /// What that agent is. `postfix`, where this used to read `msmtp`.
    pub agent: &'static str,
    /// The whole state of the local MTA, including the sentence that says which
    /// part of it is true.
    pub mta: mta::MtaState,
    /// What the credential exposure is now. See [`CREDENTIAL_NOTE`].
    pub credential_note: &'static str,
    pub dns: DnsAdvisory,
}

/// This used to say the tenant could read the credential and that the exposure
/// was inherent to relay-only mail. It was inherent to *that* design, not to
/// the problem: Postfix opens the credential as root, in `smtp(8)`'s pre-jail
/// initialisation, out of a file mode `0600`, and drops privileges afterwards.
/// What is left to say is the part that is still true — one credential for the
/// whole machine, so it is still worth being a send-only one.
const CREDENTIAL_NOTE: &str = "The relay credential is held by the local mail transfer agent, root-owned and mode 0600. \
     No tenant can read it: a site hands its message to sendmail or to 127.0.0.1:25 and never \
     sees a secret. This replaces a per-site msmtp file that had to be tenant-readable, which \
     put this same credential in every customer's hands. It is still one credential for the \
     whole server, so use a send-only one made for this machine rather than an account \
     password, and rotate it here.";

async fn view(
    ctx: &OpContext,
    host: &dyn mta::MtaHost,
    layout: &mta::Layout,
    relay: Option<&MailRelay>,
    legacy_dir: &std::path::Path,
) -> RelayView {
    let state = mta::state(
        ctx,
        host,
        layout,
        relay,
        legacy_relay_files(legacy_dir).len(),
    )
    .await;
    RelayView {
        configured: relay.is_some(),
        host: relay.map(|r| r.host.clone()),
        port: relay.map(|r| r.port),
        tls_mode: relay.map(|r| r.tls_mode.as_str()),
        username: relay.and_then(|r| r.username.clone()),
        has_password: relay.is_some_and(|r| r.password_sealed.is_some()),
        from_address: relay.map(|r| r.from_address.clone()),
        from_name: relay.and_then(|r| r.from_name.clone()),
        enabled: relay.is_some_and(|r| r.enabled),
        // Installed is not enough: a Postfix the panel has not configured does
        // whatever the package decided, which on a fresh install is deliver
        // nothing and queue everything.
        agent_installed: state.installed && state.configured,
        agent: mta::AGENT,
        mta: state,
        credential_note: CREDENTIAL_NOTE,
        dns: dns_advisory(relay),
    }
}

/// `mail.dns.publish` — write the advisory's records into the operator's zone.
///
/// The advisory stays advisory: `AdvisoryRecord::managed` is still always false,
/// and nothing publishes on its own or keeps a record in step afterwards. This
/// is the operator saying "yes, put those in", once, and being told exactly what
/// went in and what did not.
///
/// A dry run is the default. Publishing into somebody's live zone is not a thing
/// to do because a field happened to be set, and a mail domain's SPF record is
/// one an operator may already have written by hand — an existing record is
/// reported and left alone rather than overwritten, because merging two SPF
/// policies correctly is not something to guess at.
pub struct DnsPublish;

#[derive(Debug, Deserialize)]
pub struct DnsPublishInput {
    /// Write the records. Without this, the operation only reports what it would
    /// do — which is the answer most people want the first time.
    #[serde(default)]
    pub apply: bool,
}

#[derive(Debug, Serialize)]
pub struct DnsPublishOutput {
    /// Whether anything was actually written.
    pub applied: bool,
    /// One line per record, saying what happened to it.
    pub results: Vec<PublishedRecord>,
    pub advice: String,
}

#[derive(Debug, Serialize)]
pub struct PublishedRecord {
    pub name: String,
    pub record_type: &'static str,
    pub value: Option<String>,
    /// `would-create`, `created`, `exists`, `skipped` or `failed`.
    pub outcome: &'static str,
    pub detail: Option<String>,
}

#[async_trait]
impl TypedOperation for DnsPublish {
    type Input = DnsPublishInput;
    type Output = DnsPublishOutput;

    const NAME: &'static str = "mail.dns.publish";
    // Writes into the zone that fronts every site on this server. Server-wide
    // configuration, server-wide permission.
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let relay = ctx.db().mail_relay().await.map_err(UnihelmError::from)?;
        let advisory = dns_advisory(relay.as_ref());

        let mut results = Vec::new();
        for record in &advisory.records {
            // A record whose value only the provider can supply — a DKIM public
            // key, typically. Publishing a placeholder would be worse than
            // publishing nothing.
            let Some(value) = record.value.clone() else {
                results.push(PublishedRecord {
                    name: record.name.clone(),
                    record_type: record.record_type,
                    value: None,
                    outcome: "skipped",
                    detail: Some(
                        "only your provider can supply this value; copy it from their dashboard"
                            .into(),
                    ),
                });
                continue;
            };

            // The advisory leaves `{domain}` in place where the record belongs
            // to whichever domain the operator sends as. Publishing that
            // literally would create a record named `{domain}`.
            if record.name.contains('{') {
                results.push(PublishedRecord {
                    name: record.name.clone(),
                    record_type: record.record_type,
                    value: Some(value),
                    outcome: "skipped",
                    detail: Some(
                        "this record belongs to each sending domain; publish it per domain".into(),
                    ),
                });
                continue;
            }

            if !input.apply {
                results.push(PublishedRecord {
                    name: record.name.clone(),
                    record_type: record.record_type,
                    value: Some(value),
                    outcome: "would-create",
                    detail: None,
                });
                continue;
            }

            match publish_one(ctx, &record.name, record.record_type, &value).await {
                Ok(outcome) => results.push(PublishedRecord {
                    name: record.name.clone(),
                    record_type: record.record_type,
                    value: Some(value),
                    outcome,
                    detail: None,
                }),
                Err(e) => results.push(PublishedRecord {
                    name: record.name.clone(),
                    record_type: record.record_type,
                    value: Some(value),
                    outcome: "failed",
                    detail: Some(e.to_string()),
                }),
            }
        }

        Ok(DnsPublishOutput {
            applied: input.apply,
            results,
            advice: advisory.advice,
        })
    }
}

/// Put one record into the operator's zone, if it is not already there.
///
/// Never overwrites. An SPF record the operator wrote by hand is a policy, and
/// merging two SPF policies correctly is not something to guess at — the
/// existing one is reported and left exactly as it is.
async fn publish_one(
    ctx: &OpContext,
    name: &str,
    record_type: &str,
    value: &str,
) -> Result<&'static str> {
    let (_, zone, cloudflare) = crate::dns::resolve_provider(ctx, name).await?;

    let existing = cloudflare.find_records(&zone.id, record_type, name).await?;
    if !existing.is_empty() {
        return Ok("exists");
    }

    cloudflare
        .create_record(&zone.id, record_type, name, value, None)
        .await?;
    Ok("created")
}

/// `mail.relay.get` — the configured relay, the state of the local MTA, and the
/// DNS records the relay needs.
/// A unit struct, unlike the operations below it: this one only reads, so
/// there is nothing about it worth testing through a seam that [`view`] does
/// not already expose to a test directly.
pub struct RelayGet;

#[derive(Debug, Deserialize)]
pub struct RelayGetInput {}

#[async_trait]
impl TypedOperation for RelayGet {
    type Input = RelayGetInput;
    type Output = RelayView;

    const NAME: &'static str = "mail.relay.get";
    // Server-wide configuration holding a server-wide credential. Not a
    // tenant-visible read: the username and the sending domain together are
    // most of what somebody needs to guess at the credential's provider.
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let relay = ctx.db().mail_relay().await.map_err(UnihelmError::from)?;
        Ok(view(
            ctx,
            &mta::LiveHost,
            &mta::Layout::system(),
            relay.as_ref(),
            &paths::mail_dir(),
        )
        .await)
    }
}

// ---------------------------------------------------------------------------
// `mail.mta.status`
// ---------------------------------------------------------------------------

/// `mail.mta.status` — what this server actually does with a message today.
///
/// Its own operation rather than a corner of `mail.relay.get`, because the
/// answer is about the machine and not the relay row, and because the states
/// that matter most are the ones where the two disagree: a relay configured
/// with no MTA to use it, an MTA configured with no relay behind it, a
/// migration that stopped half way. Each of those has a sentence of its own,
/// and none of them rounds up to "mail works".
pub struct MtaStatus {
    host: Box<dyn mta::MtaHost>,
    layout: mta::Layout,
    legacy_dir: std::path::PathBuf,
}

impl MtaStatus {
    pub fn live() -> Self {
        Self {
            host: Box::new(mta::LiveHost),
            layout: mta::Layout::system(),
            legacy_dir: paths::mail_dir(),
        }
    }

    pub fn with_parts(
        host: Box<dyn mta::MtaHost>,
        layout: mta::Layout,
        legacy_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            host,
            layout,
            legacy_dir,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct MtaStatusInput {}

#[async_trait]
impl TypedOperation for MtaStatus {
    type Input = MtaStatusInput;
    type Output = mta::MtaState;

    const NAME: &'static str = "mail.mta.status";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let relay = ctx.db().mail_relay().await.map_err(UnihelmError::from)?;
        Ok(mta::state(
            ctx,
            self.host.as_ref(),
            &self.layout,
            relay.as_ref(),
            legacy_relay_files(&self.legacy_dir).len(),
        )
        .await)
    }
}

// ---------------------------------------------------------------------------
// `mail.mta.install`
// ---------------------------------------------------------------------------

/// `mail.mta.install` — install the local MTA, point it at the relay, and
/// retire the per-site msmtp files.
///
/// The whole migration, in one idempotent operation. Run twice, the second run
/// installs nothing, writes nothing and reloads nothing — but it *does* verify
/// the relay again, because a configuration that has not changed can still have
/// stopped working when somebody rotated a credential upstream, and a check
/// that only runs when something changes is a check that misses exactly that.
pub struct MtaInstall {
    host: Box<dyn mta::MtaHost>,
    probe: Box<dyn RelayProbe>,
    pools: Box<dyn PoolWriter>,
    layout: mta::Layout,
    legacy_dir: std::path::PathBuf,
}

impl MtaInstall {
    pub fn live() -> Self {
        Self {
            host: Box::new(mta::LiveHost),
            probe: Box::new(LiveProbe),
            pools: Box::new(LivePools),
            layout: mta::Layout::system(),
            legacy_dir: paths::mail_dir(),
        }
    }

    pub fn with_parts(
        host: Box<dyn mta::MtaHost>,
        probe: Box<dyn RelayProbe>,
        pools: Box<dyn PoolWriter>,
        layout: mta::Layout,
        legacy_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            host,
            probe,
            pools,
            layout,
            legacy_dir,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct MtaInstallInput {
    /// Take over a `main.cf` the panel did not write.
    ///
    /// Off by default and deliberately a decision: the package's own postinst
    /// always leaves a `main.cf` behind, so a foreign file is the ordinary
    /// first-install state — and it is also exactly what a machine already
    /// running somebody's mail server looks like. The displaced file is kept
    /// beside it either way.
    #[serde(default)]
    pub adopt: bool,
}

#[derive(Debug, Serialize)]
pub struct MtaInstallOutput {
    /// How far it got: `sites-migrated`, or `mta-configured` when some pools
    /// could not be re-rendered. The answer to "what state is this machine in
    /// now", which is the question after anything stops half way.
    pub reached: &'static str,
    /// The relay's own answer to a real message, from before anything changed.
    pub relay_check: smtp::SendReport,
    pub configuration: mta::ConfigureReport,
    pub sites: RewireTally,
    pub state: mta::MtaState,
}

#[async_trait]
impl TypedOperation for MtaInstall {
    type Input = MtaInstallInput;
    type Output = MtaInstallOutput;

    const NAME: &'static str = "mail.mta.install";
    const PERMISSION: Permission = Permission::ServerManage;
    // A task: a package install, three file renders, a service reload and one
    // pool re-render per PHP site. The per-site log lines are the only way to
    // see which site did not take, and on a busy box this is minutes.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        // Every step converges, and a re-run after an interruption picks up
        // whatever the last one did not finish.
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // 1. Is there anywhere for mail to go? A null client with no relay is a
        //    queue nobody drains: `sendmail` exits 0, PHP's `mail()` returns
        //    true, and every message sits in the spool until it is bounced days
        //    later. If it cannot be delivered, do not accept it.
        let relay = ctx
            .db()
            .mail_relay()
            .await
            .map_err(UnihelmError::from)?
            .filter(|r| r.is_live())
            .ok_or_else(|| {
                UnihelmError::new(
                    ErrorCode::Conflict,
                    "there is no relay for this server's mail to go to, so installing a local \
                     MTA would give it somewhere to accept messages and nowhere to send them. \
                     Configure the relay first with `mail.relay.set`, or switch the existing \
                     one back on, then run this again.",
                )
            })?;
        let password = open_password(ctx, &relay).await?;
        let hostname = self.host.hostname()?;

        // 2. Verify, before touching anything. A machine that fails here is
        //    left exactly as it was — still sending through whatever it was
        //    sending through — which is the difference between a refusal and a
        //    half-migrated server.
        ctx.log(format!(
            "asking {}:{} whether it accepts a message from this server, before changing \
             anything",
            relay.host, relay.port
        ));
        let relay_check = self.probe.probe(ctx, &relay, password.as_deref()).await;
        if !relay_check.delivered {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "the relay did not accept a message from this server, so nothing has been \
                     changed and this machine still sends mail exactly as it did. It stopped \
                     at {}: {}. {}",
                    relay_check.stage.as_str(),
                    relay_check.detail,
                    relay_check.stage.hint(),
                ),
            ));
        }
        ctx.log(format!(
            "the relay accepted a message ({}). Reached: relay-verified",
            relay_check.detail
        ));

        // 3. The package, with the SASL mechanism plugin it is useless without,
        //    and the debconf answers that stop the Debian postinst binding port
        //    25 on every address of the machine while we are still rendering.
        if self.host.installed(ctx).await? {
            ctx.log("the MTA is already installed");
        } else {
            self.host.install(ctx, &hostname).await?;
        }

        // 4. The three files, and a reload if any of them moved.
        let domains = hosted_domains(ctx).await?;
        let configuration = mta::configure(
            ctx,
            self.host.as_ref(),
            &mta::Settings {
                hostname: &hostname,
                relay: Some(&relay),
                password: password.as_deref(),
                trust_file: tls_trust_file(ctx.distro().info.family),
                domains: &domains,
                layout: &self.layout,
            },
            input.adopt,
        )
        .await?;

        // 5. Prove it is up before anything is taken away from the sites that
        //    are still working. A configured MTA that is not running accepts
        //    messages into a queue nothing drains, which is the state this
        //    operation exists to avoid creating.
        if !self.host.running(ctx).await? {
            return Err(UnihelmError::new(
                ErrorCode::ServiceUnavailable,
                "the MTA is installed and configured but is not running, so nothing has been \
                 taken away from the sites that still use the old per-site relay files — they \
                 keep sending. Look at `journalctl -u postfix`, then run this again.",
            ));
        }
        ctx.log("the MTA is running. Reached: mta-configured");

        // 6. Only now: re-render each pool, and delete each site's credential
        //    file after its own pool has stopped naming it.
        let sites = rewire_all_sites(ctx, self.pools.as_ref(), &self.legacy_dir).await?;
        ctx.log(format!(
            "{} pool(s) re-rendered, {} failed, {} not PHP, {} credential file(s) retired",
            sites.rewired, sites.failed, sites.skipped_not_php, sites.retired_files
        ));

        let state = mta::state(
            ctx,
            self.host.as_ref(),
            &self.layout,
            Some(&relay),
            legacy_relay_files(&self.legacy_dir).len(),
        )
        .await;
        let reached = if sites.failed == 0 {
            "sites-migrated"
        } else {
            "mta-configured"
        };
        ctx.log(format!("Reached: {reached}. {}", state.summary));

        Ok(MtaInstallOutput {
            reached,
            relay_check,
            configuration,
            sites,
            state,
        })
    }
}

// ---------------------------------------------------------------------------
// `mail.relay.set`
// ---------------------------------------------------------------------------

/// `mail.relay.set` — store the relay, and put the local MTA on it.
pub struct RelaySet {
    host: Box<dyn mta::MtaHost>,
    pools: Box<dyn PoolWriter>,
    layout: mta::Layout,
    legacy_dir: std::path::PathBuf,
}

impl RelaySet {
    pub fn live() -> Self {
        Self {
            host: Box::new(mta::LiveHost),
            pools: Box::new(LivePools),
            layout: mta::Layout::system(),
            legacy_dir: paths::mail_dir(),
        }
    }

    pub fn with_parts(
        host: Box<dyn mta::MtaHost>,
        pools: Box<dyn PoolWriter>,
        layout: mta::Layout,
        legacy_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            host,
            pools,
            layout,
            legacy_dir,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RelaySetInput {
    pub host: String,
    pub port: u16,
    pub tls_mode: TlsMode,
    #[serde(default)]
    pub username: Option<String>,
    /// Omit to keep the stored password; send an empty string to clear it.
    ///
    /// The distinction matters because the password is write-only: an operator
    /// editing the port of a working relay has no way to re-type a secret they
    /// cannot read, so "absent" has to mean "leave it alone".
    #[serde(default)]
    pub password: Option<String>,
    pub from_address: String,
    #[serde(default)]
    pub from_name: Option<String>,
    /// Omit to keep the stored setting; `true`/`false` to change it.
    ///
    /// Absent has to mean "leave it alone" for the same reason it does for
    /// `password` above: an operator who turned the relay off and later edits
    /// the port is not asking to start sending mail again, and this operation
    /// writes the whole row.
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct RelaySetOutput {
    pub relay: RelayView,
    /// What was written to the MTA, when there is a configured one to write to.
    pub configuration: Option<mta::ConfigureReport>,
    pub sites: RewireTally,
}

#[async_trait]
impl TypedOperation for RelaySet {
    type Input = RelaySetInput;
    type Output = RelaySetOutput;

    const NAME: &'static str = "mail.relay.set";
    const PERMISSION: Permission = Permission::ServerManage;
    // A task: it rewrites the MTA's configuration and reloads it, and on a
    // machine still carrying the old per-site wiring it re-renders one pool per
    // site. On a box with fifty sites that is well past the ~300 ms an
    // immediate operation is allowed, and the per-site log lines are the only
    // way to see which site did not take.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let host = parse_relay_host(&input.host)?;
        if input.port == 0 {
            return Err(
                UnihelmError::new(ErrorCode::InvalidPort, "the port must be 1–65535")
                    .with_field("port"),
            );
        }
        let from_address = parse_email("from_address", &input.from_address)?;
        let from_name = match input.from_name.as_deref() {
            Some(n) if !n.trim().is_empty() => Some(parse_display_name("from_name", n)?),
            _ => None,
        };
        let username = match input.username.as_deref() {
            Some(u) if !u.trim().is_empty() => Some(parse_display_name("username", u)?),
            _ => None,
        };

        // The refusal that matters most, and it happens before anything is
        // stored: a credential configured against a plaintext connection is a
        // credential that would go out in base64 on the wire (see
        // `smtp::send`). Refusing at configuration time means it is never
        // written to disk either.
        if username.is_some() && !input.tls_mode.is_encrypted() {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "a relay with a username needs TLS. base64 is an encoding, not encryption, so \
                 the panel will not store or send a credential for a plaintext relay — use \
                 STARTTLS (usually port 587) or implicit TLS (usually 465).",
            )
            .with_field("tls_mode"));
        }

        let existing = ctx.db().mail_relay().await.map_err(UnihelmError::from)?;
        let password_sealed = match input.password.as_deref() {
            // Absent: keep whatever is stored. The value is write-only, so the
            // UI cannot round-trip it.
            None => existing.as_ref().and_then(|r| r.password_sealed.clone()),
            // Explicitly empty: clear it.
            Some("") => None,
            Some(secret) => {
                if secret.len() > MAX_FIELD {
                    return Err(UnihelmError::new(
                        ErrorCode::InvalidInput,
                        "the relay password may be at most 255 characters",
                    )
                    .with_field("password"));
                }
                if let Err(detail) = smtp::reject_control_characters("password", secret) {
                    return Err(
                        UnihelmError::new(ErrorCode::InvalidInput, detail).with_field("password")
                    );
                }
                Some(ctx.master_key().seal_str(secret).map_err(|e| {
                    UnihelmError::internal(format!("the relay password could not be sealed: {e}"))
                })?)
            }
        };

        if username.is_none() && password_sealed.is_some() {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "a password without a username is not a credential any relay will accept; \
                 send an empty password to clear the stored one",
            )
            .with_field("username"));
        }

        let saved = ctx
            .db()
            .save_mail_relay(NewMailRelay {
                host,
                port: input.port,
                tls_mode: input.tls_mode,
                username,
                password_sealed,
                from_address,
                from_name,
                enabled: input
                    .enabled
                    .or_else(|| existing.as_ref().map(|r| r.enabled))
                    .unwrap_or(true),
            })
            .await
            .map_err(UnihelmError::from)?;

        // The MTA is rewritten only if the panel configured it. On a machine
        // that has not been migrated, the pools still name the per-site msmtp
        // files and those files are what its mail depends on — re-rendering
        // anything here would take the directive away and leave nothing behind
        // it.
        let mut configuration = None;
        let mut sites = RewireTally::default();
        if self.layout.state().is_ours() {
            let password = open_password(ctx, &saved).await?;
            let hostname = self.host.hostname()?;
            let domains = hosted_domains(ctx).await?;
            configuration = Some(
                mta::configure(
                    ctx,
                    self.host.as_ref(),
                    &mta::Settings {
                        hostname: &hostname,
                        relay: Some(&saved),
                        password: password.as_deref(),
                        trust_file: tls_trust_file(ctx.distro().info.family),
                        domains: &domains,
                        layout: &self.layout,
                    },
                    // Never here. Taking over a `main.cf` somebody else wrote is
                    // a decision an operator makes once, at `mail.mta.install`,
                    // and not a side effect of saving a relay.
                    false,
                )
                .await?,
            );
            if saved.is_live() {
                ctx.log(
                    "the local MTA now relays through this relay. Send one message with \
                     `mail.relay.test` to confirm it accepts the credential — the panel wrote \
                     what you asked for and cannot know whether the relay agrees.",
                );
            } else {
                ctx.log(
                    "the relay is switched off, so the MTA now refuses every message as it is \
                     submitted rather than queueing it somewhere nothing drains. Nothing on \
                     this server will send until the relay is switched back on.",
                );
            }
            // Sweeps anything an interrupted earlier migration left behind. On
            // an already-migrated machine this finds nothing and re-renders the
            // pools it already rendered, which is what idempotent looks like.
            sites = rewire_all_sites(ctx, self.pools.as_ref(), &self.legacy_dir).await?;
        } else {
            ctx.log(
                "the relay is stored. This server has no local MTA configured, so nothing was \
                 re-rendered and the sites still carrying the old per-site msmtp wiring keep \
                 using it. Run `mail.mta.install` to move this machine onto the local MTA — it \
                 verifies the relay first and re-renders the pools itself.",
            );
        }

        Ok(RelaySetOutput {
            relay: view(
                ctx,
                self.host.as_ref(),
                &self.layout,
                Some(&saved),
                &self.legacy_dir,
            )
            .await,
            configuration,
            sites,
        })
    }
}

// ---------------------------------------------------------------------------
// `mail.relay.test`
// ---------------------------------------------------------------------------

/// `mail.relay.test` — hand a real message to the relay and say what happened.
///
/// The relay, not the MTA: this is the panel's own SMTP client talking to the
/// submission service, so it answers "is this credential right" without waiting
/// on a queue. What it does not prove is that the *local* MTA is wired up —
/// `mail.mta.status` is that question, and it has its own answer.
pub struct RelayTest;

#[derive(Debug, Deserialize)]
pub struct RelayTestInput {
    /// Where to send it. Defaults to the relay's own `from_address`, which is
    /// the one address the relay is certainly willing to accept mail *from*
    /// and usually willing to deliver *to*.
    #[serde(default)]
    pub to: Option<String>,
}

#[async_trait]
impl TypedOperation for RelayTest {
    type Input = RelayTestInput;
    type Output = smtp::SendReport;

    const NAME: &'static str = "mail.relay.test";
    const PERMISSION: Permission = Permission::ServerManage;
    // Immediate, with a conversation budget below the IPC call timeout. A test
    // whose answer arrives in the task drawer thirty seconds later is a test
    // nobody reads — the same reasoning as `dns.check`.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let relay = ctx
            .db()
            .mail_relay()
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| {
                UnihelmError::new(
                    ErrorCode::NotFound,
                    "no relay is configured; set one with `mail.relay.set` first",
                )
            })?;

        let to = match input.to.as_deref() {
            Some(address) => parse_email("to", address)?,
            None => relay.from_address.clone(),
        };

        let password = open_password(ctx, &relay).await?;
        let panel_name: String = ctx
            .db()
            .get_setting_or(
                unihelm_db::settings::keys::PANEL_NAME,
                "Unihelm".to_string(),
            )
            .await;

        Ok(send_through_relay(
            &relay,
            password.as_deref(),
            &to,
            format!("{panel_name}: relay test"),
            test_body(&relay, &panel_name),
        )
        .await)
    }
}

fn test_body(relay: &MailRelay, panel_name: &str) -> String {
    format!(
        "This is a test message from {panel_name}.\n\
         \n\
         It was sent through the configured relay to prove that the panel can hand a message \
         over. Receiving it means the host, the port, the TLS mode and the credential all work.\n\
         \n\
         Relay:  {}:{} ({})\n\
         Sender: {}\n\
         \n\
         It does not prove that mail from this server reaches inboxes — that depends on SPF, \
         DKIM and DMARC, which the panel surfaces as guidance and does not manage. It also does \
         not prove this server's own mail transfer agent is wired up: `mail.mta.status` answers \
         that.\n",
        relay.host,
        relay.port,
        relay.tls_mode.as_str(),
        relay.from_address,
    )
}

#[cfg(test)]
mod tests;
