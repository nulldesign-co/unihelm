//! Outbound mail, relay-only (spec §11.18).
//!
//! # What this is, and firmly what it is not
//!
//! Unihelm v1 runs **no mail server**. It stores the address of somebody else's
//! submission service, points every PHP site's `mail()` at it, and can send one
//! test message to prove the whole path works. There are no mailboxes, no
//! inbound mail, no domains, no aliases, and no queue. The full Stalwart stack
//! is Phase 5 and explicitly optional; nothing here is a partial version of it.
//!
//! That boundary is the honest one to hold. A panel that ships "email" and
//! means "an SMTP client" is why operators end up debugging why their customer
//! cannot receive anything, and a half-built MTA on a shared box is a security
//! problem with a mail icon.
//!
//! # SPF, DKIM and DMARC are *guidance*
//!
//! The panel does not manage them and does not claim to. `mail.relay.get`
//! returns the records the configured relay needs, in the same advisory shape
//! `dns.check` uses — a structured record, a purpose, and a sentence — and every
//! one of them carries `managed: false`. DKIM in particular cannot be generated
//! here at all: the key pair belongs to the relay, and only the relay can say
//! what the selector is. Printing a made-up DKIM record would be worse than
//! printing none.
//!
//! # The credential is readable by the tenant, and that is inherent
//!
//! PHP's `mail()` runs as the site's own Linux user (spec §5), so whatever
//! configuration the sendmail shim reads is configuration that user can read.
//! There is no arrangement in which a tenant can send mail through an
//! authenticated relay and cannot recover the credential; the only way out is a
//! local submission agent that holds the secret, which is an MTA, which is
//! Phase 5.
//!
//! What the panel does about it:
//!
//! - the per-site file is `0640`, owned `root:<that tenant's group>`, so the
//!   exposure is one tenant per file rather than every user on the box;
//! - the file is under `/etc/unihelm/mail`, not in the tenant's home, so a
//!   tenant can read it but never *edit* it — an editable copy would let them
//!   redirect their site's mail to a relay of their own while still sending as
//!   the operator's domain;
//! - the operation output and the documentation both say so, so an operator
//!   chooses a send-only credential scoped to this server on purpose rather
//!   than discovering the exposure later.
//!
//! # The shim is a configuration file, not a script
//!
//! `sendmail_path` points at `msmtp` with an argv of flags and a `--file=`
//! pointing at the per-site configuration this module renders. The panel never
//! generates a shell script for PHP to run: a rendered script would be a shell
//! string the panel causes to be executed, which is exactly the category
//! spec §12 rule 2 removes. msmtp is the relay agent because it is a
//! single-binary SMTP client with no daemon, no queue directory and no setuid
//! bit — the smallest thing that can be a `sendmail` for a tenant.

pub mod smtp;

use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_config::apply::ApplyRequest;
use unihelm_config::{CommentStyle, ManagedFile, paths};
use unihelm_core::{ErrorCode, LinuxUser, Permission, Result, TenantScope, UnihelmError};
use unihelm_db::{MailRelay, NewMailRelay, TlsMode};
use unihelm_distro::Family;

use crate::registry::{Execution, OpContext, TypedOperation};
use crate::services::{NoReload, SkipValidation};

/// The sendmail-compatible client the shim runs.
///
/// Resolved against `Cmd`'s trusted binary directories rather than `PATH`, for
/// the same reason every other program in this codebase is: the agent is root,
/// and a writable directory early in `PATH` would otherwise decide what
/// "sendmail" means.
pub const SENDMAIL_AGENT: &str = "msmtp";

/// How long msmtp waits on the relay before giving up, in seconds.
///
/// Rendered into the per-site configuration. msmtp's own default is to wait
/// indefinitely, which turns a dead relay into a wedged PHP worker and, a few
/// requests later, into a site that does not answer at all.
const AGENT_TIMEOUT_SECONDS: u32 = 20;

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

// ---------------------------------------------------------------------------
// the shim
// ---------------------------------------------------------------------------

/// Where the distribution keeps its trusted CA bundle.
///
/// msmtp needs a path; it has no compiled-in root store. Getting this wrong
/// does not silently disable verification — msmtp refuses to connect — so the
/// failure mode of a bad guess here is "mail does not send", never "mail sends
/// unverified".
pub const fn tls_trust_file(family: Family) -> &'static str {
    match family {
        Family::Rhel => "/etc/pki/tls/certs/ca-bundle.crt",
        Family::Debian => "/etc/ssl/certs/ca-certificates.crt",
    }
}

/// Is the sendmail agent installed, and where?
pub fn sendmail_agent_path() -> Option<PathBuf> {
    unihelm_distro::exec::resolve_program(SENDMAIL_AGENT).ok()
}

/// What `sendmail_path` becomes for one site.
///
/// `-t` makes msmtp read the recipients from the message's own headers, which
/// is what PHP's `mail()` expects of a sendmail. There is deliberately no
/// `--read-envelope-from`: the envelope sender stays the one the operator
/// configured, because SPF is evaluated against the envelope and a relay will
/// reject a sender it is not authorised for however the application chose to
/// address the message.
///
/// # This one string does reach a shell, and that is PHP's doing
///
/// `mail()` runs `sendmail_path` through `popen(3)`, which is `/bin/sh -c`.
/// Nothing in this codebase executes it — spec §12 rule 2 still holds for
/// everything the panel runs — but the string is worth reading as though a
/// shell will see it, because one will.
///
/// Every byte of it is panel-controlled: `agent` is an absolute path
/// [`unihelm_distro::exec::resolve_program`] found in a fixed list of trusted
/// directories, and the only variable part is `domain`, which is a validated
/// `Domain` by the time a site exists — letters, digits, dots and hyphens, so
/// there is no character in it a shell would treat as anything but a filename.
/// A future caller passing an unvalidated string here would be the bug; the
/// signature takes `&str` because `Site::domain` is stored as one, and the
/// validation happened when the site was created.
pub fn sendmail_path(agent: &std::path::Path, domain: &str) -> String {
    format!(
        "{} --file={} -t",
        agent.display(),
        paths::mail_site_config(domain).display()
    )
}

/// Write one site's relay configuration and hand back its `sendmail_path`.
///
/// Returns `None` when there is nothing to point PHP at — no relay, the relay
/// switched off, or no agent installed — having removed any file a previous
/// configuration left behind. The caller renders the pool either way, so
/// turning the relay off actually takes `sendmail_path` back out of the pool
/// rather than leaving a directive pointing at a file that is gone.
pub async fn write_site_relay(
    ctx: &OpContext,
    domain: &str,
    linux_user: &LinuxUser,
    relay: Option<&MailRelay>,
) -> Result<Option<String>> {
    let path = paths::mail_site_config(domain);

    let Some(relay) = relay.filter(|r| r.is_live()) else {
        remove_site_relay(&path)?;
        return Ok(None);
    };
    let Some(agent) = sendmail_agent_path() else {
        remove_site_relay(&path)?;
        ctx.log(format!(
            "`{SENDMAIL_AGENT}` is not installed, so {domain} has no way to hand a message to \
             the relay; leaving PHP's sendmail_path unset rather than pointing it at a missing \
             program"
        ));
        return Ok(None);
    };

    // Opened here and nowhere else on this path. The plaintext exists only for
    // the length of the render.
    let password = match &relay.password_sealed {
        Some(sealed) => Some(ctx.master_key().open_str(sealed).map_err(|e| {
            UnihelmError::internal(format!(
                "the stored relay password could not be opened: {e}"
            ))
        })?),
        None => None,
    };

    std::fs::create_dir_all(paths::mail_dir()).map_err(|e| {
        UnihelmError::internal(format!("could not create the mail config directory: {e}"))
    })?;

    ctx.config()
        .apply(ApplyRequest {
            file: ManagedFile {
                path: path.clone(),
                // Readable by the tenant that runs msmtp, by nobody else. The
                // group is set below; until it is, the file is root-only,
                // which fails closed.
                mode: 0o640,
                comment_style: CommentStyle::Hash,
            },
            template: "mail/msmtprc",
            context: serde_json::json!({ "mail": {
                "site_domain": domain,
                "group": linux_user.as_str(),
                "host": relay.host,
                "port": relay.port,
                "tls_mode": relay.tls_mode.as_str(),
                "tls_trust_file": tls_trust_file(ctx.distro().info.family),
                "username": relay.username,
                "password": password,
                "from_address": relay.from_address,
                "timeout_seconds": AGENT_TIMEOUT_SECONDS,
            }}),
            // Its own lock: these files belong to no service, and sharing
            // nginx's or FPM's key would serialise mail renders behind vhost
            // renders for no reason.
            service: "unihelm-mail",
            // Nothing validates an msmtp configuration without sending mail,
            // and nothing needs reloading: msmtp is started fresh by PHP for
            // every message.
            validator: &SkipValidation,
            reloader: &NoReload,
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;

    chown_to_tenant_group(&path, linux_user)?;
    Ok(Some(sendmail_path(&agent, domain)))
}

fn remove_site_relay(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(UnihelmError::internal(format!(
            "could not remove {}: {e}",
            path.display()
        ))),
    }
}

/// Give the file to `root:<tenant group>` so exactly one tenant can read it.
///
/// A best-effort step by design: on a development instance the group does not
/// exist and the process is not root, and failing a whole relay configuration
/// over that would be wrong. What is *not* best-effort is the mode — the file
/// is written 0640 before this runs, so a failure here leaves it root-only,
/// which breaks that site's mail rather than exposing the credential.
fn chown_to_tenant_group(path: &std::path::Path, linux_user: &LinuxUser) -> Result<()> {
    let Some(gid) = group_id(linux_user.as_str()) else {
        tracing::warn!(
            user = linux_user.as_str(),
            "no group for the tenant; the relay config stays root-only and that site cannot send"
        );
        return Ok(());
    };
    if let Err(e) = std::os::unix::fs::chown(path, Some(0), Some(gid)) {
        tracing::warn!(path = %path.display(), error = %e, "could not set the relay config group");
    }
    Ok(())
}

/// The gid of a group, via `getgrnam(3)`.
fn group_id(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `getgrnam` takes a NUL-terminated string and returns a pointer
    // into a static buffer or null. The name is a validated `LinuxUser`, the
    // pointer is checked before it is read, and the `gr_gid` field is copied
    // out immediately rather than held.
    let entry = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if entry.is_null() {
        return None;
    }
    Some(unsafe { (*entry).gr_gid })
}

// ---------------------------------------------------------------------------
// wiring every site
// ---------------------------------------------------------------------------

/// The seam between "decide what every site's mail configuration should be"
/// and "write files under /etc and reload PHP-FPM".
///
/// Exists for the same reason `plan::VhostSwitcher` does: the deciding half is
/// worth testing and the writing half cannot be, in a unit test, on a machine
/// with no PHP-FPM.
#[async_trait]
pub trait PoolWriter: Send + Sync {
    async fn rewrite(
        &self,
        ctx: &OpContext,
        site: &unihelm_db::Site,
        linux_user: &LinuxUser,
        relay: Option<&MailRelay>,
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
        relay: Option<&MailRelay>,
    ) -> Result<()> {
        let sendmail = write_site_relay(ctx, &site.domain, linux_user, relay).await?;
        let Some(version) = site.php_version else {
            return Ok(());
        };
        crate::site::render_pool_with_mail(ctx, site, linux_user, version, sendmail).await
    }
}

/// Point every PHP site at the relay, or take the pointer away.
///
/// Every site is attempted even when one fails: stopping at the first failure
/// would leave the rest both un-wired *and* untried. The tally comes back with
/// the first error, and because the whole operation is idempotent a re-run
/// converges the stragglers — the same shape as `plan::switch_all_vhosts`, and
/// for the same reason.
pub async fn rewire_all_sites(
    ctx: &OpContext,
    pools: &dyn PoolWriter,
    relay: Option<&MailRelay>,
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

        match pools.rewrite(ctx, &site, &linux_user, relay).await {
            Ok(()) => {
                tally.rewired += 1;
                ctx.log(format!("mail configuration updated for {}", site.domain));
            }
            Err(e) => {
                tally.failed += 1;
                ctx.log(format!(
                    "could not update the mail configuration for {}: {e}",
                    site.domain
                ));
                first_error.get_or_insert(e);
            }
        }
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
            "These records are for `{domain}`, the domain the relay sends as. The SPF mechanism \
             is the one `{}` publishes for its customers. DKIM comes from the relay's dashboard; \
             Unihelm neither signs nor manages any of these.",
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
    /// Whether the sendmail agent is installed. `false` means sites cannot
    /// send however well the relay is configured, which is worth its own field
    /// rather than a note buried in a message.
    pub agent_installed: bool,
    pub agent: &'static str,
    /// The exposure this design cannot remove; see the module docs.
    pub credential_note: &'static str,
    pub dns: DnsAdvisory,
}

const CREDENTIAL_NOTE: &str = "PHP's mail() runs as each site's own Linux user, so that user can read the relay \
     credential for their own site (and no other site's). Use a send-only credential scoped \
     to this server, and rotate it here rather than reusing an account password.";

fn view(relay: Option<&MailRelay>) -> RelayView {
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
        agent_installed: sendmail_agent_path().is_some(),
        agent: SENDMAIL_AGENT,
        credential_note: CREDENTIAL_NOTE,
        dns: dns_advisory(relay),
    }
}

/// `mail.relay.get` — the configured relay, and the DNS records it needs.
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
        Ok(view(relay.as_ref()))
    }
}

// ---------------------------------------------------------------------------
// `mail.relay.set`
// ---------------------------------------------------------------------------

/// `mail.relay.set` — store the relay and point every PHP site at it.
pub struct RelaySet {
    pools: Box<dyn PoolWriter>,
}

impl RelaySet {
    pub fn live() -> Self {
        Self {
            pools: Box::new(LivePools),
        }
    }

    pub fn with_pools(pools: Box<dyn PoolWriter>) -> Self {
        Self { pools }
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
    pub sites: RewireTally,
}

#[async_trait]
impl TypedOperation for RelaySet {
    type Input = RelaySetInput;
    type Output = RelaySetOutput;

    const NAME: &'static str = "mail.relay.set";
    const PERMISSION: Permission = Permission::ServerManage;
    // A task: this rewrites one configuration file per site and reloads
    // PHP-FPM once per PHP version. On a box with fifty sites that is well
    // past the ~300 ms an immediate operation is allowed, and the per-site log
    // lines are the only way to see which site did not take.
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

        if !sendmail_agent_path().is_some() {
            ctx.log(format!(
                "`{SENDMAIL_AGENT}` is not installed. The relay is stored, but PHP has no \
                 program to hand a message to, so sendmail_path stays unset — install it \
                 (`{SENDMAIL_AGENT}` is packaged on both families; EPEL supplies it on RHEL) \
                 and re-run this operation."
            ));
        }

        let sites = rewire_all_sites(ctx, self.pools.as_ref(), Some(&saved)).await?;
        ctx.log(format!(
            "{} site(s) wired to the relay, {} failed, {} not PHP",
            sites.rewired, sites.failed, sites.skipped_not_php
        ));

        Ok(RelaySetOutput {
            relay: view(Some(&saved)),
            sites,
        })
    }
}

// ---------------------------------------------------------------------------
// `mail.relay.test`
// ---------------------------------------------------------------------------

/// `mail.relay.test` — hand a real message to the relay and say what happened.
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

        let credentials = match (&relay.username, &relay.password_sealed) {
            (Some(user), Some(sealed)) => {
                let password = ctx.master_key().open_str(sealed).map_err(|e| {
                    UnihelmError::internal(format!(
                        "the stored relay password could not be opened: {e}"
                    ))
                })?;
                Some(smtp::Credentials::new(user, password))
            }
            _ => None,
        };

        let panel_name: String = ctx
            .db()
            .get_setting_or(
                unihelm_db::settings::keys::PANEL_NAME,
                "Unihelm".to_string(),
            )
            .await;

        let report = smtp::send(
            &smtp::Endpoint {
                host: relay.host.clone(),
                port: relay.port,
                tls_mode: relay.tls_mode,
            },
            credentials.as_ref(),
            &smtp::Message {
                from: relay.from_address.clone(),
                from_name: relay.from_name.clone(),
                to,
                subject: format!("{panel_name}: relay test"),
                body: test_body(&relay, &panel_name),
            },
            // The EHLO name. The relay's own hostname is the wrong answer and
            // a bare `localhost` is refused by some relays; the sending domain
            // is the closest thing this server can honestly claim to be.
            &ehlo_name(&relay),
        )
        .await;

        Ok(report)
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
         DKIM and DMARC, which the panel surfaces as guidance and does not manage.\n",
        relay.host,
        relay.port,
        relay.tls_mode.as_str(),
        relay.from_address,
    )
}

#[cfg(test)]
mod tests;
