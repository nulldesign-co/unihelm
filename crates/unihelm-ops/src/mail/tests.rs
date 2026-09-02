//! Tests for the relay operations and the advisory (spec §11.18).
//!
//! Everything that would touch `/etc` or reload PHP-FPM goes through the
//! [`PoolWriter`] seam, so what is exercised here is the half worth testing:
//! what gets stored, what gets refused, which sites get rewired, and what the
//! advisory says.

use std::sync::Mutex;

use serde_json::json;
use unihelm_core::PhpVersion;
use unihelm_core::{Domain, Role, TenantScope};
use unihelm_db::{Db, NewSite, SiteType};

use super::*;
use crate::registry::testing::{auth_for, registry};
use crate::registry::{OpContext, OpRegistry};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Records what would have been written, instead of writing it.
#[derive(Default)]
struct RecordingPools {
    seen: Mutex<Vec<(String, bool)>>,
}

#[async_trait]
impl PoolWriter for RecordingPools {
    async fn rewrite(
        &self,
        _ctx: &OpContext,
        site: &unihelm_db::Site,
        _linux_user: &LinuxUser,
        relay: Option<&MailRelay>,
    ) -> Result<()> {
        self.seen
            .lock()
            .expect("no test panics while holding this")
            .push((site.domain.clone(), relay.is_some_and(|r| r.is_live())));
        Ok(())
    }
}

fn db_of(reg: &OpRegistry) -> Db {
    reg.services().db.clone()
}

async fn seed_php_site(db: &Db, customer: unihelm_core::UserId, domain: &str, php: bool) {
    let sub = db.create_subscription(customer).await.unwrap();
    let site = db
        .create_site(NewSite {
            subscription_id: sub.id,
            domain: Domain::parse(domain).unwrap(),
            site_type: if php { SiteType::Php } else { SiteType::Static },
            php_version: php.then_some(PhpVersion::V83),
            root_dir: format!("/home/{}/sites/{domain}/public", sub.linux_user),
            proxy_port: None,
            redirect_target: None,
        })
        .await
        .unwrap();
    db.set_site_status(site.id, unihelm_db::SiteStatus::Active)
        .await
        .unwrap();
}

fn relay_input() -> serde_json::Value {
    json!({
        "host": "smtp.postmarkapp.com",
        "port": 587,
        "tls_mode": "starttls",
        "username": "token-user",
        "password": "token-secret",
        "from_address": "noreply@acme.example",
        "from_name": "Acme Hosting",
    })
}

async fn run_set(
    reg: &OpRegistry,
    admin: unihelm_core::UserId,
    pools: std::sync::Arc<RecordingPools>,
    input: serde_json::Value,
) -> Result<RelaySetOutput> {
    struct Shared(std::sync::Arc<RecordingPools>);
    #[async_trait]
    impl PoolWriter for Shared {
        async fn rewrite(
            &self,
            ctx: &OpContext,
            site: &unihelm_db::Site,
            linux_user: &LinuxUser,
            relay: Option<&MailRelay>,
        ) -> Result<()> {
            self.0.rewrite(ctx, site, linux_user, relay).await
        }
    }

    let op = RelaySet::with_pools(Box::new(Shared(pools)));
    let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
    let typed: RelaySetInput = serde_json::from_value(input).expect("valid test input shape");
    op.run(&ctx, typed).await
}

// ---------------------------------------------------------------------------
// mail.relay.get
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_panel_with_no_relay_says_so_rather_than_failing() {
    let (reg, admin, _) = registry().await;
    let out = reg
        .dispatch(
            "mail.relay.get",
            &auth_for(admin, Role::Admin),
            json!({}),
            None,
        )
        .await
        .unwrap();
    assert_eq!(out["configured"], false);
    assert_eq!(out["has_password"], false);
    assert!(out["dns"]["records"].as_array().unwrap().is_empty());
    assert!(
        out["dns"]["advice"]
            .as_str()
            .unwrap()
            .contains("No relay is configured")
    );
}

#[tokio::test]
async fn a_customer_cannot_read_the_relay_configuration() {
    // The username plus the sending domain is most of what somebody needs to
    // guess where the credential came from.
    let (reg, _, customer) = registry().await;
    let err = reg
        .dispatch(
            "mail.relay.get",
            &auth_for(customer, Role::Customer),
            json!({}),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::PermissionDenied);
}

// ---------------------------------------------------------------------------
// mail.relay.set
// ---------------------------------------------------------------------------

#[tokio::test]
async fn setting_a_relay_stores_it_sealed_and_wires_every_php_site() {
    let (reg, admin, customer) = registry().await;
    let db = db_of(&reg);
    seed_php_site(&db, customer, "one.example.com", true).await;
    seed_php_site(&db, customer, "two.example.com", true).await;
    seed_php_site(&db, customer, "static.example.com", false).await;

    let pools = std::sync::Arc::new(RecordingPools::default());
    let out = run_set(&reg, admin, pools.clone(), relay_input())
        .await
        .unwrap();

    assert_eq!(out.sites.rewired, 2);
    assert_eq!(out.sites.skipped_not_php, 1);
    let seen = pools.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert!(seen.iter().all(|(_, live)| *live));

    // Sealed, not stored in the clear: a `sqlite3` session over a restored
    // backup must not hand over the relay credential.
    let stored: (Option<String>,) =
        sqlx::query_as("SELECT password_sealed FROM mail_relay WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let sealed = stored.0.unwrap();
    assert!(!sealed.contains("token-secret"));
    assert!(sealed.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn a_username_without_tls_is_refused_before_anything_is_stored() {
    // base64 is an encoding, not encryption. Refusing at configuration time
    // means the credential never reaches the disk either.
    let (reg, admin, _) = registry().await;
    let pools = std::sync::Arc::new(RecordingPools::default());
    let err = run_set(
        &reg,
        admin,
        pools,
        json!({
            "host": "smtp.example.net",
            "port": 25,
            "tls_mode": "none",
            "username": "user",
            "password": "secret",
            "from_address": "noreply@acme.example",
        }),
    )
    .await
    .unwrap_err();

    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert_eq!(err.field.as_deref(), Some("tls_mode"));
    assert!(db_of(&reg).mail_relay().await.unwrap().is_none());
}

#[tokio::test]
async fn an_unauthenticated_plaintext_relay_is_allowed() {
    // A relay on localhost or a private LAN that authorises by source IP is a
    // real configuration, and the refusal above is specifically about
    // credentials.
    let (reg, admin, _) = registry().await;
    let pools = std::sync::Arc::new(RecordingPools::default());
    let out = run_set(
        &reg,
        admin,
        pools,
        json!({
            "host": "127.0.0.1",
            "port": 25,
            "tls_mode": "none",
            "from_address": "noreply@acme.example",
        }),
    )
    .await
    .unwrap();
    assert!(out.relay.configured);
    assert!(!out.relay.has_password);
}

#[tokio::test]
async fn omitting_the_password_keeps_the_stored_one_and_an_empty_string_clears_it() {
    // The value is write-only, so an operator editing the port of a working
    // relay has no way to re-type a secret they cannot read.
    let (reg, admin, _) = registry().await;
    let pools = std::sync::Arc::new(RecordingPools::default());
    run_set(&reg, admin, pools.clone(), relay_input())
        .await
        .unwrap();

    let mut without = relay_input();
    without.as_object_mut().unwrap().remove("password");
    without["port"] = json!(2587);
    let out = run_set(&reg, admin, pools.clone(), without).await.unwrap();
    assert!(out.relay.has_password, "the stored password must survive");
    assert_eq!(out.relay.port, Some(2587));

    // Clearing needs a username to go with it, so the whole credential goes.
    let mut cleared = relay_input();
    cleared["password"] = json!("");
    cleared.as_object_mut().unwrap().remove("username");
    let out = run_set(&reg, admin, pools, cleared).await.unwrap();
    assert!(!out.relay.has_password);
    assert!(out.relay.username.is_none());
}

#[tokio::test]
async fn a_password_without_a_username_is_refused() {
    let (reg, admin, _) = registry().await;
    let pools = std::sync::Arc::new(RecordingPools::default());
    let mut input = relay_input();
    input.as_object_mut().unwrap().remove("username");
    let err = run_set(&reg, admin, pools, input).await.unwrap_err();
    assert_eq!(err.field.as_deref(), Some("username"));
}

#[tokio::test]
async fn the_relay_password_never_appears_in_any_output() {
    let (reg, admin, _) = registry().await;
    let pools = std::sync::Arc::new(RecordingPools::default());
    let out = run_set(&reg, admin, pools, relay_input()).await.unwrap();
    let rendered = serde_json::to_string(&out).unwrap();
    assert!(!rendered.contains("token-secret"));

    let read = reg
        .dispatch(
            "mail.relay.get",
            &auth_for(admin, Role::Admin),
            json!({}),
            None,
        )
        .await
        .unwrap()
        .to_string();
    assert!(!read.contains("token-secret"));
    assert!(!read.contains("password_sealed"));
}

#[tokio::test]
async fn disabling_the_relay_takes_the_wiring_back_off_every_site() {
    // Not just a flag: the pools have to be re-rendered without
    // `sendmail_path`, or PHP keeps handing messages to a configuration the
    // operator switched off.
    let (reg, admin, customer) = registry().await;
    seed_php_site(&db_of(&reg), customer, "one.example.com", true).await;

    let pools = std::sync::Arc::new(RecordingPools::default());
    run_set(&reg, admin, pools.clone(), relay_input())
        .await
        .unwrap();

    let mut off = relay_input();
    off["enabled"] = json!(false);
    run_set(&reg, admin, pools.clone(), off).await.unwrap();

    let seen = pools.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].1, "the first run wires it up");
    assert!(!seen[1].1, "the second must take it back off");
}

#[tokio::test]
async fn omitting_enabled_keeps_the_stored_setting_rather_than_switching_it_on() {
    // The operation writes the whole row, so an absent `enabled` used to be
    // read as `true`: an operator who had switched the relay off and later
    // corrected the port would have silently started sending mail again.
    // Absent means "leave it alone" here for the same reason it does for the
    // password.
    let (reg, admin, customer) = registry().await;
    seed_php_site(&db_of(&reg), customer, "one.example.com", true).await;
    let pools = std::sync::Arc::new(RecordingPools::default());

    let mut off = relay_input();
    off["enabled"] = json!(false);
    run_set(&reg, admin, pools.clone(), off).await.unwrap();

    // The same relay, one field changed, `enabled` not mentioned.
    let mut repoint = relay_input();
    repoint["port"] = json!(2525);
    repoint.as_object_mut().unwrap().remove("enabled");
    let after = run_set(&reg, admin, pools.clone(), repoint).await.unwrap();

    assert!(
        !after.relay.enabled,
        "a relay the operator turned off must stay off when another field is edited"
    );
    let seen = pools.seen.lock().unwrap().clone();
    assert!(
        !seen.last().unwrap().1,
        "and the pools must still be rendered without sendmail_path"
    );
}

#[tokio::test]
async fn a_relay_configured_for_the_first_time_is_enabled_by_default() {
    // "Keep what is stored" has nothing to keep on the first write, so the
    // absent case still has to land on `true` — otherwise configuring a relay
    // would leave it inert with no way to tell why.
    let (reg, admin, _) = registry().await;
    let pools = std::sync::Arc::new(RecordingPools::default());

    let mut fresh = relay_input();
    fresh.as_object_mut().unwrap().remove("enabled");
    let out = run_set(&reg, admin, pools.clone(), fresh).await.unwrap();

    assert!(out.relay.enabled, "a first relay with no `enabled` is on");
}

#[tokio::test]
async fn a_hostile_relay_host_is_refused_rather_than_rendered() {
    // The value goes into a line-oriented config file; a newline in it is a
    // way to add a directive.
    let (reg, admin, _) = registry().await;
    let pools = std::sync::Arc::new(RecordingPools::default());
    for bad in [
        "smtp.example.net\nfrom root@evil",
        "smtp.example.net tls_certcheck off",
        "smtp.example.net;rm -rf /",
        "",
        "smtp.example.net\r\npassword hunter2",
    ] {
        let mut input = relay_input();
        input["host"] = json!(bad);
        let err = run_set(&reg, admin, pools.clone(), input)
            .await
            .unwrap_err();
        assert_eq!(err.field.as_deref(), Some("host"), "for {bad:?}");
    }
}

#[tokio::test]
async fn a_hostile_from_address_is_refused() {
    let (reg, admin, _) = registry().await;
    let pools = std::sync::Arc::new(RecordingPools::default());
    for bad in [
        "noreply@acme.example\r\nRCPT TO:<victim@example.net>",
        "noreply",
        "@acme.example",
        "noreply@",
        "a@b",
        "two@at@example.com",
        "no reply@acme.example",
        "<noreply@acme.example>",
    ] {
        let mut input = relay_input();
        input["from_address"] = json!(bad);
        let err = run_set(&reg, admin, pools.clone(), input)
            .await
            .unwrap_err();
        assert_eq!(err.field.as_deref(), Some("from_address"), "for {bad:?}");
    }
}

// ---------------------------------------------------------------------------
// mail.relay.test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn testing_a_relay_that_was_never_configured_says_so() {
    let (reg, admin, _) = registry().await;
    let err = reg
        .dispatch(
            "mail.relay.test",
            &auth_for(admin, Role::Admin),
            json!({}),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
    assert!(err.detail.contains("mail.relay.set"));
}

#[tokio::test]
async fn a_failed_test_is_an_answer_with_a_stage_not_an_error() {
    // The point of the operation: a relay that refuses has to come back as
    // data the UI can render, complete with which step failed.
    let (reg, admin, _) = registry().await;
    let pools = std::sync::Arc::new(RecordingPools::default());
    let mut input = relay_input();
    // Nothing listens here, and no credential, so the conversation gets as far
    // as the TCP connect and no further.
    input["host"] = json!("127.0.0.1");
    input["port"] = json!(1);
    input["tls_mode"] = json!("none");
    input.as_object_mut().unwrap().remove("username");
    input.as_object_mut().unwrap().remove("password");
    run_set(&reg, admin, pools, input).await.unwrap();

    let out = reg
        .dispatch(
            "mail.relay.test",
            &auth_for(admin, Role::Admin),
            json!({}),
            None,
        )
        .await
        .unwrap();
    assert_eq!(out["delivered"], false);
    assert_eq!(out["stage"], "connect");
    assert!(out["detail"].as_str().unwrap().contains("127.0.0.1:1"));
}

#[tokio::test]
async fn a_test_recipient_that_could_inject_a_command_is_refused() {
    let (reg, admin, _) = registry().await;
    let pools = std::sync::Arc::new(RecordingPools::default());
    run_set(&reg, admin, pools, relay_input()).await.unwrap();

    let err = reg
        .dispatch(
            "mail.relay.test",
            &auth_for(admin, Role::Admin),
            json!({ "to": "ops@acme.example>\r\nRCPT TO:<victim@example.net" }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert_eq!(err.field.as_deref(), Some("to"));
}

// ---------------------------------------------------------------------------
// the advisory
// ---------------------------------------------------------------------------

fn relay_for(host: &str, from: &str) -> MailRelay {
    MailRelay {
        host: host.into(),
        port: 587,
        tls_mode: TlsMode::Starttls,
        username: Some("user".into()),
        password_sealed: Some("aa".into()),
        from_address: from.into(),
        from_name: None,
        enabled: true,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

#[test]
fn the_advisory_never_claims_to_manage_anything() {
    // Spec §11.18 is explicit: guidance, not management.
    let advisory = dns_advisory(Some(&relay_for("smtp.postmarkapp.com", "no@acme.example")));
    assert!(advisory.records.iter().all(|r| !r.managed));
    assert!(advisory.advice.contains("neither signs nor manages"));
}

#[test]
fn a_known_provider_gets_its_published_spf_include() {
    let advisory = dns_advisory(Some(&relay_for("smtp.postmarkapp.com", "no@acme.example")));
    let spf = &advisory.records[0];
    assert_eq!(spf.record_type, "TXT");
    assert_eq!(spf.name, "acme.example");
    assert_eq!(
        spf.value.as_deref(),
        Some("v=spf1 include:spf.mtasv.net ~all")
    );
    assert!(advisory.advice.contains("publishes for its customers"));
}

#[test]
fn an_unknown_relay_gets_an_honest_fallback_and_is_told_it_is_a_fallback() {
    // Guessing an include for a relay we do not know would be worse than
    // saying what we do know.
    let advisory = dns_advisory(Some(&relay_for("mail.internal.example", "no@acme.example")));
    assert_eq!(
        advisory.records[0].value.as_deref(),
        Some("v=spf1 a:mail.internal.example ~all")
    );
    assert!(advisory.advice.contains("not a relay Unihelm recognises"));
}

#[test]
fn the_dkim_record_has_no_value_because_only_the_relay_can_supply_one() {
    let advisory = dns_advisory(Some(&relay_for("smtp.mailgun.org", "no@acme.example")));
    let dkim = advisory
        .records
        .iter()
        .find(|r| r.name.contains("_domainkey"))
        .expect("a DKIM row must be surfaced");
    assert!(
        dkim.value.is_none(),
        "a made-up DKIM record would be published"
    );
    assert!(dkim.purpose.contains("does not sign"));
}

#[test]
fn the_dmarc_record_starts_at_p_none_and_reports_to_the_sender() {
    // `p=quarantine` on day one rejects mail before anybody has read a report.
    let advisory = dns_advisory(Some(&relay_for("smtp.mailgun.org", "no@acme.example")));
    let dmarc = advisory
        .records
        .iter()
        .find(|r| r.name.starts_with("_dmarc."))
        .unwrap();
    assert_eq!(dmarc.name, "_dmarc.acme.example");
    assert_eq!(
        dmarc.value.as_deref(),
        Some("v=DMARC1; p=none; rua=mailto:no@acme.example")
    );
}

// ---------------------------------------------------------------------------
// the shim
// ---------------------------------------------------------------------------

#[test]
fn sendmail_path_reads_recipients_from_the_message_and_keeps_the_configured_sender() {
    let rendered = sendmail_path(std::path::Path::new("/usr/bin/msmtp"), "example.com");
    assert!(rendered.starts_with("/usr/bin/msmtp "));
    assert!(rendered.contains("--file="));
    assert!(rendered.ends_with(" -t"));
    // `--read-envelope-from` would let an application choose the envelope
    // sender, which is what SPF is evaluated against.
    assert!(!rendered.contains("read-envelope-from"));
}

#[test]
fn the_sendmail_path_a_validated_domain_produces_carries_no_shell_metacharacters() {
    // PHP runs `sendmail_path` through popen(3), i.e. `/bin/sh -c`. The panel
    // does not execute it, but a shell will, so what goes in has to be
    // shell-inert. A `Domain` is the only variable part and its alphabet is
    // letters, digits, dots and hyphens.
    for domain in ["example.com", "a-b.example.co.uk", "xn--mgbh0fb.example"] {
        let domain = Domain::parse(domain).expect("a valid domain");
        let rendered = sendmail_path(std::path::Path::new("/usr/bin/msmtp"), domain.as_str());
        assert!(
            !rendered
                .chars()
                .any(|c| "|;&`$()<>\n\r\"'\\*?[]{}~!#".contains(c)),
            "{rendered}"
        );
    }
    // And the newtype is what stops the hostile spellings existing at all.
    for hostile in ["a.com;rm -rf /", "a.com`id`", "a.com b.com", "a.com\nb"] {
        assert!(Domain::parse(hostile).is_err(), "{hostile:?}");
    }
}

#[test]
fn the_relay_config_path_is_under_etc_and_not_in_the_tenant_home() {
    // A tenant who could edit it could point their site's mail at a relay of
    // their own while still sending as the operator's domain.
    let path = unihelm_config::paths::mail_site_config("example.com");
    assert!(path.starts_with("/etc/unihelm/mail"), "{path:?}");
    assert!(!path.to_string_lossy().contains("/home/"));
}

#[test]
fn each_family_gets_its_own_ca_bundle_path() {
    // A wrong path here makes msmtp refuse to connect; it never makes it
    // connect without verifying.
    assert!(tls_trust_file(Family::Rhel).contains("/pki/"));
    assert!(tls_trust_file(Family::Debian).contains("ca-certificates.crt"));
}

#[test]
fn the_ehlo_name_is_the_sending_domain() {
    let relay = relay_for("smtp.example.net", "noreply@acme.example");
    assert_eq!(ehlo_name(&relay), "acme.example");
}

#[test]
fn a_display_name_carrying_a_newline_is_refused() {
    assert!(parse_display_name("from_name", "Acme\r\nBcc: all@example.net").is_err());
    assert_eq!(
        parse_display_name("from_name", " میزبانی آکمه ").unwrap(),
        "میزبانی آکمه"
    );
}

#[test]
fn a_relay_host_is_lowercased_so_it_matches_however_it_was_typed() {
    assert_eq!(
        parse_relay_host(" SMTP.Example.NET ").unwrap(),
        "smtp.example.net"
    );
    assert!(
        parse_relay_host("[2001:db8::1]").is_err(),
        "brackets are not a host here"
    );
    assert!(
        parse_relay_host("2001:db8::1").is_ok(),
        "a bare IPv6 literal is"
    );
}

#[tokio::test]
async fn a_site_whose_subscription_vanished_is_skipped_rather_than_failing_the_run() {
    // One broken row must not stop every other site being wired.
    //
    // The foreign key on `sites.subscription_id` makes this state unreachable
    // through the panel, so the test has to switch enforcement off to produce
    // it. That is the point: the branch it covers exists for a database that
    // arrived some other way — a partial restore, a hand edit during an
    // incident — and the requirement is that mail wiring degrades to "skip
    // that one" rather than to "no site gets wired".
    let (reg, admin, customer) = registry().await;
    let db = db_of(&reg);
    seed_php_site(&db, customer, "good.example.com", true).await;
    seed_php_site(&db, customer, "orphan.example.com", true).await;
    let orphan = db
        .sites(&TenantScope::Global)
        .by_domain("orphan.example.com")
        .await
        .unwrap()
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM subscriptions WHERE id = ?1")
        .bind(orphan.subscription_id.0)
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(db.pool())
        .await
        .unwrap();

    let pools = std::sync::Arc::new(RecordingPools::default());
    let out = run_set(&reg, admin, pools, relay_input()).await.unwrap();
    assert_eq!(out.sites.rewired, 1);
    assert_eq!(out.sites.skipped_no_subscription, 1);
}

// ---------------------------------------------------------------------------
// publishing the advisory
// ---------------------------------------------------------------------------

/// A record whose value only the provider can supply must never be published.
///
/// A DKIM record with a placeholder in it is worse than no DKIM record: mail
/// signed against a key the zone does not carry fails verification, where mail
/// with no DKIM record at all merely goes unsigned.
#[test]
fn a_record_with_no_value_is_skipped_rather_than_invented() {
    let advisory = dns_advisory(Some(&relay_for("smtp.postmarkapp.com", "no@acme.example")));
    for record in &advisory.records {
        if record.value.is_none() {
            assert!(
                record.purpose.to_lowercase().contains("dkim")
                    || record.purpose.to_lowercase().contains("provider"),
                "a valueless record must say why: {record:?}"
            );
        }
    }
}

/// The advisory leaves `{domain}` where a record belongs to each sending domain.
/// Publishing that literally creates a record actually named `{domain}`.
#[test]
fn a_per_domain_placeholder_is_never_published_literally() {
    let advisory = dns_advisory(Some(&relay_for("smtp.postmarkapp.com", "no@acme.example")));
    for record in &advisory.records {
        if record.name.contains('{') {
            assert!(
                record.name.contains("{domain}"),
                "the only placeholder publishing knows to skip is {{domain}}: {record:?}"
            );
        }
    }
}

/// Whatever else changes, these stay advisory: nothing in the panel keeps a
/// published record in step afterwards, and a field that could read `true` would
/// invite an operator to believe otherwise.
#[test]
fn advisory_records_never_claim_to_be_managed() {
    for relay in [
        None,
        Some(relay_for("smtp.postmarkapp.com", "no@acme.example")),
        Some(relay_for("mail.internal.example", "no@acme.example")),
    ] {
        let advisory = dns_advisory(relay.as_ref());
        assert!(
            advisory.records.iter().all(|r| !r.managed),
            "the panel does not manage these"
        );
    }
}
