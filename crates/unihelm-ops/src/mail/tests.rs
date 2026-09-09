//! Tests for the relay operations, the migration, and the advisory
//! (spec §11.18).
//!
//! Everything that would touch `/etc`, install a package, reload PHP-FPM or
//! open an SMTP connection goes through a seam — [`PoolWriter`], [`RelayProbe`]
//! and [`mta::MtaHost`] — so what is exercised here is the half worth testing:
//! what gets stored, what gets refused, what order the migration happens in,
//! which files survive it, and what the panel says about a machine that is only
//! half way through.
//!
//! The rendering half of the MTA has its own tests, next to the renderers, in
//! `mta.rs`.

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

/// Records which sites would have had their pool re-rendered, in order.
#[derive(Default)]
struct RecordingPools {
    seen: Mutex<Vec<String>>,
    /// Domains whose re-render should fail, so the migration's "leave that
    /// site's credential file alone" branch is reachable.
    fail: Mutex<Vec<String>>,
}

impl RecordingPools {
    fn failing(domain: &str) -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
            fail: Mutex::new(vec![domain.to_string()]),
        }
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().expect("no test panics here").clone()
    }
}

#[async_trait]
impl PoolWriter for RecordingPools {
    async fn rewrite(
        &self,
        _ctx: &OpContext,
        site: &unihelm_db::Site,
        _linux_user: &LinuxUser,
    ) -> Result<()> {
        if self
            .fail
            .lock()
            .expect("no test panics here")
            .contains(&site.domain)
        {
            return Err(UnihelmError::internal("php-fpm refused this pool"));
        }
        self.seen
            .lock()
            .expect("no test panics here")
            .push(site.domain.clone());
        Ok(())
    }
}

/// A machine with no Postfix on it, whose answers the test decides.
///
/// It deliberately cannot answer "is the MTA configured": that is a property of
/// the files, which the real [`mta::Layout`] reads, and the tests below drive it
/// by writing a `main.cf` into a temporary directory rather than by asserting a
/// fake's opinion of one.
struct FakeHost {
    hostname: String,
    installed: Mutex<bool>,
    running: Mutex<bool>,
    queued: Option<u64>,
    installs: Mutex<usize>,
    activations: Mutex<usize>,
}

impl FakeHost {
    /// A machine that has never had an MTA on it.
    fn bare() -> Self {
        Self {
            hostname: "web-01.acme.example".into(),
            installed: Mutex::new(false),
            running: Mutex::new(false),
            queued: Some(0),
            installs: Mutex::new(0),
            activations: Mutex::new(0),
        }
    }

    /// A machine with the package installed and the unit up.
    fn running() -> Self {
        let host = Self::bare();
        *host.installed.lock().unwrap() = true;
        *host.running.lock().unwrap() = true;
        host
    }

    fn installs(&self) -> usize {
        *self.installs.lock().unwrap()
    }
}

/// Where the three files go for a test, and nowhere near `/etc`.
fn layout_in(dir: &std::path::Path) -> mta::Layout {
    mta::Layout::under(dir)
}

/// A machine that has already been migrated: the panel's own `main.cf` is on
/// disk, which is the only thing `Layout::state` asks.
fn migrated_layout(dir: &std::path::Path) -> mta::Layout {
    let layout = layout_in(dir);
    mta::put(
        &unihelm_config::ManagedFile::postfix_main_cf(&layout.main_cf),
        "myhostname = web-01.acme.example\n",
        false,
    )
    .unwrap();
    assert_eq!(layout.state(), mta::ConfigState::Ours);
    layout
}

#[async_trait]
impl mta::MtaHost for FakeHost {
    fn hostname(&self) -> Result<String> {
        Ok(self.hostname.clone())
    }

    async fn installed(&self, _ctx: &OpContext) -> Result<bool> {
        Ok(*self.installed.lock().unwrap())
    }

    async fn install(&self, _ctx: &OpContext, _hostname: &str) -> Result<()> {
        *self.installs.lock().unwrap() += 1;
        *self.installed.lock().unwrap() = true;
        Ok(())
    }

    async fn activate(&self, _ctx: &OpContext) -> Result<()> {
        *self.activations.lock().unwrap() += 1;
        *self.running.lock().unwrap() = true;
        Ok(())
    }

    async fn running(&self, _ctx: &OpContext) -> Result<bool> {
        Ok(*self.running.lock().unwrap())
    }

    async fn queued(&self) -> Option<u64> {
        self.queued
    }
}

/// A shared handle, so a test can look at what the operation did to its host.
struct SharedHost(std::sync::Arc<FakeHost>);

#[async_trait]
impl mta::MtaHost for SharedHost {
    fn hostname(&self) -> Result<String> {
        self.0.hostname()
    }
    async fn installed(&self, ctx: &OpContext) -> Result<bool> {
        self.0.installed(ctx).await
    }
    async fn install(&self, ctx: &OpContext, hostname: &str) -> Result<()> {
        self.0.install(ctx, hostname).await
    }
    async fn activate(&self, ctx: &OpContext) -> Result<()> {
        self.0.activate(ctx).await
    }
    async fn running(&self, ctx: &OpContext) -> Result<bool> {
        self.0.running(ctx).await
    }
    async fn queued(&self) -> Option<u64> {
        self.0.queued().await
    }
}

/// A relay that answers however the test says, without a relay.
struct FakeProbe {
    delivered: bool,
    calls: Mutex<usize>,
}

impl FakeProbe {
    fn accepting() -> Self {
        Self {
            delivered: true,
            calls: Mutex::new(0),
        }
    }
    fn rejecting() -> Self {
        Self {
            delivered: false,
            calls: Mutex::new(0),
        }
    }
}

#[async_trait]
impl RelayProbe for FakeProbe {
    async fn probe(
        &self,
        _ctx: &OpContext,
        _relay: &MailRelay,
        _password: Option<&str>,
    ) -> smtp::SendReport {
        *self.calls.lock().unwrap() += 1;
        smtp::SendReport {
            delivered: self.delivered,
            stage: if self.delivered {
                smtp::Stage::Body
            } else {
                smtp::Stage::Auth
            },
            detail: if self.delivered {
                "250 2.0.0 OK".into()
            } else {
                "535 5.7.8 Authentication credentials invalid".into()
            },
            code: Some(if self.delivered { 250 } else { 535 }),
            transcript: Vec::new(),
            encrypted: true,
        }
    }
}

struct SharedProbe(std::sync::Arc<FakeProbe>);

#[async_trait]
impl RelayProbe for SharedProbe {
    async fn probe(
        &self,
        ctx: &OpContext,
        relay: &MailRelay,
        password: Option<&str>,
    ) -> smtp::SendReport {
        self.0.probe(ctx, relay, password).await
    }
}

struct SharedPools(std::sync::Arc<RecordingPools>);

#[async_trait]
impl PoolWriter for SharedPools {
    async fn rewrite(
        &self,
        ctx: &OpContext,
        site: &unihelm_db::Site,
        linux_user: &LinuxUser,
    ) -> Result<()> {
        self.0.rewrite(ctx, site, linux_user).await
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

/// The state a 0.7 machine is in: one credential file per site, on disk.
fn seed_legacy_files(dir: &std::path::Path, domains: &[&str]) {
    std::fs::create_dir_all(dir).unwrap();
    for domain in domains {
        std::fs::write(
            dir.join(format!("{domain}.msmtprc")),
            "host smtp.postmarkapp.com\nuser token-user\npassword token-secret\n",
        )
        .unwrap();
    }
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

/// Run `mail.relay.set` against a machine with no MTA configured — the ordinary
/// state of a server that has not been migrated yet.
async fn run_set(
    reg: &OpRegistry,
    admin: unihelm_core::UserId,
    pools: std::sync::Arc<RecordingPools>,
    input: serde_json::Value,
) -> Result<RelaySetOutput> {
    let nowhere = std::path::Path::new("/nonexistent/unihelm-mail");
    run_set_on(
        reg,
        admin,
        FakeHost::bare(),
        pools,
        input,
        layout_in(nowhere),
        nowhere,
    )
    .await
}

async fn run_set_on(
    reg: &OpRegistry,
    admin: unihelm_core::UserId,
    host: FakeHost,
    pools: std::sync::Arc<RecordingPools>,
    input: serde_json::Value,
    layout: mta::Layout,
    legacy_dir: &std::path::Path,
) -> Result<RelaySetOutput> {
    let op = RelaySet::with_parts(
        Box::new(host),
        Box::new(SharedPools(pools)),
        layout,
        legacy_dir.to_path_buf(),
    );
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

#[tokio::test]
async fn the_relay_view_names_the_local_mta_and_not_the_client_it_replaced() {
    // The `agent` field answers "what does this server hand a message to", and
    // the answer moved from a per-site msmtp to a host MTA. `agent_installed`
    // is installed *and* configured: a Postfix the panel has not configured
    // does whatever the package decided with a message, which on a fresh
    // install is queue it forever.
    let (reg, admin, _) = registry().await;
    let nowhere = std::path::Path::new("/nonexistent/unihelm-mail");
    let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
    let view = view(&ctx, &FakeHost::bare(), &layout_in(nowhere), None, nowhere).await;

    assert_eq!(view.agent, "postfix");
    assert_ne!(view.agent, LEGACY_AGENT);
    assert!(!view.agent_installed);
    assert!(view.mta.summary.contains("mail.mta.install"));
}

// ---------------------------------------------------------------------------
// mail.relay.set
// ---------------------------------------------------------------------------

#[tokio::test]
async fn setting_a_relay_stores_it_sealed() {
    let (reg, admin, customer) = registry().await;
    let db = db_of(&reg);
    seed_php_site(&db, customer, "one.example.com", true).await;

    let pools = std::sync::Arc::new(RecordingPools::default());
    let out = run_set(&reg, admin, pools.clone(), relay_input())
        .await
        .unwrap();
    assert!(out.relay.configured);

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
async fn saving_a_relay_on_an_unmigrated_machine_leaves_the_old_wiring_alone() {
    // The regression this exists to stop. `site::render_pool` no longer emits
    // `sendmail_path` at all, so re-rendering a pool on a machine that has no
    // local MTA yet would take the msmtp directive away and leave nothing
    // behind it: that site would stop sending, at the moment an operator was
    // trying to fix its mail. Nothing is re-rendered until there is an MTA.
    let (reg, admin, customer) = registry().await;
    seed_php_site(&db_of(&reg), customer, "one.example.com", true).await;

    let pools = std::sync::Arc::new(RecordingPools::default());
    let out = run_set(&reg, admin, pools.clone(), relay_input())
        .await
        .unwrap();

    assert!(pools.seen().is_empty(), "a pool was re-rendered anyway");
    assert_eq!(out.sites.rewired, 0);
    assert!(out.configuration.is_none());
}

#[tokio::test]
async fn saving_a_relay_on_a_migrated_machine_repoints_the_mta_at_it() {
    // A `texthash:` map is cached by Postfix when it opens it, so a rotated
    // credential that is written without a reload is one the running daemons
    // never use. The configure pass owns that reload, and this asserts the
    // operation actually reaches it.
    let (reg, admin, customer) = registry().await;
    seed_php_site(&db_of(&reg), customer, "one.example.com", true).await;
    let dir = tempfile::tempdir().unwrap();

    let layout = migrated_layout(dir.path());
    let pools = std::sync::Arc::new(RecordingPools::default());
    let out = run_set_on(
        &reg,
        admin,
        FakeHost::running(),
        pools.clone(),
        relay_input(),
        layout.clone(),
        dir.path(),
    )
    .await
    .unwrap();

    let configuration = out
        .configuration
        .expect("a configured MTA must be repointed at the new relay");
    assert!(configuration.changed);
    assert!(
        configuration.reloaded,
        "a rewritten texthash: map that is not reloaded is a credential Postfix never picks up"
    );

    // The credential landed where only root can read it, and nowhere else.
    let map = std::fs::read_to_string(&layout.sasl_passwd).unwrap();
    assert!(
        map.contains("[smtp.postmarkapp.com]:587\ttoken-user:token-secret"),
        "{map}"
    );
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&layout.sasl_passwd)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode, 0o600, "the relay credential is readable: {mode:o}");
    assert!(
        !std::fs::read_to_string(&layout.main_cf)
            .unwrap()
            .contains("token-secret"),
        "the credential reached the world-readable main.cf"
    );

    // And the pool the site had is re-rendered, because on a migrated machine
    // that is how a leftover directive goes.
    assert_eq!(pools.seen(), vec!["one.example.com".to_string()]);
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
// mail.mta.install — the migration
// ---------------------------------------------------------------------------

async fn install_with(
    reg: &OpRegistry,
    admin: unihelm_core::UserId,
    host: std::sync::Arc<FakeHost>,
    probe: std::sync::Arc<FakeProbe>,
    pools: std::sync::Arc<RecordingPools>,
    layout: mta::Layout,
    legacy_dir: &std::path::Path,
) -> Result<MtaInstallOutput> {
    let op = MtaInstall::with_parts(
        Box::new(SharedHost(host)),
        Box::new(SharedProbe(probe)),
        Box::new(SharedPools(pools)),
        layout,
        legacy_dir.to_path_buf(),
    );
    let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
    op.run(&ctx, MtaInstallInput { adopt: false }).await
}

#[tokio::test]
async fn installing_an_mta_with_no_relay_behind_it_is_refused() {
    // A null client with nowhere to send is a queue nobody drains: `sendmail`
    // exits 0, PHP's mail() returns true, and the message sits in the spool
    // until it is bounced days later. Every one of those would be reported to
    // the application as sent.
    let (reg, admin, _) = registry().await;
    let dir = tempfile::tempdir().unwrap();
    let host = std::sync::Arc::new(FakeHost::bare());

    let err = install_with(
        &reg,
        admin,
        host.clone(),
        std::sync::Arc::new(FakeProbe::accepting()),
        std::sync::Arc::new(RecordingPools::default()),
        layout_in(dir.path()),
        dir.path(),
    )
    .await
    .unwrap_err();

    assert_eq!(err.code, ErrorCode::Conflict);
    assert!(
        err.detail.contains("nowhere to send them"),
        "{}",
        err.detail
    );
    assert!(
        !dir.path().join("main.cf").exists(),
        "a null client was configured with nowhere to send"
    );
    assert_eq!(host.installs(), 0, "nothing may be installed either");
}

#[tokio::test]
async fn a_relay_that_is_switched_off_is_not_something_to_install_an_mta_for() {
    // `is_live()`, not `is_some()`: a row that exists is not a relay that
    // accepts mail, and the queue-nobody-drains argument is identical.
    let (reg, admin, _) = registry().await;
    let dir = tempfile::tempdir().unwrap();
    let pools = std::sync::Arc::new(RecordingPools::default());
    let mut off = relay_input();
    off["enabled"] = json!(false);
    run_set(&reg, admin, pools.clone(), off).await.unwrap();

    let err = install_with(
        &reg,
        admin,
        std::sync::Arc::new(FakeHost::bare()),
        std::sync::Arc::new(FakeProbe::accepting()),
        pools,
        layout_in(dir.path()),
        dir.path(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Conflict);
}

#[tokio::test]
async fn a_relay_that_rejects_the_credential_leaves_the_machine_exactly_as_it_was() {
    // The whole reason the verification runs first. A configuration written
    // for a credential the relay refuses is the panel reporting success for
    // mail that will silently fail — and worse, it would have deleted the
    // per-site files the machine is currently sending through to do it.
    let (reg, admin, customer) = registry().await;
    seed_php_site(&db_of(&reg), customer, "one.example.com", true).await;
    let dir = tempfile::tempdir().unwrap();
    seed_legacy_files(dir.path(), &["one.example.com"]);

    let pools = std::sync::Arc::new(RecordingPools::default());
    run_set(&reg, admin, pools.clone(), relay_input())
        .await
        .unwrap();

    let host = std::sync::Arc::new(FakeHost::bare());
    let err = install_with(
        &reg,
        admin,
        host.clone(),
        std::sync::Arc::new(FakeProbe::rejecting()),
        pools.clone(),
        layout_in(dir.path()),
        dir.path(),
    )
    .await
    .unwrap_err();

    assert!(err.detail.contains("535"), "{}", err.detail);
    assert!(
        err.detail.contains("nothing has been changed"),
        "{}",
        err.detail
    );
    assert_eq!(host.installs(), 0, "the package was installed anyway");
    assert!(pools.seen().is_empty(), "a pool was re-rendered anyway");
    assert!(
        !dir.path().join("main.cf").exists(),
        "a configuration was written for a credential the relay rejects"
    );
    assert!(
        dir.path().join("one.example.com.msmtprc").exists(),
        "the file this site is still sending through was deleted"
    );
}

#[tokio::test]
async fn a_site_keeps_its_credential_file_until_its_own_pool_has_been_re_rendered() {
    // The order that makes every step safe to interrupt. A pool that still
    // carries `sendmail_path = msmtp --file=<that file>` needs the file: delete
    // it first and that site stops sending at its next message, which is worse
    // than the leak being fixed.
    let (reg, admin, customer) = registry().await;
    let db = db_of(&reg);
    seed_php_site(&db, customer, "good.example.com", true).await;
    seed_php_site(&db, customer, "stuck.example.com", true).await;
    let dir = tempfile::tempdir().unwrap();
    seed_legacy_files(dir.path(), &["good.example.com", "stuck.example.com"]);

    let pools = std::sync::Arc::new(RecordingPools::failing("stuck.example.com"));
    run_set(&reg, admin, pools.clone(), relay_input())
        .await
        .unwrap();

    let out = install_with(
        &reg,
        admin,
        std::sync::Arc::new(FakeHost::running()),
        std::sync::Arc::new(FakeProbe::accepting()),
        pools,
        layout_in(dir.path()),
        dir.path(),
    )
    .await
    .unwrap();

    assert_eq!(out.sites.rewired, 1);
    assert_eq!(out.sites.failed, 1);
    assert_eq!(out.sites.retired_files, 1);
    assert!(
        !dir.path().join("good.example.com.msmtprc").exists(),
        "the migrated site's copy of the credential is still there"
    );
    assert!(
        dir.path().join("stuck.example.com.msmtprc").exists(),
        "a site whose pool did not re-render lost the file it is still sending through"
    );
    // And the operator is told which state the machine reached, because it is
    // not the finished one.
    assert_eq!(out.reached, "mta-configured");
}

#[tokio::test]
async fn a_finished_migration_leaves_no_copy_of_the_credential_anywhere() {
    // Including the files of sites that never had a pool: a static site's
    // `.msmtprc` was never named by anything, and it holds the same password.
    let (reg, admin, customer) = registry().await;
    let db = db_of(&reg);
    seed_php_site(&db, customer, "php.example.com", true).await;
    seed_php_site(&db, customer, "static.example.com", false).await;
    let dir = tempfile::tempdir().unwrap();
    seed_legacy_files(
        dir.path(),
        &[
            "php.example.com",
            "static.example.com",
            "deleted.example.com",
        ],
    );

    let pools = std::sync::Arc::new(RecordingPools::default());
    run_set(&reg, admin, pools.clone(), relay_input())
        .await
        .unwrap();

    let out = install_with(
        &reg,
        admin,
        std::sync::Arc::new(FakeHost::running()),
        std::sync::Arc::new(FakeProbe::accepting()),
        pools,
        layout_in(dir.path()),
        dir.path(),
    )
    .await
    .unwrap();

    assert_eq!(out.reached, "sites-migrated");
    assert_eq!(out.sites.retired_files, 3);
    assert!(
        legacy_relay_files(dir.path()).is_empty(),
        "a copy of the relay password survived the migration: {:?}",
        legacy_relay_files(dir.path())
    );
    assert_eq!(out.state.legacy_files, 0);
}

#[tokio::test]
async fn installing_twice_installs_once_and_still_re_checks_the_relay() {
    // Idempotent: the second run finds the package already there and changes
    // nothing. It still asks the relay, because a configuration that has not
    // changed can have stopped working when somebody rotated a credential
    // upstream, and a check that only runs on a change would miss exactly that.
    let (reg, admin, _) = registry().await;
    let dir = tempfile::tempdir().unwrap();
    let pools = std::sync::Arc::new(RecordingPools::default());
    run_set(&reg, admin, pools.clone(), relay_input())
        .await
        .unwrap();

    let host = std::sync::Arc::new(FakeHost::running());
    let probe = std::sync::Arc::new(FakeProbe::accepting());
    let mut reports = Vec::new();
    for _ in 0..2 {
        reports.push(
            install_with(
                &reg,
                admin,
                host.clone(),
                probe.clone(),
                pools.clone(),
                layout_in(dir.path()),
                dir.path(),
            )
            .await
            .unwrap(),
        );
    }

    assert_eq!(host.installs(), 0, "an installed MTA was installed again");
    assert_eq!(
        *probe.calls.lock().unwrap(),
        2,
        "the relay was not re-checked"
    );
    assert!(
        reports[0].configuration.changed,
        "the first run writes the files"
    );
    assert!(
        !reports[1].configuration.changed,
        "the second run rewrote a configuration that was already correct"
    );
    assert!(
        !reports[1].configuration.reloaded,
        "Postfix was reloaded for a change that did not happen"
    );
}

#[tokio::test]
async fn an_mta_that_will_not_start_does_not_get_to_take_the_old_wiring_away() {
    // A configured MTA that is not running accepts messages into a queue
    // nothing drains. Until it is up, the sites that still work have to keep
    // working.
    let (reg, admin, customer) = registry().await;
    seed_php_site(&db_of(&reg), customer, "one.example.com", true).await;
    let dir = tempfile::tempdir().unwrap();
    seed_legacy_files(dir.path(), &["one.example.com"]);

    let pools = std::sync::Arc::new(RecordingPools::default());
    run_set(&reg, admin, pools.clone(), relay_input())
        .await
        .unwrap();

    let host = std::sync::Arc::new(FakeHost::running());
    // Installed, and dead — an MTA whose unit failed to come up.
    *host.running.lock().unwrap() = false;
    struct DeadHost(std::sync::Arc<FakeHost>);
    #[async_trait]
    impl mta::MtaHost for DeadHost {
        fn hostname(&self) -> Result<String> {
            self.0.hostname()
        }
        async fn installed(&self, ctx: &OpContext) -> Result<bool> {
            self.0.installed(ctx).await
        }
        async fn install(&self, ctx: &OpContext, hostname: &str) -> Result<()> {
            self.0.install(ctx, hostname).await
        }
        // Activation does not bring it up: that is the failure being modelled.
        async fn activate(&self, _ctx: &OpContext) -> Result<()> {
            Ok(())
        }
        async fn running(&self, _ctx: &OpContext) -> Result<bool> {
            Ok(false)
        }
        async fn queued(&self) -> Option<u64> {
            self.0.queued().await
        }
    }

    let op = MtaInstall::with_parts(
        Box::new(DeadHost(host)),
        Box::new(FakeProbe::accepting()),
        Box::new(SharedPools(pools.clone())),
        layout_in(dir.path()),
        dir.path().to_path_buf(),
    );
    let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
    let err = op
        .run(&ctx, MtaInstallInput { adopt: false })
        .await
        .unwrap_err();

    assert_eq!(err.code, ErrorCode::ServiceUnavailable);
    assert!(err.detail.contains("keep sending"), "{}", err.detail);
    assert!(pools.seen().is_empty());
    assert!(dir.path().join("one.example.com.msmtprc").exists());
}

// ---------------------------------------------------------------------------
// mail.mta.status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_status_of_a_machine_that_has_not_been_migrated_names_what_is_missing() {
    let (reg, admin, _) = registry().await;
    let dir = tempfile::tempdir().unwrap();
    seed_legacy_files(dir.path(), &["one.example.com", "two.example.com"]);
    let pools = std::sync::Arc::new(RecordingPools::default());
    run_set(&reg, admin, pools, relay_input()).await.unwrap();

    let op = MtaStatus::with_parts(
        Box::new(FakeHost::bare()),
        layout_in(dir.path()),
        dir.path().to_path_buf(),
    );
    let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
    let state = op.run(&ctx, MtaStatusInput {}).await.unwrap();

    assert!(!state.installed);
    assert!(!state.configured);
    assert!(state.relay_live);
    assert_eq!(state.legacy_files, 2);
    assert!(
        state.summary.contains("mail.mta.install"),
        "{}",
        state.summary
    );
    assert!(
        state
            .summary
            .contains("2 per-site msmtp credential file(s)"),
        "{}",
        state.summary
    );
}

#[tokio::test]
async fn an_mta_with_no_relay_behind_it_is_reported_as_sending_nothing() {
    // The visible state the change has to have: mail is not silently
    // disappearing, and the panel says exactly where it is stopping.
    let (reg, admin, _) = registry().await;
    let dir = tempfile::tempdir().unwrap();

    let op = MtaStatus::with_parts(
        Box::new(FakeHost::running()),
        migrated_layout(dir.path()),
        dir.path().to_path_buf(),
    );
    let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
    let state = op.run(&ctx, MtaStatusInput {}).await.unwrap();

    assert!(!state.relay_live);
    assert!(
        state.summary.contains("nothing will leave this machine"),
        "{}",
        state.summary
    );
    assert_eq!(state.submission, "127.0.0.1:25");
}

#[tokio::test]
async fn a_customer_cannot_read_the_mta_status() {
    // It names the relay's state and the machine's queue; the same reasoning
    // that keeps `mail.relay.get` off a tenant's session applies.
    let (reg, _, customer) = registry().await;
    let op = MtaStatus::live();
    let ctx = OpContext::new(reg.services().clone(), auth_for(customer, Role::Customer));
    assert!(
        ctx.auth().require(MtaStatus::PERMISSION).is_err(),
        "a customer holds the permission this operation asks for"
    );
    let _ = op;
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
// what is left of the old design
// ---------------------------------------------------------------------------

#[test]
fn the_panel_can_no_longer_render_a_per_site_relay_file_at_all() {
    // The retirement, asserted as a fact about the module rather than a claim
    // in a comment: `write_site_relay` and `sendmail_path` are gone, so there
    // is no code path left that writes a tenant-readable copy of the relay
    // credential. What remains is the ability to *find and delete* the ones an
    // older panel wrote.
    let dir = tempfile::tempdir().unwrap();
    seed_legacy_files(dir.path(), &["example.com"]);

    let found = legacy_relay_files(dir.path());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, "example.com");
    assert!(retire_legacy_relay_file(dir.path(), "example.com").unwrap());
    assert!(!retire_legacy_relay_file(dir.path(), "example.com").unwrap());
    assert!(legacy_relay_files(dir.path()).is_empty());
}

#[test]
fn the_sweep_only_touches_the_files_the_old_design_wrote() {
    // `/etc/unihelm/mail` now also holds the Postfix maps — the credential and
    // the sender-rewriting table. Deleting one of those would take the whole
    // machine's mail down, which is a considerably larger outage than the leak
    // being cleaned up.
    let dir = tempfile::tempdir().unwrap();
    seed_legacy_files(dir.path(), &["example.com"]);
    std::fs::write(dir.path().join("sasl_passwd"), "relay user:pw\n").unwrap();
    std::fs::write(dir.path().join("sender_canonical"), "@host to@example\n").unwrap();

    let found = legacy_relay_files(dir.path());
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(retire_legacy_relay_file(dir.path(), "example.com").unwrap());
    assert!(dir.path().join("sasl_passwd").exists());
    assert!(dir.path().join("sender_canonical").exists());
}

#[test]
fn a_machine_that_never_ran_the_old_design_has_nothing_to_sweep() {
    // A missing directory is the ordinary state of a fresh install, not an
    // error to report.
    assert!(legacy_relay_files(std::path::Path::new("/nonexistent/unihelm-mail")).is_empty());
}

#[test]
fn the_credential_note_says_the_tenant_can_no_longer_read_the_credential() {
    // It used to say the exposure was inherent to relay-only mail, because in
    // the design it described it was: msmtp ran as the tenant. The MTA holds
    // the credential as root, so the note has to stop saying otherwise —
    // an operator reading the old sentence still believes every customer on
    // the box holds their SendGrid password.
    assert!(
        CREDENTIAL_NOTE.contains("No tenant can read it"),
        "{CREDENTIAL_NOTE}"
    );
    assert!(
        !CREDENTIAL_NOTE.contains("no other site"),
        "the note still claims per-site containment: {CREDENTIAL_NOTE}"
    );
    // Still one credential for the machine, and still worth being send-only.
    assert!(CREDENTIAL_NOTE.contains("send-only"), "{CREDENTIAL_NOTE}");
}

#[test]
fn each_family_gets_its_own_ca_bundle_path() {
    // A wrong path here makes Postfix fail the delivery; it never makes it
    // deliver without verifying.
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
        parse_display_name("from_name", " Acme Hosting ").unwrap(),
        "Acme Hosting"
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
    // One broken row must not stop every other site being migrated.
    //
    // The foreign key on `sites.subscription_id` makes this state unreachable
    // through the panel, so the test has to switch enforcement off to produce
    // it. That is the point: the branch it covers exists for a database that
    // arrived some other way — a partial restore, a hand edit during an
    // incident — and the requirement is that the migration degrades to "skip
    // that one" rather than to "no site gets migrated".
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

    let dir = tempfile::tempdir().unwrap();
    let pools = std::sync::Arc::new(RecordingPools::default());
    run_set(&reg, admin, pools.clone(), relay_input())
        .await
        .unwrap();
    let out = install_with(
        &reg,
        admin,
        std::sync::Arc::new(FakeHost::running()),
        std::sync::Arc::new(FakeProbe::accepting()),
        pools,
        layout_in(dir.path()),
        dir.path(),
    )
    .await
    .unwrap();
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
