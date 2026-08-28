//! Site lifecycle (spec §11.2): the operation that turns a domain into
//! something nginx serves.
//!
//! The order matters and is the same every time: the Linux account and the
//! directory layout first, then the FPM pool, then the vhost. Each step is
//! validated by the service that will have to live with it, and the config
//! engine puts the previous state back if any of them refuses. If it all fails
//! at the last hurdle, the server is exactly as it was and the site row says
//! why.

use async_trait::async_trait;
use ferrum_config::apply::ApplyRequest;
use ferrum_config::context::{PoolContext, SiteContext, SiteType as CtxSiteType};
use ferrum_config::managed::ManagedFile;
use ferrum_config::paths;
use ferrum_core::{
    Domain, ErrorCode, FerrumError, Permission, PhpVersion, Result, SiteId, SubscriptionId,
};
use ferrum_db::sites::{NewSite, Site, SiteStatus, SiteType, SiteUpdate, WwwPolicy};
use serde::{Deserialize, Serialize};

use crate::provision;
use crate::registry::{Execution, OpContext, TypedOperation};
use crate::services::{FpmValidator, NginxValidator, UnitReloader};

/// How much memory a site's PHP pool may assume, until plans arrive in Phase 2.
/// Shared with the tenant-slice module so pool sizing and slice limits draw
/// from one budget (spec §6.3; see `slices` for why FPM is sized, not sliced).
const DEFAULT_POOL_MEMORY_MB: u32 = crate::slices::DEFAULT_TENANT_MEMORY_MB;

// ---------------------------------------------------------------------------
// site.list
// ---------------------------------------------------------------------------

pub struct List;

#[derive(Debug, Deserialize)]
pub struct ListInput {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SiteView {
    #[serde(flatten)]
    pub site: Site,
    pub aliases: Vec<String>,
    pub linux_user: String,
    pub has_certificate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub sites: Vec<SiteView>,
}

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "site.list";
    const PERMISSION: Permission = Permission::SiteRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();
        let repo = db.sites(ctx.scope());
        let sites = repo
            .list(input.limit.unwrap_or(100), input.offset.unwrap_or(0))
            .await
            .map_err(FerrumError::from)?;

        let mut views = Vec::with_capacity(sites.len());
        for site in sites {
            let aliases = repo
                .aliases(site.id)
                .await
                .map_err(FerrumError::from)?
                .into_iter()
                .map(|a| a.domain)
                .collect();
            let subscription = db
                .subscriptions(ctx.scope())
                .by_id(site.subscription_id)
                .await
                .map_err(FerrumError::from)?;
            let certificate = db
                .active_certificate_for_site(site.id)
                .await
                .map_err(FerrumError::from)?;

            views.push(SiteView {
                linux_user: subscription.map(|s| s.linux_user).unwrap_or_default(),
                aliases,
                has_certificate: certificate.is_some(),
                certificate_expires_in_days: certificate.and_then(|c| c.days_remaining()),
                site,
            });
        }

        Ok(ListOutput { sites: views })
    }
}

// ---------------------------------------------------------------------------
// site.create
// ---------------------------------------------------------------------------

pub struct Create;

#[derive(Debug, Deserialize)]
pub struct CreateInput {
    pub domain: Domain,
    #[serde(default = "default_site_type")]
    pub site_type: SiteTypeInput,
    #[serde(default)]
    pub php_version: Option<PhpVersion>,
    /// Which subscription owns it. Defaults to the caller's own.
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// Also serve `www.<domain>`.
    #[serde(default)]
    pub with_www: bool,
    #[serde(default)]
    pub proxy_port: Option<u16>,
    #[serde(default)]
    pub redirect_target: Option<Domain>,
}

fn default_site_type() -> SiteTypeInput {
    SiteTypeInput::Php
}

/// The site type as the API spells it. Mirrors [`SiteType`], but kept separate
/// so the wire format is not hostage to a storage refactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteTypeInput {
    Php,
    Static,
    Proxy,
    Redirect,
}

impl From<SiteTypeInput> for SiteType {
    fn from(v: SiteTypeInput) -> Self {
        match v {
            SiteTypeInput::Php => SiteType::Php,
            SiteTypeInput::Static => SiteType::Static,
            SiteTypeInput::Proxy => SiteType::Proxy,
            SiteTypeInput::Redirect => SiteType::Redirect,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CreateOutput {
    pub site_id: i64,
    pub domain: String,
    pub document_root: String,
    pub linux_user: String,
    /// What to do next, so the UI does not have to guess.
    pub next_steps: Vec<String>,
}

#[async_trait]
impl TypedOperation for Create {
    type Input = CreateInput;
    type Output = CreateOutput;

    const NAME: &'static str = "site.create";
    const PERMISSION: Permission = Permission::SiteManage;
    // Creating a Linux account, a directory tree and two config files, then
    // reloading two services. Not something to hold an HTTP request open for.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: false,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db().clone();
        let site_type: SiteType = input.site_type.into();

        // A PHP site needs a version, and it needs one that is installed.
        let php_version = if site_type.needs_php() {
            let version = input.php_version.ok_or_else(|| {
                FerrumError::new(ErrorCode::InvalidInput, "a PHP site needs a PHP version")
                    .with_field("php_version")
            })?;
            require_php_installed(ctx, version).await?;
            Some(version)
        } else {
            None
        };

        if site_type == SiteType::Proxy && input.proxy_port.is_none() {
            return Err(
                FerrumError::new(ErrorCode::InvalidInput, "a proxy site needs a port")
                    .with_field("proxy_port"),
            );
        }
        if site_type == SiteType::Redirect && input.redirect_target.is_none() {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "a redirect site needs a target",
            )
            .with_field("redirect_target"));
        }

        // Whose site is this?
        let subscription = match input.subscription_id {
            Some(id) => db
                .subscriptions(ctx.scope())
                .by_id(SubscriptionId(id))
                .await
                .map_err(FerrumError::from)?
                .ok_or_else(|| FerrumError::not_found("subscription"))?,
            None => db
                .default_subscription_for(ctx.auth().actor_user_id)
                .await
                .map_err(FerrumError::from)?,
        };

        if !subscription.status.can_serve() {
            return Err(FerrumError::new(
                ErrorCode::AccountSuspended,
                "this subscription is suspended and cannot host new sites",
            ));
        }

        // Plan enforcement (spec §6.2): a subscription at its plan's site limit
        // is refused here, before a row, a Linux account or a single file
        // exists. `max_dbs` is enforced the same way by the database module on
        // its side; a subscription without a plan stays unlimited (the Phase 1
        // behavior). Failed sites do not count, so the reclaim-and-retry path
        // below still works at the limit.
        crate::plan::enforce_site_limit(ctx.db(), &subscription).await?;

        let linux_user = ferrum_core::LinuxUser::parse(&subscription.linux_user)?;
        let root_dir = paths::site_public(linux_user.as_str(), input.domain.as_str());

        let wanted = NewSite {
            subscription_id: subscription.id,
            domain: input.domain.clone(),
            site_type,
            php_version,
            root_dir: root_dir.to_string_lossy().into_owned(),
            proxy_port: input.proxy_port,
            redirect_target: input
                .redirect_target
                .as_ref()
                .map(|d| format!("https://{d}")),
        };

        // The row first: a failure after this point has somewhere to be recorded.
        //
        // If the domain is already ours and its last attempt failed, this is a
        // retry, not a conflict. Anything else — an active site, another
        // tenant's failed one, an alias — stays a conflict, because reclaiming
        // those would be a way to take somebody else's domain.
        let site = match retryable_site(ctx, &input.domain, subscription.id).await? {
            Some(existing) => {
                ctx.log(format!(
                    "retrying {}, whose last attempt failed",
                    existing.domain
                ));
                db.reclaim_failed_site(existing.id, &wanted)
                    .await
                    .map_err(FerrumError::from)?
            }
            None => db.create_site(wanted).await.map_err(FerrumError::from)?,
        };

        if input.with_www
            && let Ok(www) = input.domain.with_www()
        {
            // A `www.` that is already taken is not a reason to fail the site.
            match db.sites(ctx.scope()).add_alias(site.id, &www, false).await {
                Ok(_) => ctx.log(format!("added alias {www}")),
                Err(e) => ctx.log(format!("could not add {www}: {e}")),
            }
        }

        let outcome = provision_site(ctx, &site, &linux_user).await;

        match outcome {
            Ok(()) => {
                db.set_site_status(site.id, SiteStatus::Active)
                    .await
                    .map_err(FerrumError::from)?;
                ctx.log(format!("{} is live", site.domain));

                Ok(CreateOutput {
                    site_id: site.id.get(),
                    domain: site.domain.clone(),
                    document_root: site.root_dir.clone(),
                    linux_user: subscription.linux_user,
                    next_steps: vec![
                        format!("Point {} at this server's IP address", site.domain),
                        "Issue a certificate once DNS has propagated".into(),
                        "Upload your files, or use the file manager".into(),
                    ],
                })
            }
            Err(e) => {
                // Leave the row behind, marked failed, so the UI can show what
                // went wrong instead of the site simply not appearing.
                let _ = db.set_site_status(site.id, SiteStatus::Failed).await;
                ctx.log(format!("provisioning failed: {e}"));
                Err(e)
            }
        }
    }
}

/// Everything between "there is a row" and "nginx is serving it".
async fn provision_site(
    ctx: &OpContext,
    site: &Site,
    linux_user: &ferrum_core::LinuxUser,
) -> Result<()> {
    let distro = ctx.distro().clone();
    let domain = Domain::parse(&site.domain)?;
    let log = ctx.log_sink();

    // 1. The account and the directory layout.
    let subscription = ctx
        .db()
        .subscription_by_linux_user(linux_user.as_str())
        .await
        .map_err(FerrumError::from)?
        .ok_or_else(|| FerrumError::internal("the subscription vanished mid-provision"))?;

    provision::ensure_tenant_user(ctx, linux_user, &subscription.home_dir, false).await?;
    provision::ensure_site_dirs(&distro, linux_user, &domain, log).await?;
    provision::write_placeholder(linux_user, &domain).await?;

    // 2. The FPM pool, before the vhost that points at its socket.
    if let Some(version) = site.php_version {
        render_pool(ctx, site, linux_user, version).await?;
    }

    // 3. The vhost.
    render_vhost(ctx, site, linux_user).await?;

    // 4. Log rotation. A busy site that fills the disk takes every other site
    //    on the server down with it, which would be the panel's fault.
    render_logrotate(ctx, site, linux_user).await?;

    Ok(())
}

/// Render and activate a site's PHP-FPM pool.
///
/// Picks up the configured mail relay on the way, so a site created after the
/// relay was set gets `sendmail_path` without anybody re-running
/// `mail.relay.set` (spec §11.18). A relay that is absent, switched off, or
/// missing its sendmail agent renders no directive at all — see
/// `mail::write_site_relay`.
pub async fn render_pool(
    ctx: &OpContext,
    site: &Site,
    linux_user: &ferrum_core::LinuxUser,
    version: PhpVersion,
) -> Result<()> {
    let relay = ctx.db().mail_relay().await.map_err(FerrumError::from)?;
    let sendmail = crate::mail::write_site_relay(ctx, &site.domain, linux_user, relay.as_ref())
        .await
        // Mail is not worth failing a site creation over: a site that serves
        // but cannot send is a support ticket, a site that does not exist is
        // an outage.
        .unwrap_or_else(|e| {
            ctx.log(format!(
                "could not write the mail relay configuration for {}: {e}. The site is fine; \
                 its PHP mail() will not work until this is fixed.",
                site.domain
            ));
            None
        });
    render_pool_with_mail(ctx, site, linux_user, version, sendmail).await
}

/// [`render_pool`], with the mail wiring already decided by the caller.
///
/// Split out for `mail.relay.set`, which writes every site's relay
/// configuration itself and must not have each pool re-read the relay row it
/// just wrote.
pub async fn render_pool_with_mail(
    ctx: &OpContext,
    site: &Site,
    linux_user: &ferrum_core::LinuxUser,
    version: PhpVersion,
    sendmail_path: Option<String>,
) -> Result<()> {
    let distro = ctx.distro();
    let family = distro.info.family;

    // The socket directory must exist before FPM tries to bind in it.
    std::fs::create_dir_all(paths::fpm_socket_dir())
        .map_err(|e| FerrumError::internal(format!("could not create the FPM socket dir: {e}")))?;

    // A package upgrade puts the stock `www` pool back, so this is checked
    // whenever we are about to reload FPM anyway rather than once at install.
    crate::fpm::retire_and_log(ctx, version).await;

    let mut pool = PoolContext::new(
        &site.domain,
        linux_user.as_str(),
        version,
        DEFAULT_POOL_MEMORY_MB,
        provision::nginx_user(distro),
    );
    pool.extra_ini = site.php_ini_overrides.clone();
    pool.sendmail_path = sendmail_path;

    ctx.config()
        .apply(ApplyRequest {
            file: ManagedFile::fpm_pool(paths::fpm_pool_file(family, version, &site.domain)),
            template: "php/pool.conf",
            context: serde_json::json!({ "pool": pool }),
            // One lock per PHP version: two sites on 8.3 must not have their
            // pools validated against a half-written tree.
            service: &format!("php-fpm-{}", version.as_str()),
            validator: &FpmValidator::new(distro, version),
            reloader: &UnitReloader::fpm(distro, version),
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;

    ctx.log(format!(
        "PHP {} pool ready for {}",
        version.as_str(),
        site.domain
    ));
    Ok(())
}

/// Is this create request a retry of a failed site we already own?
///
/// Returns the row to reclaim, `None` if the domain is free, and an error if it
/// belongs to something we must not take over. The error is the whole point of
/// the function: "`example.com` is already a site" tells an operator nothing
/// about what to do next, whereas naming the state does.
async fn retryable_site(
    ctx: &OpContext,
    domain: &ferrum_core::Domain,
    subscription_id: ferrum_core::SubscriptionId,
) -> Result<Option<Site>> {
    let db = ctx.db();

    // Global, not the caller's scope: a domain taken by a tenant this caller
    // cannot see is still taken, and answering "free" would produce a duplicate
    // `server_name` that nginx resolves by parse order.
    let Some(existing) = db
        .sites(&ferrum_core::TenantScope::Global)
        .by_domain(domain.as_str())
        .await
        .map_err(FerrumError::from)?
    else {
        return Ok(None);
    };

    if existing.subscription_id != subscription_id {
        return Err(FerrumError::new(
            ErrorCode::DomainAlreadyExists,
            format!("`{domain}` already belongs to another subscription"),
        ));
    }

    match existing.status {
        SiteStatus::Failed => Ok(Some(existing)),
        SiteStatus::Provisioning => Err(FerrumError::new(
            ErrorCode::Conflict,
            format!("`{domain}` is still being provisioned; wait for that task to finish"),
        )),
        SiteStatus::Active | SiteStatus::Suspended => Err(FerrumError::new(
            ErrorCode::DomainAlreadyExists,
            format!("`{domain}` is already a site; delete it first if you want to recreate it"),
        )),
    }
}

/// Render and activate a site's nginx vhost.
pub async fn render_vhost(
    ctx: &OpContext,
    site: &Site,
    linux_user: &ferrum_core::LinuxUser,
) -> Result<()> {
    render_vhost_mode(ctx, site, linux_user, false).await
}

/// [`render_vhost`], with the maintenance page optionally forced on regardless
/// of the site's own toggle.
///
/// This is the suspension path (spec §6.4): suspending a subscription must not
/// overwrite the tenant's own `maintenance_mode` flag in the database — that
/// would clobber their setting on reinstatement — so the override lives only
/// in the rendered output, and unsuspending re-renders from the stored flags.
pub async fn render_vhost_mode(
    ctx: &OpContext,
    site: &Site,
    linux_user: &ferrum_core::LinuxUser,
    force_maintenance: bool,
) -> Result<()> {
    let db = ctx.db();
    let mut context = site_context(site, linux_user)?;
    if force_maintenance {
        context.maintenance_mode = true;
    }

    let aliases: Vec<String> = db
        .sites(&ferrum_core::TenantScope::Global)
        .aliases(site.id)
        .await
        .map_err(FerrumError::from)?
        .into_iter()
        .map(|a| a.domain)
        .collect();
    context = context.with_aliases(&aliases);

    // TLS only once there is a certificate on disk. Pointing nginx at a
    // certificate that does not exist stops it from starting at all — which
    // would take every other site on the server down with this one.
    let cert_dir = paths::cert_dir(&site.domain);
    if crate::tls::certificate_present(&cert_dir) {
        context = context.with_tls(&cert_dir, true);
    }

    ctx.config()
        .apply(ApplyRequest {
            file: ManagedFile::nginx(paths::nginx_site(&site.domain)),
            template: "nginx/site.conf",
            context: serde_json::json!({
                "site": context,
                "acme_webroot": paths::acme_webroot(),
                "maintenance_root": paths::maintenance_root(),
            }),
            service: "nginx",
            validator: &NginxValidator,
            reloader: &UnitReloader::nginx(ctx.distro()),
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;

    ctx.log(format!("vhost active for {}", site.domain));
    Ok(())
}

async fn render_logrotate(
    ctx: &OpContext,
    site: &Site,
    linux_user: &ferrum_core::LinuxUser,
) -> Result<()> {
    use ferrum_config::apply::{Reloader, Validator};

    struct Noop;
    #[async_trait]
    impl Validator for Noop {
        fn name(&self) -> &'static str {
            "logrotate"
        }
        async fn validate(&self) -> std::result::Result<(), String> {
            Ok(())
        }
    }
    #[async_trait]
    impl Reloader for Noop {
        fn name(&self) -> &'static str {
            "logrotate"
        }
        async fn reload(&self) -> std::result::Result<(), String> {
            Ok(())
        }
    }

    ctx.config()
        .apply(ApplyRequest {
            file: ManagedFile::nginx(paths::logrotate_site(&site.domain)),
            template: "logrotate/site",
            context: serde_json::json!({
                "domain": site.domain,
                "log_dir": paths::site_log_dir(&site.domain),
                "keep_days": 14,
                "user": "root",
                "group": linux_user.as_str(),
            }),
            service: "logrotate",
            validator: &Noop,
            reloader: &Noop,
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;
    Ok(())
}

/// Build the template context for a stored site.
pub fn site_context(site: &Site, linux_user: &ferrum_core::LinuxUser) -> Result<SiteContext> {
    let ctx_type = match site.site_type {
        SiteType::Php => CtxSiteType::Php,
        SiteType::Static => CtxSiteType::Static,
        SiteType::Proxy => CtxSiteType::Proxy,
        SiteType::Redirect => CtxSiteType::Redirect,
    };

    let mut context = SiteContext::new(
        &site.domain,
        linux_user.as_str(),
        ctx_type,
        site.php_version.unwrap_or(PhpVersion::V83),
    );

    context.force_https = site.force_https;
    context.http3 = site.http3;
    context.maintenance_mode = site.maintenance_mode;
    context.client_max_body_size = site.client_max_body_size.clone();
    context.custom_snippet = site.custom_nginx_snippet.clone();
    context.rate_limit_enabled = site.rate_limit_enabled;
    context.rate_limit_rps = site.rate_limit_rps.clamp(1, 10_000) as u32;
    context.rate_limit_burst = site.rate_limit_burst.clamp(1, 100_000) as u32;
    context.conn_limit = site.conn_limit.clamp(1, 10_000) as u32;

    if let Some(port) = site.proxy_port {
        context.proxy_port = port.clamp(1, 65_535) as u16;
    }
    if let Some(target) = &site.redirect_target {
        context.redirect_target = target.clone();
        context.redirect_code = site.redirect_code.clamp(300, 399) as u16;
    }

    Ok(context)
}

/// Refuse to create a PHP site on a version that is not installed.
///
/// The vhost would render, nginx would reload, and every request would 502 —
/// with nothing in the panel explaining why.
async fn require_php_installed(ctx: &OpContext, version: PhpVersion) -> Result<()> {
    let slug = crate::stack::StackComponent::Php { version }.slug();
    let component = ctx.db().component(&slug).await.map_err(FerrumError::from)?;

    let installed = component
        .map(|c| c.status == ferrum_db::ComponentStatus::Installed)
        .unwrap_or(false);

    if installed {
        return Ok(());
    }

    // Trust systemd over our own bookkeeping: PHP may have been installed
    // before the panel, or by hand.
    let unit =
        ferrum_distro::svc::ManagedUnit::PhpFpm { version }.unit_name(ctx.distro().info.family);
    if ctx
        .distro()
        .svc
        .status(&unit)
        .await
        .map(|s| s.is_installed())
        .unwrap_or(false)
    {
        return Ok(());
    }

    Err(FerrumError::new(
        ErrorCode::NotFound,
        format!(
            "PHP {} is not installed. Install it from the Stack Manager first.",
            version.as_str()
        ),
    )
    .with_field("php_version"))
}

// ---------------------------------------------------------------------------
// site.update
// ---------------------------------------------------------------------------

pub struct Update;

#[derive(Debug, Deserialize)]
pub struct UpdateInput {
    pub site_id: i64,
    #[serde(default)]
    pub php_version: Option<PhpVersion>,
    #[serde(default)]
    pub force_https: Option<bool>,
    #[serde(default)]
    pub http3: Option<bool>,
    #[serde(default)]
    pub maintenance_mode: Option<bool>,
    #[serde(default)]
    pub client_max_body_size: Option<String>,
    #[serde(default)]
    pub custom_nginx_snippet: Option<Option<String>>,
    #[serde(default)]
    pub php_ini_overrides: Option<Option<String>>,
    #[serde(default)]
    pub rate_limit_enabled: Option<bool>,
    #[serde(default)]
    pub www_policy: Option<WwwPolicyInput>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WwwPolicyInput {
    None,
    Add,
    Strip,
}

impl From<WwwPolicyInput> for WwwPolicy {
    fn from(v: WwwPolicyInput) -> Self {
        match v {
            WwwPolicyInput::None => WwwPolicy::None,
            WwwPolicyInput::Add => WwwPolicy::Add,
            WwwPolicyInput::Strip => WwwPolicy::Strip,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UpdateOutput {
    pub site_id: i64,
    pub domain: String,
    pub reloaded: bool,
}

#[async_trait]
impl TypedOperation for Update {
    type Input = UpdateInput;
    type Output = UpdateOutput;

    const NAME: &'static str = "site.update";
    const PERMISSION: Permission = Permission::SiteManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db().clone();
        let id = SiteId(input.site_id);
        let repo = db.sites(ctx.scope());

        let before = repo
            .by_id(id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("site"))?;

        if let Some(version) = input.php_version {
            require_php_installed(ctx, version).await?;
        }
        if let Some(snippet) = input.custom_nginx_snippet.as_ref().and_then(|s| s.as_ref()) {
            check_snippet(snippet)?;
        }

        let site = repo
            .update(
                id,
                SiteUpdate {
                    php_version: input.php_version,
                    www_policy: input.www_policy.map(Into::into),
                    force_https: input.force_https,
                    http3: input.http3,
                    maintenance_mode: input.maintenance_mode,
                    client_max_body_size: input.client_max_body_size,
                    custom_nginx_snippet: input.custom_nginx_snippet,
                    php_ini_overrides: input.php_ini_overrides,
                    rate_limit_enabled: input.rate_limit_enabled,
                    proxy_port: None,
                    redirect_target: None,
                },
            )
            .await
            .map_err(FerrumError::from)?;

        let subscription = db
            .subscriptions(&ferrum_core::TenantScope::Global)
            .by_id(site.subscription_id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::internal("the site's subscription is missing"))?;
        let linux_user = ferrum_core::LinuxUser::parse(&subscription.linux_user)?;

        // A PHP version change needs the new pool in place before the vhost
        // points at its socket, and the old pool removed only afterwards.
        if let Some(new_version) = input.php_version
            && before.php_version != Some(new_version)
        {
            render_pool(ctx, &site, &linux_user, new_version).await?;
            render_vhost(ctx, &site, &linux_user).await?;
            if let Some(old) = before.php_version {
                remove_pool(ctx, &before, old).await;
            }
        } else {
            if let Some(version) = site.php_version {
                render_pool(ctx, &site, &linux_user, version).await?;
            }
            render_vhost(ctx, &site, &linux_user).await?;
        }

        Ok(UpdateOutput {
            site_id: site.id.get(),
            domain: site.domain,
            reloaded: true,
        })
    }
}

/// Reject a snippet that could not possibly be a fragment of a server block.
///
/// `nginx -t` is the real check and runs before anything is activated; this only
/// catches the obvious cases early, with a message that points at the problem.
fn check_snippet(snippet: &str) -> Result<()> {
    const MAX: usize = 16 * 1024;
    if snippet.len() > MAX {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "the custom snippet is too large; put a long configuration in an include file",
        )
        .with_field("custom_nginx_snippet"));
    }
    if snippet.contains('\0') {
        return Err(
            FerrumError::new(ErrorCode::InvalidInput, "the snippet contains a NUL byte")
                .with_field("custom_nginx_snippet"),
        );
    }

    // Braces must balance, or the rendered vhost would swallow everything after
    // it — including the deny rules below the snippet.
    let mut depth = 0i32;
    for c in snippet.chars() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return Err(FerrumError::new(
                        ErrorCode::InvalidInput,
                        "the snippet closes a block it did not open",
                    )
                    .with_field("custom_nginx_snippet"));
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(
            FerrumError::new(ErrorCode::InvalidInput, "the snippet leaves a block open")
                .with_field("custom_nginx_snippet"),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// site.delete
// ---------------------------------------------------------------------------

pub struct Delete;

#[derive(Debug, Deserialize)]
pub struct DeleteInput {
    pub site_id: i64,
    /// Also delete the site's files. Off by default: a deleted vhost is
    /// recoverable, a deleted home directory is not.
    #[serde(default)]
    pub purge_files: bool,
}

#[derive(Debug, Serialize)]
pub struct DeleteOutput {
    pub domain: String,
    pub files_removed: bool,
}

#[async_trait]
impl TypedOperation for Delete {
    type Input = DeleteInput;
    type Output = DeleteOutput;

    const NAME: &'static str = "site.delete";
    const PERMISSION: Permission = Permission::SiteManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db().clone();
        let id = SiteId(input.site_id);
        let site = db
            .sites(ctx.scope())
            .by_id(id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("site"))?;

        let subscription = db
            .subscriptions(&ferrum_core::TenantScope::Global)
            .by_id(site.subscription_id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::internal("the site's subscription is missing"))?;
        let linux_user = ferrum_core::LinuxUser::parse(&subscription.linux_user)?;
        let domain = Domain::parse(&site.domain)?;

        // The vhost first: stop serving before removing what was served.
        let vhost = ManagedFile::nginx(paths::nginx_site(&site.domain));
        ctx.config()
            .remove(
                &vhost,
                "nginx",
                &NginxValidator,
                &UnitReloader::nginx(ctx.distro()),
            )
            .await?;
        ctx.log(format!("removed the vhost for {}", site.domain));

        if let Some(version) = site.php_version {
            remove_pool(ctx, &site, version).await;
        }

        // Logrotate config, then the revision history for both files.
        let _ = std::fs::remove_file(paths::logrotate_site(&site.domain));
        for path in [
            paths::nginx_site(&site.domain),
            paths::logrotate_site(&site.domain),
        ] {
            let _ = db.forget_revisions(&path.to_string_lossy()).await;
        }

        if input.purge_files {
            provision::remove_site_dirs(&linux_user, &domain).await?;
            ctx.log("removed the site's files");
        } else {
            ctx.log(format!(
                "left {} in place; delete it by hand or re-run with purge_files",
                site.root_dir
            ));
        }

        db.sites(ctx.scope())
            .delete(id)
            .await
            .map_err(FerrumError::from)?;
        Ok(DeleteOutput {
            domain: site.domain,
            files_removed: input.purge_files,
        })
    }
}

/// Remove a site's pool for one PHP version.
///
/// Failures are logged rather than propagated: a leftover pool file is untidy,
/// but failing a delete because of one would leave the site half-removed, which
/// is worse.
async fn remove_pool(ctx: &OpContext, site: &Site, version: PhpVersion) {
    let family = ctx.distro().info.family;
    let file = ManagedFile::fpm_pool(paths::fpm_pool_file(family, version, &site.domain));
    let service = format!("php-fpm-{}", version.as_str());

    match ctx
        .config()
        .remove(
            &file,
            &service,
            &FpmValidator::new(ctx.distro(), version),
            &UnitReloader::fpm(ctx.distro(), version),
        )
        .await
    {
        Ok(true) => ctx.log(format!("removed the PHP {} pool", version.as_str())),
        Ok(false) => {}
        Err(e) => ctx.log(format!(
            "could not remove the PHP {} pool: {e}",
            version.as_str()
        )),
    }
}

// ---------------------------------------------------------------------------
// site.drift
// ---------------------------------------------------------------------------

/// `site.drift` — has somebody edited this site's generated files?
pub struct Drift;

#[derive(Debug, Deserialize)]
pub struct DriftInput {
    pub site_id: i64,
}

#[derive(Debug, Serialize)]
pub struct DriftOutput {
    pub path: String,
    pub state: String,
    pub diff: Vec<ferrum_config::DiffLine>,
}

#[async_trait]
impl TypedOperation for Drift {
    type Input = DriftInput;
    type Output = DriftOutput;

    const NAME: &'static str = "site.drift";
    const PERMISSION: Permission = Permission::SiteRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();
        let site = db
            .sites(ctx.scope())
            .by_id(SiteId(input.site_id))
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("site"))?;

        let subscription = db
            .subscriptions(&ferrum_core::TenantScope::Global)
            .by_id(site.subscription_id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::internal("the site's subscription is missing"))?;
        let linux_user = ferrum_core::LinuxUser::parse(&subscription.linux_user)?;

        let mut context = site_context(&site, &linux_user)?;
        let aliases: Vec<String> = db
            .sites(ctx.scope())
            .aliases(site.id)
            .await
            .map_err(FerrumError::from)?
            .into_iter()
            .map(|a| a.domain)
            .collect();
        context = context.with_aliases(&aliases);

        let cert_dir = paths::cert_dir(&site.domain);
        if crate::tls::certificate_present(&cert_dir) {
            context = context.with_tls(&cert_dir, true);
        }

        let report = ctx.config().drift_report(
            &ManagedFile::nginx(paths::nginx_site(&site.domain)),
            "nginx/site.conf",
            &serde_json::json!({
                "site": context,
                "acme_webroot": paths::acme_webroot(),
                "maintenance_root": paths::maintenance_root(),
            }),
        )?;

        Ok(DriftOutput {
            path: report.path.to_string_lossy().into_owned(),
            state: format!("{:?}", report.state).to_lowercase(),
            diff: report.diff,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snippet_must_balance_its_braces() {
        // An unbalanced snippet would swallow everything below it in the vhost,
        // including the rules that deny dotfiles.
        assert!(check_snippet("location /x { return 204; }").is_ok());
        assert!(check_snippet("add_header X-Test 1;").is_ok());
        assert!(check_snippet("").is_ok());

        assert!(check_snippet("location /x { return 204;").is_err());
        assert!(check_snippet("}").is_err());
        assert!(check_snippet("} location /y { ").is_err());
    }

    #[test]
    fn a_snippet_is_bounded_and_free_of_nul() {
        assert!(check_snippet(&"a".repeat(20_000)).is_err());
        assert!(check_snippet("ok\0bad").is_err());
    }

    #[test]
    fn the_api_site_type_maps_onto_storage() {
        for (input, expected) in [
            (SiteTypeInput::Php, SiteType::Php),
            (SiteTypeInput::Static, SiteType::Static),
            (SiteTypeInput::Proxy, SiteType::Proxy),
            (SiteTypeInput::Redirect, SiteType::Redirect),
        ] {
            assert_eq!(SiteType::from(input), expected);
        }
    }

    #[test]
    fn a_site_type_cannot_be_an_arbitrary_string() {
        assert!(serde_json::from_str::<SiteTypeInput>("\"php\"").is_ok());
        assert!(serde_json::from_str::<SiteTypeInput>("\"wordpress\"").is_err());
    }
}
