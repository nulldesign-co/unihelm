//! Site lifecycle (spec §11.2): the operation that turns a domain into
//! something nginx serves.
//!
//! The order matters and is the same every time: the Linux account and the
//! directory layout first, then the FPM pool, then the vhost. Each step is
//! validated by the service that will have to live with it, and the config
//! engine puts the previous state back if any of them refuses. If it all fails
//! at the last hurdle, the server is exactly as it was and the site row says
//! why.

use std::path::Path;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_config::apply::ApplyRequest;
use unihelm_config::context::{PoolContext, SiteContext, SiteType as CtxSiteType};
use unihelm_config::managed::ManagedFile;
use unihelm_config::paths;
use unihelm_core::{
    Domain, ErrorCode, Permission, PhpVersion, Result, SiteId, SubscriptionId, UnihelmError,
};
use unihelm_db::sites::{DomainOwner, NewSite, Site, SiteStatus, SiteType, SiteUpdate, WwwPolicy};

use crate::nginx_survey;
use crate::provision;
use crate::registry::{Execution, OpContext, TypedOperation};
use crate::services::{FpmValidator, UnitReloader};

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
            .map_err(UnihelmError::from)?;

        let mut views = Vec::with_capacity(sites.len());
        for site in sites {
            let aliases = repo
                .aliases(site.id)
                .await
                .map_err(UnihelmError::from)?
                .into_iter()
                .map(|a| a.domain)
                .collect();
            let subscription = db
                .subscriptions(ctx.scope())
                .by_id(site.subscription_id)
                .await
                .map_err(UnihelmError::from)?;
            let certificate = db
                .active_certificate_for_site(site.id)
                .await
                .map_err(UnihelmError::from)?;

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
                UnihelmError::new(ErrorCode::InvalidInput, "a PHP site needs a PHP version")
                    .with_field("php_version")
            })?;
            require_php_installed(ctx, version).await?;
            Some(version)
        } else {
            None
        };

        if site_type == SiteType::Proxy && input.proxy_port.is_none() {
            return Err(
                UnihelmError::new(ErrorCode::InvalidInput, "a proxy site needs a port")
                    .with_field("proxy_port"),
            );
        }
        if site_type == SiteType::Redirect && input.redirect_target.is_none() {
            return Err(UnihelmError::new(
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
                .map_err(UnihelmError::from)?
                .ok_or_else(|| UnihelmError::not_found("subscription"))?,
            None => db
                .default_subscription_for(ctx.auth().actor_user_id)
                .await
                .map_err(UnihelmError::from)?,
        };

        if !subscription.status.can_serve() {
            return Err(UnihelmError::new(
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

        let linux_user = unihelm_core::LinuxUser::parse(&subscription.linux_user)?;
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
                    .map_err(UnihelmError::from)?
            }
            None => {
                refuse_foreign_vhost(&input.domain, input.with_www)?;
                db.create_site(wanted).await.map_err(UnihelmError::from)?
            }
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
                    .map_err(UnihelmError::from)?;
                ctx.log(format!("{} is live", site.domain));

                // Tell whoever is integrating (spec §2.4, §14 Phase 6). Never
                // fatal: a site that is live is live whether or not a
                // notification could be queued.
                crate::webhook::emit(
                    ctx,
                    "site.created",
                    serde_json::json!({
                        "site_id": site.id.get(),
                        "domain": site.domain.to_string(),
                        "subscription_id": site.subscription_id.get(),
                    }),
                )
                .await;

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
    linux_user: &unihelm_core::LinuxUser,
) -> Result<()> {
    let distro = ctx.distro().clone();
    let domain = Domain::parse(&site.domain)?;
    let log = ctx.log_sink();

    // 1. The account and the directory layout.
    let subscription = ctx
        .db()
        .subscription_by_linux_user(linux_user.as_str())
        .await
        .map_err(UnihelmError::from)?
        .ok_or_else(|| UnihelmError::internal("the subscription vanished mid-provision"))?;

    provision::ensure_tenant_user(ctx, linux_user, &subscription.home_dir, false).await?;
    provision::ensure_site_dirs(&distro, linux_user, &domain, log).await?;
    if document_root_is_empty(&paths::site_public(linux_user.as_str(), domain.as_str())) {
        provision::write_placeholder(linux_user, &domain).await?;
    }

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

/// Has anything been put in this site's document root yet?
///
/// The holding page is a courtesy for a root nobody has uploaded to. Every
/// caller of [`provision_site`] can now be a *second* run over a root that is
/// not new — `site.create` reclaiming a failed row, and `site.reprovision` —
/// and `site.create`'s unwind deliberately leaves the tenant's directory alone
/// when provisioning fails, so what is in there is theirs.
///
/// `write_placeholder` only declines when `index.html` is already present,
/// which is the wrong question on a retry: a static site uploaded as
/// `index.htm`, or an application whose entry point is anywhere else, would
/// have had the panel's "Upload your files to replace this page" dropped in
/// beside it — and nginx's `index index.php index.html index.htm;` prefers the
/// panel's file to the tenant's. The panel would then report the site as live,
/// which it would be, serving the wrong page.
fn document_root_is_empty(root: &Path) -> bool {
    match std::fs::read_dir(root) {
        Ok(mut entries) => entries.next().is_none(),
        // Absent means nothing has been uploaded — the ordinary first create,
        // where `ensure_site_dirs` has just made the tree. Any other error is
        // a root we cannot see into, and writing into one of those blind is
        // exactly what this guard exists to stop.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

/// Render and activate a site's PHP-FPM pool.
///
/// **Nothing about mail happens here any more, and that is the point.** This
/// function used to read the `mail_relay` row and call
/// `mail::write_site_relay`, which wrote `/etc/unihelm/mail/<domain>.msmtprc`
/// and returned the `sendmail_path` the pool then pointed PHP at. Creating a
/// site was therefore also an act of copying the server's single upstream relay
/// credential into a file that site's tenant could read — and mail worked only
/// for sites that had a PHP pool, because `sendmail_path` is an FPM directive
/// and nothing else on the box ever saw it.
///
/// Outbound mail is now a host service (a Postfix null client) rather than a
/// per-site PHP setting: it holds the credential as root, and PHP's own default
/// hands messages to `/usr/sbin/sendmail`, which is that MTA. So a pool has no
/// mail configuration to render, a site has no mail file to write, and this
/// function is back to being about FPM. There is deliberately no
/// `render_pool_with_mail` variant left for a caller to reach for.
pub async fn render_pool(
    ctx: &OpContext,
    site: &Site,
    linux_user: &unihelm_core::LinuxUser,
    version: PhpVersion,
) -> Result<()> {
    let distro = ctx.distro();
    let family = distro.info.family;

    // The socket directory must exist before FPM tries to bind in it.
    std::fs::create_dir_all(paths::fpm_socket_dir())
        .map_err(|e| UnihelmError::internal(format!("could not create the FPM socket dir: {e}")))?;

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
    if let Some(note) = missing_mta_note(
        &site.domain,
        unihelm_distro::exec::program_available(SENDMAIL_PROGRAM),
    ) {
        ctx.log(note);
    }
    Ok(())
}

/// The `sendmail`-compatible program PHP hands a message to.
///
/// Resolved through `unihelm_distro`'s trusted directories rather than `PATH`,
/// like every other program name in this codebase. On a machine that has the
/// panel's mail service this is the MTA's own drop-in for it.
const SENDMAIL_PROGRAM: &str = "sendmail";

/// What to tell the operator when a PHP pool lands on a machine with no local
/// mail agent.
///
/// Not a refusal. A site that serves but cannot send mail is a support ticket
/// and a site that does not exist is an outage, which is the trade the old
/// per-site relay write made too. What it must not do is stay quiet: with
/// `sendmail_path` out of the pool, PHP hands messages to the system's
/// `sendmail`, and when there is none `mail()` returns false with nothing in
/// any log the operator reads to say why. It is not "mail is broken on this
/// site", it is "this machine has no mail service yet" — a different fix, in a
/// different place, and worth naming as such.
fn missing_mta_note(domain: &str, sendmail_present: bool) -> Option<String> {
    if sendmail_present {
        return None;
    }
    Some(format!(
        "there is no local mail agent on this machine, so PHP's mail() from {domain} has \
         nothing to hand a message to and will return false. This is a server-wide gap, not \
         a setting on this site: install the panel's mail service and every site, app and \
         cron job on the box can send. Nothing here needs re-rendering afterwards."
    ))
}

/// Is this create request a retry of a failed site we already own?
///
/// Returns the row to reclaim, `None` if the domain is free, and an error if it
/// belongs to something we must not take over. The error is the whole point of
/// the function: "`example.com` is already a site" tells an operator nothing
/// about what to do next, whereas naming the state does.
async fn retryable_site(
    ctx: &OpContext,
    domain: &unihelm_core::Domain,
    subscription_id: unihelm_core::SubscriptionId,
) -> Result<Option<Site>> {
    let db = ctx.db();

    // Global, not the caller's scope: a domain taken by a tenant this caller
    // cannot see is still taken, and answering "free" would produce a duplicate
    // `server_name` that nginx resolves by parse order.
    let Some(existing) = db
        .sites(&unihelm_core::TenantScope::Global)
        .by_domain(domain.as_str())
        .await
        .map_err(UnihelmError::from)?
    else {
        return Ok(None);
    };

    if existing.subscription_id != subscription_id {
        return Err(UnihelmError::new(
            ErrorCode::DomainAlreadyExists,
            format!("`{domain}` already belongs to another subscription"),
        ));
    }

    match existing.status {
        SiteStatus::Failed => Ok(Some(existing)),
        SiteStatus::Provisioning => Err(UnihelmError::new(
            ErrorCode::Conflict,
            format!("`{domain}` is still being provisioned; wait for that task to finish"),
        )),
        SiteStatus::Active | SiteStatus::Suspended => Err(UnihelmError::new(
            ErrorCode::DomainAlreadyExists,
            format!("`{domain}` is already a site; delete it first if you want to recreate it"),
        )),
    }
}

/// Refuse a domain that a vhost outside the panel already answers for.
///
/// A duplicate `server_name` is a warning to nginx, not an error, so `nginx -t`
/// passes and nothing is said — but our blocks come in from
/// `conf.d/unihelm.conf`, which stock `nginx.conf` reads before `sites-enabled`,
/// so the panel's brand-new placeholder wins the name and the operator's live
/// site goes dark while the panel reports a successful creation.
///
/// The way past it is to disable the hand-written vhost, not a flag: whichever
/// of the two files stays, only one of them may serve the name.
fn refuse_foreign_vhost(domain: &Domain, with_www: bool) -> Result<()> {
    let mut wanted = vec![domain.as_str().to_string()];
    if with_www && let Ok(www) = domain.with_www() {
        wanted.push(www.as_str().to_string());
    }

    let Some((taken, file)) = foreign_server_name(&nginx_survey::discover_sites(), &wanted) else {
        return Ok(());
    };

    Err(UnihelmError::new(
        ErrorCode::Conflict,
        format!(
            "`{taken}` is already served by `{file}`, an nginx vhost this panel did not \
             write. Creating the site would shadow it and take it offline; disable that \
             vhost first."
        ),
    )
    .with_field("domain"))
}

/// The first of `wanted` a foreign vhost already declares, and the file that
/// declares it.
///
/// Read through `discover_sites` rather than `survey`, whose `server_names` are
/// a flat set gathered line by line. Two reasons, and the second is the one that
/// matters: a flat set cannot name the file the operator has to go and edit, and
/// a line scan misses `server { listen 80; server_name x; }` written on one line
/// entirely — which is a guard against a silent outage failing silently.
/// `sites.discover` reads the same way, so what this refuses and what the
/// operator is shown are the same vhosts.
///
/// Exact names only. A foreign `*.example.com` is left alone deliberately:
/// nginx prefers an exact `server_name` over a wildcard, so the panel's block
/// takes only the one name it was asked for rather than shadowing the vhost.
fn foreign_server_name(
    vhosts: &[nginx_survey::DiscoveredSite],
    wanted: &[String],
) -> Option<(String, String)> {
    vhosts.iter().find_map(|vhost| {
        vhost
            .server_names
            .iter()
            .find(|name| wanted.iter().any(|w| w.eq_ignore_ascii_case(name)))
            .map(|name| (name.clone(), vhost.config_file.clone()))
    })
}

/// Render and activate a site's nginx vhost.
pub async fn render_vhost(
    ctx: &OpContext,
    site: &Site,
    linux_user: &unihelm_core::LinuxUser,
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
    linux_user: &unihelm_core::LinuxUser,
    force_maintenance: bool,
) -> Result<()> {
    let server = crate::webserver::active(ctx).await?;
    render_vhost_inner(ctx, site, linux_user, force_maintenance, server).await
}

/// [`render_vhost`], for a web server that is not (yet) the active one.
///
/// The switch's path, and its only caller. It writes a site's vhost into the
/// *target's* tree while the incumbent is still serving out of its own, which is
/// what lets the whole machine be prepared and checked before anything stops.
pub async fn render_vhost_for(
    ctx: &OpContext,
    site: &Site,
    linux_user: &unihelm_core::LinuxUser,
    server: crate::webserver::WebServer,
) -> Result<()> {
    render_vhost_inner(ctx, site, linux_user, false, server).await
}

async fn render_vhost_inner(
    ctx: &OpContext,
    site: &Site,
    linux_user: &unihelm_core::LinuxUser,
    force_maintenance: bool,
    server: crate::webserver::WebServer,
) -> Result<()> {
    let db = ctx.db();
    let mut context = site_context(site, linux_user)?;

    // Suspension is a property of the subscription, so it is read here rather
    // than trusted from the caller.
    //
    // It used to live only in `force_maintenance`, which `plan.rs` passed when
    // it suspended — and nothing else did. Certificate renewal calls
    // `render_vhost`, which passes false, so the first renewal inside the
    // thirty-day window rewrote a suspended tenant's vhost without the 503 and
    // reloaded nginx: the site came back, unattended, while the panel still
    // showed it as suspended. `site.drift` built its expected file the same way,
    // so every suspended site also reported as hand-edited.
    let suspended = match db
        .subscriptions(&unihelm_core::TenantScope::Global)
        .by_id(site.subscription_id)
        .await
        .map_err(UnihelmError::from)?
    {
        Some(sub) => !sub.status.can_serve(),
        // A site whose subscription has gone is not one to serve either.
        None => true,
    };

    if force_maintenance || suspended {
        context.maintenance_mode = true;
    }

    let aliases: Vec<String> = db
        .sites(&unihelm_core::TenantScope::Global)
        .aliases(site.id)
        .await
        .map_err(UnihelmError::from)?
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

    // One server, used for all four of file, template, validator and reloader.
    // Mixing two of them — the other server's template into this one's path, or
    // this one's file checked with the other one's `-t` — is a way to take every
    // site on the machine down that no individual argument would look wrong for.
    let vhost = server.site_vhost(&site.domain)?;
    let reloader = server.reloader(ctx.distro())?;

    ctx.config()
        .apply(ApplyRequest {
            file: vhost.file,
            template: vhost.template,
            context: serde_json::json!({
                "site": context,
                "acme_webroot": paths::acme_webroot(),
                "maintenance_root": paths::maintenance_root(),
            }),
            service: vhost.service,
            validator: server.validator()?,
            reloader: &reloader,
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
    linux_user: &unihelm_core::LinuxUser,
) -> Result<()> {
    use unihelm_config::apply::{Reloader, Validator};

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
pub fn site_context(site: &Site, linux_user: &unihelm_core::LinuxUser) -> Result<SiteContext> {
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

    // Through the setter: it decides what the site listens on, and assigning
    // the field alone is how a TLS site that does not redirect ends up with no
    // port 80 at all.
    context = context.with_force_https(site.force_https);
    context.http3 = site.http3;
    context.maintenance_mode = site.maintenance_mode;
    // Through the setter, which keeps the byte count in step: nginx enforces
    // the string and Apache the number, and setting one without the other is a
    // machine whose upload limit changes when its web server does.
    context = context.with_body_size(&site.client_max_body_size);
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
    let slug = crate::stack::StackComponent::resolve("php", Some(version.as_str()))?.slug();
    let component = ctx
        .db()
        .component(&slug)
        .await
        .map_err(UnihelmError::from)?;

    let installed = component
        .map(|c| c.status == unihelm_db::ComponentStatus::Installed)
        .unwrap_or(false);

    if installed {
        return Ok(());
    }

    // Trust systemd over our own bookkeeping: PHP may have been installed
    // before the panel, or by hand.
    let unit =
        unihelm_distro::svc::ManagedUnit::PhpFpm { version }.unit_name(ctx.distro().info.family);
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

    Err(UnihelmError::new(
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
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("site"))?;

        if let Some(version) = input.php_version {
            require_php_installed(ctx, version).await?;
        }
        // Raw configuration is an operator's tool, not a tenant's.
        //
        // `check_snippet` bounds the length, refuses a NUL and balances braces —
        // and none of that constrains what the directives *do*. A customer holds
        // SiteManage, the snippet lands inside their own server block, and the
        // nginx worker can traverse every tenant's tree and reach every tenant's
        // FPM socket, so `location ^~ /grab/ { alias /home/; }` reads other
        // people's sites. There is no validator that makes arbitrary nginx safe;
        // the answer is who is allowed to write it.
        if (input.custom_nginx_snippet.is_some() || input.php_ini_overrides.is_some())
            && !matches!(ctx.auth().acting_role, unihelm_core::Role::Admin)
        {
            return Err(UnihelmError::new(
                ErrorCode::PermissionDenied,
                "custom_nginx_snippet and php_ini_overrides are operator settings; \
                     ask your administrator to set them",
            )
            .with_field("custom_nginx_snippet"));
        }
        // A setting nothing renders is worse than a setting that is missing.
        //
        // `www_policy` was stored, echoed back by `site.list` and offered as a
        // choice in the UI, and no part of it ever reached nginx: `SiteContext`
        // has no www field and `site.conf` emits no redirect. An operator who
        // chose "strip www" got a success, a reload, and www.example.com serving
        // duplicate content for as long as they never checked. Until the vhost
        // renders it, say so.
        if input.www_policy.is_some() {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "the www policy is not implemented: nothing renders it into the vhost. \
                 Add or remove the `www.` alias instead",
            )
            .with_field("www_policy"));
        }
        if let Some(snippet) = input.custom_nginx_snippet.as_ref().and_then(|s| s.as_ref()) {
            check_snippet(snippet)?;
        }
        // The role gate above says who may write this box; it never said what
        // may be in it, and the pool renders it after the isolation lines.
        if let Some(overrides) = input.php_ini_overrides.as_ref().and_then(|s| s.as_ref()) {
            check_php_overrides(overrides)?;
        }
        if let Some(size) = input.client_max_body_size.as_ref() {
            check_body_size(size)?;
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
            .map_err(UnihelmError::from)?;

        let subscription = db
            .subscriptions(&unihelm_core::TenantScope::Global)
            .by_id(site.subscription_id)
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::internal("the site's subscription is missing"))?;
        let linux_user = unihelm_core::LinuxUser::parse(&subscription.linux_user)?;

        // The row is already written, so a render that nginx or FPM refuses has
        // to be undone here.
        //
        // The config engine restores the file it replaced and reports
        // `ValidationFailed`, which leaves disk right and the database wrong:
        // a snippet `nginx -t` rejected stays stored, and every later render of
        // this site — a certificate renewal, a suspension, an unsuspension —
        // builds the same rejected file and fails the same way. The value the
        // server never accepted must not survive the operation that proposed it.
        if let Err(e) = apply_settings(ctx, &site, &before, &linux_user, input.php_version).await {
            if let Err(revert) = repo.update(id, revert_to(&before)).await {
                ctx.log(format!(
                    "could not put {}'s settings back after the failed render: {revert}",
                    site.domain
                ));
            }
            return Err(e);
        }

        Ok(UpdateOutput {
            site_id: site.id.get(),
            domain: site.domain,
            reloaded: true,
        })
    }
}

/// Put the stored settings on disk: the pool, then the vhost that points at it.
async fn apply_settings(
    ctx: &OpContext,
    site: &Site,
    before: &Site,
    linux_user: &unihelm_core::LinuxUser,
    requested_version: Option<PhpVersion>,
) -> Result<()> {
    // A PHP version change needs the new pool in place before the vhost points
    // at its socket, and the old pool removed only afterwards.
    if let Some(new_version) = requested_version
        && before.php_version != Some(new_version)
    {
        render_pool(ctx, site, linux_user, new_version).await?;
        render_vhost(ctx, site, linux_user).await?;
        if let Some(old) = before.php_version {
            remove_pool(ctx, before, old).await;
        }
    } else {
        if let Some(version) = site.php_version {
            render_pool(ctx, site, linux_user, version).await?;
        }
        render_vhost(ctx, site, linux_user).await?;
    }
    Ok(())
}

/// The update that puts a site's settings back the way they were.
///
/// Every field `UpdateInput` can change is named here. One that is missed is a
/// value that survives its own rejection, which is the defect this exists to
/// undo — so the test next to it asserts the whole set, not a sample.
fn revert_to(before: &Site) -> SiteUpdate {
    SiteUpdate {
        php_version: before.php_version,
        www_policy: Some(before.www_policy),
        force_https: Some(before.force_https),
        http3: Some(before.http3),
        maintenance_mode: Some(before.maintenance_mode),
        client_max_body_size: Some(before.client_max_body_size.clone()),
        custom_nginx_snippet: Some(before.custom_nginx_snippet.clone()),
        php_ini_overrides: Some(before.php_ini_overrides.clone()),
        rate_limit_enabled: Some(before.rate_limit_enabled),
        proxy_port: None,
        redirect_target: None,
    }
}

/// Reject a snippet that could not possibly be a fragment of a server block.
///
/// `nginx -t` is the real check and runs before anything is activated; this only
/// catches the obvious cases early, with a message that points at the problem.
/// An nginx size value, and nothing else.
///
/// This lands in the vhost unquoted — `client_max_body_size {{ … }};` — so
/// anything accepted here is a directive a tenant gets to write. `64m; root
/// /etc; #` was a valid value: it closed the directive, opened a document root
/// over the system's configuration, and commented out the rest of the line. The
/// snippet field next to it has been validated since it was added; this one
/// never was.
///
/// nginx accepts a number with an optional k, m or g suffix, case-insensitive.
/// Nothing else is a size, so nothing else is accepted.
fn check_body_size(value: &str) -> Result<()> {
    let trimmed = value.trim();
    let reject = || {
        UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "`{value}` is not a size. Use a number with an optional k, m or g \
                 suffix, for example `64m`."
            ),
        )
        .with_field("client_max_body_size")
    };

    if trimmed.is_empty() || trimmed.len() > 16 {
        return Err(reject());
    }

    let (digits, suffix) = match trimmed.as_bytes().last() {
        Some(c) if c.is_ascii_digit() => (trimmed, None),
        Some(c) => (&trimmed[..trimmed.len() - 1], Some(*c)),
        None => return Err(reject()),
    };

    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(reject());
    }
    if let Some(c) = suffix
        && !matches!(c.to_ascii_lowercase(), b'k' | b'm' | b'g')
    {
        return Err(reject());
    }
    Ok(())
}

fn check_snippet(snippet: &str) -> Result<()> {
    const MAX: usize = 16 * 1024;
    if snippet.len() > MAX {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "the custom snippet is too large; put a long configuration in an include file",
        )
        .with_field("custom_nginx_snippet"));
    }
    if snippet.contains('\0') {
        return Err(
            UnihelmError::new(ErrorCode::InvalidInput, "the snippet contains a NUL byte")
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
                    return Err(UnihelmError::new(
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
            UnihelmError::new(ErrorCode::InvalidInput, "the snippet leaves a block open")
                .with_field("custom_nginx_snippet"),
        );
    }
    Ok(())
}

/// Settings a site may reasonably need to differ from the pool default: sizes,
/// times, and how errors are shown. Everything absent from this list is refused
/// by name — including every `php_admin_value` line `pool.conf` writes for a
/// security reason, which is the point of having a list at all.
const ALLOWED_PHP_SETTINGS: &[&str] = &[
    "date.timezone",
    "default_charset",
    "default_socket_timeout",
    "display_errors",
    "error_reporting",
    "max_execution_time",
    "max_file_uploads",
    "max_input_nesting_level",
    "max_input_time",
    "max_input_vars",
    "memory_limit",
    "output_buffering",
    "post_max_size",
    "session.cookie_httponly",
    "session.cookie_samesite",
    "session.cookie_secure",
    "session.gc_maxlifetime",
    "upload_max_filesize",
    "zlib.output_compression",
];

/// The per-site PHP overrides, restricted to settings that are per-site.
///
/// There was a guard here, but it was a guard on *who*: `site.update` refuses
/// this field from anyone who is not an admin, so the tenant escape the field
/// invites was already closed. Nothing looked at the text itself, and the text
/// is dropped at the end of the FPM pool where the last assignment of a setting
/// wins — so `php_admin_value[disable_functions] =` typed by an admin into a
/// box labelled "php.ini overrides" unset `open_basedir` and `disable_functions`
/// for that site, and the panel reported the pool as ready. A pasted php.ini
/// from a forum thread does that as easily as an attack does; the operator was
/// never told which line cost them the isolation.
///
/// Hence an allowlist and a refusal that names the offending line. Values are
/// not parsed beyond being non-empty: a value cannot contain a newline (see the
/// carriage-return check below), so it cannot become a second directive, and
/// what `memory_limit = wrong` means is FPM's question to answer at validation
/// time, not ours to guess.
fn check_php_overrides(overrides: &str) -> Result<()> {
    const MAX: usize = 4 * 1024;
    const MAX_VALUE: usize = 256;

    let refuse = |detail: String| {
        Err(UnihelmError::new(ErrorCode::InvalidInput, detail).with_field("php_ini_overrides"))
    };
    let syntax = |line_no: usize, line: &str| {
        format!(
            "line {line_no} of the PHP overrides is not a pool directive: `{line}`. This is an \
             FPM pool, not a php.ini, so each line must be `php_value[name] = value`, \
             `php_admin_value[name] = value` or `php_admin_flag[name] = on|off` — \
             `php_value[memory_limit] = 256M`, not `memory_limit = 256M`."
        )
    };

    if overrides.len() > MAX {
        return refuse(format!(
            "the PHP overrides are {} bytes and the limit is {MAX}: this box is for a few \
             per-site settings, not a whole php.ini",
            overrides.len()
        ));
    }
    if overrides.contains('\0') {
        return refuse("the PHP overrides contain a NUL byte".into());
    }
    // A lone CR ends a line for PHP's ini scanner but not for `str::lines()`,
    // so a carriage return in the middle of a line would be a directive
    // separator this function cannot see. Refuse it rather than guess where the
    // lines are.
    if overrides.contains('\r') {
        return refuse(
            "the PHP overrides contain a carriage return; save them with plain newlines".into(),
        );
    }
    if let Some(c) = overrides
        .chars()
        .find(|c| c.is_control() && *c != '\n' && *c != '\t')
    {
        return refuse(format!(
            "the PHP overrides contain a control character (U+{:04X})",
            c as u32
        ));
    }

    for (n, raw) in overrides.lines().enumerate() {
        let line_no = n + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        let Some((head, value)) = line.split_once('=') else {
            return refuse(syntax(line_no, line));
        };
        let Some((directive, key)) = head.trim().split_once('[') else {
            return refuse(syntax(line_no, line));
        };
        let Some(key) = key.trim_end().strip_suffix(']') else {
            return refuse(syntax(line_no, line));
        };
        let key = key.trim();

        // `php_flag` is missing on purpose: `php_admin_flag` says the same
        // thing and cannot be undone by ini_set() from inside the site's own
        // code, which is what an operator setting a flag from the panel means.
        if !matches!(
            directive,
            "php_value" | "php_admin_value" | "php_admin_flag"
        ) {
            return refuse(format!(
                "line {line_no} of the PHP overrides uses `{directive}[…]`, which the panel does \
                 not accept. Use `php_value[name]`, `php_admin_value[name]` or \
                 `php_admin_flag[name]`."
            ));
        }

        let named = key.to_ascii_lowercase();
        if matches!(named.as_str(), "open_basedir" | "disable_functions") {
            return refuse(format!(
                "line {line_no} of the PHP overrides sets `{key}`, which cannot be set from here. \
                 open_basedir and disable_functions are what separates one customer from another \
                 on this server: the first confines a site to its own directory, the second keeps \
                 it from running programs, and the panel sets both per pool from the site's own \
                 paths."
            ));
        }
        if !ALLOWED_PHP_SETTINGS.contains(&named.as_str()) {
            return refuse(format!(
                "line {line_no} of the PHP overrides sets `{key}`, which is not a per-site \
                 setting. The panel accepts: {}.",
                ALLOWED_PHP_SETTINGS.join(", ")
            ));
        }

        let value = value.trim();
        if value.is_empty() {
            return refuse(format!(
                "line {line_no} of the PHP overrides sets `{key}` to nothing. Give it a value, or \
                 delete the line to keep the pool's default."
            ));
        }
        if value.len() > MAX_VALUE {
            return refuse(format!(
                "line {line_no} of the PHP overrides gives `{key}` a value of {} bytes; the limit \
                 is {MAX_VALUE}",
                value.len()
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// site.alias.add / site.alias.remove
// ---------------------------------------------------------------------------

/// The other names a site answers to.
///
/// `unihelm-db` has had `aliases`, `add_alias` and `remove_alias` since the
/// first release and nothing above them ever called the last two: the only way
/// an alias was ever written was `site.create`'s `with_www` flag. So attaching
/// `www.example.com` — or a second brand's domain, or a subdomain — to a site
/// that already existed was impossible from the panel, the API and the command
/// line alike, and the only route to it was deleting the site and building it
/// again, certificate and files included.
///
/// Both operations end in a vhost re-render through `webserver::active`, so
/// they work on an Apache machine too, and both put the row back if that render
/// is refused. A stored alias that is not in the rendered `server_name` is a
/// name the panel says it serves and does not.
///
/// There is deliberately no `redirect` input, although the column exists.
/// `render_vhost_inner` collects aliases as `.map(|a| a.domain)` and the
/// templates emit one `server_name` line, so nothing renders the flag — and
/// accepting a setting nothing renders is the `www_policy` defect `site.update`
/// already refuses by name.
pub struct AliasAdd;

#[derive(Debug, Deserialize)]
pub struct AliasAddInput {
    pub site_id: i64,
    /// Validated by `Domain`'s own deserializer, which is the same parse
    /// `site.create` puts a new site's domain through: `Shop.Example.COM.`
    /// arrives normalised, and an IP address never arrives at all.
    pub domain: Domain,
}

#[derive(Debug, Serialize)]
pub struct AliasAddOutput {
    pub site_id: i64,
    pub domain: String,
    pub alias: String,
    /// Every name the site answers to now, primary first — what went into
    /// `server_name`.
    pub server_names: Vec<String>,
    /// True when the alias was already attached and this run only re-rendered.
    /// Reported rather than hidden, so a retry is not read as an attachment
    /// that happened this time.
    pub already_attached: bool,
    /// The site has a live certificate that does not name the alias, so nginx
    /// will offer the primary name's certificate for it and every browser will
    /// refuse the connection. Nothing here fixes that — issuing is `cert.issue`
    /// — so it is said out loud instead of being found by a customer.
    pub certificate_needs_reissue: bool,
}

#[async_trait]
impl TypedOperation for AliasAdd {
    type Input = AliasAddInput;
    type Output = AliasAddOutput;

    const NAME: &'static str = "site.alias.add";
    const PERMISSION: Permission = Permission::SiteManage;
    // A vhost render, a validation and a web-server reload: past the immediate
    // budget. Idempotent because an alias this site already holds converges on
    // a re-render rather than colliding with itself.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db().clone();
        let site = site_for_alias_change(ctx, SiteId(input.site_id)).await?;
        let linux_user = site_linux_user(ctx, &site).await?;
        let alias = input.domain;

        if alias.as_str() == site.domain {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                format!(
                    "`{}` is the site's own name; an alias is an *additional* name",
                    site.domain
                ),
            )
            .with_field("domain"));
        }

        // Global, not the caller's scope, for the reason `retryable_site`
        // gives: a name held by a tenant this caller cannot see is still held,
        // and two vhosts claiming one `server_name` is resolved by nginx's
        // parse order — a silent outage for whichever of the two loses.
        let owner = db
            .domain_owner(alias.as_str())
            .await
            .map_err(UnihelmError::from)?;

        let already_attached = match owner {
            Some(DomainOwner::Alias { site_id, .. }) if site_id == site.id => {
                ctx.log(format!("{alias} is already an alias of {}", site.domain));
                true
            }
            Some(DomainOwner::Site { domain, .. }) => {
                return Err(UnihelmError::new(
                    ErrorCode::DomainAlreadyExists,
                    format!(
                        "`{domain}` is already a site on this server. One name can only be \
                         served by one vhost; delete that site, or pick another name."
                    ),
                )
                .with_field("domain"));
            }
            Some(DomainOwner::Alias { domain, .. }) => {
                return Err(UnihelmError::new(
                    ErrorCode::DomainAlreadyExists,
                    format!(
                        "`{domain}` is already an alias of another site. Remove it there \
                         before attaching it here."
                    ),
                )
                .with_field("domain"));
            }
            None => {
                // The same guard a new site gets: a hand-written vhost already
                // answering for this name would be shadowed by ours, silently,
                // because `conf.d` is read before `sites-enabled`. `is_ours`
                // skips files the panel wrote, so this site cannot refuse
                // itself.
                refuse_foreign_vhost(&alias, false)?;
                db.sites(ctx.scope())
                    .add_alias(site.id, &alias, false)
                    .await
                    .map_err(UnihelmError::from)?;
                ctx.log(format!("attached {alias} to {}", site.domain));
                false
            }
        };

        // The row is written; a render the web server refuses must not leave it
        // behind. The config engine puts back the file it replaced, so the
        // server goes on answering for the old list of names — and a stored
        // alias missing from that list is the panel claiming a name it does not
        // serve. Every later render of this site would fail the same way too.
        if let Err(e) = render_vhost(ctx, &site, &linux_user).await {
            if !already_attached
                && let Err(undo) = db
                    .sites(ctx.scope())
                    .remove_alias(site.id, alias.as_str())
                    .await
            {
                ctx.log(format!(
                    "could not take {alias} back off {} after the refused render: {undo}",
                    site.domain
                ));
            }
            return Err(e);
        }

        let certificate_needs_reissue = db
            .active_certificate_for_site(site.id)
            .await
            .map_err(UnihelmError::from)?
            .is_some_and(|cert| {
                !cert
                    .domains
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(alias.as_str()))
            });
        if certificate_needs_reissue {
            ctx.log(format!(
                "the certificate does not cover {alias}: HTTPS to it will be refused by \
                 browsers until the certificate is issued again"
            ));
        }

        Ok(AliasAddOutput {
            site_id: site.id.get(),
            server_names: db
                .sites(ctx.scope())
                .server_names(site.id)
                .await
                .map_err(UnihelmError::from)?,
            domain: site.domain,
            alias: alias.as_str().to_string(),
            already_attached,
            certificate_needs_reissue,
        })
    }
}

pub struct AliasRemove;

#[derive(Debug, Deserialize)]
pub struct AliasRemoveInput {
    pub site_id: i64,
    pub domain: Domain,
}

#[derive(Debug, Serialize)]
pub struct AliasRemoveOutput {
    pub site_id: i64,
    pub domain: String,
    pub alias: String,
    /// Every name the site answers to after the removal, primary first.
    pub server_names: Vec<String>,
}

#[async_trait]
impl TypedOperation for AliasRemove {
    type Input = AliasRemoveInput;
    type Output = AliasRemoveOutput;

    const NAME: &'static str = "site.alias.remove";
    const PERMISSION: Permission = Permission::SiteManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db().clone();
        let site = site_for_alias_change(ctx, SiteId(input.site_id)).await?;
        let linux_user = site_linux_user(ctx, &site).await?;
        let alias = input.domain;

        // Read the row before deleting it, for two reasons: an alias that is
        // not this site's is refused before anything is touched rather than
        // after a `DELETE` that matched nothing, and the `redirect` flag is
        // known if the render below has to be undone.
        let existing = db
            .sites(ctx.scope())
            .aliases(site.id)
            .await
            .map_err(UnihelmError::from)?
            .into_iter()
            .find(|a| a.domain.eq_ignore_ascii_case(alias.as_str()))
            .ok_or_else(|| {
                UnihelmError::new(
                    ErrorCode::NotFound,
                    format!(
                        "`{alias}` is not an alias of `{}`. Reporting it as removed would \
                         be the panel confirming work it did not do.",
                        site.domain
                    ),
                )
                .with_field("domain")
            })?;

        db.sites(ctx.scope())
            .remove_alias(site.id, &existing.domain)
            .await
            .map_err(UnihelmError::from)?;
        ctx.log(format!("detached {} from {}", existing.domain, site.domain));

        // Symmetrical with the add: the engine restores the previous vhost on a
        // refused validation, so the web server is still answering for the name
        // this row says is gone. Put it back rather than let the two disagree.
        if let Err(e) = render_vhost(ctx, &site, &linux_user).await {
            match Domain::parse(&existing.domain) {
                Ok(domain) => {
                    if let Err(undo) = db
                        .sites(ctx.scope())
                        .add_alias(site.id, &domain, existing.redirect)
                        .await
                    {
                        ctx.log(format!(
                            "could not put {domain} back on {} after the refused render: {undo}",
                            site.domain
                        ));
                    }
                }
                Err(undo) => ctx.log(format!(
                    "could not put {} back on {} after the refused render: {undo}",
                    existing.domain, site.domain
                )),
            }
            return Err(e);
        }

        Ok(AliasRemoveOutput {
            site_id: site.id.get(),
            server_names: db
                .sites(ctx.scope())
                .server_names(site.id)
                .await
                .map_err(UnihelmError::from)?,
            domain: site.domain,
            alias: existing.domain,
        })
    }
}

/// The site an alias change may act on, or a refusal that says what to do next.
///
/// A vhost is rendered from every one of a site's names at once, so an alias
/// change is a whole-vhost rewrite. On a site that is still provisioning that
/// races the task already writing the file; on a site that never finished there
/// is no vhost to add a name to, and rendering one would quietly bring the site
/// up while its row still said `failed`. Both are refused, and the failed one
/// names the operation that does fix it.
async fn site_for_alias_change(ctx: &OpContext, id: SiteId) -> Result<Site> {
    let site = ctx
        .db()
        .sites(ctx.scope())
        .by_id(id)
        .await
        .map_err(UnihelmError::from)?
        .ok_or_else(|| UnihelmError::not_found("site"))?;

    match site.status {
        SiteStatus::Active | SiteStatus::Suspended => Ok(site),
        SiteStatus::Provisioning => Err(UnihelmError::new(
            ErrorCode::Conflict,
            format!(
                "`{}` is still being provisioned; wait for that task to finish before \
                 changing the names it answers to",
                site.domain
            ),
        )),
        SiteStatus::Failed => Err(UnihelmError::new(
            ErrorCode::Conflict,
            format!(
                "`{}` never finished provisioning, so there is no vhost to add a name to. \
                 Re-provision it first (`site.reprovision`), then add the alias.",
                site.domain
            ),
        )),
    }
}

/// The Linux account a site's files and pool belong to.
async fn site_linux_user(ctx: &OpContext, site: &Site) -> Result<unihelm_core::LinuxUser> {
    let subscription = ctx
        .db()
        .subscriptions(&unihelm_core::TenantScope::Global)
        .by_id(site.subscription_id)
        .await
        .map_err(UnihelmError::from)?
        .ok_or_else(|| UnihelmError::internal("the site's subscription is missing"))?;
    unihelm_core::LinuxUser::parse(&subscription.linux_user)
}

// ---------------------------------------------------------------------------
// site.reprovision
// ---------------------------------------------------------------------------

/// Finish a site whose creation stopped halfway.
///
/// `site.create` leaves a failed attempt as a row marked `failed` so the panel
/// can say what went wrong. Until now nothing could act on that row: the only
/// way forward was to delete the site and create it again, and the retry hidden
/// inside `site.create` — `reclaim_failed_site` — could only be reached by
/// typing the same domain into the create form a second time, which the site
/// detail page has no field for. The Configuration-drift card said "No vhost
/// exists on disk. Saving any setting writes it again", and saving a setting
/// needs a setting to change.
///
/// This runs exactly what creation runs, in the same order and through the same
/// web-server seam, and every step of it converges: the account, the directory
/// tree, the pool, the vhost and the logrotate stanza are all idempotent. The
/// one step that was not is the holding page, which is why
/// [`document_root_is_empty`] now guards it — `site.create`'s unwind
/// deliberately leaves the tenant's files alone, and a retry that papered over
/// them with "Upload your files to replace this page" would undo that while
/// reporting the site as live.
pub struct Reprovision;

#[derive(Debug, Deserialize)]
pub struct ReprovisionInput {
    pub site_id: i64,
}

#[derive(Debug, Serialize)]
pub struct ReprovisionOutput {
    pub site_id: i64,
    pub domain: String,
    pub document_root: String,
    pub linux_user: String,
    /// What the row said before this ran, so the caller can tell a repaired
    /// site from a re-rendered working one.
    pub previous_status: String,
    /// The document root already held something, so the holding page was not
    /// written over it.
    pub kept_existing_files: bool,
    pub next_steps: Vec<String>,
}

#[async_trait]
impl TypedOperation for Reprovision {
    type Input = ReprovisionInput;
    type Output = ReprovisionOutput;

    const NAME: &'static str = "site.reprovision";
    const PERMISSION: Permission = Permission::SiteManage;
    // Idempotent where `site.create` is not: every step converges, and nothing
    // here creates a row or claims a domain.
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
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("site"))?;

        // A task is already writing this site's files. Two of them rendering
        // one vhost is how a half-written file gets validated and activated.
        if site.status == SiteStatus::Provisioning {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "`{}` is already being provisioned; wait for that task to finish. If it \
                     is not running any more, delete the site and create it again.",
                    site.domain
                ),
            ));
        }

        let subscription = db
            .subscriptions(&unihelm_core::TenantScope::Global)
            .by_id(site.subscription_id)
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::internal("the site's subscription is missing"))?;

        // The same refusal `site.create` gives, rather than a run that renders
        // the maintenance page and then reports the site as active: suspension
        // is read by `render_vhost_mode` from the subscription, so this would
        // otherwise "succeed" into a 503.
        if !subscription.status.can_serve() {
            return Err(UnihelmError::new(
                ErrorCode::AccountSuspended,
                format!(
                    "the subscription that owns `{}` is suspended; unsuspend it before \
                     re-provisioning its sites",
                    site.domain
                ),
            ));
        }

        let linux_user = unihelm_core::LinuxUser::parse(&subscription.linux_user)?;

        // The check `site.create` runs, for the reason it runs it: without the
        // pool socket the vhost renders, the web server reloads, and every
        // request 502s with nothing in the panel explaining why. The PHP a site
        // was created on can be gone by the time it is repaired.
        if let Some(version) = site.php_version {
            require_php_installed(ctx, version).await?;
        }

        // A hand-written vhost may have claimed this name in the meantime, and
        // ours would shadow it without nginx saying a word. `is_ours` skips the
        // panel's own files, so a site that is already serving cannot refuse
        // its own repair.
        let domain = Domain::parse(&site.domain)?;
        refuse_foreign_vhost(&domain, false)?;

        let kept_existing_files =
            !document_root_is_empty(&paths::site_public(linux_user.as_str(), domain.as_str()));

        let previous = site.status;
        db.set_site_status(site.id, SiteStatus::Provisioning)
            .await
            .map_err(UnihelmError::from)?;
        ctx.log(format!(
            "re-provisioning {} (was {})",
            site.domain,
            previous.as_str()
        ));
        if kept_existing_files {
            ctx.log("the document root already has files in it; leaving them alone");
        }

        match provision_site(ctx, &site, &linux_user).await {
            Ok(()) => {
                db.set_site_status(site.id, SiteStatus::Active)
                    .await
                    .map_err(UnihelmError::from)?;
                ctx.log(format!("{} is live", site.domain));

                Ok(ReprovisionOutput {
                    site_id: site.id.get(),
                    domain: site.domain.clone(),
                    document_root: site.root_dir.clone(),
                    linux_user: subscription.linux_user,
                    previous_status: previous.as_str().to_string(),
                    kept_existing_files,
                    next_steps: vec![
                        format!("Check that {} resolves to this server", site.domain),
                        "Issue a certificate if this site does not have one yet".into(),
                    ],
                })
            }
            Err(e) => {
                // Back to what the row said, not to `failed`. The config engine
                // restores the file it replaced, so a site that was serving is
                // still being served — and marking it failed would be the panel
                // reporting an outage that did not happen. A site that was
                // already failed stays failed, which is the truth as well.
                if let Err(revert) = db.set_site_status(site.id, previous).await {
                    ctx.log(format!(
                        "could not restore {}'s status after the failed re-provision: {revert}",
                        site.domain
                    ));
                }
                ctx.log(format!("re-provisioning failed: {e}"));
                Err(e)
            }
        }
    }
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
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("site"))?;

        let subscription = db
            .subscriptions(&unihelm_core::TenantScope::Global)
            .by_id(site.subscription_id)
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::internal("the site's subscription is missing"))?;
        let linux_user = unihelm_core::LinuxUser::parse(&subscription.linux_user)?;
        let domain = Domain::parse(&site.domain)?;

        // The vhost first: stop serving before removing what was served.
        //
        // Through the seam, and from the *active* server. Named as nginx's, a
        // delete on an Apache machine left the Apache vhost in place — so the
        // site went on being served from a document root that was about to be
        // deleted, by an FPM pool that was about to be removed.
        let server = crate::webserver::active(ctx).await?;
        let vhost = server.site_vhost(&site.domain)?;
        let reloader = server.reloader(ctx.distro())?;
        ctx.config()
            .remove(&vhost.file, vhost.service, server.validator()?, &reloader)
            .await?;
        ctx.log(format!("removed the vhost for {}", site.domain));

        if let Some(version) = site.php_version {
            remove_pool(ctx, &site, version).await;
        }

        // Logrotate config, then the revision history for both files.
        let _ = std::fs::remove_file(paths::logrotate_site(&site.domain));
        // Both servers' paths, not just the active one's: a machine that was
        // switched has a revision history under the other name too, and leaving
        // it behind means a later site on the same domain starts with somebody
        // else's diff.
        for path in [
            paths::nginx_site(&site.domain),
            paths::apache_site(&site.domain),
            paths::logrotate_site(&site.domain),
        ] {
            let _ = db.forget_revisions(&path.to_string_lossy()).await;
        }

        // The certificate, now that nothing points at it any more.
        remove_certificate(ctx, &site.domain).await;

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
            .map_err(UnihelmError::from)?;

        // After the row is gone, so a receiver that reacts by listing sites
        // sees a world consistent with the message (spec §14 Phase 6).
        crate::webhook::emit(
            ctx,
            "site.deleted",
            serde_json::json!({
                "site_id": id.get(),
                "domain": site.domain,
                "files_removed": input.purge_files,
            }),
        )
        .await;

        Ok(DeleteOutput {
            domain: site.domain,
            files_removed: input.purge_files,
        })
    }
}

/// Take the deleted site's certificate off the disk.
///
/// Nothing else did. The `certificates` row cascades away with the site, but
/// `cert_dir` is keyed on the domain and outlived it — and `render_vhost_mode`
/// decides TLS purely from what is on disk. So the next site created for the
/// same domain came up on HTTPS with the previous one's key and chain: working
/// today, absent from `cert.list`, renewed by nobody, expired without a word.
///
/// Left in place when the panel itself answers on this domain: `panel.tls.issue`
/// writes into `cert_dir(domain)` too and `01-panel.conf` points straight at it,
/// so a site somebody created for the panel's own name would otherwise take the
/// panel's TLS down on its way out.
async fn remove_certificate(ctx: &OpContext, domain: &str) {
    let panel_domain: Option<String> = ctx
        .db()
        .get_setting(unihelm_db::panel::DOMAIN_KEY)
        .await
        .ok()
        .flatten();
    if panel_domain.as_deref() == Some(domain) {
        ctx.log("left the certificate in place: the panel is served on this domain");
        return;
    }

    match remove_certificate_dir(&paths::cert_dir(domain)) {
        Ok(true) => ctx.log("removed the certificate"),
        Ok(false) => {}
        // Untidy, not fatal: the same reasoning as the pool below. A delete that
        // fails here would leave a site half-removed, which is worse.
        Err(e) => ctx.log(format!("could not remove the certificate: {e}")),
    }
}

/// The same, against an explicit directory.
///
/// Split out so the tests can work in a temporary directory: `paths::set_root`
/// is a process-wide `OnceLock`, which a parallel test binary cannot use to give
/// each test its own tree.
fn remove_certificate_dir(dir: &Path) -> std::io::Result<bool> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
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
    pub diff: Vec<unihelm_config::DiffLine>,
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
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("site"))?;

        let subscription = db
            .subscriptions(&unihelm_core::TenantScope::Global)
            .by_id(site.subscription_id)
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::internal("the site's subscription is missing"))?;
        let linux_user = unihelm_core::LinuxUser::parse(&subscription.linux_user)?;

        let mut context = site_context(&site, &linux_user)?;
        let aliases: Vec<String> = db
            .sites(ctx.scope())
            .aliases(site.id)
            .await
            .map_err(UnihelmError::from)?
            .into_iter()
            .map(|a| a.domain)
            .collect();
        context = context.with_aliases(&aliases);

        let cert_dir = paths::cert_dir(&site.domain);
        if crate::tls::certificate_present(&cert_dir) {
            context = context.with_tls(&cert_dir, true);
        }

        // The same seam as the render above, and it has to be: a drift report
        // built from nginx's template against a machine serving with Apache
        // would call every vhost on it hand-edited.
        let vhost = crate::webserver::active(ctx)
            .await?
            .site_vhost(&site.domain)?;

        let report = ctx.config().drift_report(
            &vhost.file,
            vhost.template,
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

    /// The settings sites are actually given this box for must keep working, or
    /// the allowlist is a regression dressed as a fix.
    #[test]
    fn php_overrides_accept_the_settings_that_are_a_sites_own_business() {
        assert!(check_php_overrides("").is_ok());
        assert!(check_php_overrides("php_value[memory_limit] = 512M").is_ok());
        assert!(
            check_php_overrides(
                "; the media library needs a bigger upload\n\
                 php_value[upload_max_filesize] = 256M\n\
                 php_value[post_max_size] = 256M\n\
                 \n\
                 php_admin_value[max_execution_time] = 300\n\
                 php_admin_flag[display_errors] = off\n\
                 php_value[date.timezone] = Europe/Berlin\n\
                 php_value[error_reporting] = E_ALL & ~E_DEPRECATED\n"
            )
            .is_ok()
        );
    }

    /// This is the whole reason the box is checked at all: the overrides render
    /// at the end of the FPM pool, where the last assignment wins, so a line
    /// like these used to unset the isolation for that site and report success.
    #[test]
    fn a_php_override_that_unsets_the_isolation_is_refused_by_name() {
        for (overrides, named) in [
            ("php_admin_value[disable_functions] =", "disable_functions"),
            ("php_admin_value[open_basedir] = /", "open_basedir"),
            (
                "php_value[memory_limit] = 512M\nphp_admin_value[DISABLE_FUNCTIONS] = ",
                "DISABLE_FUNCTIONS",
            ),
        ] {
            let err = check_php_overrides(overrides).expect_err("accepted an escape");
            assert_eq!(err.code, ErrorCode::InvalidInput);
            assert_eq!(err.field.as_deref(), Some("php_ini_overrides"));
            assert!(
                err.detail.contains(named),
                "the message must name the line's setting: {}",
                err.detail
            );
            assert!(
                err.detail.contains("separates one customer from another"),
                "the message must say what the setting is for: {}",
                err.detail
            );
        }
    }

    /// Everything the pool sets as a boundary, and everything nobody asked for,
    /// is refused by name rather than rewritten or dropped.
    #[test]
    fn a_php_override_outside_the_allowlist_is_refused_and_says_what_is_allowed() {
        for setting in [
            "session.save_path",
            "sendmail_path",
            "opcache.file_cache",
            "allow_url_include",
            "extension",
            "auto_prepend_file",
        ] {
            let err = check_php_overrides(&format!("php_admin_value[{setting}] = x"))
                .expect_err("accepted a setting that is not per-site");
            assert!(err.detail.contains(setting), "{}", err.detail);
            assert!(err.detail.contains("memory_limit"), "{}", err.detail);
        }
        // `php_flag` and a bare word are not pool directives either.
        assert!(check_php_overrides("php_flag[display_errors] = on").is_err());
        assert!(check_php_overrides("open_basedir[x] = /").is_err());
    }

    /// Operators paste php.ini, because the field is called "php.ini
    /// overrides". Say which line, and what the pool syntax is.
    #[test]
    fn a_php_override_written_as_php_ini_is_refused_with_the_pool_syntax() {
        for overrides in [
            "memory_limit = 256M",
            "php_value[memory_limit] = 512M\nmemory_limit = 256M",
            "php_value[memory_limit 512M",
            "php_value[memory_limit] 512M",
        ] {
            let err = check_php_overrides(overrides).expect_err("accepted a non-directive");
            assert_eq!(err.field.as_deref(), Some("php_ini_overrides"));
            assert!(
                err.detail.contains("php_value[memory_limit] = 256M"),
                "the message must show the shape it wants: {}",
                err.detail
            );
        }
    }

    /// A carriage return is the interesting one: PHP's ini scanner ends a line
    /// on a lone CR and `str::lines()` does not, so a CR in the middle of an
    /// accepted line would smuggle a second directive past the line loop.
    #[test]
    fn php_overrides_are_bounded_and_free_of_nul_and_carriage_returns() {
        assert!(check_php_overrides(&"a".repeat(5_000)).is_err());
        assert!(check_php_overrides("php_value[memory_limit] = 256M\0").is_err());
        assert!(
            check_php_overrides(
                "php_value[memory_limit] = 256M\rphp_admin_value[open_basedir] = /"
            )
            .is_err()
        );
        assert!(check_php_overrides("php_value[memory_limit] = 256M\x1b[2J").is_err());
        assert!(check_php_overrides("php_value[memory_limit] =").is_err());
    }

    /// The pool no longer names a mail program, so "can this site send mail?"
    /// stopped being a question about the site. It is now a question about the
    /// machine, and the answer has to reach the operator somewhere.
    #[test]
    fn a_pool_on_a_machine_with_no_mail_agent_says_the_gap_is_the_server_not_the_site() {
        let note = missing_mta_note("example.com", false).expect("a note");
        assert!(note.contains("example.com"), "{note}");
        assert!(
            note.contains("mail()") && note.contains("false"),
            "say what PHP actually does, which is fail rather than pretend: {note}"
        );
        assert!(
            note.contains("cron"),
            "one install fixes every sender on the box, not just this site: {note}"
        );
        assert!(
            missing_mta_note("example.com", true).is_none(),
            "a machine with a mail agent has nothing to report"
        );
    }

    /// Defence in depth for rows written before the allowlist existed: they
    /// still render verbatim, so the pool assigns the boundary again below them
    /// and ordering stops being what decides it.
    #[test]
    fn the_pool_restates_the_isolation_after_the_per_site_overrides() {
        use unihelm_config::TemplateSet;

        let mut pool = PoolContext::new("example.com", "uh_abc123", PhpVersion::V83, 1024, "nginx");
        pool.extra_ini =
            Some("php_admin_value[disable_functions] =\nphp_admin_value[open_basedir] = /".into());

        let rendered = TemplateSet::load()
            .expect("the templates load")
            .render("php/pool.conf", &serde_json::json!({ "pool": &pool }))
            .expect("the pool renders");

        let last_assignment = |setting: &str| {
            let prefix = format!("php_admin_value[{setting}]");
            rendered
                .lines()
                .map(str::trim)
                .rfind(|line| line.starts_with(&prefix))
                .unwrap_or_default()
                .to_string()
        };

        assert_eq!(
            last_assignment("open_basedir"),
            format!("php_admin_value[open_basedir] = {}", pool.open_basedir),
            "the overrides won the pool: {rendered}"
        );
        assert_eq!(
            last_assignment("disable_functions"),
            format!(
                "php_admin_value[disable_functions] = {}",
                pool.disable_functions
            ),
            "the overrides won the pool: {rendered}"
        );
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

    /// The certificate outlived the site it belonged to, and `render_vhost_mode`
    /// reads TLS off the disk — so the next site on the domain came up on HTTPS
    /// with material no row knew about and nothing would ever renew.
    #[test]
    fn a_deleted_sites_certificate_does_not_wait_on_disk_for_the_next_site() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("example.com");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("fullchain.pem"), "chain").unwrap();
        std::fs::write(dir.join("privkey.pem"), "key").unwrap();
        assert!(crate::tls::certificate_present(&dir));

        assert!(remove_certificate_dir(&dir).unwrap());
        assert!(
            !crate::tls::certificate_present(&dir),
            "a recreated site would have picked this certificate up"
        );

        // A site that never had one is not a failed delete.
        assert!(!remove_certificate_dir(&dir).unwrap());
    }

    /// nginx resolves a duplicate `server_name` by parse order and only warns,
    /// so shadowing somebody's hand-written vhost is a silent outage.
    #[test]
    fn a_domain_an_unmanaged_vhost_already_serves_is_a_conflict() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("shop.conf"),
            "server {\n    listen 80;\n    server_name Shop.example.com;\n    root /srv/shop;\n}\n",
        )
        .unwrap();
        let vhosts = nginx_survey::discover_sites_in(&[dir.path().to_path_buf()]);

        // Case-insensitively: a `server_name` is a hostname, not a string.
        let (name, file) = foreign_server_name(&vhosts, &["shop.example.com".to_string()]).unwrap();
        assert_eq!(name, "Shop.example.com");
        assert!(
            file.ends_with("shop.conf"),
            "the refusal has to say which file to go and edit, not just that one exists: {file}"
        );
        assert!(foreign_server_name(&vhosts, &["other.example.com".to_string()]).is_none());
    }

    /// nginx does not care where the newlines are, and people do write a whole
    /// vhost on one line. A guard against a silent outage that only sees the
    /// tidy spelling of a config file is a guard that fails silently itself.
    #[test]
    fn a_vhost_written_on_one_line_is_found_too() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("shop.conf"),
            "server { listen 80; server_name shop.example.com; root /srv/shop; }\n",
        )
        .unwrap();
        let vhosts = nginx_survey::discover_sites_in(&[dir.path().to_path_buf()]);

        assert!(foreign_server_name(&vhosts, &["shop.example.com".to_string()]).is_some());
    }
}

#[cfg(test)]
mod update_tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use serde_json::json;
    use unihelm_core::{Role, TenantScope};
    use unihelm_db::sites::NewSite;

    /// A rejected render must not leave its value behind: every later render of
    /// the site — a renewal, a suspension, an unsuspension — builds the vhost
    /// from the stored row and would fail on it again.
    #[tokio::test]
    async fn a_rejected_update_puts_back_every_setting_it_could_have_changed() {
        let (reg, _admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let sub = db.create_subscription(customer).await.unwrap();
        let before = db
            .create_site(NewSite {
                subscription_id: sub.id,
                domain: Domain::parse("example.com").unwrap(),
                site_type: SiteType::Php,
                php_version: Some(PhpVersion::V83),
                root_dir: format!("/home/{}/sites/example.com/public", sub.linux_user),
                proxy_port: None,
                redirect_target: None,
            })
            .await
            .unwrap();

        let repo = db.sites(&TenantScope::Global);
        let proposed = repo
            .update(
                before.id,
                SiteUpdate {
                    php_version: Some(PhpVersion::V82),
                    www_policy: Some(WwwPolicy::Strip),
                    force_https: Some(!before.force_https),
                    http3: Some(!before.http3),
                    maintenance_mode: Some(!before.maintenance_mode),
                    client_max_body_size: Some("512m".into()),
                    custom_nginx_snippet: Some(Some("bogus_directive foo;".into())),
                    php_ini_overrides: Some(Some("open_basedir=/".into())),
                    rate_limit_enabled: Some(!before.rate_limit_enabled),
                    proxy_port: None,
                    redirect_target: None,
                },
            )
            .await
            .unwrap();
        assert_ne!(proposed.custom_nginx_snippet, before.custom_nginx_snippet);

        let after = repo.update(before.id, revert_to(&before)).await.unwrap();

        assert_eq!(after.php_version, before.php_version);
        assert_eq!(after.www_policy, before.www_policy);
        assert_eq!(after.force_https, before.force_https);
        assert_eq!(after.http3, before.http3);
        assert_eq!(after.maintenance_mode, before.maintenance_mode);
        assert_eq!(after.client_max_body_size, before.client_max_body_size);
        assert_eq!(after.custom_nginx_snippet, before.custom_nginx_snippet);
        assert_eq!(after.php_ini_overrides, before.php_ini_overrides);
        assert_eq!(after.rate_limit_enabled, before.rate_limit_enabled);
    }

    /// It was accepted, stored, echoed back and reported as reloaded, and no
    /// part of it ever reached nginx.
    #[tokio::test]
    async fn a_www_policy_is_refused_rather_than_stored_and_forgotten() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let sub = db.create_subscription(customer).await.unwrap();
        let site = db
            .create_site(NewSite {
                subscription_id: sub.id,
                domain: Domain::parse("example.com").unwrap(),
                site_type: SiteType::Static,
                php_version: None,
                root_dir: format!("/home/{}/sites/example.com/public", sub.linux_user),
                proxy_port: None,
                redirect_target: None,
            })
            .await
            .unwrap();

        let err = reg
            .dispatch(
                "site.update",
                &auth_for(admin, Role::Admin),
                json!({ "site_id": site.id.get(), "www_policy": "strip" }),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("www_policy"));
        assert_eq!(
            db.sites(&TenantScope::Global)
                .by_id(site.id)
                .await
                .unwrap()
                .unwrap()
                .www_policy,
            WwwPolicy::None,
            "a setting the panel cannot honour must not be stored either"
        );
    }

    /// Being an admin is permission to tune a site, not permission to take the
    /// isolation off one. The row must not be written either: it is rendered
    /// verbatim by every later pool render, long after whoever typed it has
    /// forgotten they did.
    #[tokio::test]
    async fn php_overrides_that_disable_the_isolation_are_refused_even_for_an_admin() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let sub = db.create_subscription(customer).await.unwrap();
        let site = db
            .create_site(NewSite {
                subscription_id: sub.id,
                domain: Domain::parse("example.com").unwrap(),
                site_type: SiteType::Static,
                php_version: None,
                root_dir: format!("/home/{}/sites/example.com/public", sub.linux_user),
                proxy_port: None,
                redirect_target: None,
            })
            .await
            .unwrap();

        let err = reg
            .dispatch(
                "site.update",
                &auth_for(admin, Role::Admin),
                json!({
                    "site_id": site.id.get(),
                    "php_ini_overrides": "php_admin_value[disable_functions] =",
                }),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("php_ini_overrides"));
        assert!(err.detail.contains("disable_functions"), "{}", err.detail);
        assert_eq!(
            db.sites(&TenantScope::Global)
                .by_id(site.id)
                .await
                .unwrap()
                .unwrap()
                .php_ini_overrides,
            None
        );
    }
}
#[cfg(test)]
mod body_size_tests {
    use super::*;

    /// The value lands unquoted in `client_max_body_size {…};`, so anything
    /// accepted here is a directive the tenant gets to write into their own
    /// vhost — and nginx reads the whole file, so "their own" is optimistic.
    #[test]
    fn a_size_that_closes_the_directive_is_refused() {
        let attacks = [
            "64m; root /etc; #",
            "1m;}\nserver{listen 80;server_name _;root /;",
            "10m; autoindex on",
            "5m\nroot /etc",
            "1m; include /etc/passwd;",
        ];
        for attack in attacks {
            assert!(
                check_body_size(attack).is_err(),
                "accepted an injection: {attack:?}"
            );
        }
    }

    /// Sizes people actually set must still work, or the fix is a regression.
    #[test]
    fn real_sizes_are_accepted() {
        for ok in ["0", "64m", "64M", "1g", "512k", "1024", "20m"] {
            assert!(check_body_size(ok).is_ok(), "refused a real size: {ok:?}");
        }
    }

    /// Neither an empty value nor a suffix nginx does not know is a size.
    #[test]
    fn nonsense_is_refused() {
        for bad in [
            "",
            "  ",
            "m",
            "64x",
            "-1m",
            "1.5m",
            "64 m",
            "999999999999999999999m",
        ] {
            assert!(check_body_size(bad).is_err(), "accepted nonsense: {bad:?}");
        }
    }
}

#[cfg(test)]
mod alias_tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use unihelm_core::{Role, TenantScope};
    use unihelm_db::sites::NewSite;

    /// A site owned by `sub`, active unless told otherwise.
    async fn seed(
        db: &unihelm_db::Db,
        sub: &unihelm_db::subscriptions::Subscription,
        domain: &str,
        status: SiteStatus,
    ) -> Site {
        let site = db
            .create_site(NewSite {
                subscription_id: sub.id,
                domain: Domain::parse(domain).unwrap(),
                site_type: SiteType::Static,
                php_version: None,
                root_dir: format!("/home/{}/sites/{domain}/public", sub.linux_user),
                proxy_port: None,
                redirect_target: None,
            })
            .await
            .unwrap();
        db.set_site_status(site.id, status).await.unwrap();
        db.sites(&TenantScope::Global)
            .by_id(site.id)
            .await
            .unwrap()
            .unwrap()
    }

    fn context(reg: &crate::registry::OpRegistry, user: unihelm_core::UserId) -> OpContext {
        OpContext::new(reg.services().clone(), auth_for(user, Role::Admin))
    }

    /// The whole reason the collision check is not left to the `INSERT`: two
    /// vhosts claiming one `server_name` is resolved by nginx's parse order,
    /// so taking another customer's domain as an alias is the same outage as
    /// creating a duplicate site — and it must be refused before the row.
    #[tokio::test]
    async fn an_alias_that_is_another_customers_site_is_refused_and_names_it() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let mine = db.create_subscription(customer).await.unwrap();
        let theirs = db.create_subscription(admin).await.unwrap();
        let site = seed(&db, &mine, "example.com", SiteStatus::Active).await;
        seed(&db, &theirs, "other.example", SiteStatus::Active).await;

        let err = AliasAdd
            .run(
                &context(&reg, admin),
                AliasAddInput {
                    site_id: site.id.get(),
                    domain: Domain::parse("other.example").unwrap(),
                },
            )
            .await
            .expect_err("took another customer's domain");

        assert_eq!(err.code, ErrorCode::DomainAlreadyExists);
        assert_eq!(err.field.as_deref(), Some("domain"));
        assert!(err.detail.contains("other.example"), "{}", err.detail);
        assert!(
            db.sites(&TenantScope::Global)
                .aliases(site.id)
                .await
                .unwrap()
                .is_empty(),
            "a refused alias must not be stored"
        );
    }

    /// The same check, for a name that is already somebody else's alias rather
    /// than somebody else's site.
    #[tokio::test]
    async fn an_alias_that_is_another_sites_alias_is_refused_and_says_where_it_lives() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let mine = db.create_subscription(customer).await.unwrap();
        let theirs = db.create_subscription(admin).await.unwrap();
        let site = seed(&db, &mine, "example.com", SiteStatus::Active).await;
        let other = seed(&db, &theirs, "other.example", SiteStatus::Active).await;
        db.sites(&TenantScope::Global)
            .add_alias(other.id, &Domain::parse("shop.example").unwrap(), false)
            .await
            .unwrap();

        let err = AliasAdd
            .run(
                &context(&reg, admin),
                AliasAddInput {
                    site_id: site.id.get(),
                    domain: Domain::parse("shop.example").unwrap(),
                },
            )
            .await
            .expect_err("stole another site's alias");

        assert_eq!(err.code, ErrorCode::DomainAlreadyExists);
        assert!(err.detail.contains("another site"), "{}", err.detail);
        assert_eq!(
            db.sites(&TenantScope::Global)
                .aliases(other.id)
                .await
                .unwrap()
                .len(),
            1,
            "the other site must keep its alias"
        );
    }

    /// `server_name example.com example.com;` is a duplicate nginx warns about
    /// and the panel would have to explain; the site's own name is not an
    /// additional name for it.
    #[tokio::test]
    async fn a_site_cannot_be_its_own_alias() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let sub = db.create_subscription(customer).await.unwrap();
        let site = seed(&db, &sub, "example.com", SiteStatus::Active).await;

        let err = AliasAdd
            .run(
                &context(&reg, admin),
                AliasAddInput {
                    site_id: site.id.get(),
                    domain: Domain::parse("example.com").unwrap(),
                },
            )
            .await
            .expect_err("accepted the site's own name");

        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("domain"));
    }

    /// A failed site has no vhost, so there is nothing to add a name to — and
    /// rendering one here would bring the site up while its row still said
    /// `failed`. The refusal has to point at the operation that does fix it,
    /// or it is the same dead end the operator was already in.
    #[tokio::test]
    async fn an_alias_on_a_failed_site_is_refused_and_names_the_way_out() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let sub = db.create_subscription(customer).await.unwrap();
        let site = seed(&db, &sub, "example.com", SiteStatus::Failed).await;

        let err = AliasAdd
            .run(
                &context(&reg, admin),
                AliasAddInput {
                    site_id: site.id.get(),
                    domain: Domain::parse("www.example.com").unwrap(),
                },
            )
            .await
            .expect_err("added a name to a site with no vhost");

        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(
            err.detail.contains("site.reprovision"),
            "the refusal must name the operation that unblocks it: {}",
            err.detail
        );
    }

    /// Reporting a removal that removed nothing is the panel confirming work it
    /// did not do — the defect class this project treats as top severity.
    #[tokio::test]
    async fn removing_an_alias_that_was_never_attached_is_refused_not_reported_as_done() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let sub = db.create_subscription(customer).await.unwrap();
        let site = seed(&db, &sub, "example.com", SiteStatus::Active).await;

        let err = AliasRemove
            .run(
                &context(&reg, admin),
                AliasRemoveInput {
                    site_id: site.id.get(),
                    domain: Domain::parse("www.example.com").unwrap(),
                },
            )
            .await
            .expect_err("reported a removal that did not happen");

        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(err.field.as_deref(), Some("domain"));
        assert!(err.detail.contains("www.example.com"), "{}", err.detail);
    }

    /// Naming another site's alias must not detach it: the removal is keyed on
    /// the site as well as the name, and the refusal comes before the delete.
    #[tokio::test]
    async fn removing_another_sites_alias_does_not_touch_it() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let mine = db.create_subscription(customer).await.unwrap();
        let theirs = db.create_subscription(admin).await.unwrap();
        let site = seed(&db, &mine, "example.com", SiteStatus::Active).await;
        let other = seed(&db, &theirs, "other.example", SiteStatus::Active).await;
        db.sites(&TenantScope::Global)
            .add_alias(other.id, &Domain::parse("shop.example").unwrap(), false)
            .await
            .unwrap();

        let err = AliasRemove
            .run(
                &context(&reg, admin),
                AliasRemoveInput {
                    site_id: site.id.get(),
                    domain: Domain::parse("shop.example").unwrap(),
                },
            )
            .await
            .expect_err("detached an alias from a site that did not own it");

        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(
            db.sites(&TenantScope::Global)
                .aliases(other.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// An alias is not a wildcard, an IP address or a bare label. The parse is
    /// `Domain`'s, so it is the same one `site.create` puts a domain through.
    #[test]
    fn an_alias_must_be_a_domain_before_it_reaches_the_operation() {
        let ok: AliasAddInput =
            serde_json::from_str(r#"{"site_id":1,"domain":"Shop.Example.COM."}"#).unwrap();
        assert_eq!(ok.domain.as_str(), "shop.example.com");

        for bad in ["", "localhost", "192.0.2.1", "*.example.com", "-x.example"] {
            let raw = serde_json::json!({ "site_id": 1, "domain": bad }).to_string();
            assert!(
                serde_json::from_str::<AliasAddInput>(&raw).is_err(),
                "accepted `{bad}` as an alias"
            );
        }
    }

    /// A second task is already rewriting this site's files; the two would race
    /// over one vhost.
    #[tokio::test]
    async fn reprovisioning_a_site_that_is_mid_provision_is_refused() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let sub = db.create_subscription(customer).await.unwrap();
        let site = seed(&db, &sub, "example.com", SiteStatus::Provisioning).await;

        let err = Reprovision
            .run(
                &context(&reg, admin),
                ReprovisionInput {
                    site_id: site.id.get(),
                },
            )
            .await
            .expect_err("raced the provisioning task");

        assert_eq!(err.code, ErrorCode::Conflict);
        assert_eq!(
            db.sites(&TenantScope::Global)
                .by_id(site.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            SiteStatus::Provisioning,
            "a refused re-provision must not have moved the row"
        );
    }

    /// Re-provisioning a suspended tenant's site would render the maintenance
    /// page and then mark the row active: a site the panel calls live and the
    /// visitor gets a 503 from. `site.create` refuses the same thing.
    #[tokio::test]
    async fn reprovisioning_a_suspended_subscriptions_site_is_refused() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let sub = db.create_subscription(customer).await.unwrap();
        let site = seed(&db, &sub, "example.com", SiteStatus::Failed).await;
        db.set_subscription_status(
            sub.id,
            unihelm_db::subscriptions::SubscriptionStatus::Suspended,
            Some("unpaid"),
        )
        .await
        .unwrap();

        let err = Reprovision
            .run(
                &context(&reg, admin),
                ReprovisionInput {
                    site_id: site.id.get(),
                },
            )
            .await
            .expect_err("re-provisioned a suspended tenant's site");

        assert_eq!(err.code, ErrorCode::AccountSuspended);
        assert_eq!(
            db.sites(&TenantScope::Global)
                .by_id(site.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            SiteStatus::Failed
        );
    }

    /// The holding page says "Upload your files to replace this page". Dropping
    /// it into a root that already has files puts it in front of them —
    /// `index index.php index.html index.htm;` prefers it to a tenant's
    /// `index.htm` — and the panel would then report a live site serving the
    /// wrong page. `site.create`'s unwind leaves those files alone on purpose;
    /// a retry must not undo that.
    #[test]
    fn the_holding_page_is_only_written_into_an_empty_document_root() {
        let root = tempfile::tempdir().unwrap();

        let fresh = root.path().join("public");
        std::fs::create_dir_all(&fresh).unwrap();
        assert!(document_root_is_empty(&fresh));

        // Never created: the ordinary first create, before `ensure_site_dirs`.
        assert!(document_root_is_empty(&root.path().join("never-made")));

        // A static site the tenant uploaded, with no `index.html` for
        // `write_placeholder`'s own check to catch.
        std::fs::write(fresh.join("index.htm"), "<h1>real site</h1>").unwrap();
        assert!(!document_root_is_empty(&fresh));

        // And an application whose entry point is not an index file at all.
        let app = root.path().join("app");
        std::fs::create_dir_all(app.join("vendor")).unwrap();
        assert!(!document_root_is_empty(&app));
    }
}
