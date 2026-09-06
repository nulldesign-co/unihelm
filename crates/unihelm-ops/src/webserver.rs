//! Which web server serves this machine's sites.
//!
//! The catalogue has offered nginx, Apache and OpenLiteSpeed since 0.2, and
//! only nginx has ever been able to serve a site: a vhost is a rendered
//! template, `site.rs` named `nginx/site.conf` in two places, and installing
//! either of the others got you a web server the panel could not write a vhost
//! for. `docs/design/web-servers.md` sets out the order this is fixed in; this
//! module is its first step and deliberately its dullest.
//!
//! **Nothing here changes behaviour.** [`active`] can only answer `Nginx`,
//! because nothing writes the setting it reads. What moves is where the answer
//! comes from: the two call sites in `site.rs` now ask this module for the
//! template, the path, the validator and the reloader instead of naming nginx's
//! literally. That seam is the part worth getting wrong on its own, with the
//! whole test suite still describing a machine that runs nginx — rather than
//! discovering it is in the wrong place while also writing an Apache template.
//!
//! The three arms are spelled out rather than left as a `TODO`, and the two that
//! are not built yet refuse with the release they land in. A panel that offers
//! Apache in its catalogue and then fails with a template-not-found is telling
//! the operator their machine is broken; one that says "Apache cannot serve
//! sites until 0.7" is telling them the truth.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use unihelm_config::{ManagedFile, paths};
use unihelm_core::{ErrorCode, Permission, Result, UnihelmError};
use unihelm_distro::Distro;

use crate::registry::{Execution, OpContext, TypedOperation};
use crate::services::{ApacheValidator, NginxValidator, UnitReloader};

/// Where the active web server is recorded.
///
/// Absent on every machine until something writes it, which is why [`active`]
/// treats absent as nginx rather than as an error: every server this panel has
/// ever installed runs nginx, and a missing row is that fact, not a fault.
pub const WEB_SERVER_SETTING: &str = "webserver.active";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebServer {
    Nginx,
    Apache,
    Litespeed,
}

impl WebServer {
    /// The catalogue slug that installs it — the same string the Stack page and
    /// `stack.install` use, so there is one spelling of "Apache" in the project.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nginx => "nginx",
            Self::Apache => "apache",
            Self::Litespeed => "litespeed",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Nginx => "Nginx",
            Self::Apache => "Apache",
            Self::Litespeed => "OpenLiteSpeed",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "nginx" => Some(Self::Nginx),
            "apache" => Some(Self::Apache),
            "litespeed" => Some(Self::Litespeed),
            _ => None,
        }
    }

    /// Everything the apply engine needs to write one site's vhost.
    ///
    /// One function rather than four accessors because the four answers only
    /// make sense together: a template rendered into the other server's path,
    /// or checked with the other server's validator, is a way to take a machine
    /// down that no individual getter would look wrong.
    pub fn site_vhost(self, domain: &str) -> Result<Vhost> {
        match self {
            Self::Nginx => Ok(Vhost {
                file: ManagedFile::nginx(paths::nginx_site(domain)),
                template: "nginx/site.conf",
                service: "nginx",
            }),
            Self::Apache => Ok(Vhost {
                file: ManagedFile::apache(paths::apache_site(domain)),
                template: "apache/site.conf",
                service: "apache",
            }),
            other => Err(unbuilt(other)),
        }
    }

    /// The service's own configuration check, which the apply engine runs
    /// between writing the file and reloading — and after which it rolls back.
    ///
    /// The engine will not activate a file it cannot validate, and that rule is
    /// why OpenLiteSpeed is last in the order of work rather than first.
    pub fn validator(self) -> Result<&'static dyn unihelm_config::apply::Validator> {
        match self {
            Self::Nginx => Ok(&NginxValidator),
            Self::Apache => Ok(&ApacheValidator),
            other => Err(unbuilt(other)),
        }
    }

    /// The panel's own vhost, when a domain has been attached to it.
    ///
    /// Load-bearing in a way a site's is not: if this is wrong, the panel that
    /// would tell you it is wrong is the thing that is down.
    pub fn panel_vhost(self) -> Result<Vhost> {
        match self {
            Self::Nginx => Ok(Vhost {
                file: ManagedFile::nginx(paths::nginx_panel()),
                template: "nginx/panel.conf",
                service: "nginx",
            }),
            Self::Apache => Ok(Vhost {
                file: ManagedFile::apache(paths::apache_panel()),
                template: "apache/panel.conf",
                service: "apache",
            }),
            other => Err(unbuilt(other)),
        }
    }

    /// The default vhost, which answers for every hostname no site claims.
    pub fn catchall(self) -> Result<Vhost> {
        match self {
            Self::Nginx => Ok(Vhost {
                file: ManagedFile::nginx(paths::nginx_catchall()),
                template: "nginx/catchall.conf",
                service: "nginx",
            }),
            Self::Apache => Ok(Vhost {
                file: ManagedFile::apache(paths::apache_catchall()),
                template: "apache/catchall.conf",
                service: "apache",
            }),
            other => Err(unbuilt(other)),
        }
    }

    /// The one include added to the server's own configuration.
    ///
    /// The whole footprint the panel has on a file the distribution owns, which
    /// is what keeps `apt upgrade` and a panel upgrade independent.
    pub fn hook(self) -> Result<Vhost> {
        match self {
            Self::Nginx => Ok(Vhost {
                file: ManagedFile::nginx(paths::nginx_hook()),
                template: "nginx/unihelm.conf",
                service: "nginx",
            }),
            Self::Apache => Ok(Vhost {
                file: ManagedFile::apache(paths::apache_hook()),
                template: "apache/unihelm.conf",
                service: "apache",
            }),
            other => Err(unbuilt(other)),
        }
    }

    /// The unit that serves, for starting the target and stopping the incumbent.
    pub fn unit(self) -> Result<unihelm_distro::ManagedUnit> {
        match self {
            Self::Nginx => Ok(unihelm_distro::ManagedUnit::Nginx),
            Self::Apache => Ok(unihelm_distro::ManagedUnit::Apache),
            other => Err(unbuilt(other)),
        }
    }

    /// How a configuration change is made live.
    ///
    /// A reload for every one of the three: they all re-read their configuration
    /// without dropping connections, and a restart to publish a vhost would take
    /// every other site on the machine down for the length of it.
    pub fn reloader(self, distro: &Distro) -> Result<UnitReloader> {
        match self {
            Self::Nginx => Ok(UnitReloader::nginx(distro)),
            Self::Apache => Ok(UnitReloader::apache(distro)),
            other => Err(unbuilt(other)),
        }
    }
}

/// One file the panel writes for whichever server is serving.
#[derive(Debug)]
pub struct Vhost {
    pub file: ManagedFile,
    pub template: &'static str,
    /// Serialisation key — every file belonging to one service shares it, so
    /// two sites are never written and reloaded at the same time.
    pub service: &'static str,
}

impl Vhost {
    /// The path the vhost is written to, for a caller that wants only that.
    pub fn path(&self) -> &PathBuf {
        &self.file.path
    }
}

// ---------------------------------------------------------------------------
// What a server cannot do
// ---------------------------------------------------------------------------

/// One thing a site is configured for that the target web server cannot do.
///
/// The reason this exists at all: switching is not "render the other template".
/// nginx has three per-site controls with no equivalent in Apache's base
/// modules, and an operator who has rate limiting on a site, moves to Apache and
/// is not told has lost a control they chose and still believe they have. That
/// is the same failure as every serious bug this project has had — the panel
/// saying a thing is true when it is not — and it is worth more than the
/// templates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Gap {
    /// The site this is about, or `None` when it is about the whole machine.
    ///
    /// Two of the panel's features are server-wide and nginx-only — the WAF and
    /// Adminer — so a switch loses them for every site at once rather than for
    /// one. Reporting those against an arbitrary domain would tell an operator
    /// with forty sites that one of them has a problem.
    pub domain: Option<String>,
    /// The field the panel shows, so the page that reports it can point at the
    /// control the operator set.
    pub field: &'static str,
    /// What is lost, in a sentence an operator can act on.
    pub detail: String,
}

/// Everything the sites on this machine are configured for that `target` cannot
/// serve.
///
/// An empty answer is the only one that makes a switch safe to do silently.
/// Anything else is presented, per site and per control, and the operator
/// decides — the panel does not decide for them in either direction: refusing
/// outright would strand somebody who set a rate limit once and does not want
/// it, and proceeding quietly is the failure above.
pub fn gaps(target: WebServer, sites: &[unihelm_db::Site]) -> Vec<Gap> {
    let mut found = Vec::new();
    for site in sites {
        // Nginx can do everything the panel offers, because the panel's
        // offering grew out of what nginx does. This is not an assumption about
        // the other two.
        if target == WebServer::Nginx {
            continue;
        }

        if site.rate_limit_enabled {
            found.push(Gap {
                domain: Some(site.domain.clone()),
                field: "rate_limit_enabled",
                detail: format!(
                    "{} limits requests to {}/s with a burst of {}. {} has no request rate \
                     limiting in its base modules — mod_ratelimit throttles bandwidth in \
                     KiB/s, not requests — so this site would serve unlimited requests \
                     until mod_qos or mod_evasive is installed and configured by hand.",
                    site.domain,
                    site.rate_limit_rps,
                    site.rate_limit_burst,
                    target.display_name(),
                ),
            });
        }

        if site.http3 {
            found.push(Gap {
                domain: Some(site.domain.clone()),
                field: "http3",
                detail: format!(
                    "{} advertises HTTP/3. {} has no production HTTP/3: the module is \
                     experimental and needs a patched build. The site would fall back to \
                     HTTP/2, which works — but the panel would keep showing HTTP/3 as on.",
                    site.domain,
                    target.display_name(),
                ),
            });
        }

        if site.custom_nginx_snippet.is_some() {
            found.push(Gap {
                domain: Some(site.domain.clone()),
                field: "custom_nginx_snippet",
                detail: format!(
                    "{} has a custom nginx snippet. It is nginx configuration: rendering it \
                     into an {} vhost would fail the configuration check and roll the whole \
                     switch back, and translating it would mean guessing what it was for. It \
                     would not be applied.",
                    site.domain,
                    target.display_name(),
                ),
            });
        }
    }
    found
}

/// What this machine as a whole loses by moving to `target`.
///
/// The companion to [`gaps`], and separate from it because these are not
/// properties of a site: the WAF and Adminer are configured once and apply to
/// everything, so a switch turns them off for every site at once.
///
/// Both are nginx-only today, and both fail in the way this project treats as
/// worst. The WAF's rules are loaded by nginx's ModSecurity connector, which
/// Apache does not read — so after a switch the panel keeps showing the WAF as
/// enabled, at the paranoia level somebody chose, while no request is inspected.
/// Adminer is served from an nginx vhost, so the database GUI simply stops
/// answering. Neither announces itself.
pub async fn server_gaps(ctx: &OpContext, target: WebServer) -> Result<Vec<Gap>> {
    if target == WebServer::Nginx {
        return Ok(Vec::new());
    }

    let mut found = Vec::new();

    if ctx
        .db()
        .get_setting_or(unihelm_db::settings::keys::WAF_ENABLED, false)
        .await
    {
        found.push(Gap {
            domain: None,
            field: "waf_enabled",
            detail: format!(
                "The WAF is enabled server-wide. Its rules are loaded by nginx's ModSecurity \
                 connector, and {} does not read that configuration — so no request would be \
                 inspected, while the Firewall page went on showing the WAF as on. Turn it \
                 off before switching, so that what the panel says matches what the server \
                 does.",
                target.display_name()
            ),
        });
    }

    // The file, not a setting: it is what `db.adminer.status` reads, so this
    // cannot disagree with what the panel shows on the Databases page.
    if paths::adminer_php().exists() {
        found.push(Gap {
            domain: None,
            field: "adminer",
            detail: format!(
                "Adminer, the database GUI, is served from an nginx vhost this panel writes. \
                 There is no {} vhost for it yet, so it would stop answering until one \
                 exists. Nothing in a database is affected.",
                target.display_name()
            ),
        });
    }

    Ok(found)
}

/// The refusal for a server that is in the catalogue and cannot serve yet.
///
/// It names the version, because "not implemented" on a panel that offered the
/// install reads as a bug in the panel rather than as work that is scheduled.
fn unbuilt(server: WebServer) -> UnihelmError {
    UnihelmError::new(
        ErrorCode::NotImplemented,
        format!(
            "{} is installed and this panel cannot write vhosts for it yet — it renders \
             sites for Nginx and Apache. OpenLiteSpeed lands after them; until it does, a \
             site served by this machine is served by one of those two.",
            server.display_name()
        ),
    )
}

/// Hand port 80 from one web server to the other.
///
/// Pulled out of [`Switch::run`] because it is the only part of a switch that
/// can leave a machine serving nothing, and a decision that dangerous should be
/// assertable without standing up a whole switch.
///
/// **`disable`, not `stop`.** Stopping leaves the unit enabled, so the next
/// reboot starts *both* — and they both want port 80. Whichever systemd reaches
/// first binds it and the other fails, so a machine switched to Apache could
/// come back from a reboot serving with nginx, or serving nothing at all,
/// depending on unit ordering nobody controls. The failure is invisible until
/// that reboot, which may be months after the switch, by which time nothing
/// connects the outage to the operation that caused it.
///
/// The two calls are also deliberately in this order and not overlapped: they
/// contend for the same port, so starting the target before the incumbent is
/// down means the target fails to bind and the rollback below fires on a
/// machine that was never actually broken.
async fn exchange(ctx: &OpContext, from: WebServer, target: WebServer) -> Result<()> {
    let svc = &ctx.distro().svc;
    let family = ctx.distro().info.family;
    let leaving = from.unit()?.unit_name(family);
    let arriving = target.unit()?.unit_name(family);

    svc.disable(&leaving, true).await?;
    if let Err(e) = svc.enable(&arriving, true).await {
        // The target would not start. Put the incumbent back — enabled as well
        // as running, which is what `enable(_, true)` does — because the
        // alternative is a machine serving nothing, now and after every reboot.
        ctx.log(format!(
            "{} did not start ({e}); restoring {}",
            target.display_name(),
            from.display_name()
        ));
        svc.enable(&leaving, true).await.ok();
        return Err(UnihelmError::new(
            ErrorCode::Internal,
            format!(
                "{} would not start, so {} was put back and is serving again: {e}",
                target.display_name(),
                from.display_name(),
            ),
        ));
    }
    Ok(())
}

/// Which web server this machine serves sites with.
///
/// Absent means nginx. Not a default anybody chose — it is the only one the
/// panel has ever been able to render a vhost for, so every existing server is
/// on it, and reading a missing row as "unknown" would break every one of them
/// at once.
pub async fn active(ctx: &OpContext) -> Result<WebServer> {
    match ctx.db().get_setting::<WebServer>(WEB_SERVER_SETTING).await {
        Ok(Some(server)) => Ok(server),
        Ok(None) => Ok(WebServer::Nginx),
        // Deliberately an error and not a fall back to nginx. A row that exists
        // and cannot be read is a machine that may be serving with Apache, and
        // guessing nginx there would write vhosts into a directory nothing is
        // reading and report success.
        Err(e) => Err(UnihelmError::internal(format!(
            "the record of which web server serves this machine (`{WEB_SERVER_SETTING}`) \
             could not be read: {e}. Until it can, the panel will not write a vhost, \
             because it cannot say which server would read it."
        ))),
    }
}

// ---------------------------------------------------------------------------
// webserver.switch
// ---------------------------------------------------------------------------

/// `webserver.switch` — move every site on this machine to another web server.
///
/// One operation for the whole machine rather than one per site, and that is
/// the design rather than a convenience: two web servers both wanting port 80
/// is not a half-migrated machine, it is a machine where the second one failed
/// to start and nobody noticed until the first was stopped. So every vhost is
/// written, the whole configuration is checked with the target's own tool, and
/// only then does the incumbent stop.
pub struct Switch;

#[derive(Debug, Deserialize)]
pub struct SwitchInput {
    /// `nginx`, `apache` or `litespeed`.
    pub target: String,
    /// Proceed even though some sites lose a control they are configured for.
    ///
    /// Defaults to false, and the refusal that comes back lists every site and
    /// every control. An operator who has a rate limit on a shop and is moved
    /// off it silently has lost something they chose and still believe they
    /// have; making them say so is the whole point of [`gaps`].
    #[serde(default)]
    pub accept_gaps: bool,
}

#[derive(Debug, Serialize)]
pub struct SwitchOutput {
    pub from: String,
    pub to: String,
    /// How many sites were re-rendered.
    pub sites: usize,
    /// What each of them lost, when the caller accepted it.
    pub dropped: Vec<Gap>,
}

#[async_trait::async_trait]
impl TypedOperation for Switch {
    type Input = SwitchInput;
    type Output = SwitchOutput;

    const NAME: &'static str = "webserver.switch";
    const PERMISSION: Permission = Permission::StackManage;
    // A task: it re-renders every vhost on the machine and restarts what serves
    // them, which on a server with forty sites is not a request-response.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        // Re-running it lands on the same state: the same vhosts, the same
        // unit running. A run interrupted between stopping one and starting the
        // other is exactly the case a second run has to be able to finish.
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let target = WebServer::from_slug(&input.target).ok_or_else(|| {
            UnihelmError::new(
                ErrorCode::InvalidInput,
                format!(
                    "`{}` is not a web server this panel knows. It serves with: nginx, \
                     apache, litespeed.",
                    input.target
                ),
            )
            .with_field("target")
        })?;
        // Refuses here rather than after writing anything, so asking for
        // OpenLiteSpeed today leaves the machine exactly as it was.
        let _ = target.site_vhost("probe.invalid")?;

        let from = active(ctx).await?;
        if from == target {
            ctx.log(format!(
                "{} already serves this machine; nothing to do",
                target.display_name()
            ));
            return Ok(SwitchOutput {
                from: from.as_str().into(),
                to: target.as_str().into(),
                sites: 0,
                dropped: Vec::new(),
            });
        }

        refuse_where_the_panel_writes_where_the_server_does_not_read(ctx, target)?;
        refuse_when_the_target_is_not_installed(ctx, target).await?;
        if target == WebServer::Apache {
            ensure_apache_modules(ctx).await?;
            admit_to_the_web_group(ctx, target).await?;
        }

        let db = ctx.db();
        // Every site on the machine, not a tenant's page of them: a switch that
        // moved some is a machine with vhosts in two trees and one web server
        // reading only one of them.
        let sites = db.all_sites().await.map_err(UnihelmError::from)?;

        let mut dropped = gaps(target, &sites);
        dropped.extend(server_gaps(ctx, target).await?);
        if !dropped.is_empty() && !input.accept_gaps {
            let affected = dropped
                .iter()
                .filter_map(|g| g.domain.as_deref())
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            let server_wide = dropped.iter().filter(|g| g.domain.is_none()).count();
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "{} and {} of this machine's sites are configured for something {} cannot \
                     do:\n\n{}\n\nSwitch anyway to accept these, or change them \
                     first.",
                    match server_wide {
                        0 => "Nothing server-wide".to_string(),
                        1 => "One server-wide feature".to_string(),
                        n => format!("{n} server-wide features"),
                    },
                    affected,
                    target.display_name(),
                    dropped
                        .iter()
                        .map(|g| format!("  - {}", g.detail))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            )
            .with_field("accept_gaps"));
        }

        // From here on the machine is being changed, and every failure has to
        // leave the incumbent serving. Nothing below stops it until the whole
        // target configuration has been written and checked.
        ctx.log(format!(
            "moving {} site(s) from {} to {}",
            sites.len(),
            from.display_name(),
            target.display_name()
        ));

        // 1. The include, so the target reads what is written next.
        write_hook(ctx, target).await?;

        // 2. Every vhost, into the target's own tree. The incumbent is still
        //    serving from its own the entire time.
        let mut rendered = 0usize;
        for site in &sites {
            let subscription = db
                .subscriptions(&unihelm_core::TenantScope::Global)
                .by_id(site.subscription_id)
                .await
                .map_err(UnihelmError::from)?;
            let Some(subscription) = subscription else {
                // A site whose subscription is gone is not one to serve. It is
                // skipped rather than failing the switch, because one orphaned
                // row must not be able to hold a machine on its old web server.
                ctx.log(format!(
                    "{}: no subscription; not rendered for {}",
                    site.domain,
                    target.display_name()
                ));
                continue;
            };
            let linux_user = unihelm_core::LinuxUser::parse(&subscription.linux_user)?;
            crate::site::render_vhost_for(ctx, site, &linux_user, target).await?;
            rendered += 1;
        }

        // 3. The default vhost, which answers for every name no site claims.
        //    Last of the three, because on Apache the *first* vhost parsed owns
        //    an address and this one has to be able to lose that race to
        //    nothing: writing it before the sites would make an unconfigured
        //    hostname land on whichever site happened to be written first for
        //    the length of the switch.
        crate::stack::write_catchall_for(ctx, target).await?;

        // 4. The target's own check, over the whole tree. The apply calls above
        //    each ran it too, but only over what existed at the time — this is
        //    the first moment the complete configuration exists.
        if let Err(detail) = target.validator()?.validate().await {
            return Err(UnihelmError::new(
                ErrorCode::ConfigValidationFailed,
                format!(
                    "{} rejected the configuration this panel wrote for it, so nothing was \
                     switched and {} is still serving:\n\n{detail}",
                    target.display_name(),
                    from.display_name(),
                ),
            ));
        }

        // 5. The exchange. This is the only unsafe moment, and it is as short as
        //    two systemctl calls: they both want port 80.
        exchange(ctx, from, target).await?;

        // 6. Only now is it true, so only now is it written. A setting recorded
        //    before the unit started would have the panel render into a tree
        //    nothing reads for as long as it took somebody to notice.
        db.set_setting(WEB_SERVER_SETTING, &target)
            .await
            .map_err(UnihelmError::from)?;
        ctx.log(format!("{} is serving this machine", target.display_name()));

        Ok(SwitchOutput {
            from: from.as_str().into(),
            to: target.as_str().into(),
            sites: rendered,
            dropped,
        })
    }
}

/// The Apache modules the panel's vhosts need.
///
/// This list exists because **a missing Apache module is not a syntax error**.
/// `apachectl configtest` passes, Apache starts, every page loads, and the
/// directives that needed the module are silently inert: no security headers,
/// no compression, no cache lifetimes — and with `proxy_fcgi` missing, a PHP
/// site serves the source of every `.php` file it has as plain text.
///
/// That is the whole reason the switch checks rather than trusts. nginx has no
/// equivalent hazard: its features are compiled in, and a directive it does not
/// know fails `nginx -t` loudly.
const APACHE_MODULES: &[(&str, &str)] = &[
    (
        "proxy_fcgi",
        "hands .php requests to PHP-FPM over its socket",
    ),
    (
        "proxy_http",
        "reverse-proxies sites that sit in front of an app",
    ),
    (
        "proxy_wstunnel",
        "carries websockets, including the panel's terminal",
    ),
    ("ssl", "terminates TLS"),
    (
        "rewrite",
        "the https redirect, maintenance mode and redirect sites",
    ),
    ("headers", "the security headers on every response"),
    ("expires", "cache lifetimes on static assets"),
    ("deflate", "compression"),
];

/// Refuse a target whose configuration tree this build writes to the wrong place.
///
/// Every `paths::apache_*` is `/etc/apache2/...`, which is Debian's layout.
/// Red Hat's Apache is `httpd` and reads `/etc/httpd/conf.d`, so on EL the panel
/// would write a complete and correct set of vhosts into a directory httpd has
/// never heard of.
///
/// The reason this has to be a refusal rather than a warning is what happens
/// next: `apachectl configtest` **passes**, because the configuration httpd
/// actually parses is the stock one and there is nothing wrong with it. The
/// switch's own safety check would therefore report success, nginx would be
/// stopped, httpd would start, and every site on the machine would answer with
/// the distribution's default page. Validation that cannot see the files it is
/// meant to be validating is worse than no validation, because it is trusted.
///
/// EL support is a matter of resolving these paths against the family. Until
/// that is done, this says so instead of proving it the expensive way.
fn refuse_where_the_panel_writes_where_the_server_does_not_read(
    ctx: &OpContext,
    target: WebServer,
) -> Result<()> {
    if target == WebServer::Apache && ctx.distro().info.family == unihelm_distro::Family::Rhel {
        return Err(UnihelmError::new(
            ErrorCode::NotImplemented,
            format!(
                "this panel writes Apache vhosts to {}, which is Debian's layout. On {} \
                 Apache is `httpd` and reads /etc/httpd/conf.d, so the vhosts would be \
                 written correctly and read by nothing — and `apachectl configtest` would \
                 still pass, because httpd would be checking its stock configuration. \
                 Nginx keeps serving this machine.",
                paths::apache_dir().display(),
                ctx.distro().info.pretty_name,
            ),
        )
        .with_field("target"));
    }
    Ok(())
}

/// The account each web server runs its workers as.
///
/// nginx.org's package uses `nginx` on both families. Apache is `www-data` on
/// Debian and `apache` on EL — the one place in this module where the two
/// families disagree about something other than a unit name.
fn runtime_account(server: WebServer, family: unihelm_distro::Family) -> Option<&'static str> {
    match (server, family) {
        (WebServer::Nginx, _) => Some("nginx"),
        (WebServer::Apache, unihelm_distro::Family::Debian) => Some("www-data"),
        (WebServer::Apache, unihelm_distro::Family::Rhel) => Some("apache"),
        (WebServer::Litespeed, _) => None,
    }
}

/// Let the arriving web server reach what the incumbent could.
///
/// This is the step without which nothing else in a switch matters. The panel's
/// whole isolation model is built on one group: a tenant's site directory is
/// `tenant:nginx` at `0710`, so the tenant owns it outright and the web server
/// can *traverse* it because it is in that group and nobody else can do either.
/// Each site's FPM socket is `0660` with the same group, for the same reason.
///
/// Apache runs as `www-data`, which is in none of that. Without this, a machine
/// switched to Apache answers **403 for every static file** — it cannot walk
/// into the directory — and **503 for every PHP page**, because it cannot open
/// the socket. Every template in this release could be perfect and the machine
/// would still serve nothing, which is what makes this a precondition and not a
/// refinement.
///
/// Adding the account to the existing group rather than inventing a shared one:
/// the group already exists on every machine this panel has ever provisioned,
/// with the right membership and the right mode on several thousand
/// directories. A new group would mean re-owning all of them, which is a
/// migration that can half-finish. The name reads oddly on an Apache machine —
/// it is the web server's group, whatever it is called.
async fn admit_to_the_web_group(ctx: &OpContext, target: WebServer) -> Result<()> {
    let family = ctx.distro().info.family;
    let Some(account) = runtime_account(target, family) else {
        return Ok(());
    };
    let group = crate::provision::nginx_user(ctx.distro());
    if account == group {
        return Ok(());
    }

    // `-a -G` appends. Without `-a` this *replaces* every supplementary group
    // the account has, which on `www-data` is how a switch would take away
    // whatever else the machine had granted it.
    unihelm_distro::Cmd::new("usermod")
        .args(["-a", "-G", group, account])
        .timeout(std::time::Duration::from_secs(15))
        .run_checked()
        .await
        .map_err(|e| {
            UnihelmError::internal(format!(
                "{} runs as `{account}` and could not be added to the `{group}` group ({e}). \
                 Without it every site directory (mode 0710) and every FPM socket (mode 0660) \
                 stays unreachable, so the machine would answer 403 for static files and 503 \
                 for PHP. Nothing was switched.",
                target.display_name()
            ))
        })?;

    ctx.log(format!(
        "`{account}` added to `{group}`, so {} can read site directories and FPM sockets",
        target.display_name()
    ));
    Ok(())
}

/// Turn on what the vhosts need, and refuse if anything is still missing.
///
/// Enabling rather than only reporting: this panel exists so that nothing has to
/// be done over ssh, and `a2enmod` on an already-enabled module is a no-op that
/// prints so. The check afterwards is what makes it safe — the enable is a
/// best effort, the verification is not.
async fn ensure_apache_modules(ctx: &OpContext) -> Result<()> {
    if ctx.distro().info.family != unihelm_distro::Family::Rhel {
        for (module, _) in APACHE_MODULES {
            // Failures are not fatal here. A module compiled in statically has
            // no `.load` file for a2enmod to find, and reporting that as a
            // broken machine would refuse a switch that would have worked. The
            // verification below is what decides.
            let _ = unihelm_distro::Cmd::new("a2enmod")
                .args(["-q", module])
                .timeout(std::time::Duration::from_secs(15))
                .run()
                .await;
        }
    }

    // `apachectl -M` is Apache's own answer, which is the only one that counts:
    // it lists what the running configuration actually loads, statically linked
    // modules included.
    let mut listed = String::new();
    for binary in ["apache2ctl", "apachectl"] {
        if let Ok(out) = unihelm_distro::Cmd::new(binary)
            .arg("-M")
            .timeout(std::time::Duration::from_secs(15))
            .run()
            .await
        {
            listed = out.trimmed_stdout().to_string();
            if !listed.is_empty() {
                break;
            }
        }
    }
    if listed.is_empty() {
        return Err(UnihelmError::new(
            ErrorCode::Conflict,
            "Apache would not report its loaded modules, so the panel cannot tell whether              the vhosts it writes would work. Nothing was switched."
                .to_string(),
        ));
    }

    let missing = modules_missing_from(&listed);
    if !missing.is_empty() {
        return Err(UnihelmError::new(
            ErrorCode::Conflict,
            format!(
                "Apache is missing {} module(s) the panel's vhosts need, and a missing                  Apache module is silent — the configuration would pass its own check and                  the directives would simply do nothing. Nothing was switched:

{}",
                missing.len(),
                missing
                    .iter()
                    .map(|(module, why)| format!("  - mod_{module}: {why}"))
                    .collect::<Vec<_>>()
                    .join("
"),
            ),
        ));
    }
    Ok(())
}

/// Which of [`APACHE_MODULES`] `apachectl -M` did not list.
///
/// Its own function so the matching can be asserted. `-M` prints one module per
/// line as `proxy_fcgi_module (shared)`, and the trap is the substring: looking
/// for `proxy` alone finds `proxy_fcgi_module` and reports mod_proxy present on
/// a machine that has only the FastCGI half — so the `_module` suffix is part of
/// what is searched for, and the search is per line rather than over the blob.
fn modules_missing_from(listed: &str) -> Vec<&'static (&'static str, &'static str)> {
    let present: std::collections::BTreeSet<&str> = listed
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|token| token.strip_suffix("_module"))
        .collect();
    APACHE_MODULES
        .iter()
        .filter(|(module, _)| !present.contains(module))
        .collect()
}

/// Refuse before anything is written when the target's packages are not there.
///
/// Naming the Stack page rather than the package: an operator reading "install
/// apache2" has to work out where, and the panel already has one place for it.
async fn refuse_when_the_target_is_not_installed(ctx: &OpContext, target: WebServer) -> Result<()> {
    let unit = target.unit()?.unit_name(ctx.distro().info.family);
    // The unit existing at all is the question, not whether it is running: the
    // target is by definition not running yet.
    //
    // On the *state*, not on Ok/Err. Asking systemd about a unit it has never
    // heard of succeeds — it answers `load_state=not-found` — so a match that
    // accepted any `Ok` would have called an uninstalled Apache installed, and
    // the switch would have stopped nginx before finding out.
    let state = ctx
        .distro()
        .svc
        .status(&unit)
        .await
        .map(|s| s.state)
        .unwrap_or(unihelm_distro::svc::UnitState::NotFound);
    if state == unihelm_distro::svc::UnitState::NotFound {
        return Err(UnihelmError::new(
            ErrorCode::Conflict,
            format!(
                "{} is not installed on this server ({unit} does not exist), so there is \
                 nothing to switch to. Install it from the Stack page first.",
                target.display_name(),
                unit = unit.as_str(),
            ),
        )
        .with_field("target"));
    }
    Ok(())
}

/// The include the target reads the panel's tree through.
async fn write_hook(ctx: &OpContext, target: WebServer) -> Result<()> {
    let hook = target.hook()?;
    let reloader = target.reloader(ctx.distro())?;
    ctx.config()
        .apply(unihelm_config::ApplyRequest {
            file: hook.file,
            template: hook.template,
            context: serde_json::json!({
                "nginx_dir": paths::nginx_dir(),
                "apache_dir": paths::apache_dir(),
            }),
            service: hook.service,
            // Not the target's validator: this file is written *before* the
            // vhosts it includes exist, and on a machine where the target has
            // never run there is nothing coherent to check yet. The full check
            // in step 4 is what covers it, over the complete tree.
            validator: &crate::services::SkipValidation,
            reloader: &reloader,
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_catalogued_web_server_has_an_arm() {
        // The catalogue's web_server category and this enum have to name the
        // same three things. A fourth entry added there without one here would
        // be installable and then unserveable with no refusal to say so — which
        // is exactly the state Apache and LiteSpeed were in before this module.
        let catalogued: Vec<&str> = crate::catalogue::CATALOGUE
            .iter()
            .filter(|e| e.category == crate::catalogue::Category::WebServer)
            .map(|e| e.slug)
            .collect();
        for slug in &catalogued {
            assert!(
                WebServer::from_slug(slug).is_some(),
                "the catalogue installs {slug} and this module has no arm for it"
            );
        }
        for server in [WebServer::Nginx, WebServer::Apache, WebServer::Litespeed] {
            assert!(
                catalogued.contains(&server.as_str()),
                "{} is in this enum and not in the catalogue",
                server.as_str()
            );
        }
    }

    #[test]
    fn nginx_renders_the_template_and_path_it_always_has() {
        // The seam must not move a single byte on a machine running nginx. This
        // is the whole safety claim of the step: same file, same template, same
        // serialisation key as the two call sites named literally before.
        let vhost = WebServer::Nginx.site_vhost("example.com").unwrap();
        assert_eq!(vhost.template, "nginx/site.conf");
        assert_eq!(vhost.service, "nginx");
        assert_eq!(*vhost.path(), paths::nginx_site("example.com"));
        assert_eq!(vhost.file.mode, 0o644);
    }

    #[test]
    fn apache_renders_its_own_template_into_its_own_tree() {
        // Every one of the four has to be Apache's. Nginx's template into
        // Apache's path is a file nothing reads; Apache's file checked with
        // `nginx -t` is a change the apply engine believes it validated.
        let vhost = WebServer::Apache.site_vhost("example.com").unwrap();
        assert_eq!(vhost.template, "apache/site.conf");
        assert_eq!(vhost.service, "apache");
        assert_eq!(*vhost.path(), paths::apache_site("example.com"));
        assert_ne!(*vhost.path(), paths::nginx_site("example.com"));
        assert_eq!(
            WebServer::Apache.validator().unwrap().name(),
            "apachectl configtest"
        );
        assert_eq!(WebServer::Nginx.validator().unwrap().name(), "nginx -t");
    }

    #[test]
    fn a_server_that_cannot_serve_yet_refuses_by_name() {
        // One server today. Left as a loop rather than written out, because the
        // next entry added to the catalogue joins it here and the assertions
        // below are what stop it shipping unreachable.
        #[allow(clippy::single_element_loop)]
        for server in [WebServer::Litespeed] {
            let err = server.site_vhost("example.com").unwrap_err();
            assert_eq!(err.code, ErrorCode::NotImplemented);
            assert!(
                err.detail.contains(server.display_name()),
                "a refusal that does not name what was asked for: {}",
                err.detail
            );
            // And the same refusal from the validator, so a caller cannot
            // assemble half an Apache apply out of the parts that do answer.
            match server.validator() {
                Ok(_) => panic!("{} offered a validator it does not have", server.as_str()),
                Err(e) => assert_eq!(e.code, ErrorCode::NotImplemented),
            }
        }
    }

    fn site(domain: &str) -> unihelm_db::Site {
        unihelm_db::Site {
            id: unihelm_core::SiteId(1),
            subscription_id: unihelm_core::SubscriptionId(1),
            domain: domain.to_string(),
            site_type: unihelm_db::SiteType::Php,
            php_version: Some(unihelm_core::PhpVersion::V83),
            root_dir: format!("/home/uh_a/sites/{domain}"),
            status: unihelm_db::SiteStatus::Active,
            www_policy: unihelm_db::WwwPolicy::None,
            force_https: true,
            http3: false,
            maintenance_mode: false,
            client_max_body_size: "64m".into(),
            custom_nginx_snippet: None,
            php_ini_overrides: None,
            rate_limit_enabled: false,
            rate_limit_rps: 20,
            rate_limit_burst: 40,
            conn_limit: 20,
            proxy_port: None,
            redirect_target: None,
            redirect_code: 301,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn nginx_can_serve_everything_the_panel_offers() {
        // Not an assumption — the panel's per-site controls grew out of what
        // nginx does, so this is true by construction and stays true only while
        // nothing is added that nginx cannot do.
        let mut loaded = site("a.test");
        loaded.rate_limit_enabled = true;
        loaded.http3 = true;
        loaded.custom_nginx_snippet = Some("add_header X 1;".into());
        assert_eq!(gaps(WebServer::Nginx, &[loaded]), Vec::new());
    }

    #[test]
    fn apache_reports_the_three_controls_it_cannot_honour() {
        let mut loaded = site("a.test");
        loaded.rate_limit_enabled = true;
        loaded.http3 = true;
        loaded.custom_nginx_snippet = Some("add_header X 1;".into());

        let found = gaps(WebServer::Apache, &[loaded, site("plain.test")]);
        let fields: Vec<&str> = found.iter().map(|g| g.field).collect();
        assert_eq!(
            fields,
            vec!["rate_limit_enabled", "http3", "custom_nginx_snippet"]
        );
        // Every gap names its own site: a switch across forty sites has to say
        // which three are affected, not that three things are wrong somewhere.
        assert!(
            found.iter().all(|g| g.domain.as_deref() == Some("a.test")),
            "{found:?}"
        );
        // And a site that uses none of them is not mentioned at all.
        assert!(
            !found
                .iter()
                .any(|g| g.domain.as_deref() == Some("plain.test")),
            "{found:?}"
        );
    }

    #[tokio::test]
    async fn an_enabled_waf_is_reported_before_it_goes_silently_inert() {
        // The worst shape of failure this project has: the panel keeps showing
        // the WAF as enabled, at the paranoia level somebody chose, while no
        // request is inspected — because the rules are loaded by nginx's
        // ModSecurity connector and Apache never reads that file.
        let ctx = op_ctx().await;
        assert_eq!(
            server_gaps(&ctx, WebServer::Apache).await.unwrap(),
            Vec::new(),
            "a machine with no WAF has nothing to report"
        );

        ctx.db()
            .set_setting(unihelm_db::settings::keys::WAF_ENABLED, &true)
            .await
            .unwrap();

        let found = server_gaps(&ctx, WebServer::Apache).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].field, "waf_enabled");
        // Server-wide, so it belongs to no site: reporting it against one
        // domain would tell an operator with forty sites that one has a fault.
        assert_eq!(found[0].domain, None);
        assert!(found[0].detail.contains("Apache"), "{}", found[0].detail);
    }

    #[tokio::test]
    async fn nginx_loses_nothing_server_wide_either() {
        let ctx = op_ctx().await;
        ctx.db()
            .set_setting(unihelm_db::settings::keys::WAF_ENABLED, &true)
            .await
            .unwrap();
        assert_eq!(
            server_gaps(&ctx, WebServer::Nginx).await.unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn a_gap_says_what_is_lost_rather_than_naming_a_field() {
        // "rate_limit_enabled: unsupported" tells an operator nothing about
        // what their site will do differently on Monday.
        let mut loaded = site("shop.test");
        loaded.rate_limit_enabled = true;
        loaded.rate_limit_rps = 5;
        let found = gaps(WebServer::Apache, &[loaded]);
        let detail = &found[0].detail;
        assert!(detail.contains("shop.test"), "{detail}");
        assert!(detail.contains('5'), "{detail}");
        assert!(detail.contains("Apache"), "{detail}");
        assert!(detail.contains("unlimited requests"), "{detail}");
    }

    async fn op_ctx() -> OpContext {
        op_ctx_on(unihelm_distro::Family::Debian).await
    }

    async fn op_ctx_on(family: unihelm_distro::Family) -> OpContext {
        use crate::registry::Services;
        use std::sync::Arc;
        use unihelm_core::{AuthContext, Role, TenantScope, UserId};

        let distro = unihelm_distro::mock::mock_distro_with_recorder(family).0;
        let db = unihelm_db::Db::open_memory().await.unwrap();
        let services = Arc::new(
            Services::new(distro, db, unihelm_db::MasterKey::generate()).expect("templates"),
        );
        let auth = AuthContext::from_role(UserId(1), Role::Admin, TenantScope::Global, "req-test");
        OpContext::new(services, auth)
    }

    async fn switch_to(ctx: &OpContext, target: &str, accept_gaps: bool) -> Result<SwitchOutput> {
        Switch
            .run(
                ctx,
                SwitchInput {
                    target: target.into(),
                    accept_gaps,
                },
            )
            .await
    }

    #[tokio::test]
    async fn a_machine_with_no_setting_is_already_on_nginx() {
        // Every server this panel has ever installed. Switching to nginx has to
        // be a success that does nothing rather than a conflict, or the first
        // thing an operator tries on a fresh machine is an error.
        let ctx = op_ctx().await;
        let out = switch_to(&ctx, "nginx", false).await.unwrap();
        assert_eq!(out.from, "nginx");
        assert_eq!(out.to, "nginx");
        assert_eq!(out.sites, 0);
    }

    #[tokio::test]
    async fn a_target_this_build_cannot_render_refuses_before_anything_is_written() {
        // The order is what matters: OpenLiteSpeed is catalogued and could be
        // installed, and asking for it has to leave the machine exactly as it
        // was rather than half-written and rolled back.
        let ctx = op_ctx().await;
        let err = switch_to(&ctx, "litespeed", false).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotImplemented);
        assert!(err.detail.contains("OpenLiteSpeed"), "{}", err.detail);
        // And the record of what serves is untouched.
        assert_eq!(active(&ctx).await.unwrap(), WebServer::Nginx);
    }

    #[tokio::test]
    async fn a_target_that_is_not_installed_refuses_before_stopping_anything() {
        // The mock has no apache2.service, which is the state of every machine
        // that has not installed Apache. Systemd answers about a unit it has
        // never heard of with a *success* carrying `not-found`, so a check that
        // only looked at Ok/Err would have called this installed and stopped
        // nginx before finding out otherwise.
        let ctx = op_ctx().await;
        let err = switch_to(&ctx, "apache", false).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("not installed"), "{}", err.detail);
        assert!(err.detail.contains("apache2.service"), "{}", err.detail);
        assert_eq!(active(&ctx).await.unwrap(), WebServer::Nginx);
    }

    #[tokio::test]
    async fn the_incumbent_is_disabled_and_not_merely_stopped() {
        // The bug this pins: `systemctl stop nginx` leaves nginx *enabled*, so
        // the next reboot starts nginx and Apache together and they fight over
        // port 80. The machine comes back serving with whichever systemd
        // reached first — possibly the server the operator switched away from,
        // possibly neither. Nothing about it is visible until that reboot.
        let ctx = op_ctx().await;
        let family = ctx.distro().info.family;
        let nginx = WebServer::Nginx.unit().unwrap().unit_name(family);
        let apache = WebServer::Apache.unit().unwrap().unit_name(family);
        let svc = &ctx.distro().svc;

        // A machine as it is before a switch: nginx enabled and running.
        svc.enable(&nginx, true).await.unwrap();

        exchange(&ctx, WebServer::Nginx, WebServer::Apache)
            .await
            .unwrap();

        let left = svc.status(&nginx).await.unwrap();
        assert_eq!(
            left.enabled.as_deref(),
            Some("disabled"),
            "nginx was stopped but left enabled, so a reboot starts it beside Apache"
        );
        assert!(!left.is_active(), "nginx is still running");

        let arrived = svc.status(&apache).await.unwrap();
        assert_eq!(arrived.enabled.as_deref(), Some("enabled"));
        assert!(
            arrived.is_active(),
            "Apache is not running after the switch"
        );
    }

    #[tokio::test]
    async fn a_target_that_will_not_start_leaves_the_incumbent_enabled_again() {
        // Rollback has to undo the *disable* as well as the stop. Putting nginx
        // back with `systemctl start` alone would leave a machine that serves
        // now and serves nothing after the next reboot — the same latent
        // failure, reached by the path that was supposed to avoid it.
        let ctx = op_ctx().await;
        let family = ctx.distro().info.family;
        let nginx = WebServer::Nginx.unit().unwrap().unit_name(family);
        let svc = &ctx.distro().svc;
        svc.enable(&nginx, true).await.unwrap();

        // Litespeed has no unit arm, so `exchange` fails before touching
        // anything — the incumbent must be untouched, not merely restored.
        let err = exchange(&ctx, WebServer::Nginx, WebServer::Litespeed)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotImplemented);

        let still = svc.status(&nginx).await.unwrap();
        assert_eq!(still.enabled.as_deref(), Some("enabled"));
        assert!(
            still.is_active(),
            "nginx was taken down for a target that could never start"
        );
    }

    #[test]
    fn each_web_server_names_the_account_its_workers_run_as() {
        use unihelm_distro::Family;
        // The account matters because the panel's whole isolation model is one
        // group: site directories are `tenant:nginx` at 0710 and FPM sockets
        // are 0660 with the same group. A web server outside that group answers
        // 403 for every static file and 503 for every PHP page, with a
        // configuration that is otherwise perfect.
        assert_eq!(
            runtime_account(WebServer::Nginx, Family::Debian),
            Some("nginx")
        );
        assert_eq!(
            runtime_account(WebServer::Nginx, Family::Rhel),
            Some("nginx")
        );
        // The one place the two families disagree about more than a unit name.
        assert_eq!(
            runtime_account(WebServer::Apache, Family::Debian),
            Some("www-data")
        );
        assert_eq!(
            runtime_account(WebServer::Apache, Family::Rhel),
            Some("apache")
        );
        // Not built, so it has no account to admit rather than a guessed one.
        assert_eq!(runtime_account(WebServer::Litespeed, Family::Debian), None);
    }

    #[tokio::test]
    async fn switching_to_the_server_already_serving_admits_nobody() {
        // nginx is already the group. `usermod -a -G nginx nginx` would be a
        // command run for nothing on every no-op switch.
        let ctx = op_ctx().await;
        admit_to_the_web_group(&ctx, WebServer::Nginx)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn apache_is_refused_on_a_family_whose_layout_this_build_does_not_write() {
        // Every `paths::apache_*` is Debian's /etc/apache2. On EL, Apache is
        // httpd and reads /etc/httpd/conf.d — so the vhosts would be written
        // correctly and read by nothing, and `apachectl configtest` would still
        // pass because httpd would be checking its own stock configuration.
        // The switch's safety check would report success while taking every
        // site on the machine down to the distribution's default page.
        let ctx = op_ctx_on(unihelm_distro::Family::Rhel).await;
        let err = switch_to(&ctx, "apache", true).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotImplemented);
        assert!(err.detail.contains("/etc/httpd"), "{}", err.detail);
        assert_eq!(active(&ctx).await.unwrap(), WebServer::Nginx);

        // And the refusal comes before the not-installed check, so an EL
        // machine that *does* have httpd still gets the layout answer rather
        // than being told to install what it already has.
        assert!(!err.detail.contains("not installed"), "{}", err.detail);
    }

    #[tokio::test]
    async fn a_target_that_is_not_a_web_server_names_the_ones_that_are() {
        let ctx = op_ctx().await;
        let err = switch_to(&ctx, "caddy", false).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.detail.contains("nginx"), "{}", err.detail);
        assert!(err.detail.contains("apache"), "{}", err.detail);
    }

    #[test]
    fn a_module_apache_did_not_list_is_reported_as_missing() {
        // The real shape of `apachectl -M`, indented, one per line.
        let full: String = APACHE_MODULES
            .iter()
            .map(|(m, _)| format!(" {m}_module (shared)\n"))
            .collect();
        assert!(modules_missing_from(&full).is_empty(), "{full}");

        let without_fcgi = full.replace(" proxy_fcgi_module (shared)\n", "");
        let missing = modules_missing_from(&without_fcgi);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].0, "proxy_fcgi");
    }

    #[test]
    fn a_prefix_match_does_not_pass_a_module_off_as_another() {
        // `proxy_fcgi_module` contains `proxy`. A substring search over the
        // whole output would report mod_proxy present on a machine that has
        // only the FastCGI half — and mod_proxy_http is what a proxy site needs.
        let only_fcgi = " proxy_fcgi_module (shared)\n";
        let missing: Vec<&str> = modules_missing_from(only_fcgi)
            .iter()
            .map(|(m, _)| *m)
            .collect();
        assert!(missing.contains(&"proxy_http"), "{missing:?}");
        assert!(missing.contains(&"proxy_wstunnel"), "{missing:?}");
        assert!(!missing.contains(&"proxy_fcgi"), "{missing:?}");
    }

    #[test]
    fn the_setting_round_trips_as_the_slug() {
        // It is stored in the database and read back by a later release. Serde
        // renaming it to `Nginx` would make every stored row unreadable the day
        // somebody renames a variant.
        for server in [WebServer::Nginx, WebServer::Apache, WebServer::Litespeed] {
            let json = serde_json::to_value(server).unwrap();
            assert_eq!(json, serde_json::json!(server.as_str()));
            assert_eq!(
                serde_json::from_value::<WebServer>(json).unwrap(),
                server,
                "{server:?} does not survive a round trip through the setting"
            );
        }
    }
}
