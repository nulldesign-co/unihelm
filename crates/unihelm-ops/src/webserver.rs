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
    /// The site this is about.
    pub domain: String,
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
                domain: site.domain.clone(),
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
                domain: site.domain.clone(),
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
                domain: site.domain.clone(),
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

        refuse_when_the_target_is_not_installed(ctx, target).await?;
        if target == WebServer::Apache {
            ensure_apache_modules(ctx).await?;
        }

        let db = ctx.db();
        // Every site on the machine, not a tenant's page of them: a switch that
        // moved some is a machine with vhosts in two trees and one web server
        // reading only one of them.
        let sites = db.all_sites().await.map_err(UnihelmError::from)?;

        let dropped = gaps(target, &sites);
        if !dropped.is_empty() && !input.accept_gaps {
            return Err(UnihelmError::new(
                ErrorCode::Conflict,
                format!(
                    "{} of this machine's sites are configured for something {} cannot \
                     do:\n\n{}\n\nSwitch anyway to accept these, or change the sites \
                     first.",
                    dropped
                        .iter()
                        .map(|g| g.domain.as_str())
                        .collect::<std::collections::BTreeSet<_>>()
                        .len(),
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
        let svc = &ctx.distro().svc;
        let leaving = from.unit()?.unit_name(ctx.distro().info.family);
        let arriving = target.unit()?.unit_name(ctx.distro().info.family);

        svc.action(&leaving, unihelm_distro::svc::SvcAction::Stop)
            .await?;
        if let Err(e) = svc.enable(&arriving, true).await {
            // The target would not start. Put the incumbent back before
            // returning, because the alternative is a machine serving nothing.
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
        assert!(found.iter().all(|g| g.domain == "a.test"), "{found:?}");
        // And a site that uses none of them is not mentioned at all.
        assert!(!found.iter().any(|g| g.domain == "plain.test"), "{found:?}");
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
        use crate::registry::Services;
        use std::sync::Arc;
        use unihelm_core::{AuthContext, Role, TenantScope, UserId};

        let distro = unihelm_distro::Distro::mock();
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
