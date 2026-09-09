//! Which web server serves this machine's sites.
//!
//! The catalogue has offered nginx, Apache and OpenLiteSpeed since 0.2, and
//! only nginx has ever been able to serve a site: a vhost is a rendered
//! template, `site.rs` named `nginx/site.conf` in two places, and installing
//! either of the others got you a web server the panel could not write a vhost
//! for. `docs/design/web-servers.md` sets out the order this is fixed in; this
//! module is its first step and deliberately its dullest.
//!
//! That first step said "nothing here changes behaviour: [`active`] can only
//! answer `Nginx`, because nothing writes the setting it reads". It no longer
//! can — the switch writes the setting, and [`active`] probes the machine when
//! there is no row — and the sentence is kept here because forgetting it is how
//! the seam went wrong twice. What moved first was only where the answer comes
//! from: the two call sites in `site.rs` ask this module for the template, the
//! path, the validator and the reloader instead of naming nginx's literally.
//! Everything that answers *which* server is a later, riskier layer on top, and
//! two of its failures were release blockers — see [`active`] on what is worth
//! recording, and `Switch::run` on why "already serving" is not "already set
//! up".
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

    // An incumbent that is not installed is not an error.
    //
    // On a machine that never had nginx — Apache installed from the Stack page
    // on a fresh server — the incumbent this operation is nominally moving away
    // from does not exist, and `systemctl disable` on an unknown unit fails. It
    // used to fail here, which meant the one operation that could correct the
    // panel's idea of what serves the machine could not be run on the machine
    // that needed it most.
    let leaving_present = svc
        .status(&leaving)
        .await
        .map(|s| s.enabled.is_some() || s.is_active())
        .unwrap_or(false);
    if leaving_present {
        svc.disable(&leaving, true).await?;
    } else {
        ctx.log(format!(
            "{} is not installed on this machine, so there is nothing to stop",
            from.display_name()
        ));
    }
    if let Err(e) = svc.enable(&arriving, true).await {
        // The target would not start. Put the incumbent back — enabled as well
        // as running, which is what `enable(_, true)` does — because the
        // alternative is a machine serving nothing, now and after every reboot.
        ctx.log(format!(
            "{} did not start ({e}); restoring {}",
            target.display_name(),
            from.display_name()
        ));
        // Read back, not assumed. `enable --now` succeeding means systemd
        // accepted the request, not that the service is running — the lesson
        // `stack.rs` already learned — and this message used to state
        // unconditionally that the incumbent "is serving again" after throwing
        // the result away with `.ok()`. If nginx also fails to come back, the
        // machine is serving nothing and the panel was telling the operator it
        // was fine, in the one moment they most needed the truth.
        // Nothing was taken down if the incumbent was never there, so there is
        // nothing to put back and the machine is in the state it started in.
        let restored = !leaving_present
            || (svc.enable(&leaving, true).await.is_ok()
                && svc
                    .status(&leaving)
                    .await
                    .map(|s| s.is_active())
                    .unwrap_or(false));

        if restored {
            return Err(UnihelmError::new(
                ErrorCode::Internal,
                format!(
                    "{} would not start, so {} was put back and is serving again: {e}",
                    target.display_name(),
                    from.display_name(),
                ),
            ));
        }

        ctx.log(format!(
            "{} could not be started again either — this machine is not serving",
            from.display_name()
        ));
        return Err(UnihelmError::new(
            ErrorCode::Internal,
            format!(
                "{} would not start, and {} could not be started again either — \
                 **this machine is serving nothing right now**. Neither web server is \
                 running. `systemctl status {}` and `systemctl status {}` say why; the \
                 configuration for both is still on disk and nothing was deleted. \
                 The original failure was: {e}",
                target.display_name(),
                from.display_name(),
                arriving.as_str(),
                leaving.as_str(),
            ),
        ));
    }
    Ok(())
}

/// Which catalogued web server is actually running on this machine.
///
/// `None` when none of them is — a fresh server, or one whose web server is
/// stopped. The caller treats that as nginx, which is what the installer puts
/// there and what every machine this panel has ever provisioned runs.
///
/// Order is the catalogue's, and it decides ties. Two web servers cannot both
/// hold port 80, so a machine with two *active* units is one where somebody
/// started a second by hand and it failed to bind; the first is the one serving.
/// That case is logged rather than guessed at silently.
async fn probe_active(ctx: &OpContext) -> Option<WebServer> {
    let svc = &ctx.distro().svc;
    let mut running = Vec::new();
    for server in [WebServer::Nginx, WebServer::Apache, WebServer::Litespeed] {
        let Ok(unit) = server.unit() else { continue };
        // A unit systemd has never heard of answers successfully with
        // `not-found`, so this asks whether it is *active*, not whether the
        // call succeeded — the distinction that made the first version of
        // `refuse_when_the_target_is_not_installed` wrong.
        if svc
            .status(&unit.unit_name(ctx.distro().info.family))
            .await
            .map(|s| s.is_active())
            .unwrap_or(false)
        {
            running.push(server);
        }
    }

    if running.len() > 1 {
        ctx.log(format!(
            "more than one web server is running ({}); treating {} as the one serving, \
             because they cannot both hold port 80",
            running
                .iter()
                .map(|s| s.display_name())
                .collect::<Vec<_>>()
                .join(", "),
            running[0].display_name()
        ));
    }
    running.first().copied()
}

/// Which web server this machine serves sites with.
///
/// Absent means nginx. Not a default anybody chose — it is the only one the
/// panel has ever been able to render a vhost for, so every existing server is
/// on it, and reading a missing row as "unknown" would break every one of them
/// at once.
///
/// **Only a measurement is written down.** The probe can answer "nothing is
/// running", which is not the same as "nginx runs here", and recording the
/// fallback as though it were an observation is how a single poll during a
/// reboot pinned a machine to the wrong web server for good.
pub async fn active(ctx: &OpContext) -> Result<WebServer> {
    match ctx.db().get_setting::<WebServer>(WEB_SERVER_SETTING).await {
        Ok(Some(server)) => Ok(server),
        // No row. Ask the machine instead of assuming.
        //
        // This used to answer nginx flatly, and the row is written in exactly
        // one place — the end of a successful switch. So a server where somebody
        // installed Apache from the Stack page and never switched (there was
        // nothing to switch *from*) had the panel convinced nginx was serving:
        // the Stack page drew a Serving badge on an nginx that was not installed,
        // offered to "switch to Apache" from the Apache already running, and
        // `site.create` wrote nginx vhosts into a directory httpd never reads and
        // reported success. On a machine that never had nginx the switch could
        // not even be used to correct it, because it begins by disabling the
        // incumbent — which was not there.
        Ok(None) => match probe_active(ctx).await {
            // A measurement. Cached, so the probe costs one systemctl call per
            // machine rather than one per vhost render. A failure to write is
            // not a failure to answer: the probe told us the truth, and
            // refusing to render a vhost because a cache write failed would be
            // worse than paying for the probe again.
            Some(found) => {
                if let Err(e) = ctx.db().set_setting(WEB_SERVER_SETTING, &found).await {
                    tracing::warn!(error = %e, "could not record the web server this machine runs");
                }
                Ok(found)
            }
            // Nothing was running, so nothing was measured — and **this branch
            // writes no row**. It used to: `probe_active().unwrap_or(Nginx)`
            // was written back whether it was an answer or a fallback, which
            // turned one poll taken while no web server happened to be up into
            // a permanent record. The row is durable and only a successful
            // switch ever rewrites it, so the probe never ran again. On the
            // machine this probe was added for — Apache installed from the
            // Stack page, nothing to switch from — the very first Stack page
            // load happens *before* Apache is installed, cached nginx, and the
            // panel then wrote nginx vhosts for an Apache box and reported
            // every site live. The reboot and package-upgrade windows are the
            // same defect reached by another road.
            //
            // Nginx is still the answer, for the reason in the doc comment
            // above: every machine this panel has provisioned runs it, and
            // reading "cannot tell" as an error would break all of them at
            // once. It is a guess, so it is not written down as a fact.
            None => Ok(WebServer::Nginx),
        },
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

/// `webserver.gaps` — what a switch to `target` would cost, without doing it.
///
/// Immediate, and that is the whole point of it existing. `webserver.switch` is
/// a task: it re-renders every vhost on the machine, so the HTTP call returns
/// 202 and a task id long before the operation has looked at a single site. The
/// refusal that lists what would be lost therefore arrives — if at all — in a
/// task log nobody is watching, and the panel had no way to show an operator
/// the cost before they agreed to it. Worse, the confirm-then-accept flow the
/// page implements could never complete: the first click always succeeded with
/// a 202, which cleared the pending state, so `accept_gaps` was unsendable.
///
/// So the question is asked separately from the doing. This answers it in one
/// round trip, changes nothing, and needs only `ServerRead` — reading what a
/// switch would cost is not the same authority as making one.
pub struct Gaps;

#[derive(Debug, Deserialize)]
pub struct GapsInput {
    /// Absent means the server that is serving right now.
    ///
    /// That is the *after* the switch question, and it is the same question:
    /// asked of the active server, this answers "which controls does this
    /// machine show as set and not actually apply". Computed rather than
    /// recorded, so it cannot go stale — a site whose rate limit is turned off
    /// after a switch stops being listed the moment it is, without anything
    /// having to remember to update a stored list.
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GapsOutput {
    pub target: String,
    /// Sites that would lose a control, and features the machine would lose.
    pub gaps: Vec<Gap>,
    /// How many distinct sites are affected.
    pub sites: usize,
}

#[async_trait::async_trait]
impl TypedOperation for Gaps {
    type Input = GapsInput;
    type Output = GapsOutput;

    const NAME: &'static str = "webserver.gaps";
    const PERMISSION: Permission = Permission::ServerRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let target = match &input.target {
            Some(slug) => WebServer::from_slug(slug).ok_or_else(|| {
                UnihelmError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "`{slug}` is not a web server this panel knows. It serves with: \
                         nginx, apache."
                    ),
                )
                .with_field("target")
            })?,
            None => active(ctx).await?,
        };

        let sites = ctx.db().all_sites().await.map_err(UnihelmError::from)?;
        let mut gaps_found = gaps(target, &sites);
        gaps_found.extend(server_gaps(ctx, target).await?);

        let affected = gaps_found
            .iter()
            .filter_map(|g| g.domain.as_deref())
            .collect::<std::collections::BTreeSet<_>>()
            .len();

        Ok(GapsOutput {
            target: target.as_str().into(),
            gaps: gaps_found,
            sites: affected,
        })
    }
}

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
        // Already serving is **not** the same as already set up, and reading it
        // as "nothing to do" was this release's version of the 0.7 defect.
        //
        // The include that makes the target read the panel's tree is written in
        // exactly one place: `write_hook`, from this operation. So a machine
        // where Apache was installed by hand and never switched — the machine
        // the probe in [`active`] was added for — has Apache serving, the panel
        // correctly reporting Apache, vhosts rendered into
        // `/etc/apache2/unihelm.d`, and *nothing including that directory*.
        // `apachectl configtest` passes over a configuration that does not
        // contain the file, the reload succeeds, and every site shows Active
        // while Apache answers with the distribution's default page. The one
        // operation that could repair it returned success without writing a
        // byte, so the machine had no way out through the panel at all.
        //
        // It stays a cheap success where the footprint is already on disk,
        // which is every ordinary machine. Where it is not, the switch does the
        // work it would have done coming from the other server — minus the
        // exchange, because there is nothing to hand port 80 over to.
        let already_serving = from == target;
        if already_serving && the_panel_has_a_footprint_in(target)? {
            ctx.log(format!(
                "{} already serves this machine and the panel's include is in its \
                 configuration; nothing to do",
                target.display_name()
            ));
            return Ok(SwitchOutput {
                from: from.as_str().into(),
                to: target.as_str().into(),
                sites: 0,
                dropped: Vec::new(),
            });
        }

        // Both refusals now guard the converge as well, and the first of them
        // is why that matters on Red Hat: `active()` answers Apache there as
        // readily as on Debian (httpd.service is the same `ManagedUnit`), and
        // every `paths::apache_*` in this build is Debian's layout. Reached
        // through the old early return, an EL machine serving with httpd got
        // "nothing to do" and the panel went on writing /etc/apache2 files that
        // httpd has never heard of.
        refuse_where_the_panel_writes_where_the_server_does_not_read(ctx, target)?;
        refuse_when_the_target_is_not_installed(ctx, target).await?;

        if already_serving {
            ctx.log(format!(
                "{} serves this machine and the panel's include is not in its \
                 configuration, so nothing the panel has written is being read; \
                 writing it and re-rendering every vhost",
                target.display_name()
            ));
        }

        let db = ctx.db();
        // Every site on the machine, not a tenant's page of them: a switch that
        // moved some is a machine with vhosts in two trees and one web server
        // reading only one of them.
        let sites = db.all_sites().await.map_err(UnihelmError::from)?;

        let mut dropped = gaps(target, &sites);
        dropped.extend(server_gaps(ctx, target).await?);
        // Reported either way, refused only when this is a move. A converge is
        // not costing the operator these controls — the machine is already on
        // this server, so they are already not being applied — and refusing
        // would leave the one repair path closed behind a question about a
        // choice nobody is making. They still come back in `dropped`, which is
        // what the page lists, and `webserver.gaps` answers the same question
        // on demand.
        if !dropped.is_empty() && !input.accept_gaps && !already_serving {
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
        //
        // These two come *after* the gaps refusal on purpose. Run before it, a
        // switch the operator then declined had already enabled Apache modules
        // and — the part that matters — added `www-data` to the group that
        // traverses every tenant's site directory. A refusal has to leave the
        // machine as it found it, and a standing privilege grant made on the
        // way to being told no is not that.
        if target == WebServer::Apache {
            ensure_apache_modules(ctx).await?;
            admit_to_the_web_group(ctx, target).await?;
        }

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

        // 3. The panel's own vhost, when a domain has been attached to it.
        //
        //    Left out, a switch made the panel unreachable at its own address —
        //    the one an operator would use to look at what had just gone wrong.
        //    It is written with the sites rather than after the exchange for the
        //    same reason they are: the incumbent is still serving, so a failure
        //    here costs nothing.
        if let Some(panel_domain) = db
            .get_setting::<unihelm_core::Domain>(unihelm_db::panel::DOMAIN_KEY)
            .await
            .map_err(UnihelmError::from)?
        {
            crate::panel::render_vhost_for(ctx, &panel_domain, target).await?;
            ctx.log(format!(
                "the panel's own vhost at {panel_domain} rewritten for {}",
                target.display_name()
            ));
        }

        // 4. The default vhost, which answers for every name no site claims.
        //    Last of the three, because on Apache the *first* vhost parsed owns
        //    an address and this one has to be able to lose that race to
        //    nothing: writing it before the sites would make an unconfigured
        //    hostname land on whichever site happened to be written first for
        //    the length of the switch.
        crate::stack::write_catchall_for(ctx, target).await?;

        // 5. The target's own check, over the whole tree. The apply calls above
        //    each ran it too, but only over what existed at the time — this is
        //    the first moment the complete configuration exists.
        if let Err(detail) = target.validator()?.validate().await {
            return Err(UnihelmError::new(
                ErrorCode::ConfigValidationFailed,
                format!(
                    "{} rejected the configuration this panel wrote for it. **{} is still \
                     serving and nothing about it changed** — the exchange had not happened \
                     yet. The {} configuration is on disk under {} and is not being read by \
                     anything; fixing what is named below and running the switch again \
                     overwrites it. The error was:\n\n{detail}",
                    target.display_name(),
                    from.display_name(),
                    target.display_name(),
                    target
                        .site_vhost("example.com")?
                        .path()
                        .parent()
                        .map_or_else(
                            || "the target's own tree".to_string(),
                            |dir| dir.display().to_string()
                        ),
                ),
            ));
        }

        // 6. The exchange. This is the only unsafe moment, and it is as short as
        //    two systemctl calls: they both want port 80.
        //
        //    Skipped on a converge, and it has to be: `exchange` disables the
        //    incumbent before starting the target, and with the two the same
        //    unit that is `systemctl disable --now apache2` on the machine
        //    Apache is currently serving — this operation taking the site down
        //    it was called to repair. What is worth doing instead is the half
        //    that is not about port 80: `enable --now` on a unit that is
        //    already up is a no-op except for the *enabled* bit, and an Apache
        //    started by hand is exactly the one that is running and not enabled,
        //    so the machine comes back from its next reboot serving nothing.
        if already_serving {
            let unit = target.unit()?.unit_name(ctx.distro().info.family);
            ctx.distro().svc.enable(&unit, true).await?;
            ctx.log(format!(
                "{} left enabled, so it comes back after a reboot",
                target.display_name()
            ));
        } else {
            exchange(ctx, from, target).await?;
        }

        // 7. Only now is it true, so only now is it written. A setting recorded
        //    before the unit started would have the panel render into a tree
        //    nothing reads for as long as it took somebody to notice.
        //
        //    And if *this* fails, the machine has already switched. Returning
        //    the database error alone would leave an operator believing nothing
        //    happened, while every later vhost the panel renders goes into the
        //    tree the old server used to read — invisibly, until somebody
        //    notices a new site never came up. So the failure says which of the
        //    two things is true.
        if let Err(e) = db.set_setting(WEB_SERVER_SETTING, &target).await {
            return Err(UnihelmError::internal(format!(
                "{} is now serving this machine — the switch itself completed — but the \
                 panel could not record it ({e}). Until that row is written the panel \
                 will keep rendering vhosts for {}, into a directory nothing reads, so a \
                 site created now would not come up. Run the switch again once the \
                 database is writable; it is idempotent and will finish the last step.",
                target.display_name(),
                from.display_name(),
            )));
        }
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
    // The base the three proxy modules are built on. Debian's `a2enmod
    // proxy_fcgi` pulls it in, EL loads it from its own conf.d — but a machine
    // where somebody has been editing by hand may have neither, and without it
    // every `ProxyPass` and every `SetHandler proxy:` line is a startup error.
    ("proxy", "the base every proxy directive is built on"),
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
    // Everything below is enabled by default on both families, which is exactly
    // why it was left out — and why it is here now. The check exists for the
    // machine that is not in its default state, and on that machine a missing
    // `alias` is every ACME challenge 404ing with no error anywhere.
    ("alias", "the ACME challenge path and the maintenance page"),
    (
        "dir",
        "DirectoryIndex, and the front controller PHP sites need",
    ),
    ("authz_core", "every `Require` line, including the denials"),
    ("filter", "the output filters compression runs through"),
    ("mime", "content types on every response"),
    ("log_config", "the per-site access log"),
];

/// Modules a site is better with and still correct without.
///
/// Kept apart from [`APACHE_MODULES`] because the two need opposite treatment.
/// A missing required module makes the configuration wrong, so it refuses; a
/// missing one of these makes it *smaller*, and refusing a switch that would
/// have worked is its own kind of wrong. `Protocols h2 http/1.1` is valid
/// without mod_http2 — Apache simply never offers HTTP/2 — so this is said out
/// loud and the switch continues.
const APACHE_PREFERRED_MODULES: &[(&str, &str)] = &[(
    "http2",
    "HTTP/2. Without it every TLS site serves over HTTP/1.1, which works and is slower",
)];

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
pub(crate) async fn admit_to_the_web_group(ctx: &OpContext, target: WebServer) -> Result<()> {
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
///
/// A note on why, because the first version of this comment had it wrong and
/// the wrong version is the more frightening one. It claimed a missing module
/// is *silently* inert — configtest passing, pages loading, directives doing
/// nothing — and that without `mod_proxy_fcgi` a site would serve the source of
/// every `.php` file as plain text. That is not what happens. With `mod_proxy`
/// loaded and `mod_proxy_fcgi` absent, mod_proxy claims the request, finds no
/// provider for `fcgi` and returns 500; with `mod_proxy` also absent, the
/// `<Proxy>` block is an invalid command and configtest fails outright. Five of
/// the others behave the same way: `Header`, `ExpiresActive`, `RewriteEngine`
/// and `SSLEngine` are all unknown directives without their modules, and Apache
/// refuses to start.
///
/// So the real hazard is narrower and worth naming accurately: `mod_deflate`
/// and `mod_http2` *are* silent — `AddOutputFilterByType` without mod_filter
/// and mod_deflate simply compresses nothing, and `Protocols h2` without
/// mod_http2 simply never offers HTTP/2. Everything else fails loudly. The
/// check earns its place anyway, because "loudly" here means a switch that
/// stops halfway on a machine that was serving fine, and finding that out
/// before anything is written is the whole point.
pub(crate) async fn ensure_apache_modules(ctx: &OpContext) -> Result<()> {
    if ctx.distro().info.family != unihelm_distro::Family::Rhel {
        for (module, _) in APACHE_MODULES.iter().chain(APACHE_PREFERRED_MODULES) {
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

    // Said, not refused: see [`APACHE_PREFERRED_MODULES`].
    for (module, why) in APACHE_PREFERRED_MODULES {
        if !module_listed(&listed, module) {
            ctx.log(format!(
                "mod_{module} is not loaded, so this machine loses {why}"
            ));
        }
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
    APACHE_MODULES
        .iter()
        .filter(|(module, _)| !module_listed(listed, module))
        .collect()
}

/// Whether `apachectl -M` named this module.
///
/// It prints ` proxy_fcgi_module (shared)`, one per line, indented — so the
/// suffix has to come off before anything is compared. Statically linked
/// modules appear here too, which is why this is the answer that counts rather
/// than the presence of a `.load` file.
fn module_listed(listed: &str, module: &str) -> bool {
    listed
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|token| token.strip_suffix("_module"))
        .any(|name| name == module)
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

/// Whether this server's own configuration actually reaches the panel's files.
///
/// Two files and no memory of having written them, because the memory is the
/// thing that was wrong: the panel recorded a switch and the include it depends
/// on was written by that switch alone, so any other road to serving with a
/// server — installed by hand, installed from the Stack page, or a switch that
/// died between steps — arrived with the record set and the tree unreadable.
///
/// The hook is the include; without it the whole `unihelm.d` directory is a
/// directory nothing parses. The catch-all is what answers for a hostname no
/// site claims, and without it the first vhost parsed answers for every unknown
/// name — one customer's site serving another's domain.
fn the_panel_has_a_footprint_in(server: WebServer) -> Result<bool> {
    Ok(server.hook()?.path().exists() && server.catchall()?.path().exists())
}

/// The include the target reads the panel's tree through.
pub(crate) async fn write_hook(ctx: &OpContext, target: WebServer) -> Result<()> {
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
    async fn a_machine_with_no_setting_reads_as_nginx() {
        // Every server this panel has ever installed runs nginx, so a missing
        // row still reads as nginx rather than as an error.
        let ctx = op_ctx().await;
        assert_eq!(active(&ctx).await.unwrap(), WebServer::Nginx);
    }

    #[tokio::test]
    async fn switching_to_the_incumbent_on_a_machine_it_is_not_installed_on_says_so() {
        // This used to answer "nginx already serves this machine; nothing to
        // do" on a machine with no nginx at all — the panel stating as fact
        // something it had not checked, which is the failure this whole review
        // exists for. The mock has no nginx.service, which is the state of a
        // fresh server before anything is installed.
        //
        // It is not an error where it matters. A machine that actually serves
        // with nginx has nginx installed, so it passes this check and stops at
        // the footprint test above it.
        let ctx = op_ctx().await;
        let err = switch_to(&ctx, "nginx", false).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("not installed"), "{}", err.detail);
    }

    #[tokio::test]
    async fn a_probe_that_could_not_tell_is_not_written_down_as_a_fact() {
        // The defect: `probe_active().unwrap_or(Nginx)` was written to the
        // settings table whether it was a measurement or a fallback. The row is
        // durable and only a successful switch rewrites it, so one poll taken
        // while nothing was running — a reboot, a package upgrade, or simply
        // the first Stack page load on a machine where Apache had not been
        // installed yet — pinned the panel to nginx for good. On the machine
        // this probe was added for, that is nginx vhosts written for an Apache
        // box with every site reported live.
        let ctx = op_ctx().await;
        assert_eq!(active(&ctx).await.unwrap(), WebServer::Nginx);
        assert_eq!(
            ctx.db()
                .get_setting::<WebServer>(WEB_SERVER_SETTING)
                .await
                .unwrap(),
            None,
            "a fallback was recorded as though the machine had been measured"
        );

        // Apache comes up. The answer has to follow the machine, and it cannot
        // once a guess has been cached.
        let apache = WebServer::Apache
            .unit()
            .unwrap()
            .unit_name(ctx.distro().info.family);
        ctx.distro().svc.enable(&apache, true).await.unwrap();

        assert_eq!(active(&ctx).await.unwrap(), WebServer::Apache);
        assert_eq!(
            ctx.db()
                .get_setting::<WebServer>(WEB_SERVER_SETTING)
                .await
                .unwrap(),
            Some(WebServer::Apache),
            "a measurement is the one answer worth caching"
        );
    }

    #[test]
    fn a_machine_with_no_include_is_not_a_machine_with_nothing_to_do() {
        // The footprint is read off the disk, never off the setting. The record
        // of which server serves and the files that server reads are written by
        // different things, and every machine in the defect above has the first
        // without the second.
        for server in [WebServer::Nginx, WebServer::Apache] {
            // Neither file exists under a test's `/`, which is the same shape
            // as the machine this is about.
            assert!(
                !the_panel_has_a_footprint_in(server).unwrap(),
                "{} reported a footprint that is not on disk",
                server.display_name()
            );
        }
    }

    #[tokio::test]
    async fn apache_already_serving_is_never_reported_done_over_a_tree_it_does_not_read() {
        // The 0.7 defect wearing new clothes. Apache installed by hand and
        // never switched: `active()` now correctly answers Apache, `site.create`
        // renders `apache/site.conf` into /etc/apache2/unihelm.d, `apachectl
        // configtest` passes *because nothing includes that directory*, the
        // reload succeeds and the panel marks the site live. Apache serves the
        // distribution's default page for every domain on the machine.
        //
        // `webserver.switch --target apache` was the only operation that could
        // have written the include, and it returned success with `sites: 0`
        // without writing a byte. So the invariant here is the one that was
        // broken: this operation either leaves the include in place or says
        // why it could not. What it must never do again is report success over
        // an Apache that reads none of what the panel wrote.
        let ctx = op_ctx().await;
        let apache = WebServer::Apache
            .unit()
            .unwrap()
            .unit_name(ctx.distro().info.family);
        ctx.distro().svc.enable(&apache, true).await.unwrap();
        assert_eq!(active(&ctx).await.unwrap(), WebServer::Apache);
        assert!(!the_panel_has_a_footprint_in(WebServer::Apache).unwrap());

        match switch_to(&ctx, "apache", true).await {
            Ok(out) => assert!(
                the_panel_has_a_footprint_in(WebServer::Apache).unwrap(),
                "reported success ({out:?}) over an Apache that includes none of the \
                 configuration the panel writes"
            ),
            // The other honest answer, and the one a machine with no writable
            // /etc/apache2 gets: it tried, it could not finish, and it said so.
            // Anything that is not one of these two is the silent success this
            // test exists to keep from coming back.
            Err(e) => assert!(
                !e.detail.contains("nothing to do"),
                "still answering with a no-op: {}",
                e.detail
            ),
        }
    }

    #[tokio::test]
    async fn apache_serving_a_red_hat_machine_is_refused_rather_than_called_done() {
        // `ManagedUnit::Apache` is httpd.service on EL, so the probe answers
        // Apache there as readily as on Debian — while every `paths::apache_*`
        // in this build is /etc/apache2, which httpd has never heard of. The
        // layout refusal guarded the switch and the switch alone returned early
        // before reaching it, so this machine was told "nothing to do" and the
        // panel went on writing files nothing reads.
        let ctx = op_ctx_on(unihelm_distro::Family::Rhel).await;
        let httpd = WebServer::Apache
            .unit()
            .unwrap()
            .unit_name(ctx.distro().info.family);
        assert_eq!(httpd.as_str(), "httpd.service");
        ctx.distro().svc.enable(&httpd, true).await.unwrap();
        assert_eq!(active(&ctx).await.unwrap(), WebServer::Apache);

        let err = switch_to(&ctx, "apache", true).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotImplemented);
        assert!(err.detail.contains("/etc/httpd"), "{}", err.detail);
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
    fn a_preferred_module_is_not_treated_as_a_missing_required_one() {
        // `Protocols h2 http/1.1` is valid without mod_http2 — Apache simply
        // never offers HTTP/2. Refusing a switch over it would refuse one that
        // would have worked, so it is said out loud instead.
        let required: String = APACHE_MODULES
            .iter()
            .map(|(m, _)| format!(" {m}_module (shared)\n"))
            .collect();
        assert!(modules_missing_from(&required).is_empty(), "{required}");
        for (module, _) in APACHE_PREFERRED_MODULES {
            assert!(
                !module_listed(&required, module),
                "{module} is in the preferred list and in the required one"
            );
        }
    }

    #[test]
    fn a_module_name_is_matched_whole() {
        // `proxy` and `proxy_fcgi` are different modules, and a machine with
        // only the second must not read as having the first: every ProxyPass
        // line is a startup error without the base module.
        let only_fcgi = " proxy_fcgi_module (shared)\n";
        assert!(module_listed(only_fcgi, "proxy_fcgi"));
        assert!(!module_listed(only_fcgi, "proxy"));
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
