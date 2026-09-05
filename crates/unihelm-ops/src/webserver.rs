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
use unihelm_core::{ErrorCode, Result, UnihelmError};
use unihelm_distro::Distro;

use crate::registry::OpContext;
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
    pub fn site_vhost(self, domain: &str) -> Result<SiteVhost> {
        match self {
            Self::Nginx => Ok(SiteVhost {
                file: ManagedFile::nginx(paths::nginx_site(domain)),
                template: "nginx/site.conf",
                service: "nginx",
            }),
            Self::Apache => Ok(SiteVhost {
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

/// Everything one site's vhost needs, for whichever server is serving it.
#[derive(Debug)]
pub struct SiteVhost {
    pub file: ManagedFile,
    pub template: &'static str,
    /// Serialisation key — every file belonging to one service shares it, so
    /// two sites are never written and reloaded at the same time.
    pub service: &'static str,
}

impl SiteVhost {
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
