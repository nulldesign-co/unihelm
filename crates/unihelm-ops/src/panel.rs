//! The panel's own domain and certificate (spec §11.5).
//!
//! `unihelm-web` listens on loopback and never faces the internet directly;
//! nginx terminates TLS in front of it (`templates/nginx/panel.conf.j2`).
//! Until now that vhost was a manual exercise — point a domain at the server,
//! write the proxy config yourself, run certbot by hand. This module turns it
//! into one operation: `panel.tls.issue` records the domain, obtains a Let's
//! Encrypt certificate over HTTP-01, renders the panel vhost through the
//! config engine and reloads nginx. The renewal scheduler then keeps the
//! certificate alive through the same path (spec §10.2).

use std::path::Path;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_config::apply::ApplyRequest;
use unihelm_config::managed::ManagedFile;
use unihelm_config::paths;
use unihelm_core::config::UnihelmConfig;
use unihelm_core::{Domain, Email, ErrorCode, Permission, Result, UnihelmError};
use unihelm_db::CertKind;

use crate::acme::{self, Directory};
use crate::registry::{Execution, OpContext, TypedOperation};
use crate::services::{NginxValidator, UnitReloader};

/// `client_max_body_size` for the panel vhost. Chunked uploads in the file
/// manager need headroom (spec §11.7); the API itself is capped far lower
/// inside `unihelm-web`, so this is a ceiling, not an invitation.
const PANEL_MAX_BODY: &str = "64m";

/// An address nginx can dial, from an address the panel listens on.
///
/// They are not the same thing: since the default became all-interfaces, the
/// listen value is `0.0.0.0:8088`, and `proxy_pass http://0.0.0.0:8088` is
/// rejected by nginx — which fails `nginx -t`, so the reload takes down every
/// vhost on the box, not just the panel's. nginx and the panel share a machine,
/// so loopback is the honest upstream.
fn dialable(listen: &str) -> Option<String> {
    let addr: std::net::SocketAddr = listen.parse().ok()?;
    if !addr.ip().is_unspecified() {
        return Some(listen.to_string());
    }
    let loopback = if addr.is_ipv6() {
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    };
    Some(std::net::SocketAddr::new(loopback, addr.port()).to_string())
}

/// How nginx should reach the panel: where, and over which scheme.
///
/// Both come from one read of the same file, because they have to agree. The
/// panel terminates its own TLS by default, so proxying to `http://` is a 502 on
/// the panel's own vhost — and the listen address it serves on is not
/// necessarily one nginx can dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub address: String,
    pub scheme: &'static str,
}

pub fn panel_upstream() -> Upstream {
    upstream_from(Path::new(unihelm_core::config::paths::CONFIG))
}

fn upstream_from(path: &Path) -> Upstream {
    // Absent or unreadable, assume the defaults the panel itself would use.
    let default = UnihelmConfig::default();
    let fallback = Upstream {
        address: dialable(&default.panel.listen).unwrap_or_else(|| "127.0.0.1:8088".to_string()),
        scheme: scheme_for(default.panel.tls),
    };

    let Ok(text) = std::fs::read_to_string(path) else {
        return fallback;
    };
    match UnihelmConfig::from_toml(&text) {
        Ok(config) => match dialable(&config.panel.listen) {
            Some(address) => Upstream {
                address,
                scheme: scheme_for(config.panel.tls),
            },
            None => {
                tracing::warn!(
                    path = %path.display(),
                    "listen address does not parse; using the default upstream"
                );
                fallback
            }
        },
        Err(_) => {
            tracing::warn!(
                path = %path.display(),
                "config file unreadable; using the default upstream"
            );
            fallback
        }
    }
}

fn scheme_for(tls: unihelm_core::config::PanelTls) -> &'static str {
    match tls {
        unihelm_core::config::PanelTls::Off => "http",
        unihelm_core::config::PanelTls::SelfSigned => "https",
    }
}

pub fn vhost_context(domain: &Domain, upstream: &Upstream) -> serde_json::Value {
    let cert_dir = paths::cert_dir(domain.as_str());
    serde_json::json!({
        "panel_domain": domain.as_str(),
        "acme_webroot": paths::acme_webroot(),
        "cert_path": cert_dir.join("fullchain.pem"),
        "key_path": cert_dir.join("privkey.pem"),
        "max_body_size": PANEL_MAX_BODY,
        "upstream": upstream.address,
        "upstream_scheme": upstream.scheme,
    })
}

/// `panel.tls.issue` — give the panel a domain and a Let's Encrypt
/// certificate, and put its vhost live.
pub struct Issue;

#[derive(Debug, Deserialize)]
pub struct IssueInput {
    /// The domain the panel will be served on. It must already resolve to
    /// this server, or the CA cannot fetch the HTTP-01 challenge.
    pub domain: Domain,
    /// Contact address for expiry warnings from the CA.
    #[serde(default)]
    pub contact_email: Option<Email>,
    /// Use the staging directory. Its root is not publicly trusted — this is
    /// for proving the flow works, not for a panel anyone logs in to.
    #[serde(default)]
    pub staging: bool,
}

#[derive(Debug, Serialize)]
pub struct IssueOutput {
    pub certificate_id: i64,
    pub domain: Domain,
    pub issuer: String,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: time::OffsetDateTime,
    pub days_valid: i64,
}

#[async_trait]
impl TypedOperation for Issue {
    type Input = IssueInput;
    type Output = IssueOutput;

    const NAME: &'static str = "panel.tls.issue";
    // The panel's own vhost and certificate are server configuration, not any
    // tenant's resource — admin only.
    const PERMISSION: Permission = Permission::ServerManage;
    // Minutes, not milliseconds: the CA has to fetch the challenge over the
    // public internet, which waits on DNS the panel does not control.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: false,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db().clone();
        let domain = input.domain;
        let names = vec![domain.as_str().to_string()];

        // The domain is recorded before the attempt: it is what the status
        // endpoint reports and what the renewal scheduler reads, and a failed
        // first issuance should read as "panel.example.com — issuance failed",
        // not as "no domain configured".
        db.set_setting(unihelm_db::panel::DOMAIN_KEY, &domain)
            .await
            .map_err(UnihelmError::from)?;

        let directory = if input.staging {
            Directory::Staging
        } else {
            Directory::Production
        };
        let contact = input
            .contact_email
            .map(|e| e.as_str().to_string())
            .unwrap_or_else(|| format!("admin@{}", domain.as_str()));

        ctx.log(format!(
            "requesting a panel certificate for {} from {}",
            domain.as_str(),
            if input.staging {
                "the staging directory"
            } else {
                "Let's Encrypt"
            }
        ));

        // The row before the attempt, so a failure has somewhere to be
        // recorded (same pattern as `cert.issue`). `site_id` is NULL: the
        // panel is not a site, and this NULL is what the renewal scheduler
        // uses to route the row back through this operation.
        let cert_dir = paths::cert_dir(domain.as_str());
        let record = db
            .create_certificate(None, CertKind::Le, &names, &cert_dir.to_string_lossy())
            .await
            .map_err(UnihelmError::from)?;

        // The first issuance happens before the panel vhost exists, and that
        // is fine: the catch-all default server (00-catchall.conf) serves
        // `/.well-known/acme-challenge/` for every Host, so the challenge is
        // reachable the moment DNS points at this server.
        let issued = match obtain(ctx, &names, &contact, directory).await {
            Ok(issued) => issued,
            Err(e) => {
                let _ = db.certificate_failed(record.id, &e.detail).await;
                return Err(e);
            }
        };

        // Files first, then the row, then the vhost — nginx must never be
        // pointed at a certificate that is not on disk yet.
        acme::write_certificate(&cert_dir, &issued)?;
        ctx.log(format!("certificate written to {}", cert_dir.display()));

        db.certificate_issued(
            record.id,
            &issued.issuer,
            issued.not_before,
            issued.not_after,
        )
        .await
        .map_err(UnihelmError::from)?;

        // `certificate_issued` retires the rows this one replaces *by site
        // id*, and the panel's row has none — `site_id = NULL` matches nothing
        // in SQL. Left alone, every renewal would add one more active row for
        // the scheduler to renew separately for ever (the duplicate-order bug
        // from the live server, reintroduced through the panel path), so the
        // panel has its own supersede.
        db.supersede_panel_certificates(record.id)
            .await
            .map_err(UnihelmError::from)?;

        // The vhost, through the config engine: render → nginx -t → activate
        // → reload, with rollback on failure (spec §10.4). On a renewal the
        // engine correctly reports "nothing to do" — same paths, same
        // upstream — which is why the explicit reload below exists.
        ctx.config()
            .apply(ApplyRequest {
                file: ManagedFile::nginx(paths::nginx_panel()),
                template: "nginx/panel.conf",
                context: vhost_context(&domain, &panel_upstream()),
                service: "nginx",
                validator: &NginxValidator,
                reloader: &UnitReloader::nginx(ctx.distro()),
                post_check: None,
                force: false,
                task_id: ctx.task_id().map(|t| t.to_string()),
            })
            .await?;

        // nginx holds certificates in memory from the moment it loads them,
        // so replacing the files on disk changes nothing until it is told to
        // look again — and the unchanged vhost means the apply above skipped
        // its reload. Without this line every panel renewal would appear to
        // succeed while the expiring certificate stayed live, the failure
        // that only shows up ninety days later (the cert.rs lesson).
        {
            use unihelm_config::apply::Reloader;
            let reloader = UnitReloader::nginx(ctx.distro());
            reloader.reload().await.map_err(|e| {
                UnihelmError::new(
                    ErrorCode::ConfigRollback,
                    format!("the certificate is on disk but nginx would not reload: {e}"),
                )
            })?;
            ctx.log("nginx reloaded onto the new certificate");
        }

        let days_valid = (issued.not_after - unihelm_db::now()).whole_days();
        ctx.log(format!(
            "the panel is now served at https://{}",
            domain.as_str()
        ));

        Ok(IssueOutput {
            certificate_id: record.id,
            domain,
            issuer: issued.issuer,
            not_after: issued.not_after,
            days_valid,
        })
    }
}

/// Register or restore the ACME account, then run the order.
///
/// Mirrors `cert::obtain` line for line — same account, same shared webroot —
/// and stays a separate copy on purpose: the site path and the panel path will
/// diverge (DNS-01 for a panel behind a proxy, for one), and a shared helper
/// growing flags for both callers is how that kind of function rots.
async fn obtain(
    ctx: &OpContext,
    names: &[String],
    contact: &str,
    directory: Directory,
) -> Result<acme::Issued> {
    acme::install_crypto_provider();

    let db = ctx.db();
    let key = ctx.master_key();

    let stored = db
        .acme_account(directory.url())
        .await
        .map_err(UnihelmError::from)?;
    let opened = match &stored {
        Some(account) => Some(key.open_str(&account.credentials_sealed).map_err(|e| {
            UnihelmError::internal(format!(
                "the stored ACME credential could not be decrypted ({e}). \
                 If /etc/unihelm/secret.key was replaced, delete the acme_accounts row \
                 and the panel will register again."
            ))
        })?),
        None => None,
    };

    let (account, fresh) =
        acme::load_or_register(opened.as_deref(), directory, Some(contact)).await?;

    if let Some(credential) = fresh {
        let sealed = key.seal_str(&credential).map_err(UnihelmError::from)?;
        db.save_acme_account(directory.url(), contact, &sealed)
            .await
            .map_err(UnihelmError::from)?;
        ctx.log("registered a new ACME account");
    }

    // The webroot the catch-all and every site vhost serve
    // `/.well-known/acme-challenge/` from.
    let webroot = paths::acme_webroot();
    std::fs::create_dir_all(&webroot).map_err(|e| {
        UnihelmError::internal(format!("could not create {}: {e}", webroot.display()))
    })?;

    let log = |line: &str| ctx.log(line);
    acme::issue_http01(&account, &webroot, names, &log).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_panel(domain: &str, upstream: &str) -> String {
        render_panel_with(domain, upstream, "http")
    }

    fn render_panel_with(domain: &str, address: &str, scheme: &'static str) -> String {
        let set = unihelm_config::TemplateSet::load().unwrap();
        set.render(
            "nginx/panel.conf",
            &vhost_context(
                &Domain::parse(domain).unwrap(),
                &Upstream {
                    address: address.to_string(),
                    scheme,
                },
            ),
        )
        .unwrap()
    }

    /// The rendered file with comment lines stripped, so assertions about
    /// what nginx will *do* are not satisfied — or broken — by prose.
    fn directives_only(rendered: &str) -> String {
        rendered
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_panel_vhost_proxies_to_the_web_listen_address() {
        // The template is strict-undefined, so this render succeeding is
        // itself the test that `vhost_context` supplies every key the
        // template uses — a renamed key fails here, not on a live server.
        let out = render_panel("panel.example.com", "127.0.0.1:8088");
        assert!(out.contains("server_name panel.example.com;"), "{out}");
        assert!(out.contains("proxy_pass http://127.0.0.1:8088;"), "{out}");
        assert!(
            out.contains("/var/lib/unihelm/state/certs/panel.example.com/fullchain.pem"),
            "certificate path must follow the shared cert store layout:\n{out}"
        );
        assert!(
            out.contains("/var/lib/unihelm/state/certs/panel.example.com/privkey.pem"),
            "{out}"
        );
        assert!(out.contains("client_max_body_size 64m;"), "{out}");
    }

    #[test]
    fn the_http_server_keeps_acme_reachable_and_redirects_everything_else() {
        // Renewals fetch the challenge over plain HTTP from this same vhost,
        // so the redirect must never swallow the challenge path.
        let out = directives_only(&render_panel("panel.example.com", "127.0.0.1:8088"));
        assert!(
            out.contains("location ^~ /.well-known/acme-challenge/"),
            "{out}"
        );
        assert!(out.contains("root /var/lib/unihelm/state/acme;"), "{out}");
        assert!(
            out.contains("return 301 https://$host$request_uri;"),
            "{out}"
        );
    }

    #[test]
    fn the_panel_vhost_never_claims_default_server_or_reuseport() {
        // Both may appear once per address in the whole configuration and the
        // catch-all owns them; the panel carrying either breaks every site on
        // the server.
        let out = directives_only(&render_panel("panel.example.com", "127.0.0.1:8088"));
        assert!(!out.contains("default_server"), "{out}");
        assert!(!out.contains("reuseport"), "{out}");
    }

    #[test]
    fn a_missing_config_file_falls_back_to_the_loopback_default() {
        // Dev instances build their config in memory and write nothing to
        // /etc. The fallback has to be an address nginx can dial, which the
        // panel's own default listen (all interfaces) is not.
        let up = upstream_from(Path::new("/nonexistent/unihelm/config.toml"));
        assert_eq!(up.address, "127.0.0.1:8088");
        assert_eq!(up.scheme, "https");
    }

    /// `proxy_pass http://0.0.0.0:8088` is rejected by nginx, and a rejected
    /// directive fails `nginx -t` — which blocks the reload for every vhost on
    /// the box, not just the panel's.
    #[test]
    fn an_all_interfaces_listen_is_dialled_over_loopback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        std::fs::write(&path, "[panel]\nlisten = \"0.0.0.0:8088\"\n").unwrap();
        assert_eq!(upstream_from(&path).address, "127.0.0.1:8088");

        std::fs::write(&path, "[panel]\nlisten = \"[::]:8088\"\n").unwrap();
        assert_eq!(upstream_from(&path).address, "[::1]:8088");
    }

    /// The panel terminates its own TLS unless told otherwise, so proxying to
    /// `http://` would answer every request on the panel's domain with a 502.
    #[test]
    fn the_scheme_follows_what_the_panel_is_actually_serving() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        std::fs::write(&path, "[panel]\nlisten = \"0.0.0.0:8088\"\n").unwrap();
        assert_eq!(upstream_from(&path).scheme, "https", "the default is TLS");

        std::fs::write(
            &path,
            "[panel]\nlisten = \"127.0.0.1:8088\"\ntls = \"off\"\n",
        )
        .unwrap();
        assert_eq!(upstream_from(&path).scheme, "http");

        let out = render_panel_with("panel.example.com", "127.0.0.1:8088", "https");
        assert!(out.contains("proxy_pass https://127.0.0.1:8088;"), "{out}");
    }

    #[test]
    fn the_upstream_comes_from_the_config_file_when_it_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        std::fs::write(&path, "[panel]\nlisten = \"127.0.0.1:9001\"\n").unwrap();
        assert_eq!(upstream_from(&path).address, "127.0.0.1:9001");

        // A listen value nginx would choke on must not reach `proxy_pass`:
        // a bad upstream fails `nginx -t` and blocks every config change.
        std::fs::write(&path, "[panel]\nlisten = \"not an address\"\n").unwrap();
        assert_eq!(upstream_from(&path).address, "127.0.0.1:8088");

        // Garbage falls back rather than failing the whole issuance.
        std::fs::write(&path, "listen = = =").unwrap();
        assert_eq!(upstream_from(&path).address, "127.0.0.1:8088");
    }

    #[tokio::test]
    async fn a_customer_cannot_issue_the_panel_certificate() {
        // The panel vhost proxies every tenant's traffic; issuing it is
        // server management, never a tenant action.
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, _admin, customer) = registry().await;
        let err = reg
            .dispatch(
                "panel.tls.issue",
                &auth_for(customer, Role::Customer),
                serde_json::json!({ "domain": "panel.example.com" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn a_hostile_domain_is_rejected_before_the_operation_body_runs() {
        // The input is a validated `Domain` newtype, so shell metacharacters,
        // path traversal and header tricks die in deserialisation — nothing
        // here ever becomes a certificate directory name or an nginx
        // `server_name`.
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, admin, _customer) = registry().await;
        for hostile in [
            "panel.example.com; rm -rf /",
            "../../../etc/nginx",
            "panel example.com",
            "",
        ] {
            let err = reg
                .dispatch(
                    "panel.tls.issue",
                    &auth_for(admin, Role::Admin),
                    serde_json::json!({ "domain": hostile }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "for input {hostile:?}");
        }
    }

    #[tokio::test]
    async fn a_hostile_contact_email_is_rejected_the_same_way() {
        use crate::registry::testing::{auth_for, registry};
        use unihelm_core::Role;

        let (reg, admin, _customer) = registry().await;
        let err = reg
            .dispatch(
                "panel.tls.issue",
                &auth_for(admin, Role::Admin),
                serde_json::json!({
                    "domain": "panel.example.com",
                    "contact_email": "a@b.com\r\nBcc: everyone@example.com",
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
}
