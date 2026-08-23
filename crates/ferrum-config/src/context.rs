//! The typed contexts the templates render from.
//!
//! Every field a template reads exists here as a real field, so a renamed
//! template variable is a compile error rather than a strict-undefined failure
//! at the moment somebody creates a site.

use std::path::{Path, PathBuf};

use ferrum_core::PhpVersion;
use serde::Serialize;

use crate::paths;

/// What kind of thing a site serves (spec §11.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteType {
    Php,
    Static,
    /// Reverse proxy to a local port — Node apps and docker apps both land here.
    Proxy,
    Redirect,
}

impl SiteType {
    pub const fn as_str(self) -> &'static str {
        match self {
            SiteType::Php => "php",
            SiteType::Static => "static",
            SiteType::Proxy => "proxy",
            SiteType::Redirect => "redirect",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "php" => SiteType::Php,
            "static" => SiteType::Static,
            "proxy" => SiteType::Proxy,
            "redirect" => SiteType::Redirect,
            _ => return None,
        })
    }

    pub const fn needs_php(self) -> bool {
        matches!(self, SiteType::Php)
    }
}

/// The response headers every site gets unless an admin changes them.
///
/// Chosen to be safe for a site the panel knows nothing about: no CSP, because
/// a wrong one breaks WordPress and a permissive one is theatre, and HSTS only
/// where TLS is actually on.
pub fn default_security_headers(tls_enabled: bool) -> Vec<String> {
    let mut headers = vec![
        "X-Content-Type-Options nosniff".to_string(),
        "X-Frame-Options SAMEORIGIN".to_string(),
        "Referrer-Policy strict-origin-when-cross-origin".to_string(),
    ];
    if tls_enabled {
        // Six months, no preload: preload is a one-way door and not ours to walk
        // through on a customer's domain.
        headers
            .push("Strict-Transport-Security \"max-age=15552000; includeSubDomains\"".to_string());
    }
    headers
}

/// Everything `nginx/site.conf` needs.
#[derive(Debug, Clone, Serialize)]
pub struct SiteContext {
    pub domain: String,
    pub site_type: &'static str,
    /// Primary domain plus aliases, space-separated for `server_name`.
    pub server_names: String,
    /// A safe identifier derived from the domain, for nginx zone names.
    pub zone_name: String,
    pub document_root: PathBuf,
    pub access_log: PathBuf,
    pub error_log: PathBuf,

    pub tls_enabled: bool,
    pub force_https: bool,
    pub http3: bool,
    pub ocsp_stapling: bool,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub chain_path: PathBuf,

    pub client_max_body_size: String,
    pub security_headers: Vec<String>,
    pub maintenance_mode: bool,

    pub rate_limit_enabled: bool,
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub conn_limit: u32,

    pub fpm_socket: PathBuf,
    pub php_timeout: u32,

    pub proxy_port: u16,
    pub proxy_timeout: u32,

    pub redirect_code: u16,
    pub redirect_target: String,

    /// Raw nginx, validated by `nginx -t` before activation.
    pub custom_snippet: Option<String>,
}

impl SiteContext {
    /// A PHP site with the panel's defaults.
    pub fn new(domain: &str, linux_user: &str, site_type: SiteType, php: PhpVersion) -> Self {
        let zone_name = zone_name_for(domain);
        Self {
            domain: domain.to_string(),
            site_type: site_type.as_str(),
            server_names: domain.to_string(),
            zone_name,
            document_root: paths::site_public(linux_user, domain),
            access_log: paths::site_log_dir(domain).join("access.log"),
            error_log: paths::site_log_dir(domain).join("error.log"),

            tls_enabled: false,
            force_https: true,
            // Off by default: QUIC needs UDP/443 open, and silently depending on
            // a firewall change nobody made is worse than plain HTTP/2.
            http3: false,
            ocsp_stapling: false,
            cert_path: paths::cert_dir(domain).join("fullchain.pem"),
            key_path: paths::cert_dir(domain).join("privkey.pem"),
            chain_path: paths::cert_dir(domain).join("chain.pem"),

            client_max_body_size: "64m".into(),
            security_headers: default_security_headers(false),
            maintenance_mode: false,

            rate_limit_enabled: false,
            rate_limit_rps: 20,
            rate_limit_burst: 40,
            conn_limit: 20,

            fpm_socket: paths::fpm_socket(&zone_name_for(domain), php),
            php_timeout: 60,

            proxy_port: 3000,
            proxy_timeout: 60,

            redirect_code: 301,
            redirect_target: String::new(),

            custom_snippet: None,
        }
    }

    /// Primary plus aliases.
    pub fn with_aliases(mut self, aliases: &[String]) -> Self {
        let mut names = vec![self.domain.clone()];
        names.extend(aliases.iter().cloned());
        self.server_names = names.join(" ");
        self
    }

    /// Turn TLS on and point at an issued certificate.
    pub fn with_tls(mut self, cert_dir: &Path, stapling: bool) -> Self {
        self.tls_enabled = true;
        self.cert_path = cert_dir.join("fullchain.pem");
        self.key_path = cert_dir.join("privkey.pem");
        self.chain_path = cert_dir.join("chain.pem");
        self.ocsp_stapling = stapling;
        self.security_headers = default_security_headers(true);
        self
    }
}

/// A domain reduced to something nginx will accept as an identifier.
///
/// `example.com` becomes `example_com`. Used for zone and cache names, where a
/// dot or a hyphen would be a syntax error.
pub fn zone_name_for(domain: &str) -> String {
    domain
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// One entry of a pool's environment.
#[derive(Debug, Clone, Serialize)]
pub struct EnvEntry {
    pub key: String,
    pub value: String,
}

/// Everything `php/pool.conf` needs.
#[derive(Debug, Clone, Serialize)]
pub struct PoolContext {
    pub name: String,
    pub site_domain: String,
    pub php_version: String,
    pub user: String,
    pub group: String,
    pub socket: PathBuf,
    pub socket_owner: String,
    pub socket_group: String,

    pub pm: &'static str,
    pub max_children: u32,
    pub start_servers: u32,
    pub min_spare_servers: u32,
    pub max_spare_servers: u32,
    pub idle_timeout: u32,
    pub max_requests: u32,

    pub log_dir: PathBuf,
    pub tmp_dir: PathBuf,
    pub session_dir: PathBuf,
    pub slowlog_timeout: u32,
    pub terminate_timeout: u32,

    pub open_basedir: String,
    pub disable_functions: String,
    pub allow_url_fopen: &'static str,

    pub memory_limit: String,
    pub max_execution_time: u32,
    pub max_input_time: u32,
    pub upload_max_filesize: String,
    pub post_max_size: String,
    pub max_input_vars: u32,
    pub timezone: String,

    pub opcache_memory_mb: u32,
    pub opcache_max_files: u32,
    pub opcache_validate_timestamps: u8,

    pub env: Vec<EnvEntry>,
    pub extra_ini: Option<String>,
}

/// Functions disabled by default.
///
/// Everything here is a way to execute a program or probe the host. Notably
/// absent: `exec` and `shell_exec` are included, but `putenv` and `getenv` are
/// not — Composer and several mainstream frameworks need them, and blocking
/// them produces support tickets rather than security.
pub const DEFAULT_DISABLE_FUNCTIONS: &str = "exec,passthru,shell_exec,system,proc_open,popen,\
     proc_nice,proc_terminate,proc_get_status,proc_close,pcntl_exec,pcntl_fork,\
     dl,chroot,symlink,link,posix_kill,posix_setuid,posix_setgid,posix_setpgid,\
     posix_mkfifo,show_source,highlight_file";

impl PoolContext {
    /// A pool sized for a given memory allowance.
    ///
    /// `memory_mb` is the tenant's budget, not the server's: a 512 MB customer
    /// on a 16 GB box should not be allowed 40 workers.
    pub fn new(
        domain: &str,
        linux_user: &str,
        php: PhpVersion,
        memory_mb: u32,
        nginx_user: &str,
    ) -> Self {
        let pool_name = zone_name_for(domain);
        let site_root = paths::site_root(linux_user, domain);

        // Each worker is assumed to peak near the per-request memory limit.
        // Dividing the budget by that is crude but honest, and far better than a
        // fixed number that OOMs a 1 GB VPS.
        let per_worker_mb = 128;
        let max_children = (memory_mb / per_worker_mb).clamp(2, 50);
        // Below a handful of workers there is nothing to keep warm, and idle
        // processes are exactly what a small box cannot spare.
        let pm = if max_children <= 4 {
            "ondemand"
        } else {
            "dynamic"
        };

        Self {
            name: pool_name.clone(),
            site_domain: domain.to_string(),
            php_version: php.as_str().to_string(),
            user: linux_user.to_string(),
            group: linux_user.to_string(),
            socket: paths::fpm_socket(&pool_name, php),
            // The socket is owned by the tenant but readable by nginx's group,
            // so only this site's nginx location can reach this pool.
            socket_owner: linux_user.to_string(),
            socket_group: nginx_user.to_string(),

            pm,
            max_children,
            start_servers: (max_children / 4).max(1),
            min_spare_servers: (max_children / 4).max(1),
            max_spare_servers: (max_children / 2).max(2),
            idle_timeout: 10,
            max_requests: 500,

            log_dir: paths::site_log_dir(domain),
            tmp_dir: site_root.join("tmp"),
            session_dir: site_root.join("tmp/sessions"),
            slowlog_timeout: 10,
            terminate_timeout: 120,

            open_basedir: format!(
                "{}:{}:/usr/share/php",
                site_root.display(),
                site_root.join("tmp").display()
            ),
            disable_functions: DEFAULT_DISABLE_FUNCTIONS.replace([' ', '\n'], ""),
            allow_url_fopen: "on",

            memory_limit: format!("{per_worker_mb}M"),
            max_execution_time: 60,
            max_input_time: 60,
            upload_max_filesize: "64M".into(),
            post_max_size: "64M".into(),
            max_input_vars: 3000,
            timezone: "UTC".into(),

            opcache_memory_mb: 96,
            opcache_max_files: 10_000,
            // Timestamp validation on: turning it off is faster but means a
            // deploy does not take effect until the pool is restarted, which is
            // a support ticket waiting to happen.
            opcache_validate_timestamps: 1,

            env: Vec::new(),
            extra_ini: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TemplateSet;

    fn render_site(ctx: &SiteContext) -> String {
        let set = TemplateSet::load().unwrap();
        set.render(
            "nginx/site.conf",
            &serde_json::json!({
                "site": ctx,
                "acme_webroot": paths::ACME_WEBROOT,
                "maintenance_root": "/var/lib/ferrum/state/maintenance",
            }),
        )
        .unwrap()
    }

    /// The rendered file with comment lines stripped.
    ///
    /// Assertions about what nginx will *do* must not be satisfied — or broken —
    /// by prose in a comment.
    fn directives_only(rendered: &str) -> String {
        rendered
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn php_site() -> SiteContext {
        SiteContext::new("example.com", "ft_abc123", SiteType::Php, PhpVersion::V83)
    }

    #[test]
    fn a_php_vhost_renders_with_the_path_info_guard() {
        let out = render_site(&php_site());
        // The line that stops /upload.png/x.php from becoming code execution.
        assert!(
            out.contains("try_files $uri =404;"),
            "missing the PATH_INFO guard:\n{out}"
        );
        assert!(out.contains("fastcgi_pass unix:/run/ferrum/fpm/example_com-php83.sock;"));
        assert!(out.contains("server_name example.com;"));
        assert!(out.contains("root /home/ft_abc123/sites/example.com/public;"));
    }

    #[test]
    fn a_site_vhost_never_claims_default_server_or_reuseport() {
        // Both may appear once per address in the whole configuration; a site
        // carrying either breaks every other site on the server.
        let mut ctx = php_site().with_tls(&paths::cert_dir("example.com"), true);
        ctx.http3 = true;
        let out = directives_only(&render_site(&ctx));
        assert!(
            !out.contains("default_server"),
            "a site must not be the default server:\n{out}"
        );
        assert!(
            !out.contains("reuseport"),
            "reuseport belongs only to the catch-all:\n{out}"
        );
        assert!(out.contains("listen 443 quic;"));
    }

    #[test]
    fn tls_off_serves_plain_http_and_does_not_reference_a_certificate() {
        let out = directives_only(&render_site(&php_site()));
        assert!(out.contains("listen 80;"));
        assert!(
            !out.contains("ssl_certificate"),
            "no certificate should be referenced:\n{out}"
        );
        assert!(!out.contains("return 301 https://"));
    }

    #[test]
    fn tls_on_redirects_http_and_keeps_acme_reachable() {
        let ctx = php_site().with_tls(&paths::cert_dir("example.com"), false);
        let out = render_site(&ctx);
        assert!(out.contains("return 301 https://$host$request_uri;"));
        assert!(out.contains(
            "ssl_certificate     /var/lib/ferrum/state/certs/example.com/fullchain.pem;"
        ));
        assert!(
            out.contains("Strict-Transport-Security"),
            "HSTS should appear once TLS is on"
        );
        // A renewal must work even while every other request is redirected.
        let redirect_block = out.split("return 301").next().unwrap();
        assert!(redirect_block.contains("/.well-known/acme-challenge/"));
    }

    #[test]
    fn tls_without_forced_https_still_answers_on_port_80() {
        let mut ctx = php_site().with_tls(&paths::cert_dir("example.com"), false);
        ctx.force_https = false;
        let out = render_site(&ctx);
        assert!(out.contains("listen 443 ssl;"));
        assert!(out.contains("listen 80;"));
        assert!(!out.contains("return 301 https://"));
    }

    #[test]
    fn ocsp_stapling_is_only_configured_when_asked_for() {
        let with = render_site(&php_site().with_tls(&paths::cert_dir("example.com"), true));
        assert!(with.contains("ssl_stapling on;"));
        assert!(with.contains("ssl_trusted_certificate"));

        let without = directives_only(&render_site(
            &php_site().with_tls(&paths::cert_dir("example.com"), false),
        ));
        assert!(!without.contains("ssl_stapling"));
    }

    #[test]
    fn aliases_all_appear_in_server_name() {
        let ctx = php_site().with_aliases(&["www.example.com".into(), "example.net".into()]);
        let out = render_site(&ctx);
        assert!(
            out.contains("server_name example.com www.example.com example.net;"),
            "{out}"
        );
    }

    #[test]
    fn a_static_site_has_no_php_handler_at_all() {
        let ctx = SiteContext::new(
            "static.example.com",
            "ft_abc",
            SiteType::Static,
            PhpVersion::V83,
        );
        let out = directives_only(&render_site(&ctx));
        assert!(
            !out.contains("fastcgi_pass"),
            "a static site must never reach PHP:\n{out}"
        );
        assert!(out.contains("try_files $uri $uri/ =404;"));
    }

    #[test]
    fn a_proxy_site_passes_websockets_through() {
        let mut ctx = SiteContext::new(
            "app.example.com",
            "ft_abc",
            SiteType::Proxy,
            PhpVersion::V83,
        );
        ctx.proxy_port = 4321;
        let out = directives_only(&render_site(&ctx));
        assert!(out.contains("proxy_pass http://127.0.0.1:4321;"));
        assert!(out.contains("proxy_set_header Upgrade $http_upgrade;"));
        assert!(out.contains("proxy_set_header Connection $connection_upgrade;"));
        assert!(!out.contains("fastcgi_pass"));
    }

    #[test]
    fn a_redirect_site_preserves_the_request_uri() {
        let mut ctx = SiteContext::new(
            "old.example.com",
            "ft_abc",
            SiteType::Redirect,
            PhpVersion::V83,
        );
        ctx.redirect_target = "https://new.example.com".into();
        let out = render_site(&ctx);
        assert!(
            out.contains("return 301 https://new.example.com$request_uri;"),
            "{out}"
        );
    }

    #[test]
    fn maintenance_mode_keeps_acme_working() {
        let mut ctx = php_site();
        ctx.maintenance_mode = true;
        let out = directives_only(&render_site(&ctx));
        assert!(out.contains("return 503;"));
        assert!(
            out.contains("/.well-known/acme-challenge/"),
            "a certificate must stay renewable during maintenance:\n{out}"
        );
        assert!(
            !out.contains("fastcgi_pass"),
            "maintenance mode must not reach PHP"
        );
    }

    #[test]
    fn dotfiles_are_denied_but_well_known_is_not() {
        let out = render_site(&php_site());
        assert!(out.contains("location ~ /\\.(?!well-known)"), "{out}");
        assert!(out.contains(".well-known/acme-challenge"));
    }

    #[test]
    fn a_custom_snippet_lands_inside_the_server_block() {
        let mut ctx = php_site();
        ctx.custom_snippet = Some("    location /custom { return 204; }".into());
        let out = render_site(&ctx);
        assert!(out.contains("location /custom { return 204; }"));
        // Inside the server block, not after it.
        let after_snippet = out.split("location /custom").nth(1).unwrap();
        assert!(after_snippet.trim_end().ends_with('}'));
    }

    #[test]
    fn zone_names_are_valid_nginx_identifiers() {
        assert_eq!(zone_name_for("example.com"), "example_com");
        assert_eq!(zone_name_for("my-site.co.uk"), "my_site_co_uk");
        assert_eq!(zone_name_for("xn--fsq.example.com"), "xn__fsq_example_com");
        for name in ["example.com", "a-b.c.d", "sub.domain.example"] {
            let zone = zone_name_for(name);
            assert!(
                zone.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{zone}"
            );
        }
    }

    #[test]
    fn pool_sizing_respects_a_small_server() {
        let tiny = PoolContext::new("a.com", "ft_a", PhpVersion::V83, 256, "nginx");
        assert_eq!(
            tiny.pm, "ondemand",
            "a 256 MB tenant cannot afford warm workers"
        );
        assert_eq!(tiny.max_children, 2);

        let big = PoolContext::new("b.com", "ft_b", PhpVersion::V83, 4096, "nginx");
        assert_eq!(big.pm, "dynamic");
        assert_eq!(big.max_children, 32);
        assert!(big.start_servers >= 1 && big.start_servers <= big.max_children);
        assert!(big.max_spare_servers >= big.min_spare_servers);
    }

    #[test]
    fn a_pool_renders_with_the_isolation_that_matters() {
        let set = TemplateSet::load().unwrap();
        let pool = PoolContext::new("example.com", "ft_abc123", PhpVersion::V83, 1024, "nginx");
        let rendered = set
            .render("php/pool.conf", &serde_json::json!({ "pool": pool }))
            .unwrap();
        // Pool files comment with `;`.
        let out: String = rendered
            .lines()
            .filter(|l| !l.trim_start().starts_with(';'))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(out.contains("user  = ft_abc123"));
        assert!(out.contains("listen.mode  = 0660"));
        assert!(out.contains("listen.group = nginx"));
        // open_basedir must be admin, or a script can widen it with ini_set().
        assert!(out.contains("php_admin_value[open_basedir] = /home/ft_abc123/sites/example.com"));
        assert!(out.contains("php_admin_flag[display_errors] = off"));
        assert!(out.contains("php_admin_value[disable_functions]"));
        assert!(out.contains("shell_exec"));
        // Things frameworks need must NOT be disabled.
        assert!(!out.contains("putenv"), "disabling putenv breaks Composer");
        assert!(!out.contains(",getenv"));
    }

    #[test]
    fn pool_execution_limits_are_bounded() {
        let set = TemplateSet::load().unwrap();
        let pool = PoolContext::new("example.com", "ft_a", PhpVersion::V84, 1024, "nginx");
        let out = set
            .render("php/pool.conf", &serde_json::json!({ "pool": pool }))
            .unwrap();
        assert!(
            out.contains("request_terminate_timeout = 120s"),
            "a runaway script must be killed"
        );
        assert!(
            out.contains("pm.max_requests = 500"),
            "workers must be recycled"
        );
    }

    #[test]
    fn the_catchall_owns_default_server_and_reuseport() {
        let set = TemplateSet::load().unwrap();
        let out = set
            .render(
                "nginx/catchall.conf",
                &serde_json::json!({
                    "acme_webroot": paths::ACME_WEBROOT,
                    "default_cert": "/var/lib/ferrum/state/certs/_default/cert.pem",
                    "default_key": "/var/lib/ferrum/state/certs/_default/key.pem",
                    "http3": true,
                }),
            )
            .unwrap();
        assert!(out.contains("listen 80 default_server;"));
        assert!(out.contains("reuseport"));
        assert!(
            out.contains("return 444;"),
            "an unconfigured host should get nothing"
        );
    }

    #[test]
    fn the_http_level_include_defines_connection_upgrade() {
        // Proxy sites reference $connection_upgrade; without this map nginx
        // refuses to start with "unknown variable".
        let set = TemplateSet::load().unwrap();
        let out = set
            .render(
                "nginx/ferrum.conf",
                &serde_json::json!({ "nginx_dir": paths::NGINX_DIR }),
            )
            .unwrap();
        assert!(out.contains("map $http_upgrade $connection_upgrade"));
        assert!(out.contains("include /etc/nginx/ferrum.d/*.conf;"));
    }
}
