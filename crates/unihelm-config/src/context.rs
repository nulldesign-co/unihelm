//! The typed contexts the templates render from.
//!
//! Every field a template reads exists here as a real field, so a renamed
//! template variable is a compile error rather than a strict-undefined failure
//! at the moment somebody creates a site.

use std::path::{Path, PathBuf};

use serde::Serialize;
use unihelm_core::PhpVersion;

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

/// One address a site answers on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Listener {
    pub port: u16,
    /// Whether this one terminates TLS. Never true for port 80.
    pub tls: bool,
}

/// Everything `nginx/site.conf` needs.
#[derive(Debug, Clone, Serialize)]
pub struct SiteContext {
    pub domain: String,
    pub site_type: &'static str,
    /// Primary domain plus aliases, space-separated for `server_name`.
    pub server_names: String,
    /// Every alias, without the primary domain.
    ///
    /// Kept beside `server_names` rather than derived from it, because the two
    /// web servers want opposite shapes: nginx takes one `server_name` line
    /// with everything on it, Apache takes `ServerName` for the primary and
    /// `ServerAlias` for the rest. Splitting the joined string back apart in a
    /// template is how a domain containing a space — which validation forbids,
    /// today — becomes two vhosts tomorrow.
    pub aliases: Vec<String>,
    /// A safe identifier derived from the domain, for nginx zone names.
    pub zone_name: String,
    pub document_root: PathBuf,
    pub access_log: PathBuf,
    pub error_log: PathBuf,

    pub tls_enabled: bool,
    pub force_https: bool,
    /// The ports the site's own content answers on, and whether each is TLS.
    ///
    /// Computed here because it is a real decision and not a formatting one.
    /// nginx takes several `listen` lines in one `server` block, so its template
    /// spells the cases out inline; Apache has one port per `<VirtualHost>` and
    /// cannot mix TLS and plain in the same block, so the same site needs two
    /// blocks with identical bodies. A template that worked the pair out from
    /// `tls_enabled` alone got this wrong: with TLS on and `force_https` off it
    /// rendered only `*:443`, and a site that was meant to keep answering plain
    /// HTTP stopped listening on port 80 altogether.
    pub listeners: Vec<Listener>,
    pub http3: bool,
    pub ocsp_stapling: bool,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub chain_path: PathBuf,

    pub client_max_body_size: String,
    /// The same limit in bytes.
    ///
    /// nginx parses `64m` itself; Apache's `LimitRequestBody` takes a number of
    /// bytes and nothing else. Parsed once here rather than in a template,
    /// because a template that got it wrong would silently serve a limit a
    /// thousand times too large or too small.
    pub max_body_bytes: u64,
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
            aliases: Vec::new(),
            zone_name,
            document_root: paths::site_public(linux_user, domain),
            access_log: paths::site_log_dir(domain).join("access.log"),
            error_log: paths::site_log_dir(domain).join("error.log"),

            tls_enabled: false,
            force_https: true,
            listeners: vec![Listener {
                port: 80,
                tls: false,
            }],
            // Off by default: QUIC needs UDP/443 open, and silently depending on
            // a firewall change nobody made is worse than plain HTTP/2.
            http3: false,
            ocsp_stapling: false,
            cert_path: paths::cert_dir(domain).join("fullchain.pem"),
            key_path: paths::cert_dir(domain).join("privkey.pem"),
            chain_path: paths::cert_dir(domain).join("chain.pem"),

            client_max_body_size: DEFAULT_BODY_SIZE.into(),
            max_body_bytes: parse_body_size(DEFAULT_BODY_SIZE),
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
        self.aliases = aliases.to_vec();
        self
    }

    /// Set the body limit from the panel's spelling of it, keeping the byte
    /// count in step.
    ///
    /// The two fields must never be set separately: nginx would enforce one and
    /// Apache the other, so a machine that switched web servers would change a
    /// limit nobody touched.
    pub fn with_body_size(mut self, size: &str) -> Self {
        self.max_body_bytes = parse_body_size(size);
        self.client_max_body_size = size.to_string();
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
        self.relisten()
    }

    /// Whether plain HTTP still serves the site, or only redirects to it.
    ///
    /// Its own setter because it changes what the site listens on, and setting
    /// the field without recomputing that is how a site ends up with no port 80.
    pub fn with_force_https(mut self, force: bool) -> Self {
        self.force_https = force;
        self.relisten()
    }

    /// Recompute [`SiteContext::listeners`] from the TLS fields.
    ///
    /// Three cases, and the middle one is the one that was wrong:
    ///
    /// - no TLS — plain 80, and nothing else.
    /// - TLS, redirecting — 443 only. Port 80 exists, but as the separate
    ///   redirect vhost the templates render above this one, not as the site.
    /// - TLS, not redirecting — **both**. The operator has said plain HTTP
    ///   should still serve the site rather than bounce to https.
    fn relisten(mut self) -> Self {
        self.listeners = if !self.tls_enabled {
            vec![Listener {
                port: 80,
                tls: false,
            }]
        } else if self.force_https {
            vec![Listener {
                port: 443,
                tls: true,
            }]
        } else {
            vec![
                Listener {
                    port: 443,
                    tls: true,
                },
                Listener {
                    port: 80,
                    tls: false,
                },
            ]
        };
        self
    }
}

/// A domain reduced to something nginx will accept as an identifier.
///
/// The panel's default body limit, in nginx's spelling.
pub const DEFAULT_BODY_SIZE: &str = "64m";

/// `64m` into bytes, the way nginx reads it.
///
/// nginx accepts a bare number of bytes, or one suffixed `k`, `m` or `g`, in
/// either case. Apache's `LimitRequestBody` takes bytes and nothing else, so a
/// number has to be produced here for the same limit to mean the same thing
/// under both.
///
/// An unparseable value falls back to the default rather than to zero or to
/// unlimited. Both of those are catastrophic in opposite directions — zero
/// refuses every upload on the site, unlimited lets one request fill the disk —
/// and the value has already been validated by the time it reaches here, so
/// this arm is reached only if that validation is ever loosened.
pub fn parse_body_size(size: &str) -> u64 {
    let trimmed = size.trim();
    let (digits, scale) = match trimmed.chars().last() {
        Some('k') | Some('K') => (&trimmed[..trimmed.len() - 1], 1024),
        Some('m') | Some('M') => (&trimmed[..trimmed.len() - 1], 1024 * 1024),
        Some('g') | Some('G') => (&trimmed[..trimmed.len() - 1], 1024 * 1024 * 1024),
        _ => (trimmed, 1),
    };
    match digits.trim().parse::<u64>() {
        Ok(n) => n.saturating_mul(scale),
        Err(_) => 64 * 1024 * 1024,
    }
}

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

    /// What PHP's `mail()` runs, or `None` for "leave PHP's own default".
    ///
    /// `None` renders no `sendmail_path` line at all rather than an empty one:
    /// an empty `sendmail_path` makes `mail()` execute nothing and return
    /// *true*, so an application would report every message as sent. Absent,
    /// PHP falls back to whatever the system has — usually nothing, which at
    /// least fails honestly (spec §11.18).
    pub sendmail_path: Option<String>,
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
            // Filled in by `unihelm_ops::mail` when a relay is configured. A
            // pool rendered without one is a pool whose sites cannot send
            // mail, which is the correct state for a panel with no relay.
            sendmail_path: None,
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
                "acme_webroot": paths::acme_webroot(),
                "maintenance_root": "/var/lib/unihelm/state/maintenance",
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
        SiteContext::new("example.com", "uh_abc123", SiteType::Php, PhpVersion::V83)
    }

    // -----------------------------------------------------------------------
    // The Apache template
    //
    // Read against `nginx/site.conf` rather than on its own. The failure this
    // guards against is not a template that does not render — it is one that
    // renders, passes `apachectl configtest`, serves every page correctly, and
    // has quietly dropped a protection the nginx one has. So each test below
    // names the nginx line it is the counterpart of.
    // -----------------------------------------------------------------------

    fn render_apache(ctx: &SiteContext) -> String {
        let set = TemplateSet::load().unwrap();
        set.render(
            "apache/site.conf",
            &serde_json::json!({
                "site": ctx,
                "acme_webroot": paths::acme_webroot(),
                "maintenance_root": "/var/lib/unihelm/state/maintenance",
            }),
        )
        .unwrap()
    }

    /// nginx: `try_files $uri =404;` inside `location ~ \.php$`.
    ///
    /// Without it a request for `/uploads/avatar.png/evil.php` reaches PHP with
    /// `PATH_INFO` set and an upload directory is remote code execution. Apache
    /// spells it `<If "! -f %{REQUEST_FILENAME}">`, and the handler must be
    /// inside the same block that carries the check.
    #[test]
    fn apache_never_hands_php_a_path_that_is_not_a_file() {
        let out = directives_only(&render_apache(&php_site()));
        assert!(out.contains("AcceptPathInfo Off"), "{out}");
        assert!(out.contains(r#"<If "! -f %{REQUEST_FILENAME}">"#), "{out}");
        assert!(out.contains("Require all denied"), "{out}");

        // Order is the whole point: the guard has to be inside the FilesMatch
        // that sets the handler, not somewhere else in the file.
        let files_match = out
            .find(r#"<FilesMatch "\.php$">"#)
            .expect("no php FilesMatch");
        let guard = out.find(r#"<If "! -f"#).expect("no guard");
        let handler = out.find("SetHandler").expect("no handler");
        assert!(
            files_match < guard && guard < handler,
            "the guard must sit between the FilesMatch and the SetHandler:\n{out}"
        );
    }

    /// nginx spells both file lists `location ~*`, and the `*` is the whole
    /// point of them.
    ///
    /// `<FilesMatch>` is case-sensitive. Without `(?i)` the deny list refused
    /// `backup.sql` and served `backup.SQL` in full — and the class of file it
    /// exists to hide is the hand-made dump, the copied `.env` and the editor
    /// backup, none of which is reliably lowercase. Confirmed against Apache
    /// 2.4.67 during review: `GET /backup.SQL` returned 200 and the dump.
    #[test]
    fn the_file_denials_are_case_insensitive_the_way_nginx_spells_them() {
        let out = directives_only(&render_apache(&php_site()));
        for block in ["sql|bak|old", "jpg|jpeg|png"] {
            let line = out
                .lines()
                .find(|l| l.contains(block) && l.contains("FilesMatch"))
                .unwrap_or_else(|| panic!("no FilesMatch for {block}:\n{out}"));
            assert!(
                line.contains("(?i)"),
                "case-sensitive where nginx is not — `.SQL` and `.ENV` walk past this: {line}"
            );
        }
        // And nginx really does spell it the case-insensitive way, so this is
        // parity and not an invention.
        let nginx = directives_only(&render_site(&php_site()));
        assert!(nginx.contains("location ~* \\.(?:sql|bak"), "{nginx}");
    }

    /// A `.htaccess` merges after the vhost's own sections and wins.
    ///
    /// `AllowOverride All` therefore let anything inside the document root
    /// re-grant every file the vhost denies — confirmed against Apache 2.4.67,
    /// where a four-line `.htaccess` turned the 403 on `/.env` into a 200 with
    /// its contents. nginx has no `.htaccess` mechanism, so its denials are
    /// unconditional and this was a difference a switch introduced in silence.
    #[test]
    fn a_htaccess_cannot_re_grant_what_the_vhost_denied() {
        for ctx in [php_site(), {
            let mut static_site = php_site();
            static_site.site_type = SiteType::Static.as_str();
            static_site
        }] {
            let out = directives_only(&render_apache(&ctx));
            assert!(
                !out.contains("AllowOverride All"),
                "a .htaccess can switch off every denial in this file:\n{out}"
            );
            assert!(out.contains("AllowOverride FileInfo"), "{out}");
            // FileInfo is what carries RewriteRule, so permalinks still work.
            // AuthConfig is what carries `Require`, and it must not be here.
            let line = out
                .lines()
                .find(|l| l.trim_start().starts_with("AllowOverride"))
                .expect("no AllowOverride");
            assert!(!line.contains("AuthConfig"), "{line}");
        }
    }

    /// A symlink in one tenant's document root must not serve another tenant's
    /// files.
    ///
    /// The web server account is in every tenant's group so it can traverse
    /// their site directories, so Apache's `+FollowSymLinks` made
    /// `ln -s /home/other_tenant/sites/x/public/.env .` a working URL — any
    /// customer who could write a file could read another tenant's, while the
    /// panel presented the two as isolated. nginx follows any symlink by
    /// default and had the same hole with nothing written down at all.
    ///
    /// `-FollowSymLinks` has to be explicit, which is why this asserts on the
    /// whole token and not merely on the absence of a `+`: `Options` merges with
    /// the enclosing block, Debian's stock `<Directory />` grants FollowSymLinks,
    /// and a directory that ends up with both follows the link unchecked.
    #[test]
    fn neither_template_follows_a_symlink_out_of_the_tenant_it_belongs_to() {
        for ctx in [php_site(), {
            let mut static_site = php_site();
            static_site.site_type = SiteType::Static.as_str();
            static_site
        }] {
            let apache = directives_only(&render_apache(&ctx));
            for line in apache.lines().map(str::trim) {
                assert!(
                    !line.starts_with("Options ")
                        || line
                            .split_whitespace()
                            .all(|t| t != "FollowSymLinks" && t != "+FollowSymLinks"),
                    "this directory follows a symlink whoever owns its target: {line}"
                );
            }
            assert!(
                apache.contains("Options -Indexes -FollowSymLinks +SymLinksIfOwnerMatch"),
                "the document root does not restrict symlinks to an owner match:\n{apache}"
            );

            // nginx had the same exposure by default and gets the same rule.
            // `from=$document_root` checks only below the root; the components
            // above it are the panel's own and are not a tenant's to plant.
            let nginx = directives_only(&render_site(&ctx));
            assert!(
                nginx.contains("disable_symlinks if_not_owner from=$document_root;"),
                "nginx follows a planted symlink into another tenant's files:\n{nginx}"
            );
        }
    }

    /// The companion to `a_htaccess_cannot_re_grant_what_the_vhost_denied`, for
    /// the other half of what an override hands back.
    ///
    /// The owner check above is worth nothing if a one-line `.htaccess` — which
    /// the customer, or a compromised plugin, can write — is allowed to say
    /// `Options +FollowSymLinks`. `Options=` names exactly which options a
    /// `.htaccess` may set, and FollowSymLinks was in that list.
    #[test]
    fn a_htaccess_can_only_be_given_the_owner_matched_symlink_option() {
        for ctx in [php_site(), {
            let mut static_site = php_site();
            static_site.site_type = SiteType::Static.as_str();
            static_site
        }] {
            let out = directives_only(&render_apache(&ctx));
            let line = out
                .lines()
                .map(str::trim)
                .find(|l| l.starts_with("AllowOverride"))
                .unwrap_or_else(|| panic!("no AllowOverride:\n{out}"));
            let overridable = line
                .split_whitespace()
                .find_map(|t| t.strip_prefix("Options="))
                .unwrap_or_else(|| panic!("no Options= list to check: {line}"));
            assert!(
                !overridable.split(',').any(|opt| opt == "FollowSymLinks"),
                "a one-line .htaccess turns unrestricted symlinks back on: {line}"
            );
            assert!(
                overridable
                    .split(',')
                    .any(|opt| opt == "SymLinksIfOwnerMatch"),
                "a .htaccess cannot even keep the owner-matched form: {line}"
            );
        }
    }

    /// nginx: `location ~ /\.(?!well-known)` and the dangerous-extension list.
    #[test]
    fn apache_denies_dotfiles_and_leftovers_the_way_nginx_does() {
        let out = directives_only(&render_apache(&php_site()));
        assert!(
            out.contains(r#"<DirectoryMatch "/\.(?!well-known)">"#),
            "{out}"
        );
        assert!(
            out.contains("sql|bak|old|orig|save|swp|log|env|ini|conf|sh|yml|yaml|lock"),
            "{out}"
        );
    }

    /// nginx: the ACME location, before the redirect and outside maintenance.
    ///
    /// A certificate has to stay renewable while the site is 301ing everything
    /// to https and while it is showing a maintenance page. Both vhosts carry
    /// it, which is why this counts rather than merely checking presence.
    #[test]
    fn acme_survives_the_redirect_and_maintenance_mode() {
        let mut ctx = php_site().with_tls(&paths::cert_dir("example.com"), true);
        ctx.force_https = true;
        ctx.maintenance_mode = true;
        let out = directives_only(&render_apache(&ctx));

        // Per vhost, not in total: a count over the whole file passes when both
        // aliases land in one vhost and the other has none, which is the exact
        // shape of the bug — a certificate that renews on http and not on https,
        // or the other way round.
        let vhosts: Vec<&str> = out.split("<VirtualHost").skip(1).collect();
        assert_eq!(
            vhosts.len(),
            2,
            "expected a redirect vhost and a real one:\n{out}"
        );
        for vhost in vhosts {
            assert!(
                vhost.contains("Alias /.well-known/acme-challenge/"),
                "a vhost with no ACME alias:\n{vhost}"
            );
            assert!(
                vhost.contains(r"RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/"),
                "a vhost whose rewrite swallows the ACME path:\n{vhost}"
            );
        }
    }

    /// A TLS site that does not force https must still answer on port 80.
    ///
    /// nginx says so with a second `listen 80` inside the same server block.
    /// Apache cannot mix a TLS port and a plain one in one `<VirtualHost>`, and
    /// the template used to derive its single port from `tls_enabled` alone —
    /// so this site rendered as `*:443` only and stopped answering plain HTTP
    /// altogether. The redirect vhost does not cover it either: that one is
    /// rendered only when `force_https` is on, which is exactly when this is
    /// off.
    #[test]
    fn a_tls_site_that_does_not_redirect_still_listens_on_port_eighty() {
        let ctx = php_site()
            .with_tls(&paths::cert_dir("example.com"), true)
            .with_force_https(false);

        let out = directives_only(&render_apache(&ctx));
        assert!(out.contains("<VirtualHost *:443>"), "{out}");
        assert!(
            out.contains("<VirtualHost *:80>"),
            "a TLS site that does not redirect has nothing on port 80:\n{out}"
        );
        // And the plain block must not claim TLS — SSLEngine on port 80 is a
        // configuration Apache refuses to start with.
        let plain = out
            .split("<VirtualHost *:80>")
            .nth(1)
            .and_then(|s| s.split("</VirtualHost>").next())
            .expect("no plain vhost body");
        assert!(!plain.contains("SSLEngine"), "{plain}");
        // The body is otherwise identical to the TLS one — same document root,
        // same PHP handler, same denials. A plain block that served less than
        // the TLS block would be a second, quieter site.
        assert!(plain.contains("SetHandler"), "{plain}");
        assert!(plain.contains("Require all denied"), "{plain}");

        // nginx renders the same site the same way, from the same context.
        let nginx = directives_only(&render_site(&ctx));
        assert!(nginx.contains("listen 443 ssl"), "{nginx}");
        assert!(nginx.contains("listen 80;"), "{nginx}");
    }

    /// The other two cases, so the fix cannot swing the other way.
    #[test]
    fn a_redirecting_site_serves_only_on_443_and_a_plain_site_only_on_80() {
        let redirecting = php_site()
            .with_tls(&paths::cert_dir("example.com"), true)
            .with_force_https(true);
        let out = directives_only(&render_apache(&redirecting));
        // Exactly two: the redirect vhost on 80, and the site on 443. A third
        // would mean the site itself is answering plain HTTP after somebody
        // asked for every request to be redirected.
        assert_eq!(out.matches("<VirtualHost").count(), 2, "{out}");
        assert_eq!(out.matches("<VirtualHost *:80>").count(), 1, "{out}");

        let plain = directives_only(&render_apache(&php_site()));
        assert_eq!(plain.matches("<VirtualHost").count(), 1, "{plain}");
        assert!(plain.contains("<VirtualHost *:80>"), "{plain}");
        assert!(!plain.contains("SSLEngine"), "{plain}");
    }

    /// nginx: `client_max_body_size 64m;`
    ///
    /// Apache takes bytes. The same limit has to mean the same thing, or a
    /// switch silently changes what a site accepts.
    #[test]
    fn the_body_limit_means_the_same_under_both() {
        let out = directives_only(&render_apache(&php_site().with_body_size("64m")));
        assert!(out.contains("LimitRequestBody 67108864"), "{out}");

        for (spelled, bytes) in [
            ("512k", 524_288u64),
            ("8m", 8_388_608),
            ("1g", 1_073_741_824),
            ("1048576", 1_048_576),
            ("2M", 2_097_152),
        ] {
            assert_eq!(parse_body_size(spelled), bytes, "{spelled}");
        }
        // Already validated upstream; the fallback is the default rather than
        // zero (refuses every upload) or unlimited (one request fills a disk).
        assert_eq!(parse_body_size("nonsense"), 64 * 1024 * 1024);
    }

    /// nginx: one `server_name` line. Apache: `ServerName` plus `ServerAlias`.
    #[test]
    fn aliases_become_server_alias_and_the_primary_stays_the_server_name() {
        let ctx = php_site().with_aliases(&["www.example.com".into(), "example.net".into()]);
        let out = directives_only(&render_apache(&ctx));
        assert!(out.contains("ServerName example.com"), "{out}");
        assert!(out.contains("ServerAlias www.example.com"), "{out}");
        assert!(out.contains("ServerAlias example.net"), "{out}");
        // And nginx still gets all three on one line, from the same context.
        assert!(
            render_site(&ctx).contains("server_name example.com www.example.com example.net;"),
            "the two servers disagree about the same site's names"
        );
    }

    /// nginx: the asset block only for sites served from disk.
    ///
    /// The same bug is available here and is worse, because `<FilesMatch>` has
    /// no prefix/regex precedence rule to blame it on — it would simply apply.
    #[test]
    fn apache_caches_assets_only_for_sites_served_from_disk() {
        let mut proxy = php_site();
        proxy.site_type = SiteType::Proxy.as_str();
        proxy.proxy_port = 3000;
        assert!(!directives_only(&render_apache(&proxy)).contains("ExpiresActive"));
        assert!(directives_only(&render_apache(&php_site())).contains("ExpiresActive"));
    }

    /// A snippet written for nginx must not be rendered into an Apache vhost.
    ///
    /// It would fail `apachectl configtest`, roll the whole change back, and
    /// leave the site unrenderable — so it is left out, and said so in the file.
    #[test]
    fn an_nginx_snippet_is_not_rendered_into_apache() {
        let mut ctx = php_site();
        ctx.custom_snippet = Some("add_header X-Test 1;".into());
        let out = render_apache(&ctx);
        assert!(!directives_only(&out).contains("add_header"), "{out}");
        assert!(out.contains("NOT APPLIED"), "{out}");
        // nginx still applies it, from the same context.
        assert!(directives_only(&render_site(&ctx)).contains("add_header X-Test 1;"));
    }

    /// A proxy site's websocket upgrade has to be matched before the catch-all,
    /// or the handshake is answered by the HTTP proxy and fails.
    #[test]
    fn websockets_are_matched_before_the_http_proxy() {
        let mut proxy = php_site();
        proxy.site_type = SiteType::Proxy.as_str();
        proxy.proxy_port = 3000;
        let out = directives_only(&render_apache(&proxy));
        let ws = out.find("ws://127.0.0.1:3000").expect("no websocket rule");
        let http = out
            .find("ProxyPass        / http://")
            .expect("no proxy pass");
        assert!(ws < http, "{out}");
    }

    /// A regex location outranks a prefix one, so the asset block must not exist
    /// on a site that has nothing on disk to serve.
    ///
    /// It did, unconditionally, and it beat `location /` for every css, js and
    /// image request — answering each with `try_files $uri =404` against a
    /// document root that holds none of them. Every application the panel put
    /// behind a proxy came up with no styles, no scripts and no images.
    #[test]
    fn the_asset_cache_block_is_only_for_sites_served_from_disk() {
        let has_asset_block = |t: SiteType| {
            render_site(&SiteContext::new("a.test", "u", t, PhpVersion::V83))
                .contains("expires 30d")
        };

        assert!(has_asset_block(SiteType::Php), "php serves from disk");
        assert!(has_asset_block(SiteType::Static), "static serves from disk");
        assert!(
            !has_asset_block(SiteType::Proxy),
            "a proxy site has no document root; this block 404s its whole front end"
        );
        assert!(
            !has_asset_block(SiteType::Redirect),
            "a redirect site serves nothing at all"
        );
    }

    /// Every `location` block in a rendered vhost, as (its opening line, its
    /// body).
    ///
    /// No location in this template contains a nested block, so a `}` alone on
    /// its own line closes the one that was opened.
    fn location_blocks(rendered: &str) -> Vec<(String, String)> {
        let mut blocks = Vec::new();
        let mut lines = rendered.lines();
        while let Some(line) = lines.next() {
            if !line.trim_start().starts_with("location ") {
                continue;
            }
            let mut body = String::new();
            for inner in lines.by_ref() {
                if inner.trim() == "}" {
                    break;
                }
                body.push_str(inner);
                body.push('\n');
            }
            blocks.push((line.trim().to_string(), body));
        }
        blocks
    }

    /// nginx's `add_header` list does not merge: a location carrying one header
    /// of its own inherits none from the server block.
    ///
    /// The asset location carries `Cache-Control`, so every css, js, image,
    /// font and video went out with no X-Content-Type-Options, no
    /// X-Frame-Options, no Referrer-Policy and no HSTS — most of the bytes on
    /// most sites. Nothing showed it: the HTML comes from a different location
    /// and still carried all four, so a spot check of the page passed.
    #[test]
    fn the_asset_location_repeats_the_security_headers_it_would_otherwise_lose() {
        let mut ctx = php_site().with_tls(&paths::cert_dir("example.com"), true);
        ctx.http3 = true;
        let rendered = render_site(&ctx);

        let (_, asset) = location_blocks(&rendered)
            .into_iter()
            .find(|(head, _)| head.contains("jpg|jpeg"))
            .unwrap_or_else(|| panic!("no static asset location:\n{rendered}"));
        let asset = directives_only(&asset);

        assert!(
            ctx.security_headers
                .iter()
                .any(|h| h.starts_with("Strict-Transport-Security")),
            "a TLS site is meant to carry HSTS, so this test would prove nothing without it"
        );
        for header in &ctx.security_headers {
            assert!(
                asset.contains(&format!("add_header {header} always;")),
                "assets are served with no `{header}`:\n{asset}"
            );
        }
        assert!(
            asset.contains(r#"add_header Alt-Svc 'h3=":443"; ma=86400' always;"#),
            "a client whose first request is an asset never learns HTTP/3 exists:\n{asset}"
        );
        // And the header this location was already setting is still set.
        assert!(
            asset.contains(r#"add_header Cache-Control "public, immutable";"#),
            "{asset}"
        );
    }

    /// The same trap, across every shape of site, so the next location to grow
    /// an `add_header` of its own cannot drop the security headers in silence.
    #[test]
    fn no_location_sets_a_header_of_its_own_and_loses_the_security_headers() {
        for site_type in [
            SiteType::Php,
            SiteType::Static,
            SiteType::Proxy,
            SiteType::Redirect,
        ] {
            for maintenance in [false, true] {
                let mut ctx = php_site().with_tls(&paths::cert_dir("example.com"), true);
                ctx.site_type = site_type.as_str();
                ctx.redirect_target = "https://new.example.com".into();
                ctx.maintenance_mode = maintenance;
                ctx.http3 = true;
                let rendered = render_site(&ctx);

                for (head, body) in location_blocks(&rendered) {
                    let body = directives_only(&body);
                    if !body.contains("add_header") {
                        continue;
                    }
                    for header in &ctx.security_headers {
                        assert!(
                            body.contains(&format!("add_header {header} always;")),
                            "`{head}` on a {} site sets a header of its own, so nginx hands it \
                             none of the server's — `{header}` is gone here:\n{body}",
                            site_type.as_str()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_php_vhost_renders_with_the_path_info_guard() {
        let out = render_site(&php_site());
        // The line that stops /upload.png/x.php from becoming code execution.
        assert!(
            out.contains("try_files $uri =404;"),
            "missing the PATH_INFO guard:\n{out}"
        );
        assert!(out.contains("fastcgi_pass unix:/run/unihelm/fpm/example_com-php83.sock;"));
        assert!(out.contains("server_name example.com;"));
        assert!(out.contains("root /home/uh_abc123/sites/example.com/public;"));
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
            "ssl_certificate     /var/lib/unihelm/state/certs/example.com/fullchain.pem;"
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
            "uh_abc",
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
            "uh_abc",
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
            "uh_abc",
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
        let tiny = PoolContext::new("a.com", "uh_a", PhpVersion::V83, 256, "nginx");
        assert_eq!(
            tiny.pm, "ondemand",
            "a 256 MB tenant cannot afford warm workers"
        );
        assert_eq!(tiny.max_children, 2);

        let big = PoolContext::new("b.com", "uh_b", PhpVersion::V83, 4096, "nginx");
        assert_eq!(big.pm, "dynamic");
        assert_eq!(big.max_children, 32);
        assert!(big.start_servers >= 1 && big.start_servers <= big.max_children);
        assert!(big.max_spare_servers >= big.min_spare_servers);
    }

    #[test]
    fn a_pool_renders_with_the_isolation_that_matters() {
        let set = TemplateSet::load().unwrap();
        let pool = PoolContext::new("example.com", "uh_abc123", PhpVersion::V83, 1024, "nginx");
        let rendered = set
            .render("php/pool.conf", &serde_json::json!({ "pool": pool }))
            .unwrap();
        // Pool files comment with `;`.
        let out: String = rendered
            .lines()
            .filter(|l| !l.trim_start().starts_with(';'))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(out.contains("user  = uh_abc123"));
        assert!(out.contains("listen.mode  = 0660"));
        assert!(out.contains("listen.group = nginx"));
        // open_basedir must be admin, or a script can widen it with ini_set().
        assert!(out.contains("php_admin_value[open_basedir] = /home/uh_abc123/sites/example.com"));
        assert!(out.contains("php_admin_flag[display_errors] = off"));
        assert!(out.contains("php_admin_value[disable_functions]"));
        assert!(out.contains("shell_exec"));
        // Things frameworks need must NOT be disabled.
        assert!(!out.contains("putenv"), "disabling putenv breaks Composer");
        assert!(!out.contains(",getenv"));
    }

    #[test]
    fn a_pool_without_a_relay_renders_no_sendmail_path_at_all() {
        // Not an empty one: PHP's mail() with an empty sendmail_path executes
        // nothing and returns true, so an application would report every
        // message as delivered (spec §11.18).
        let set = TemplateSet::load().unwrap();
        let pool = PoolContext::new("example.com", "uh_a", PhpVersion::V83, 1024, "nginx");
        let out = set
            .render("php/pool.conf", &serde_json::json!({ "pool": pool }))
            .unwrap();
        assert!(
            !out.lines()
                .any(|l| l.trim_start().starts_with("php_admin_value[sendmail_path]")),
            "an unconfigured relay must leave the directive out entirely"
        );
    }

    #[test]
    fn a_configured_relay_renders_sendmail_path_where_a_script_cannot_change_it() {
        let set = TemplateSet::load().unwrap();
        let mut pool = PoolContext::new("example.com", "uh_a", PhpVersion::V83, 1024, "nginx");
        pool.sendmail_path =
            Some("/usr/bin/msmtp --file=/etc/unihelm/mail/example.com.msmtprc -t".into());
        let out = set
            .render("php/pool.conf", &serde_json::json!({ "pool": pool }))
            .unwrap();
        assert!(out.contains(
            "php_admin_value[sendmail_path] = /usr/bin/msmtp \
             --file=/etc/unihelm/mail/example.com.msmtprc -t"
        ));
        // `php_value` would let a script ini_set() its way to running a
        // program of its own choosing as this tenant.
        assert!(!out.contains("php_value[sendmail_path]"));
    }

    #[test]
    fn the_relay_config_keeps_certificate_checking_on_and_never_logs_to_a_tenant_file() {
        let set = TemplateSet::load().unwrap();
        let out = set
            .render(
                "mail/msmtprc",
                &serde_json::json!({ "mail": {
                    "site_domain": "example.com",
                    "group": "uh_a",
                    "host": "smtp.example.net",
                    "port": 587,
                    "tls_mode": "starttls",
                    "tls_trust_file": "/etc/ssl/certs/ca-certificates.crt",
                    "username": "panel@example.com",
                    "password": "s3cret",
                    "from_address": "noreply@example.com",
                    "timeout_seconds": 20,
                }}),
            )
            .unwrap();
        assert!(out.contains("tls             on"));
        assert!(out.contains("tls_starttls    on"));
        assert!(
            out.contains("tls_certcheck   on"),
            "verification must stay on"
        );
        assert!(out.contains("auth            on"));
        assert!(out.contains("from            noreply@example.com"));
        // The tenant runs this; a log file they could write is a log file they
        // could forge or fill.
        assert!(out.contains("syslog          on"));
        assert!(!out.contains("logfile"));
    }

    #[test]
    fn a_plaintext_relay_renders_tls_off_and_no_credential() {
        let set = TemplateSet::load().unwrap();
        let out = set
            .render(
                "mail/msmtprc",
                &serde_json::json!({ "mail": {
                    "site_domain": "example.com",
                    "group": "uh_a",
                    "host": "127.0.0.1",
                    "port": 25,
                    "tls_mode": "none",
                    "tls_trust_file": "",
                    "username": serde_json::Value::Null,
                    "password": serde_json::Value::Null,
                    "from_address": "noreply@example.com",
                    "timeout_seconds": 20,
                }}),
            )
            .unwrap();
        assert!(out.contains("tls             off"));
        assert!(out.contains("auth            off"));
        assert!(
            !out.contains("password  "),
            "no credential may be rendered here"
        );
    }

    #[test]
    fn pool_execution_limits_are_bounded() {
        let set = TemplateSet::load().unwrap();
        let pool = PoolContext::new("example.com", "uh_a", PhpVersion::V84, 1024, "nginx");
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
                    "acme_webroot": paths::acme_webroot(),
                    "default_cert": "/var/lib/unihelm/state/certs/_default/cert.pem",
                    "default_key": "/var/lib/unihelm/state/certs/_default/key.pem",
                    "http3": true,
                    // On a server Unihelm set up, nothing else claims these.
                    "owns_default": true,
                    "catchall_names": "unihelm-catchall.invalid",
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

    /// The same file on a server that was already hosting sites.
    ///
    /// `default_server` and `reuseport` may each appear once per listening
    /// address in the whole configuration. Writing a second one is not an
    /// override, it is a configuration nginx refuses to load — so the panel
    /// would fail `nginx -t`, roll the stack install back, and decline to set
    /// itself up on a working server.
    #[test]
    fn the_catchall_yields_to_a_configuration_that_was_here_first() {
        let set = TemplateSet::load().unwrap();
        let out = set
            .render(
                "nginx/catchall.conf",
                &serde_json::json!({
                    "acme_webroot": paths::acme_webroot(),
                    "default_cert": "/var/lib/unihelm/state/certs/_default/cert.pem",
                    "default_key": "/var/lib/unihelm/state/certs/_default/key.pem",
                    "http3": true,
                    "owns_default": false,
                    "catchall_names": "unihelm-catchall.invalid",
                }),
            )
            .unwrap();

        let directives: String = out
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!directives.contains("default_server"), "{directives}");
        assert!(
            !directives.contains("reuseport"),
            "reuseport is once-per-address too: {directives}"
        );
        assert!(
            directives.contains("unihelm-catchall.invalid"),
            "the yielding block still needs a name of its own"
        );
        assert!(
            out.contains("/.well-known/acme-challenge/"),
            "ACME must work on an adopted server too, or no certificate can be issued"
        );
    }

    #[test]
    fn the_http_level_include_defines_connection_upgrade() {
        // Proxy sites reference $connection_upgrade; without this map nginx
        // refuses to start with "unknown variable".
        let set = TemplateSet::load().unwrap();
        let out = set
            .render(
                "nginx/unihelm.conf",
                &serde_json::json!({ "nginx_dir": paths::nginx_dir() }),
            )
            .unwrap();
        assert!(out.contains("map $http_upgrade $connection_upgrade"));
        assert!(out.contains("include /etc/nginx/unihelm.d/*.conf;"));
    }
}
