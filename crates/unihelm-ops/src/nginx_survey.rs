//! What nginx is already serving on this machine.
//!
//! Unihelm was written for a server it owns from the start, and on that server
//! its catchall vhost can declare `default_server` freely — it is the only
//! configuration there is. On a machine that already hosts sites the assumption
//! is simply wrong: `default_server` may appear once per listening address, so
//! writing it a second time makes `nginx -t` fail and the whole stack setup
//! roll back. The panel then refuses to install a stack on precisely the
//! servers people most want a panel for.
//!
//! Nothing here changes a file. It reads the configuration nginx would read and
//! reports what is there, so the rest of the code can fit around it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use unihelm_config::paths;

/// What an existing nginx configuration already declares.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NginxSurvey {
    /// Files, outside Unihelm's own, that already carry `default_server`.
    pub default_server_files: Vec<PathBuf>,
    /// Every `server_name` found, excluding the catchall's own `_`.
    pub server_names: BTreeSet<String>,
    /// Config files that are not ours.
    pub foreign_files: Vec<PathBuf>,
}

impl NginxSurvey {
    /// Whether somebody else has already claimed the default server.
    pub fn has_foreign_default_server(&self) -> bool {
        !self.default_server_files.is_empty()
    }
}

/// The directories nginx includes on a stock Debian or RHEL install.
fn search_roots() -> Vec<PathBuf> {
    let root = paths::root();
    vec![
        root.join("etc/nginx/conf.d"),
        root.join("etc/nginx/sites-enabled"),
    ]
}

/// True for a file Unihelm itself wrote, which must not count as foreign.
fn is_ours(path: &Path) -> bool {
    let ours = paths::nginx_dir();
    path.starts_with(&ours) || path == paths::nginx_hook()
}

/// Read what nginx is already configured to do.
///
/// Deliberately a text scan rather than a parser. The one question that has to
/// be answered exactly — "may I write `default_server`?" — is answered
/// conservatively: a commented-out directive does not count, and anything else
/// that looks like one does, because the cost of a false positive is a catchall
/// without `default_server` (which still works) and the cost of a false
/// negative is a failed `nginx -t` and a rolled-back stack install.
pub fn survey() -> NginxSurvey {
    survey_dirs(&search_roots())
}

/// The same scan over explicit directories, so it can be tested without
/// repointing the process-wide path root, which is write-once by design.
pub fn survey_dirs(roots: &[PathBuf]) -> NginxSurvey {
    let mut out = NginxSurvey::default();

    for root in roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if is_ours(&path) {
                continue;
            }
            // sites-enabled is symlinks into sites-available; resolve so the
            // same vhost is not reported twice under two names.
            let resolved = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            let Ok(text) = std::fs::read_to_string(&resolved) else {
                continue;
            };

            let mut has_default = false;
            for line in text.lines() {
                let line = line.trim();
                if line.starts_with('#') {
                    continue;
                }
                // Strip a trailing comment so `listen 80; # default_server` does
                // not read as a declaration.
                let code = line.split('#').next().unwrap_or("");
                if code.contains("default_server") {
                    has_default = true;
                }
                if let Some(rest) = code.strip_prefix("server_name") {
                    for name in rest.trim_end_matches(';').split_whitespace() {
                        if name != "_" && !name.is_empty() {
                            out.server_names.insert(name.to_string());
                        }
                    }
                }
            }

            out.foreign_files.push(path.clone());
            if has_default {
                out.default_server_files.push(path);
            }
        }
    }

    out.foreign_files.sort();
    out.default_server_files.sort();
    out
}

/// The first nginx release with the `http2 on;` directive.
///
/// Before 1.25.1 HTTP/2 was a listen parameter — `listen 443 ssl http2;` — and
/// `http2 on;` is not merely ignored there, it is a hard `unknown directive`
/// that fails `nginx -t`. Ubuntu 24.04, which this project supports and tests on
/// every release, ships 1.24.0, so every vhost the panel rendered was invalid on
/// a first-class target. CI never saw it because the smoke test installs the
/// panel and never asks it to create a site.
pub const HTTP2_ON_SINCE: (u32, u32, u32) = (1, 25, 1);

/// Parse `nginx/1.24.0 (Ubuntu)` into its version triple.
pub fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let rest = text.split("nginx/").nth(1)?;
    let v = rest.split_whitespace().next()?;
    let mut parts = v.split('.').map(|p| p.parse::<u32>().ok());
    Some((
        parts.next()??,
        parts.next()??,
        parts.next().flatten().unwrap_or(0),
    ))
}

/// Whether this nginx wants `http2 on;` or the older listen parameter.
pub fn supports_http2_on(version: Option<(u32, u32, u32)>) -> bool {
    // Unknown means new: the directive has been correct since 2023, and a
    // machine whose nginx we cannot interrogate is more likely current than
    // ancient. The failure is symmetric and `nginx -t` catches it either way.
    version.is_none_or(|v| v >= HTTP2_ON_SINCE)
}

/// Ask the installed nginx for its version.
///
/// `None` when nginx is not installed, which is the ordinary case on a fresh
/// server and not an error. Goes through the exec module like every other
/// command the panel runs — the no-shell gate enforces that, and it is right to:
/// one place owns process spawning, argument handling and timeouts.
pub async fn installed_version() -> Option<(u32, u32, u32)> {
    // nginx writes `-v` to stderr on success, so the failure text is read too.
    let out = unihelm_distro::Cmd::new("nginx")
        .arg("-v")
        .timeout(std::time::Duration::from_secs(5))
        .run()
        .await
        .ok()?;
    let text = if out.trimmed_stdout().is_empty() {
        out.failure_text()
    } else {
        out.trimmed_stdout().to_string()
    };
    parse_version(&text)
}

/// A site nginx is already serving that Unihelm did not create.
///
/// The panel used to show an empty server to an operator with a dozen live
/// vhosts, which is not a neutral omission: a control panel that cannot see what
/// the server is doing is one you cannot trust to change it. This is the reading
/// half — nothing here adopts, rewrites or takes ownership of anything.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredSite {
    /// The first name on the vhost, used as its identity.
    pub domain: String,
    /// Every name it answers for, including the first.
    pub server_names: Vec<String>,
    /// php, static, proxy or redirect, inferred from what the vhost does.
    pub kind: String,
    /// Document root, when it has one.
    pub root: Option<String>,
    /// Upstream for a proxy site.
    pub proxy_pass: Option<String>,
    /// FPM socket or address for a PHP site.
    pub fastcgi_pass: Option<String>,
    /// Whether it terminates TLS, and with which certificate.
    pub tls_certificate: Option<String>,
    /// The file it came from, so the operator can go and read it.
    pub config_file: String,
    /// Ports it listens on.
    pub listens: Vec<String>,
}

/// Read the vhosts nginx is serving that Unihelm did not write.
pub fn discover_sites() -> Vec<DiscoveredSite> {
    discover_sites_in(&search_roots())
}

/// The same, over explicit directories, for tests.
pub fn discover_sites_in(roots: &[PathBuf]) -> Vec<DiscoveredSite> {
    let mut out: Vec<DiscoveredSite> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for root in roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();

        for path in paths {
            if is_ours(&path) {
                continue;
            }
            let resolved = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            let Ok(text) = std::fs::read_to_string(&resolved) else {
                continue;
            };
            for site in parse_vhost(&text, &path) {
                // sites-enabled is symlinks into sites-available; the same vhost
                // reachable under two names is still one site.
                if seen.insert(site.domain.clone()) {
                    out.push(site);
                }
            }
        }
    }
    out
}

/// Pull the sites out of one config file.
///
/// Works on a flattened statement stream rather than on lines: nginx does not
/// care where the newlines are, and people write `server { listen 80;
/// server_name x; root /srv/x; }` all on one line. A line-oriented scan lost
/// every such vhost entirely — it saw the block open and skipped the rest of
/// the line, so the block never closed and the site was never reported.
///
/// Still a scan and not a parser: enough to tell an operator what is on their
/// server and what kind of thing it is, honest about the rest. Anything it
/// cannot classify is reported as `unknown` rather than guessed at.
fn parse_vhost(text: &str, path: &Path) -> Vec<DiscoveredSite> {
    // Strip comments first, so a `#` inside no string we care about survives to
    // confuse the split.
    let stripped: String = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");

    // Split into statements and braces, keeping the delimiters.
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ch in stripped.chars() {
        match ch {
            '{' | '}' | ';' => {
                let t = cur.trim();
                if !t.is_empty() {
                    tokens.push(t.to_string());
                }
                tokens.push(ch.to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        tokens.push(cur.trim().to_string());
    }

    let blank = |path: &Path| DiscoveredSite {
        domain: String::new(),
        server_names: Vec::new(),
        kind: "unknown".into(),
        root: None,
        proxy_pass: None,
        fastcgi_pass: None,
        tls_certificate: None,
        config_file: path.display().to_string(),
        listens: Vec::new(),
    };

    let mut sites = Vec::new();
    let mut depth = 0usize;
    let mut server_depth: Option<usize> = None;
    let mut site = blank(path);
    let mut has_return = false;
    let mut pending = String::new();

    for token in tokens {
        match token.as_str() {
            "{" => {
                if server_depth.is_none() && pending.trim() == "server" {
                    server_depth = Some(depth);
                    site = blank(path);
                    has_return = false;
                }
                depth += 1;
                pending.clear();
            }
            "}" => {
                depth = depth.saturating_sub(1);
                pending.clear();
                if server_depth == Some(depth) {
                    server_depth = None;
                    // A vhost with no name serves nothing anybody can ask for.
                    if let Some(first) = site.server_names.first().cloned() {
                        site.domain = first;
                        site.kind = classify(&site, has_return).into();
                        sites.push(site.clone());
                    }
                }
            }
            ";" => pending.clear(),
            _ => {
                pending = token.clone();
                if server_depth.is_none() {
                    continue;
                }
                let stmt = token.trim();
                let value = |d: &str| -> Option<String> {
                    let at = stmt.find(d)?;
                    let before_ok = at == 0
                        || !stmt[..at]
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_alphanumeric() || c == '_');
                    let rest = &stmt[at + d.len()..];
                    if !before_ok || !rest.chars().next().is_some_and(char::is_whitespace) {
                        return None;
                    }
                    Some(rest.trim().to_string()).filter(|v| !v.is_empty())
                };

                if let Some(v) = value("server_name") {
                    for name in v.split_whitespace() {
                        if name != "_" {
                            site.server_names.push(name.to_string());
                        }
                    }
                } else if let Some(v) = value("listen") {
                    site.listens.push(v);
                } else if let Some(v) = value("root") {
                    site.root = Some(v);
                } else if let Some(v) = value("proxy_pass") {
                    site.proxy_pass.get_or_insert(v);
                } else if let Some(v) = value("fastcgi_pass") {
                    site.fastcgi_pass.get_or_insert(v);
                } else if let Some(v) = value("ssl_certificate") {
                    site.tls_certificate.get_or_insert(v);
                } else if value("return").is_some() {
                    has_return = true;
                }
            }
        }
    }
    sites
}

/// What kind of site this is, in Unihelm's own vocabulary.
fn classify(site: &DiscoveredSite, has_return: bool) -> &'static str {
    if site.fastcgi_pass.is_some() {
        "php"
    } else if site.proxy_pass.is_some() {
        "proxy"
    } else if site.root.is_some() {
        "static"
    } else if has_return {
        // A bare `return 301 …` block, which is how a www-to-apex redirect and
        // an http-to-https hop are both written.
        "redirect"
    } else {
        "unknown"
    }
}

// ---------------------------------------------------------------------------
// the operation
// ---------------------------------------------------------------------------

use unihelm_core::{Permission, Result};

use crate::registry::{Execution, OpContext, TypedOperation};

#[derive(Debug, Default, serde::Deserialize)]
pub struct DiscoverInput {}

#[derive(Debug, serde::Serialize)]
pub struct DiscoverOutput {
    /// Sites nginx is serving that Unihelm did not create.
    pub sites: Vec<DiscoveredSiteDto>,
    /// Files, outside Unihelm's own, that already declare `default_server`.
    pub default_server_files: Vec<String>,
    /// Whether the panel's catchall will yield the default server here.
    pub yields_default_server: bool,
    /// The installed nginx, when it could be asked.
    pub nginx_version: Option<String>,
}

/// The wire shape. Mirrors [`DiscoveredSite`] so the reading type stays free of
/// API concerns.
#[derive(Debug, serde::Serialize)]
pub struct DiscoveredSiteDto {
    pub domain: String,
    pub server_names: Vec<String>,
    pub kind: String,
    pub root: Option<String>,
    pub proxy_pass: Option<String>,
    pub fastcgi_pass: Option<String>,
    pub tls_certificate: Option<String>,
    pub config_file: String,
    pub listens: Vec<String>,
}

impl From<DiscoveredSite> for DiscoveredSiteDto {
    fn from(s: DiscoveredSite) -> Self {
        Self {
            domain: s.domain,
            server_names: s.server_names,
            kind: s.kind,
            root: s.root,
            proxy_pass: s.proxy_pass,
            fastcgi_pass: s.fastcgi_pass,
            tls_certificate: s.tls_certificate,
            config_file: s.config_file,
            listens: s.listens,
        }
    }
}

/// What nginx is already serving here.
pub struct Discover;

#[async_trait::async_trait]
impl TypedOperation for Discover {
    type Input = DiscoverInput;
    type Output = DiscoverOutput;

    const NAME: &'static str = "sites.discover";
    // Read-only, and the *read* permission for the same reason the posture scan
    // uses it: an operator cannot decide what to do about the twelve vhosts on
    // their server without first being allowed to see them. Nothing here is
    // disclosed that `ls /etc/nginx/conf.d` would not show the same account.
    const PERMISSION: Permission = Permission::ServerRead;
    // Reads a handful of small files and runs `nginx -v`.
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, _ctx: &OpContext, _input: Self::Input) -> Result<Self::Output> {
        let survey = survey();
        let sites = discover_sites().into_iter().map(Into::into).collect();
        let version = installed_version().await;

        Ok(DiscoverOutput {
            sites,
            default_server_files: survey
                .default_server_files
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            yields_default_server: survey.has_foreign_default_server(),
            nginx_version: version.map(|(a, b, c)| format!("{a}.{b}.{c}")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), body).unwrap();
    }

    /// The case that sent us here: a server already hosting sites, one of which
    /// is the default. Writing a second `default_server` fails `nginx -t`, and
    /// the whole stack install rolls back.
    #[test]
    fn an_existing_default_server_is_found() {
        let tmp = tempfile::tempdir().unwrap();
        let conf_d = tmp.path().join("conf.d");
        write(
            &conf_d,
            "example.com.conf",
            "server {\n listen 80;\n server_name example.com www.example.com;\n}\n",
        );
        write(
            &conf_d,
            "default.conf",
            "server {\n listen 80 default_server;\n server_name _;\n}\n",
        );

        let s = survey_dirs(&[conf_d]);
        assert!(
            s.has_foreign_default_server(),
            "the default server was missed"
        );
        assert!(s.server_names.contains("example.com"));
        assert!(s.server_names.contains("www.example.com"));
        assert!(
            !s.server_names.contains("_"),
            "the catchall placeholder is not a site"
        );
    }

    /// A blank server, which is what Unihelm was written for: nothing claims the
    /// default, so the catchall may.
    #[test]
    fn a_clean_server_reports_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let conf_d = tmp.path().join("conf.d");
        std::fs::create_dir_all(&conf_d).unwrap();

        let s = survey_dirs(&[conf_d]);
        assert!(!s.has_foreign_default_server());
        assert!(s.server_names.is_empty());
    }

    /// A commented-out directive is not a declaration. Debian's stock
    /// `sites-available/default` ships exactly this for 443, and treating it as
    /// live would drop `default_server` from our catchall for no reason.
    #[test]
    fn a_commented_directive_does_not_count() {
        let tmp = tempfile::tempdir().unwrap();
        let conf_d = tmp.path().join("conf.d");
        write(
            &conf_d,
            "site.conf",
            "server {\n # listen 443 ssl default_server;\n listen 80; # default_server\n server_name a.test;\n}\n",
        );

        let s = survey_dirs(&[conf_d]);
        assert!(
            !s.has_foreign_default_server(),
            "a comment was read as a declaration"
        );
        assert!(s.server_names.contains("a.test"));
    }

    /// Our own files must never make us think somebody else owns the default.
    #[test]
    fn our_own_catchall_is_not_foreign() {
        let ours = paths::nginx_dir();
        assert!(is_ours(&ours.join("00-catchall.conf")));
        assert!(is_ours(&paths::nginx_hook()));
        assert!(!is_ours(Path::new("/etc/nginx/conf.d/example.com.conf")));
    }

    #[test]
    fn http2_on_is_gated_on_the_release_that_introduced_it() {
        // Ubuntu 24.04's stock nginx, a distribution this project tests on.
        assert_eq!(
            parse_version("nginx version: nginx/1.24.0 (Ubuntu)"),
            Some((1, 24, 0))
        );
        assert!(
            !supports_http2_on(Some((1, 24, 0))),
            "1.24 has no `http2 on;`"
        );

        assert!(supports_http2_on(Some((1, 25, 1))));
        assert!(supports_http2_on(Some((1, 27, 3))));
        assert!(!supports_http2_on(Some((1, 25, 0))));
        assert!(supports_http2_on(Some((2, 0, 0))));

        // A two-part version still parses; nginx has shipped them.
        assert_eq!(parse_version("nginx/1.26"), Some((1, 26, 0)));
        assert_eq!(parse_version("something else"), None);

        // Not knowing must not produce the older syntax on a modern server.
        assert!(supports_http2_on(None));
    }

    /// The shapes a real server actually holds.
    ///
    /// Modelled on a machine with twelve hand-written vhosts: mostly Node apps
    /// behind `proxy_pass`, one PHP site, some static, and the redirect blocks
    /// that carry http to https. The panel showed that server as empty.
    #[test]
    fn discovery_recognises_the_shapes_people_actually_write() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("conf.d");
        std::fs::create_dir_all(&d).unwrap();

        std::fs::write(
            d.join("app.conf"),
            concat!(
                "server {\n",
                "    listen 443 ssl;\n",
                "    server_name app.example.com;\n",
                "    ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;\n",
                "    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;\n",
                "    location / {\n",
                "        proxy_pass http://127.0.0.1:3000;\n",
                "        proxy_set_header Host $host;\n",
                "    }\n",
                "}\n",
                "server {\n",
                "    listen 80;\n",
                "    server_name app.example.com;\n",
                "    return 301 https://$host$request_uri;\n",
                "}\n",
            ),
        )
        .unwrap();

        std::fs::write(
            d.join("blog.conf"),
            concat!(
                "server {\n",
                "    listen 80;\n",
                "    server_name blog.example.com www.blog.example.com;\n",
                "    root /var/www/blog;\n",
                "    index index.php;\n",
                "    location ~ \\.php$ {\n",
                "        fastcgi_pass unix:/run/php/php8.3-fpm.sock;\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();

        std::fs::write(
            d.join("docs.conf"),
            concat!(
                "server {\n",
                "    listen 80;\n",
                "    server_name docs.example.com;\n",
                "    root /srv/docs;\n",
                "    index index.html;\n",
                "}\n",
            ),
        )
        .unwrap();

        let found = discover_sites_in(&[d]);
        let by = |name: &str| found.iter().find(|s| s.domain == name).cloned();

        let app = by("app.example.com").expect("the proxy site was missed");
        assert_eq!(app.kind, "proxy");
        assert_eq!(app.proxy_pass.as_deref(), Some("http://127.0.0.1:3000"));
        assert_eq!(
            app.tls_certificate.as_deref(),
            Some("/etc/letsencrypt/live/app.example.com/fullchain.pem"),
            "ssl_certificate_key must not be read as the certificate"
        );

        let blog = by("blog.example.com").expect("the php site was missed");
        assert_eq!(blog.kind, "php");
        assert_eq!(blog.root.as_deref(), Some("/var/www/blog"));
        assert!(
            blog.server_names
                .contains(&"www.blog.example.com".to_string())
        );

        let docs = by("docs.example.com").expect("the static site was missed");
        assert_eq!(docs.kind, "static");
        assert_eq!(docs.root.as_deref(), Some("/srv/docs"));

        // The http-to-https block carries the same name as the proxy vhost, and
        // one name is one site.
        assert_eq!(found.len(), 3, "found: {found:#?}");
    }

    /// Our own files are not discoveries; reporting them would have the panel
    /// offer to adopt itself.
    #[test]
    fn discovery_skips_what_unihelm_wrote() {
        assert!(is_ours(&paths::nginx_dir().join("01-panel.conf")));
        assert!(is_ours(&paths::nginx_dir().join("00-catchall.conf")));
    }

    /// A vhost with no server_name answers for nothing anyone can request, and
    /// listing it as a site would be a lie.
    #[test]
    fn a_nameless_vhost_is_not_a_site() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("conf.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("x.conf"),
            "server {\n listen 8080;\n root /srv/x;\n}\n",
        )
        .unwrap();
        assert!(discover_sites_in(&[d]).is_empty());
    }

    /// The single-line `location` block, which is how these are usually written.
    ///
    /// The first version of this scan only looked at the start of a line, so a
    /// vhost written this way came back as `unknown` with no upstream — and the
    /// unit tests missed it because they were written in the expanded form
    /// nobody uses. Found by running discovery against a realistic config.
    #[test]
    fn a_directive_inside_a_one_line_location_block_is_seen() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("conf.d");
        std::fs::create_dir_all(&d).unwrap();

        std::fs::write(
            d.join("app.conf"),
            concat!(
                "server {\n",
                "    listen 443 ssl;\n",
                "    server_name app.test;\n",
                "    ssl_certificate /etc/ssl/app.pem;\n",
                "    ssl_certificate_key /etc/ssl/app.key;\n",
                "    location / { proxy_pass http://127.0.0.1:3000; }\n",
                "}\n",
            ),
        )
        .unwrap();
        std::fs::write(
            d.join("php.conf"),
            concat!(
                "server {\n",
                "    listen 80;\n",
                "    server_name php.test;\n",
                "    root /var/www/php;\n",
                "    location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.3-fpm.sock; }\n",
                "}\n",
            ),
        )
        .unwrap();

        let found = discover_sites_in(&[d]);
        let app = found.iter().find(|s| s.domain == "app.test").unwrap();
        assert_eq!(app.kind, "proxy", "one-line location block was missed");
        assert_eq!(app.proxy_pass.as_deref(), Some("http://127.0.0.1:3000"));
        assert_eq!(
            app.tls_certificate.as_deref(),
            Some("/etc/ssl/app.pem"),
            "ssl_certificate_key must not be read as ssl_certificate"
        );

        let php = found.iter().find(|s| s.domain == "php.test").unwrap();
        assert_eq!(php.kind, "php", "fastcgi in a one-line block was missed");
    }

    /// `proxy_pass_header` is not `proxy_pass`, and a substring match would make
    /// every proxied vhost report the wrong upstream.
    #[test]
    fn a_longer_directive_is_not_mistaken_for_a_shorter_one() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("conf.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("x.conf"),
            concat!(
                "server {\n",
                "    listen 80;\n",
                "    server_name x.test;\n",
                "    root /srv/x;\n",
                "    proxy_pass_header Server;\n",
                "}\n",
            ),
        )
        .unwrap();

        let found = discover_sites_in(&[d]);
        let x = found.iter().find(|s| s.domain == "x.test").unwrap();
        assert_eq!(
            x.proxy_pass, None,
            "proxy_pass_header was read as proxy_pass"
        );
        assert_eq!(x.kind, "static");
    }

    /// A whole vhost on one line.
    ///
    /// The line-oriented version of this scan lost these completely: it saw the
    /// block open, skipped the rest of the line, never saw the closing brace and
    /// so never reported the site at all. Found by running discovery against a
    /// realistic config rather than against the expanded form the other tests
    /// were written in.
    #[test]
    fn a_vhost_written_entirely_on_one_line_is_found() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("conf.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("docs.conf"),
            "server { listen 80; server_name docs.test; root /srv/docs; index index.html; }\n",
        )
        .unwrap();

        let found = discover_sites_in(&[d]);
        assert_eq!(found.len(), 1, "the one-line vhost was lost: {found:#?}");
        assert_eq!(found[0].domain, "docs.test");
        assert_eq!(found[0].kind, "static");
        assert_eq!(found[0].root.as_deref(), Some("/srv/docs"));
    }

    /// Nested blocks must not close the server early.
    #[test]
    fn nested_blocks_do_not_end_the_vhost() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("conf.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("n.conf"),
            concat!(
                "server {\n",
                "  server_name deep.test;\n",
                "  location / {\n",
                "    if ($host = other) {\n",
                "      return 404;\n",
                "    }\n",
                "    proxy_pass http://127.0.0.1:9000;\n",
                "  }\n",
                "}\n",
            ),
        )
        .unwrap();

        let found = discover_sites_in(&[d]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].kind, "proxy");
        assert_eq!(
            found[0].proxy_pass.as_deref(),
            Some("http://127.0.0.1:9000")
        );
    }
}
