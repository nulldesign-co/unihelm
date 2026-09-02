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
}
