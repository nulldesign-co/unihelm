//! The template environment (spec §4.1 `minijinja`).
//!
//! Three decisions carry this module:
//!
//! - **Templates are embedded in the binary**, so a panel upgrade cannot leave a
//!   stale template on disk and there is no template directory to keep in sync.
//! - **Undefined variables are an error.** This is the important one. A
//!   template that silently renders `server_name ;` because a field was renamed
//!   produces a catch-all vhost that hijacks every site on the server. Strict
//!   undefined turns that into a render failure before anything is written.
//! - **Templates are compiled at startup, not on first use**, so a broken
//!   template is a boot failure rather than a 500 the first time somebody
//!   creates a site.

use minijinja::{Environment, UndefinedBehavior};

use crate::{ConfigError, Result};

/// Every template the panel renders, with the name it is registered under.
///
/// Adding one here and forgetting to add it to the compile check is not
/// possible: the set is this list.
const TEMPLATES: &[(&str, &str)] = &[
    (
        "nginx/site.conf",
        include_str!("../templates/nginx/site.conf.j2"),
    ),
    (
        "nginx/catchall.conf",
        include_str!("../templates/nginx/catchall.conf.j2"),
    ),
    (
        "nginx/panel.conf",
        include_str!("../templates/nginx/panel.conf.j2"),
    ),
    (
        "nginx/unihelm.conf",
        include_str!("../templates/nginx/unihelm.conf.j2"),
    ),
    (
        "logrotate/site",
        include_str!("../templates/logrotate/site.j2"),
    ),
    (
        "php/pool.conf",
        include_str!("../templates/php/pool.conf.j2"),
    ),
    (
        "systemd/tenant.slice",
        include_str!("../templates/systemd/tenant.slice.j2"),
    ),
    (
        "systemd/tenant-dropin.conf",
        include_str!("../templates/systemd/tenant-dropin.conf.j2"),
    ),
    (
        "systemd/node-app.service",
        include_str!("../templates/systemd/node-app.service.j2"),
    ),
    (
        "systemd/plugin.service",
        include_str!("../templates/systemd/plugin.service.j2"),
    ),
    (
        "nginx/adminer.conf",
        include_str!("../templates/nginx/adminer.conf.j2"),
    ),
    (
        "mysql/unihelm.cnf",
        include_str!("../templates/mysql/unihelm.cnf.j2"),
    ),
    (
        "ssh/sftp.conf",
        include_str!("../templates/ssh/sftp.conf.j2"),
    ),
    // The panel-managed block inside a tenant's authorized_keys (spec §11.16).
    // A fragment rather than a whole file: the lines around it are the
    // tenant's own and are spliced back untouched.
    (
        "ssh/authorized_keys.block",
        include_str!("../templates/ssh/authorized_keys.block.j2"),
    ),
    (
        "nginx/waf.conf",
        include_str!("../templates/nginx/waf.conf.j2"),
    ),
    (
        "nginx/load-module.conf",
        include_str!("../templates/nginx/load-module.conf.j2"),
    ),
    // The per-site outbound relay configuration (spec §11.18). Not a script:
    // the panel never renders something it would then execute through a shell.
    ("mail/msmtprc", include_str!("../templates/mail/msmtprc.j2")),
    // Not nginx syntax: this is the ModSecurity rules file nginx's
    // `modsecurity_rules_file` points at (spec §11.9).
    (
        "modsecurity/main.conf",
        include_str!("../templates/modsecurity/main.conf.j2"),
    ),
];

pub struct TemplateSet {
    env: Environment<'static>,
}

impl TemplateSet {
    /// Build and validate the environment. Fails if any template does not parse.
    pub fn load() -> Result<Self> {
        let mut env = Environment::new();

        // The single most important line in this crate.
        env.set_undefined_behavior(UndefinedBehavior::Strict);

        // These are config files, not HTML: escaping `&` into `&amp;` inside an
        // nginx directive would be a bug, not a safety feature. Values reaching
        // templates are already validated newtypes (spec §12 rule 3), which is
        // where the actual safety comes from.
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::None);

        // Keep rendered configs readable: a block tag on its own line should not
        // leave a blank line behind it.
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);

        // Which HTTP/2 spelling this machine's nginx accepts.
        //
        // A global rather than a key threaded through every render context,
        // because it is a property of the server rather than of the thing being
        // rendered, and every nginx template needs it. `true` is the safe
        // default for the same reason `supports_http2_on` treats an unknown
        // version as new: the directive has been correct since 2023.
        env.add_global("http2_on", minijinja::Value::from(true));

        for (name, source) in TEMPLATES {
            env.add_template(name, source)
                .map_err(|e| ConfigError::Template {
                    template: (*name).to_string(),
                    detail: format!("{e:#}"),
                })?;
        }

        Ok(Self { env })
    }

    /// Record what the installed nginx accepts.
    ///
    /// Called once the version is known. Until 1.25.1, HTTP/2 was a listen
    /// parameter and `http2 on;` is an `unknown directive` that fails
    /// `nginx -t` — on Ubuntu 24.04, which ships 1.24.0, every vhost the panel
    /// rendered was invalid.
    pub fn set_http2_on(&mut self, supported: bool) {
        self.env
            .add_global("http2_on", minijinja::Value::from(supported));
    }

    pub fn render(&self, name: &str, context: &serde_json::Value) -> Result<String> {
        let template = self
            .env
            .get_template(name)
            .map_err(|e| ConfigError::Template {
                template: name.to_string(),
                detail: format!("{e:#}"),
            })?;

        let mut rendered = template
            .render(context)
            .map_err(|e| ConfigError::Template {
                template: name.to_string(),
                // `{:#}` includes the chain, which is where "undefined value" says
                // *which* value.
                detail: format!("{e:#}"),
            })?;

        // Every config file ends with a newline. Some editors and some parsers
        // care, and the diff view is nicer.
        if !rendered.ends_with('\n') {
            rendered.push('\n');
        }
        Ok(rendered)
    }

    /// Register an extra template at runtime.
    ///
    /// Used by tests and, later, by plugins. Core templates stay embedded so a
    /// panel upgrade cannot leave a stale one on disk.
    pub fn add_template(&mut self, name: &str, source: &str) -> Result<()> {
        self.env
            .add_template_owned(name.to_string(), source.to_string())
            .map_err(|e| ConfigError::Template {
                template: name.to_string(),
                detail: format!("{e:#}"),
            })
    }

    pub fn names(&self) -> Vec<&str> {
        self.env.templates().map(|(name, _)| name).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_embedded_template_parses() {
        let set = TemplateSet::load().expect("a template that does not parse must fail at load");
        assert_eq!(set.names().len(), TEMPLATES.len());
    }

    /// The catchall owns `default_server` on a server Unihelm set up, and must
    /// yield it on one that was already serving sites: the directive may appear
    /// once per listening address, so a second one fails `nginx -t` and rolls
    /// the entire stack install back.
    #[test]
    fn the_catchall_yields_an_existing_default_server() {
        let set = TemplateSet::load().unwrap();
        let ctx = |owns| {
            json!({
                "acme_webroot": "/var/lib/unihelm/acme",
                "default_cert": "/x/fullchain.pem",
                "default_key": "/x/privkey.pem",
                "owns_default": owns,
                "catchall_names": "unihelm-catchall.invalid",
                "http3": false,
            })
        };

        // Only directives count. The file's own header explains what
        // `default_server` is, and a comment is not a declaration — which is
        // exactly the distinction nginx makes too.
        let directives = |rendered: &str| -> String {
            rendered
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
        };

        let owning = set.render("nginx/catchall.conf", &ctx(true)).unwrap();
        assert!(
            directives(&owning).contains("default_server"),
            "on a server we own, the catchall must be the default"
        );

        let yielding = set.render("nginx/catchall.conf", &ctx(false)).unwrap();
        let yielded = directives(&yielding);
        assert!(
            !yielded.contains("default_server"),
            "a second default_server is what nginx -t refuses:\n{yielded}"
        );
        assert!(
            !yielded.contains("server_name _;"),
            "yielding means not claiming every unmatched name either"
        );
        assert!(
            yielding.contains("unihelm-catchall.invalid"),
            "the yielding block still needs a name of its own"
        );
        // Both shapes must still serve ACME, or a certificate can never be
        // issued for the panel on an adopted server.
        for rendered in [&owning, &yielding] {
            assert!(rendered.contains("/.well-known/acme-challenge/"));
        }
    }

    /// The `location` block nginx would pick for an HTTPS request for `path`,
    /// by its own rule: prefix matches, longest wins, whatever order they
    /// appear in.
    ///
    /// Scoped to the TLS server first, because this file has two and both
    /// declare `location /`. A matcher blind to that would report the port-80
    /// redirect when the 443 server has no better match — and would accept a
    /// directive found on the plain-HTTP side as if it applied to the tunnel.
    fn tls_location_serving(rendered: &str, path: &str) -> String {
        let tls = rendered
            .split("\nserver {")
            .find(|block| block.contains("listen 443"))
            .expect("the panel vhost has no TLS server");

        let mut best: Option<(usize, String)> = None;
        let mut lines = tls.lines();
        while let Some(line) = lines.next() {
            let Some(rest) = line.trim().strip_prefix("location ") else {
                continue;
            };
            let Some(prefix) = rest.strip_suffix(" {") else {
                continue;
            };
            let prefix = prefix.trim_start_matches("^~ ").trim();
            let mut body = String::new();
            for inner in lines.by_ref() {
                if inner.trim() == "}" {
                    break;
                }
                body.push_str(inner);
                body.push('\n');
            }
            let longer = match &best {
                Some((len, _)) => prefix.len() > *len,
                None => true,
            };
            if path.starts_with(prefix) && longer {
                best = Some((prefix.len(), body));
            }
        }
        best.unwrap_or_else(|| panic!("no location in the panel's TLS server matches {path}"))
            .1
    }

    /// A web terminal is idle whenever the operator is reading rather than
    /// typing, and nginx's default `proxy_read_timeout` of 60s is the gap it
    /// allows between reads on an upgraded connection. Neither end of this
    /// tunnel pings, so the location that carries it has to say otherwise or a
    /// quiet minute of a build takes the live view away.
    #[test]
    fn an_idle_web_terminal_is_not_dropped_by_the_default_read_timeout() {
        let set = TemplateSet::load().unwrap();
        let rendered = set
            .render(
                "nginx/panel.conf",
                &json!({
                    "panel_domain": "panel.example.com",
                    "acme_webroot": "/var/lib/unihelm/acme",
                    "cert_path": "/var/lib/unihelm/state/certs/panel.example.com/fullchain.pem",
                    "key_path": "/var/lib/unihelm/state/certs/panel.example.com/privkey.pem",
                    "max_body_size": "512m",
                    "upstream": "127.0.0.1:8088",
                    "upstream_scheme": "http",
                }),
            )
            .unwrap();

        let block = tls_location_serving(&rendered, "/api/terminal/ws");
        assert!(
            block.contains("proxy_set_header Upgrade $http_upgrade;"),
            "the terminal is a WebSocket and still needs its upgrade headers:\n{block}"
        );
        assert!(
            block.contains("proxy_read_timeout 24h;"),
            "an idle PTY must outlive nginx's 60s default:\n{block}"
        );
    }

    #[test]
    fn an_undefined_variable_is_an_error_not_an_empty_string() {
        // The failure this prevents: `server_name ;` silently becoming a
        // catch-all that swallows every request on the server.
        let mut env = Environment::new();
        env.set_undefined_behavior(UndefinedBehavior::Strict);
        env.add_template("t", "server_name {{ domain }};").unwrap();

        let err = env
            .get_template("t")
            .unwrap()
            .render(json!({}))
            .unwrap_err();
        assert!(format!("{err:#}").contains("undefined"), "got: {err:#}");

        let ok = env
            .get_template("t")
            .unwrap()
            .render(json!({"domain": "example.com"}))
            .unwrap();
        assert_eq!(ok, "server_name example.com;");
    }

    #[test]
    fn config_values_are_not_html_escaped() {
        let set = TemplateSet::load().unwrap();
        // A real case: a custom snippet containing `&&` or a query string.
        let mut env = Environment::new();
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::None);
        env.add_template("t", "{{ v }}").unwrap();
        let out = env
            .get_template("t")
            .unwrap()
            .render(json!({"v": "a && b > c"}))
            .unwrap();
        assert_eq!(out, "a && b > c");
        let _ = set;
    }

    #[test]
    fn rendered_output_always_ends_with_a_newline() {
        let mut set = TemplateSet::load().unwrap();
        set.add_template("t", "no trailing newline").unwrap();
        assert!(set.render("t", &json!({})).unwrap().ends_with('\n'));
    }

    #[test]
    fn an_unknown_template_name_is_an_error() {
        let set = TemplateSet::load().unwrap();
        assert!(set.render("nginx/does-not-exist", &json!({})).is_err());
    }
}
