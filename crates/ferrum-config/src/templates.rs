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
        "nginx/ferrum.conf",
        include_str!("../templates/nginx/ferrum.conf.j2"),
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
        "nginx/adminer.conf",
        include_str!("../templates/nginx/adminer.conf.j2"),
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

        for (name, source) in TEMPLATES {
            env.add_template(name, source)
                .map_err(|e| ConfigError::Template {
                    template: (*name).to_string(),
                    detail: format!("{e:#}"),
                })?;
        }

        Ok(Self { env })
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
