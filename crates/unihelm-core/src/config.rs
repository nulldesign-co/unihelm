//! The bootstrap configuration both daemons read (spec §4.3).
//!
//! Deliberately tiny. Everything that can live in the database *does* live in the
//! database, so that changing it is an audited API call rather than an SSH
//! session and a restart. What stays in `/etc/unihelm/config.toml` is only what is
//! needed to reach the database in the first place.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Where the packaged install expects its files.
pub mod paths {
    pub const CONFIG: &str = "/etc/unihelm/config.toml";
    pub const SECRET_KEY: &str = "/etc/unihelm/secret.key";
    pub const DATA_DIR: &str = "/var/lib/unihelm";
    pub const DATABASE: &str = "/var/lib/unihelm/panel.db";
    pub const STATE_DIR: &str = "/var/lib/unihelm/state";
    pub const RUNTIME_DIR: &str = "/run/unihelm";
    pub const AGENT_SOCKET: &str = "/run/unihelm/agent.sock";
    pub const LOG_DIR: &str = "/var/log/unihelm";
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UnihelmConfig {
    pub panel: PanelConfig,
    pub agent: AgentConfig,
    pub log: LogConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PanelConfig {
    /// Where `unihelm-web` listens. Bind to a loopback address and put the panel
    /// behind its own managed vhost if you want it on 443 — which is what
    /// `panel.tls.issue` does, narrowing this to loopback itself once that
    /// vhost is serving.
    pub listen: String,
    pub database: PathBuf,
    pub state_dir: PathBuf,
    /// Unix socket for the CLI, so `unihelm` works without a network round trip.
    pub cli_socket: PathBuf,
    /// Send session cookies with the `Secure` attribute.
    ///
    /// On by default — the panel is expected to be reached over TLS. Turning it
    /// off is for plain-HTTP development only, and the panel says so at startup.
    pub secure_cookies: bool,
    /// How the panel serves itself.
    ///
    /// A fresh install has no domain, and requiring one — or an ssh tunnel — just
    /// to see the panel is not a decision to make on the operator's behalf. So
    /// the panel terminates TLS itself with a certificate it generates, and is
    /// reachable at `https://<the server's address>:8088` the moment the
    /// installer finishes. The browser warns that the certificate is self-signed,
    /// which is true and is what every panel in this category does; attaching a
    /// domain later with `unihelm cert panel` replaces it with a real one.
    #[serde(default)]
    pub tls: PanelTls,
}

/// Where the panel's TLS comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PanelTls {
    /// Generate a certificate and serve HTTPS. The default: it is the only
    /// setting under which a fresh install is reachable and safe to log in to.
    #[default]
    SelfSigned,
    /// Serve plain HTTP.
    ///
    /// Correct only behind a proxy that terminates TLS and sets
    /// `X-Forwarded-Proto` — which is what `unihelm cert panel <domain>` sets
    /// up. It does **not** switch this off for you, whatever this comment used
    /// to say: the vhost proxies to whatever the panel is serving, and a
    /// self-signed certificate on a loopback hop costs nothing, while a panel
    /// that had silently moved to plain HTTP would be one misconfigured proxy
    /// away from serving its login form in the clear. On its own, off the
    /// loopback interface, this means passwords cross the network unencrypted.
    Off,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    pub socket: PathBuf,
    /// The unprivileged account `unihelm-web` runs as. The agent resolves this to
    /// a uid at startup and refuses connections from anyone else (spec §5.1).
    pub web_user: String,
    /// Task workers, not counting the dedicated fast lane (spec §10.1).
    pub workers: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// `error`, `warn`, `info`, `debug`, `trace`, or any `RUST_LOG` filter.
    pub level: String,
    pub format: LogFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Structured, for journald and log shipping.
    Json,
    /// Human-readable, for `unihelm dev`.
    Text,
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            // All interfaces, because a fresh install has no domain and no
            // other way to be looked at; `tls` below is what keeps that safe.
            // This comment read "loopback by default" for as long as the value
            // was not loopback — a line of prose asserting the opposite of the
            // line under it, in the file the rest of the panel reads to find
            // out where it listens. `panel.tls.issue` narrows this to loopback
            // once a vhost serves the panel under a real name.
            listen: "0.0.0.0:8088".into(),
            database: PathBuf::from(paths::DATABASE),
            state_dir: PathBuf::from(paths::STATE_DIR),
            cli_socket: PathBuf::from("/run/unihelm/web.sock"),
            secure_cookies: true,
            tls: PanelTls::SelfSigned,
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            socket: PathBuf::from(paths::AGENT_SOCKET),
            web_user: "unihelm".into(),
            workers: 2,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: LogFormat::Json,
        }
    }
}

impl UnihelmConfig {
    /// Parse a config document.
    ///
    /// Unknown keys are an error, not a warning: a typo in `listen` that silently
    /// leaves the panel on its default address is exactly the class of surprise
    /// this panel exists to avoid.
    pub fn from_toml(text: &str) -> Result<Self, String> {
        toml_lite::parse(text)
    }

    /// A development configuration rooted at `dir`, with nothing under `/etc`.
    pub fn for_dev(dir: &Path) -> Self {
        Self {
            panel: PanelConfig {
                // Dev stays on loopback and plain HTTP: it is one developer on
                // one machine, and a self-signed certificate would only put a
                // browser warning in front of every reload.
                listen: "127.0.0.1:8088".into(),
                database: dir.join("panel.db"),
                state_dir: dir.join("state"),
                cli_socket: dir.join("web.sock"),
                // Dev runs on plain http://127.0.0.1, where a Secure cookie
                // would simply never be sent back.
                secure_cookies: false,
                tls: PanelTls::Off,
            },
            agent: AgentConfig {
                socket: dir.join("agent.sock"),
                // In dev both processes are the same account.
                web_user: String::new(),
                workers: 2,
            },
            // sqlx logs every statement at debug; useful once, unreadable always.
            log: LogConfig {
                level: "debug,sqlx=warn".into(),
                format: LogFormat::Text,
            },
        }
    }

    /// Rewrite `panel.listen` in a config document, leaving every other byte of
    /// it — comments, key order, the operator's own edits — where it was.
    ///
    /// `panel.tls.issue` narrows the listener to loopback once the panel's own
    /// vhost is serving it, and one changed setting should be one changed line.
    /// Serialising a parsed [`UnihelmConfig`] back out would have been shorter
    /// and would have deleted every comment in the file, including the ones
    /// explaining choices the operator made and this panel never asked about.
    ///
    /// The result is parsed again before it is handed back, and a rewrite that
    /// does not read back as the value asked for is an error rather than a
    /// file: `/etc/unihelm/config.toml` is what `unihelm-web` reads at startup,
    /// and a document it cannot parse is a panel that does not come up — a
    /// lockout with no way back in through the panel itself.
    pub fn rewrite_panel_listen(text: &str, listen: &str) -> Result<String, String> {
        toml_lite::set_panel_listen(text, listen)
    }

    /// Sanity-check a loaded config before anything acts on it.
    pub fn validate(&self) -> Result<(), String> {
        if self.panel.listen.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!(
                "panel.listen must be an address:port, got `{}`",
                self.panel.listen
            ));
        }
        if !self.agent.socket.is_absolute() && !self.agent.socket.starts_with(".") {
            return Err("agent.socket must be an absolute path".into());
        }
        if self.agent.workers == 0 || self.agent.workers > 32 {
            return Err("agent.workers must be between 1 and 32".into());
        }
        Ok(())
    }
}

/// A deliberately small TOML reader.
///
/// The config is a handful of `key = "value"` lines under three tables, and
/// keeping the parse in-crate means `unihelm-core` stays dependency-light for
/// everything that links it. If the config ever grows arrays or nesting, replace
/// this with the `toml` crate in the binaries rather than growing it here.
mod toml_lite {
    use super::{LogFormat, PanelTls, UnihelmConfig};
    use std::path::PathBuf;

    pub fn parse(text: &str) -> Result<UnihelmConfig, String> {
        let mut cfg = UnihelmConfig::default();
        let mut table = String::new();

        for (lineno, raw) in text.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let at = || format!("line {}", lineno + 1);

            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                table = name.trim().to_string();
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("{}: expected `key = value`, got `{line}`", at()));
            };
            let key = key.trim();
            let value = unquote(value.trim());

            match (table.as_str(), key) {
                ("panel", "listen") => cfg.panel.listen = value,
                ("panel", "database") => cfg.panel.database = PathBuf::from(value),
                ("panel", "state_dir") => cfg.panel.state_dir = PathBuf::from(value),
                ("panel", "cli_socket") => cfg.panel.cli_socket = PathBuf::from(value),
                ("panel", "tls") => {
                    cfg.panel.tls = match value.as_str() {
                        "self-signed" => PanelTls::SelfSigned,
                        "off" => PanelTls::Off,
                        other => {
                            return Err(format!(
                                "{}: tls must be self-signed or off, got `{other}`",
                                at()
                            ));
                        }
                    };
                }
                ("panel", "secure_cookies") => {
                    cfg.panel.secure_cookies = match value.as_str() {
                        "true" => true,
                        "false" => false,
                        other => {
                            return Err(format!(
                                "{}: secure_cookies must be true or false, got `{other}`",
                                at()
                            ));
                        }
                    };
                }

                ("agent", "socket") => cfg.agent.socket = PathBuf::from(value),
                ("agent", "web_user") => cfg.agent.web_user = value,
                ("agent", "workers") => {
                    cfg.agent.workers = value
                        .parse()
                        .map_err(|_| format!("{}: workers must be a number", at()))?;
                }

                ("log", "level") => cfg.log.level = value,
                ("log", "format") => {
                    cfg.log.format = match value.as_str() {
                        "json" => LogFormat::Json,
                        "text" => LogFormat::Text,
                        other => return Err(format!("{}: unknown log format `{other}`", at())),
                    };
                }

                ("", _) => return Err(format!("{}: `{key}` is outside any table", at())),
                (t, k) => return Err(format!("{}: unknown key `{k}` in table [{t}]", at())),
            }
        }

        Ok(cfg)
    }

    /// Write one `panel.listen` value into a document the rest of which is
    /// none of our business. See [`super::UnihelmConfig::rewrite_panel_listen`].
    pub fn set_panel_listen(text: &str, listen: &str) -> Result<String, String> {
        // Only an address:port is ever written. The value goes into the file
        // verbatim, so a `#` or a newline smuggled in through it would comment
        // out the rest of the line or invent a key — caught here rather than at
        // the next startup, when the panel would be the thing failing to parse.
        if listen.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!(
                "`{listen}` is not an address:port, so it will not be written to the config"
            ));
        }
        let replacement = format!("listen = \"{listen}\"");

        let mut out = String::with_capacity(text.len() + replacement.len() + 16);
        let mut table = String::new();
        let mut replaced = false;
        let mut panel_header_line: Option<usize> = None;

        for (index, raw) in text.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                table = name.trim().to_string();
                if table == "panel" && panel_header_line.is_none() {
                    panel_header_line = Some(index);
                }
            } else if table == "panel"
                && line.split_once('=').map(|(k, _)| k.trim()) == Some("listen")
            {
                // Every occurrence, not just the first: the parser above takes
                // the last value it reads, so a file that says `listen` twice
                // and has one of them rewritten still starts on the old
                // address — the change would look applied and do nothing.
                let indent = &raw[..raw.len() - raw.trim_start().len()];
                out.push_str(indent);
                out.push_str(&replacement);
                out.push('\n');
                replaced = true;
                continue;
            }
            out.push_str(raw);
            out.push('\n');
        }

        if !replaced {
            // A `[panel]` table with no `listen` line was running on the
            // default; state it rather than leaving the table looking as though
            // nothing changed. With no `[panel]` table at all there is one to
            // add, at the end, where it cannot land inside somebody else's.
            out = match panel_header_line {
                Some(header) => {
                    let mut rebuilt = String::with_capacity(out.len() + replacement.len() + 1);
                    for (index, raw) in text.lines().enumerate() {
                        rebuilt.push_str(raw);
                        rebuilt.push('\n');
                        if index == header {
                            rebuilt.push_str(&replacement);
                            rebuilt.push('\n');
                        }
                    }
                    rebuilt
                }
                None => {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str("\n[panel]\n");
                    out.push_str(&replacement);
                    out.push('\n');
                    out
                }
            };
        }

        // The proof, not the intention: what was written parses, and parses to
        // the address that was asked for.
        let parsed = super::UnihelmConfig::from_toml(&out)
            .map_err(|e| format!("the rewritten config would not parse ({e})"))?;
        if parsed.panel.listen != listen {
            return Err(format!(
                "the rewritten config reads back as `{}`, not `{listen}`",
                parsed.panel.listen
            ));
        }
        Ok(out)
    }

    /// Strip a trailing `#` comment, respecting quotes.
    fn strip_comment(line: &str) -> &str {
        let mut in_quotes = false;
        for (i, c) in line.char_indices() {
            match c {
                '"' => in_quotes = !in_quotes,
                '#' if !in_quotes => return &line[..i],
                _ => {}
            }
        }
        line
    }

    fn unquote(v: &str) -> String {
        v.strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .map(str::to_string)
            .unwrap_or_else(|| v.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh panel is reachable, and reachable safely.
    ///
    /// This used to assert the opposite — that the default was loopback — and
    /// that is what "safe" was taken to mean. It was the wrong invariant: it
    /// made a fresh install invisible on the server it had just been installed
    /// on, so the only ways to see the panel were an ssh tunnel or a domain,
    /// and whether to attach a domain is the operator's decision, not a
    /// precondition for looking at what you installed.
    ///
    /// The property that actually matters is the one below: off loopback, the
    /// panel must be terminating TLS. A password typed into a public address
    /// over plain HTTP is the thing to prevent — not the address itself.
    #[test]
    fn a_fresh_panel_is_reachable_and_encrypted() {
        let c = UnihelmConfig::default();
        let addr: std::net::SocketAddr = c
            .panel
            .listen
            .parse()
            .expect("the default listen address parses");

        assert!(
            !addr.ip().is_loopback(),
            "a fresh panel must be reachable on the server it was installed on"
        );
        assert_eq!(
            c.panel.tls,
            PanelTls::SelfSigned,
            "a panel off loopback must terminate TLS"
        );
        assert!(c.panel.secure_cookies);
        assert_eq!(c.agent.web_user, "unihelm");
        assert!(c.validate().is_ok());
    }

    /// The pairing above is the invariant, so state it directly: no default and
    /// no shipped example may put the panel on a public address in the clear.
    #[test]
    fn the_shipped_example_never_serves_plain_http_off_loopback() {
        let example = include_str!("../../../installer/config.toml.example");
        let c = UnihelmConfig::from_toml(example).expect("the shipped example parses");
        let addr: std::net::SocketAddr = c.panel.listen.parse().expect("its listen parses");
        if !addr.ip().is_loopback() {
            assert_eq!(
                c.panel.tls,
                PanelTls::SelfSigned,
                "config.toml.example exposes the panel over plain HTTP"
            );
        }
    }

    #[test]
    fn parses_a_full_config() {
        let text = r#"
# Unihelm panel configuration

[panel]
listen = "0.0.0.0:8443"        # exposed on purpose
database = "/var/lib/unihelm/panel.db"
state_dir = "/var/lib/unihelm/state"

[agent]
socket = "/run/unihelm/agent.sock"
web_user = "unihelm"
workers = 4

[log]
level = "debug"
format = "text"
"#;
        let c = UnihelmConfig::from_toml(text).unwrap();
        assert_eq!(c.panel.listen, "0.0.0.0:8443");
        assert_eq!(c.agent.workers, 4);
        assert_eq!(c.log.format, LogFormat::Text);
        assert_eq!(c.panel.database, PathBuf::from("/var/lib/unihelm/panel.db"));
    }

    #[test]
    fn an_empty_config_is_the_defaults() {
        assert_eq!(
            UnihelmConfig::from_toml("").unwrap(),
            UnihelmConfig::default()
        );
        assert_eq!(
            UnihelmConfig::from_toml("\n\n# only comments\n").unwrap(),
            UnihelmConfig::default()
        );
    }

    #[test]
    fn a_typo_is_an_error_not_a_silent_default() {
        // The failure this guards against: `lisen = "0.0.0.0:8443"` parsing fine
        // and the panel quietly staying on loopback.
        let err = UnihelmConfig::from_toml("[panel]\nlisen = \"0.0.0.0:8443\"").unwrap_err();
        assert!(err.contains("unknown key"), "got: {err}");
        assert!(
            err.contains("line 2"),
            "errors should point at the line: {err}"
        );

        assert!(UnihelmConfig::from_toml("[pannel]\nlisten = \"x\"").is_err());
        assert!(
            UnihelmConfig::from_toml("listen = \"x\"").is_err(),
            "keys need a table"
        );
        assert!(UnihelmConfig::from_toml("[agent]\nworkers = many").is_err());
        assert!(UnihelmConfig::from_toml("[log]\nformat = \"xml\"").is_err());
        assert!(UnihelmConfig::from_toml("[panel]\nlisten").is_err());
    }

    #[test]
    fn hashes_inside_quotes_are_not_comments() {
        let c = UnihelmConfig::from_toml("[log]\nlevel = \"unihelm_web=debug,tower_http=info\"")
            .unwrap();
        assert_eq!(c.log.level, "unihelm_web=debug,tower_http=info");
        let c = UnihelmConfig::from_toml("[panel]\nstate_dir = \"/srv/a#b\"").unwrap();
        assert_eq!(c.panel.state_dir, PathBuf::from("/srv/a#b"));
    }

    #[test]
    fn secure_cookies_default_on_and_parse_as_booleans() {
        assert!(UnihelmConfig::default().panel.secure_cookies);
        assert!(
            !UnihelmConfig::from_toml("[panel]\nsecure_cookies = false")
                .unwrap()
                .panel
                .secure_cookies
        );
        assert!(UnihelmConfig::from_toml("[panel]\nsecure_cookies = yes").is_err());
    }

    /// The operator's file comes back as their file, with one line different.
    ///
    /// `panel.tls.issue` narrows the listener after it puts the panel's vhost
    /// live, and it does that to a file a human wrote and will read again. A
    /// rewrite that dropped their comments — or the settings this parser does
    /// not model yet — would be the panel helping itself to the whole document.
    #[test]
    fn rewriting_the_listen_address_changes_that_line_and_nothing_else() {
        let before = include_str!("../../../installer/config.toml.example");
        let after = UnihelmConfig::rewrite_panel_listen(before, "127.0.0.1:8088")
            .expect("the shipped example can be narrowed");

        assert_eq!(
            UnihelmConfig::from_toml(&after).unwrap().panel.listen,
            "127.0.0.1:8088"
        );
        assert!(after.contains("listen = \"127.0.0.1:8088\""), "{after}");
        assert!(!after.contains("0.0.0.0:8088"), "{after}");

        // Every other line survives byte for byte, comments included.
        let dropped: Vec<&str> = before
            .lines()
            .filter(|l| !l.starts_with("listen = "))
            .filter(|l| !after.lines().any(|k| k == *l))
            .collect();
        assert!(dropped.is_empty(), "these lines were lost: {dropped:?}");
    }

    #[test]
    fn rewriting_keeps_the_port_and_only_touches_the_panel_table() {
        let text = "[panel]\nlisten = \"0.0.0.0:9001\"\n\n[agent]\nworkers = 4\n";
        let after = UnihelmConfig::rewrite_panel_listen(text, "127.0.0.1:9001").unwrap();
        let parsed = UnihelmConfig::from_toml(&after).unwrap();
        assert_eq!(parsed.panel.listen, "127.0.0.1:9001");
        assert_eq!(parsed.agent.workers, 4);

        // A `listen` under another table is that table's business.
        let other = "[panel]\nlisten = \"0.0.0.0:8088\"\n[log]\nlevel = \"info\"\n";
        let after = UnihelmConfig::rewrite_panel_listen(other, "127.0.0.1:8088").unwrap();
        assert_eq!(after.matches("listen = ").count(), 1, "{after}");
    }

    /// The parser takes the last value it reads. A rewrite that changed only
    /// the first of two `listen` lines would look applied, restart the panel,
    /// and leave it on exactly the address it was told to leave.
    #[test]
    fn a_config_that_names_listen_twice_has_both_lines_rewritten() {
        let text = "[panel]\nlisten = \"0.0.0.0:8088\"\nsecure_cookies = true\nlisten = \"0.0.0.0:8088\"\n";
        let after = UnihelmConfig::rewrite_panel_listen(text, "127.0.0.1:8088").unwrap();
        assert_eq!(after.matches("127.0.0.1:8088").count(), 2, "{after}");
        assert_eq!(
            UnihelmConfig::from_toml(&after).unwrap().panel.listen,
            "127.0.0.1:8088"
        );
    }

    #[test]
    fn a_config_that_never_named_listen_gets_the_line_it_was_missing() {
        // Running on the default is not the same as saying so, and after a
        // narrowing the file has to say so or the next restart undoes it.
        let with_table = UnihelmConfig::rewrite_panel_listen(
            "[panel]\nsecure_cookies = true\n",
            "127.0.0.1:8088",
        )
        .unwrap();
        assert_eq!(
            UnihelmConfig::from_toml(&with_table).unwrap().panel.listen,
            "127.0.0.1:8088"
        );
        assert!(with_table.contains("secure_cookies = true"), "{with_table}");

        let without_table =
            UnihelmConfig::rewrite_panel_listen("[log]\nlevel = \"info\"\n", "127.0.0.1:8088")
                .unwrap();
        let parsed = UnihelmConfig::from_toml(&without_table).unwrap();
        assert_eq!(parsed.panel.listen, "127.0.0.1:8088");
        assert_eq!(parsed.log.level, "info");
    }

    /// Nothing is written that the panel could not read back. A config file
    /// `unihelm-web` cannot parse is a panel that will not start, and there is
    /// no way to fix that from inside the panel.
    #[test]
    fn a_rewrite_that_would_not_parse_is_refused_rather_than_returned() {
        assert!(UnihelmConfig::rewrite_panel_listen("[panel]\n", "not-an-address").is_err());
        assert!(
            UnihelmConfig::rewrite_panel_listen("[panel]\n", "127.0.0.1:8088\"\nrm = \"x").is_err(),
            "a value that could break out of its quotes must never be written"
        );
        // The file was already broken before we touched it — say so instead of
        // saving a second broken version of it.
        assert!(UnihelmConfig::rewrite_panel_listen("listen = = =", "127.0.0.1:8088").is_err());
    }

    #[test]
    fn validation_catches_nonsense() {
        let mut c = UnihelmConfig::default();
        c.panel.listen = "not-an-address".into();
        assert!(c.validate().is_err());

        let mut c = UnihelmConfig::default();
        c.agent.workers = 0;
        assert!(c.validate().is_err());

        let mut c = UnihelmConfig::default();
        c.agent.socket = PathBuf::from("relative/agent.sock");
        assert!(c.validate().is_err());
    }

    #[test]
    fn dev_config_stays_inside_its_directory() {
        let c = UnihelmConfig::for_dev(Path::new("/tmp/unihelm-dev"));
        assert!(c.panel.database.starts_with("/tmp/unihelm-dev"));
        assert!(c.agent.socket.starts_with("/tmp/unihelm-dev"));
        assert!(c.validate().is_ok());
    }
}
