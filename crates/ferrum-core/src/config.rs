//! The bootstrap configuration both daemons read (spec §4.3).
//!
//! Deliberately tiny. Everything that can live in the database *does* live in the
//! database, so that changing it is an audited API call rather than an SSH
//! session and a restart. What stays in `/etc/ferrum/config.toml` is only what is
//! needed to reach the database in the first place.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Where the packaged install expects its files.
pub mod paths {
    pub const CONFIG: &str = "/etc/ferrum/config.toml";
    pub const SECRET_KEY: &str = "/etc/ferrum/secret.key";
    pub const DATA_DIR: &str = "/var/lib/ferrum";
    pub const DATABASE: &str = "/var/lib/ferrum/panel.db";
    pub const STATE_DIR: &str = "/var/lib/ferrum/state";
    pub const RUNTIME_DIR: &str = "/run/ferrum";
    pub const AGENT_SOCKET: &str = "/run/ferrum/agent.sock";
    pub const LOG_DIR: &str = "/var/log/ferrum";
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FerrumConfig {
    pub panel: PanelConfig,
    pub agent: AgentConfig,
    pub log: LogConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PanelConfig {
    /// Where `ferrum-web` listens. Bind to a loopback address and put the panel
    /// behind its own managed vhost if you want it on 443.
    pub listen: String,
    pub database: PathBuf,
    pub state_dir: PathBuf,
    /// Unix socket for the CLI, so `ferrum` works without a network round trip.
    pub cli_socket: PathBuf,
    /// Send session cookies with the `Secure` attribute.
    ///
    /// On by default — the panel is expected to be reached over TLS. Turning it
    /// off is for plain-HTTP development only, and the panel says so at startup.
    pub secure_cookies: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    pub socket: PathBuf,
    /// The unprivileged account `ferrum-web` runs as. The agent resolves this to
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
    /// Human-readable, for `ferrum dev`.
    Text,
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            // Loopback by default: exposing a brand-new panel to the internet
            // should be a decision somebody typed, not what happens if they
            // don't (spec §12 rule 8).
            listen: "127.0.0.1:8088".into(),
            database: PathBuf::from(paths::DATABASE),
            state_dir: PathBuf::from(paths::STATE_DIR),
            cli_socket: PathBuf::from("/run/ferrum/web.sock"),
            secure_cookies: true,
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            socket: PathBuf::from(paths::AGENT_SOCKET),
            web_user: "ferrum".into(),
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

impl FerrumConfig {
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
                listen: "127.0.0.1:8088".into(),
                database: dir.join("panel.db"),
                state_dir: dir.join("state"),
                cli_socket: dir.join("web.sock"),
                // Dev runs on plain http://127.0.0.1, where a Secure cookie
                // would simply never be sent back.
                secure_cookies: false,
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
/// keeping the parse in-crate means `ferrum-core` stays dependency-light for
/// everything that links it. If the config ever grows arrays or nesting, replace
/// this with the `toml` crate in the binaries rather than growing it here.
mod toml_lite {
    use super::{FerrumConfig, LogFormat};
    use std::path::PathBuf;

    pub fn parse(text: &str) -> Result<FerrumConfig, String> {
        let mut cfg = FerrumConfig::default();
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

    #[test]
    fn defaults_are_safe() {
        let c = FerrumConfig::default();
        assert!(
            c.panel.listen.starts_with("127.0.0.1"),
            "a fresh panel must not be world-facing"
        );
        assert_eq!(c.agent.web_user, "ferrum");
        assert!(c.validate().is_ok());
    }

    #[test]
    fn parses_a_full_config() {
        let text = r#"
# Ferrum panel configuration

[panel]
listen = "0.0.0.0:8443"        # exposed on purpose
database = "/var/lib/ferrum/panel.db"
state_dir = "/var/lib/ferrum/state"

[agent]
socket = "/run/ferrum/agent.sock"
web_user = "ferrum"
workers = 4

[log]
level = "debug"
format = "text"
"#;
        let c = FerrumConfig::from_toml(text).unwrap();
        assert_eq!(c.panel.listen, "0.0.0.0:8443");
        assert_eq!(c.agent.workers, 4);
        assert_eq!(c.log.format, LogFormat::Text);
        assert_eq!(c.panel.database, PathBuf::from("/var/lib/ferrum/panel.db"));
    }

    #[test]
    fn an_empty_config_is_the_defaults() {
        assert_eq!(
            FerrumConfig::from_toml("").unwrap(),
            FerrumConfig::default()
        );
        assert_eq!(
            FerrumConfig::from_toml("\n\n# only comments\n").unwrap(),
            FerrumConfig::default()
        );
    }

    #[test]
    fn a_typo_is_an_error_not_a_silent_default() {
        // The failure this guards against: `lisen = "0.0.0.0:8443"` parsing fine
        // and the panel quietly staying on loopback.
        let err = FerrumConfig::from_toml("[panel]\nlisen = \"0.0.0.0:8443\"").unwrap_err();
        assert!(err.contains("unknown key"), "got: {err}");
        assert!(
            err.contains("line 2"),
            "errors should point at the line: {err}"
        );

        assert!(FerrumConfig::from_toml("[pannel]\nlisten = \"x\"").is_err());
        assert!(
            FerrumConfig::from_toml("listen = \"x\"").is_err(),
            "keys need a table"
        );
        assert!(FerrumConfig::from_toml("[agent]\nworkers = many").is_err());
        assert!(FerrumConfig::from_toml("[log]\nformat = \"xml\"").is_err());
        assert!(FerrumConfig::from_toml("[panel]\nlisten").is_err());
    }

    #[test]
    fn hashes_inside_quotes_are_not_comments() {
        let c =
            FerrumConfig::from_toml("[log]\nlevel = \"ferrum_web=debug,tower_http=info\"").unwrap();
        assert_eq!(c.log.level, "ferrum_web=debug,tower_http=info");
        let c = FerrumConfig::from_toml("[panel]\nstate_dir = \"/srv/a#b\"").unwrap();
        assert_eq!(c.panel.state_dir, PathBuf::from("/srv/a#b"));
    }

    #[test]
    fn secure_cookies_default_on_and_parse_as_booleans() {
        assert!(FerrumConfig::default().panel.secure_cookies);
        assert!(
            !FerrumConfig::from_toml("[panel]\nsecure_cookies = false")
                .unwrap()
                .panel
                .secure_cookies
        );
        assert!(FerrumConfig::from_toml("[panel]\nsecure_cookies = yes").is_err());
    }

    #[test]
    fn validation_catches_nonsense() {
        let mut c = FerrumConfig::default();
        c.panel.listen = "not-an-address".into();
        assert!(c.validate().is_err());

        let mut c = FerrumConfig::default();
        c.agent.workers = 0;
        assert!(c.validate().is_err());

        let mut c = FerrumConfig::default();
        c.agent.socket = PathBuf::from("relative/agent.sock");
        assert!(c.validate().is_err());
    }

    #[test]
    fn dev_config_stays_inside_its_directory() {
        let c = FerrumConfig::for_dev(Path::new("/tmp/ferrum-dev"));
        assert!(c.panel.database.starts_with("/tmp/ferrum-dev"));
        assert!(c.agent.socket.starts_with("/tmp/ferrum-dev"));
        assert!(c.validate().is_ok());
    }
}
