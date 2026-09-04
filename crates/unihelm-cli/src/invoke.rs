//! Turning a parsed command line into an operation call (spec §11.20).
//!
//! Everything in here is a pure function: command line in, operation name and
//! JSON payload out. That is deliberate, and it is what makes the CLI testable
//! without a root agent, a socket or a database — the tests below are the only
//! honest way to check that `unihelm site create` sends what `site.create`
//! expects, short of running a server.
//!
//! Two things this module refuses to do:
//!
//! - **Validate.** `Domain`, `PhpVersion`, `DbName` and friends already parse
//!   themselves inside the operation, and the agent re-parses whatever the CLI
//!   sends whether the CLI checked it or not. A second copy of the rules here
//!   would drift from the first and start disagreeing about what is legal
//!   (spec §12 rule 3). Anything shaped like a value goes over the wire as a
//!   string and comes back as a typed error.
//! - **Read.** Secrets arrive already resolved in [`Secrets`], so this module
//!   never touches stdin or the environment and every test can hand it a fixed
//!   value.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::cli::*;

/// One operation call: a registry name and the JSON its input type parses.
#[derive(Debug, Clone, PartialEq)]
pub struct Invocation {
    pub op: &'static str,
    pub input: Value,
}

impl Invocation {
    fn new(op: &'static str, input: Value) -> Self {
        Self { op, input }
    }
}

/// What the executor should do with a command.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// One operation, one round trip.
    Call(Invocation),
    /// Read Sentinel's settings, apply the flags that were given, write the
    /// whole struct back.
    ///
    /// `sentinel.settings.set` takes every field, with no serde defaults — so a
    /// CLI that sent only `--enabled true` would silently reset the ban window
    /// and the allowlist. Read-modify-write is the only spelling of "change one
    /// knob" that does not quietly destroy the others.
    MergeSentinelSettings(SentinelPatch),
    /// The CLI answers this one itself: accounts, tasks, health, completions.
    Local,
}

/// The Sentinel fields a `settings-set` invocation wants changed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SentinelPatch {
    pub enabled: Option<bool>,
    pub ssh_threshold: Option<u32>,
    pub window_minutes: Option<u32>,
    pub ban_minutes: Option<u32>,
    pub allowlist: Option<Vec<String>>,
}

impl SentinelPatch {
    /// Fold the patch into the settings the agent just returned.
    pub fn apply(&self, mut current: Value) -> Value {
        let Some(map) = current.as_object_mut() else {
            return current;
        };
        if let Some(v) = self.enabled {
            map.insert("enabled".into(), v.into());
        }
        if let Some(v) = self.ssh_threshold {
            map.insert("ssh_threshold".into(), v.into());
        }
        if let Some(v) = self.window_minutes {
            map.insert("window_minutes".into(), v.into());
        }
        if let Some(v) = self.ban_minutes {
            map.insert("ban_minutes".into(), v.into());
        }
        if let Some(list) = &self.allowlist {
            // `--allowlist ''` arrives as one empty element and means "clear",
            // which is the only way a value-taking flag can express emptiness.
            let cleaned: Vec<Value> = list
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| Value::from(s.to_string()))
                .collect();
            map.insert("allowlist".into(), Value::Array(cleaned));
        }
        current
    }
}

/// Secret material, resolved by the caller before planning starts.
///
/// Separating this from the command line is what keeps [`action_for`] pure: the
/// stdin read and the environment lookup happen once, in `main`, where they can
/// fail loudly.
#[derive(Debug, Clone, Default)]
pub struct Secrets {
    pub dns_token: Option<String>,
    pub s3_secret_access_key: Option<String>,
    pub sftp_password: Option<String>,
    pub mail_relay_password: Option<String>,
}

// ---------------------------------------------------------------------------
// the planner
// ---------------------------------------------------------------------------

/// `{"component": "mariadb", "version": "11.4"}`, with the version left out when
/// the caller has no opinion.
///
/// No whitelist here on purpose. It used to be a `ValueEnum` of four names,
/// which is why the CLI could install four things; the catalogue in the agent is
/// the list now, and it refuses anything not in it — one place to add an engine
/// rather than three that have to agree.
fn component_value(component: &str, version: Option<&str>) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("component".into(), json!(component));
    if let Some(v) = version {
        m.insert("version".into(), json!(v));
    }
    serde_json::Value::Object(m)
}

/// Map a parsed command onto the operation it invokes.
pub fn action_for(command: &Command, secrets: &Secrets) -> Result<Action> {
    let action = match command {
        // Handled by the CLI itself; see main.rs.
        Command::Doctor
        | Command::User(_)
        | Command::Ops(OpsCommand::List)
        | Command::Task(_)
        | Command::Completions { .. } => Action::Local,

        // The nearest thing to "is the agent there, and which one is it".
        Command::Ops(OpsCommand::Agent) => call("sys.ping", json!({})),

        // `status` is a metrics snapshot with a hand-written renderer.
        Command::Status => call("metrics.snapshot", json!({})),

        Command::Site(cmd) => site(cmd)?,
        Command::Docker(cmd) => match cmd {
            DockerCommand::List => call("docker.list", json!({})),
            DockerCommand::Start { container } => {
                call("docker.start", json!({ "container": container }))
            }
            DockerCommand::Stop { container } => {
                call("docker.stop", json!({ "container": container }))
            }
            DockerCommand::Restart { container } => {
                call("docker.restart", json!({ "container": container }))
            }
            DockerCommand::Remove { container } => {
                call("docker.remove", json!({ "container": container }))
            }
            DockerCommand::Logs { container, lines } => {
                let input = Input::new()
                    .set("container", container.clone())
                    .maybe("lines", *lines)
                    .done();
                call("docker.logs", input)
            }
        },
        Command::Runtime(cmd) => match cmd {
            RuntimeCommand::List => call("runtime.list", json!({})),
            RuntimeCommand::SetDefault { runtime, version } => call(
                "runtime.default.set",
                json!({ "runtime": runtime, "version": version }),
            ),
            RuntimeCommand::Install { major } => call("runtime.install", json!({ "major": major })),
        },
        Command::Php(cmd) => php(cmd),
        Command::Stack(cmd) => stack(cmd)?,
        Command::Db(cmd) => db(cmd),
        Command::Backup(cmd) => backup(cmd, secrets)?,
        Command::Cron(cmd) => cron(cmd),
        Command::Dns(cmd) => dns(cmd, secrets)?,
        Command::Firewall(cmd) => firewall(cmd),
        Command::App(cmd) => app(cmd)?,
        Command::Wordpress(cmd) => wordpress(cmd),
        Command::Plan(cmd) => plan(cmd),
        Command::Subscription(cmd) => subscription(cmd),
        Command::Cert(cmd) => cert(cmd),
        Command::Svc(cmd) => svc(cmd)?,
        Command::Waf(cmd) => waf(cmd)?,
        Command::Alert(cmd) => alert(cmd)?,
        Command::Webhook(cmd) => webhook(cmd)?,
        Command::Plugin(cmd) => plugin(cmd)?,
        Command::Import(cmd) => import(cmd)?,
        Command::SshKeys(cmd) => ssh_keys(cmd),
        Command::Mail(cmd) => mail(cmd, secrets),
        Command::Branding(cmd) => branding(cmd),
        Command::Quota(cmd) => quota(cmd),
        Command::Sftp(cmd) => sftp(cmd, secrets),
        Command::Security(SecurityCommand::Posture) => call("security.posture", json!({})),
    };
    Ok(action)
}

fn call(op: &'static str, input: Value) -> Action {
    Action::Call(Invocation::new(op, input))
}

// ---------------------------------------------------------------------------
// per-area builders
// ---------------------------------------------------------------------------

fn site(cmd: &SiteCommand) -> Result<Action> {
    Ok(match cmd {
        SiteCommand::List(page) => call("site.list", paged(*page)),
        SiteCommand::Discover => call("sites.discover", json!({})),
        SiteCommand::Create {
            domain,
            kind,
            php,
            subscription,
            with_www,
            proxy_port,
            redirect_to,
        } => {
            let site_type = match kind {
                SiteKind::Php => "php",
                SiteKind::Static => "static",
                SiteKind::Proxy => "proxy",
                SiteKind::Redirect => "redirect",
            };
            let input = Input::new()
                .set("domain", domain.clone())
                .set("site_type", site_type)
                .set("with_www", *with_www)
                .maybe("php_version", php.clone())
                .maybe("subscription_id", *subscription)
                .maybe("proxy_port", *proxy_port)
                .maybe("redirect_target", redirect_to.clone())
                .done();
            call("site.create", input)
        }
        SiteCommand::Update {
            site_id,
            php,
            force_https,
            http3,
            maintenance,
            client_max_body_size,
            rate_limit,
            www,
            nginx_snippet,
            clear_nginx_snippet,
            php_ini,
            clear_php_ini,
        } => {
            let www_policy = www.map(|w| match w {
                WwwPolicyArg::None => "none",
                WwwPolicyArg::Add => "add",
                WwwPolicyArg::Strip => "strip",
            });
            let input = Input::new()
                .set("site_id", *site_id)
                .maybe("php_version", php.clone())
                .maybe("force_https", *force_https)
                .maybe("http3", *http3)
                .maybe("maintenance_mode", *maintenance)
                .maybe("client_max_body_size", client_max_body_size.clone())
                .maybe("rate_limit_enabled", *rate_limit)
                .maybe("www_policy", www_policy)
                // `Option<Option<String>>` on the operation: absent leaves the
                // snippet alone, an explicit null removes it. The CLI spells
                // that second case `--clear-…` so it cannot happen by accident.
                .nullable(
                    "custom_nginx_snippet",
                    nginx_snippet.clone(),
                    *clear_nginx_snippet,
                )
                .nullable("php_ini_overrides", php_ini.clone(), *clear_php_ini)
                .done();
            call("site.update", input)
        }
        SiteCommand::Delete {
            site_id,
            purge_files,
        } => call(
            "site.delete",
            json!({ "site_id": site_id, "purge_files": purge_files }),
        ),
        SiteCommand::Drift { site_id } => call("site.drift", json!({ "site_id": site_id })),
    })
}

fn php(cmd: &PhpCommand) -> Action {
    match cmd {
        // There is no `php.list` operation and there should not be one: what is
        // installed is the Stack Manager's answer, and asking twice invites two
        // answers that disagree.
        PhpCommand::List => call("stack.status", json!({})),
        PhpCommand::Install {
            version,
            extensions,
        } => call(
            "stack.install",
            json!({
                "component": "php",
                "version": version,
                "extensions": extensions,
            }),
        ),
    }
}

fn stack(cmd: &StackCommand) -> Result<Action> {
    Ok(match cmd {
        StackCommand::Status => call("stack.status", json!({})),
        StackCommand::Install {
            component,
            version,
            extensions,
        } => {
            let mut input = component_value(component, version.as_deref());
            if let Some(map) = input.as_object_mut() {
                map.insert("extensions".into(), json!(extensions));
            }
            call("stack.install", input)
        }
        StackCommand::Remove { component, version } => call(
            "stack.remove",
            component_value(component, version.as_deref()),
        ),
    })
}

fn db(cmd: &DbCommand) -> Action {
    match cmd {
        DbCommand::List(page) => call("db.list", paged(*page)),
        DbCommand::Create {
            name,
            engine,
            subscription,
            owner,
        } => {
            let input = Input::new()
                .set("name", name.clone())
                .set("engine", engine_str(*engine))
                .maybe("subscription_id", *subscription)
                .maybe("owner", owner.clone())
                .done();
            call("db.create", input)
        }
        DbCommand::Drop {
            database_id,
            confirm_name,
        } => call(
            "db.drop",
            json!({ "database_id": database_id, "confirm_name": confirm_name }),
        ),
        DbCommand::User(DbUserCommand::Create {
            username,
            engine,
            subscription,
        }) => {
            let input = Input::new()
                .set("username", username.clone())
                .set("engine", engine_str(*engine))
                .maybe("subscription_id", *subscription)
                .done();
            call("db.user.create", input)
        }
        DbCommand::User(DbUserCommand::Drop { username }) => {
            call("db.user.drop", json!({ "username": username }))
        }
        DbCommand::User(DbUserCommand::Password { username }) => {
            call("db.user.password", json!({ "username": username }))
        }
        DbCommand::Grant { database, user } => call(
            "db.grant",
            json!({ "database": database, "username": user }),
        ),
        DbCommand::Adminer(AdminerCommand::Status) => call("db.adminer.status", json!({})),
        DbCommand::Adminer(AdminerCommand::Enable) => call("db.adminer.enable", json!({})),
        DbCommand::Adminer(AdminerCommand::Disable) => call("db.adminer.disable", json!({})),
    }
}

fn engine_str(engine: DbEngineArg) -> &'static str {
    match engine {
        DbEngineArg::Mysql => "mysql",
        DbEngineArg::Postgres => "postgres",
    }
}

fn backup(cmd: &BackupCommand, secrets: &Secrets) -> Result<Action> {
    Ok(match cmd {
        BackupCommand::Repo(BackupRepoCommand::Init {
            kind,
            label,
            path,
            s3_access_key_id,
            s3_region,
            s3_secret_stdin: _,
        }) => {
            let kind_str = match kind {
                RepoKindArg::Local => "local",
                RepoKindArg::S3 => "s3",
            };
            let mut input = Input::new()
                .set("kind", kind_str)
                .set("label", label.clone())
                .set("path_or_url", path.clone());
            if *kind == RepoKindArg::S3 {
                let access_key_id = s3_access_key_id
                    .clone()
                    .context("an s3 repository needs --s3-access-key-id")?;
                let secret = secrets.s3_secret_access_key.clone().context(
                    "an s3 repository needs its secret key: pass --s3-secret-stdin or set \
                     UNIHELM_S3_SECRET_ACCESS_KEY",
                )?;
                let s3 = Input::new()
                    .set("access_key_id", access_key_id)
                    .set("secret_access_key", secret)
                    .maybe("region", s3_region.clone())
                    .done();
                input = input.set("s3", s3);
            }
            call("backup.repo.init", input.done())
        }
        BackupCommand::Repo(BackupRepoCommand::Delete { repo_id }) => {
            call("backup.repo.delete", json!({ "repo_id": repo_id }))
        }
        BackupCommand::Run {
            repo,
            scope,
            subscription,
        } => {
            let input = Input::new()
                .set("repo_id", *repo)
                .set("scope", scope_str(*scope))
                .maybe("subscription_id", *subscription)
                .done();
            call("backup.run", input)
        }
        BackupCommand::List { repo, subscription } => {
            let input = Input::new()
                .set("repo_id", *repo)
                .maybe("subscription_id", *subscription)
                .done();
            call("backup.list", input)
        }
        BackupCommand::Restore { repo, snapshot } => call(
            "backup.restore",
            json!({ "repo_id": repo, "snapshot_id": snapshot }),
        ),
        BackupCommand::Schedule(BackupScheduleCommand::Set {
            repo,
            scope,
            subscription,
            cron,
            keep_daily,
            keep_weekly,
            keep_monthly,
            disabled,
        }) => {
            let input = Input::new()
                .set("repo_id", *repo)
                .set("scope", scope_str(*scope))
                .set("cron", cron.clone())
                .set("enabled", !*disabled)
                .maybe("subscription_id", *subscription)
                .maybe("keep_daily", *keep_daily)
                .maybe("keep_weekly", *keep_weekly)
                .maybe("keep_monthly", *keep_monthly)
                .done();
            call("backup.schedule.set", input)
        }
        BackupCommand::Schedule(BackupScheduleCommand::Delete { schedule_id }) => call(
            "backup.schedule.delete",
            json!({ "schedule_id": schedule_id }),
        ),
    })
}

fn scope_str(scope: BackupScopeArg) -> &'static str {
    match scope {
        BackupScopeArg::Panel => "panel",
        BackupScopeArg::Subscription => "subscription",
    }
}

fn cron(cmd: &CronCommand) -> Action {
    match cmd {
        CronCommand::List { subscription, page } => {
            let input = Input::new()
                .maybe("subscription_id", *subscription)
                .maybe("limit", page.limit)
                .maybe("offset", page.offset)
                .done();
            call("cron.list", input)
        }
        CronCommand::Set {
            schedule,
            command,
            id,
            subscription,
            disabled,
        } => {
            let input = Input::new()
                .set("schedule", schedule.clone())
                .set("command", command.clone())
                .set("enabled", !*disabled)
                .maybe("id", *id)
                .maybe("subscription_id", *subscription)
                .done();
            call("cron.set", input)
        }
        CronCommand::Delete { id } => call("cron.delete", json!({ "id": id })),
    }
}

fn dns(cmd: &DnsCommand, secrets: &Secrets) -> Result<Action> {
    Ok(match cmd {
        DnsCommand::Check { domain } => call("dns.check", json!({ "domain": domain })),
        DnsCommand::ProviderSet {
            kind,
            label,
            token_stdin: _,
        } => {
            let token = secrets.dns_token.clone().context(
                "the provider token must come from stdin or the environment: pass --token-stdin \
                 or set UNIHELM_DNS_TOKEN",
            )?;
            let kind = match kind {
                DnsProviderArg::Cloudflare => "cloudflare",
            };
            call(
                "dns.provider.set",
                json!({ "kind": kind, "label": label, "token": token }),
            )
        }
        DnsCommand::IssueWildcard {
            site_id,
            staging,
            contact_email,
        } => {
            let input = Input::new()
                .set("site_id", *site_id)
                .set("staging", *staging)
                .maybe("contact_email", contact_email.clone())
                .done();
            call("cert.issue_wildcard", input)
        }
    })
}

fn firewall(cmd: &FirewallCommand) -> Action {
    match cmd {
        FirewallCommand::Rules => call("fw.rules", json!({})),
        FirewallCommand::Enable => call("fw.enable", json!({})),
        FirewallCommand::Disable => call("fw.disable", json!({})),
        FirewallCommand::Open {
            port,
            proto,
            source,
            comment,
        } => {
            let input = Input::new()
                .set("port", *port)
                .set("proto", proto_str(*proto))
                .maybe("source", source.clone())
                .maybe("comment", comment.clone())
                .done();
            call("fw.port.open", input)
        }
        FirewallCommand::Close {
            port,
            proto,
            source,
        } => {
            let input = Input::new()
                .set("port", *port)
                .set("proto", proto_str(*proto))
                .maybe("source", source.clone())
                .done();
            call("fw.port.close", input)
        }
        FirewallCommand::Ban {
            ip,
            minutes,
            reason,
        } => {
            let input = Input::new()
                .set("ip", ip.clone())
                .maybe("minutes", *minutes)
                .maybe("reason", reason.clone())
                .done();
            call("fw.ban", input)
        }
        FirewallCommand::Unban { ip } => call("fw.unban", json!({ "ip": ip })),
        FirewallCommand::Bans { limit } => {
            call("fw.bans", Input::new().maybe("limit", *limit).done())
        }
        FirewallCommand::Settings => call("sentinel.settings", json!({})),
        FirewallCommand::SettingsSet {
            enabled,
            ssh_threshold,
            window_minutes,
            ban_minutes,
            allowlist,
        } => Action::MergeSentinelSettings(SentinelPatch {
            enabled: *enabled,
            ssh_threshold: *ssh_threshold,
            window_minutes: *window_minutes,
            ban_minutes: *ban_minutes,
            allowlist: allowlist.clone(),
        }),
    }
}

fn proto_str(proto: ProtoArg) -> &'static str {
    match proto {
        ProtoArg::Tcp => "tcp",
        ProtoArg::Udp => "udp",
    }
}

fn app(cmd: &AppCommand) -> Result<Action> {
    Ok(match cmd {
        AppCommand::List(page) => call("app.list", paged(*page)),
        AppCommand::Create {
            name,
            entry,
            subscription,
            env,
            node_env,
            memory_mb,
            proxy_domain,
            runtime_version,
            runtime,
        } => {
            let node_env = node_env.map(|e| match e {
                NodeEnvArg::Production => "production",
                NodeEnvArg::Development => "development",
                NodeEnvArg::Test => "test",
            });
            let input = Input::new()
                .set("name", name.clone())
                .set("entry", entry.clone())
                .set("env", Value::Array(parse_env(env)?))
                .maybe("subscription_id", *subscription)
                .maybe("node_env", node_env)
                .maybe("memory_mb", *memory_mb)
                .maybe("proxy_domain", proxy_domain.clone())
                .maybe("runtime_version", runtime_version.clone())
                .maybe("runtime", runtime.clone())
                .done();
            call("app.create", input)
        }
        AppCommand::Delete { app_id } => call("app.delete", json!({ "app_id": app_id })),
        AppCommand::Restart { app_id } => call("app.restart", json!({ "app_id": app_id })),
        AppCommand::Update {
            app_id,
            runtime,
            runtime_version,
            unpin,
        } => {
            let mut input = json!({ "app_id": app_id });
            if let Some(r) = runtime {
                input["runtime"] = json!(r);
            }
            // `--unpin` sends an explicit null, which is what tells the
            // operation to go back to the default rather than to leave the
            // pin alone. Omitting the key entirely is the "leave it" case.
            if *unpin {
                input["runtime_version"] = serde_json::Value::Null;
            } else if let Some(v) = runtime_version {
                input["runtime_version"] = json!(v);
            }
            call("app.update", input)
        }
        AppCommand::Logs { app_id, lines } => {
            let input = Input::new()
                .set("app_id", *app_id)
                .maybe("lines", *lines)
                .done();
            call("app.logs", input)
        }
    })
}

/// `KEY=VALUE` pairs, split on the *first* `=`.
///
/// Splitting on the last one would mangle every value that legitimately
/// contains an equals sign — a base64 padding, a connection string, a JWT.
pub fn parse_env(pairs: &[String]) -> Result<Vec<Value>> {
    pairs
        .iter()
        .map(|pair| {
            let Some((key, value)) = pair.split_once('=') else {
                bail!("`{pair}` is not KEY=VALUE");
            };
            if key.is_empty() {
                bail!("`{pair}` has an empty name");
            }
            Ok(json!({ "key": key, "value": value }))
        })
        .collect()
}

fn wordpress(cmd: &WordpressCommand) -> Action {
    match cmd {
        WordpressCommand::Install {
            site_id,
            title,
            admin_user,
            admin_email,
            subdirectory,
            locale,
            auto_update,
        } => {
            let input = Input::new()
                .set("site_id", *site_id)
                .set("title", title.clone())
                .set("admin_user", admin_user.clone())
                .set("admin_email", admin_email.clone())
                .set("auto_update", *auto_update)
                .maybe("subdirectory", subdirectory.clone())
                .maybe("locale", locale.clone())
                .done();
            call("wp.install", input)
        }
        WordpressCommand::Detect {
            site_id,
            subdirectory,
        } => {
            let input = Input::new()
                .set("site_id", *site_id)
                .maybe("subdirectory", subdirectory.clone())
                .done();
            call("wp.detect", input)
        }
        WordpressCommand::Update {
            install_id,
            version,
            no_update_db,
        } => {
            let input = Input::new()
                .set("install_id", *install_id)
                .set("update_db", !*no_update_db)
                .maybe("version", version.clone())
                .done();
            call("wp.update", input)
        }
        WordpressCommand::Plugin(WpPluginCommand::List { install_id }) => {
            call("wp.plugin.list", json!({ "install_id": install_id }))
        }
        WordpressCommand::Plugin(WpPluginCommand::Update {
            install_id,
            plugins,
        }) => call(
            "wp.plugin.update",
            json!({ "install_id": install_id, "plugins": plugins }),
        ),
        WordpressCommand::Cli {
            install_id,
            subcommand,
            args,
        } => {
            let group = match subcommand {
                WpSubcommandArg::Core => "core",
                WpSubcommandArg::Plugin => "plugin",
                WpSubcommandArg::Theme => "theme",
                WpSubcommandArg::Option => "option",
                WpSubcommandArg::User => "user",
                WpSubcommandArg::Db => "db",
                WpSubcommandArg::Cache => "cache",
                WpSubcommandArg::Rewrite => "rewrite",
            };
            call(
                "wp.cli",
                json!({ "install_id": install_id, "subcommand": group, "args": args }),
            )
        }
    }
}

fn plan(cmd: &PlanCommand) -> Action {
    match cmd {
        PlanCommand::List(page) => call("plan.list", paged(*page)),
        PlanCommand::Create {
            name,
            max_sites,
            max_dbs,
            storage_mb,
            can_ssh,
            can_cron,
            can_node_apps,
        } => {
            let input = Input::new()
                .set("name", name.clone())
                .set("max_sites", *max_sites)
                .set("max_dbs", *max_dbs)
                .set("storage_mb", *storage_mb)
                .set("can_ssh", *can_ssh)
                .set("can_node_apps", *can_node_apps)
                // Absent means "whatever the operation defaults to", which is on.
                .maybe("can_cron", *can_cron)
                .done();
            call("plan.create", input)
        }
        PlanCommand::Update {
            plan_id,
            name,
            max_sites,
            max_dbs,
            storage_mb,
            can_ssh,
            can_cron,
            can_node_apps,
        } => {
            let input = Input::new()
                .set("plan_id", *plan_id)
                .maybe("name", name.clone())
                .maybe("max_sites", *max_sites)
                .maybe("max_dbs", *max_dbs)
                .maybe("storage_mb", *storage_mb)
                .maybe("can_ssh", *can_ssh)
                .maybe("can_cron", *can_cron)
                .maybe("can_node_apps", *can_node_apps)
                .done();
            call("plan.update", input)
        }
        PlanCommand::Delete { plan_id } => call("plan.delete", json!({ "plan_id": plan_id })),
        PlanCommand::Assign { subscription, plan } => call(
            "plan.assign",
            json!({ "subscription_id": subscription, "plan_id": plan }),
        ),
    }
}

fn subscription(cmd: &SubscriptionCommand) -> Action {
    match cmd {
        SubscriptionCommand::List(page) => call("subscription.list", paged(*page)),
        SubscriptionCommand::Suspend {
            subscription_id,
            reason,
        } => call(
            "subscription.suspend",
            json!({ "subscription_id": subscription_id, "reason": reason }),
        ),
        SubscriptionCommand::Unsuspend { subscription_id } => call(
            "subscription.unsuspend",
            json!({ "subscription_id": subscription_id }),
        ),
    }
}

fn cert(cmd: &CertCommand) -> Action {
    match cmd {
        CertCommand::List => call("cert.list", json!({})),
        CertCommand::Issue {
            site_id,
            staging,
            contact_email,
        } => {
            let input = Input::new()
                .set("site_id", *site_id)
                .set("staging", *staging)
                .maybe("contact_email", contact_email.clone())
                .done();
            call("cert.issue", input)
        }
        CertCommand::Panel {
            domain,
            contact_email,
            staging,
        } => {
            let input = Input::new()
                .set("domain", domain.clone())
                .set("staging", *staging)
                .maybe("contact_email", contact_email.clone())
                .done();
            call("panel.tls.issue", input)
        }
    }
}

fn svc(cmd: &SvcCommand) -> Result<Action> {
    Ok(match cmd {
        SvcCommand::Status { unit, version } => call(
            "svc.status",
            json!({ "unit": unit_value(*unit, version.as_deref())? }),
        ),
        SvcCommand::Action {
            unit,
            action,
            version,
        } => {
            let action = match action {
                SvcActionArg::Start => "start",
                SvcActionArg::Stop => "stop",
                SvcActionArg::Restart => "restart",
                SvcActionArg::Reload => "reload",
            };
            call(
                "svc.action",
                json!({ "unit": unit_value(*unit, version.as_deref())?, "action": action }),
            )
        }
    })
}

/// `ManagedUnit` is internally tagged on `unit`, so a PHP-FPM unit is
/// `{"unit":"php_fpm","version":"8.3"}` and everything else is just the tag.
fn unit_value(unit: UnitArg, version: Option<&str>) -> Result<Value> {
    let name = match unit {
        UnitArg::Nginx => "nginx",
        UnitArg::PhpFpm => "php_fpm",
        UnitArg::MariaDb => "maria_db",
        UnitArg::PostgreSql => "postgre_sql",
        UnitArg::KvStore => "kv_store",
        UnitArg::Docker => "docker",
        UnitArg::Sshd => "sshd",
        UnitArg::UnihelmWeb => "unihelm_web",
        UnitArg::UnihelmAgentd => "unihelm_agentd",
    };
    if unit == UnitArg::PhpFpm {
        let version = version.context("`php-fpm` needs --version, e.g. --version 8.3")?;
        return Ok(json!({ "unit": name, "version": version }));
    }
    Ok(json!({ "unit": name }))
}

fn waf(cmd: &WafCommand) -> Result<Action> {
    Ok(match cmd {
        WafCommand::Status => call("waf.status", json!({})),
        WafCommand::Enable {
            site,
            mode,
            paranoia,
        } => {
            let mode = mode.map(|m| match m {
                WafModeArg::Off => "off",
                WafModeArg::Detect => "detect",
                WafModeArg::Block => "block",
            });
            let input = Input::new()
                .maybe("site_id", *site)
                .maybe("mode", mode)
                .maybe("paranoia_level", *paranoia)
                .done();
            call("waf.enable", input)
        }
        WafCommand::Disable { site } => {
            call("waf.disable", Input::new().maybe("site_id", *site).done())
        }
        WafCommand::RulesSet { exclusions, site } => call(
            "waf.rules.set",
            json!({ "exclusions": parse_exclusions(exclusions, *site)? }),
        ),
    })
}

/// `RULE_ID=REASON` pairs. The reason is mandatory on purpose: an exclusion
/// nobody wrote a reason for is one nobody can ever safely remove.
pub fn parse_exclusions(items: &[String], site: Option<i64>) -> Result<Vec<Value>> {
    items
        .iter()
        .map(|item| {
            let Some((rule, reason)) = item.split_once('=') else {
                bail!("`{item}` is not RULE_ID=REASON");
            };
            let rule_id: i64 = rule
                .trim()
                .parse()
                .with_context(|| format!("`{rule}` is not a rule id"))?;
            let reason = reason.trim();
            if reason.is_empty() {
                bail!("exclusion for rule {rule_id} needs a reason");
            }
            Ok(Input::new()
                .set("rule_id", rule_id)
                .set("reason", reason.to_string())
                .maybe("site_id", site)
                .done())
        })
        .collect()
}

fn webhook(cmd: &WebhookCommand) -> Result<Action> {
    Ok(match cmd {
        WebhookCommand::List => call("webhook.list", json!({})),
        WebhookCommand::Set {
            url,
            event,
            id,
            disabled,
            rotate_secret,
        } => call(
            "webhook.set",
            json!({
                "id": id,
                "url": url,
                "events": event,
                // The operation defaults `active` to true, so the flag is
                // inverted here rather than defaulted twice in two places.
                "active": !disabled,
                "rotate_secret": rotate_secret,
            }),
        ),
        WebhookCommand::Delete { id } => call("webhook.delete", json!({ "id": id })),
        WebhookCommand::Test { id } => call("webhook.test", json!({ "id": id })),
    })
}

fn plugin(cmd: &PluginCommand) -> Result<Action> {
    Ok(match cmd {
        PluginCommand::List => call("plugin.list", json!({})),
        PluginCommand::Install { source } => call("plugin.install", json!({ "source": source })),
        PluginCommand::Enable { slug } => call("plugin.enable", json!({ "slug": slug })),
        PluginCommand::Disable { slug } => call("plugin.disable", json!({ "slug": slug })),
        PluginCommand::Remove { slug } => call("plugin.remove", json!({ "slug": slug })),
    })
}

fn ssh_keys(cmd: &SshKeysCommand) -> Action {
    match cmd {
        SshKeysCommand::List { subscription } => call(
            "ssh.keys.list",
            Input::new().maybe("subscription_id", *subscription).done(),
        ),
        SshKeysCommand::Add { key, subscription } => call(
            "ssh.keys.add",
            Input::new()
                .set("key", key.clone())
                .maybe("subscription_id", *subscription)
                .done(),
        ),
        SshKeysCommand::Remove {
            fingerprint,
            subscription,
        } => call(
            "ssh.keys.remove",
            Input::new()
                .set("fingerprint", fingerprint.clone())
                .maybe("subscription_id", *subscription)
                .done(),
        ),
    }
}

fn import(cmd: &ImportCommand) -> Result<Action> {
    Ok(match cmd {
        ImportCommand::Plan {
            source,
            path,
            subscription,
            php,
        } => {
            // `source` is a tagged enum on the operation side, and the two tags
            // do not carry the same field: cPanel names a tarball, aaPanel
            // names an installation root the operation defaults to `/www`.
            let source = match source {
                ImportSourceArg::Cpanel => Input::new().set("kind", "cpanel").set(
                    "path",
                    path.clone().context(
                        "`import plan --source cpanel` needs --path, the cpmove tarball",
                    )?,
                ),
                ImportSourceArg::Aapanel => Input::new()
                    .set("kind", "aapanel")
                    .maybe("root", path.clone()),
            };
            let input = Input::new()
                .set("source", source.done())
                .set("subscription_id", *subscription)
                .maybe("php_version", php.clone())
                .done();
            call("import.plan", input)
        }
        ImportCommand::List { plan, page } => {
            let input = Input::new()
                .maybe("plan_id", *plan)
                .maybe("limit", page.limit)
                .maybe("offset", page.offset)
                .done();
            call("import.list", input)
        }
        ImportCommand::Apply { plan_id } => call("import.apply", json!({ "plan_id": plan_id })),
    })
}

fn mail(cmd: &MailCommand, secrets: &Secrets) -> Action {
    match cmd {
        MailCommand::Relay(MailRelayCommand::Get) => call("mail.relay.get", json!({})),
        MailCommand::DnsPublish { apply } => call("mail.dns.publish", json!({ "apply": apply })),
        MailCommand::Relay(MailRelayCommand::Set {
            host,
            port,
            tls,
            from,
            from_name,
            username,
            password_stdin: _,
            enabled,
        }) => {
            let tls_mode = match tls {
                TlsModeArg::None => "none",
                TlsModeArg::Starttls => "starttls",
                TlsModeArg::Implicit => "implicit",
            };
            let input = Input::new()
                .set("host", host.clone())
                .set("port", *port)
                .set("tls_mode", tls_mode)
                .set("from_address", from.clone())
                .maybe("from_name", from_name.clone())
                .maybe("username", username.clone())
                // Absent means "keep the stored one". The password is
                // write-only, so a missing key is the only way to say it.
                .maybe("password", secrets.mail_relay_password.clone())
                .maybe("enabled", *enabled)
                .done();
            call("mail.relay.set", input)
        }
        MailCommand::Relay(MailRelayCommand::Test { to }) => call(
            "mail.relay.test",
            Input::new().maybe("to", to.clone()).done(),
        ),
    }
}

fn branding(cmd: &BrandingCommand) -> Action {
    match cmd {
        BrandingCommand::Get { reseller } => call(
            "branding.get",
            Input::new().maybe("reseller_id", *reseller).done(),
        ),
        BrandingCommand::Set {
            reseller,
            panel_name,
            support_url,
            primary_color,
            login_host,
            clear,
            clear_logo,
            clear_favicon,
            clear_login_background,
        } => {
            let cleared: Vec<Value> = clear
                .iter()
                .map(|field| {
                    Value::from(match field {
                        BrandingFieldArg::PanelName => "panel_name",
                        BrandingFieldArg::SupportUrl => "support_url",
                        BrandingFieldArg::PrimaryColor => "primary_color",
                        BrandingFieldArg::LoginHost => "login_host",
                    })
                })
                .collect();
            // An asset the operator said nothing about is left alone: the
            // operation defaults each one to `keep`, so the key stays absent
            // rather than being sent as an explicit no-op.
            let clear_asset = |yes: bool| yes.then(|| json!({ "action": "clear" }));
            let input = Input::new()
                .maybe("reseller_id", *reseller)
                .maybe("panel_name", panel_name.clone())
                .maybe("support_url", support_url.clone())
                .maybe("primary_color", primary_color.clone())
                .maybe("login_host", login_host.clone())
                .maybe("clear", (!cleared.is_empty()).then_some(cleared))
                .maybe("logo", clear_asset(*clear_logo))
                .maybe("favicon", clear_asset(*clear_favicon))
                .maybe("login_background", clear_asset(*clear_login_background))
                .done();
            call("branding.set", input)
        }
    }
}

fn alert(cmd: &AlertCommand) -> Result<Action> {
    Ok(match cmd {
        AlertCommand::Rules => call("alert.rules.list", json!({})),
        AlertCommand::RulesSet {
            kind,
            target,
            threshold,
            disabled,
        } => {
            let kind = match kind {
                AlertKindArg::DiskPct => "disk_pct",
                AlertKindArg::MemPct => "mem_pct",
                AlertKindArg::Load => "load",
                AlertKindArg::ServiceDown => "service_down",
                AlertKindArg::CertExpiryDays => "cert_expiry_days",
            };
            let input = Input::new()
                .set("kind", kind)
                .set("enabled", !*disabled)
                .maybe("target", target.clone())
                .maybe("threshold", *threshold)
                .done();
            call("alert.rules.set", input)
        }
        AlertCommand::Events { limit, open_only } => {
            let input = Input::new()
                .set("open_only", *open_only)
                .maybe("limit", *limit)
                .done();
            call("alert.events.list", input)
        }
        AlertCommand::Channels => call("alert.channels.list", json!({})),
        AlertCommand::ChannelsSet {
            id,
            kind,
            label,
            config_json: config,
            enabled,
        } => {
            let kind = kind.map(|k| match k {
                ChannelKindArg::Webhook => "webhook",
                ChannelKindArg::Telegram => "telegram",
            });
            let config =
                match config {
                    Some(raw) => Some(serde_json::from_str::<Value>(raw).context(
                        "--config must be a JSON object, e.g. '{\"url\":\"https://…\"}'",
                    )?),
                    None => None,
                };
            let input = Input::new()
                .maybe("id", *id)
                .maybe("kind", kind)
                .maybe("label", label.clone())
                .maybe("config", config)
                .maybe("enabled", *enabled)
                .done();
            call("alert.channels.set", input)
        }
        AlertCommand::ChannelsDelete { id } => call("alert.channels.delete", json!({ "id": id })),
        AlertCommand::ChannelsTest { id } => call("alert.channels.test", json!({ "id": id })),
    })
}

fn quota(cmd: &QuotaCommand) -> Action {
    match cmd {
        QuotaCommand::Backend => call("quota.backend", json!({})),
        QuotaCommand::Set {
            subscription_id,
            soft_mb,
            hard_mb,
        } => call(
            "quota.set",
            json!({ "subscription_id": subscription_id, "soft_mb": soft_mb, "hard_mb": hard_mb }),
        ),
        QuotaCommand::Usage { subscription_id } => {
            call("quota.usage", json!({ "subscription_id": subscription_id }))
        }
    }
}

fn sftp(cmd: &SftpCommand, secrets: &Secrets) -> Action {
    match cmd {
        SftpCommand::Enable {
            subscription_id,
            password_stdin: _,
        } => {
            let input = Input::new()
                .set("subscription_id", *subscription_id)
                .maybe("password", secrets.sftp_password.clone())
                .done();
            call("sftp.enable", input)
        }
        SftpCommand::Disable { subscription_id } => call(
            "sftp.disable",
            json!({ "subscription_id": subscription_id }),
        ),
    }
}

fn paged(page: Page) -> Value {
    Input::new()
        .maybe("limit", page.limit)
        .maybe("offset", page.offset)
        .done()
}

// ---------------------------------------------------------------------------
// payload builder
// ---------------------------------------------------------------------------

/// A JSON object under construction.
///
/// The distinction it exists to keep straight: **absent is not null**. Half the
/// update operations take `Option<T>` and read a missing key as "leave this
/// alone", so a builder that helpfully wrote `null` for every unset flag would
/// clear fields the user never mentioned.
#[derive(Debug, Default)]
struct Input(Map<String, Value>);

impl Input {
    fn new() -> Self {
        Self(Map::new())
    }

    fn set(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.0.insert(key.to_string(), value.into());
        self
    }

    fn maybe(mut self, key: &str, value: Option<impl Into<Value>>) -> Self {
        if let Some(value) = value {
            self.0.insert(key.to_string(), value.into());
        }
        self
    }

    /// A field whose operation type is `Option<Option<T>>`: absent leaves it,
    /// `clear` writes an explicit null, a value sets it.
    fn nullable(mut self, key: &str, value: Option<String>, clear: bool) -> Self {
        if clear {
            self.0.insert(key.to_string(), Value::Null);
        } else if let Some(value) = value {
            self.0.insert(key.to_string(), value.into());
        }
        self
    }

    fn done(self) -> Value {
        Value::Object(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Plan the command line the way `main` would, with no secrets available.
    fn plan_argv(argv: &[&str]) -> Result<Action> {
        let cli = Cli::try_parse_from(argv)?;
        action_for(&cli.command, &Secrets::default())
    }

    fn invocation(argv: &[&str]) -> Invocation {
        match plan_argv(argv).expect("should plan") {
            Action::Call(inv) => inv,
            other => panic!("{argv:?} planned {other:?}, not a call"),
        }
    }

    #[test]
    fn site_create_sends_only_the_fields_that_were_given() {
        let inv = invocation(&["unihelm", "site", "create", "example.com"]);
        assert_eq!(inv.op, "site.create");
        assert_eq!(inv.input["domain"], "example.com");
        assert_eq!(inv.input["site_type"], "php");
        assert_eq!(inv.input["with_www"], false);
        // The keys nobody asked about must be missing, not null: `site.create`
        // reads a null `php_version` as "no PHP", not as "your choice".
        assert!(inv.input.get("php_version").is_none());
        assert!(inv.input.get("proxy_port").is_none());
        assert!(inv.input.get("subscription_id").is_none());
    }

    #[test]
    fn site_update_distinguishes_leaving_a_snippet_from_clearing_it() {
        let untouched = invocation(&["unihelm", "site", "update", "7"]);
        assert!(
            untouched.input.get("custom_nginx_snippet").is_none(),
            "an update that says nothing about the snippet must not touch it"
        );

        let cleared = invocation(&["unihelm", "site", "update", "7", "--clear-nginx-snippet"]);
        assert_eq!(cleared.input["custom_nginx_snippet"], Value::Null);

        let set = invocation(&[
            "unihelm",
            "site",
            "update",
            "7",
            "--nginx-snippet",
            "add_header X-A b;",
        ]);
        assert_eq!(set.input["custom_nginx_snippet"], "add_header X-A b;");
    }

    #[test]
    fn php_install_targets_the_stack_manager() {
        let inv = invocation(&["unihelm", "php", "install", "8.3", "--ext", "redis,imagick"]);
        assert_eq!(inv.op, "stack.install");
        assert_eq!(inv.input["component"], "php");
        assert_eq!(inv.input["version"], "8.3");
        assert_eq!(inv.input["extensions"], json!(["redis", "imagick"]));
    }

    /// A version is optional now, for every slug.
    ///
    /// This used to refuse `stack install php` and demand `--version`, because
    /// the CLI held its own copy of what could be installed and knew PHP was the
    /// one with versions. The catalogue holds that now and every entry has
    /// versions, so an omitted one means "the recommended one" rather than a
    /// mistake — and the agent, which has the list, is what decides.
    #[test]
    fn an_omitted_version_is_left_for_the_catalogue_to_fill_in() {
        let inv = invocation(&["unihelm", "stack", "install", "php"]);
        assert_eq!(inv.op, "stack.install");
        assert_eq!(inv.input["component"], "php");
        assert!(
            inv.input.get("version").is_none(),
            "an absent version must stay absent rather than being guessed here: {}",
            inv.input
        );
    }

    /// And a slug the CLI has never heard of still travels, because the CLI is
    /// no longer the thing that knows. The agent refuses it against the
    /// catalogue, which is the one list.
    #[test]
    fn an_unknown_slug_is_the_agents_to_refuse() {
        let inv = invocation(&["unihelm", "stack", "install", "redis"]);
        assert_eq!(inv.input["component"], "redis");
    }

    #[test]
    fn dropping_a_database_carries_the_retyped_name() {
        let inv = invocation(&["unihelm", "db", "drop", "3", "--confirm-name", "shop"]);
        assert_eq!(inv.op, "db.drop");
        assert_eq!(inv.input["database_id"], 3);
        assert_eq!(inv.input["confirm_name"], "shop");
    }

    #[test]
    fn a_dns_token_is_refused_unless_it_came_from_stdin_or_the_environment() {
        // No secret resolved: the plan must fail rather than send an empty
        // token that the agent would store as a working credential.
        let err = plan_argv(&[
            "unihelm",
            "dns",
            "provider-set",
            "--label",
            "cf",
            "--token-stdin",
        ])
        .unwrap_err();
        assert!(err.to_string().contains("stdin"), "{err}");

        let cli = Cli::try_parse_from([
            "unihelm",
            "dns",
            "provider-set",
            "--label",
            "cf",
            "--token-stdin",
        ])
        .unwrap();
        let secrets = Secrets {
            dns_token: Some("cf-token".into()),
            ..Secrets::default()
        };
        let Action::Call(inv) = action_for(&cli.command, &secrets).unwrap() else {
            panic!("expected a call");
        };
        assert_eq!(inv.op, "dns.provider.set");
        assert_eq!(inv.input["token"], "cf-token");
    }

    #[test]
    fn an_s3_repository_needs_both_halves_of_its_credential() {
        let err = plan_argv(&[
            "unihelm",
            "backup",
            "repo",
            "init",
            "--kind",
            "s3",
            "--label",
            "off",
            "--path",
            "s3.example.com/bucket",
        ])
        .unwrap_err();
        assert!(err.to_string().contains("--s3-access-key-id"), "{err}");

        // A local repository must not be asked for one.
        let inv = invocation(&[
            "unihelm",
            "backup",
            "repo",
            "init",
            "--kind",
            "local",
            "--label",
            "disk",
            "--path",
            "/srv/backups",
        ]);
        assert_eq!(inv.op, "backup.repo.init");
        assert!(inv.input.get("s3").is_none());
    }

    #[test]
    fn env_pairs_split_on_the_first_equals_sign() {
        let parsed = parse_env(&["TOKEN=abc==".to_string(), "A=1".to_string()]).unwrap();
        assert_eq!(parsed[0]["key"], "TOKEN");
        assert_eq!(
            parsed[0]["value"], "abc==",
            "splitting on the last `=` would truncate base64 and JWT values"
        );
        assert_eq!(parsed[1]["value"], "1");

        assert!(parse_env(&["novalue".to_string()]).is_err());
        assert!(parse_env(&["=orphan".to_string()]).is_err());
    }

    #[test]
    fn an_exclusion_without_a_reason_is_refused() {
        assert!(parse_exclusions(&["942100".to_string()], None).is_err());
        assert!(parse_exclusions(&["942100=".to_string()], None).is_err());
        assert!(parse_exclusions(&["abc=typo".to_string()], None).is_err());

        let ok =
            parse_exclusions(&["942100=false positive on /wp-admin".to_string()], Some(4)).unwrap();
        assert_eq!(ok[0]["rule_id"], 942100);
        assert_eq!(ok[0]["site_id"], 4);
    }

    #[test]
    fn php_fpm_is_the_one_unit_that_needs_a_version() {
        let inv = invocation(&["unihelm", "svc", "status", "maria-db"]);
        assert_eq!(inv.input["unit"], json!({ "unit": "maria_db" }));

        let err = plan_argv(&["unihelm", "svc", "status", "php-fpm"]).unwrap_err();
        assert!(err.to_string().contains("--version"), "{err}");

        let inv = invocation(&["unihelm", "svc", "status", "php-fpm", "--version", "8.3"]);
        assert_eq!(
            inv.input["unit"],
            json!({ "unit": "php_fpm", "version": "8.3" })
        );
    }

    #[test]
    fn changing_one_sentinel_knob_reads_the_rest_back_first() {
        // The regression this guards: `sentinel.settings.set` has no serde
        // defaults, so sending `{enabled:true}` alone would reset the window,
        // the threshold and the whole allowlist.
        let action =
            plan_argv(&["unihelm", "firewall", "settings-set", "--enabled", "true"]).unwrap();
        let Action::MergeSentinelSettings(patch) = action else {
            panic!("expected a read-modify-write, got {action:?}");
        };
        assert_eq!(patch.enabled, Some(true));
        assert!(patch.ban_minutes.is_none());

        let current = json!({
            "enabled": false,
            "ssh_threshold": 6,
            "window_minutes": 10,
            "ban_minutes": 60,
            "allowlist": ["203.0.113.7"],
        });
        let merged = patch.apply(current);
        assert_eq!(merged["enabled"], true);
        assert_eq!(merged["ban_minutes"], 60);
        assert_eq!(merged["allowlist"], json!(["203.0.113.7"]));
    }

    #[test]
    fn an_empty_allowlist_flag_clears_the_list() {
        let action =
            plan_argv(&["unihelm", "firewall", "settings-set", "--allowlist", ""]).unwrap();
        let Action::MergeSentinelSettings(patch) = action else {
            panic!("expected a read-modify-write");
        };
        let merged = patch.apply(json!({ "allowlist": ["10.0.0.1"] }));
        assert_eq!(merged["allowlist"], json!([]));
    }

    #[test]
    fn wildcards_go_through_the_dns_01_operation_not_the_http_01_one() {
        let inv = invocation(&["unihelm", "dns", "issue-wildcard", "5", "--staging"]);
        assert_eq!(inv.op, "cert.issue_wildcard");
        assert_eq!(inv.input["staging"], true);

        let inv = invocation(&["unihelm", "cert", "issue", "5"]);
        assert_eq!(inv.op, "cert.issue");
        assert_eq!(inv.input["staging"], false);
    }

    #[test]
    fn a_disabled_flag_becomes_enabled_false() {
        // `--disabled` reads better than `--enabled false` on a create, but the
        // wire field is `enabled` and getting the inversion wrong would silently
        // switch every new job on.
        let inv = invocation(&[
            "unihelm",
            "cron",
            "set",
            "--schedule",
            "@daily",
            "--command",
            "/bin/true",
            "--disabled",
        ]);
        assert_eq!(inv.input["enabled"], false);

        let inv = invocation(&[
            "unihelm",
            "cron",
            "set",
            "--schedule",
            "@daily",
            "--command",
            "/bin/true",
        ]);
        assert_eq!(inv.input["enabled"], true);
    }

    #[test]
    fn a_malformed_channel_config_is_rejected_with_an_example() {
        let err = plan_argv(&[
            "unihelm",
            "alert",
            "channels-set",
            "--config-json",
            "not json",
        ])
        .unwrap_err();
        assert!(err.to_string().contains("JSON object"), "{err}");
    }

    #[test]
    fn local_commands_never_reach_the_agent() {
        for argv in [
            vec!["unihelm", "doctor"],
            vec!["unihelm", "user", "list"],
            vec!["unihelm", "task", "list"],
            vec!["unihelm", "completions", "bash"],
        ] {
            assert_eq!(
                plan_argv(&argv).unwrap(),
                Action::Local,
                "{argv:?} must be answered by the CLI itself"
            );
        }
    }
}
