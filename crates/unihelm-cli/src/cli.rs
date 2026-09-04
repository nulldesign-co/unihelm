//! The command tree (spec §11.20).
//!
//! This module is nothing but the shape of the command line: the arguments the
//! user types and the value enums their help text is generated from. It builds
//! no payloads and performs no I/O, which is what lets `completions.rs` render
//! the whole tree without a database, a socket or a root process.
//!
//! Two rules the tree obeys everywhere:
//!
//! - **No secret is ever a plain flag.** A token typed as `--token hunter2`
//!   lands in the shell history and in `/proc/<pid>/cmdline`, where every other
//!   account on the box can read it while the command runs. Secrets arrive on
//!   stdin (`--*-stdin`, the pattern `user create-admin` already set) or from an
//!   environment variable, never from argv.
//! - **Values are passed through as typed.** The CLI does not re-implement
//!   `Domain::parse` or `PhpVersion::parse`: it sends the string and lets the
//!   operation's own input type reject it, because parsing *is* validation and
//!   there must be exactly one copy of it (spec §12 rule 3).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use unihelm_core::config::paths;

#[derive(Parser, Debug)]
#[command(name = "unihelm", version, about = "Unihelm hosting panel")]
pub struct Cli {
    #[arg(long, default_value = paths::CONFIG, global = true)]
    pub config: PathBuf,

    /// Operate on a development instance rooted at this directory.
    #[arg(long, global = true)]
    pub dev: Option<PathBuf>,

    /// Emit JSON instead of a human-readable table.
    #[arg(long, global = true)]
    pub json: bool,

    /// Follow the task an operation starts, and exit with its outcome.
    #[arg(short = 'f', long, global = true)]
    pub follow: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Full health report: config, database, agent, system.
    Doctor,
    /// One-line status of the panel and the machine.
    Status,
    /// Account management.
    #[command(subcommand)]
    User(UserCommand),
    /// Inspect the operation registry.
    #[command(subcommand)]
    Ops(OpsCommand),

    /// Websites and their vhosts.
    #[command(subcommand)]
    Site(SiteCommand),
    /// Language runtimes installed on this server.
    #[command(subcommand)]
    Runtime(RuntimeCommand),
    /// Docker containers, images and volumes.
    #[command(subcommand)]
    Docker(DockerCommand),
    /// PHP versions.
    #[command(subcommand)]
    Php(PhpCommand),
    /// Databases, database users and Adminer.
    #[command(subcommand)]
    Db(DbCommand),
    /// Backup repositories, runs, schedules and restores.
    #[command(subcommand)]
    Backup(BackupCommand),
    /// Scheduled jobs.
    #[command(subcommand)]
    Cron(CronCommand),
    /// DNS checks, provider credentials and wildcard certificates.
    #[command(subcommand)]
    Dns(DnsCommand),
    /// Firewall rules, bans and Sentinel settings.
    #[command(subcommand, alias = "fw")]
    Firewall(FirewallCommand),
    /// Node.js applications.
    #[command(subcommand, alias = "apps")]
    App(AppCommand),
    /// WordPress installs.
    #[command(subcommand, alias = "wp")]
    Wordpress(WordpressCommand),
    /// Hosting plans.
    #[command(subcommand)]
    Plan(PlanCommand),
    /// Subscriptions and their suspension state.
    #[command(subcommand, alias = "sub")]
    Subscription(SubscriptionCommand),
    /// The software stack: nginx, PHP, MariaDB, PostgreSQL.
    #[command(subcommand)]
    Stack(StackCommand),
    /// Long-running tasks.
    #[command(subcommand)]
    Task(TaskCommand),
    /// TLS certificates.
    #[command(subcommand)]
    Cert(CertCommand),
    /// Managed system services.
    #[command(subcommand)]
    Svc(SvcCommand),
    /// The ModSecurity web application firewall.
    #[command(subcommand)]
    Waf(WafCommand),
    /// Alert rules, open events and notification channels.
    #[command(subcommand, alias = "alerts")]
    Alert(AlertCommand),

    /// Outgoing webhooks: where the panel reports events, and their secrets.
    #[command(subcommand)]
    Webhook(WebhookCommand),

    /// Plugin sidecars: install, enable, remove.
    #[command(subcommand)]
    Plugin(PluginCommand),

    /// Migrations from cPanel and aaPanel: plan first, then apply.
    #[command(subcommand)]
    Import(ImportCommand),

    /// The SSH keys a subscription may log in with.
    #[command(subcommand)]
    SshKeys(SshKeysCommand),

    /// The outbound mail relay: where PHP's mail() hands messages over.
    #[command(subcommand)]
    Mail(MailCommand),

    /// Panel branding: name, colour, support URL, login host and images.
    #[command(subcommand)]
    Branding(BrandingCommand),
    /// Per-subscription disk quotas.
    #[command(subcommand)]
    Quota(QuotaCommand),
    /// Chrooted SFTP access.
    #[command(subcommand)]
    Sftp(SftpCommand),
    /// Security posture of the server.
    #[command(subcommand)]
    Security(SecurityCommand),

    /// Print a shell completion script.
    ///
    /// Hidden because it is plumbing: the packaging installs its output, and a
    /// user who needs it has been told the incantation. It is still a real
    /// subcommand so `unihelm completions bash > …` works anywhere.
    #[command(hide = true)]
    Completions {
        /// Which shell to write a script for.
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}

// ---------------------------------------------------------------------------
// existing groups
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum UserCommand {
    /// Create the first administrator. Refuses if any account already exists.
    CreateAdmin {
        /// The login name for the account.
        #[arg(long)]
        username: String,
        /// The account's email address.
        #[arg(long)]
        email: String,
        /// Read the password from stdin instead of generating one.
        #[arg(long)]
        password_stdin: bool,
    },
    /// List accounts.
    List,
    /// Set an account's password.
    ///
    /// The generated one is printed once at install and stored only as a hash,
    /// so without this an operator who lost that line is locked out of their own
    /// panel with no way back in — there is no account page in the UI either.
    /// Lift the lock a burst of failed logins put on an account.
    ///
    /// Five wrong passwords in fifteen minutes refuses every attempt after them,
    /// the correct one included. Changing the password does not help — the count
    /// is on attempts, not on the credential — so without this the only cure is
    /// to wait, from a root shell on the machine, locked out of the panel.
    Unlock {
        /// The account to unlock. Its username or its email address.
        username: String,
    },
    Passwd {
        /// The account to change.
        username: String,
        /// Read the new password from stdin instead of generating one, so it
        /// never reaches the shell history or the process list.
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum OpsCommand {
    /// Every operation this build can reach, and the command that reaches it.
    List,
    /// The running agent's version and platform.
    Agent,
}

// ---------------------------------------------------------------------------
// sites
// ---------------------------------------------------------------------------

/// Docker containers, images and volumes.
#[derive(Subcommand, Debug)]
pub enum DockerCommand {
    /// Everything Docker has on this server.
    List,
}

/// Language runtimes installed on this server.
#[derive(Subcommand, Debug)]
pub enum RuntimeCommand {
    /// Every runtime found, with each version and where it lives.
    List,
    /// Install a Node major line from NodeSource.
    ///
    /// Installing a line that is already there reports so and changes nothing.
    Install {
        /// The major line: 20, 22, 24.
        #[arg(long)]
        major: u32,
    },
}

#[derive(Subcommand, Debug)]
pub enum SiteCommand {
    /// List sites.
    List(Page),
    /// Sites nginx is already serving that the panel did not create.
    ///
    /// Read-only. A server that was hosting sites before Unihelm arrived showed
    /// up in the panel as empty, which is a poor thing for a control panel to
    /// say about a machine running a dozen vhosts.
    Discover,
    /// Create a site and render its vhost.
    Create {
        /// The domain to serve, e.g. `shop.example`.
        domain: String,
        /// What the vhost serves.
        #[arg(long = "type", value_enum, default_value_t = SiteKind::Php)]
        kind: SiteKind,
        /// PHP version for a `php` site, e.g. `8.3`.
        #[arg(long)]
        php: Option<String>,
        /// Which subscription owns it. Defaults to the caller's own.
        #[arg(long)]
        subscription: Option<i64>,
        /// Also serve `www.<domain>`.
        #[arg(long)]
        with_www: bool,
        /// Upstream port for a `proxy` site.
        #[arg(long)]
        proxy_port: Option<u16>,
        /// Destination for a `redirect` site.
        #[arg(long)]
        redirect_to: Option<String>,
    },
    /// Change a site's settings. Omitted flags are left alone.
    Update {
        /// The site's id, as `unihelm site list` shows it.
        site_id: i64,
        /// Move the site to another PHP version, e.g. `8.3`.
        #[arg(long)]
        php: Option<String>,
        /// Redirect plain HTTP to HTTPS.
        #[arg(long, value_name = "BOOL")]
        force_https: Option<bool>,
        /// Offer HTTP/3 (QUIC) alongside HTTP/2.
        #[arg(long, value_name = "BOOL")]
        http3: Option<bool>,
        /// Serve the maintenance page instead of the site.
        #[arg(long, value_name = "BOOL")]
        maintenance: Option<bool>,
        /// Largest request body nginx will accept, e.g. `64m`.
        #[arg(long, value_name = "SIZE")]
        client_max_body_size: Option<String>,
        /// Apply the panel's rate-limit zone to this site.
        #[arg(long, value_name = "BOOL")]
        rate_limit: Option<bool>,
        /// What to do with the `www.` prefix.
        #[arg(long, value_enum)]
        www: Option<WwwPolicyArg>,
        /// Replace the custom nginx snippet.
        #[arg(long, conflicts_with = "clear_nginx_snippet")]
        nginx_snippet: Option<String>,
        /// Remove the custom nginx snippet.
        #[arg(long)]
        clear_nginx_snippet: bool,
        /// Replace the per-site `php.ini` overrides.
        #[arg(long, conflicts_with = "clear_php_ini")]
        php_ini: Option<String>,
        /// Remove the per-site `php.ini` overrides.
        #[arg(long)]
        clear_php_ini: bool,
    },
    /// Delete a site.
    Delete {
        /// The site's id, as `unihelm site list` shows it.
        site_id: i64,
        /// Also delete the site's files. A deleted vhost is recoverable; a
        /// deleted home directory is not.
        #[arg(long)]
        purge_files: bool,
    },
    /// Compare a site's files on disk with what the panel would render.
    Drift {
        /// The site's id, as `unihelm site list` shows it.
        site_id: i64,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum SiteKind {
    Php,
    Static,
    Proxy,
    Redirect,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum WwwPolicyArg {
    None,
    Add,
    Strip,
}

/// The `limit`/`offset` pair every listing shares.
#[derive(Args, Debug, Default, Clone, Copy)]
pub struct Page {
    /// How many rows to return.
    #[arg(long)]
    pub limit: Option<i64>,
    /// How many rows to skip.
    #[arg(long)]
    pub offset: Option<i64>,
}

// ---------------------------------------------------------------------------
// php + stack
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum PhpCommand {
    /// Every PHP version this build can install, and what is installed now.
    List,
    /// Install a PHP version and its FPM pool support.
    Install {
        /// Dotted version, e.g. `8.3`.
        version: String,
        // NOTE: the help below is duplicated on `stack install --ext`; they are
        // the same flag on the same operation, spelled twice because `php
        // install 8.3` is what people reach for.
        /// Extensions to add to the default set. Repeat or comma-separate.
        #[arg(long = "ext", value_delimiter = ',')]
        extensions: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum StackCommand {
    /// What is installed, and what the units say about it.
    Status,
    /// Install a component from its vendor's repository.
    Install {
        /// Which component to install.
        #[arg(value_enum)]
        component: StackComponentArg,
        /// Required for `php`: the dotted version, e.g. `8.3`.
        #[arg(long)]
        version: Option<String>,
        /// Extensions to add to the default set. Repeat or comma-separate.
        #[arg(long = "ext", value_delimiter = ',')]
        extensions: Vec<String>,
    },
    /// Remove a component.
    Remove {
        /// Which component to remove.
        #[arg(value_enum)]
        component: StackComponentArg,
        /// Required for `php`: the dotted version, e.g. `8.3`.
        #[arg(long)]
        version: Option<String>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum StackComponentArg {
    Nginx,
    Php,
    Mariadb,
    Postgres,
}

// ---------------------------------------------------------------------------
// databases
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum DbCommand {
    /// List databases.
    List(Page),
    /// Create a database.
    Create {
        /// The database name. The panel prefixes it with the tenant's own.
        name: String,
        /// Which engine it lives in.
        #[arg(long, value_enum)]
        engine: DbEngineArg,
        /// Which subscription owns it. Defaults to the caller's own.
        #[arg(long)]
        subscription: Option<i64>,
        /// An existing database user to bind as owner.
        #[arg(long)]
        owner: Option<String>,
    },
    /// Drop a database. The name must be retyped — dropped data has no undo.
    Drop {
        /// The database's id, as `unihelm db list` shows it.
        database_id: i64,
        /// The database's own name, retyped.
        #[arg(long)]
        confirm_name: String,
    },
    /// Database users.
    #[command(subcommand)]
    User(DbUserCommand),
    /// Grant a user full rights on a database.
    Grant {
        /// The database to grant on.
        #[arg(long)]
        database: String,
        /// The database user to grant to.
        #[arg(long)]
        user: String,
    },
    /// The Adminer database client.
    #[command(subcommand)]
    Adminer(AdminerCommand),
}

#[derive(Subcommand, Debug)]
pub enum DbUserCommand {
    /// Create a database user; the generated password is printed once.
    Create {
        /// The user name. The panel prefixes it with the tenant's own.
        username: String,
        /// Which engine the account lives in.
        #[arg(long, value_enum)]
        engine: DbEngineArg,
        /// Which subscription owns it. Defaults to the caller's own.
        #[arg(long)]
        subscription: Option<i64>,
    },
    /// Drop a database user.
    Drop {
        /// The full user name, as `unihelm db list` shows it.
        username: String,
    },
    /// Roll a database user's password; the new one is printed once.
    Password {
        /// The full user name, as `unihelm db list` shows it.
        username: String,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum DbEngineArg {
    Mysql,
    Postgres,
}

#[derive(Subcommand, Debug)]
pub enum AdminerCommand {
    /// Whether Adminer is enabled, and where it listens.
    Status,
    /// Enable Adminer on loopback.
    Enable,
    /// Disable Adminer and remove its vhost.
    Disable,
}

// ---------------------------------------------------------------------------
// backups
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum BackupCommand {
    /// Backup repositories.
    #[command(subcommand)]
    Repo(BackupRepoCommand),
    /// Take a backup now.
    Run {
        /// Repository id, as `unihelm backup repo` rows show it.
        #[arg(long)]
        repo: i64,
        /// What the backup covers.
        #[arg(long, value_enum)]
        scope: BackupScopeArg,
        /// Required for `subscription` scope; refused for `panel`.
        #[arg(long)]
        subscription: Option<i64>,
    },
    /// List snapshots in a repository.
    List {
        /// Repository id.
        #[arg(long)]
        repo: i64,
        /// Narrow to one subscription's snapshots.
        #[arg(long)]
        subscription: Option<i64>,
    },
    /// Restore a snapshot.
    Restore {
        /// Repository id.
        #[arg(long)]
        repo: i64,
        /// The snapshot's restic id.
        #[arg(long)]
        snapshot: String,
    },
    /// Unattended backup schedules.
    #[command(subcommand)]
    Schedule(BackupScheduleCommand),
}

#[derive(Subcommand, Debug)]
pub enum BackupRepoCommand {
    /// Initialise a repository. `restic init` runs against it.
    Init {
        /// Where the repository lives.
        #[arg(long, value_enum)]
        kind: RepoKindArg,
        /// Your name for it, shown in listings.
        #[arg(long)]
        label: String,
        /// An absolute path for `local`; `endpoint/bucket[/prefix]` for `s3`.
        #[arg(long)]
        path: String,
        /// S3 access key id. Not a secret; the secret half is read from stdin.
        #[arg(long)]
        s3_access_key_id: Option<String>,
        /// S3 region, where the endpoint needs one.
        #[arg(long)]
        s3_region: Option<String>,
        /// Read the S3 secret access key from stdin.
        ///
        /// The secret never becomes an argument: argv is world-readable in
        /// `/proc` for as long as the process lives.
        #[arg(long)]
        s3_secret_stdin: bool,
    },
    /// Forget a repository. The data on the far end is left alone.
    Delete {
        /// Repository id.
        repo_id: i64,
    },
}

#[derive(Subcommand, Debug)]
pub enum BackupScheduleCommand {
    /// Create or replace a schedule.
    Set {
        /// Repository id.
        #[arg(long)]
        repo: i64,
        /// What each run covers.
        #[arg(long, value_enum)]
        scope: BackupScopeArg,
        /// Required for `subscription` scope; refused for `panel`.
        #[arg(long)]
        subscription: Option<i64>,
        /// Five fields: `minute hour day-of-month month day-of-week`.
        #[arg(long)]
        cron: String,
        /// Daily snapshots to keep.
        #[arg(long)]
        keep_daily: Option<i64>,
        /// Weekly snapshots to keep.
        #[arg(long)]
        keep_weekly: Option<i64>,
        /// Monthly snapshots to keep.
        #[arg(long)]
        keep_monthly: Option<i64>,
        /// Keep the row but stop running it.
        #[arg(long)]
        disabled: bool,
    },
    /// Delete a schedule.
    Delete {
        /// Schedule id.
        schedule_id: i64,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum RepoKindArg {
    Local,
    S3,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum BackupScopeArg {
    Panel,
    Subscription,
}

// ---------------------------------------------------------------------------
// cron
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum CronCommand {
    /// List scheduled jobs.
    List {
        /// Narrow to one subscription.
        #[arg(long)]
        subscription: Option<i64>,
        #[command(flatten)]
        page: Page,
    },
    /// Create a job, or update one with `--id`.
    Set {
        /// Five fields, or a `@daily`-style nickname.
        #[arg(long)]
        schedule: String,
        /// The command line to run, as the tenant.
        #[arg(long)]
        command: String,
        /// Update this job instead of creating one.
        #[arg(long)]
        id: Option<i64>,
        /// Which subscription owns it. Defaults to the caller's own.
        #[arg(long)]
        subscription: Option<i64>,
        /// Keep the row, render it commented out.
        #[arg(long)]
        disabled: bool,
    },
    /// Delete a job.
    Delete {
        /// Job id, as `unihelm cron list` shows it.
        id: i64,
    },
}

// ---------------------------------------------------------------------------
// dns
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum DnsCommand {
    /// Does this domain point at this server yet?
    Check {
        /// The domain to look up.
        domain: String,
    },
    /// Store a DNS provider credential, sealed at rest.
    #[command(name = "provider-set")]
    ProviderSet {
        /// Which provider the token is for.
        #[arg(long, value_enum, default_value_t = DnsProviderArg::Cloudflare)]
        kind: DnsProviderArg,
        /// Your name for this credential — the only handle you get on a value
        /// you can never read back.
        #[arg(long)]
        label: String,
        /// Read the API token from stdin. Falls back to `UNIHELM_DNS_TOKEN`.
        #[arg(long)]
        token_stdin: bool,
    },
    /// Issue a wildcard certificate over DNS-01.
    #[command(name = "issue-wildcard")]
    IssueWildcard {
        /// The site whose domain the wildcard covers.
        site_id: i64,
        /// Use the CA's staging directory. Never install one on a live site.
        #[arg(long)]
        staging: bool,
        /// Contact address for expiry warnings from the CA.
        #[arg(long)]
        contact_email: Option<String>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum DnsProviderArg {
    Cloudflare,
}

// ---------------------------------------------------------------------------
// firewall
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum FirewallCommand {
    /// Every rule the backend is enforcing, merged with the panel's own.
    Rules,
    /// Open a port.
    Open {
        /// The port number.
        port: u16,
        /// Transport protocol.
        #[arg(long, value_enum, default_value_t = ProtoArg::Tcp)]
        proto: ProtoArg,
        /// Restrict to a source address or CIDR.
        #[arg(long)]
        source: Option<String>,
        /// A note stored with the rule, for whoever reads it next.
        #[arg(long)]
        comment: Option<String>,
    },
    /// Close a port.
    Close {
        /// The port number.
        port: u16,
        /// Transport protocol.
        #[arg(long, value_enum, default_value_t = ProtoArg::Tcp)]
        proto: ProtoArg,
        /// The source the rule was opened for, if it had one.
        #[arg(long)]
        source: Option<String>,
    },
    /// Ban an address.
    Ban {
        /// The address to ban.
        ip: String,
        /// Minutes. `0` is permanent, and only ever an operator's choice.
        #[arg(long)]
        minutes: Option<u32>,
        /// Why, for the ban list and the audit trail.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Lift a ban.
    Unban {
        /// The address to unban.
        ip: String,
    },
    /// Current bans.
    Bans {
        /// How many to return.
        #[arg(long)]
        limit: Option<i64>,
    },
    /// Sentinel's settings.
    Settings,
    /// Change Sentinel's settings. Omitted flags keep their stored value.
    #[command(name = "settings-set")]
    SettingsSet {
        /// Sentinel's master switch.
        #[arg(long, value_name = "BOOL")]
        enabled: Option<bool>,
        /// Failed SSH authentications inside the window that earn a ban.
        #[arg(long)]
        ssh_threshold: Option<u32>,
        /// How far back each scan looks.
        #[arg(long)]
        window_minutes: Option<u32>,
        /// How long one of Sentinel's own bans lasts.
        #[arg(long)]
        ban_minutes: Option<u32>,
        /// Replace the allowlist. Repeat or comma-separate; pass `--allowlist ''`
        /// to clear it.
        #[arg(long, value_delimiter = ',')]
        allowlist: Option<Vec<String>>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum ProtoArg {
    Tcp,
    Udp,
}

// ---------------------------------------------------------------------------
// node apps
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum AppCommand {
    /// List applications.
    List(Page),
    /// Create an application and its systemd unit.
    Create {
        /// The application's name; it becomes part of the unit name.
        name: String,
        /// Tenant-home-relative path to the JS entry point.
        #[arg(long)]
        entry: String,
        /// Which subscription owns it. Defaults to the caller's own.
        #[arg(long)]
        subscription: Option<i64>,
        /// `KEY=VALUE`, repeatable.
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// What `NODE_ENV` is set to. Production unless you say otherwise.
        #[arg(long, value_enum)]
        node_env: Option<NodeEnvArg>,
        /// Per-app `MemoryMax`, inside the tenant slice's own ceiling.
        #[arg(long)]
        memory_mb: Option<u32>,
        /// Pin to an installed runtime version, e.g. `22.11.0`.
        ///
        /// `unihelm runtime list` shows which are on this server. Without it the
        /// app runs on whichever a bare `node` resolves to.
        #[arg(long)]
        runtime_version: Option<String>,
        /// Which language it is written in: node, python, ruby, bun, deno, go.
        #[arg(long, value_name = "RUNTIME")]
        runtime: Option<String>,
        /// Publish the app behind this domain as a reverse-proxy site.
        #[arg(long)]
        proxy_domain: Option<String>,
    },
    /// Delete an application.
    Delete {
        /// Application id, as `unihelm app list` shows it.
        app_id: i64,
    },
    /// Restart an application.
    Restart {
        /// Application id.
        app_id: i64,
    },
    /// Move an application to a different runtime or version.
    ///
    /// Re-renders its unit and restarts it, keeping the port, the proxy site
    /// and everything in the app directory.
    Update {
        /// Which app.
        app_id: i64,
        /// Change the language: node, python, ruby, bun, deno, go.
        #[arg(long)]
        runtime: Option<String>,
        /// Pin to a version.
        #[arg(long, conflicts_with = "unpin")]
        runtime_version: Option<String>,
        /// Run on whatever a bare command name resolves to.
        #[arg(long)]
        unpin: bool,
    },
    /// Recent journal output for an application.
    Logs {
        /// Application id.
        app_id: i64,
        /// How many lines to fetch.
        #[arg(long)]
        lines: Option<u32>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum NodeEnvArg {
    Production,
    Development,
    Test,
}

// ---------------------------------------------------------------------------
// wordpress
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum WordpressCommand {
    /// Install WordPress into a site.
    Install {
        /// The site to install into.
        site_id: i64,
        /// The site title WordPress will show.
        #[arg(long)]
        title: String,
        /// The WordPress administrator's login name.
        #[arg(long)]
        admin_user: String,
        /// The WordPress administrator's email address.
        #[arg(long)]
        admin_email: String,
        /// Install into a subdirectory of the document root.
        #[arg(long)]
        subdirectory: Option<String>,
        /// `en_US` by default; `fa_IR` is a first-class case.
        #[arg(long)]
        locale: Option<String>,
        /// Unattended core updates for this install.
        #[arg(long)]
        auto_update: bool,
    },
    /// Find an existing WordPress under a site and adopt it.
    Detect {
        /// The site to look under.
        site_id: i64,
        /// Look in a subdirectory of the document root instead of the root.
        #[arg(long)]
        subdirectory: Option<String>,
    },
    /// Update WordPress core.
    Update {
        /// Install id, as `unihelm wp detect` and the site listing show it.
        install_id: i64,
        /// Update to a specific core version instead of the latest.
        #[arg(long)]
        version: Option<String>,
        /// Skip `wp core update-db`.
        #[arg(long)]
        no_update_db: bool,
    },
    /// Plugins.
    #[command(subcommand)]
    Plugin(WpPluginCommand),
    /// Run an allowlisted `wp` command group.
    Cli {
        /// Install id.
        install_id: i64,
        /// The command group. Only these are allowed.
        #[arg(value_enum)]
        subcommand: WpSubcommandArg,
        /// Everything after the group.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum WpPluginCommand {
    /// List plugins and their update status.
    List {
        /// Install id.
        install_id: i64,
    },
    /// Update plugins. No slugs means "everything with an update".
    Update {
        /// Install id.
        install_id: i64,
        /// Plugin slugs to update.
        #[arg(value_name = "SLUG")]
        plugins: Vec<String>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub enum WpSubcommandArg {
    Core,
    Plugin,
    Theme,
    Option,
    User,
    Db,
    Cache,
    Rewrite,
}

// ---------------------------------------------------------------------------
// plans and subscriptions
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum PlanCommand {
    /// List plans.
    List(Page),
    /// Create a plan.
    Create {
        /// The plan's name, shown to customers.
        name: String,
        /// How many sites a subscription on this plan may have.
        #[arg(long)]
        max_sites: u32,
        /// How many databases a subscription on this plan may have.
        #[arg(long)]
        max_dbs: u32,
        /// Disk allowance, in MiB.
        #[arg(long)]
        storage_mb: u32,
        /// Allow SFTP/SSH access.
        #[arg(long)]
        can_ssh: bool,
        /// Cron is on by default; pass `--can-cron false` to withhold it.
        #[arg(long, value_name = "BOOL")]
        can_cron: Option<bool>,
        /// Allow Node.js applications.
        #[arg(long)]
        can_node_apps: bool,
    },
    /// Change a plan. Omitted flags are left alone.
    Update {
        /// Plan id, as `unihelm plan list` shows it.
        plan_id: i64,
        /// Rename the plan.
        #[arg(long)]
        name: Option<String>,
        /// New site allowance.
        #[arg(long)]
        max_sites: Option<u32>,
        /// New database allowance.
        #[arg(long)]
        max_dbs: Option<u32>,
        /// New disk allowance, in MiB.
        #[arg(long)]
        storage_mb: Option<u32>,
        /// Allow SFTP/SSH access.
        #[arg(long, value_name = "BOOL")]
        can_ssh: Option<bool>,
        /// Allow cron jobs.
        #[arg(long, value_name = "BOOL")]
        can_cron: Option<bool>,
        /// Allow Node.js applications.
        #[arg(long, value_name = "BOOL")]
        can_node_apps: Option<bool>,
    },
    /// Delete a plan no subscription is on.
    Delete {
        /// Plan id.
        plan_id: i64,
    },
    /// Move a subscription onto a plan.
    Assign {
        /// The subscription to move.
        #[arg(long)]
        subscription: i64,
        /// The plan to move it onto.
        #[arg(long)]
        plan: i64,
    },
}

#[derive(Subcommand, Debug)]
pub enum SubscriptionCommand {
    /// List subscriptions and their plans.
    List(Page),
    /// Suspend a subscription.
    Suspend {
        /// Subscription id, as `unihelm subscription list` shows it.
        subscription_id: i64,
        /// Shown to the tenant. Required: "suspended for no recorded reason"
        /// helps nobody.
        #[arg(long)]
        reason: String,
    },
    /// Lift a suspension.
    Unsuspend {
        /// Subscription id.
        subscription_id: i64,
    },
}

// ---------------------------------------------------------------------------
// tasks
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum TaskCommand {
    /// Recent tasks, newest first.
    List(Page),
    /// One task's current state.
    Show {
        /// The task's UUID.
        task_id: String,
    },
    /// A task's log. `--follow` streams it until the task finishes.
    Logs {
        /// The task's UUID.
        task_id: String,
        /// Resume point, so a re-run does not re-print the whole log.
        #[arg(long, default_value_t = 0)]
        after_seq: i64,
    },
    /// Ask the agent to cancel a task.
    Cancel {
        /// The task's UUID.
        task_id: String,
    },
}

// ---------------------------------------------------------------------------
// certificates
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum CertCommand {
    /// Every certificate the panel holds, with days remaining.
    List,
    /// Issue a certificate for a site over HTTP-01.
    Issue {
        /// The site to issue for.
        site_id: i64,
        /// Use the CA's staging directory. Never install one on a live site.
        #[arg(long)]
        staging: bool,
        /// Contact address for expiry warnings from the CA.
        #[arg(long)]
        contact_email: Option<String>,
    },
    /// Issue the certificate the panel itself is served with.
    Panel {
        /// The domain the panel is served on. It must already resolve here.
        domain: String,
        /// Contact address for expiry warnings from the CA.
        #[arg(long)]
        contact_email: Option<String>,
        /// Use the CA's staging directory. Not for a panel anyone logs in to.
        #[arg(long)]
        staging: bool,
    },
}

// ---------------------------------------------------------------------------
// services
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum SvcCommand {
    /// One managed unit's state.
    Status {
        /// Which unit. The list is fixed; there is no way to name another.
        #[arg(value_enum)]
        unit: UnitArg,
        /// Required for `php-fpm`: the dotted version, e.g. `8.3`.
        #[arg(long)]
        version: Option<String>,
    },
    /// Start, stop, restart or reload a managed unit.
    Action {
        /// Which unit.
        #[arg(value_enum)]
        unit: UnitArg,
        /// What to do to it. Prefer `reload` over `restart` where it works.
        #[arg(value_enum)]
        action: SvcActionArg,
        /// Required for `php-fpm`: the dotted version, e.g. `8.3`.
        #[arg(long)]
        version: Option<String>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "kebab-case")]
pub enum UnitArg {
    Nginx,
    PhpFpm,
    MariaDb,
    PostgreSql,
    KvStore,
    Docker,
    Sshd,
    UnihelmWeb,
    UnihelmAgentd,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum SvcActionArg {
    Start,
    Stop,
    Restart,
    Reload,
}

// ---------------------------------------------------------------------------
// waf
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum WafCommand {
    /// Server-wide and per-site WAF state.
    Status,
    /// Switch the WAF on, for the server or for one site.
    Enable {
        /// One site. Absent means the whole server, which is the prerequisite
        /// for any per-site policy.
        #[arg(long)]
        site: Option<i64>,
        /// `detect` logs only; `block` enforces the CRS anomaly score.
        #[arg(long, value_enum)]
        mode: Option<WafModeArg>,
        /// CRS paranoia level. Higher catches more and false-positives more.
        #[arg(long)]
        paranoia: Option<i64>,
    },
    /// Switch the WAF off, for the server or for one site.
    Disable {
        /// One site. Absent switches the WAF off for the whole server.
        #[arg(long)]
        site: Option<i64>,
    },
    /// Replace the whole exclusion list. No `--exclusion` clears it.
    #[command(name = "rules-set")]
    RulesSet {
        /// `RULE_ID=REASON`, repeatable.
        #[arg(long = "exclusion", value_name = "RULE_ID=REASON")]
        exclusions: Vec<String>,
        /// Scope every exclusion in this call to one site.
        #[arg(long)]
        site: Option<i64>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub enum WafModeArg {
    Off,
    Detect,
    Block,
}

// ---------------------------------------------------------------------------
// alerts
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum AlertCommand {
    /// Alert rules and the events open right now.
    Rules,
    /// Create or replace one rule.
    #[command(name = "rules-set")]
    RulesSet {
        /// What the rule watches.
        #[arg(value_enum)]
        kind: AlertKindArg,
        /// Which resource, when the kind needs one — a mount, a unit.
        #[arg(long)]
        target: Option<String>,
        /// The value at which the rule fires.
        #[arg(long)]
        threshold: Option<f64>,
        /// Keep the rule but stop evaluating it.
        #[arg(long)]
        disabled: bool,
    },
    /// Alert events.
    Events {
        /// How many to return.
        #[arg(long)]
        limit: Option<i64>,
        /// Only events that have not closed again.
        #[arg(long)]
        open_only: bool,
    },
    /// Notification channels.
    Channels,
    /// Create or edit a notification channel.
    #[command(name = "channels-set")]
    ChannelsSet {
        /// Edit this channel instead of creating one.
        #[arg(long)]
        id: Option<i64>,
        /// Where notifications go. Required when creating.
        #[arg(long, value_enum)]
        kind: Option<ChannelKindArg>,
        /// Your name for the channel.
        #[arg(long)]
        label: Option<String>,
        /// The channel's own settings as a JSON object. Omit on an edit to keep
        /// the stored value, secrets included.
        ///
        /// Spelled `--config-json` because `--config` is the global that names
        /// the panel's configuration file, and clap resolves argument ids
        /// globally: two arguments called `config` are one argument with two
        /// incompatible types.
        #[arg(long, value_name = "JSON")]
        config_json: Option<String>,
        /// Whether the channel is used.
        #[arg(long, value_name = "BOOL")]
        enabled: Option<bool>,
    },
    /// Delete a notification channel.
    #[command(name = "channels-delete")]
    ChannelsDelete {
        /// Channel id, as `unihelm alert channels` shows it.
        id: i64,
    },
    /// Send a test notification through a channel.
    #[command(name = "channels-test")]
    ChannelsTest {
        /// Channel id.
        id: i64,
    },
}

/// `unihelm webhook …`
///
/// A webhook secret is shown once, when it is minted, and never again — the
/// panel stores it to sign with, not to hand back. `--rotate-secret` is how a
/// leaked one is replaced.
#[derive(Debug, Subcommand)]
pub enum WebhookCommand {
    /// Every hook, with its event list and failure count.
    List,
    /// Create a hook, or update one by id.
    Set {
        /// Where deliveries are POSTed. HTTPS unless the host is loopback.
        url: String,
        /// Which events to send. Repeat the flag, or comma-separate.
        #[arg(long, value_delimiter = ',', required = true)]
        event: Vec<String>,
        /// Update this hook instead of creating one.
        #[arg(long)]
        id: Option<i64>,
        /// Keep the hook but stop delivering to it.
        #[arg(long)]
        disabled: bool,
        /// Mint a new signing secret, invalidating the old one.
        #[arg(long)]
        rotate_secret: bool,
    },
    /// Remove a hook.
    Delete { id: i64 },
    /// Send a test delivery and report what the endpoint answered.
    Test { id: i64 },
}

/// `unihelm plugin …`
///
/// A plugin runs as a sidecar under its own account, never in the agent (spec
/// §6). Install takes a staged directory containing `plugin.toml`; the panel
/// verifies its signature before anything is copied into place.
#[derive(Debug, Subcommand)]
pub enum PluginCommand {
    /// Installed plugins and what each one registers.
    List,
    /// Install from a staged directory.
    Install {
        /// Absolute path to a tree containing `plugin.toml`.
        source: String,
    },
    /// Start a plugin's sidecar and route its extension points.
    Enable { slug: String },
    /// Stop the sidecar, leaving the plugin installed.
    Disable { slug: String },
    /// Stop it and remove it entirely.
    Remove { slug: String },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum AlertKindArg {
    DiskPct,
    MemPct,
    Load,
    ServiceDown,
    CertExpiryDays,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum ChannelKindArg {
    Webhook,
    Telegram,
}

// ---------------------------------------------------------------------------
// import, mail, branding
// ---------------------------------------------------------------------------

/// `unihelm import …`
///
/// A migration is two steps, and the first one changes nothing: `plan` reads a
/// cPanel tarball or an aaPanel installation and stores the whole mapping —
/// which domains become which sites, which databases, and everything that does
/// not map — and `apply` executes that stored document by id. Apply never
/// re-scans, so the thing an operator read is the thing that runs (spec
/// §11.15).
#[derive(Debug, Subcommand)]
pub enum ImportCommand {
    /// Read a source and store the mapping. Nothing is created.
    Plan {
        /// Which panel the source came from.
        #[arg(long, value_enum)]
        source: ImportSourceArg,
        /// The cpmove tarball for `cpanel`, or the installation root for
        /// `aapanel`, which defaults to `/www`. Absolute, on this server.
        #[arg(long)]
        path: Option<String>,
        /// Which subscription the imported sites and databases land in.
        #[arg(long)]
        subscription: i64,
        /// PHP version for imported sites whose own version Unihelm does not
        /// offer, e.g. `8.3`.
        #[arg(long)]
        php: Option<String>,
    },
    /// Stored plans, newest first. One plan in full with `--plan`.
    List {
        /// Show this plan's whole document and its outcome.
        #[arg(long)]
        plan: Option<i64>,
        #[command(flatten)]
        page: Page,
    },
    /// Execute a stored plan: sites, databases and files are created.
    Apply {
        /// Plan id, as `unihelm import list` shows it.
        plan_id: i64,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum ImportSourceArg {
    Cpanel,
    Aapanel,
}

/// `unihelm mail …`
///
/// Unihelm runs no mail server. This is the address of somebody else's
/// submission service, the credential to use with it, and one test message —
/// no mailboxes, no inbound mail, no queue (spec §11.18).
#[derive(Debug, Subcommand)]
pub enum MailCommand {
    /// Publish the mail DNS records into the configured provider's zone.
    ///
    /// Reports what it would write unless --apply is given. An existing record
    /// is left exactly as it is.
    DnsPublish {
        /// Actually write the records.
        #[arg(long)]
        apply: bool,
    },
    /// The outbound relay.
    #[command(subcommand)]
    Relay(MailRelayCommand),
}

#[derive(Debug, Subcommand)]
pub enum MailRelayCommand {
    /// The configured relay, and the DNS records it needs.
    Get,
    /// Store the relay and point every PHP site at it.
    Set {
        /// The submission host, e.g. `smtp.example.com`.
        host: String,
        /// The submission port. 587 for STARTTLS, 465 for implicit TLS.
        #[arg(long)]
        port: u16,
        /// How the connection is protected. A relay with a username needs one
        /// of the encrypted modes; the operation refuses the other pairing.
        #[arg(long, value_enum)]
        tls: TlsModeArg,
        /// The envelope sender every site sends as.
        #[arg(long)]
        from: String,
        /// The display name that goes with it.
        #[arg(long)]
        from_name: Option<String>,
        /// The relay username.
        #[arg(long)]
        username: Option<String>,
        /// Read the relay password from stdin.
        ///
        /// Omitted, the stored password is kept: it is write-only, so an
        /// operator changing the port has no way to re-type it. Pass an empty
        /// line to clear it.
        #[arg(long)]
        password_stdin: bool,
        /// Whether sites actually send through it.
        #[arg(long, value_name = "BOOL")]
        enabled: Option<bool>,
    },
    /// Send one test message and report what the relay said.
    Test {
        /// Where to send it. Defaults to the relay's own from address, which
        /// is the one address the relay certainly accepts mail from.
        #[arg(long)]
        to: Option<String>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum TlsModeArg {
    None,
    Starttls,
    Implicit,
}

/// `unihelm ssh-keys …`
///
/// The panel owns one managed block inside the account's `authorized_keys`;
/// keys an operator put there by hand are left alone and reported separately,
/// which is why removing takes a fingerprint rather than an index.
#[derive(Debug, Subcommand)]
pub enum SshKeysCommand {
    /// Every key in the managed block, and whether anything else is present.
    List {
        /// Which subscription owns it. Defaults to the caller's own.
        #[arg(long)]
        subscription: Option<i64>,
    },
    /// Authorise one public key.
    Add {
        /// The public key, in `authorized_keys` form, e.g.
        /// `ssh-ed25519 AAAAC3Nz... name@host`.
        key: String,
        /// Which subscription owns it. Defaults to the caller's own.
        #[arg(long)]
        subscription: Option<i64>,
    },
    /// Withdraw one key, named by its fingerprint.
    Remove {
        /// The fingerprint as `ssh-keys list` prints it.
        fingerprint: String,
        /// Which subscription owns it. Defaults to the caller's own.
        #[arg(long)]
        subscription: Option<i64>,
    },
}

/// `unihelm branding …`
///
/// Images are not settable from here: the bytes travel base64-encoded inside
/// the operation, which is a job for the UI or the API and not for a shell.
/// `--clear-*` is, because removing an image needs no bytes.
#[derive(Debug, Subcommand)]
pub enum BrandingCommand {
    /// The stored branding for one owner, and what it resolves to.
    Get {
        /// Admin only. A reseller always reads their own.
        #[arg(long)]
        reseller: Option<i64>,
    },
    /// Set the panel name, colour, support URL and login host.
    Set {
        /// Admin only. A reseller always writes their own.
        #[arg(long)]
        reseller: Option<i64>,
        /// What the panel calls itself.
        #[arg(long)]
        panel_name: Option<String>,
        /// Where "support" links to. `http:` or `https:` only.
        #[arg(long)]
        support_url: Option<String>,
        /// The accent colour, as `#rrggbb`.
        #[arg(long)]
        primary_color: Option<String>,
        /// The hostname this branding answers on.
        #[arg(long)]
        login_host: Option<String>,
        /// Reset a field to inheriting. Repeat the flag, or comma-separate.
        #[arg(long, value_enum, value_delimiter = ',')]
        clear: Vec<BrandingFieldArg>,
        /// Remove this owner's logo, uncovering the panel's.
        #[arg(long)]
        clear_logo: bool,
        /// Remove this owner's favicon.
        #[arg(long)]
        clear_favicon: bool,
        /// Remove this owner's login background.
        #[arg(long)]
        clear_login_background: bool,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum BrandingFieldArg {
    PanelName,
    SupportUrl,
    PrimaryColor,
    LoginHost,
}

// ---------------------------------------------------------------------------
// quota, sftp, security
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum QuotaCommand {
    /// Which quota backend is in force, and whether it is enforcing.
    Backend,
    /// Set a subscription's soft and hard limits.
    Set {
        /// Subscription id.
        subscription_id: i64,
        /// Warning threshold, in MiB.
        #[arg(long)]
        soft_mb: u64,
        /// Enforced ceiling, in MiB.
        #[arg(long)]
        hard_mb: u64,
    },
    /// A subscription's current usage.
    Usage {
        /// Subscription id.
        subscription_id: i64,
    },
}

#[derive(Subcommand, Debug)]
pub enum SftpCommand {
    /// Give a subscription chrooted SFTP access.
    Enable {
        /// Subscription id.
        subscription_id: i64,
        /// Read the SFTP password from stdin. Without it the account is created
        /// with no password and only a key will get in.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Take SFTP access away.
    Disable {
        /// Subscription id.
        subscription_id: i64,
    },
}

#[derive(Subcommand, Debug)]
pub enum SecurityCommand {
    /// Scan the server and report what is weak.
    Posture,
}

// ---------------------------------------------------------------------------
// completions
// ---------------------------------------------------------------------------

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_internally_consistent() {
        // clap's own audit: duplicate long flags, a global that collides with a
        // subcommand's own argument, an unreachable positional. It panics with
        // the offending name, which is far better than discovering it in a
        // shell six months later.
        Cli::command().debug_assert();
    }

    #[test]
    fn json_and_follow_are_global_so_they_work_after_the_subcommand() {
        // `unihelm site list --json` must parse: a scripting flag that only works
        // before the subcommand is a flag people file bugs about.
        let cli = Cli::try_parse_from(["unihelm", "site", "list", "--json"]).unwrap();
        assert!(cli.json);
        let cli = Cli::try_parse_from(["unihelm", "task", "logs", "abc", "-f"]).unwrap();
        assert!(cli.follow);
    }

    #[test]
    fn a_secret_can_never_be_given_as_an_argument() {
        // The whole point of the stdin pattern: there is no spelling of these
        // commands that puts the secret into argv, so it cannot leak through
        // /proc or the shell history.
        for argv in [
            vec![
                "unihelm",
                "dns",
                "provider-set",
                "--label",
                "cf",
                "--token",
                "secret",
            ],
            vec![
                "unihelm",
                "backup",
                "repo",
                "init",
                "--kind",
                "s3",
                "--label",
                "b",
                "--path",
                "p",
                "--s3-secret-access-key",
                "secret",
            ],
            vec!["unihelm", "sftp", "enable", "1", "--password", "secret"],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "{argv:?} must not be accepted: it would put a secret in argv"
            );
        }
    }

    #[test]
    fn clearing_a_snippet_and_setting_it_are_mutually_exclusive() {
        // Asking for both is a mistake with two plausible outcomes, so it is
        // rejected rather than silently resolved one way.
        assert!(
            Cli::try_parse_from([
                "unihelm",
                "site",
                "update",
                "1",
                "--nginx-snippet",
                "x",
                "--clear-nginx-snippet",
            ])
            .is_err()
        );
    }
}
