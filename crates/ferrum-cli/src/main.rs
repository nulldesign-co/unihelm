//! `ferrum` — the command-line half of the panel (spec §11.20).
//!
//! Two jobs in Phase 0:
//!
//! - **`ferrum doctor`**, the first thing to run when something looks wrong. It
//!   checks the pieces in the order they depend on each other, so the first
//!   failure is usually the real one.
//! - **`ferrum user create-admin`**, which the installer calls to create the
//!   first account. This is the one command that must work before any session,
//!   any HTTP listener, or any agent exists.
//!
//! TODO(scope): spec §11.20 has the CLI talking to the REST API over
//! `panel.cli_socket`. That needs the API surface Phase 1 introduces; until then
//! the CLI reads the database directly (as root, on the same host), which is what
//! `doctor` and first-run setup need anyway.

mod report;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ferrum_core::config::{FerrumConfig, paths};
use ferrum_core::{AuthContext, Email, Role, TenantScope, Username};
use ferrum_db::Db;
use ferrum_db::users::NewUser;
use ferrum_distro::{Distro, SupportStatus};
use ferrum_ipc::IpcClient;

use crate::report::{Report, human_bytes};

#[derive(Parser, Debug)]
#[command(name = "ferrum", version, about = "Ferrum hosting panel")]
struct Cli {
    #[arg(long, default_value = paths::CONFIG, global = true)]
    config: PathBuf,

    /// Operate on a development instance rooted at this directory.
    #[arg(long, global = true)]
    dev: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Full health report: config, database, agent, system.
    Doctor {
        /// Emit JSON instead of a human-readable report.
        #[arg(long)]
        json: bool,
    },
    /// One-line status of the panel and the machine.
    Status,
    /// Account management.
    #[command(subcommand)]
    User(UserCommand),
    /// Inspect the operation registry.
    #[command(subcommand)]
    Ops(OpsCommand),
}

#[derive(Subcommand, Debug)]
enum UserCommand {
    /// Create the first administrator. Refuses if any account already exists.
    CreateAdmin {
        #[arg(long)]
        username: String,
        #[arg(long)]
        email: String,
        /// Read the password from stdin instead of generating one.
        #[arg(long)]
        password_stdin: bool,
    },
    /// List accounts.
    List,
}

#[derive(Subcommand, Debug)]
enum OpsCommand {
    /// List every operation the running agent will accept.
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli)?;

    let exit = match cli.command {
        Command::Doctor { json } => doctor(&config, json).await?,
        Command::Status => {
            status(&config).await?;
            0
        }
        Command::User(cmd) => {
            user(&config, cmd).await?;
            0
        }
        Command::Ops(cmd) => {
            ops(&config, cmd).await?;
            0
        }
    };

    std::process::exit(exit);
}

fn load_config(cli: &Cli) -> Result<FerrumConfig> {
    let config = if let Some(dir) = &cli.dev {
        FerrumConfig::for_dev(dir)
    } else {
        match std::fs::read_to_string(&cli.config) {
            Ok(text) => FerrumConfig::from_toml(&text)
                .map_err(|e| anyhow::anyhow!("{}: {e}", cli.config.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => FerrumConfig::default(),
            Err(e) => {
                return Err(e).with_context(|| format!("could not read {}", cli.config.display()));
            }
        }
    };
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

async fn doctor(config: &FerrumConfig, json: bool) -> Result<i32> {
    let mut report = Report::default();

    check_system(&mut report);
    check_database(config, &mut report).await;
    check_agent(config, &mut report).await;
    check_disk(config, &mut report);

    if json {
        println!("{}", serde_json::to_string_pretty(&report.to_json())?);
    } else {
        report.print();
    }
    Ok(report.exit_code())
}

fn check_system(report: &mut Report) {
    match Distro::detect() {
        Ok(distro) => {
            let info = &distro.info;
            match info.support_status() {
                SupportStatus::Supported => {
                    report.ok(
                        "system",
                        format!("{} ({})", info.pretty_name, info.arch.as_str()),
                    );
                }
                SupportStatus::Untested(why) => {
                    report.warn("system", format!("{} — {why}", info.pretty_name));
                }
                SupportStatus::Unsupported(why) => report.fail("system", why),
            }

            for problem in info.preflight() {
                report.fail("system requirements", problem);
            }
            report.ok(
                "backends",
                format!(
                    "packages: {}, firewall: {}, security: {:?}",
                    distro.pkg.name(),
                    distro.fw.name(),
                    distro.sec.kind()
                ),
            );
        }
        Err(e) => report.fail("system", e.to_string()),
    }
}

async fn check_database(config: &FerrumConfig, report: &mut Report) {
    let path = &config.panel.database;
    if !path.exists() {
        report.fail("database", format!("{} does not exist yet", path.display()));
        return;
    }

    match Db::open(path).await {
        Ok(db) => {
            match db.integrity_check().await {
                Ok(result) if result == "ok" => {
                    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                    report.ok(
                        "database",
                        format!("{} ({})", path.display(), human_bytes(size)),
                    );
                }
                Ok(result) => report.fail("database", format!("integrity check: {result}")),
                Err(e) => report.fail("database", format!("integrity check failed: {e}")),
            }

            match db.has_any_user().await {
                Ok(true) => report.ok("accounts", "at least one account exists"),
                Ok(false) => report.warn(
                    "accounts",
                    "no accounts yet — run `ferrum user create-admin`",
                ),
                Err(e) => report.fail("accounts", e.to_string()),
            }
            db.close().await;
        }
        Err(e) => report.fail("database", format!("{}: {e}", path.display())),
    }
}

async fn check_agent(config: &FerrumConfig, report: &mut Report) {
    let socket = &config.agent.socket;

    if !socket.exists() {
        report.fail(
            "agent socket",
            format!(
                "{} does not exist — is ferrum-agentd running?",
                socket.display()
            ),
        );
        return;
    }

    // The socket being reachable by anyone else would undo the whole privilege
    // split, so check the mode as well as the connection.
    if let Ok(meta) = std::fs::metadata(socket) {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            report.fail(
                "agent socket",
                format!("{} is mode {mode:o}; expected 0700", socket.display()),
            );
        } else {
            report.ok(
                "agent socket",
                format!("{} (mode {mode:o})", socket.display()),
            );
        }
    }

    match IpcClient::connect(socket).await {
        Ok(client) => match client.ping().await {
            Ok(()) => report.ok("agent", "responding to ping"),
            Err(e) => report.fail("agent", format!("connected but did not answer: {e}")),
        },
        Err(e) => report.fail("agent", format!("could not connect: {e}")),
    }
}

fn check_disk(config: &FerrumConfig, report: &mut Report) {
    let dir = config
        .panel
        .database
        .parent()
        .unwrap_or(std::path::Path::new("/"));
    match available_bytes(dir) {
        Some(free) if free < 512 * 1024 * 1024 => {
            report.fail(
                "disk space",
                format!("{} free on {}", human_bytes(free), dir.display()),
            );
        }
        Some(free) if free < 2 * 1024 * 1024 * 1024 => {
            report.warn(
                "disk space",
                format!("{} free on {}", human_bytes(free), dir.display()),
            );
        }
        Some(free) => report.ok(
            "disk space",
            format!("{} free on {}", human_bytes(free), dir.display()),
        ),
        None => report.warn("disk space", format!("could not stat {}", dir.display())),
    }
}

/// Free space via `statvfs`, so the report works before any metrics exist.
fn available_bytes(path: &std::path::Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `stat` is a zeroed, correctly sized `statvfs`, and `c_path` is a
    // valid NUL-terminated string that outlives the call.
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &raw mut stat) != 0 {
            return None;
        }
        Some(stat.f_bavail as u64 * stat.f_frsize as u64)
    }
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

async fn status(config: &FerrumConfig) -> Result<()> {
    let client = IpcClient::connect(&config.agent.socket)
        .await
        .with_context(|| {
            format!(
                "could not reach the agent at {}",
                config.agent.socket.display()
            )
        })?;

    // The CLI runs as root on the same host; the agent still re-checks this
    // context against the database before acting on it.
    let auth = admin_auth(config).await?;

    let snapshot = client
        .call_ok("metrics.snapshot", &auth, serde_json::json!({}))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let cpu = snapshot["cpu"]["usage_pct"].as_f64().unwrap_or(0.0);
    let cores = snapshot["cpu"]["cores"].as_u64().unwrap_or(0);
    let mem_used = snapshot["memory"]["used_bytes"].as_u64().unwrap_or(0);
    let mem_total = snapshot["memory"]["total_bytes"].as_u64().unwrap_or(0);
    let load = snapshot["load"]["one"].as_f64().unwrap_or(0.0);
    let uptime = snapshot["uptime_seconds"].as_u64().unwrap_or(0);

    println!("cpu      {cpu:.1}% of {cores} core(s), load {load:.2}");
    println!(
        "memory   {} / {}",
        human_bytes(mem_used),
        human_bytes(mem_total)
    );
    println!("uptime   {}", format_uptime(uptime));

    if let Some(disks) = snapshot["disks"].as_array() {
        for disk in disks {
            let mount = disk["mount"].as_str().unwrap_or("?");
            let used = disk["used_bytes"].as_u64().unwrap_or(0);
            let total = disk["total_bytes"].as_u64().unwrap_or(1);
            println!(
                "disk     {mount}: {} / {} ({:.0}%)",
                human_bytes(used),
                human_bytes(total),
                used as f64 / total as f64 * 100.0
            );
        }
    }

    Ok(())
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    match (days, hours) {
        (0, 0) => format!("{minutes}m"),
        (0, h) => format!("{h}h {minutes}m"),
        (d, h) => format!("{d}d {h}h"),
    }
}

// ---------------------------------------------------------------------------
// user
// ---------------------------------------------------------------------------

async fn user(config: &FerrumConfig, cmd: UserCommand) -> Result<()> {
    let db = Db::open(&config.panel.database)
        .await
        .with_context(|| format!("could not open {}", config.panel.database.display()))?;

    match cmd {
        UserCommand::CreateAdmin {
            username,
            email,
            password_stdin,
        } => {
            if db.has_any_user().await? {
                anyhow::bail!(
                    "an account already exists; create further accounts from the panel so the \
                     action is audited"
                );
            }

            let password = if password_stdin {
                let mut buf = String::new();
                std::io::Write::flush(&mut std::io::stdout())?;
                std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut buf)?;
                buf.trim_end_matches(['\n', '\r']).to_string()
            } else {
                generate_password()
            };

            let created = db
                .users(&TenantScope::Global)
                .create(NewUser {
                    role: Role::Admin,
                    email: Email::parse(&email)?,
                    username: Username::parse(&username)?,
                    password: password.clone(),
                    reseller_id: None,
                    full_name: None,
                    locale: "en".into(),
                })
                .await?;

            println!(
                "created administrator `{}` (id {})",
                created.username, created.id
            );
            if !password_stdin {
                println!();
                println!("  password: {password}");
                println!();
                println!(
                    "This is the only time it is shown. Store it, then change it in the panel."
                );
            }
        }

        UserCommand::List => {
            let users = db.users(&TenantScope::Global).list(500, 0).await?;
            if users.is_empty() {
                println!("no accounts yet");
                return Ok(());
            }
            println!(
                "{:<6} {:<20} {:<10} {:<28} status",
                "id", "username", "role", "email"
            );
            for u in users {
                println!(
                    "{:<6} {:<20} {:<10} {:<28} {}",
                    u.id.get(),
                    u.username,
                    u.role.as_str(),
                    u.email,
                    u.status.as_str()
                );
            }
        }
    }

    db.close().await;
    Ok(())
}

/// A generated first password: long, random, and printed once.
///
/// Words would be friendlier, but shipping a wordlist to save an operator one
/// copy-paste is not a trade this project makes.
fn generate_password() -> String {
    use rand::Rng;
    // Ambiguous characters removed: this gets read off a terminal and retyped.
    const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

// ---------------------------------------------------------------------------
// ops
// ---------------------------------------------------------------------------

async fn ops(config: &FerrumConfig, cmd: OpsCommand) -> Result<()> {
    match cmd {
        OpsCommand::List => {
            let client = IpcClient::connect(&config.agent.socket)
                .await
                .with_context(|| {
                    format!(
                        "could not reach the agent at {}",
                        config.agent.socket.display()
                    )
                })?;
            let auth = admin_auth(config).await?;
            let info = client
                .call_ok("sys.ping", &auth, serde_json::json!({}))
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("agent {} on {}", info["agent_version"], info["distro"]);
            // TODO(scope): a `sys.operations` op would let the CLI list the
            // registry directly. Not needed until there is more than a handful.
        }
    }
    Ok(())
}

/// Build an auth context for the local administrator.
///
/// The CLI does not invent privileges: it names an existing admin account, and
/// the agent re-derives that account's rights from the database before acting
/// (spec §12 rule 4).
async fn admin_auth(config: &FerrumConfig) -> Result<AuthContext> {
    let db = Db::open(&config.panel.database).await?;
    let admin = db
        .users(&TenantScope::Global)
        .list(500, 0)
        .await?
        .into_iter()
        .find(|u| u.role == Role::Admin && u.status.can_log_in())
        .context("no active administrator account exists; run `ferrum user create-admin`")?;
    db.close().await;

    Ok(AuthContext::from_role(
        admin.id,
        Role::Admin,
        TenantScope::Global,
        format!("cli-{}", uuid_like()),
    ))
}

/// A short random request id. The CLI does not need real UUIDs, only something
/// unique enough to correlate one invocation's log lines.
fn uuid_like() -> String {
    use rand::Rng;
    let n: u64 = rand::thread_rng().r#gen();
    format!("{n:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passwords_are_long_and_unambiguous() {
        let a = generate_password();
        let b = generate_password();
        assert_ne!(a, b);
        assert_eq!(a.chars().count(), 24);
        for bad in ['l', 'I', '1', 'O', '0'] {
            assert!(!a.contains(bad), "`{bad}` is too easy to misread: {a}");
        }
        // And it must satisfy the panel's own policy.
        assert!(ferrum_db::password::check_strength(&a).is_ok());
    }

    #[test]
    fn uptime_reads_naturally() {
        assert_eq!(format_uptime(45), "0m");
        assert_eq!(format_uptime(600), "10m");
        assert_eq!(format_uptime(3_700), "1h 1m");
        assert_eq!(format_uptime(90_000), "1d 1h");
    }

    #[test]
    fn report_levels_drive_the_exit_code() {
        let mut r = Report::default();
        r.warn("docker", "not installed");
        assert_eq!(r.exit_code(), 0, "a warning must not fail a monitoring run");
        r.fail("agent", "socket missing");
        assert_eq!(r.exit_code(), 1);
    }
}
