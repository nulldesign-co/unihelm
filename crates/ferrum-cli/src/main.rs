//! `ferrum` — the command-line half of the panel (spec §11.20).
//!
//! The CLI reaches every operation the UI does, over the same Unix socket, with
//! the same identity model. It is not a second API: `session.rs` opens the
//! agent socket `ferrum-web` opens, and the agent re-derives the acting
//! account's rights from the database before it does anything (spec §12 rule 4).
//! There is no CLI-only privilege, no CLI-only endpoint and no CLI-only auth
//! path to keep in step.
//!
//! Three commands are answered without the agent, because they have to work
//! when it is not there:
//!
//! - **`ferrum doctor`**, the first thing to run when something looks wrong. It
//!   checks the pieces in the order they depend on each other, so the first
//!   failure is usually the real one.
//! - **`ferrum user create-admin`**, which the installer calls to create the
//!   first account, before any session, listener or agent exists.
//! - **`ferrum task …`**, which reads the task table directly; see `tasks.rs`.
//!
//! Output is a table by default and `--json` everywhere for scripting, and the
//! exit code is meaningful — see the table in `session.rs`.

mod cli;
mod completions;
mod invoke;
mod output;
mod parity;
mod report;
mod session;
mod tasks;

use anyhow::{Context, Result};
use clap::Parser;
use ferrum_core::config::FerrumConfig;
use ferrum_core::{Email, Role, TenantScope, Username};
use ferrum_db::Db;
use ferrum_db::users::NewUser;
use ferrum_distro::{Distro, SupportStatus};
use ferrum_ipc::IpcClient;

use crate::cli::{
    BackupCommand, BackupRepoCommand, Cli, Command, DnsCommand, MailCommand, MailRelayCommand,
    OpsCommand, SftpCommand, UserCommand,
};
use crate::invoke::{Action, Secrets, action_for};
use crate::report::{Report, human_bytes};
use crate::session::{EXIT_LOCAL_FAILURE, Session, TransportFailure};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let json = cli.json;
    let code = match run(cli).await {
        Ok(code) => code,
        Err(error) => report_failure(&error, json),
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<i32> {
    let config = load_config(&cli)?;

    match &cli.command {
        Command::Doctor => return doctor(&config, cli.json).await,
        Command::User(cmd) => {
            user(&config, cmd).await?;
            return Ok(0);
        }
        Command::Ops(OpsCommand::List) => {
            let table = parity::as_json();
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&table)?);
            } else {
                print!("{}", output::render("cli.ops", &table));
            }
            return Ok(0);
        }
        Command::Completions { shell } => {
            completions::generate(*shell, &mut std::io::stdout());
            return Ok(0);
        }
        Command::Task(cmd) => {
            // Reading tasks must work when the agent is down — that is exactly
            // when somebody wants to see why the last one failed. Only `cancel`
            // needs the socket.
            let session = if matches!(cmd, cli::TaskCommand::Cancel { .. }) {
                Session::connected(&config, cli.json, cli.follow).await?
            } else {
                Session::local(&config, cli.json, cli.follow).await?
            };
            let code = tasks::run(&session, cmd).await;
            session.close().await;
            return code;
        }
        _ => {}
    }

    // Secrets are read here, once, so the planner stays a pure function.
    let secrets = resolve_secrets(&cli.command)?;
    let action = action_for(&cli.command, &secrets)?;
    debug_assert!(
        !matches!(action, Action::Local),
        "a local command reached the agent path"
    );

    let session = Session::connected(&config, cli.json, cli.follow).await?;
    let code = session.execute(&action).await;
    session.close().await;
    code
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

/// Print a failure that never reached an operation, and answer with its exit
/// code.
///
/// A transport failure carries a real `FER-15xx` code and gets the same
/// treatment as an operation that ran and said no; anything else is the CLI
/// failing before it could ask, which is exit 1.
fn report_failure(error: &anyhow::Error, json: bool) -> i32 {
    if let Some(TransportFailure(ferrum)) = error.downcast_ref::<TransportFailure>() {
        if json {
            print_json(&serde_json::json!({
                "error": {
                    "code": ferrum.code.code(),
                    "slug": ferrum.code.slug(),
                    "detail": ferrum.detail,
                }
            }));
        } else {
            // The same shape `Session::report_error` uses, so a human sees one
            // format and a log grep matches both.
            eprintln!(
                "error: {} {}: {}",
                ferrum.code.code(),
                ferrum.code.slug(),
                ferrum.detail
            );
        }
        return session::exit_code_for(ferrum.code);
    }

    if json {
        print_json(&serde_json::json!({
            "error": { "code": null, "slug": "cli_error", "detail": format!("{error:#}") }
        }));
    } else {
        eprintln!("error: {error:#}");
    }
    EXIT_LOCAL_FAILURE
}

fn print_json(value: &serde_json::Value) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(e) => eprintln!("could not serialise the error: {e}"),
    }
}

// ---------------------------------------------------------------------------
// secrets
// ---------------------------------------------------------------------------

/// Resolve the one secret a command may need, from stdin or the environment.
///
/// Never from argv: a token given as `--token hunter2` is visible in
/// `/proc/<pid>/cmdline` to every account on the machine for as long as the
/// command runs, and lands in the shell history for ever after. No command in
/// `cli.rs` has a flag that takes one.
fn resolve_secrets(command: &Command) -> Result<Secrets> {
    let mut secrets = Secrets::default();
    match command {
        Command::Dns(DnsCommand::ProviderSet { token_stdin, .. }) => {
            secrets.dns_token = secret(*token_stdin, "FERRUM_DNS_TOKEN")?;
        }
        Command::Backup(BackupCommand::Repo(BackupRepoCommand::Init {
            s3_secret_stdin, ..
        })) => {
            secrets.s3_secret_access_key = secret(*s3_secret_stdin, "FERRUM_S3_SECRET_ACCESS_KEY")?;
        }
        Command::Sftp(SftpCommand::Enable { password_stdin, .. }) => {
            secrets.sftp_password = secret(*password_stdin, "FERRUM_SFTP_PASSWORD")?;
        }
        Command::Mail(MailCommand::Relay(MailRelayCommand::Set { password_stdin, .. })) => {
            secrets.mail_relay_password =
                secret_allowing_empty(*password_stdin, "FERRUM_MAIL_RELAY_PASSWORD", true)?;
        }
        _ => {}
    }
    Ok(secrets)
}

fn secret(from_stdin: bool, env_var: &str) -> Result<Option<String>> {
    secret_allowing_empty(from_stdin, env_var, false)
}

/// As `secret`, but `clearable` decides what an empty line means.
///
/// For a token or an access key it means the pipe delivered nothing and the
/// only honest answer is an error. For a password the operation lets you
/// clear, an empty line is a real instruction — so it has to survive as
/// `Some("")` rather than being rejected here or silently read as absent,
/// which the operation would take as "keep what is stored".
fn secret_allowing_empty(
    from_stdin: bool,
    env_var: &str,
    clearable: bool,
) -> Result<Option<String>> {
    if from_stdin {
        return Ok(Some(read_secret_line(clearable)?));
    }
    Ok(std::env::var(env_var).ok().filter(|v| !v.is_empty()))
}

/// One line from stdin, with the trailing newline removed and nothing else
/// touched — a token may legitimately contain anything else.
fn read_secret_line(allow_empty: bool) -> Result<String> {
    let mut buffer = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut buffer)
        .context("could not read the secret from stdin")?;
    let value = buffer.trim_end_matches(['\n', '\r']).to_string();
    if value.is_empty() && !allow_empty {
        anyhow::bail!("nothing arrived on stdin");
    }
    Ok(value)
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
// user
// ---------------------------------------------------------------------------

async fn user(config: &FerrumConfig, cmd: &UserCommand) -> Result<()> {
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

            let password = if *password_stdin {
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
                    email: Email::parse(email)?,
                    username: Username::parse(username)?,
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
            if !*password_stdin {
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
                db.close().await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Report;

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
    fn report_levels_drive_the_exit_code() {
        let mut r = Report::default();
        r.warn("docker", "not installed");
        assert_eq!(r.exit_code(), 0, "a warning must not fail a monitoring run");
        r.fail("agent", "socket missing");
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn a_secret_flag_prefers_stdin_but_falls_back_to_the_environment() {
        // SAFETY: single-threaded test, and the variable is removed again
        // before it can reach another one.
        unsafe { std::env::set_var("FERRUM_TEST_SECRET", "from-env") };
        assert_eq!(
            secret(false, "FERRUM_TEST_SECRET").unwrap(),
            Some("from-env".to_string())
        );
        unsafe { std::env::set_var("FERRUM_TEST_SECRET", "") };
        assert_eq!(
            secret(false, "FERRUM_TEST_SECRET").unwrap(),
            None,
            "an empty variable is not a credential"
        );
        unsafe { std::env::remove_var("FERRUM_TEST_SECRET") };
        assert_eq!(secret(false, "FERRUM_TEST_SECRET").unwrap(), None);
    }

    #[test]
    fn a_command_with_no_secret_resolves_none_and_never_reads_stdin() {
        // If this ever blocked, `ferrum site list` in a script with no stdin
        // would hang for ever.
        let cli = Cli::try_parse_from(["ferrum", "site", "list"]).unwrap();
        let secrets = resolve_secrets(&cli.command).unwrap();
        assert!(secrets.dns_token.is_none());
        assert!(secrets.s3_secret_access_key.is_none());
        assert!(secrets.sftp_password.is_none());
    }
}
