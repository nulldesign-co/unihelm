//! Tenant database management (spec §11.4): MariaDB and PostgreSQL databases,
//! users, passwords and grants.
//!
//! Three rules shape everything in this file:
//!
//! 1. **SQL is data, identifiers are types.** Every identifier that reaches a
//!    statement is a [`DbName`] — `[A-Za-z0-9_]`, validated at deserialization
//!    (spec §5.2 rule 1) — so it needs no quoting in either engine and
//!    identifier injection is impossible by construction. The only string
//!    *values* we ever embed are passwords we generated ourselves; they still
//!    go through [`quote_str`], whose contract is documented on the function.
//! 2. **SQL travels on stdin, never on argv.** `mariadb -e "..."` would put a
//!    password into `/proc/<pid>/cmdline` for anyone on the box to read. The
//!    clients read the batch from stdin instead (`psql -f -`; `mariadb` reads
//!    stdin natively), via [`ferrum_distro::Cmd::stdin_data`].
//! 3. **Passwords are shown once and stored never.** They are generated from a
//!    CSPRNG, returned in the operation's direct output, and exist afterwards
//!    only in the engine's own auth tables. That is why every operation here is
//!    `Execution::Immediate`: a Task's input is persisted in the tasks table
//!    and its logs stream and persist too, so a password-bearing response must
//!    ride the one channel that is never written down. The statements are
//!    single local DDLs over a unix socket — well inside the immediate budget.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ferrum_core::{DbName, ErrorCode, FerrumError, Permission, Result, SubscriptionId};
use ferrum_db::databases::{Database, DbEngine, DbUser, NewDatabase, NewDbUser};
use ferrum_db::subscriptions::Subscription;
use ferrum_distro::svc::ManagedUnit;
use ferrum_distro::{CmdOutput, Family};
use serde::{Deserialize, Serialize};

use crate::registry::{Execution, OpContext, TypedOperation};

// ---------------------------------------------------------------------------
// The shell: how a SQL batch reaches an engine
// ---------------------------------------------------------------------------

/// One batch for one engine, fully specified: the exact client argv and the
/// exact bytes for its stdin. Built by pure functions so tests can assert both
/// without running anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlJob {
    /// `argv[0]` is the program; the rest are its arguments, verbatim.
    pub argv: Vec<String>,
    /// The statements, written to the client's stdin and then EOF.
    pub sql: String,
    /// True when `sql` embeds a credential. A secret job's SQL and the client's
    /// diagnostics (which can echo the failing statement) must never reach a
    /// log line or an error detail.
    pub secret: bool,
}

/// The seam between "which statements" and "actually running a client".
///
/// Production uses [`SystemShell`]; tests install a recorder so operations can
/// be asserted down to the exact argv and stdin without MariaDB installed.
#[async_trait]
pub trait DbShell: Send + Sync {
    async fn run(&self, job: &SqlJob) -> Result<CmdOutput>;
}

/// Runs the real client through [`ferrum_distro::Cmd`] — argv array, resolved
/// against trusted directories, scrubbed environment, SQL on stdin.
pub struct SystemShell;

#[async_trait]
impl DbShell for SystemShell {
    async fn run(&self, job: &SqlJob) -> Result<CmdOutput> {
        let (program, args) = job
            .argv
            .split_first()
            .ok_or_else(|| FerrumError::internal("a SqlJob must carry a program"))?;
        ferrum_distro::Cmd::new(program.clone())
            .args(args)
            // Local DDL over a unix socket. 30 s is generous; the default 120 s
            // would hold an Immediate IPC round trip open far too long.
            .timeout(Duration::from_secs(30))
            .stdin_data(job.sql.as_bytes().to_vec())
            .run()
            .await
            .map_err(FerrumError::from)
    }
}

/// The shell operations actually use. In tests, a per-thread recorder can be
/// installed; in production this is always [`SystemShell`].
fn shell() -> Arc<dyn DbShell> {
    #[cfg(test)]
    if let Some(s) = testing::installed_shell() {
        return s;
    }
    Arc::new(SystemShell)
}

/// Run one job through the installed shell.
///
/// The public entry point for modules outside this one — `harden` uses it to
/// run the post-install SQL — so they get the same argv discipline, the same
/// secret handling, and the same test recorder.
pub async fn run_sql(job: &SqlJob) -> Result<CmdOutput> {
    execute(shell().as_ref(), job).await
}

/// Run a job and turn a non-zero exit into an error — with the client's own
/// diagnostics when they are safe to show, and without them when the statement
/// carried a credential (both engines echo parts of a failing statement).
async fn execute(shell: &dyn DbShell, job: &SqlJob) -> Result<CmdOutput> {
    let out = shell.run(job).await?;
    if out.success() {
        return Ok(out);
    }
    if job.secret {
        Err(FerrumError::new(
            ErrorCode::CommandFailed,
            format!(
                "the {} client refused the statement (exit {}); its output is withheld because \
                 the statement carried a credential",
                out.program, out.status
            ),
        ))
    } else {
        Err(FerrumError::new(
            ErrorCode::CommandFailed,
            out.failure_text(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Client invocations (researched Phase 2 argv patterns — keep them exact)
// ---------------------------------------------------------------------------

/// The `mariadb` client argv for root-over-socket administration.
///
/// - `--no-defaults` **must be the first option**: MySQL-family clients only
///   honour it there. Without it a `/etc/my.cnf` or `~/.my.cnf` edited by
///   anyone could silently redirect the client at another host or add options.
/// - `--protocol=socket` + an explicit per-family socket path: root on the
///   local socket is authenticated by the `unix_socket` plugin, so there is no
///   password to manage, and the connection can never accidentally go over TCP.
/// - `--batch` disables interactive niceties and history files.
/// - Query mode adds `--skip-column-names` so "does X exist" answers are just
///   the value, not a header to parse around.
pub fn mysql_argv(family: Family, query: bool) -> Vec<String> {
    let socket = match family {
        Family::Debian => "/run/mysqld/mysqld.sock",
        Family::Rhel => "/var/lib/mysql/mysql.sock",
    };
    let mut argv = vec![
        "mariadb".to_string(),
        "--no-defaults".to_string(),
        "--protocol=socket".to_string(),
        format!("--socket={socket}"),
        "--user=root".to_string(),
        "--batch".to_string(),
    ];
    if query {
        argv.push("--skip-column-names".to_string());
    }
    argv
}

/// The `psql` argv for postgres-over-socket administration.
///
/// - `-v ON_ERROR_STOP=1`: without it psql runs *past* a failed statement and
///   still exits 0, which would turn "the CREATE failed" into silent success.
/// - `-U postgres -h /var/run/postgresql`: the superuser over the local socket
///   directory (peer/local auth; no password involved).
/// - `-f -` reads the batch from stdin — the whole point, see the module docs.
/// - Query mode adds `-tA` (tuples only, unaligned) for parseable answers.
pub fn postgres_argv(query: bool) -> Vec<String> {
    let mut argv = vec![
        "psql".to_string(),
        "-v".to_string(),
        "ON_ERROR_STOP=1".to_string(),
        "-U".to_string(),
        "postgres".to_string(),
        "-h".to_string(),
        "/var/run/postgresql".to_string(),
    ];
    if query {
        argv.push("-tA".to_string());
    }
    argv.push("-f".to_string());
    argv.push("-".to_string());
    argv
}

fn argv_for(family: Family, engine: DbEngine, query: bool) -> Vec<String> {
    match engine {
        DbEngine::Mysql => mysql_argv(family, query),
        DbEngine::Postgres => postgres_argv(query),
    }
}

// ---------------------------------------------------------------------------
// Statement builders (pure, and the quoting contract)
// ---------------------------------------------------------------------------

/// Quote a string **value** for a SQL literal. The exact contract, per engine:
///
/// - **PostgreSQL**: with `standard_conforming_strings = on` (the server
///   default since 9.1), `''` is the *only* escape inside a `'...'` literal and
///   backslash is an ordinary character. Doubling quotes is therefore complete.
/// - **MariaDB**: backslash *is* an escape character inside string literals
///   unless `sql_mode` contains `NO_BACKSLASH_ESCAPES`. Doubling quotes is
///   valid there too — so a value with quotes doubled and **no backslashes**
///   parses to the same bytes under every `sql_mode`.
///
/// Hence one contract for both engines: reject backslashes and control bytes
/// outright, double every `'`. In practice the only values quoted here are
/// passwords from [`generate_password`], whose alphabet contains none of the
/// rejected bytes — this function is the belt to that braces.
pub fn quote_str(value: &str) -> Result<String> {
    if value
        .bytes()
        .any(|b| b == b'\\' || b.is_ascii_control())
    {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "string values in SQL may not contain backslashes or control characters",
        ));
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

/// Quote a [`DbName`] appearing in a string-literal position (existence
/// probes). Its alphabet can never trip [`quote_str`], hence the expect.
fn quote_name(name: &DbName) -> String {
    quote_str(name.as_str()).expect("a DbName contains no quotes, backslashes or control bytes")
}

/// A MySQL account in `'user'@'localhost'` form. `localhost` is deliberate:
/// remote access is a separate, firewall-coupled flow (spec §11.4), not a
/// default anyone gets for free.
fn mysql_account(user: &DbName) -> String {
    format!("'{}'@'localhost'", user.as_str())
}

pub fn sql_db_exists(engine: DbEngine, name: &DbName) -> String {
    match engine {
        DbEngine::Mysql => format!(
            "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = {};\n",
            quote_name(name)
        ),
        DbEngine::Postgres => format!(
            "SELECT 1 FROM pg_database WHERE datname = {};\n",
            quote_name(name)
        ),
    }
}

pub fn sql_user_exists(engine: DbEngine, user: &DbName) -> String {
    match engine {
        DbEngine::Mysql => format!(
            "SELECT 1 FROM mysql.user WHERE User = {} AND Host = 'localhost';\n",
            quote_name(user)
        ),
        DbEngine::Postgres => format!(
            "SELECT 1 FROM pg_roles WHERE rolname = {};\n",
            quote_name(user)
        ),
    }
}

/// The create statement, plus — when an owner is bound — the grant that makes
/// the database usable, in one stdin batch so both run or the client reports
/// which failed.
///
/// PostgreSQL expresses ownership in the CREATE itself (`OWNER`), which is the
/// strong form: the owner holds every privilege on the database. MySQL has no
/// per-database owner, so the closest equivalent is `GRANT ALL ON name.*`.
pub fn sql_create_db(engine: DbEngine, name: &DbName, owner: Option<&DbName>) -> String {
    match (engine, owner) {
        (DbEngine::Mysql, None) => format!("CREATE DATABASE {};\n", name.as_str()),
        (DbEngine::Mysql, Some(user)) => format!(
            "CREATE DATABASE {};\nGRANT ALL PRIVILEGES ON {}.* TO {};\n",
            name.as_str(),
            name.as_str(),
            mysql_account(user)
        ),
        (DbEngine::Postgres, None) => format!("CREATE DATABASE {};\n", name.as_str()),
        (DbEngine::Postgres, Some(user)) => format!(
            "CREATE DATABASE {} OWNER {};\n",
            name.as_str(),
            user.as_str()
        ),
    }
}

/// `IF EXISTS` on purpose: a drop that half-finished (engine dropped, metadata
/// row left behind) must be re-runnable to completion, not stuck on an error.
pub fn sql_drop_db(engine: DbEngine, name: &DbName) -> String {
    match engine {
        DbEngine::Mysql => format!("DROP DATABASE IF EXISTS {};\n", name.as_str()),
        DbEngine::Postgres => format!("DROP DATABASE IF EXISTS {};\n", name.as_str()),
    }
}

pub fn sql_create_user(engine: DbEngine, user: &DbName, password: &str) -> Result<String> {
    let pw = quote_str(password)?;
    Ok(match engine {
        DbEngine::Mysql => format!(
            "CREATE USER {} IDENTIFIED BY {};\n",
            mysql_account(user),
            pw
        ),
        DbEngine::Postgres => format!(
            "CREATE ROLE {} WITH LOGIN PASSWORD {};\n",
            user.as_str(),
            pw
        ),
    })
}

pub fn sql_drop_user(engine: DbEngine, user: &DbName) -> String {
    match engine {
        DbEngine::Mysql => format!("DROP USER IF EXISTS {};\n", mysql_account(user)),
        DbEngine::Postgres => format!("DROP ROLE IF EXISTS {};\n", user.as_str()),
    }
}

pub fn sql_set_password(engine: DbEngine, user: &DbName, password: &str) -> Result<String> {
    let pw = quote_str(password)?;
    Ok(match engine {
        DbEngine::Mysql => format!("ALTER USER {} IDENTIFIED BY {};\n", mysql_account(user), pw),
        DbEngine::Postgres => {
            format!("ALTER ROLE {} WITH PASSWORD {};\n", user.as_str(), pw)
        }
    })
}

/// MySQL: full control over the one database. PostgreSQL: `GRANT ALL ON
/// DATABASE` is connect/create/temp — table-level rights come from ownership,
/// which is what `db.create` with an owner sets up; this grant is the "second
/// user on an existing database" path.
pub fn sql_grant(engine: DbEngine, name: &DbName, user: &DbName) -> String {
    match engine {
        DbEngine::Mysql => format!(
            "GRANT ALL PRIVILEGES ON {}.* TO {};\n",
            name.as_str(),
            mysql_account(user)
        ),
        DbEngine::Postgres => format!(
            "GRANT ALL PRIVILEGES ON DATABASE {} TO {};\n",
            name.as_str(),
            user.as_str()
        ),
    }
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

/// 24 characters over `[A-Za-z0-9]` ≈ 143 bits from the thread-local CSPRNG.
///
/// The alphabet deliberately contains nothing [`quote_str`] escapes or rejects
/// — the password would be safe to embed even if the quoting were wrong, and it
/// pastes cleanly into every client and `.env` file.
pub fn generate_password() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const LEN: usize = 24;
    let mut rng = rand::thread_rng();
    (0..LEN)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

// ---------------------------------------------------------------------------
// Shared op plumbing
// ---------------------------------------------------------------------------

const fn engine_unit(engine: DbEngine) -> ManagedUnit {
    match engine {
        DbEngine::Mysql => ManagedUnit::MariaDb,
        DbEngine::Postgres => ManagedUnit::PostgreSql,
    }
}

const fn engine_slug(engine: DbEngine) -> &'static str {
    match engine {
        DbEngine::Mysql => "mariadb",
        DbEngine::Postgres => "postgresql",
    }
}

const fn engine_display(engine: DbEngine) -> &'static str {
    match engine {
        DbEngine::Mysql => "MariaDB",
        DbEngine::Postgres => "PostgreSQL",
    }
}

/// Refuse to manage objects on an engine that is not there.
///
/// Same shape as `require_php_installed`: our own bookkeeping first, then
/// systemd's view for engines installed before (or without) the panel. The
/// client binary erroring with "not found" later would be true but useless;
/// this error says what to do about it.
async fn require_engine_ready(ctx: &OpContext, engine: DbEngine) -> Result<()> {
    let installed = ctx
        .db()
        .component(engine_slug(engine))
        .await
        .map_err(FerrumError::from)?
        .map(|c| c.status == ferrum_db::ComponentStatus::Installed)
        .unwrap_or(false);
    if installed {
        return Ok(());
    }

    let unit = engine_unit(engine).unit_name(ctx.distro().info.family);
    if ctx
        .distro()
        .svc
        .status(&unit)
        .await
        .map(|s| s.is_installed())
        .unwrap_or(false)
    {
        return Ok(());
    }

    Err(FerrumError::new(
        ErrorCode::NotFound,
        format!(
            "{} is not installed. Install it from the Stack Manager first.",
            engine_display(engine)
        ),
    )
    .with_field("engine"))
}

/// Which subscription owns the object — the caller's own by default, or a
/// named one the caller's scope can actually see (same contract as
/// `site.create`). Suspended subscriptions cannot gain resources.
async fn resolve_subscription(ctx: &OpContext, id: Option<i64>) -> Result<Subscription> {
    let db = ctx.db();
    let subscription = match id {
        Some(raw) => db
            .subscriptions(ctx.scope())
            .by_id(SubscriptionId(raw))
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("subscription"))?,
        None => db
            .default_subscription_for(ctx.auth().actor_user_id)
            .await
            .map_err(FerrumError::from)?,
    };
    if !subscription.status.can_serve() {
        return Err(FerrumError::new(
            ErrorCode::AccountSuspended,
            "this subscription is suspended and cannot manage databases",
        ));
    }
    Ok(subscription)
}

// ---------------------------------------------------------------------------
// db.list
// ---------------------------------------------------------------------------

pub struct List;

#[derive(Debug, Deserialize)]
pub struct ListInput {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub databases: Vec<Database>,
    pub users: Vec<DbUser>,
}

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "db.list";
    const PERMISSION: Permission = Permission::DbManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let repo = ctx.db().databases(ctx.scope());
        let limit = input.limit.unwrap_or(100);
        let offset = input.offset.unwrap_or(0);
        Ok(ListOutput {
            databases: repo.list(limit, offset).await.map_err(FerrumError::from)?,
            users: repo
                .list_users(limit, offset)
                .await
                .map_err(FerrumError::from)?,
        })
    }
}

// ---------------------------------------------------------------------------
// db.create
// ---------------------------------------------------------------------------

pub struct Create;

#[derive(Debug, Deserialize)]
pub struct CreateInput {
    pub name: DbName,
    pub engine: DbEngine,
    /// Which subscription owns it. Defaults to the caller's own.
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// An existing database user to bind as owner (`GRANT ALL` on MySQL,
    /// `OWNER` on PostgreSQL). Must belong to the same subscription and engine.
    #[serde(default)]
    pub owner: Option<DbName>,
}

#[derive(Debug, Serialize)]
pub struct CreateOutput {
    pub database_id: i64,
    pub name: String,
    pub engine: DbEngine,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

#[async_trait]
impl TypedOperation for Create {
    type Input = CreateInput;
    type Output = CreateOutput;

    const NAME: &'static str = "db.create";
    const PERMISSION: Permission = Permission::DbManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db().clone();
        let subscription = resolve_subscription(ctx, input.subscription_id).await?;
        require_engine_ready(ctx, input.engine).await?;

        // An owner must already exist, in the same subscription and engine —
        // binding someone else's user would be a cross-tenant grant.
        if let Some(owner) = &input.owner {
            let user = db
                .databases(ctx.scope())
                .user_by_name(owner.as_str())
                .await
                .map_err(FerrumError::from)?
                .ok_or_else(|| FerrumError::not_found("database user"))?;
            if user.engine != input.engine || user.subscription_id != subscription.id {
                return Err(FerrumError::new(
                    ErrorCode::InvalidInput,
                    "the owner must be a database user of the same engine and subscription",
                )
                .with_field("owner"));
            }
        }

        // Metadata probe first for a precise answer, engine probe second so a
        // database created outside the panel is refused rather than adopted —
        // CREATE would fail anyway, but "exists outside the panel" beats a raw
        // client error. The UNIQUE index remains the racing-writers authority.
        if db
            .database_by_name_global(input.name.as_str())
            .await
            .map_err(FerrumError::from)?
            .is_some()
        {
            return Err(FerrumError::new(
                ErrorCode::AlreadyExists,
                format!("`{}` is already a managed database", input.name.as_str()),
            ));
        }

        let sh = shell();
        let family = ctx.distro().info.family;
        let probe = SqlJob {
            argv: argv_for(family, input.engine, true),
            sql: sql_db_exists(input.engine, &input.name),
            secret: false,
        };
        if !execute(sh.as_ref(), &probe).await?.trimmed_stdout().is_empty() {
            return Err(FerrumError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "a {} database named `{}` already exists on this server outside the panel",
                    engine_display(input.engine),
                    input.name.as_str()
                ),
            ));
        }

        // Claim the name in metadata before touching the engine, so two racing
        // creates resolve on the UNIQUE index — only the winner runs CREATE.
        let row = db
            .create_database(NewDatabase {
                subscription_id: subscription.id,
                engine: input.engine,
                name: input.name.as_str().to_string(),
            })
            .await
            .map_err(FerrumError::from)?;

        let create = SqlJob {
            argv: argv_for(family, input.engine, false),
            sql: sql_create_db(input.engine, &input.name, input.owner.as_ref()),
            secret: false,
        };
        if let Err(e) = execute(sh.as_ref(), &create).await {
            // Compensate: the engine refused, so the claim must be released or
            // the name is burned forever.
            let _ = db
                .databases(&ferrum_core::TenantScope::Global)
                .delete(row.id)
                .await;
            return Err(e);
        }

        ctx.log(format!(
            "created {} database {}",
            engine_display(input.engine),
            input.name.as_str()
        ));
        Ok(CreateOutput {
            database_id: row.id,
            name: row.name,
            engine: row.engine,
            owner: input.owner.map(|o| o.as_str().to_string()),
        })
    }
}

// ---------------------------------------------------------------------------
// db.drop
// ---------------------------------------------------------------------------

pub struct Drop;

#[derive(Debug, Deserialize)]
pub struct DropInput {
    pub database_id: i64,
    /// Must equal the database's name, retyped. There is no precedent to copy —
    /// `site.delete` guards its destructive half behind a `purge_files` flag
    /// because a vhost is re-renderable — but dropped data has no re-render, so
    /// this uses the type-the-name pattern instead of a boolean a UI could
    /// default to `true`.
    pub confirm_name: String,
}

#[derive(Debug, Serialize)]
pub struct DropOutput {
    pub name: String,
    pub engine: DbEngine,
    pub dropped: bool,
}

#[async_trait]
impl TypedOperation for Drop {
    type Input = DropInput;
    type Output = DropOutput;

    const NAME: &'static str = "db.drop";
    const PERMISSION: Permission = Permission::DbManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();
        let repo = db.databases(ctx.scope());
        let found = repo
            .by_id(input.database_id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("database"))?;

        if input.confirm_name != found.name {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!(
                    "type the database's name (`{}`) to confirm dropping it",
                    found.name
                ),
            )
            .with_field("confirm_name"));
        }

        // Engine first, metadata second: if the DROP fails the row survives to
        // describe what still exists; if the row delete fails the next attempt
        // hits `IF EXISTS` and completes.
        let name = DbName::parse(&found.name)?;
        let job = SqlJob {
            argv: argv_for(ctx.distro().info.family, found.engine, false),
            sql: sql_drop_db(found.engine, &name),
            secret: false,
        };
        execute(shell().as_ref(), &job).await?;

        repo.delete(found.id).await.map_err(FerrumError::from)?;
        ctx.log(format!("dropped database {}", found.name));
        Ok(DropOutput {
            name: found.name,
            engine: found.engine,
            dropped: true,
        })
    }
}

// ---------------------------------------------------------------------------
// db.user.create
// ---------------------------------------------------------------------------

pub struct UserCreate;

#[derive(Debug, Deserialize)]
pub struct UserCreateInput {
    pub username: DbName,
    pub engine: DbEngine,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserCreateOutput {
    pub user_id: i64,
    pub username: String,
    pub engine: DbEngine,
    /// Shown exactly once, here. The panel keeps no copy — losing it means
    /// resetting it (`db.user.password`), never recovering it.
    pub password: String,
}

#[async_trait]
impl TypedOperation for UserCreate {
    type Input = UserCreateInput;
    type Output = UserCreateOutput;

    const NAME: &'static str = "db.user.create";
    const PERMISSION: Permission = Permission::DbManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db().clone();
        let subscription = resolve_subscription(ctx, input.subscription_id).await?;
        require_engine_ready(ctx, input.engine).await?;

        if db
            .db_user_by_name_global(input.username.as_str())
            .await
            .map_err(FerrumError::from)?
            .is_some()
        {
            return Err(FerrumError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "`{}` is already a managed database user",
                    input.username.as_str()
                ),
            ));
        }

        let sh = shell();
        let family = ctx.distro().info.family;
        let probe = SqlJob {
            argv: argv_for(family, input.engine, true),
            sql: sql_user_exists(input.engine, &input.username),
            secret: false,
        };
        if !execute(sh.as_ref(), &probe).await?.trimmed_stdout().is_empty() {
            return Err(FerrumError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "a {} user named `{}` already exists on this server outside the panel",
                    engine_display(input.engine),
                    input.username.as_str()
                ),
            ));
        }

        let row = db
            .create_db_user(NewDbUser {
                subscription_id: subscription.id,
                engine: input.engine,
                username: input.username.as_str().to_string(),
            })
            .await
            .map_err(FerrumError::from)?;

        let password = generate_password();
        let create = SqlJob {
            argv: argv_for(family, input.engine, false),
            sql: sql_create_user(input.engine, &input.username, &password)?,
            secret: true,
        };
        if let Err(e) = execute(sh.as_ref(), &create).await {
            let _ = db
                .databases(&ferrum_core::TenantScope::Global)
                .delete_user(row.id)
                .await;
            return Err(e);
        }

        // Log the event, never the credential.
        ctx.log(format!(
            "created {} user {}",
            engine_display(input.engine),
            input.username.as_str()
        ));
        Ok(UserCreateOutput {
            user_id: row.id,
            username: row.username,
            engine: row.engine,
            password,
        })
    }
}

// ---------------------------------------------------------------------------
// db.user.drop
// ---------------------------------------------------------------------------

pub struct UserDrop;

#[derive(Debug, Deserialize)]
pub struct UserDropInput {
    pub username: DbName,
}

#[derive(Debug, Serialize)]
pub struct UserDropOutput {
    pub username: String,
    pub engine: DbEngine,
    pub dropped: bool,
}

#[async_trait]
impl TypedOperation for UserDrop {
    type Input = UserDropInput;
    type Output = UserDropOutput;

    const NAME: &'static str = "db.user.drop";
    const PERMISSION: Permission = Permission::DbManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let repo = ctx.db().databases(ctx.scope());
        let found = repo
            .user_by_name(input.username.as_str())
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("database user"))?;

        // Engine first, metadata second — same reasoning as db.drop. Note that
        // PostgreSQL refuses to drop a role that still owns a database; that
        // error surfaces verbatim so the operator knows to drop or reassign the
        // database first, rather than us cascading through owned objects.
        let job = SqlJob {
            argv: argv_for(ctx.distro().info.family, found.engine, false),
            sql: sql_drop_user(found.engine, &input.username),
            secret: false,
        };
        execute(shell().as_ref(), &job).await?;

        repo.delete_user(found.id).await.map_err(FerrumError::from)?;
        ctx.log(format!("dropped database user {}", found.username));
        Ok(UserDropOutput {
            username: found.username,
            engine: found.engine,
            dropped: true,
        })
    }
}

// ---------------------------------------------------------------------------
// db.user.password
// ---------------------------------------------------------------------------

pub struct UserPassword;

#[derive(Debug, Deserialize)]
pub struct UserPasswordInput {
    pub username: DbName,
}

#[derive(Debug, Serialize)]
pub struct UserPasswordOutput {
    pub username: String,
    pub engine: DbEngine,
    /// The new password — shown once, stored nowhere, like at creation.
    pub password: String,
}

#[async_trait]
impl TypedOperation for UserPassword {
    type Input = UserPasswordInput;
    type Output = UserPasswordOutput;

    const NAME: &'static str = "db.user.password";
    const PERMISSION: Permission = Permission::DbManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();
        let found = db
            .databases(ctx.scope())
            .user_by_name(input.username.as_str())
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("database user"))?;

        let password = generate_password();
        let job = SqlJob {
            argv: argv_for(ctx.distro().info.family, found.engine, false),
            sql: sql_set_password(found.engine, &input.username, &password)?,
            secret: true,
        };
        execute(shell().as_ref(), &job).await?;

        db.touch_db_user(found.id).await.map_err(FerrumError::from)?;
        ctx.log(format!("reset the password of {}", found.username));
        Ok(UserPasswordOutput {
            username: found.username,
            engine: found.engine,
            password,
        })
    }
}

// ---------------------------------------------------------------------------
// db.grant
// ---------------------------------------------------------------------------

pub struct Grant;

#[derive(Debug, Deserialize)]
pub struct GrantInput {
    pub database: DbName,
    pub username: DbName,
}

#[derive(Debug, Serialize)]
pub struct GrantOutput {
    pub database: String,
    pub username: String,
    pub engine: DbEngine,
    pub granted: bool,
}

#[async_trait]
impl TypedOperation for Grant {
    type Input = GrantInput;
    type Output = GrantOutput;

    const NAME: &'static str = "db.grant";
    const PERMISSION: Permission = Permission::DbManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let repo = ctx.db().databases(ctx.scope());

        // Both ends resolved inside the caller's scope: a grant is only ever
        // wired between objects the caller could already see.
        let database = repo
            .by_name(input.database.as_str())
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("database"))?;
        let user = repo
            .user_by_name(input.username.as_str())
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("database user"))?;

        if database.engine != user.engine {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "the database and the user live in different engines",
            )
            .with_field("username"));
        }
        // Cross-subscription grants would quietly couple two tenants' lifecycles
        // (dropping one subscription's user revokes another's access).
        if database.subscription_id != user.subscription_id {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "the database and the user belong to different subscriptions",
            )
            .with_field("username"));
        }

        let job = SqlJob {
            argv: argv_for(ctx.distro().info.family, database.engine, false),
            sql: sql_grant(database.engine, &input.database, &input.username),
            secret: false,
        };
        execute(shell().as_ref(), &job).await?;

        ctx.log(format!(
            "granted {} access to {}",
            input.username.as_str(),
            input.database.as_str()
        ));
        Ok(GrantOutput {
            database: database.name,
            username: user.username,
            engine: database.engine,
            granted: true,
        })
    }
}

// ---------------------------------------------------------------------------
// Test plumbing: install a recording shell for the current thread
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    thread_local! {
        // Thread-local rather than global: `#[tokio::test]` runs each test's
        // future on its own thread (current-thread runtime), so recorders never
        // bleed between concurrently running tests.
        static SHELL: RefCell<Option<Arc<dyn DbShell>>> = const { RefCell::new(None) };
    }

    pub fn install_shell(shell: Arc<dyn DbShell>) {
        SHELL.with(|s| *s.borrow_mut() = Some(shell));
    }

    pub fn installed_shell() -> Option<Arc<dyn DbShell>> {
        SHELL.with(|s| s.borrow().clone())
    }

    /// Records every job and answers with scripted outputs (default: success
    /// with empty stdout, i.e. "does not exist" for probes).
    #[derive(Default)]
    pub struct RecordingShell {
        pub jobs: Mutex<Vec<SqlJob>>,
        pub scripted: Mutex<VecDeque<CmdOutput>>,
    }

    impl RecordingShell {
        pub fn recorded(&self) -> Vec<SqlJob> {
            self.jobs.lock().expect("shell mutex").clone()
        }

        pub fn clear(&self) {
            self.jobs.lock().expect("shell mutex").clear();
        }

        pub fn script(&self, out: CmdOutput) {
            self.scripted.lock().expect("shell mutex").push_back(out);
        }

        pub fn output(program: &str, status: i32, stdout: &str, stderr: &str) -> CmdOutput {
            CmdOutput {
                program: program.to_string(),
                status,
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
                duration: Duration::from_millis(1),
            }
        }
    }

    #[async_trait]
    impl DbShell for RecordingShell {
        async fn run(&self, job: &SqlJob) -> Result<CmdOutput> {
            self.jobs.lock().expect("shell mutex").push(job.clone());
            Ok(self
                .scripted
                .lock()
                .expect("shell mutex")
                .pop_front()
                .unwrap_or_else(|| Self::output(&job.argv[0], 0, "", "")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::registry::OpRegistry;
    use crate::registry::testing::{auth_for, registry};
    use ferrum_core::{Role, UserId};
    use serde_json::json;

    async fn setup() -> (OpRegistry, UserId, UserId, Arc<RecordingShell>) {
        let (reg, admin, customer) = registry().await;
        // Pretend both engines are installed, the way the Stack Manager records
        // them (claim creates the row, installed finalises it); the mock
        // systemd knows no units, so this is the path taken.
        for slug in ["mariadb", "postgresql"] {
            let db = &reg.services().db;
            db.claim_component(slug, ferrum_db::ComponentStatus::Installing, "test-task")
                .await
                .unwrap();
            db.component_installed(slug, Some("1.0-mock")).await.unwrap();
        }
        let sh = Arc::new(RecordingShell::default());
        install_shell(sh.clone());
        (reg, admin, customer, sh)
    }

    async fn dispatch(
        reg: &OpRegistry,
        user: UserId,
        role: Role,
        op: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value> {
        reg.dispatch(op, &auth_for(user, role), input, None).await
    }

    // --- pure builders ------------------------------------------------------

    #[test]
    fn the_mariadb_invocation_is_exactly_the_researched_pattern() {
        // --no-defaults is only honoured as the first option; if this test
        // fails because someone reordered the argv, that is the bug it caught.
        let argv = mysql_argv(Family::Debian, false);
        assert_eq!(
            argv,
            vec![
                "mariadb",
                "--no-defaults",
                "--protocol=socket",
                "--socket=/run/mysqld/mysqld.sock",
                "--user=root",
                "--batch",
            ]
        );
        assert_eq!(argv[1], "--no-defaults");

        let rhel = mysql_argv(Family::Rhel, true);
        assert!(rhel.contains(&"--socket=/var/lib/mysql/mysql.sock".to_string()));
        assert_eq!(rhel.last().unwrap(), "--skip-column-names");
    }

    #[test]
    fn the_psql_invocation_reads_sql_from_stdin_and_stops_on_error() {
        assert_eq!(
            postgres_argv(false),
            vec![
                "psql",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                "-h",
                "/var/run/postgresql",
                "-f",
                "-",
            ]
        );
        let q = postgres_argv(true);
        assert_eq!(q[q.len() - 3..].to_vec(), vec!["-tA", "-f", "-"]);
    }

    #[test]
    fn hostile_looking_but_valid_names_stay_inert_in_sql() {
        // These pass DbName validation — letters, digits, underscores — and
        // MUST appear bare and harmless. If any of these needed quoting, the
        // newtype's alphabet would be wrong, not the builder.
        for name in ["drop_database_x", "union_select_1", "_default", "OR_1_1"] {
            let n = DbName::parse(name).unwrap();
            assert_eq!(
                sql_create_db(DbEngine::Mysql, &n, None),
                format!("CREATE DATABASE {name};\n")
            );
            assert_eq!(
                sql_db_exists(DbEngine::Postgres, &n),
                format!("SELECT 1 FROM pg_database WHERE datname = '{name}';\n")
            );
        }
    }

    #[test]
    fn create_with_owner_binds_per_engine_semantics() {
        let name = DbName::parse("shop").unwrap();
        let owner = DbName::parse("shop_rw").unwrap();
        assert_eq!(
            sql_create_db(DbEngine::Mysql, &name, Some(&owner)),
            "CREATE DATABASE shop;\nGRANT ALL PRIVILEGES ON shop.* TO 'shop_rw'@'localhost';\n"
        );
        assert_eq!(
            sql_create_db(DbEngine::Postgres, &name, Some(&owner)),
            "CREATE DATABASE shop OWNER shop_rw;\n"
        );
    }

    #[test]
    fn string_quoting_doubles_quotes_and_rejects_escape_material() {
        assert_eq!(quote_str("plain").unwrap(), "'plain'");
        assert_eq!(quote_str("a'b").unwrap(), "'a''b'");
        assert_eq!(quote_str("''").unwrap(), "''''''");
        // Backslash is an escape character in MariaDB's default sql_mode; a
        // value containing one could re-open the literal we just closed.
        assert!(quote_str("a\\b").is_err());
        assert!(quote_str("a\nb").is_err());
        assert!(quote_str("a\0b").is_err());
    }

    #[test]
    fn generated_passwords_are_long_random_and_need_no_escaping() {
        let a = generate_password();
        let b = generate_password();
        assert_eq!(a.len(), 24);
        assert_ne!(a, b, "two CSPRNG passwords colliding is a broken RNG");
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        // The alphabet must stay disjoint from everything quote_str treats
        // specially, so quoting stays belt-and-braces.
        assert!(!a.contains('\'') && !a.contains('\\'));
    }

    // --- op level -----------------------------------------------------------

    #[tokio::test]
    async fn db_create_probes_then_creates_with_the_exact_argv_and_stdin() {
        let (reg, _, customer, sh) = setup().await;
        let out = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "shop_db", "engine": "mysql" }),
        )
        .await
        .unwrap();
        assert_eq!(out["name"], "shop_db");

        let jobs = sh.recorded();
        assert_eq!(jobs.len(), 2, "one existence probe, one CREATE");
        assert_eq!(
            jobs[0].argv,
            mysql_argv(Family::Debian, true),
            "the probe uses query mode"
        );
        assert_eq!(
            jobs[0].sql,
            "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'shop_db';\n"
        );
        assert_eq!(jobs[1].argv, mysql_argv(Family::Debian, false));
        assert_eq!(jobs[1].sql, "CREATE DATABASE shop_db;\n");
        assert!(!jobs[1].secret);
    }

    #[tokio::test]
    async fn db_create_on_postgres_goes_through_psql() {
        let (reg, _, customer, sh) = setup().await;
        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "warehouse", "engine": "postgres" }),
        )
        .await
        .unwrap();

        let jobs = sh.recorded();
        assert_eq!(jobs[0].argv, postgres_argv(true));
        assert_eq!(jobs[1].argv, postgres_argv(false));
        assert_eq!(jobs[1].sql, "CREATE DATABASE warehouse;\n");
    }

    #[tokio::test]
    async fn a_database_that_exists_outside_the_panel_is_refused_not_adopted() {
        let (reg, _, customer, sh) = setup().await;
        // The engine-level probe answers "1": something already lives there.
        sh.script(RecordingShell::output("mariadb", 0, "1\n", ""));

        let err = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "preexisting", "engine": "mysql" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::AlreadyExists);
        assert_eq!(sh.recorded().len(), 1, "no CREATE may follow a hit probe");
        assert!(
            reg.services()
                .db
                .database_by_name_global("preexisting")
                .await
                .unwrap()
                .is_none(),
            "a refused create must leave no metadata claim behind"
        );
    }

    #[tokio::test]
    async fn a_failed_engine_create_releases_the_name_claim() {
        let (reg, _, customer, sh) = setup().await;
        sh.script(RecordingShell::output("mariadb", 0, "", "")); // probe: free
        sh.script(RecordingShell::output("mariadb", 1, "", "ERROR 1006 (HY000)"));

        let err = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "doomed", "engine": "mysql" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::CommandFailed);
        assert!(
            reg.services()
                .db
                .database_by_name_global("doomed")
                .await
                .unwrap()
                .is_none(),
            "otherwise the name is burned forever after a transient failure"
        );
    }

    #[tokio::test]
    async fn db_create_refuses_when_the_engine_is_not_installed() {
        // No component rows, and the mock systemd knows no units.
        let (reg, _, customer) = registry().await;
        install_shell(Arc::new(RecordingShell::default()));
        let err = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "shop_db", "engine": "mysql" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(err.detail.contains("Stack Manager"));
    }

    #[tokio::test]
    async fn user_create_returns_a_one_time_password_and_stores_none() {
        let (reg, _, customer, sh) = setup().await;
        let out = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.user.create",
            json!({ "username": "shop_rw", "engine": "mysql" }),
        )
        .await
        .unwrap();

        let password = out["password"].as_str().unwrap();
        assert_eq!(password.len(), 24);

        let jobs = sh.recorded();
        let create = &jobs[1];
        assert!(create.secret, "a password-bearing job must be marked secret");
        assert_eq!(
            create.sql,
            format!("CREATE USER 'shop_rw'@'localhost' IDENTIFIED BY '{password}';\n")
        );

        // Nothing password-shaped may survive anywhere in the panel database.
        let row: Vec<(String,)> =
            sqlx::query_as("SELECT username FROM db_users WHERE username = 'shop_rw'")
                .fetch_all(reg.services().db.pool())
                .await
                .unwrap();
        assert_eq!(row.len(), 1);
        let everything: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT username, engine, created_at, updated_at FROM db_users",
        )
        .fetch_all(reg.services().db.pool())
        .await
        .unwrap();
        for (a, b, c, d) in everything {
            for field in [a, b, c, d] {
                assert!(!field.contains(password), "the password leaked into storage");
            }
        }
    }

    #[tokio::test]
    async fn a_failing_secret_statement_never_leaks_the_password_in_the_error() {
        let (reg, _, customer, sh) = setup().await;
        sh.script(RecordingShell::output("mariadb", 0, "", "")); // probe: free
        // Engines echo the failing statement in diagnostics; simulate that.
        sh.script(RecordingShell::output(
            "mariadb",
            1,
            "",
            "ERROR 1064 near 'IDENTIFIED BY ...'",
        ));

        let err = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.user.create",
            json!({ "username": "leaky", "engine": "mysql" }),
        )
        .await
        .unwrap_err();

        // Recover the password the op generated from the recorded job, then
        // assert the error withheld it — and the client's own text too.
        let jobs = sh.recorded();
        let sql = &jobs[1].sql;
        let pw = sql
            .rsplit("IDENTIFIED BY '")
            .next()
            .unwrap()
            .trim_end_matches(";\n")
            .trim_end_matches('\'');
        assert_eq!(pw.len(), 24, "sanity: extracted the generated password");
        assert!(!err.detail.contains(pw));
        assert!(!err.detail.contains("1064"), "diagnostics must be withheld");

        // And the failed create released its metadata row.
        assert!(
            reg.services()
                .db
                .db_user_by_name_global("leaky")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn db_drop_demands_the_name_retyped() {
        let (reg, _, customer, sh) = setup().await;
        let created = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "keeper", "engine": "mysql" }),
        )
        .await
        .unwrap();
        let id = created["database_id"].as_i64().unwrap();
        sh.clear();

        let err = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.drop",
            json!({ "database_id": id, "confirm_name": "kepler" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(sh.recorded().is_empty(), "no SQL may run on a bad confirm");

        let ok = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.drop",
            json!({ "database_id": id, "confirm_name": "keeper" }),
        )
        .await
        .unwrap();
        assert_eq!(ok["dropped"], true);
        assert_eq!(sh.recorded()[0].sql, "DROP DATABASE IF EXISTS keeper;\n");
        assert!(
            reg.services()
                .db
                .database_by_name_global("keeper")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_customer_cannot_list_or_drop_another_tenants_databases() {
        let (reg, admin, customer, sh) = setup().await;
        let theirs = dispatch(
            &reg,
            admin,
            Role::Admin,
            "db.create",
            json!({ "name": "admins_db", "engine": "mysql" }),
        )
        .await
        .unwrap();
        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "customers_db", "engine": "mysql" }),
        )
        .await
        .unwrap();
        sh.clear();

        // The list shows only their own.
        let listed = dispatch(&reg, customer, Role::Customer, "db.list", json!({}))
            .await
            .unwrap();
        let names: Vec<&str> = listed["databases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["customers_db"]);

        // A direct probe at the admin's id answers "not found", identically to
        // a database that does not exist — and runs no SQL at all.
        let err = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.drop",
            json!({
                "database_id": theirs["database_id"],
                "confirm_name": "admins_db",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(sh.recorded().is_empty());
    }

    #[tokio::test]
    async fn a_password_reset_issues_a_fresh_secret_over_the_wire_only() {
        let (reg, _, customer, sh) = setup().await;
        let created = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.user.create",
            json!({ "username": "rotate_rw", "engine": "postgres" }),
        )
        .await
        .unwrap();
        let first = created["password"].as_str().unwrap().to_string();
        sh.clear();

        let reset = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.user.password",
            json!({ "username": "rotate_rw" }),
        )
        .await
        .unwrap();
        let second = reset["password"].as_str().unwrap();
        assert_eq!(second.len(), 24);
        assert_ne!(first, second);

        let jobs = sh.recorded();
        assert_eq!(jobs.len(), 1);
        assert!(jobs[0].secret);
        assert_eq!(
            jobs[0].sql,
            format!("ALTER ROLE rotate_rw WITH PASSWORD '{second}';\n")
        );
    }

    #[tokio::test]
    async fn user_drop_removes_engine_account_then_metadata() {
        let (reg, _, customer, sh) = setup().await;
        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.user.create",
            json!({ "username": "gone_rw", "engine": "mysql" }),
        )
        .await
        .unwrap();
        sh.clear();

        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.user.drop",
            json!({ "username": "gone_rw" }),
        )
        .await
        .unwrap();
        assert_eq!(
            sh.recorded()[0].sql,
            "DROP USER IF EXISTS 'gone_rw'@'localhost';\n"
        );
        assert!(
            reg.services()
                .db
                .db_user_by_name_global("gone_rw")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn grants_only_wire_same_engine_same_subscription_pairs() {
        let (reg, _, customer, sh) = setup().await;
        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "mysql_db", "engine": "mysql" }),
        )
        .await
        .unwrap();
        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.user.create",
            json!({ "username": "warehouse_rw", "engine": "postgres" }),
        )
        .await
        .unwrap();
        sh.clear();

        let err = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.grant",
            json!({ "database": "mysql_db", "username": "warehouse_rw" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(sh.recorded().is_empty());
    }

    #[tokio::test]
    async fn a_valid_grant_runs_the_expected_statement() {
        let (reg, _, customer, sh) = setup().await;
        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "shop", "engine": "mysql" }),
        )
        .await
        .unwrap();
        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.user.create",
            json!({ "username": "shop_rw", "engine": "mysql" }),
        )
        .await
        .unwrap();
        sh.clear();

        let out = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.grant",
            json!({ "database": "shop", "username": "shop_rw" }),
        )
        .await
        .unwrap();
        assert_eq!(out["granted"], true);
        assert_eq!(
            sh.recorded()[0].sql,
            "GRANT ALL PRIVILEGES ON shop.* TO 'shop_rw'@'localhost';\n"
        );
    }

    #[tokio::test]
    async fn an_invalid_db_name_is_rejected_before_any_sql_runs() {
        let (reg, _, customer, sh) = setup().await;
        for hostile in ["a;DROP", "a'b", "a b", "mysql", "pg_x", "../etc"] {
            let err = dispatch(
                &reg,
                customer,
                Role::Customer,
                "db.create",
                json!({ "name": hostile, "engine": "mysql" }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "for `{hostile}`");
        }
        assert!(
            sh.recorded().is_empty(),
            "hostile names must die at deserialization, never near a client"
        );
    }
}
