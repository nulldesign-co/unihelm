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
//!    stdin natively), via [`unihelm_distro::Cmd::stdin_data`].
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
use serde::{Deserialize, Serialize};
use unihelm_core::{DbName, ErrorCode, Permission, Result, SubscriptionId, UnihelmError};
use unihelm_db::Db;
use unihelm_db::databases::{Database, DbEngine, DbUser, NewDatabase, NewDbUser};
use unihelm_db::subscriptions::Subscription;
use unihelm_distro::svc::ManagedUnit;
use unihelm_distro::{CmdOutput, Family};

use crate::engine::RootConnection;
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

/// The environment a client is given, which is the only place a credential may
/// travel.
///
/// **Deliberately not a field of [`SqlJob`].** That type derives `Debug` and
/// the test recorder keeps every job it is handed, so a password inside it is
/// one `?job` away from a log line — the same leak rule 2 above puts the SQL on
/// stdin to avoid. It is also why this carries a hand-written `Debug`, exactly
/// as `unihelm_db::MasterKey` and `engine::RootConnection` do.
///
/// Two names ever go in it: `MYSQL_PWD` and `PGPASSWORD`, which are how the two
/// clients read a password without one appearing on the command line.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ClientEnv(Vec<(&'static str, String)>);

impl ClientEnv {
    fn one(name: &'static str, value: String) -> Self {
        Self(vec![(name, value)])
    }

    /// The names alone, for the `--env NAME` that tells Docker to take each one
    /// from the panel's own process rather than from an argv.
    fn names(&self) -> Vec<&'static str> {
        self.0.iter().map(|(name, _)| *name).collect()
    }

    fn pairs(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.0.iter().map(|(name, value)| (*name, value.as_str()))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for ClientEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| format!("{name}=<redacted>")))
            .finish()
    }
}

/// The seam between "which statements" and "actually running a client".
///
/// Production uses [`SystemShell`]; tests install a recorder so operations can
/// be asserted down to the exact argv and stdin without MariaDB installed.
#[async_trait]
pub trait DbShell: Send + Sync {
    /// `env` is the credential channel and is empty for every host invocation.
    /// It is a parameter rather than part of the job for the reason
    /// [`ClientEnv`] gives.
    async fn run(&self, job: &SqlJob, env: &ClientEnv) -> Result<CmdOutput>;
}

/// Runs the real client through [`unihelm_distro::Cmd`] — argv array, resolved
/// against trusted directories, scrubbed environment, SQL on stdin.
pub struct SystemShell;

#[async_trait]
impl DbShell for SystemShell {
    async fn run(&self, job: &SqlJob, env: &ClientEnv) -> Result<CmdOutput> {
        let (program, args) = job
            .argv
            .split_first()
            .ok_or_else(|| UnihelmError::internal("a SqlJob must carry a program"))?;
        let mut cmd = unihelm_distro::Cmd::new(program.clone())
            .args(args)
            // Local DDL, over a unix socket or through `docker exec` into a
            // container on this same machine. 30 s is generous for either; the
            // default 120 s would hold an Immediate IPC round trip open far too
            // long.
            .timeout(Duration::from_secs(30))
            .stdin_data(job.sql.as_bytes().to_vec());
        // `Cmd` starts from an empty environment, so this is the whole of what
        // the client can read — and the value exists nowhere else: not in the
        // argv, not in the job, not in a file.
        for (name, value) in env.pairs() {
            cmd = cmd.env(name, value);
        }
        cmd.run().await.map_err(UnihelmError::from)
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
///
/// No environment, because every caller of this one builds a host invocation:
/// hardening runs against a MariaDB this panel has just installed as packages,
/// where root authenticates over the socket and there is no password to pass.
pub async fn run_sql(job: &SqlJob) -> Result<CmdOutput> {
    execute(shell().as_ref(), job, &ClientEnv::default()).await
}

/// Run a job and turn a non-zero exit into an error — with the client's own
/// diagnostics when they are safe to show, and without them when the statement
/// carried a credential (both engines echo parts of a failing statement).
async fn execute(shell: &dyn DbShell, job: &SqlJob, env: &ClientEnv) -> Result<CmdOutput> {
    let out = shell.run(job, env).await?;
    if out.success() {
        return Ok(out);
    }
    if job.secret {
        Err(UnihelmError::new(
            ErrorCode::CommandFailed,
            format!(
                "the {} client refused the statement (exit {}); its output is withheld because \
                 the statement carried a credential",
                out.program, out.status
            ),
        ))
    } else {
        Err(UnihelmError::new(
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

/// The variable the MySQL-family clients read a password out of, so it never
/// has to be typed on a command line. Deprecated by Oracle and still the only
/// non-argv route both `mysql` and `mariadb` honour.
const MYSQL_PASSWORD_ENV: &str = "MYSQL_PWD";

/// libpq's, read by `psql` and by every client built on it.
const POSTGRES_PASSWORD_ENV: &str = "PGPASSWORD";

/// The `mariadb`/`mysql` client argv for root **inside the engine's own
/// container**.
///
/// Three differences from [`mysql_argv`], and each one is forced by where this
/// runs:
///
/// - **TCP to the container's own loopback**, not a socket. The socket path
///   differs between the official image and each distribution's packaging and
///   the panel does not get to guess; the port the server binds inside the
///   container is in the engine record and is not a guess. It is the same
///   choice, for the same reason, that `engine`'s readiness probe makes.
/// - **A password**, because the image's root is not authenticated by
///   `unix_socket` — and it arrives through [`MYSQL_PASSWORD_ENV`], never on
///   the argv. `/proc/<pid>/cmdline` is readable by every local account on the
///   machine, and that is precisely the boundary sealing the credential exists
///   to hold.
/// - **The program and the user come off the record**, because the image
///   decides both: `mariadb:11.8` carries `mariadb` and `mysql:8.0` carries
///   `mysql`, and asking either for the other's name is a missing binary on a
///   server that is perfectly healthy.
///
/// `--no-defaults` stays first for the reason it is first there: the clients
/// only honour it in that position.
pub fn mysql_container_argv(conn: &RootConnection, query: bool) -> Vec<String> {
    let mut argv = vec![
        conn.client.to_string(),
        "--no-defaults".to_string(),
        "--protocol=tcp".to_string(),
        format!("--host={}", conn.host),
        format!("--port={}", conn.port),
        format!("--user={}", conn.user),
        "--batch".to_string(),
    ];
    if query {
        argv.push("--skip-column-names".to_string());
    }
    argv
}

/// The `psql` argv for the superuser inside the engine's own container.
///
/// `-v ON_ERROR_STOP=1` and `-f -` are [`postgres_argv`]'s and are here for the
/// same reasons — psql otherwise runs past a failed statement and still exits
/// zero, and the batch belongs on stdin. What changes is the address and the
/// credential: TCP to the container's loopback, and the password in
/// [`POSTGRES_PASSWORD_ENV`] rather than on the command line.
pub fn postgres_container_argv(conn: &RootConnection, query: bool) -> Vec<String> {
    let mut argv = vec![
        conn.client.to_string(),
        "-v".to_string(),
        "ON_ERROR_STOP=1".to_string(),
        "-U".to_string(),
        conn.user.clone(),
        "-h".to_string(),
        conn.host.to_string(),
        "-p".to_string(),
        conn.port.to_string(),
    ];
    if query {
        argv.push("-tA".to_string());
    }
    argv.push("-f".to_string());
    argv.push("-".to_string());
    argv
}

/// One client invocation for one engine, wherever that engine turned out to be.
///
/// The single place the two paths meet, so no operation can pick one by
/// accident: everything below this line — the statements, the quoting, the
/// `LIKE` escaping in a grant, the privilege cleanup after a drop — is
/// identical whether the server is in a container or on the host.
fn client_for(
    home: &EngineHome,
    family: Family,
    engine: DbEngine,
    query: bool,
) -> (Vec<String>, ClientEnv) {
    match home {
        EngineHome::Host => (argv_for(family, engine, query), ClientEnv::default()),
        EngineHome::Container(conn) => {
            let (client, variable) = match engine {
                DbEngine::Mysql => (mysql_container_argv(conn, query), MYSQL_PASSWORD_ENV),
                DbEngine::Postgres => (postgres_container_argv(conn, query), POSTGRES_PASSWORD_ENV),
            };
            let env = ClientEnv::one(variable, conn.password.clone());
            (conn.exec_argv(&env.names(), client), env)
        }
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
    if value.bytes().any(|b| b == b'\\' || b.is_ascii_control()) {
        return Err(UnihelmError::new(
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
/// A PostgreSQL identifier, quoted.
///
/// Postgres folds an unquoted identifier to lower case, so `CREATE DATABASE
/// MyApp` makes a database called `myapp` — and every later statement that
/// names it as stored, `MyApp`, folds too and happens to find it, right up
/// until something quotes it and does not. `DbName` accepts upper case
/// (`is_ascii_alphanumeric`), so this is reachable with an ordinary name.
///
/// The value is already constrained to `[A-Za-z0-9_]` by `DbName::parse`, so
/// there is nothing here to escape; the quotes are what stop the folding, and
/// the assertion is what keeps that true if the newtype ever widens.
fn pg_ident(name: &DbName) -> String {
    debug_assert!(
        name.as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "DbName widened without updating pg_ident"
    );
    format!("\"{}\"", name.as_str())
}

/// A database name in a MySQL *identifier* position.
///
/// The counterpart of [`pg_ident`], and it was missing: `CREATE DATABASE` and
/// `DROP DATABASE` interpolated the bare name, so a database called `order`,
/// `group` or `select` — all of which `DbName::parse` accepts, since its
/// reserved list only holds the engine's own schemas — produced a syntax error
/// the operator saw as "the panel is broken" rather than "pick another name".
///
/// Backticks, not the escaping [`mysql_grant_pattern`] does: a GRANT's database
/// part is a *pattern* and needs its `_` escaped, an identifier is not and must
/// not be. Swapping the two creates a database with a literal backslash in its
/// name.
fn mysql_ident(name: &DbName) -> String {
    debug_assert!(
        name.as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "DbName widened without updating mysql_ident"
    );
    format!("`{}`", name.as_str())
}

fn mysql_account(user: &DbName) -> String {
    format!("'{}'@'localhost'", user.as_str())
}

/// Escape the `LIKE` metacharacters in a database name.
///
/// MySQL and MariaDB match the database part of a database-level `GRANT` as a
/// pattern, not as a name: `_` matches any single character, `%` any run of
/// them. `DbName::parse` allows `_`, so `shop_db` is an ordinary name here.
///
/// `%` is escaped as well. `DbName` cannot produce one today — the assertion
/// below says so — but the escaping is written for the alphabet this function
/// might be handed, not the one it happens to get, because whoever widens the
/// newtype will not come looking for this function.
fn escape_like_metacharacters(name: &DbName) -> String {
    debug_assert!(
        !name.as_str().bytes().any(|b| b == b'`' || b == b'\\'),
        "DbName widened to allow backticks or backslashes; the quoting here no longer holds"
    );
    name.as_str().replace('_', "\\_").replace('%', "\\%")
}

/// Render a [`DbName`] for the **database position of a MySQL `GRANT`**, which
/// is a pattern position and nothing like an identifier position.
///
/// This existed as a bare `{}.*` and gave every tenant privileges on their
/// neighbours' data: `GRANT ALL PRIVILEGES ON shop_db.*` grants on everything
/// matching `shop?db`, so a customer creating `shop_db` on a shared host was
/// silently handed `shopadb`, `shop1db` and the rest — full access, invisible
/// in the panel, and no error anywhere to notice it by.
///
/// Backticks alone do not disarm the pattern; the escape has to go *inside*
/// them, which is the form the MySQL manual prescribes: `` `shop\_db` ``.
fn mysql_grant_pattern(name: &DbName) -> String {
    format!("`{}`", escape_like_metacharacters(name))
}

/// The `mysql.db` predicate matching every privilege row this panel could have
/// written for `name`.
///
/// `mysql.db.Db` holds the grant's *pattern*, stored exactly as the statement
/// spelled it — so a grant written by [`mysql_grant_pattern`] leaves the eight
/// characters `shop\_db` there, which `Db = 'shop_db'` walks straight past.
/// Missing that row would undo what the cleanup in [`sql_drop_db`] exists for:
/// MySQL keeps privilege rows after a `DROP DATABASE`, so the next tenant
/// handed the same name inherits them. Grants written before the escaping (and
/// any made by hand) carry the bare name, so both forms are matched.
///
/// The backslash is spelled `0x5C` because a backslash *inside a literal* means
/// one thing under `NO_BACKSLASH_ESCAPES` and another without it — the very
/// ambiguity [`quote_str`] refuses to inherit — while a hex literal means the
/// same byte under every `sql_mode`.
fn mysql_db_privilege_match(name: &DbName) -> String {
    let bare = quote_name(name);
    let escaped = escape_like_metacharacters(name);
    if escaped == name.as_str() {
        // Nothing to escape, so the grant wrote the bare name and one form is
        // the whole story.
        return format!("Db = {bare}");
    }
    // `shop\_db` becomes CONCAT('shop', 0x5C, '_db'): the chunks between the
    // backslashes, quoted, with the backslash itself supplied as a hex literal.
    let mut args: Vec<String> = Vec::new();
    for (i, chunk) in escaped.split('\\').enumerate() {
        if i > 0 {
            args.push("0x5C".to_string());
        }
        if !chunk.is_empty() {
            args.push(format!("'{chunk}'"));
        }
    }
    format!("Db IN ({bare}, CONCAT({}))", args.join(", "))
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
///
/// The two MySQL statements name the same database in two different languages:
/// CREATE takes an identifier, so the name goes in as written, while GRANT
/// takes a pattern and goes through [`mysql_grant_pattern`]. Swapping them
/// would create a database with a literal backslash in its name.
pub fn sql_create_db(engine: DbEngine, name: &DbName, owner: Option<&DbName>) -> String {
    match (engine, owner) {
        (DbEngine::Mysql, None) => format!("CREATE DATABASE {};\n", mysql_ident(name)),
        (DbEngine::Mysql, Some(user)) => format!(
            "CREATE DATABASE {};\nGRANT ALL PRIVILEGES ON {}.* TO {};\n",
            mysql_ident(name),
            mysql_grant_pattern(name),
            mysql_account(user)
        ),
        (DbEngine::Postgres, None) => format!("CREATE DATABASE {};\n", pg_ident(name)),
        (DbEngine::Postgres, Some(user)) => format!(
            "CREATE DATABASE {} OWNER {};\n",
            pg_ident(name),
            pg_ident(user)
        ),
    }
}

/// `IF EXISTS` on purpose: a drop that half-finished (engine dropped, metadata
/// row left behind) must be re-runnable to completion, not stuck on an error.
pub fn sql_drop_db(engine: DbEngine, name: &DbName) -> String {
    match engine {
        // MySQL does not remove privileges when a database is dropped: the rows
        // in mysql.db outlive it, so the next tenant to be given the same name
        // inherits whatever the last one's users were granted on it. The
        // privilege tables are cleared explicitly, and FLUSH makes the running
        // server forget the in-memory copy it would otherwise keep serving.
        //
        // Only mysql.db holds a pattern (hence mysql_db_privilege_match, which
        // also matches the escaped spelling a database-level GRANT stores);
        // table- and column-level grants cannot be patterns, so those rows carry
        // the bare name. DROP DATABASE itself names an identifier, unescaped.
        DbEngine::Mysql => format!(
            "DROP DATABASE IF EXISTS {};\n\
             DELETE FROM mysql.db WHERE {};\n\
             DELETE FROM mysql.tables_priv WHERE Db = {};\n\
             DELETE FROM mysql.columns_priv WHERE Db = {};\n\
             FLUSH PRIVILEGES;\n",
            mysql_ident(name),
            mysql_db_privilege_match(name),
            quote_name(name),
            quote_name(name)
        ),
        DbEngine::Postgres => format!("DROP DATABASE IF EXISTS {};\n", pg_ident(name)),
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
            pg_ident(user),
            pw
        ),
    })
}

pub fn sql_drop_user(engine: DbEngine, user: &DbName) -> String {
    match engine {
        DbEngine::Mysql => format!("DROP USER IF EXISTS {};\n", mysql_account(user)),
        DbEngine::Postgres => format!("DROP ROLE IF EXISTS {};\n", pg_ident(user)),
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
            mysql_grant_pattern(name),
            mysql_account(user)
        ),
        DbEngine::Postgres => format!(
            "GRANT ALL PRIVILEGES ON DATABASE {} TO {};\n",
            pg_ident(name),
            pg_ident(user)
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

/// The catalogue slugs that speak one engine's protocol.
///
/// A `DbEngine` names a wire format, not a product: MariaDB and MySQL are one
/// `Mysql`, and an operator who installed either expects `db.create` to find
/// it. `mysql` was missing here and it is in the catalogue, so a machine that
/// installed MySQL was told MariaDB was not installed. `postgresql` was in this
/// list and is **not** a catalogue slug at all — `stack.install postgres`
/// writes the row `postgres` — so the lookup never matched and every PostgreSQL
/// answer fell through to the systemd probe below it.
const fn engine_slugs(engine: DbEngine) -> &'static [&'static str] {
    match engine {
        // MariaDB first: it is what the panel installs by default and the one
        // it hardens, so on the machine that somehow carries both it is the
        // panel's own that the panel manages.
        DbEngine::Mysql => &["mariadb", "mysql"],
        DbEngine::Postgres => &["postgres"],
    }
}

const fn engine_display(engine: DbEngine) -> &'static str {
    match engine {
        DbEngine::Mysql => "MariaDB",
        DbEngine::Postgres => "PostgreSQL",
    }
}

/// Where the engine an operation must talk to actually lives, and therefore how
/// its client is invoked.
///
/// The refusal `require_engine_ready` was, plus the answer every operation here
/// then needs. It has to be one function because the two questions have one
/// source: "is MariaDB installed" and "is it a container or packages" are
/// answered by the same lookup, and asking them separately is how the panel
/// came to say yes to the first and act on the wrong answer to the second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineHome {
    /// Host packages: the client on this machine, over the local socket. Still
    /// exactly right for an operator who chose "on the server", where root is
    /// authenticated by `unix_socket` and there is no password to hold.
    Host,
    /// A container the panel installed: the client that ships inside the image,
    /// run through `docker exec`, authenticating with the sealed root password.
    Container(RootConnection),
}

/// Find the engine, or refuse by name.
///
/// Registry first, because it is the only thing that knows a container is
/// there. 0.3.0 made a container the default for every engine in the
/// catalogue and nothing here was told: the row `stack.install` wrote had no
/// unit, no packages and — until this release — not even the name this
/// function looked for, so the panel installed MariaDB, said it worked, and
/// then answered "MariaDB is not installed" to the first database anybody tried
/// to create in it.
///
/// The two host probes below it are unchanged in spirit: our own bookkeeping,
/// then systemd's view for an engine installed before (or without) the panel.
async fn engine_home(ctx: &OpContext, engine: DbEngine) -> Result<EngineHome> {
    if let Some(conn) =
        crate::engine::root_connection(ctx.db(), ctx.master_key(), engine_slugs(engine)).await?
    {
        return Ok(EngineHome::Container(conn));
    }

    for slug in engine_slugs(engine) {
        let installed = ctx
            .db()
            .component(slug)
            .await
            .map_err(UnihelmError::from)?
            .map(|c| c.status == unihelm_db::ComponentStatus::Installed)
            .unwrap_or(false);
        if installed {
            return Ok(EngineHome::Host);
        }
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
        return Ok(EngineHome::Host);
    }

    Err(UnihelmError::new(
        ErrorCode::NotFound,
        format!(
            "{} is not installed on this server, in a container or as packages. \
             Install it from the Stack Manager first.",
            engine_display(engine)
        ),
    )
    .with_field("engine"))
}

/// Refuse a database creation that would exceed the subscription's plan.
///
/// The counterpart of `plan::enforce_site_limit`, and it lives here for the
/// reason that module's header gives: enforcement belongs at the point the
/// resource is created, so no other path can forget it. A subscription with no
/// plan is unlimited, and the refusal names the plan and both numbers, because
/// "quota exceeded" alone tells an operator nothing about which knob to turn
/// (spec §10.5).
async fn enforce_db_limit(db: &Db, subscription: &Subscription) -> Result<()> {
    let Some(plan) = db
        .plan_of_subscription(subscription.id)
        .await
        .map_err(UnihelmError::from)?
    else {
        return Ok(());
    };

    let used = db
        .quota_db_count(subscription.id)
        .await
        .map_err(UnihelmError::from)?;
    if used >= plan.max_dbs {
        return Err(UnihelmError::new(
            ErrorCode::QuotaExceeded,
            format!(
                "plan `{}` allows {} database(s) and this subscription already has {}",
                plan.name, plan.max_dbs, used
            ),
        ));
    }
    Ok(())
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
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("subscription"))?,
        None => db
            .default_subscription_for(ctx.auth().actor_user_id)
            .await
            .map_err(UnihelmError::from)?,
    };
    if !subscription.status.can_serve() {
        return Err(UnihelmError::new(
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
            databases: repo.list(limit, offset).await.map_err(UnihelmError::from)?,
            users: repo
                .list_users(limit, offset)
                .await
                .map_err(UnihelmError::from)?,
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
        enforce_db_limit(&db, &subscription).await?;
        // Where the engine is, resolved once and used for both statements
        // below: a probe that asked the container and a CREATE that asked the
        // host would be two answers about one machine.
        let home = engine_home(ctx, input.engine).await?;

        // An owner must already exist, in the same subscription and engine —
        // binding someone else's user would be a cross-tenant grant.
        if let Some(owner) = &input.owner {
            let user = db
                .databases(ctx.scope())
                .user_by_name(owner.as_str())
                .await
                .map_err(UnihelmError::from)?
                .ok_or_else(|| UnihelmError::not_found("database user"))?;
            if user.engine != input.engine || user.subscription_id != subscription.id {
                return Err(UnihelmError::new(
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
            .map_err(UnihelmError::from)?
            .is_some()
        {
            return Err(UnihelmError::new(
                ErrorCode::AlreadyExists,
                format!("`{}` is already a managed database", input.name.as_str()),
            ));
        }

        let sh = shell();
        let family = ctx.distro().info.family;
        let (argv, env) = client_for(&home, family, input.engine, true);
        let probe = SqlJob {
            argv,
            sql: sql_db_exists(input.engine, &input.name),
            secret: false,
        };
        if !execute(sh.as_ref(), &probe, &env)
            .await?
            .trimmed_stdout()
            .is_empty()
        {
            return Err(UnihelmError::new(
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
            .map_err(UnihelmError::from)?;

        let (argv, env) = client_for(&home, family, input.engine, false);
        let create = SqlJob {
            argv,
            sql: sql_create_db(input.engine, &input.name, input.owner.as_ref()),
            secret: false,
        };
        if let Err(e) = execute(sh.as_ref(), &create, &env).await {
            // Compensate: the engine refused, so the claim must be released or
            // the name is burned forever.
            let _ = db
                .databases(&unihelm_core::TenantScope::Global)
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
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("database"))?;

        if input.confirm_name != found.name {
            return Err(UnihelmError::new(
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
        let home = engine_home(ctx, found.engine).await?;
        let (argv, env) = client_for(&home, ctx.distro().info.family, found.engine, false);
        let job = SqlJob {
            argv,
            sql: sql_drop_db(found.engine, &name),
            secret: false,
        };
        execute(shell().as_ref(), &job, &env).await?;

        repo.delete(found.id).await.map_err(UnihelmError::from)?;
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
        let home = engine_home(ctx, input.engine).await?;

        if db
            .db_user_by_name_global(input.username.as_str())
            .await
            .map_err(UnihelmError::from)?
            .is_some()
        {
            return Err(UnihelmError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "`{}` is already a managed database user",
                    input.username.as_str()
                ),
            ));
        }

        let sh = shell();
        let family = ctx.distro().info.family;
        let (argv, env) = client_for(&home, family, input.engine, true);
        let probe = SqlJob {
            argv,
            sql: sql_user_exists(input.engine, &input.username),
            secret: false,
        };
        if !execute(sh.as_ref(), &probe, &env)
            .await?
            .trimmed_stdout()
            .is_empty()
        {
            return Err(UnihelmError::new(
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
            .map_err(UnihelmError::from)?;

        let password = generate_password();
        let (argv, env) = client_for(&home, family, input.engine, false);
        let create = SqlJob {
            argv,
            sql: sql_create_user(input.engine, &input.username, &password)?,
            secret: true,
        };
        if let Err(e) = execute(sh.as_ref(), &create, &env).await {
            let _ = db
                .databases(&unihelm_core::TenantScope::Global)
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
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("database user"))?;

        // Engine first, metadata second — same reasoning as db.drop. Note that
        // PostgreSQL refuses to drop a role that still owns a database; that
        // error surfaces verbatim so the operator knows to drop or reassign the
        // database first, rather than us cascading through owned objects.
        let home = engine_home(ctx, found.engine).await?;
        let (argv, env) = client_for(&home, ctx.distro().info.family, found.engine, false);
        let job = SqlJob {
            argv,
            sql: sql_drop_user(found.engine, &input.username),
            secret: false,
        };
        execute(shell().as_ref(), &job, &env).await?;

        repo.delete_user(found.id)
            .await
            .map_err(UnihelmError::from)?;
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
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("database user"))?;

        let password = generate_password();
        let home = engine_home(ctx, found.engine).await?;
        let (argv, env) = client_for(&home, ctx.distro().info.family, found.engine, false);
        let job = SqlJob {
            argv,
            sql: sql_set_password(found.engine, &input.username, &password)?,
            secret: true,
        };
        execute(shell().as_ref(), &job, &env).await?;

        db.touch_db_user(found.id)
            .await
            .map_err(UnihelmError::from)?;
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
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("database"))?;
        let user = repo
            .user_by_name(input.username.as_str())
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("database user"))?;

        if database.engine != user.engine {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "the database and the user live in different engines",
            )
            .with_field("username"));
        }
        // Cross-subscription grants would quietly couple two tenants' lifecycles
        // (dropping one subscription's user revokes another's access).
        if database.subscription_id != user.subscription_id {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "the database and the user belong to different subscriptions",
            )
            .with_field("username"));
        }

        let home = engine_home(ctx, database.engine).await?;
        let (argv, env) = client_for(&home, ctx.distro().info.family, database.engine, false);
        let job = SqlJob {
            argv,
            sql: sql_grant(database.engine, &input.database, &input.username),
            secret: false,
        };
        execute(shell().as_ref(), &job, &env).await?;

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
        /// The environment each job was given, kept beside it rather than in
        /// it: a test has to be able to assert that the root password reached
        /// the client *and* that it is nowhere in the argv, and only a recorder
        /// that sees both can.
        pub envs: Mutex<Vec<ClientEnv>>,
        pub scripted: Mutex<VecDeque<CmdOutput>>,
    }

    impl RecordingShell {
        pub fn recorded(&self) -> Vec<SqlJob> {
            self.jobs.lock().expect("shell mutex").clone()
        }

        pub fn environments(&self) -> Vec<ClientEnv> {
            self.envs.lock().expect("shell mutex").clone()
        }

        pub fn clear(&self) {
            self.jobs.lock().expect("shell mutex").clear();
            self.envs.lock().expect("shell mutex").clear();
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
        async fn run(&self, job: &SqlJob, env: &ClientEnv) -> Result<CmdOutput> {
            self.jobs.lock().expect("shell mutex").push(job.clone());
            self.envs.lock().expect("shell mutex").push(env.clone());
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
    use serde_json::json;
    use unihelm_core::{Role, UserId};

    async fn setup() -> (OpRegistry, UserId, UserId, Arc<RecordingShell>) {
        let (reg, admin, customer) = registry().await;
        // Pretend both engines are installed **on the host**, the way the Stack
        // Manager records them (claim creates the row, installed finalises it);
        // the mock systemd knows no units, so this is the path taken.
        //
        // The slugs are the catalogue's own. This list read `postgresql` until
        // the container work, which is not a slug the panel ever writes —
        // `stack.install postgres` writes `postgres` — so the row lookup never
        // matched here or on a real server, and every PostgreSQL answer came
        // out of the systemd fallback instead.
        for slug in ["mariadb", "postgres"] {
            let db = &reg.services().db;
            db.claim_component(slug, unihelm_db::ComponentStatus::Installing, "test-task")
                .await
                .unwrap();
            db.component_installed(slug, Some("1.0-mock"))
                .await
                .unwrap();
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
                format!("CREATE DATABASE `{name}`;\n")
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
            "CREATE DATABASE `shop`;\nGRANT ALL PRIVILEGES ON `shop`.* TO 'shop_rw'@'localhost';\n"
        );
        assert_eq!(
            sql_create_db(DbEngine::Postgres, &name, Some(&owner)),
            "CREATE DATABASE \"shop\" OWNER \"shop_rw\";\n"
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
        assert_eq!(jobs[1].sql, "CREATE DATABASE `shop_db`;\n");
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
        assert_eq!(jobs[1].sql, "CREATE DATABASE \"warehouse\";\n");
    }

    #[tokio::test]
    async fn a_subscription_at_its_database_limit_is_refused_by_name() {
        use unihelm_db::plans::NewPlan;

        let (reg, _, customer, sh) = setup().await;
        let db = &reg.services().db;
        let plan = db
            .plans(&unihelm_core::TenantScope::Global)
            .create(NewPlan {
                owner_user_id: None,
                name: "Solo".into(),
                max_sites: 1,
                max_dbs: 1,
                storage_mb: 1024,
                can_ssh: false,
                can_cron: true,
                can_node_apps: false,
            })
            .await
            .unwrap();
        // The same subscription `db.create` resolves for a customer who names none.
        let sub = db.default_subscription_for(customer).await.unwrap();
        db.assign_plan(sub.id, plan.id).await.unwrap();

        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "first_db", "engine": "mysql" }),
        )
        .await
        .unwrap();

        // The refusal names the plan and both numbers so the operator knows
        // which knob to turn (spec §10.5), and lands before anything runs.
        let err = dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "second_db", "engine": "mysql" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::QuotaExceeded);
        assert!(err.detail.contains("Solo"), "{}", err.detail);
        assert_eq!(
            sh.recorded().len(),
            2,
            "the refused create must not reach the engine"
        );
        assert!(
            db.database_by_name_global("second_db")
                .await
                .unwrap()
                .is_none(),
            "a refused create must leave no metadata claim behind"
        );
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
        sh.script(RecordingShell::output(
            "mariadb",
            1,
            "",
            "ERROR 1006 (HY000)",
        ));

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

    // --- the engine is in a container ---------------------------------------

    /// The registry record `engine::install_container` writes when it brings an
    /// engine up. On a default install it is the *only* thing on the machine
    /// that says where that engine is: there are no packages, no unit and no
    /// socket.
    async fn record_a_container(
        reg: &OpRegistry,
        slug: &str,
        version: &str,
        host_port: u16,
        container_port: u16,
        root_user: &str,
        password: &str,
    ) -> String {
        let plan = crate::engine::EnginePlan::resolve(slug, Some(version)).unwrap();
        let container = plan.container().as_str().to_string();
        let mut engines = crate::engine::EngineRegistry::new();
        engines.insert(
            container.clone(),
            crate::engine::EngineRecord {
                slug: slug.to_string(),
                version: version.to_string(),
                image: plan.image().as_str().to_string(),
                container: container.clone(),
                volume: plan.volume().map(str::to_string),
                host_port,
                container_port,
                root_user: Some(root_user.to_string()),
                root_password_sealed: Some(reg.services().master_key.seal_str(password).unwrap()),
            },
        );
        reg.services()
            .db
            .set_setting(crate::engine::ENGINES_SETTING, &engines)
            .await
            .unwrap();
        container
    }

    #[tokio::test]
    async fn db_create_runs_the_client_inside_the_container_the_engine_is_in() {
        // The whole of issue 69: 0.3.0 made a container the default for every
        // engine in the catalogue, and this file only ever built a socket
        // client. On the path a fresh install actually takes there is no
        // socket, because there is no host install to own one — and no
        // `mariadb` binary on the machine to run against it either.
        let (reg, _, customer, sh) = setup().await;
        let container = record_a_container(
            &reg,
            "mariadb",
            "11.8",
            3306,
            3306,
            "root",
            "s3cret-root-pw",
        )
        .await;

        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "shop_db", "engine": "mysql" }),
        )
        .await
        .unwrap();

        let jobs = sh.recorded();
        assert_eq!(jobs.len(), 2, "one existence probe, one CREATE");
        let probe: Vec<&str> = jobs[0].argv.iter().map(String::as_str).collect();
        assert_eq!(
            probe,
            vec![
                "docker",
                "exec",
                // Without `-i` Docker hands the client `/dev/null`, the batch
                // on stdin is silently empty, and the panel reports a database
                // it never created.
                "-i",
                // The name only. `--env NAME=value` would put the root
                // password in `/proc/<pid>/cmdline`, which every local account
                // can read.
                "--env",
                "MYSQL_PWD",
                container.as_str(),
                "mariadb",
                "--no-defaults",
                "--protocol=tcp",
                "--host=127.0.0.1",
                // The port *inside* the container, not the one this machine
                // publishes: a client running in there never crosses that
                // boundary, and the two numbers differ as soon as a second
                // version is installed.
                "--port=3306",
                "--user=root",
                "--batch",
                "--skip-column-names",
            ]
        );

        // The statements are untouched. This changes how the client is invoked
        // and nothing below that line.
        assert_eq!(
            jobs[0].sql,
            "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'shop_db';\n"
        );
        assert_eq!(jobs[1].sql, "CREATE DATABASE `shop_db`;\n");

        // The credential reaches the client through the environment and appears
        // on no command line at all.
        assert!(
            !jobs
                .iter()
                .any(|j| j.argv.iter().any(|a| a.contains("s3cret-root-pw"))),
            "the root password reached an argv: {:?}",
            jobs.iter().map(|j| &j.argv).collect::<Vec<_>>()
        );
        let envs = sh.environments();
        for env in &envs {
            assert_eq!(
                env.pairs().collect::<Vec<_>>(),
                vec![("MYSQL_PWD", "s3cret-root-pw")]
            );
            // And a recorder that keeps it must not print it either.
            assert!(!format!("{env:?}").contains("s3cret"), "{env:?}");
        }
    }

    #[tokio::test]
    async fn a_containerised_postgres_is_reached_with_the_psql_inside_it() {
        let (reg, _, customer, sh) = setup().await;
        let container =
            record_a_container(&reg, "postgres", "17", 5432, 5432, "postgres", "pg-root-pw").await;

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
        let create: Vec<&str> = jobs[1].argv.iter().map(String::as_str).collect();
        assert_eq!(
            create,
            vec![
                "docker",
                "exec",
                "-i",
                "--env",
                "PGPASSWORD",
                container.as_str(),
                "psql",
                // Without this psql runs past a failed statement and still
                // exits zero, which would turn "the CREATE failed" into silent
                // success — inside a container exactly as on a socket.
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                "-h",
                "127.0.0.1",
                "-p",
                "5432",
                "-f",
                "-",
            ]
        );
        assert_eq!(jobs[1].sql, "CREATE DATABASE \"warehouse\";\n");
        assert_eq!(
            sh.environments()[1].pairs().collect::<Vec<_>>(),
            vec![("PGPASSWORD", "pg-root-pw")]
        );
    }

    #[tokio::test]
    async fn a_host_install_still_goes_over_its_socket_with_no_credential() {
        // The other half of the promise: the socket path is not a rewrite, and
        // an operator who chose "on the server" must keep the client they had.
        let (reg, _, customer, sh) = setup().await;
        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "on_the_host", "engine": "mysql" }),
        )
        .await
        .unwrap();

        let jobs = sh.recorded();
        assert_eq!(jobs[1].argv, mysql_argv(Family::Debian, false));
        assert!(
            sh.environments().iter().all(ClientEnv::is_empty),
            "root over the local socket is authenticated by unix_socket; there is no \
             password to hand it"
        );
    }

    #[tokio::test]
    async fn every_slug_the_catalogue_offers_for_an_engine_is_one_it_is_found_under() {
        // `require_engine_ready` asked about `mariadb` and `postgresql`.
        // `postgresql` is not a slug the panel ever writes — `stack.install
        // postgres` writes `postgres` — so that lookup never matched, and
        // `mysql` is in the catalogue, reaches this same code, and was in
        // neither list. Both engines were found only by the systemd fallback,
        // which answers for neither a container nor a mock.
        for (slug, engine, name) in [
            ("mysql", "mysql", "under_mysql"),
            ("postgres", "postgres", "under_postgres"),
        ] {
            let (reg, _, customer) = registry().await;
            install_shell(Arc::new(RecordingShell::default()));
            let db = &reg.services().db;
            db.claim_component(slug, unihelm_db::ComponentStatus::Installing, "t")
                .await
                .unwrap();
            db.component_installed(slug, Some("1.0-mock"))
                .await
                .unwrap();

            dispatch(
                &reg,
                customer,
                Role::Customer,
                "db.create",
                json!({ "name": name, "engine": engine }),
            )
            .await
            .unwrap_or_else(|e| panic!("{slug}: {}", e.detail));
        }
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
        assert!(
            create.secret,
            "a password-bearing job must be marked secret"
        );
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
        let everything: Vec<(String, String, String, String)> =
            sqlx::query_as("SELECT username, engine, created_at, updated_at FROM db_users")
                .fetch_all(reg.services().db.pool())
                .await
                .unwrap();
        for (a, b, c, d) in everything {
            for field in [a, b, c, d] {
                assert!(
                    !field.contains(password),
                    "the password leaked into storage"
                );
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
        assert_eq!(
            sh.recorded()[0].sql,
            concat!(
                "DROP DATABASE IF EXISTS `keeper`;\n",
                // MySQL keeps a dropped database's privilege rows, so the next
                // tenant handed the same name would inherit them.
                "DELETE FROM mysql.db WHERE Db = 'keeper';\n",
                "DELETE FROM mysql.tables_priv WHERE Db = 'keeper';\n",
                "DELETE FROM mysql.columns_priv WHERE Db = 'keeper';\n",
                "FLUSH PRIVILEGES;\n",
            )
        );
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
            "GRANT ALL PRIVILEGES ON `shop`.* TO 'shop_rw'@'localhost';\n"
        );
    }

    #[tokio::test]
    async fn a_grant_on_an_underscored_name_stays_inside_the_tenants_own_database() {
        // The reported case, end to end: MySQL reads a GRANT's database part as
        // a pattern, so a tenant creating `shop_db` was granted everything
        // matching `shop?db` — their neighbours' databases on a shared server.
        let (reg, _, customer, sh) = setup().await;
        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.user.create",
            json!({ "username": "shop_rw", "engine": "mysql" }),
        )
        .await
        .unwrap();
        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.create",
            json!({ "name": "shop_db", "engine": "mysql", "owner": "shop_rw" }),
        )
        .await
        .unwrap();

        // Both halves of the owner-binding batch, each in its own language: an
        // identifier for CREATE, an escaped pattern for GRANT.
        assert_eq!(
            sh.recorded().last().unwrap().sql,
            "CREATE DATABASE `shop_db`;\n\
             GRANT ALL PRIVILEGES ON `shop\\_db`.* TO 'shop_rw'@'localhost';\n"
        );
        sh.clear();

        dispatch(
            &reg,
            customer,
            Role::Customer,
            "db.grant",
            json!({ "database": "shop_db", "username": "shop_rw" }),
        )
        .await
        .unwrap();
        assert_eq!(
            sh.recorded()[0].sql,
            "GRANT ALL PRIVILEGES ON `shop\\_db`.* TO 'shop_rw'@'localhost';\n"
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
#[cfg(test)]
mod tenancy_tests {
    use super::*;

    /// A dropped MySQL database must not leave its privileges behind.
    ///
    /// MySQL keeps the rows in mysql.db, mysql.tables_priv and
    /// mysql.columns_priv when a database is dropped. Hand the same name to the
    /// next tenant — which a panel does, because names are chosen by customers
    /// and `shop` is a popular one — and their database arrives with the
    /// previous tenant's users already granted on it.
    #[test]
    fn dropping_a_mysql_database_clears_its_privileges() {
        let name = DbName::parse("shop").unwrap();
        let sql = sql_drop_db(DbEngine::Mysql, &name);

        assert!(sql.contains("DROP DATABASE IF EXISTS `shop`"));
        for table in ["mysql.db", "mysql.tables_priv", "mysql.columns_priv"] {
            assert!(
                sql.contains(&format!("DELETE FROM {table} WHERE Db = 'shop'")),
                "privileges left in {table}:\n{sql}"
            );
        }
        assert!(
            sql.contains("FLUSH PRIVILEGES"),
            "the running server keeps an in-memory copy:\n{sql}"
        );
    }

    /// Postgres folds an unquoted identifier to lower case, so a name with a
    /// capital in it creates an object under a different name than the one the
    /// panel recorded.
    #[test]
    fn postgres_identifiers_are_quoted_so_case_survives() {
        let name = DbName::parse("MyApp").unwrap();
        let user = DbName::parse("MyApp_rw").unwrap();

        // Each statement names whichever identifiers it is about, so the
        // expectation is per statement rather than one string for all of them.
        for (sql, want) in [
            (
                sql_create_db(DbEngine::Postgres, &name, Some(&user)),
                vec!["\"MyApp\"", "\"MyApp_rw\""],
            ),
            (sql_drop_db(DbEngine::Postgres, &name), vec!["\"MyApp\""]),
            (
                sql_grant(DbEngine::Postgres, &name, &user),
                vec!["\"MyApp\"", "\"MyApp_rw\""],
            ),
            (
                sql_drop_user(DbEngine::Postgres, &user),
                vec!["\"MyApp_rw\""],
            ),
        ] {
            for ident in want {
                assert!(
                    sql.contains(ident),
                    "{ident} unquoted gets folded to lower case:\n{sql}"
                );
            }
        }
    }

    /// The database part of a MySQL GRANT is a `LIKE` pattern, so `_` matches
    /// any single character. Granting on a bare `shop_db` therefore granted
    /// `shop1db`, `shopAdb` and every other neighbour on a shared host — full
    /// privileges on another customer's data, with nothing in the panel to show
    /// for it.
    #[test]
    fn a_mysql_grant_escapes_the_underscore_that_would_match_other_tenants_databases() {
        let name = DbName::parse("shop_db").unwrap();
        let user = DbName::parse("shop_rw").unwrap();

        assert_eq!(
            sql_grant(DbEngine::Mysql, &name, &user),
            "GRANT ALL PRIVILEGES ON `shop\\_db`.* TO 'shop_rw'@'localhost';\n"
        );
        // db.create binds an owner with a grant of its own, walking into the
        // same trap from the other direction.
        assert_eq!(
            sql_create_db(DbEngine::Mysql, &name, Some(&user)),
            "CREATE DATABASE `shop_db`;\n\
             GRANT ALL PRIVILEGES ON `shop\\_db`.* TO 'shop_rw'@'localhost';\n"
        );
    }

    /// The escape belongs in the GRANT and nowhere else: CREATE and DROP name
    /// an identifier, and `CREATE DATABASE shop\_db` would make a database with
    /// a backslash in its name that nothing else in the panel could address.
    #[test]
    fn create_and_drop_name_the_database_literally_not_as_a_pattern() {
        let name = DbName::parse("shop_db").unwrap();

        assert_eq!(
            sql_create_db(DbEngine::Mysql, &name, None),
            "CREATE DATABASE `shop_db`;\n"
        );
        assert!(
            sql_drop_db(DbEngine::Mysql, &name).starts_with("DROP DATABASE IF EXISTS `shop_db`;\n"),
            "{}",
            sql_drop_db(DbEngine::Mysql, &name)
        );
    }

    /// The privilege cleanup has to find the row the escaped grant actually
    /// wrote. MySQL stores a database-level grant's pattern verbatim, so the
    /// grant above leaves `shop\_db` in mysql.db and a `Db = 'shop_db'`
    /// predicate walks past it — handing the privileges to the next tenant
    /// given that name, which is exactly what this cleanup exists to stop.
    #[test]
    fn dropping_a_database_clears_the_escaped_privilege_rows_as_well() {
        let sql = sql_drop_db(DbEngine::Mysql, &DbName::parse("shop_db").unwrap());

        assert!(
            sql.contains(
                "DELETE FROM mysql.db WHERE Db IN ('shop_db', CONCAT('shop', 0x5C, '_db'));"
            ),
            "the escaped grant row survives the drop:\n{sql}"
        );
        // Table- and column-level grants cannot be patterns, so those rows hold
        // the bare name and keep the bare predicate.
        assert!(
            sql.contains("DELETE FROM mysql.tables_priv WHERE Db = 'shop_db';"),
            "{sql}"
        );
        assert!(
            sql.contains("DELETE FROM mysql.columns_priv WHERE Db = 'shop_db';"),
            "{sql}"
        );
    }
}
