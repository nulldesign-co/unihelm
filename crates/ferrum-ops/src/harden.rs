//! Making a freshly installed database engine safe to have on the internet.
//!
//! Upstream's job is to ship a database that starts. Ours is to ship a database
//! that a hosting server can survive having, and those are not the same
//! default. Installing MariaDB 11.8 through the panel on a live AlmaLinux box
//! produced, in one step and with no warning:
//!
//! * `bind_address` unset, so `mariadbd` listened on `0.0.0.0:3306`. The box
//!   had no firewall — the panel had already reported `fw: none` honestly — so
//!   the database was reachable from the whole internet the moment it started.
//! * Two anonymous accounts, `''@'localhost'` and `''@'<hostname>'`, with no
//!   password.
//! * The `test` database, plus the two wildcard grant rows that let *any*
//!   account, including those anonymous ones, use anything named `test%`.
//!
//! Separately each is a known wart that `mysql_secure_installation` exists to
//! remove. Together, on a multi-tenant host, they are a tenant-isolation
//! failure: every tenant's PHP runs on this machine, so every tenant could
//! connect with no credential at all and share one database namespace.
//!
//! So the panel does that work itself, at install time, without asking. Remote
//! access is a real feature (spec §11.6) and stays available — but it becomes
//! an explicit, audited act that opens a firewall port and changes a managed
//! config file, rather than the state you wake up in.
//!
//! The SQL here is idempotent by construction: every statement is an `IF
//! EXISTS` drop or a delete of rows matched by value, so re-running after a
//! package upgrade that restored a default costs nothing and fixes anything
//! that came back.

use ferrum_config::apply::ApplyRequest;
use ferrum_config::managed::ManagedFile;
use ferrum_config::paths;
use ferrum_core::{FerrumError, Result};

use crate::db::{SqlJob, mysql_argv, run_sql};
use crate::registry::OpContext;
use crate::services::{MariaDbValidator, UnitReloader};

/// Everything `mysql_secure_installation` does that a panel should do for you,
/// minus the parts that need a human.
///
/// Not included: setting a root password. Root authenticates through the
/// `unix_socket` plugin, which means "be root on this machine" — strictly
/// stronger than a password stored somewhere the panel can read it, and the
/// reason [`mysql_argv`] never carries one.
const SECURE_SQL: &str = "\
-- Anonymous accounts: no password, and on a shared host every tenant's PHP is
-- a local client. `IF EXISTS` so a re-run after an upgrade is silent.
DROP USER IF EXISTS ''@'localhost';
DROP USER IF EXISTS ''@'%';
DELETE FROM mysql.global_priv WHERE User = '';
-- The `test` database and the wildcard grants that come with it: a namespace
-- every account can write, which is exactly what tenant isolation forbids.
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db IN ('test', 'test\\\\_%');
FLUSH PRIVILEGES;
";

/// Harden a MariaDB the panel has just installed.
///
/// Ordering matters and is deliberate: the config file goes down and the
/// service restarts *before* the SQL runs, so the window in which the engine is
/// both listening on every interface and still carrying anonymous accounts is
/// as short as the panel can make it. A failure at either step is fatal to the
/// install — an engine that is running but not hardened is worse than one that
/// did not finish installing, because the operator would believe it was safe.
pub async fn mariadb(ctx: &OpContext) -> Result<()> {
    let distro = ctx.distro();
    let family = distro.info.family;

    ctx.config()
        .apply(ApplyRequest {
            file: ManagedFile::mysql(paths::mysql_conf_d(family).join("60-ferrum.cnf")),
            template: "mysql/ferrum.cnf",
            context: serde_json::json!({}),
            service: "mariadb",
            validator: &MariaDbValidator,
            reloader: &UnitReloader::mariadb(distro),
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await?;
    ctx.log("bound MariaDB to loopback; remote access is now an explicit, audited change");

    let out = run_sql(&SqlJob {
        argv: mysql_argv(family, false),
        sql: SECURE_SQL.to_string(),
        secret: false,
    })
    .await
    .map_err(|e| {
        FerrumError::internal(format!(
            "MariaDB installed but could not be secured ({e}); it is refusing to be \
             left with anonymous accounts and a shared `test` database"
        ))
    })?;
    let _ = out;

    ctx.log("removed the anonymous accounts and the `test` database");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_distro::Family;

    #[test]
    fn the_hardening_sql_removes_every_default_the_live_box_had() {
        // Each line here maps to something actually found on the AlmaLinux box
        // after a panel install; see the module docs.
        for required in [
            "DROP USER IF EXISTS ''@'localhost'",
            "DELETE FROM mysql.global_priv WHERE User = ''",
            "DROP DATABASE IF EXISTS test",
            "mysql.db WHERE Db IN ('test'",
            "FLUSH PRIVILEGES",
        ] {
            assert!(SECURE_SQL.contains(required), "missing: {required}");
        }
    }

    #[test]
    fn every_statement_is_safe_to_run_twice() {
        // A package upgrade can restore what this removed, so the panel re-runs
        // it. Anything that is not idempotent would turn that into an error the
        // operator has to interpret.
        for statement in SECURE_SQL
            .lines()
            .filter(|l| !l.trim_start().starts_with("--"))
            .filter(|l| !l.trim().is_empty())
        {
            let s = statement.trim();
            let idempotent = s.contains("IF EXISTS")
                || s.starts_with("DELETE FROM")
                || s.starts_with("FLUSH");
            assert!(idempotent, "not safe to re-run: {s}");
        }
    }

    #[test]
    fn the_root_password_is_deliberately_not_set() {
        // `mysql_secure_installation` would prompt for one. Root here
        // authenticates through unix_socket — "be root on this machine" — and a
        // password would have to live somewhere the panel could read it, which
        // is weaker, not stronger.
        assert!(!SECURE_SQL.to_uppercase().contains("SET PASSWORD"));
        assert!(!SECURE_SQL.to_uppercase().contains("IDENTIFIED BY"));
    }

    #[test]
    fn the_admin_client_never_goes_over_tcp() {
        // The whole point of binding to loopback is lost if our own client then
        // reaches the engine over the network.
        for family in [Family::Debian, Family::Rhel] {
            let argv = mysql_argv(family, false);
            assert!(argv.iter().any(|a| a == "--protocol=socket"), "{argv:?}");
            assert!(argv.iter().any(|a| a.starts_with("--socket=")), "{argv:?}");
            assert!(
                !argv.iter().any(|a| a.starts_with("--host")),
                "{argv:?}"
            );
        }
    }
}
