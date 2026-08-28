//! Which operation each CLI command reaches (spec §11.20).
//!
//! Spec §11.20 asks for a CLI that reaches everything the UI can. That is easy
//! to claim and easy to quietly stop being true: a wave adds three operations,
//! the UI grows three buttons, and nobody notices the CLI did not. So the claim
//! is checked from two directions, and this table is what both of them read.
//!
//! - `tests/gates/cli-parity.sh` takes every operation registered in
//!   `crates/ferrum-ops/src/registry.rs` and requires it to appear here or in
//!   the gate's allowlist, which carries a reason per entry. **The failing list
//!   is the checklist.**
//! - [`tests::every_listed_command_really_plans_that_operation`] parses each
//!   `argv` below through the real command tree and the real planner and
//!   asserts it emits exactly the operation it is filed under. Without that
//!   half the gate would only be checking that somebody typed a name into a
//!   table.
//!
//! It is also what `ferrum ops list` prints, so an operator can see the mapping
//! without reading the source.

use serde_json::{Value, json};

/// Every operation the CLI reaches, with one example invocation.
///
/// The `argv` is a real command line, not documentation: the test below runs it.
/// Where a command needs a secret it is written in its `--*-stdin` form and the
/// test supplies the value, because that is the only spelling the CLI accepts.
///
/// One operation per line, deliberately: it keeps a diff that adds an operation
/// to one line, and it lets `tests/gates/cli-parity.sh` read the table without
/// a Rust parser. rustfmt would otherwise spread each entry over four lines.
#[rustfmt::skip]
pub const COVERAGE: &[(&str, &[&str])] = &[
    ("alert.channels.delete", &["ferrum", "alert", "channels-delete", "1"]),
    ("alert.channels.list", &["ferrum", "alert", "channels"]),
    ("alert.channels.set", &["ferrum", "alert", "channels-set", "--label", "ops"]),
    ("alert.channels.test", &["ferrum", "alert", "channels-test", "1"]),
    ("alert.events.list", &["ferrum", "alert", "events"]),
    ("alert.rules.list", &["ferrum", "alert", "rules"]),
    ("alert.rules.set", &["ferrum", "alert", "rules-set", "load", "--threshold", "4"]),
    ("app.create", &["ferrum", "app", "create", "api", "--entry", "server.js"]),
    ("app.delete", &["ferrum", "app", "delete", "1"]),
    ("app.list", &["ferrum", "app", "list"]),
    ("app.logs", &["ferrum", "app", "logs", "1"]),
    ("app.restart", &["ferrum", "app", "restart", "1"]),
    ("backup.list", &["ferrum", "backup", "list", "--repo", "1"]),
    ("backup.repo.delete", &["ferrum", "backup", "repo", "delete", "1"]),
    ("backup.repo.init", &["ferrum", "backup", "repo", "init", "--kind", "local", "--label", "disk", "--path", "/srv/backups"]),
    ("backup.restore", &["ferrum", "backup", "restore", "--repo", "1", "--snapshot", "abc123"]),
    ("backup.run", &["ferrum", "backup", "run", "--repo", "1", "--scope", "panel"]),
    ("backup.schedule.delete", &["ferrum", "backup", "schedule", "delete", "1"]),
    ("backup.schedule.set", &["ferrum", "backup", "schedule", "set", "--repo", "1", "--scope", "panel", "--cron", "0 3 * * *"]),
    ("cert.issue", &["ferrum", "cert", "issue", "1"]),
    ("cert.issue_wildcard", &["ferrum", "dns", "issue-wildcard", "1"]),
    ("cert.list", &["ferrum", "cert", "list"]),
    ("cron.delete", &["ferrum", "cron", "delete", "1"]),
    ("cron.list", &["ferrum", "cron", "list"]),
    ("cron.set", &["ferrum", "cron", "set", "--schedule", "@daily", "--command", "/usr/bin/true"]),
    ("db.adminer.disable", &["ferrum", "db", "adminer", "disable"]),
    ("db.adminer.enable", &["ferrum", "db", "adminer", "enable"]),
    ("db.adminer.status", &["ferrum", "db", "adminer", "status"]),
    ("db.create", &["ferrum", "db", "create", "shop", "--engine", "mysql"]),
    ("db.drop", &["ferrum", "db", "drop", "1", "--confirm-name", "shop"]),
    ("db.grant", &["ferrum", "db", "grant", "--database", "shop", "--user", "shop_rw"]),
    ("db.list", &["ferrum", "db", "list"]),
    ("db.user.create", &["ferrum", "db", "user", "create", "shop_rw", "--engine", "mysql"]),
    ("db.user.drop", &["ferrum", "db", "user", "drop", "shop_rw"]),
    ("db.user.password", &["ferrum", "db", "user", "password", "shop_rw"]),
    ("dns.check", &["ferrum", "dns", "check", "example.com"]),
    ("dns.provider.set", &["ferrum", "dns", "provider-set", "--label", "cf", "--token-stdin"]),
    ("fw.ban", &["ferrum", "firewall", "ban", "203.0.113.7"]),
    ("fw.bans", &["ferrum", "firewall", "bans"]),
    ("fw.port.close", &["ferrum", "firewall", "close", "8080"]),
    ("fw.port.open", &["ferrum", "firewall", "open", "8080"]),
    ("fw.rules", &["ferrum", "firewall", "rules"]),
    ("fw.unban", &["ferrum", "firewall", "unban", "203.0.113.7"]),
    ("metrics.snapshot", &["ferrum", "status"]),
    ("panel.tls.issue", &["ferrum", "cert", "panel", "panel.example.com"]),
    ("plan.assign", &["ferrum", "plan", "assign", "--subscription", "1", "--plan", "2"]),
    ("plan.create", &["ferrum", "plan", "create", "basic", "--max-sites", "5", "--max-dbs", "5", "--storage-mb", "1024"]),
    ("plan.delete", &["ferrum", "plan", "delete", "1"]),
    ("plan.list", &["ferrum", "plan", "list"]),
    ("plan.update", &["ferrum", "plan", "update", "1", "--max-sites", "10"]),
    ("plugin.disable", &["ferrum", "plugin", "disable", "acme-dns"]),
    ("plugin.enable", &["ferrum", "plugin", "enable", "acme-dns"]),
    ("plugin.install", &["ferrum", "plugin", "install", "/srv/staging/acme-dns"]),
    ("plugin.list", &["ferrum", "plugin", "list"]),
    ("plugin.remove", &["ferrum", "plugin", "remove", "acme-dns"]),
    ("quota.backend", &["ferrum", "quota", "backend"]),
    ("quota.set", &["ferrum", "quota", "set", "1", "--soft-mb", "1024", "--hard-mb", "2048"]),
    ("quota.usage", &["ferrum", "quota", "usage", "1"]),
    ("security.posture", &["ferrum", "security", "posture"]),
    ("sentinel.settings", &["ferrum", "firewall", "settings"]),
    ("sentinel.settings.set", &["ferrum", "firewall", "settings-set", "--enabled", "true"]),
    ("sftp.disable", &["ferrum", "sftp", "disable", "1"]),
    ("sftp.enable", &["ferrum", "sftp", "enable", "1"]),
    ("site.create", &["ferrum", "site", "create", "example.com"]),
    ("site.delete", &["ferrum", "site", "delete", "1"]),
    ("site.drift", &["ferrum", "site", "drift", "1"]),
    ("site.list", &["ferrum", "site", "list"]),
    ("site.update", &["ferrum", "site", "update", "1", "--http3", "true"]),
    ("stack.install", &["ferrum", "stack", "install", "nginx"]),
    ("stack.remove", &["ferrum", "stack", "remove", "nginx"]),
    ("stack.status", &["ferrum", "stack", "status"]),
    ("subscription.list", &["ferrum", "subscription", "list"]),
    ("subscription.suspend", &["ferrum", "subscription", "suspend", "1", "--reason", "unpaid"]),
    ("subscription.unsuspend", &["ferrum", "subscription", "unsuspend", "1"]),
    ("svc.action", &["ferrum", "svc", "action", "nginx", "reload"]),
    ("svc.status", &["ferrum", "svc", "status", "nginx"]),
    ("sys.ping", &["ferrum", "ops", "agent"]),
    ("waf.disable", &["ferrum", "waf", "disable"]),
    ("waf.enable", &["ferrum", "waf", "enable"]),
    ("waf.rules.set", &["ferrum", "waf", "rules-set", "--exclusion", "942100=known false positive"]),
    ("waf.status", &["ferrum", "waf", "status"]),
    ("webhook.delete", &["ferrum", "webhook", "delete", "1"]),
    ("webhook.list", &["ferrum", "webhook", "list"]),
    ("webhook.set", &["ferrum", "webhook", "set", "https://example.test/hook", "--event", "site.created"]),
    ("webhook.test", &["ferrum", "webhook", "test", "1"]),
    ("wp.cli", &["ferrum", "wp", "cli", "1", "core", "version"]),
    ("wp.detect", &["ferrum", "wp", "detect", "1"]),
    ("wp.install", &["ferrum", "wp", "install", "1", "--title", "Shop", "--admin-user", "admin", "--admin-email", "admin@example.com"]),
    ("wp.plugin.list", &["ferrum", "wp", "plugin", "list", "1"]),
    ("wp.plugin.update", &["ferrum", "wp", "plugin", "update", "1"]),
    ("wp.update", &["ferrum", "wp", "update", "1"]),
];

/// The table as JSON, for `ferrum ops list`.
pub fn as_json() -> Value {
    let rows: Vec<Value> = COVERAGE
        .iter()
        .map(|(op, argv)| {
            // Drop the program name: what an operator wants to see is the
            // subcommand path, not `ferrum ferrum site list`.
            let command = argv[1..].join(" ");
            json!({ "operation": op, "command": command })
        })
        .collect();
    json!({ "operations": rows, "count": COVERAGE.len() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::invoke::{Action, Secrets, action_for};
    use clap::Parser;

    /// Every secret the table's commands need, so the planner gets past the
    /// "this must come from stdin" check without any real I/O.
    fn secrets() -> Secrets {
        Secrets {
            dns_token: Some("test-token".into()),
            s3_secret_access_key: Some("test-secret".into()),
            sftp_password: Some("test-password".into()),
        }
    }

    #[test]
    fn every_listed_command_really_plans_that_operation() {
        // This is what makes the parity gate mean something: the gate greps
        // this table for names, and this test proves each name is what the
        // command actually sends.
        for (op, argv) in COVERAGE {
            let cli = Cli::try_parse_from(*argv)
                .unwrap_or_else(|e| panic!("`{}` does not parse: {e}", argv.join(" ")));
            let action = action_for(&cli.command, &secrets())
                .unwrap_or_else(|e| panic!("`{}` does not plan: {e}", argv.join(" ")));
            match action {
                Action::Call(invocation) => assert_eq!(
                    invocation.op,
                    *op,
                    "`{}` sends `{}`, not `{op}`",
                    argv.join(" "),
                    invocation.op
                ),
                // The one read-modify-write: it touches both settings ops.
                Action::MergeSentinelSettings(_) => assert!(
                    matches!(*op, "sentinel.settings" | "sentinel.settings.set"),
                    "`{}` is a Sentinel merge but is filed under `{op}`",
                    argv.join(" ")
                ),
                Action::Local => panic!(
                    "`{}` is filed under `{op}` but never reaches the agent",
                    argv.join(" ")
                ),
            }
        }
    }

    #[test]
    fn no_operation_is_listed_twice() {
        // A duplicate would make the gate's count agree while hiding a gap.
        let mut names: Vec<&str> = COVERAGE.iter().map(|(op, _)| *op).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(
            before,
            names.len(),
            "an operation appears twice in COVERAGE"
        );
    }

    #[test]
    fn the_table_is_sorted_so_a_diff_stays_readable() {
        let names: Vec<&str> = COVERAGE.iter().map(|(op, _)| *op).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "keep COVERAGE in operation-name order");
    }

    #[test]
    fn ops_list_shows_the_command_without_the_program_name() {
        let json = as_json();
        assert_eq!(json["count"], COVERAGE.len());
        let first = &json["operations"][0];
        assert_eq!(first["operation"], "alert.channels.delete");
        assert_eq!(first["command"], "alert channels-delete 1");
    }
}
