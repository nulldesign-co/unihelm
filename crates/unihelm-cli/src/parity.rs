//! Which operation each CLI command reaches (spec §11.20).
//!
//! Spec §11.20 asks for a CLI that reaches everything the UI can. That is easy
//! to claim and easy to quietly stop being true: a wave adds three operations,
//! the UI grows three buttons, and nobody notices the CLI did not. So the claim
//! is checked from two directions, and this table is what both of them read.
//!
//! - `tests/gates/cli-parity.sh` takes every operation registered in
//!   `crates/unihelm-ops/src/registry.rs` and requires it to appear here or in
//!   the gate's allowlist, which carries a reason per entry. **The failing list
//!   is the checklist.**
//! - [`tests::every_listed_command_really_plans_that_operation`] parses each
//!   `argv` below through the real command tree and the real planner and
//!   asserts it emits exactly the operation it is filed under. Without that
//!   half the gate would only be checking that somebody typed a name into a
//!   table.
//! - [`tests::every_planned_payload_parses_as_its_operation_s_input`] takes the
//!   JSON each of those commands would send and deserialises it into the
//!   operation's own `Input` type, then checks every key it sends is really a
//!   field on that struct. "Reachable" has to mean the operation *accepts* what
//!   the CLI sends, not that a name matches; the second half is there because
//!   none of the `Input` types can use `deny_unknown_fields`, so a misspelt
//!   optional field would otherwise be dropped in silence.
//!
//! It is also what `unihelm ops list` prints, so an operator can see the mapping
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
    ("alert.channels.delete", &["unihelm", "alert", "channels-delete", "1"]),
    ("alert.channels.list", &["unihelm", "alert", "channels"]),
    ("alert.channels.set", &["unihelm", "alert", "channels-set", "--label", "ops"]),
    ("alert.channels.test", &["unihelm", "alert", "channels-test", "1"]),
    ("alert.events.list", &["unihelm", "alert", "events"]),
    ("alert.rules.list", &["unihelm", "alert", "rules"]),
    ("alert.rules.set", &["unihelm", "alert", "rules-set", "load", "--threshold", "4"]),
    ("app.create", &["unihelm", "app", "create", "api", "--entry", "server.js"]),
    ("app.delete", &["unihelm", "app", "delete", "1"]),
    ("app.list", &["unihelm", "app", "list"]),
    ("app.logs", &["unihelm", "app", "logs", "1"]),
    ("app.restart", &["unihelm", "app", "restart", "1"]),
    ("backup.list", &["unihelm", "backup", "list", "--repo", "1"]),
    ("backup.repo.delete", &["unihelm", "backup", "repo", "delete", "1"]),
    ("backup.repo.init", &["unihelm", "backup", "repo", "init", "--kind", "local", "--label", "disk", "--path", "/srv/backups"]),
    ("backup.restore", &["unihelm", "backup", "restore", "--repo", "1", "--snapshot", "abc123"]),
    ("backup.run", &["unihelm", "backup", "run", "--repo", "1", "--scope", "panel"]),
    ("backup.schedule.delete", &["unihelm", "backup", "schedule", "delete", "1"]),
    ("backup.schedule.set", &["unihelm", "backup", "schedule", "set", "--repo", "1", "--scope", "panel", "--cron", "0 3 * * *"]),
    ("branding.get", &["unihelm", "branding", "get"]),
    ("branding.set", &["unihelm", "branding", "set", "--panel-name", "Acme Hosting"]),
    ("cert.issue", &["unihelm", "cert", "issue", "1"]),
    ("cert.issue_wildcard", &["unihelm", "dns", "issue-wildcard", "1"]),
    ("cert.list", &["unihelm", "cert", "list"]),
    ("cron.delete", &["unihelm", "cron", "delete", "1"]),
    ("cron.list", &["unihelm", "cron", "list"]),
    ("cron.set", &["unihelm", "cron", "set", "--schedule", "@daily", "--command", "/usr/bin/true"]),
    ("db.adminer.disable", &["unihelm", "db", "adminer", "disable"]),
    ("db.adminer.enable", &["unihelm", "db", "adminer", "enable"]),
    ("db.adminer.status", &["unihelm", "db", "adminer", "status"]),
    ("db.create", &["unihelm", "db", "create", "shop", "--engine", "mysql"]),
    ("db.drop", &["unihelm", "db", "drop", "1", "--confirm-name", "shop"]),
    ("db.grant", &["unihelm", "db", "grant", "--database", "shop", "--user", "shop_rw"]),
    ("db.list", &["unihelm", "db", "list"]),
    ("db.user.create", &["unihelm", "db", "user", "create", "shop_rw", "--engine", "mysql"]),
    ("db.user.drop", &["unihelm", "db", "user", "drop", "shop_rw"]),
    ("db.user.password", &["unihelm", "db", "user", "password", "shop_rw"]),
    ("dns.check", &["unihelm", "dns", "check", "example.com"]),
    ("dns.provider.set", &["unihelm", "dns", "provider-set", "--label", "cf", "--token-stdin"]),
    ("docker.list", &["unihelm", "docker", "list"]),
    ("fw.ban", &["unihelm", "firewall", "ban", "203.0.113.7"]),
    ("fw.bans", &["unihelm", "firewall", "bans"]),
    ("fw.port.close", &["unihelm", "firewall", "close", "8080"]),
    ("fw.port.open", &["unihelm", "firewall", "open", "8080"]),
    ("fw.rules", &["unihelm", "firewall", "rules"]),
    ("fw.unban", &["unihelm", "firewall", "unban", "203.0.113.7"]),
    ("import.apply", &["unihelm", "import", "apply", "1"]),
    ("import.list", &["unihelm", "import", "list"]),
    ("import.plan", &["unihelm", "import", "plan", "--source", "cpanel", "--path", "/srv/backups/cpmove-shop.tar.gz", "--subscription", "1"]),
    ("mail.dns.publish", &["unihelm", "mail", "dns-publish"]),
    ("mail.relay.get", &["unihelm", "mail", "relay", "get"]),
    ("mail.relay.set", &["unihelm", "mail", "relay", "set", "smtp.example.com", "--port", "587", "--tls", "starttls", "--from", "panel@example.com"]),
    ("mail.relay.test", &["unihelm", "mail", "relay", "test", "--to", "ops@example.com"]),
    ("metrics.snapshot", &["unihelm", "status"]),
    ("panel.tls.issue", &["unihelm", "cert", "panel", "panel.example.com"]),
    ("plan.assign", &["unihelm", "plan", "assign", "--subscription", "1", "--plan", "2"]),
    ("plan.create", &["unihelm", "plan", "create", "basic", "--max-sites", "5", "--max-dbs", "5", "--storage-mb", "1024"]),
    ("plan.delete", &["unihelm", "plan", "delete", "1"]),
    ("plan.list", &["unihelm", "plan", "list"]),
    ("plan.update", &["unihelm", "plan", "update", "1", "--max-sites", "10"]),
    ("plugin.disable", &["unihelm", "plugin", "disable", "acme-dns"]),
    ("plugin.enable", &["unihelm", "plugin", "enable", "acme-dns"]),
    ("plugin.install", &["unihelm", "plugin", "install", "/srv/staging/acme-dns"]),
    ("plugin.list", &["unihelm", "plugin", "list"]),
    ("plugin.remove", &["unihelm", "plugin", "remove", "acme-dns"]),
    ("quota.backend", &["unihelm", "quota", "backend"]),
    ("quota.set", &["unihelm", "quota", "set", "1", "--soft-mb", "1024", "--hard-mb", "2048"]),
    ("quota.usage", &["unihelm", "quota", "usage", "1"]),
    ("runtime.install", &["unihelm", "runtime", "install", "--major", "22"]),
    ("runtime.list", &["unihelm", "runtime", "list"]),
    ("security.posture", &["unihelm", "security", "posture"]),
    ("sentinel.settings", &["unihelm", "firewall", "settings"]),
    ("sentinel.settings.set", &["unihelm", "firewall", "settings-set", "--enabled", "true"]),
    ("sftp.disable", &["unihelm", "sftp", "disable", "1"]),
    ("sftp.enable", &["unihelm", "sftp", "enable", "1"]),
    ("site.create", &["unihelm", "site", "create", "example.com"]),
    ("site.delete", &["unihelm", "site", "delete", "1"]),
    ("site.drift", &["unihelm", "site", "drift", "1"]),
    ("site.list", &["unihelm", "site", "list"]),
    ("site.update", &["unihelm", "site", "update", "1", "--http3", "true"]),
    ("sites.discover", &["unihelm", "site", "discover"]),
    ("ssh.keys.add", &["unihelm", "ssh-keys", "add", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyBytesHere name@host"]),
    ("ssh.keys.list", &["unihelm", "ssh-keys", "list"]),
    ("ssh.keys.remove", &["unihelm", "ssh-keys", "remove", "SHA256:0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"]),
    ("stack.install", &["unihelm", "stack", "install", "nginx"]),
    ("stack.remove", &["unihelm", "stack", "remove", "nginx"]),
    ("stack.status", &["unihelm", "stack", "status"]),
    ("subscription.list", &["unihelm", "subscription", "list"]),
    ("subscription.suspend", &["unihelm", "subscription", "suspend", "1", "--reason", "unpaid"]),
    ("subscription.unsuspend", &["unihelm", "subscription", "unsuspend", "1"]),
    ("svc.action", &["unihelm", "svc", "action", "nginx", "reload"]),
    ("svc.status", &["unihelm", "svc", "status", "nginx"]),
    ("sys.ping", &["unihelm", "ops", "agent"]),
    ("waf.disable", &["unihelm", "waf", "disable"]),
    ("waf.enable", &["unihelm", "waf", "enable"]),
    ("waf.rules.set", &["unihelm", "waf", "rules-set", "--exclusion", "942100=known false positive"]),
    ("waf.status", &["unihelm", "waf", "status"]),
    ("webhook.delete", &["unihelm", "webhook", "delete", "1"]),
    ("webhook.list", &["unihelm", "webhook", "list"]),
    ("webhook.set", &["unihelm", "webhook", "set", "https://example.test/hook", "--event", "site.created"]),
    ("webhook.test", &["unihelm", "webhook", "test", "1"]),
    ("wp.cli", &["unihelm", "wp", "cli", "1", "core", "version"]),
    ("wp.detect", &["unihelm", "wp", "detect", "1"]),
    ("wp.install", &["unihelm", "wp", "install", "1", "--title", "Shop", "--admin-user", "admin", "--admin-email", "admin@example.com"]),
    ("wp.plugin.list", &["unihelm", "wp", "plugin", "list", "1"]),
    ("wp.plugin.update", &["unihelm", "wp", "plugin", "update", "1"]),
    ("wp.update", &["unihelm", "wp", "update", "1"]),
];

/// The table as JSON, for `unihelm ops list`.
pub fn as_json() -> Value {
    let rows: Vec<Value> = COVERAGE
        .iter()
        .map(|(op, argv)| {
            // Drop the program name: what an operator wants to see is the
            // subcommand path, not `unihelm unihelm site list`.
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
            mail_relay_password: Some("test-password".into()),
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

    /// Deserialise a planned payload into the operation's own `Input` type.
    ///
    /// This is the check that a table of names cannot make: it is the
    /// operation's own parser saying yes. A required field the CLI spells
    /// wrongly, a number sent where a string belongs, a value a newtype
    /// refuses — all of them fail here rather than on the wire.
    fn parses_as<T: serde::de::DeserializeOwned>(op: &str, input: &Value) {
        if let Err(e) = serde_json::from_value::<T>(input.clone()) {
            panic!("`{op}` would send input its own operation refuses: {e}\n  {input}");
        }
    }

    /// Every top-level key the CLI sends must be a field the operation has.
    ///
    /// The parse check above cannot see this. None of the `Input` structs use
    /// `deny_unknown_fields` — they cannot, several of them flatten an enum —
    /// so a *misspelt optional* key deserialises perfectly and is silently
    /// dropped: `site update --maintenance true` would report success and
    /// change nothing. The only place that spelling is written down is the
    /// struct, so this reads the struct.
    ///
    /// `type_path` is `stringify!`d from the table below, and its first segment
    /// is the module, which is the file — or, once a module has grown enough
    /// to be split up, the directory. Both spellings are tried, the same way
    /// `module_file()` in `tests/gates/cli-parity.sh` does it, so a module
    /// becoming a directory does not turn this check into a panic.
    fn keys_are_real_fields(op: &str, type_path: &str, input: &Value) {
        let Some(fields) = input.as_object() else {
            return;
        };
        // Everything but the type name is the module path, so a type nested
        // two deep (`terminal::keys::AddInput`) is read from
        // `terminal/keys.rs` rather than from `terminal/mod.rs`, which would
        // not contain the fields and would fail for the wrong reason.
        let mut segments: Vec<&str> = type_path.split("::").collect();
        segments.pop().expect("a module-qualified type");
        assert!(
            !segments.is_empty(),
            "`{op}` names `{type_path}` with no module to look it up in"
        );
        let module = segments.join("/");
        let base = format!("{}/../unihelm-ops/src/{module}", env!("CARGO_MANIFEST_DIR"));
        let flat = format!("{base}.rs");
        let path = if std::path::Path::new(&flat).is_file() {
            flat
        } else {
            format!("{base}/mod.rs")
        };
        let source = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("could not read {path} for `{op}` ({e}); where does module `{module}` live?")
        });
        for key in fields.keys() {
            assert!(
                source.contains(&format!("pub {key}:")),
                "`{op}` sends `{key}`, which is not a field in {path} — serde would \
                 discard it without a word"
            );
        }
    }

    /// The payload the CLI would send for one COVERAGE row.
    fn payload(op: &str) -> Value {
        let (_, argv) = COVERAGE
            .iter()
            .find(|(name, _)| *name == op)
            .unwrap_or_else(|| panic!("`{op}` is not in COVERAGE"));
        let cli = Cli::try_parse_from(*argv).expect("parses");
        match action_for(&cli.command, &secrets()).expect("plans") {
            Action::Call(invocation) => invocation.input,
            // The merge's write is built from what the agent returned, so the
            // payload under test is the merged struct, not the patch.
            Action::MergeSentinelSettings(patch) => patch.apply(
                serde_json::to_value(unihelm_ops::fwops::SentinelSettings::default())
                    .expect("settings serialise"),
            ),
            Action::Local => panic!("`{op}` never reaches the agent"),
        }
    }

    #[test]
    fn every_planned_payload_parses_as_its_operation_s_input() {
        use unihelm_ops::*;

        macro_rules! check {
            ($($op:literal => $ty:ty),* $(,)?) => {{
                let mut checked: Vec<&str> = Vec::new();
                $(
                    let input = payload($op);
                    parses_as::<$ty>($op, &input);
                    keys_are_real_fields($op, stringify!($ty), &input);
                    checked.push($op);
                )*
                checked
            }};
        }

        let mut checked = check! {
            "alert.channels.delete" => alerts::ChannelsDeleteInput,
            "alert.channels.list" => alerts::ChannelsListInput,
            "alert.channels.set" => alerts::ChannelsSetInput,
            "alert.channels.test" => alerts::ChannelsTestInput,
            "alert.events.list" => alerts::EventsListInput,
            "alert.rules.list" => alerts::RulesListInput,
            "alert.rules.set" => alerts::RulesSetInput,
            "app.create" => nodeapp::CreateInput,
            "app.delete" => nodeapp::DeleteInput,
            "app.list" => nodeapp::ListInput,
            "app.logs" => nodeapp::LogsInput,
            "app.restart" => nodeapp::RestartInput,
            "backup.list" => backup::ListInput,
            "backup.repo.delete" => backup::RepoDeleteInput,
            "backup.repo.init" => backup::RepoInitInput,
            "backup.restore" => backup::RestoreInput,
            "backup.run" => backup::RunInput,
            "backup.schedule.delete" => backup::ScheduleDeleteInput,
            "backup.schedule.set" => backup::ScheduleSetInput,
            "branding.get" => branding::GetInput,
            "branding.set" => branding::SetInput,
            "cert.issue" => cert::IssueInput,
            "cert.issue_wildcard" => dns::IssueWildcardInput,
            "cert.list" => cert::ListInput,
            "cron.delete" => cron::DeleteInput,
            "cron.list" => cron::ListInput,
            "cron.set" => cron::SetInput,
            "db.adminer.disable" => adminer::DisableInput,
            "db.adminer.enable" => adminer::EnableInput,
            "db.adminer.status" => adminer::StatusInput,
            "db.create" => db::CreateInput,
            "db.drop" => db::DropInput,
            "db.grant" => db::GrantInput,
            "db.list" => db::ListInput,
            "db.user.create" => db::UserCreateInput,
            "db.user.drop" => db::UserDropInput,
            "db.user.password" => db::UserPasswordInput,
            "dns.check" => dns::CheckInput,
            "dns.provider.set" => dns::ProviderSetInput,
            "fw.ban" => fwops::BanInput,
            "fw.bans" => fwops::BansInput,
            "fw.port.close" => fwops::PortInput,
            "fw.port.open" => fwops::PortInput,
            "fw.rules" => fwops::RulesInput,
            "fw.unban" => fwops::UnbanInput,
            "import.apply" => importer::ApplyInput,
            "import.list" => importer::ListInput,
            "import.plan" => importer::PlanInput,
            "mail.dns.publish" => mail::DnsPublishInput,
            "mail.relay.get" => mail::RelayGetInput,
            "mail.relay.set" => mail::RelaySetInput,
            "mail.relay.test" => mail::RelayTestInput,
            "metrics.snapshot" => metrics::SnapshotInput,
            "panel.tls.issue" => panel::IssueInput,
            "plan.assign" => plan::AssignInput,
            "plan.create" => plan::CreateInput,
            "plan.delete" => plan::DeleteInput,
            "plan.list" => plan::ListInput,
            "plan.update" => plan::UpdateInput,
            "plugin.disable" => plugin::SlugInput,
            "plugin.enable" => plugin::SlugInput,
            "plugin.install" => plugin::InstallInput,
            "plugin.list" => plugin::ListInput,
            "plugin.remove" => plugin::SlugInput,
            "quota.backend" => quota::BackendInput,
            "quota.set" => quota::SetInput,
            "quota.usage" => quota::UsageInput,
            "docker.list" => docker::ListInput,
            "runtime.install" => runtimes::InstallInput,
            "runtime.list" => runtimes::ListInput,
            "security.posture" => posture::PostureInput,
            "sentinel.settings" => fwops::SettingsGetInput,
            "sentinel.settings.set" => fwops::SentinelSettings,
            "sftp.disable" => sftp::DisableInput,
            "sftp.enable" => sftp::EnableInput,
            "site.create" => site::CreateInput,
            "site.delete" => site::DeleteInput,
            "site.drift" => site::DriftInput,
            "site.list" => site::ListInput,
            "site.update" => site::UpdateInput,
            "sites.discover" => nginx_survey::DiscoverInput,
            "ssh.keys.add" => terminal::keys::AddInput,
            "ssh.keys.list" => terminal::keys::ListInput,
            "ssh.keys.remove" => terminal::keys::RemoveInput,
            "stack.install" => stack::InstallInput,
            "stack.remove" => stack::RemoveInput,
            "stack.status" => stack::StatusInput,
            "subscription.list" => plan::ListSubscriptionsInput,
            "subscription.suspend" => plan::SuspendInput,
            "subscription.unsuspend" => plan::UnsuspendInput,
            "svc.action" => svc::ActionInput,
            "svc.status" => svc::StatusInput,
            "sys.ping" => sys::PingInput,
            "waf.disable" => waf::DisableInput,
            "waf.enable" => waf::EnableInput,
            "waf.rules.set" => waf::RulesSetInput,
            "waf.status" => waf::StatusInput,
            "webhook.delete" => webhook::DeleteInput,
            "webhook.list" => webhook::ListInput,
            "webhook.set" => webhook::SetInput,
            "webhook.test" => webhook::TestInput,
            "wp.cli" => wordpress::CliInput,
            "wp.detect" => wordpress::DetectInput,
            "wp.install" => wordpress::InstallInput,
            "wp.plugin.list" => wordpress::PluginListInput,
            "wp.plugin.update" => wordpress::PluginUpdateInput,
            "wp.update" => wordpress::UpdateInput,
        };

        // And the table above must cover the table below, or an operation could
        // be added to COVERAGE and quietly never have its payload checked.
        checked.sort_unstable();
        let mut listed: Vec<&str> = COVERAGE.iter().map(|(op, _)| *op).collect();
        listed.sort_unstable();
        assert_eq!(
            checked, listed,
            "every COVERAGE row needs an Input type here, and vice versa"
        );
    }

    #[test]
    fn a_payload_with_a_misspelt_required_field_is_caught() {
        // The guard on the guard: `parses_as` has to actually reject something,
        // or the test above is 82 assertions that never fire. `site.create`
        // without its domain is exactly the shape of a rename gone wrong.
        let broken = json!({ "domian": "example.com" });
        let outcome = std::panic::catch_unwind(|| {
            parses_as::<unihelm_ops::site::CreateInput>("site.create", &broken)
        });
        assert!(
            outcome.is_err(),
            "a missing required field must fail the payload check"
        );
    }

    #[test]
    fn a_misspelt_optional_field_is_caught_even_though_serde_accepts_it() {
        // The gap this closes, demonstrated: `site.update` takes
        // `maintenance_mode`, and `maintenance` deserialises without complaint
        // because there is no `deny_unknown_fields` to complain. Only the
        // source check notices.
        let plausible = json!({ "site_id": 1, "maintenance": true });
        assert!(
            serde_json::from_value::<unihelm_ops::site::UpdateInput>(plausible.clone()).is_ok(),
            "serde really does accept it, which is the whole problem"
        );
        let outcome = std::panic::catch_unwind(|| {
            keys_are_real_fields("site.update", "site::UpdateInput", &plausible)
        });
        assert!(
            outcome.is_err(),
            "the source check must catch what serde does not"
        );
    }

    #[test]
    fn a_newtype_that_refuses_its_value_is_caught() {
        // The other half: a field that is present, of the right JSON type, and
        // still not a legal value. `Domain` is the one the CLI leans on most.
        let outcome = std::panic::catch_unwind(|| {
            parses_as::<unihelm_ops::site::CreateInput>(
                "site.create",
                &json!({ "domain": "not a domain at all" }),
            )
        });
        assert!(outcome.is_err(), "an invalid Domain must fail the check");
    }
}
