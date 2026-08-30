//! Turning an operation's JSON answer into something a person can read
//! (spec §11.20).
//!
//! `--json` prints the agent's reply verbatim and is the contract scripts use.
//! Everything here is the other half: the default, human view. It is
//! deliberately generic — one table renderer plus a handful of column orders —
//! because ninety-eight operations cannot each carry a bespoke printer without
//! the printers rotting out of step with the operations.
//!
//! One rule worth stating: **column order never comes from map iteration
//! order.** `serde_json`'s `preserve_order` feature is enabled by another crate
//! in this workspace, so a `Map` is a `BTreeMap` when `unihelm-cli` is built
//! alone and an `IndexMap` when the workspace is built together. Sorting the
//! keys explicitly makes the output the same in both, which is also what makes
//! the tests below mean anything.

use serde_json::Value;

/// Cells longer than this are cut. A table that wraps is a table nobody can
/// read; `--json` is the lossless view and the marker says which one you want.
const MAX_CELL: usize = 60;

/// The column order for the listings people actually read, so the useful field
/// is not buried three columns to the right of a timestamp.
///
/// Keys are `<operation>` for a bare array, or `<operation>.<field>` for the
/// named array inside an output object — several operations answer with two
/// (`db.list` returns databases *and* users; `fw.bans` returns bans and the
/// addresses the firewall is dropping without a record), and one column order
/// cannot serve both.
///
/// The names come from the operations' own output types. An operation with no
/// entry here still renders — the columns are then the row's own keys, sorted
/// — and a name that no longer exists loses its column rather than printing a
/// stripe of dashes, so this table degrades instead of lying.
#[rustfmt::skip]
const COLUMNS: &[(&str, &[&str])] = &[
    ("site.list.sites", &["id", "domain", "site_type", "php_version", "status", "has_certificate"]),
    ("db.list.databases", &["id", "name", "engine", "subscription_id"]),
    ("db.list.users", &["id", "username", "engine", "subscription_id"]),
    ("cert.list.certificates", &["id", "domains", "status", "not_after", "days_remaining", "due_for_renewal"]),
    ("cron.list.jobs", &["id", "subscription_id", "schedule", "command", "enabled", "last_error"]),
    ("plan.list.plans", &["id", "name", "max_sites", "max_dbs", "storage_mb", "can_ssh", "can_cron", "can_node_apps", "subscriptions"]),
    ("subscription.list.subscriptions", &["id", "customer_id", "customer_username", "plan_id", "status", "sites", "suspended_reason"]),
    ("app.list.apps", &["id", "name", "entry", "port", "node_env", "enabled", "state"]),
    ("fw.bans.bans", &["ip", "reason", "banned_at", "expires_at", "in_backend"]),
    ("fw.rules.rules", &["port", "proto", "source", "comment", "in_panel", "in_backend", "drift"]),
    ("backup.list.snapshots", &["short_id", "time", "hostname", "paths", "tags"]),
    ("stack.status.components", &["slug", "display_name", "status", "installed_version", "unit_state"]),
    ("alert.events.list.events", &["id", "rule_id", "subject", "message", "value", "raised_at", "resolved_at"]),
    ("alert.rules.list.rules", &["id", "kind", "target", "threshold", "enabled"]),
    ("alert.channels.list.channels", &["id", "kind", "label", "enabled"]),
    // Straight from `wp plugin list --format=json`, so these are WordPress's
    // field names, not the panel's.
    ("wp.plugin.list.plugins", &["name", "status", "version", "update"]),
    ("security.posture.findings", &["severity", "id", "title", "risk"]),
    // Two CLI-local views. They are not registered operations — the task table
    // is the panel's own bookkeeping and `cli.ops` is this build's parity table
    // — but they render through the same table code.
    ("task.list.tasks", &["id", "op", "status", "progress", "created_at", "finished_at"]),
    ("cli.ops.operations", &["operation", "command"]),
];

/// Render one operation's output for a terminal.
pub fn render(op: &str, value: &Value) -> String {
    if op == "metrics.snapshot" {
        return snapshot(value);
    }
    render_value(op, value)
}

fn render_value(op: &str, value: &Value) -> String {
    match value {
        Value::Array(rows) => table(op, rows),
        Value::Object(map) => {
            // The common shape: array(s) of rows, plus a little context.
            // `{"tasks": [...], "active": 3}` prints the count and the table;
            // `{"databases": [...], "users": [...]}` prints both tables under
            // their own headings, because an output with two lists in it is not
            // a record and should not be printed as one.
            let mut arrays: Vec<&String> = map
                .iter()
                .filter(|(_, v)| v.is_array())
                .map(|(k, _)| k)
                .collect();
            if arrays.is_empty() {
                return pairs(map);
            }
            arrays.sort();

            let mut out = String::new();
            let mut scalars: Vec<(&String, &Value)> = map
                .iter()
                .filter(|(k, _)| !arrays.iter().any(|a| a.as_str() == k.as_str()))
                .collect();
            scalars.sort_by(|a, b| a.0.cmp(b.0));
            for (k, v) in scalars {
                out.push_str(&format!("{k}: {}\n", cell(v)));
            }

            let single = arrays.len() == 1;
            for key in arrays {
                let rows = map[key.as_str()].as_array().expect("filtered to arrays");
                if !out.is_empty() {
                    out.push('\n');
                }
                // One list needs no heading; more than one does, or the reader
                // cannot tell which table they are looking at.
                if !single {
                    out.push_str(&format!("{key}:\n"));
                }
                out.push_str(&table(&format!("{op}.{key}"), rows));
            }
            out
        }
        other => cell(other),
    }
}

/// Key/value lines for a single record.
fn pairs(map: &serde_json::Map<String, Value>) -> String {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    let width = keys.iter().map(|k| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for key in keys {
        out.push_str(&format!("{key:<width$}  {}\n", cell(&map[key])));
    }
    if out.is_empty() {
        out.push_str("(no fields)\n");
    }
    out
}

fn table(op: &str, rows: &[Value]) -> String {
    if rows.is_empty() {
        return "(none)\n".to_string();
    }
    // A list of scalars is a list, not a table.
    if rows.iter().all(|r| !r.is_object()) {
        return rows
            .iter()
            .map(|r| format!("{}\n", cell(r)))
            .collect::<String>();
    }

    let columns = columns_for(op, rows);
    let mut widths: Vec<usize> = columns.iter().map(|c| c.len()).collect();
    let mut body: Vec<Vec<String>> = Vec::with_capacity(rows.len());
    for row in rows {
        let cells: Vec<String> = columns
            .iter()
            .map(|c| row.get(c.as_str()).map(cell).unwrap_or_else(|| "-".into()))
            .collect();
        for (i, text) in cells.iter().enumerate() {
            widths[i] = widths[i].max(display_width(text));
        }
        body.push(cells);
    }

    let mut out = String::new();
    out.push_str(&line(&columns, &widths));
    for row in body {
        out.push_str(&line(&row, &widths));
    }
    out
}

fn line(cells: &[String], widths: &[usize]) -> String {
    let mut out = String::new();
    for (i, text) in cells.iter().enumerate() {
        if i + 1 == cells.len() {
            out.push_str(text);
        } else {
            let pad = widths[i].saturating_sub(display_width(text));
            out.push_str(text);
            out.push_str(&" ".repeat(pad + 2));
        }
    }
    out.push('\n');
    out
}

/// Which columns to show, and in which order.
fn columns_for(op: &str, rows: &[Value]) -> Vec<String> {
    if let Some((_, wanted)) = COLUMNS.iter().find(|(name, _)| *name == op) {
        // Only the columns that are actually present: a listing that grew or
        // lost a field should lose a column, not print a stripe of dashes.
        let present: Vec<String> = wanted
            .iter()
            .filter(|c| rows.iter().any(|r| r.get(**c).is_some()))
            .map(|c| (*c).to_string())
            .collect();
        if !present.is_empty() {
            return present;
        }
    }
    // No spec: every scalar key any row has, sorted. Nested objects are left
    // out of the table — they belong in `--json`, not in a column.
    let mut keys: Vec<String> = Vec::new();
    for row in rows {
        if let Some(map) = row.as_object() {
            for (k, v) in map {
                if !v.is_object() && !v.is_array() && !keys.iter().any(|seen| seen == k) {
                    keys.push(k.clone());
                }
            }
        }
    }
    keys.sort();
    keys
}

/// One cell's text. Long values are cut with a marker rather than allowed to
/// wrap and destroy the alignment of every row below.
fn cell(value: &Value) -> String {
    let text = match value {
        Value::Null => "-".to_string(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    };
    let text = text.replace(['\n', '\t'], " ");
    if text.chars().count() > MAX_CELL {
        let kept: String = text.chars().take(MAX_CELL - 1).collect();
        return format!("{kept}…");
    }
    text
}

/// Character count, not byte count: a Persian domain or a UTF-8 error detail
/// would otherwise be padded by its byte length and pull the column apart.
fn display_width(text: &str) -> usize {
    text.chars().count()
}

// ---------------------------------------------------------------------------
// the one bespoke renderer
// ---------------------------------------------------------------------------

/// `metrics.snapshot` earns a hand-written view: it is what `unihelm status`
/// prints, it is read far more often than anything else here, and its shape is
/// fixed.
fn snapshot(value: &Value) -> String {
    let cpu = value["cpu"]["usage_pct"].as_f64().unwrap_or(0.0);
    let cores = value["cpu"]["cores"].as_u64().unwrap_or(0);
    let mem_used = value["memory"]["used_bytes"].as_u64().unwrap_or(0);
    let mem_total = value["memory"]["total_bytes"].as_u64().unwrap_or(0);
    let load = value["load"]["one"].as_f64().unwrap_or(0.0);
    let uptime = value["uptime_seconds"].as_u64().unwrap_or(0);

    let mut out = String::new();
    out.push_str(&format!(
        "cpu      {cpu:.1}% of {cores} core(s), load {load:.2}\n"
    ));
    out.push_str(&format!(
        "memory   {} / {}\n",
        crate::report::human_bytes(mem_used),
        crate::report::human_bytes(mem_total)
    ));
    out.push_str(&format!("uptime   {}\n", format_uptime(uptime)));

    if let Some(disks) = value["disks"].as_array() {
        for disk in disks {
            let mount = disk["mount"].as_str().unwrap_or("?");
            let used = disk["used_bytes"].as_u64().unwrap_or(0);
            let total = disk["total_bytes"].as_u64().unwrap_or(1).max(1);
            out.push_str(&format!(
                "disk     {mount}: {} / {} ({:.0}%)\n",
                crate::report::human_bytes(used),
                crate::report::human_bytes(total),
                used as f64 / total as f64 * 100.0
            ));
        }
    }
    out
}

pub fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    match (days, hours) {
        (0, 0) => format!("{minutes}m"),
        (0, h) => format!("{h}h {minutes}m"),
        (d, h) => format!("{d}d {h}h"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_listing_becomes_an_aligned_table() {
        let value = json!({
            "sites": [
                { "id": 1, "domain": "a.example", "site_type": "php", "status": "active" },
                { "id": 12, "domain": "much-longer.example", "site_type": "static", "status": "active" },
            ]
        });
        let out = render("site.list", &value);
        let lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
        assert!(lines[0].starts_with("id  "), "header first: {lines:?}");
        // Every row starts its second column at the same offset, including the
        // one whose first cell is a character wider.
        let starts: Vec<usize> = lines.iter().map(|l| second_column_start(l)).collect();
        assert!(starts.iter().all(|s| *s == starts[0]), "{lines:?}");
    }

    fn second_column_start(line: &str) -> usize {
        let gap = line.find("  ").expect("cells are separated by two spaces");
        gap + line[gap..]
            .find(|c: char| c != ' ')
            .expect("a second cell follows")
    }

    #[test]
    fn an_empty_listing_says_so_instead_of_printing_a_bare_header() {
        assert_eq!(render("site.list", &json!({ "sites": [] })), "(none)\n");
        assert_eq!(render("cert.list", &json!([])), "(none)\n");
    }

    #[test]
    fn columns_come_from_the_spec_when_there_is_one() {
        let value = json!({
            "sites": [
                { "zzz_last": 1, "id": 7, "domain": "a.example", "site_type": "php" }
            ]
        });
        let out = render("site.list", &value);
        let header = out.lines().next().unwrap();
        assert!(header.starts_with("id"), "{header}");
        assert!(
            !header.contains("zzz_last"),
            "a spec lists the columns worth showing, not every field: {header}"
        );
    }

    #[test]
    fn an_output_with_two_lists_prints_two_tables_under_their_own_names() {
        // `db.list` answers with databases *and* users. Printed as one record
        // it was two lines of compact JSON; the point of the human view is that
        // it is readable.
        let value = json!({
            "databases": [{ "id": 1, "name": "shop", "engine": "mysql", "subscription_id": 2 }],
            "users": [{ "id": 3, "username": "shop_rw", "engine": "mysql", "subscription_id": 2 }],
        });
        let out = render("db.list", &value);
        assert!(out.contains("databases:\n"), "{out}");
        assert!(out.contains("users:\n"), "{out}");
        assert!(out.contains("shop_rw"), "{out}");
        // Each table gets its own column order, from its own key.
        assert!(out.contains("id  name"), "{out}");
        assert!(out.contains("id  username"), "{out}");
    }

    #[test]
    fn a_single_list_needs_no_heading_and_no_leading_blank_line() {
        let out = render("site.list", &json!({ "sites": [{ "id": 1 }] }));
        assert!(!out.starts_with('\n'), "leading blank line: {out:?}");
        assert!(!out.contains("sites:"), "{out}");
    }

    #[test]
    fn columns_without_a_spec_are_sorted_rather_than_map_ordered() {
        // The hazard this guards: `serde_json`'s preserve_order feature is on
        // when the workspace is built together and off when this crate is built
        // alone, so unsorted keys would print in two different orders.
        let value = json!([{ "zebra": 1, "alpha": 2, "middle": 3 }]);
        let header = render("no.such.op", &value)
            .lines()
            .next()
            .unwrap()
            .to_string();
        assert!(header.starts_with("alpha"), "{header}");
        assert!(header.contains("middle"), "{header}");
        assert!(header.ends_with("zebra"), "{header}");
    }

    #[test]
    fn a_single_record_prints_as_key_value_lines() {
        let out = render(
            "site.create",
            &json!({ "site_id": 4, "domain": "x.example" }),
        );
        assert!(out.contains("site_id"), "{out}");
        assert!(out.contains("x.example"), "{out}");
    }

    #[test]
    fn a_long_cell_is_cut_and_says_so() {
        let long = "e".repeat(200);
        let out = render("no.such.op", &json!([{ "detail": long }]));
        let row = out.lines().nth(1).unwrap();
        assert!(row.chars().count() <= MAX_CELL, "{row}");
        assert!(row.ends_with('…'), "the cut must be visible: {row}");
    }

    #[test]
    fn a_missing_field_is_a_dash_not_a_panic() {
        let value = json!({ "sites": [{ "id": 1 }, { "id": 2, "domain": "b.example" }] });
        let out = render("site.list", &value);
        assert!(out.contains('-'), "{out}");
    }

    #[test]
    fn newlines_inside_a_value_cannot_break_the_table() {
        let out = render("no.such.op", &json!([{ "a": "one\ntwo", "b": 1 }]));
        assert_eq!(out.lines().count(), 2, "header plus exactly one row: {out}");
    }

    #[test]
    fn the_status_snapshot_reads_as_a_summary() {
        let out = render(
            "metrics.snapshot",
            &json!({
                "cpu": { "usage_pct": 12.5, "cores": 4 },
                "memory": { "used_bytes": 1024 * 1024 * 512, "total_bytes": 1024 * 1024 * 1024 },
                "load": { "one": 0.42 },
                "uptime_seconds": 90_000,
                "disks": [{ "mount": "/", "used_bytes": 50, "total_bytes": 100 }],
            }),
        );
        assert!(out.contains("12.5% of 4 core(s)"), "{out}");
        assert!(out.contains("512.0 MiB / 1.0 GiB"), "{out}");
        assert!(out.contains("1d 1h"), "{out}");
        assert!(out.contains("/: 50 B / 100 B (50%)"), "{out}");
    }

    #[test]
    fn uptime_reads_naturally() {
        assert_eq!(format_uptime(45), "0m");
        assert_eq!(format_uptime(600), "10m");
        assert_eq!(format_uptime(3_700), "1h 1m");
        assert_eq!(format_uptime(90_000), "1d 1h");
    }
}
