//! Health reporting for `ferrum doctor` (spec §5.5).

use std::fmt;

/// One line of a health report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub level: Level,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    /// Works, but something is worth knowing about.
    Warn,
    /// Broken. `ferrum doctor` exits non-zero if any check is at this level, so
    /// it can be used in a monitoring cron.
    Fail,
}

impl Level {
    fn marker(self) -> &'static str {
        match self {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
        }
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {:<28} {}",
            self.level.marker(),
            self.name,
            self.detail
        )
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn push(&mut self, name: impl Into<String>, level: Level, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            level,
            detail: detail.into(),
        });
    }

    pub fn ok(&mut self, name: impl Into<String>, detail: impl Into<String>) {
        self.push(name, Level::Ok, detail);
    }

    pub fn warn(&mut self, name: impl Into<String>, detail: impl Into<String>) {
        self.push(name, Level::Warn, detail);
    }

    pub fn fail(&mut self, name: impl Into<String>, detail: impl Into<String>) {
        self.push(name, Level::Fail, detail);
    }

    /// The worst level in the report — what the exit code is derived from.
    pub fn worst(&self) -> Level {
        self.checks
            .iter()
            .map(|c| c.level)
            .max()
            .unwrap_or(Level::Ok)
    }

    /// 0 when everything passes or only warns, 1 when anything failed.
    ///
    /// Warnings deliberately do not fail: a panel that exits non-zero because
    /// Docker is not installed would be useless in a monitoring cron.
    pub fn exit_code(&self) -> i32 {
        i32::from(self.worst() == Level::Fail)
    }

    pub fn print(&self) {
        for check in &self.checks {
            println!("{check}");
        }
        let failed = self
            .checks
            .iter()
            .filter(|c| c.level == Level::Fail)
            .count();
        let warned = self
            .checks
            .iter()
            .filter(|c| c.level == Level::Warn)
            .count();
        println!();
        match (failed, warned) {
            (0, 0) => println!("{} checks, all healthy", self.checks.len()),
            (0, w) => println!("{} checks, {w} warning(s)", self.checks.len()),
            (f, w) => println!(
                "{} checks, {f} failure(s), {w} warning(s)",
                self.checks.len()
            ),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "status": match self.worst() {
                Level::Ok => "ok",
                Level::Warn => "warn",
                Level::Fail => "fail",
            },
            "checks": self.checks.iter().map(|c| serde_json::json!({
                "name": c.name,
                "level": match c.level {
                    Level::Ok => "ok",
                    Level::Warn => "warn",
                    Level::Fail => "fail",
                },
                "detail": c.detail,
            })).collect::<Vec<_>>(),
        })
    }
}

/// Human-readable byte size.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_fails_only_on_failures() {
        let mut r = Report::default();
        r.ok("a", "fine");
        assert_eq!(r.exit_code(), 0);

        r.warn("b", "docker is not installed");
        assert_eq!(
            r.exit_code(),
            0,
            "warnings must not break a monitoring cron"
        );

        r.fail("c", "database is unreadable");
        assert_eq!(r.exit_code(), 1);
        assert_eq!(r.worst(), Level::Fail);
    }

    #[test]
    fn an_empty_report_is_healthy() {
        assert_eq!(Report::default().exit_code(), 0);
        assert_eq!(Report::default().worst(), Level::Ok);
    }

    #[test]
    fn json_output_is_machine_readable() {
        let mut r = Report::default();
        r.ok("database", "integrity ok");
        r.fail("agent", "socket missing");
        let json = r.to_json();
        assert_eq!(json["status"], "fail");
        assert_eq!(json["checks"][0]["level"], "ok");
        assert_eq!(json["checks"][1]["name"], "agent");
    }

    #[test]
    fn byte_formatting_is_readable() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(52_428_800), "50.0 MiB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }
}
