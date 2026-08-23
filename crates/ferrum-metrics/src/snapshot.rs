//! The shapes the API and the dashboard consume.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LoadAverage {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CpuUsage {
    pub cores: u32,
    /// Global usage as a percentage of all cores combined.
    pub usage_pct: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryUsage {
    pub total_bytes: u64,
    pub used_bytes: u64,
    /// What a new process could actually get — the number that matters, not
    /// `total - used`.
    pub available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
}

impl MemoryUsage {
    pub fn used_pct(&self) -> f32 {
        pct(self.used_bytes, self.total_bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskUsage {
    pub mount: String,
    pub filesystem: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
}

impl DiskUsage {
    pub fn used_pct(&self) -> f32 {
        pct(self.used_bytes, self.total_bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTotals {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
}

/// The panel's own resident memory — surfaced in the UI and asserted by CI
/// against the 80 MB budget (spec §3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelFootprint {
    pub web_rss_bytes: Option<u64>,
    pub agent_rss_bytes: Option<u64>,
    pub total_rss_bytes: Option<u64>,
}

impl PanelFootprint {
    /// The CI budget, in bytes.
    pub const BUDGET_BYTES: u64 = 80 * 1024 * 1024;
    /// What we are actually aiming for.
    pub const TARGET_BYTES: u64 = 50 * 1024 * 1024;

    pub fn within_budget(&self) -> Option<bool> {
        self.total_rss_bytes.map(|b| b <= Self::BUDGET_BYTES)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerSnapshot {
    #[serde(with = "time::serde::rfc3339")]
    pub at: time::OffsetDateTime,
    pub uptime_seconds: u64,
    pub load: LoadAverage,
    pub cpu: CpuUsage,
    pub memory: MemoryUsage,
    pub disks: Vec<DiskUsage>,
    pub network: NetworkTotals,
    pub panel: PanelFootprint,
}

fn pct(part: u64, whole: u64) -> f32 {
    if whole == 0 {
        return 0.0;
    }
    let raw = (part as f64 / whole as f64 * 100.0) as f32;
    (raw * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentages_handle_the_empty_case() {
        let m = MemoryUsage {
            total_bytes: 0,
            used_bytes: 0,
            available_bytes: 0,
            swap_total_bytes: 0,
            swap_used_bytes: 0,
        };
        assert_eq!(
            m.used_pct(),
            0.0,
            "an unknown total must not divide by zero"
        );
    }

    #[test]
    fn percentages_round_to_one_decimal() {
        let d = DiskUsage {
            mount: "/".into(),
            filesystem: "ext4".into(),
            total_bytes: 3,
            used_bytes: 1,
            available_bytes: 2,
        };
        assert_eq!(d.used_pct(), 33.3);
    }

    #[test]
    fn budget_check_distinguishes_unknown_from_over() {
        assert_eq!(PanelFootprint::default().within_budget(), None);
        let ok = PanelFootprint {
            web_rss_bytes: Some(30 * 1024 * 1024),
            agent_rss_bytes: Some(20 * 1024 * 1024),
            total_rss_bytes: Some(50 * 1024 * 1024),
        };
        assert_eq!(ok.within_budget(), Some(true));
        let over = PanelFootprint {
            total_rss_bytes: Some(81 * 1024 * 1024),
            ..ok
        };
        assert_eq!(over.within_budget(), Some(false));
    }

    #[test]
    fn snapshot_serialises_with_an_rfc3339_timestamp() {
        let s = ServerSnapshot {
            at: time::OffsetDateTime::UNIX_EPOCH,
            uptime_seconds: 10,
            load: LoadAverage {
                one: 0.1,
                five: 0.2,
                fifteen: 0.3,
            },
            cpu: CpuUsage {
                cores: 2,
                usage_pct: 12.5,
            },
            memory: MemoryUsage {
                total_bytes: 100,
                used_bytes: 50,
                available_bytes: 50,
                swap_total_bytes: 0,
                swap_used_bytes: 0,
            },
            disks: vec![],
            network: NetworkTotals {
                rx_bytes: 1,
                tx_bytes: 2,
                rx_bytes_per_sec: 0,
                tx_bytes_per_sec: 0,
            },
            panel: PanelFootprint::default(),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["at"], "1970-01-01T00:00:00Z");
        assert_eq!(v["cpu"]["cores"], 2);
        // Round-trips, so the UI and the CLI see the same shape.
        let back: ServerSnapshot = serde_json::from_value(v).unwrap();
        assert_eq!(back, s);
    }
}
