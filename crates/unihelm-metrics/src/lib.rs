//! `unihelm-metrics` — the collector behind the dashboard and the alert rules
//! (spec §11.11).
//!
//! The budget is the design constraint: **≤ 1% of one core on average** and no
//! meaningful contribution to the 80 MB RSS ceiling (spec §3). So the collector
//! keeps one long-lived [`sysinfo::System`], refreshes only the subsystems a
//! given call needs, and throttles back-to-back refreshes — a dashboard with
//! four widgets open must not become four full `/proc` sweeps per second.

pub mod snapshot;

pub use snapshot::{
    CpuUsage, DiskUsage, LoadAverage, MemoryUsage, NetworkTotals, PanelFootprint, ServerSnapshot,
};

use std::time::{Duration, Instant};

use sysinfo::{Disks, MemoryRefreshKind, Networks, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::sync::Mutex;

/// CPU percentages need two samples to mean anything; anything closer together
/// than this is served from the previous reading.
pub const MIN_REFRESH_INTERVAL: Duration = Duration::from_millis(900);

/// Collects server metrics.
///
/// Cheap to clone-by-reference (`Arc<Collector>`); the interior state is behind
/// one mutex so concurrent dashboard requests coalesce onto a single refresh.
pub struct Collector {
    inner: Mutex<Inner>,
}

struct Inner {
    system: System,
    disks: Disks,
    networks: Networks,
    last_refresh: Option<Instant>,
    last_snapshot: Option<ServerSnapshot>,
    /// Byte counters from the previous sample, to derive rates.
    last_net: Option<(Instant, NetworkTotals)>,
}

impl Collector {
    pub fn new() -> Self {
        let mut system = System::new();
        // Prime the CPU counters so the first real sample has something to diff
        // against instead of reporting 0%.
        system.refresh_cpu_usage();

        Self {
            inner: Mutex::new(Inner {
                system,
                disks: Disks::new_with_refreshed_list(),
                networks: Networks::new_with_refreshed_list(),
                last_refresh: None,
                last_snapshot: None,
                last_net: None,
            }),
        }
    }

    /// A full server snapshot, refreshed at most once per
    /// [`MIN_REFRESH_INTERVAL`].
    pub async fn snapshot(&self) -> ServerSnapshot {
        let mut inner = self.inner.lock().await;

        if let (Some(last), Some(prev)) = (inner.last_refresh, inner.last_snapshot.as_ref())
            && last.elapsed() < MIN_REFRESH_INTERVAL
        {
            return prev.clone();
        }

        let now = Instant::now();
        inner.system.refresh_cpu_usage();
        inner
            .system
            .refresh_memory_specifics(MemoryRefreshKind::everything());
        inner.disks.refresh(true);
        inner.networks.refresh(true);

        let cpu = CpuUsage {
            cores: inner.system.cpus().len() as u32,
            usage_pct: round1(inner.system.global_cpu_usage()),
        };

        let memory = MemoryUsage {
            total_bytes: inner.system.total_memory(),
            // `used_memory` counts what applications hold; cache and buffers are
            // reclaimable and would otherwise make every Linux box look full.
            used_bytes: inner.system.used_memory(),
            available_bytes: inner.system.available_memory(),
            swap_total_bytes: inner.system.total_swap(),
            swap_used_bytes: inner.system.used_swap(),
        };

        let disks = inner
            .disks
            .list()
            .iter()
            .filter(|d| {
                // Pseudo and loop filesystems are noise on a dashboard.
                let fs = d.file_system().to_string_lossy().to_ascii_lowercase();
                !matches!(
                    fs.as_str(),
                    "tmpfs" | "devtmpfs" | "squashfs" | "overlay" | "ramfs"
                ) && d.total_space() > 0
            })
            .map(|d| DiskUsage {
                mount: d.mount_point().to_string_lossy().into_owned(),
                filesystem: d.file_system().to_string_lossy().into_owned(),
                total_bytes: d.total_space(),
                used_bytes: d.total_space().saturating_sub(d.available_space()),
                available_bytes: d.available_space(),
            })
            .collect::<Vec<_>>();

        let totals = inner.networks.list().values().fold(
            NetworkTotals {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_bytes_per_sec: 0,
                tx_bytes_per_sec: 0,
            },
            |mut acc, data| {
                acc.rx_bytes = acc.rx_bytes.saturating_add(data.total_received());
                acc.tx_bytes = acc.tx_bytes.saturating_add(data.total_transmitted());
                acc
            },
        );
        let network = derive_rates(&mut inner.last_net, now, totals);

        let load = System::load_average();
        let snapshot = ServerSnapshot {
            at: time::OffsetDateTime::now_utc(),
            uptime_seconds: System::uptime(),
            load: LoadAverage {
                one: round2(load.one),
                five: round2(load.five),
                fifteen: round2(load.fifteen),
            },
            cpu,
            memory,
            disks,
            network,
            panel: PanelFootprint::default(),
        };

        inner.last_refresh = Some(now);
        inner.last_snapshot = Some(snapshot.clone());
        snapshot
    }

    /// Resident memory of the two panel processes — the number the CI budget
    /// check asserts against (spec §3).
    pub async fn panel_footprint(
        &self,
        web_pid: Option<u32>,
        agent_pid: Option<u32>,
    ) -> PanelFootprint {
        let mut inner = self.inner.lock().await;
        // Deduplicate: sysinfo refreshes nothing at all when the same pid appears
        // twice in the list, and the two pids are identical whenever the web
        // process and the agent are the same process (tests, `unihelm dev`).
        let mut pids: Vec<sysinfo::Pid> = [web_pid, agent_pid]
            .into_iter()
            .flatten()
            .map(sysinfo::Pid::from_u32)
            .collect();
        pids.sort_unstable();
        pids.dedup();

        if pids.is_empty() {
            return PanelFootprint::default();
        }

        inner.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&pids),
            true,
            ProcessRefreshKind::nothing().with_memory(),
        );

        let rss = |pid: Option<u32>| {
            pid.and_then(|p| inner.system.process(sysinfo::Pid::from_u32(p)))
                .map(|p| p.memory())
        };

        let web = rss(web_pid);
        let agent = rss(agent_pid);
        PanelFootprint {
            web_rss_bytes: web,
            agent_rss_bytes: agent,
            total_rss_bytes: match (web, agent) {
                (None, None) => None,
                (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
            },
        }
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

/// Turn cumulative byte counters into per-second rates.
fn derive_rates(
    last: &mut Option<(Instant, NetworkTotals)>,
    now: Instant,
    mut totals: NetworkTotals,
) -> NetworkTotals {
    if let Some((prev_at, prev)) = last.as_ref() {
        let elapsed = now.saturating_duration_since(*prev_at).as_secs_f64();
        if elapsed > 0.01 {
            // Counters reset when an interface disappears or the box reboots;
            // `saturating_sub` turns that into a zero rate rather than a spike.
            totals.rx_bytes_per_sec =
                ((totals.rx_bytes.saturating_sub(prev.rx_bytes)) as f64 / elapsed) as u64;
            totals.tx_bytes_per_sec =
                ((totals.tx_bytes.saturating_sub(prev.tx_bytes)) as f64 / elapsed) as u64;
        }
    }
    *last = Some((
        now,
        NetworkTotals {
            rx_bytes_per_sec: 0,
            tx_bytes_per_sec: 0,
            ..totals
        },
    ));
    totals
}

fn round1(v: f32) -> f32 {
    (v * 10.0).round() / 10.0
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_snapshot_reports_plausible_numbers() {
        let c = Collector::new();
        let s = c.snapshot().await;

        assert!(s.cpu.cores >= 1, "a machine has at least one core");
        assert!((0.0..=100.0 * s.cpu.cores as f32).contains(&s.cpu.usage_pct));
        assert!(s.memory.total_bytes > 0);
        assert!(s.memory.used_bytes <= s.memory.total_bytes);
        assert!(s.uptime_seconds > 0);
        assert!(s.load.one >= 0.0);
    }

    #[tokio::test]
    async fn disks_exclude_pseudo_filesystems_and_report_consistent_totals() {
        let c = Collector::new();
        let s = c.snapshot().await;
        for d in &s.disks {
            assert!(d.total_bytes > 0, "{} reported no capacity", d.mount);
            assert!(
                d.used_bytes <= d.total_bytes,
                "{} used more than it has",
                d.mount
            );
            assert!(!d.filesystem.eq_ignore_ascii_case("tmpfs"));
            assert!(d.used_pct() <= 100.0);
        }
    }

    #[tokio::test]
    async fn repeated_calls_inside_the_window_are_served_from_cache() {
        let c = Collector::new();
        let a = c.snapshot().await;
        let b = c.snapshot().await;
        // The cached snapshot is returned verbatim, so the timestamps match.
        assert_eq!(
            a.at, b.at,
            "back-to-back snapshots must not each sweep /proc"
        );
    }

    #[test]
    fn rates_are_derived_from_the_delta_not_the_total() {
        let mut last = None;
        let t0 = Instant::now();
        let first = derive_rates(
            &mut last,
            t0,
            NetworkTotals {
                rx_bytes: 1_000,
                tx_bytes: 500,
                rx_bytes_per_sec: 0,
                tx_bytes_per_sec: 0,
            },
        );
        assert_eq!(
            first.rx_bytes_per_sec, 0,
            "the first sample has nothing to diff against"
        );

        let second = derive_rates(
            &mut last,
            t0 + Duration::from_secs(2),
            NetworkTotals {
                rx_bytes: 3_000,
                tx_bytes: 900,
                rx_bytes_per_sec: 0,
                tx_bytes_per_sec: 0,
            },
        );
        assert_eq!(second.rx_bytes_per_sec, 1_000);
        assert_eq!(second.tx_bytes_per_sec, 200);
    }

    #[test]
    fn a_counter_reset_produces_zero_not_a_spike() {
        let mut last = None;
        let t0 = Instant::now();
        derive_rates(
            &mut last,
            t0,
            NetworkTotals {
                rx_bytes: 10_000,
                tx_bytes: 10_000,
                rx_bytes_per_sec: 0,
                tx_bytes_per_sec: 0,
            },
        );
        // Interface reappeared with fresh counters.
        let after = derive_rates(
            &mut last,
            t0 + Duration::from_secs(1),
            NetworkTotals {
                rx_bytes: 5,
                tx_bytes: 5,
                rx_bytes_per_sec: 0,
                tx_bytes_per_sec: 0,
            },
        );
        assert_eq!(after.rx_bytes_per_sec, 0);
        assert_eq!(after.tx_bytes_per_sec, 0);
    }

    #[tokio::test]
    async fn our_own_process_has_a_measurable_footprint() {
        let c = Collector::new();
        let me = std::process::id();
        let fp = c.panel_footprint(Some(me), None).await;
        assert!(
            fp.web_rss_bytes.unwrap_or(0) > 0,
            "should be able to read our own RSS"
        );
        assert_eq!(fp.agent_rss_bytes, None);
        assert_eq!(fp.total_rss_bytes, fp.web_rss_bytes);
    }

    #[tokio::test]
    async fn the_same_pid_twice_still_reports_memory() {
        // Regression: passing a duplicated pid made sysinfo refresh nothing, so
        // the footprint came back empty and the budget check silently passed.
        let c = Collector::new();
        let me = std::process::id();
        let fp = c.panel_footprint(Some(me), Some(me)).await;
        assert!(fp.web_rss_bytes.unwrap_or(0) > 0);
        assert!(fp.agent_rss_bytes.unwrap_or(0) > 0);
        assert!(fp.total_rss_bytes.unwrap_or(0) > 0);
    }

    #[tokio::test]
    async fn footprint_of_nothing_is_none_not_zero() {
        let c = Collector::new();
        let fp = c.panel_footprint(None, None).await;
        assert_eq!(
            fp.total_rss_bytes, None,
            "unknown must be distinguishable from 0 bytes"
        );
    }
}
