//! Plans, quotas and the reseller allocation math (spec §6.2).
//!
//! A plan is a named bundle of *limits* (numbers the OS or the panel enforces)
//! and *features* (capabilities that switch permissions on and off). A reseller
//! additionally has an **allocation**: the same shape, acting as a ceiling on the
//! sum of everything it has provisioned.

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, Result, UnihelmError};
use crate::newtypes::PhpVersion;
use crate::rbac::Permission;

/// A quota value. `None` means unlimited — only an admin-owned plan should
/// normally carry one.
pub type Limit = Option<u64>;

/// Add two limits, where unlimited absorbs everything.
fn add(a: Limit, b: Limit) -> Limit {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.saturating_add(y)),
        _ => None,
    }
}

/// Is `value` within `ceiling`? Unlimited fits only inside unlimited.
fn fits(value: Limit, ceiling: Limit) -> bool {
    match (value, ceiling) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(v), Some(c)) => v <= c,
    }
}

/// The numeric half of a plan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PlanLimits {
    pub disk_mb: Limit,
    pub inode_count: Limit,
    pub monthly_bandwidth_mb: Limit,
    pub site_count: Limit,
    pub db_count: Limit,
    /// Reserved for Phase 5; carried now so plans do not need a migration later.
    pub mailbox_count: Limit,
    pub cron_count: Limit,
    pub nodejs_app_count: Limit,
    pub php_workers_max: Limit,
    /// cgroup `MemoryMax` for the tenant slice.
    pub memory_mb: Limit,
    /// cgroup `CPUQuota`, in percent of one core (200 = two full cores).
    pub cpu_pct: Limit,
    pub backup_quota_mb: Limit,
}

/// Every field, so `sum`/`fits_within` can never silently miss one.
macro_rules! for_each_limit {
    ($mac:ident) => {
        $mac!(disk_mb, "disk");
        $mac!(inode_count, "inodes");
        $mac!(monthly_bandwidth_mb, "bandwidth");
        $mac!(site_count, "sites");
        $mac!(db_count, "databases");
        $mac!(mailbox_count, "mailboxes");
        $mac!(cron_count, "cron jobs");
        $mac!(nodejs_app_count, "node apps");
        $mac!(php_workers_max, "php workers");
        $mac!(memory_mb, "memory");
        $mac!(cpu_pct, "cpu");
        $mac!(backup_quota_mb, "backup quota");
    };
}

impl PlanLimits {
    /// Aggregate two limit sets — used to total a reseller's provisioned plans.
    pub fn plus(&self, other: &Self) -> Self {
        macro_rules! f {
            ($field:ident, $label:expr) => {};
        }
        for_each_limit!(f);
        Self {
            disk_mb: add(self.disk_mb, other.disk_mb),
            inode_count: add(self.inode_count, other.inode_count),
            monthly_bandwidth_mb: add(self.monthly_bandwidth_mb, other.monthly_bandwidth_mb),
            site_count: add(self.site_count, other.site_count),
            db_count: add(self.db_count, other.db_count),
            mailbox_count: add(self.mailbox_count, other.mailbox_count),
            cron_count: add(self.cron_count, other.cron_count),
            nodejs_app_count: add(self.nodejs_app_count, other.nodejs_app_count),
            php_workers_max: add(self.php_workers_max, other.php_workers_max),
            memory_mb: add(self.memory_mb, other.memory_mb),
            cpu_pct: add(self.cpu_pct, other.cpu_pct),
            backup_quota_mb: add(self.backup_quota_mb, other.backup_quota_mb),
        }
    }

    /// Check every field against a ceiling, naming the first field that overflows.
    pub fn fits_within(&self, ceiling: &Self) -> Result<()> {
        macro_rules! check {
            ($field:ident, $label:expr) => {
                if !fits(self.$field, ceiling.$field) {
                    return Err(UnihelmError::new(
                        ErrorCode::ResellerAllocationExceeded,
                        format!(
                            "{} would exceed the allocation ({} requested, {} available)",
                            $label,
                            self.$field
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "unlimited".into()),
                            ceiling
                                .$field
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "unlimited".into()),
                        ),
                    )
                    .with_field(stringify!($field)));
                }
            };
        }
        for_each_limit!(check);
        Ok(())
    }

    /// Would adding `candidate` to `already_used` still fit inside `ceiling`?
    ///
    /// This is the check run when a reseller assigns a plan to a new customer,
    /// and again by the nightly reconciliation report.
    pub fn assignment_fits(already_used: &Self, candidate: &Self, ceiling: &Self) -> Result<()> {
        already_used.plus(candidate).fits_within(ceiling)
    }
}

/// The capability half of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PlanFeatures {
    pub can_ssh: bool,
    pub can_docker_apps: bool,
    pub can_node_apps: bool,
    pub can_cron: bool,
    pub can_backups: bool,
    pub can_manage_dns: bool,
    /// Empty means "every version the server has installed".
    pub allowed_php_versions: Vec<PhpVersion>,
}

impl Default for PlanFeatures {
    fn default() -> Self {
        Self {
            can_ssh: false,
            can_docker_apps: false,
            can_node_apps: false,
            can_cron: true,
            can_backups: true,
            can_manage_dns: false,
            allowed_php_versions: Vec::new(),
        }
    }
}

impl PlanFeatures {
    /// Permissions to strip from an actor's context because the plan disables
    /// them. Feeds [`crate::rbac::AuthContext::revoke`].
    pub fn denied_permissions(&self) -> Vec<Permission> {
        let mut denied = Vec::new();
        if !self.can_ssh {
            denied.push(Permission::SshAccess);
            denied.push(Permission::TerminalAccess);
        }
        if !self.can_docker_apps {
            denied.push(Permission::DockerApps);
        }
        if !self.can_node_apps {
            denied.push(Permission::NodeApps);
        }
        if !self.can_cron {
            denied.push(Permission::CronManage);
        }
        if !self.can_backups {
            denied.push(Permission::BackupManage);
        }
        if !self.can_manage_dns {
            denied.push(Permission::DnsManage);
        }
        denied
    }

    pub fn allows_php(&self, v: PhpVersion) -> bool {
        self.allowed_php_versions.is_empty() || self.allowed_php_versions.contains(&v)
    }
}

/// Current consumption against a plan, for the quota bars in the UI and for the
/// pre-flight check before a create operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaUsage {
    pub disk_mb: u64,
    pub inode_count: u64,
    pub monthly_bandwidth_mb: u64,
    pub site_count: u64,
    pub db_count: u64,
    pub cron_count: u64,
    pub nodejs_app_count: u64,
    pub backup_mb: u64,
}

impl QuotaUsage {
    /// Refuse an operation that would push a counted resource over its limit.
    pub fn check_headroom(&self, limits: &PlanLimits, what: CountedResource) -> Result<()> {
        let (used, limit, label) = match what {
            CountedResource::Site => (self.site_count, limits.site_count, "sites"),
            CountedResource::Database => (self.db_count, limits.db_count, "databases"),
            CountedResource::CronJob => (self.cron_count, limits.cron_count, "cron jobs"),
            CountedResource::NodeApp => {
                (self.nodejs_app_count, limits.nodejs_app_count, "node apps")
            }
        };
        match limit {
            None => Ok(()),
            Some(max) if used < max => Ok(()),
            Some(max) => Err(UnihelmError::new(
                ErrorCode::QuotaExceeded,
                format!("plan allows {max} {label}; {used} already in use"),
            )),
        }
    }
}

/// Resources whose count is capped by a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountedResource {
    Site,
    Database,
    CronJob,
    NodeApp,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(disk: Option<u64>, sites: Option<u64>) -> PlanLimits {
        PlanLimits {
            disk_mb: disk,
            site_count: sites,
            ..Default::default()
        }
    }

    #[test]
    fn unlimited_absorbs_in_sums() {
        let a = limits(Some(1000), Some(5));
        let b = limits(None, Some(3));
        let sum = a.plus(&b);
        assert_eq!(sum.disk_mb, None);
        assert_eq!(sum.site_count, Some(8));
    }

    #[test]
    fn unlimited_does_not_fit_in_a_finite_ceiling() {
        let plan = limits(None, Some(1));
        let ceiling = limits(Some(10_000), Some(100));
        let e = plan.fits_within(&ceiling).unwrap_err();
        assert_eq!(e.code, ErrorCode::ResellerAllocationExceeded);
        assert_eq!(e.field.as_deref(), Some("disk_mb"));
    }

    #[test]
    fn anything_fits_in_an_unlimited_ceiling() {
        assert!(
            limits(None, None)
                .fits_within(&PlanLimits::default())
                .is_ok()
        );
    }

    #[test]
    fn reseller_assignment_math() {
        let ceiling = limits(Some(10_000), Some(20));
        let used = limits(Some(9_000), Some(18));
        // Fits exactly.
        assert!(
            PlanLimits::assignment_fits(&used, &limits(Some(1_000), Some(2)), &ceiling).is_ok()
        );
        // One megabyte over.
        let e = PlanLimits::assignment_fits(&used, &limits(Some(1_001), Some(1)), &ceiling)
            .unwrap_err();
        assert_eq!(e.field.as_deref(), Some("disk_mb"));
    }

    #[test]
    fn saturating_sum_does_not_panic() {
        let huge = limits(Some(u64::MAX), None);
        assert_eq!(huge.plus(&huge).disk_mb, Some(u64::MAX));
    }

    #[test]
    fn quota_headroom() {
        let l = limits(None, Some(2));
        let mut usage = QuotaUsage {
            site_count: 1,
            ..Default::default()
        };
        assert!(usage.check_headroom(&l, CountedResource::Site).is_ok());
        usage.site_count = 2;
        let e = usage.check_headroom(&l, CountedResource::Site).unwrap_err();
        assert_eq!(e.code, ErrorCode::QuotaExceeded);
        // An unset limit means unlimited, not zero.
        assert!(usage.check_headroom(&l, CountedResource::Database).is_ok());
    }

    #[test]
    fn default_features_are_conservative() {
        let f = PlanFeatures::default();
        assert!(!f.can_ssh, "shell access must be opt-in");
        assert!(!f.can_docker_apps);
        let denied = f.denied_permissions();
        assert!(denied.contains(&Permission::SshAccess));
        assert!(denied.contains(&Permission::TerminalAccess));
        assert!(!denied.contains(&Permission::CronManage));
    }

    #[test]
    fn php_allowlist_empty_means_all() {
        let mut f = PlanFeatures::default();
        assert!(f.allows_php(PhpVersion::V83));
        f.allowed_php_versions = vec![PhpVersion::V83, PhpVersion::V84];
        assert!(f.allows_php(PhpVersion::V83));
        assert!(!f.allows_php(PhpVersion::V74));
    }
}
