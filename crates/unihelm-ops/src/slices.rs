//! Per-tenant resource limits via systemd slices (spec §6.3).
//!
//! Every customer subscription gets one slice unit, `unihelm-<user>.slice`,
//! written to `/etc/systemd/system` through the config engine like every other
//! file the panel owns. systemd materialises the slice as a cgroup the moment
//! any unit joins it, and the `[Slice]` directives become that cgroup's
//! controller files: `MemoryMax` → `memory.max`, `CPUQuota` → `cpu.max`,
//! `TasksMax` → `pids.max`, `IOWeight` → `io.weight`. From then on the *kernel*
//! enforces the plan — the panel's only job is keeping the unit file truthful.
//! cgroups v2 is an install precondition (spec §7.1: the preflight refuses v1
//! systems), so there is exactly one hierarchy and one set of semantics.
//!
//! In slice unit names every `-` is a nesting level, so `unihelm-uh_ab.slice`
//! automatically sits under an implicit `unihelm.slice` that systemd creates on
//! its own. That gives an operator a single handle on *all* tenants at once
//! (`systemd-cgtop`, or a future `unihelm.slice` unit capping the lot) without
//! this module writing a parent unit.
//!
//! # What joins the slice — and the two exceptions
//!
//! Per-tenant units join by carrying `Slice=unihelm-<user>.slice`: Node app
//! services (spec §11.6) via the drop-in [`apply_unit_slice_dropin`] writes,
//! and quota'd shell sessions later via pam_systemd wiring. The slice exists
//! from the moment the tenant account does, so those features land into a
//! ceiling that is already standing.
//!
//! **Tenant cron jobs do not join the slice** (spec §11.8), and an earlier
//! version of this comment claimed they would by passing `--slice` to
//! `systemd-run`. They cannot, and the reason is worth stating plainly rather
//! than leaving as an aspiration:
//!
//! - A crontab line is executed **by cron, as the tenant**. Whatever wrapper
//!   the line names therefore also runs unprivileged, and an unprivileged
//!   process may not place itself into a *system* slice: `systemd-run --uid=…
//!   --slice=unihelm-<user>.slice` is a privileged operation, and
//!   `systemd-run --user` lands in `user-<uid>.slice`, which is a different
//!   cgroup with none of this module's limits on it.
//! - Prefixing the line with a wrapper would also mean quoting the tenant's
//!   command back into a single shell word so the wrapper could pass it on —
//!   i.e. building a shell string out of tenant input, which is the one thing
//!   this codebase does not do (spec §12 rule 2).
//!
//! So the jobs run in `cron.service`'s own cgroup, under `system.slice`, and a
//! runaway tenant cron job is bounded by the server rather than by the plan.
//! The fix is not a cleverer crontab line: it is to stop using crontab for
//! tenant jobs and render each one as a systemd timer + service pair written by
//! the (root) agent, where `Slice=` and `User=` are ordinary unit directives
//! and the command is an argv array. `unihelm_ops::cron` renders from the
//! database precisely so that swap changes the renderer and nothing else.
//!
//! **PHP-FPM pools cannot join the slice, and this module does not pretend
//! otherwise.** All pools of one PHP version are children of that version's
//! single FPM master (`php8.3-fpm.service`), and systemd places a unit's
//! processes — every fork included — in *that unit's* cgroup. `Slice=` is
//! per unit, not per pool, so putting one tenant's pool in their slice would
//! mean putting the shared master (and with it every tenant on that PHP
//! version) there. Migrating individual workers by writing their PIDs into the
//! tenant cgroup would violate systemd's single-writer ownership of the tree
//! and be silently undone on the next daemon-reload. Until tenants get
//! per-tenant FPM masters (a Phase 2+ option), a tenant's PHP memory is bounded
//! the way FPM itself bounds it: `pm.max_children × memory_limit` in the pool
//! file, both derived from the same tenant memory budget this module owns —
//! see [`TenantSlice::fpm_pool_memory_mb`].

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_config::apply::{ApplyOutcome, ApplyRequest, Reloader, Validator, managed_for};
use unihelm_config::paths;
use unihelm_core::{ErrorCode, LinuxUser, Result, UnihelmError};
use unihelm_distro::svc::{SvcAction, UnitName};
use unihelm_distro::{Cmd, Distro};

use crate::registry::OpContext;
use crate::services::SkipValidation;

/// The tenant memory budget used until plans arrive (spec §6.2 `memory_mb`).
///
/// This is a *sizing input*, not an enforced cap: it feeds
/// [`TenantSlice::fpm_pool_memory_mb`] and through it `pm.max_children`, so the
/// FPM pool of a plan-less tenant is dimensioned for half a gigabyte rather
/// than for whatever the server happens to have.
pub const DEFAULT_TENANT_MEMORY_MB: u32 = 512;

/// The serialisation key every systemd unit write shares, so two concurrent
/// slice writes cannot interleave their validate/daemon-reload sequences.
const SYSTEMD_SERVICE: &str = "systemd";

/// The drop-in file name used for slice assignment. One fixed name per unit:
/// re-assigning a unit to another tenant's slice overwrites it rather than
/// accumulating contradictory drop-ins systemd would resolve by sort order.
const SLICE_DROPIN: &str = "unihelm-slice.conf";

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

/// One tenant's resource ceiling, straight from the plan fields (spec §6.2:
/// `memory_mb`, `cpu_pct`; §6.3: `MemoryMax`, `CPUQuota`, `TasksMax`).
///
/// Every field is optional because "no limit" is a legitimate plan value, and
/// rendering an absent limit as *nothing* (rather than as some huge number)
/// keeps the unit file readable to the operator who cats it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantSlice {
    /// Hard memory cap in MiB (`MemoryMax`). The kernel OOM-kills inside the
    /// slice when it is hit — the tenant's process dies, not the server's.
    pub memory_max_mb: Option<u32>,
    /// Percent of a single CPU (`CPUQuota`): 200 means two full cores.
    pub cpu_quota_pct: Option<u32>,
    /// Fork-bomb ceiling (`TasksMax` → `pids.max`).
    pub pids_max: Option<u32>,
    /// Proportional IO weight 1–10000, default 100 (`IOWeight`). Not a cap:
    /// it only bites while the disk is contended.
    pub io_weight: Option<u32>,
}

impl Default for TenantSlice {
    /// No ceilings — the slice exists, accounts, and waits for a plan.
    ///
    /// Deliberate: wave 1 has no plans yet (spec §6.2 lands with the plans
    /// module), and a cap invented here would be wrong for somebody. An
    /// unlimited slice still buys real things — per-tenant usage counters, and
    /// a standing unit that future Node/cron work joins — while an invented
    /// `MemoryMax` could OOM a legitimate site the day the first Node app
    /// deploys into it.
    fn default() -> Self {
        Self {
            memory_max_mb: None,
            cpu_quota_pct: None,
            pids_max: None,
            io_weight: None,
        }
    }
}

impl TenantSlice {
    /// The memory budget the tenant's FPM pools should be sized for.
    ///
    /// This is the honest half of PHP enforcement (see the module docs for why
    /// the slice itself cannot hold FPM workers): `PoolContext::new` divides
    /// this budget by the per-worker `memory_limit` to derive
    /// `pm.max_children`, so a 512 MB tenant gets 4 workers, not 50.
    pub fn fpm_pool_memory_mb(&self) -> u32 {
        self.memory_max_mb.unwrap_or(DEFAULT_TENANT_MEMORY_MB)
    }

    /// One line for the task log, so "what did this actually set?" is
    /// answerable from the task history rather than by catting the unit.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(mb) = self.memory_max_mb {
            parts.push(format!("memory {mb} MB"));
        }
        if let Some(pct) = self.cpu_quota_pct {
            parts.push(format!("cpu {pct}%"));
        }
        if let Some(pids) = self.pids_max {
            parts.push(format!("pids {pids}"));
        }
        if let Some(w) = self.io_weight {
            parts.push(format!("io weight {w}"));
        }
        if parts.is_empty() {
            "no limits (accounting only)".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// What `systemd/tenant.slice` renders from. Clamped, never raw: a plan edit
/// of `io_weight = 0` must become a valid unit, not a file systemd refuses —
/// which, written and daemon-reloaded, would leave the tenant with *no* limits.
#[derive(Debug, Serialize)]
struct SliceContext {
    linux_user: String,
    memory_max_mb: Option<u32>,
    /// 90% of the cap: reclaim-and-throttle before the OOM kill.
    memory_high_mb: Option<u32>,
    cpu_quota_pct: Option<u32>,
    pids_max: Option<u32>,
    io_weight: Option<u32>,
}

impl SliceContext {
    fn new(user: &LinuxUser, limits: &TenantSlice) -> Self {
        // Floors and ranges are systemd's and the kernel's, not taste:
        // IOWeight is documented 1..10000; CPUQuota=0% is rejected; a slice
        // whose memory.max is below a few MB cannot start any process at all.
        let memory_max_mb = limits.memory_max_mb.map(|mb| mb.max(32));
        Self {
            linux_user: user.as_str().to_string(),
            memory_max_mb,
            memory_high_mb: memory_max_mb.map(|mb| (mb * 9 / 10).max(16)),
            cpu_quota_pct: limits.cpu_quota_pct.map(|p| p.clamp(1, 10_000)),
            pids_max: limits.pids_max.map(|p| p.max(8)),
            io_weight: limits.io_weight.map(|w| w.clamp(1, 10_000)),
        }
    }
}

// ---------------------------------------------------------------------------
// Names and paths
// ---------------------------------------------------------------------------

/// The tenant's slice unit file name: `unihelm-<user>.slice`.
///
/// Hyphens in the user are escaped to `\x2d` (systemd's own escaping) because
/// in *slice* names a `-` is a nesting separator: `unihelm-a-b.slice` would be
/// a grandchild slice `unihelm.slice/unihelm-a.slice/unihelm-a-b.slice`, and two
/// tenants `a` and `a-b` would end up with one nested inside the other's
/// accounting. Escaped, every tenant is exactly one level under
/// `unihelm.slice`, siblings, whatever their names.
pub fn slice_file_name(user: &LinuxUser) -> String {
    format!("unihelm-{}.slice", user.as_str().replace('-', "\\x2d"))
}

/// The same, as a validated [`UnitName`] for the svc backend.
pub fn slice_unit_name(user: &LinuxUser) -> UnitName {
    // Infallible for any parsed LinuxUser: its alphabet is [a-z0-9_-], 1-32
    // chars, and after escaping the result is within UnitName's alphabet and
    // length. The test `every_valid_linux_user_yields_a_valid_unit_name`
    // pins this reasoning down.
    UnitName::parse(&slice_file_name(user))
        .expect("a validated LinuxUser always escapes to a valid unit name")
}

/// Where the slice unit lives: `/etc/systemd/system/unihelm-<user>.slice`.
pub fn slice_unit_path(user: &LinuxUser) -> PathBuf {
    paths::systemd_unit(&slice_file_name(user))
}

// ---------------------------------------------------------------------------
// Validator and reloader
// ---------------------------------------------------------------------------

/// `systemd-analyze verify` against the freshly written unit file.
///
/// Where the binary is absent — minimal containers, a developer's laptop —
/// this degrades to [`SkipValidation`] semantics deliberately: an unverifiable
/// unit is a smaller risk than refusing to provision tenants on a machine
/// that merely lacks a diagnostic tool, and unlike nginx a bad slice file
/// cannot take running services down — systemd rejects it in isolation.
struct SliceVerify<'a> {
    path: &'a Path,
}

#[async_trait]
impl Validator for SliceVerify<'_> {
    fn name(&self) -> &'static str {
        "systemd-analyze verify"
    }

    async fn validate(&self) -> std::result::Result<(), String> {
        if !unihelm_distro::exec::program_available("systemd-analyze") {
            return Ok(());
        }
        match Cmd::new("systemd-analyze")
            .args(["verify", "--"])
            .arg(self.path)
            .run()
            .await
        {
            Ok(out) if out.success() => Ok(()),
            // The tool's own words, verbatim — same policy as `nginx -t`.
            Ok(out) => Err(out.failure_text()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// `systemctl daemon-reload`, as the config engine's activation step.
///
/// A slice has no process to signal; daemon-reload makes systemd re-read the
/// unit and re-realise the slice's cgroup, so changed limits reach a *running*
/// tenant without restarting anything inside it.
struct DaemonReload<'a> {
    distro: &'a Distro,
}

#[async_trait]
impl Reloader for DaemonReload<'_> {
    fn name(&self) -> &'static str {
        "systemctl daemon-reload"
    }

    async fn reload(&self) -> std::result::Result<(), String> {
        self.distro
            .svc
            .daemon_reload()
            .await
            .map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Apply / remove
// ---------------------------------------------------------------------------

/// Write (or update) the tenant's slice unit and make systemd load it.
///
/// Idempotent and convergent: re-applying identical limits is a no-op in the
/// config engine (no write, no daemon-reload), so this is safe to call on
/// every provisioning pass the way [`crate::provision::ensure_tenant_user`]
/// does. A unit file at this path that the panel did not write is refused,
/// never overwritten — same contract as every other managed file.
pub async fn apply_tenant_slice(
    ctx: &OpContext,
    user: &LinuxUser,
    limits: &TenantSlice,
) -> Result<ApplyOutcome> {
    apply_tenant_slice_at(ctx, &slice_unit_path(user), user, limits).await
}

/// The same, against an explicit path.
///
/// Split out so tests can run in a temporary directory: `paths::set_root` is a
/// process-wide `OnceLock`, which a parallel test binary cannot use to give
/// each test its own tree (same reasoning as `fpm::retire_stock_pool_in`).
pub async fn apply_tenant_slice_at(
    ctx: &OpContext,
    path: &Path,
    user: &LinuxUser,
    limits: &TenantSlice,
) -> Result<ApplyOutcome> {
    let outcome = ctx
        .config()
        .apply(ApplyRequest {
            file: managed_for(path),
            template: "systemd/tenant.slice",
            context: serde_json::json!({ "slice": SliceContext::new(user, limits) }),
            service: SYSTEMD_SERVICE,
            validator: &SliceVerify { path },
            reloader: &DaemonReload {
                distro: ctx.distro(),
            },
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await
        .map_err(UnihelmError::from)?;

    if outcome.changed {
        ctx.log(format!(
            "slice {} enforces: {}",
            slice_unit_name(user),
            limits.describe()
        ));
    }
    Ok(outcome)
}

/// Remove the tenant's slice on subscription/user teardown.
///
/// Returns whether anything was actually removed, and is idempotent — tearing
/// down a tenant whose slice is already gone (or was never written) is not an
/// error, because teardown tasks get retried.
///
/// The slice is *stopped* first: stopping a slice kills every process still in
/// its cgroup, which is exactly what deleting a tenant needs — an orphaned
/// Node app must not keep serving after its owner is gone (spec §6.4 makes
/// stop-the-slice the suspension mechanic; deletion is its terminal form).
/// This is precisely why it must **not** be called from single-site deletion:
/// the tenant's other sites and apps live in the same slice.
pub async fn remove_tenant_slice(ctx: &OpContext, user: &LinuxUser) -> Result<bool> {
    remove_tenant_slice_at(ctx, &slice_unit_path(user), user).await
}

/// The same, against an explicit path (test seam, as for apply).
pub async fn remove_tenant_slice_at(
    ctx: &OpContext,
    path: &Path,
    user: &LinuxUser,
) -> Result<bool> {
    let unit = slice_unit_name(user);
    let distro = ctx.distro();

    // Stop only what is actually running; asking systemd to stop a unit it
    // never loaded would fail the teardown for nothing.
    let status = distro.svc.status(&unit).await.map_err(UnihelmError::from)?;
    if status.is_installed() && status.is_active() {
        distro
            .svc
            .action(&unit, SvcAction::Stop)
            .await
            .map_err(UnihelmError::from)?;
        ctx.log(format!("stopped {unit}; its remaining processes are gone"));
    }

    // Validation is skipped on removal: there is no file left to verify, and
    // systemd is indifferent to a unit disappearing — the daemon-reload just
    // unloads it.
    let removed = ctx
        .config()
        .remove(
            &managed_for(path),
            SYSTEMD_SERVICE,
            &SkipValidation,
            &DaemonReload { distro },
        )
        .await
        .map_err(UnihelmError::from)?;

    if removed {
        // The unit is gone; keeping revisions for it would offer the UI a
        // "restore" onto a tenant that no longer exists.
        let _ = ctx.db().forget_revisions(&path.to_string_lossy()).await;
        ctx.log(format!("removed {unit}"));
    }
    Ok(removed)
}

/// Write the drop-in that lands a per-tenant service in the tenant's slice.
///
/// For the future units of spec §6.3's table — Node app services, workers —
/// which are created by their own modules but must live inside the ceiling
/// this module owns. Only `unihelm-*.service` units are accepted: a drop-in on
/// a *shared* daemon (nginx, an FPM master) would drag every tenant it serves
/// into one tenant's slice, which is the exact opposite of isolation.
pub async fn apply_unit_slice_dropin(
    ctx: &OpContext,
    unit: &UnitName,
    user: &LinuxUser,
) -> Result<ApplyOutcome> {
    let path = paths::systemd_dropin(unit.as_str(), SLICE_DROPIN);
    apply_unit_slice_dropin_at(ctx, &path, unit, user).await
}

/// The same, against an explicit path (test seam, as for apply).
pub async fn apply_unit_slice_dropin_at(
    ctx: &OpContext,
    path: &Path,
    unit: &UnitName,
    user: &LinuxUser,
) -> Result<ApplyOutcome> {
    if !unit.as_str().ends_with(".service") {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!("`{unit}` is not a service; only services take a [Service] slice drop-in"),
        ));
    }
    if !unit.as_str().starts_with("unihelm-") {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!(
                "refusing to move `{unit}` into a tenant slice: only the panel's own \
                 per-tenant units (unihelm-*) belong to a single tenant"
            ),
        ));
    }

    // No validator here even where systemd-analyze exists: the drop-in is
    // legitimately written *before* the unit it decorates (the slice
    // assignment must be in place when the unit first starts), and verifying a
    // unit that does not exist yet fails for reasons unrelated to the drop-in.
    ctx.config()
        .apply(ApplyRequest {
            file: managed_for(path),
            template: "systemd/tenant-dropin.conf",
            context: serde_json::json!({
                "dropin": { "slice_unit": slice_file_name(user) }
            }),
            service: SYSTEMD_SERVICE,
            validator: &SkipValidation,
            reloader: &DaemonReload {
                distro: ctx.distro(),
            },
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await
        .map_err(UnihelmError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use unihelm_config::TemplateSet;
    use unihelm_core::{AuthContext, Role, TenantScope, UserId};
    use unihelm_distro::Family;
    use unihelm_distro::mock::{SharedRecorder, mock_distro_with_recorder};

    fn user() -> LinuxUser {
        LinuxUser::parse("uh_abc12345").unwrap()
    }

    fn render(limits: &TenantSlice) -> String {
        TemplateSet::load()
            .unwrap()
            .render(
                "systemd/tenant.slice",
                &serde_json::json!({ "slice": SliceContext::new(&user(), limits) }),
            )
            .unwrap()
    }

    /// An OpContext over a recorded mock distro and an in-memory database.
    ///
    /// Built directly rather than through `registry::testing::registry()`
    /// because these tests must see the recorder, and no dispatch (hence no
    /// auth verification) happens on the way to the functions under test.
    async fn ctx(family: Family) -> (OpContext, SharedRecorder) {
        let (distro, rec) = mock_distro_with_recorder(family);
        let db = unihelm_db::Db::open_memory().await.unwrap();
        let services = Arc::new(
            crate::registry::Services::new(distro, db, unihelm_db::MasterKey::generate())
                .expect("templates compile"),
        );
        let auth = AuthContext::from_role(UserId(1), Role::Admin, TenantScope::Global, "req-test");
        (OpContext::new(services, auth), rec)
    }

    // -- rendering ----------------------------------------------------------

    #[test]
    fn an_unlimited_slice_renders_accounting_and_nothing_else() {
        let body = render(&TenantSlice::default());
        assert_eq!(
            body,
            "[Unit]\n\
             Description=Unihelm tenant uh_abc12345 resource limits\n\
             \n\
             [Slice]\n\
             MemoryAccounting=yes\n\
             CPUAccounting=yes\n\
             TasksAccounting=yes\n\
             IOAccounting=yes\n"
        );
    }

    #[test]
    fn every_limit_renders_its_directive_and_only_when_set() {
        let body = render(&TenantSlice {
            memory_max_mb: Some(1024),
            cpu_quota_pct: Some(150),
            pids_max: Some(256),
            io_weight: Some(50),
        });
        assert!(body.contains("MemoryMax=1024M\n"), "{body}");
        assert!(
            body.contains("MemoryHigh=921M\n"),
            "the soft cap throttles at 90% before the OOM kill: {body}"
        );
        assert!(
            body.contains("MemorySwapMax=0\n"),
            "a cap that can swap is not a cap: {body}"
        );
        assert!(body.contains("CPUQuota=150%\n"), "{body}");
        assert!(body.contains("TasksMax=256\n"), "{body}");
        assert!(body.contains("IOWeight=50\n"), "{body}");

        // And a partial set leaves the others out entirely.
        let partial = render(&TenantSlice {
            memory_max_mb: None,
            cpu_quota_pct: None,
            pids_max: Some(256),
            io_weight: None,
        });
        for absent in [
            "MemoryMax",
            "MemoryHigh",
            "MemorySwapMax",
            "CPUQuota",
            "IOWeight",
        ] {
            assert!(
                !partial.contains(absent),
                "unexpected `{absent}` in {partial}"
            );
        }
        assert!(partial.contains("TasksMax=256\n"));
    }

    #[test]
    fn nonsense_limit_values_are_clamped_into_what_systemd_accepts() {
        // A plan edit of 0 must not render a unit systemd refuses to load —
        // written and reloaded, that would leave the tenant with NO limits.
        let body = render(&TenantSlice {
            memory_max_mb: Some(0),
            cpu_quota_pct: Some(0),
            pids_max: Some(0),
            io_weight: Some(999_999),
        });
        assert!(body.contains("MemoryMax=32M\n"), "{body}");
        assert!(body.contains("CPUQuota=1%\n"), "{body}");
        assert!(body.contains("TasksMax=8\n"), "{body}");
        assert!(body.contains("IOWeight=10000\n"), "{body}");
    }

    #[test]
    fn the_dropin_lands_a_unit_in_the_tenant_slice() {
        let body = TemplateSet::load()
            .unwrap()
            .render(
                "systemd/tenant-dropin.conf",
                &serde_json::json!({ "dropin": { "slice_unit": slice_file_name(&user()) } }),
            )
            .unwrap();
        assert_eq!(body, "[Service]\nSlice=unihelm-uh_abc12345.slice\n");
    }

    // -- naming -------------------------------------------------------------

    #[test]
    fn slice_names_follow_the_tenant_user() {
        assert_eq!(slice_file_name(&user()), "unihelm-uh_abc12345.slice");
        assert_eq!(
            slice_unit_name(&user()).as_str(),
            "unihelm-uh_abc12345.slice"
        );
    }

    #[test]
    fn a_hyphenated_user_is_escaped_not_nested() {
        // In slice names `-` is a hierarchy separator: unescaped, tenant `ab`
        // would contain tenant `ab-cd`'s cgroup inside its own accounting.
        let hyphenated = LinuxUser::parse("ab-cd").unwrap();
        assert_eq!(slice_file_name(&hyphenated), "unihelm-ab\\x2dcd.slice");
        assert!(UnitName::parse(&slice_file_name(&hyphenated)).is_ok());
    }

    #[test]
    fn every_valid_linux_user_yields_a_valid_unit_name() {
        // Pins the `expect` in slice_unit_name: the whole LinuxUser alphabet,
        // escaped, stays inside UnitName's alphabet and length budget.
        for name in ["a", "_x", "uh_abc12345", "a-b-c-d", "z_9-", &"a".repeat(32)] {
            let user = LinuxUser::parse(name).unwrap();
            let unit = slice_file_name(&user);
            assert!(UnitName::parse(&unit).is_ok(), "`{name}` produced `{unit}`");
        }
    }

    #[test]
    fn hostile_account_names_never_reach_a_unit_name() {
        // The validation lives in LinuxUser::parse — nothing unparsed can
        // reach slice_file_name. These are the classics that must die there.
        for hostile in [
            "../../etc/systemd/system/evil",
            "uh_a b",
            "uh_a\nExecStart=/bin/sh",
            "FT_UPPER",
            "root",
            "",
        ] {
            assert!(
                LinuxUser::parse(hostile).is_err(),
                "expected `{hostile}` to be rejected"
            );
        }
    }

    // -- fpm sizing ---------------------------------------------------------

    #[test]
    fn fpm_pool_sizing_follows_the_tenant_memory_budget() {
        // The PHP half of enforcement (module docs: FPM cannot join the
        // slice): the budget flows into PoolContext, which divides it by the
        // per-worker memory_limit to get pm.max_children.
        let capped = TenantSlice {
            memory_max_mb: Some(1024),
            ..TenantSlice::default()
        };
        let pool = unihelm_config::PoolContext::new(
            "example.com",
            "uh_abc12345",
            unihelm_core::PhpVersion::V83,
            capped.fpm_pool_memory_mb(),
            "nginx",
        );
        assert_eq!(pool.max_children, 8, "1024 MB / 128 MB per worker");

        // No plan yet → the documented default budget, not the server's RAM.
        assert_eq!(
            TenantSlice::default().fpm_pool_memory_mb(),
            DEFAULT_TENANT_MEMORY_MB
        );
    }

    // -- applying and removing ----------------------------------------------

    #[tokio::test]
    async fn applying_a_slice_writes_a_managed_unit_file() {
        let (ctx, _rec) = ctx(Family::Debian).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(slice_file_name(&user()));

        let outcome = apply_tenant_slice_at(&ctx, &path, &user(), &TenantSlice::default())
            .await
            .unwrap();
        assert!(outcome.changed);
        assert!(outcome.reloaded, "systemd must be told about the new unit");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk.starts_with("# UNIHELM-MANAGED"),
            "unit files carry the managed header (# is a comment to systemd): {on_disk}"
        );
        assert!(on_disk.contains("[Slice]"));
    }

    #[tokio::test]
    async fn reapplying_identical_limits_neither_writes_nor_reloads() {
        // ensure_tenant_user runs on every site creation; a daemon-reload per
        // page click is the churn the engine's hash check exists to prevent.
        let (ctx, _rec) = ctx(Family::Debian).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(slice_file_name(&user()));
        let limits = TenantSlice {
            memory_max_mb: Some(512),
            ..TenantSlice::default()
        };

        apply_tenant_slice_at(&ctx, &path, &user(), &limits)
            .await
            .unwrap();
        let again = apply_tenant_slice_at(&ctx, &path, &user(), &limits)
            .await
            .unwrap();
        assert!(!again.changed);
        assert!(!again.reloaded);
    }

    #[tokio::test]
    async fn a_foreign_unit_file_is_never_overwritten() {
        // An operator's hand-written unihelm-<user>.slice is *their* statement
        // about this tenant's limits; silently replacing it is how panels
        // lose trust. Same contract as every managed file.
        let (ctx, _rec) = ctx(Family::Debian).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(slice_file_name(&user()));
        std::fs::write(&path, "[Slice]\nMemoryMax=64M\n").unwrap();

        let err = apply_tenant_slice_at(&ctx, &path, &user(), &TenantSlice::default())
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigDrift);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[Slice]\nMemoryMax=64M\n",
            "the operator's file must be untouched"
        );
    }

    #[tokio::test]
    async fn removal_is_idempotent() {
        // Teardown tasks are retried; the second attempt must find nothing to
        // do and say so, not fail the retry.
        let (ctx, _rec) = ctx(Family::Debian).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(slice_file_name(&user()));

        apply_tenant_slice_at(&ctx, &path, &user(), &TenantSlice::default())
            .await
            .unwrap();

        assert!(remove_tenant_slice_at(&ctx, &path, &user()).await.unwrap());
        assert!(!path.exists());
        assert!(
            !remove_tenant_slice_at(&ctx, &path, &user()).await.unwrap(),
            "removing an already-removed slice is a no-op, not an error"
        );
        // And a tenant whose slice never existed at all.
        let never = dir.path().join("unihelm-uh_never.slice");
        assert!(!remove_tenant_slice_at(&ctx, &never, &user()).await.unwrap());
    }

    #[tokio::test]
    async fn removing_a_live_slice_stops_it_first() {
        // Stopping the slice kills every process still inside its cgroup — an
        // orphaned app must not keep serving after its tenant is deleted
        // (spec §6.4).
        let (ctx, rec) = ctx(Family::Debian).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(slice_file_name(&user()));
        let unit = slice_unit_name(&user());

        apply_tenant_slice_at(&ctx, &path, &user(), &TenantSlice::default())
            .await
            .unwrap();
        // Simulate a unit having joined the slice: the mock marks it running.
        ctx.distro()
            .svc
            .action(&unit, SvcAction::Start)
            .await
            .unwrap();

        remove_tenant_slice_at(&ctx, &path, &user()).await.unwrap();

        let actions = rec.lock().unwrap().service_actions.clone();
        assert!(
            actions.contains(&(unit.as_str().to_string(), SvcAction::Stop)),
            "a live slice must be stopped before its unit file goes: {actions:?}"
        );
    }

    #[tokio::test]
    async fn an_idle_slice_is_removed_without_a_stop() {
        let (ctx, rec) = ctx(Family::Debian).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(slice_file_name(&user()));

        apply_tenant_slice_at(&ctx, &path, &user(), &TenantSlice::default())
            .await
            .unwrap();
        remove_tenant_slice_at(&ctx, &path, &user()).await.unwrap();

        assert!(
            rec.lock().unwrap().service_actions.is_empty(),
            "stopping a unit systemd never loaded would fail the teardown for nothing"
        );
    }

    #[tokio::test]
    async fn a_service_dropin_lands_the_unit_in_the_tenant_slice() {
        let (ctx, _rec) = ctx(Family::Debian).await;
        let dir = tempfile::tempdir().unwrap();
        let unit = UnitName::parse("unihelm-app-blog-1.service").unwrap();
        let path = dir
            .path()
            .join(format!("{}.d", unit.as_str()))
            .join(SLICE_DROPIN);

        let outcome = apply_unit_slice_dropin_at(&ctx, &path, &unit, &user())
            .await
            .unwrap();
        assert!(outcome.changed);

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk.contains("[Service]\nSlice=unihelm-uh_abc12345.slice\n"),
            "{on_disk}"
        );
    }

    #[tokio::test]
    async fn a_dropin_is_refused_for_units_the_panel_does_not_own() {
        // Moving a shared daemon into one tenant's slice would put every
        // tenant it serves under that tenant's limits.
        let (ctx, _rec) = ctx(Family::Debian).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dropin.conf");

        for shared in ["nginx.service", "php8.3-fpm.service", "sshd.service"] {
            let unit = UnitName::parse(shared).unwrap();
            let err = apply_unit_slice_dropin_at(&ctx, &path, &unit, &user())
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{shared}");
        }
        // And non-service units, whose [Service] section would be ignored —
        // a drop-in that silently does nothing is worse than an error.
        let slice = UnitName::parse("unihelm-x.slice").unwrap();
        assert!(
            apply_unit_slice_dropin_at(&ctx, &path, &slice, &user())
                .await
                .is_err()
        );
        assert!(!path.exists(), "no refused drop-in may reach the disk");
    }

    #[test]
    fn the_log_line_names_what_was_enforced() {
        assert_eq!(
            TenantSlice::default().describe(),
            "no limits (accounting only)"
        );
        assert_eq!(
            TenantSlice {
                memory_max_mb: Some(512),
                cpu_quota_pct: Some(100),
                pids_max: Some(256),
                io_weight: Some(100),
            }
            .describe(),
            "memory 512 MB, cpu 100%, pids 256, io weight 100"
        );
    }
}
