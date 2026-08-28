//! Plans, plan assignment, and the subscription suspension lifecycle
//! (spec §6.2, §6.4).
//!
//! A plan is a named bundle of limits and feature flags owned by the admin
//! (global) or by a reseller. Enforcement happens where each resource is
//! created — `site.create` calls [`enforce_site_limit`] before inserting
//! anything, and the database module checks `max_dbs` the same way on its
//! side — so a limit is never a decoration that a different code path forgets.
//!
//! # What suspension does (and deliberately does not do)
//!
//! Suspending a subscription sets its status — which blocks every "create
//! something new" path via `SubscriptionStatus::can_serve` — and re-renders
//! each of its active sites' vhosts with the maintenance page forced on. The
//! site rows themselves are untouched: the subscription status is the single
//! source of truth, so unsuspending is exactly the reverse render and nothing
//! has to remember per-site state.
//!
//! The PHP-FPM pools keep running while suspended. The vhost answers 503 for
//! every request, so PHP is unreachable from the web either way; stopping the
//! pools too would buy no additional web-facing effect, but would add a
//! start-ordering problem to unsuspend (pool up before vhost, per version) and
//! a failure mode where a pool that will not start leaves a *reinstated*
//! tenant down. Spec §6.4's "stop tenant slice / disable SFTP, cron, db remote
//! access" belongs to the slice, SFTP and cron modules, which read the same
//! subscription status — that seam is theirs, not duplicated here.
//!
//! Panel *login* blocking is separate on purpose: it keys off `users.status`
//! (see `sessions.rs` and the agent's `verify_auth`), not the subscription. A
//! customer whose subscription is suspended for non-payment must still be able
//! to log in — to read the reason and to pay — they just cannot serve traffic
//! or create anything new.

use std::sync::Arc;

use async_trait::async_trait;
use ferrum_core::{
    ErrorCode, FerrumError, LinuxUser, Permission, PlanId, Result, SubscriptionId, TenantScope,
};
use ferrum_db::plans::NewPlan;
use ferrum_db::sites::{Site, SiteStatus};
use ferrum_db::subscriptions::{Subscription, SubscriptionStatus};
use ferrum_db::{Db, Plan};
use serde::{Deserialize, Serialize};

use crate::registry::{Execution, OpContext, TypedOperation};

/// Refuse a site creation that would exceed the subscription's plan.
///
/// Called from `site.create` before any row exists. A subscription with no
/// plan is unlimited — that is the Phase 1 behavior, unchanged — and the
/// refusal names the plan and both numbers, because "quota exceeded" alone
/// tells an operator nothing about which knob to turn (spec §10.5).
pub async fn enforce_site_limit(db: &Db, subscription: &Subscription) -> Result<()> {
    let Some(plan) = db
        .plan_of_subscription(subscription.id)
        .await
        .map_err(FerrumError::from)?
    else {
        return Ok(());
    };

    let used = db
        .quota_site_count(subscription.id)
        .await
        .map_err(FerrumError::from)?;
    if used >= plan.max_sites {
        return Err(FerrumError::new(
            ErrorCode::QuotaExceeded,
            format!(
                "plan `{}` allows {} site(s) and this subscription already has {}",
                plan.name, plan.max_sites, used
            ),
        ));
    }
    Ok(())
}

/// A plan name that is safe to render everywhere it will appear (UI, audit
/// rows, quota errors). Trimmed, bounded, no control characters.
fn validate_plan_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "a plan name must be 1–64 characters",
        )
        .with_field("name"));
    }
    if name.chars().any(char::is_control) {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "a plan name must not contain control characters",
        )
        .with_field("name"));
    }
    Ok(name.to_string())
}

// ---------------------------------------------------------------------------
// plan.list
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
pub struct PlanView {
    #[serde(flatten)]
    pub plan: Plan,
    /// How many subscriptions are on it — the number that gates deletion, so
    /// the UI can grey the button out instead of surprising the operator.
    pub subscriptions: i64,
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub plans: Vec<PlanView>,
}

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "plan.list";
    const PERMISSION: Permission = Permission::PlanManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();
        let plans = db
            .plans(ctx.scope())
            .list(input.limit.unwrap_or(100), input.offset.unwrap_or(0))
            .await
            .map_err(FerrumError::from)?;

        let mut views = Vec::with_capacity(plans.len());
        for plan in plans {
            let subscriptions = db
                .subscriptions_on_plan(plan.id)
                .await
                .map_err(FerrumError::from)?;
            views.push(PlanView {
                plan,
                subscriptions,
            });
        }
        Ok(ListOutput { plans: views })
    }
}

// ---------------------------------------------------------------------------
// subscription.list
// ---------------------------------------------------------------------------

/// `subscription.list` — the tenants themselves, not their sites.
///
/// The plans page derived this from `site.list` until now, which had two
/// consequences it could not fix from the client: a subscription with no sites
/// was invisible, and the suspension state was unreadable, because suspending
/// deliberately leaves the site rows alone (see the module docs) — so the one
/// thing a client could see was the one thing that does not change.
///
/// Scoped like every other repository call: a reseller sees their customers'
/// subscriptions, a customer sees their own.
pub struct ListSubscriptions;

#[derive(Debug, Deserialize)]
pub struct ListSubscriptionsInput {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SubscriptionView {
    #[serde(flatten)]
    pub subscription: Subscription,
    /// The owner's username, so the UI can name a tenant instead of printing a
    /// row id at somebody.
    pub customer_username: Option<String>,
    /// How many sites it holds, and how many of those are actually serving.
    /// Suspending stops the serving ones; the confirmation dialog needs to be
    /// able to say which those are before it asks.
    pub sites: i64,
    pub active_sites: i64,
}

#[derive(Debug, Serialize)]
pub struct ListSubscriptionsOutput {
    pub subscriptions: Vec<SubscriptionView>,
}

#[async_trait]
impl TypedOperation for ListSubscriptions {
    type Input = ListSubscriptionsInput;
    type Output = ListSubscriptionsOutput;

    const NAME: &'static str = "subscription.list";
    // Not PlanManage: a customer must be able to see their own subscription and
    // whether it is suspended. The scope filter is what keeps them to it.
    const PERMISSION: Permission = Permission::SiteRead;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();
        let subscriptions = db
            .subscriptions(ctx.scope())
            .list(input.limit.unwrap_or(200), input.offset.unwrap_or(0))
            .await
            .map_err(FerrumError::from)?;

        let mut views = Vec::with_capacity(subscriptions.len());
        for subscription in subscriptions {
            let sites = db
                .sites(ctx.scope())
                .for_subscription(subscription.id)
                .await
                .map_err(FerrumError::from)?;
            let customer_username = db
                .users(ctx.scope())
                .by_id(subscription.customer_id)
                .await
                .map_err(FerrumError::from)?
                .map(|u| u.username.as_str().to_string());

            views.push(SubscriptionView {
                sites: sites.len() as i64,
                active_sites: sites
                    .iter()
                    .filter(|s| s.status == SiteStatus::Active)
                    .count() as i64,
                customer_username,
                subscription,
            });
        }
        Ok(ListSubscriptionsOutput {
            subscriptions: views,
        })
    }
}

// ---------------------------------------------------------------------------
// plan.create
// ---------------------------------------------------------------------------

pub struct Create;

#[derive(Debug, Deserialize)]
pub struct CreateInput {
    pub name: String,
    // u32, not i64: a negative limit is rejected by the parser before the
    // operation body ever runs (spec §12 rule 3).
    pub max_sites: u32,
    pub max_dbs: u32,
    pub storage_mb: u32,
    #[serde(default)]
    pub can_ssh: bool,
    #[serde(default = "default_true")]
    pub can_cron: bool,
    #[serde(default)]
    pub can_node_apps: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct CreateOutput {
    pub plan: Plan,
}

#[async_trait]
impl TypedOperation for Create {
    type Input = CreateInput;
    type Output = CreateOutput;

    const NAME: &'static str = "plan.create";
    const PERMISSION: Permission = Permission::PlanManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let name = validate_plan_name(&input.name)?;

        // Ownership comes from who is asking, never from the input: an admin's
        // plans are global (owner NULL, spec §6.2), a reseller's are their own.
        // The repository enforces the same rule again from the scope — passing
        // `None` here and letting a reseller-scoped create overwrite it keeps
        // one place authoritative.
        let plan = ctx
            .db()
            .plans(ctx.scope())
            .create(NewPlan {
                owner_user_id: None,
                name,
                max_sites: i64::from(input.max_sites),
                max_dbs: i64::from(input.max_dbs),
                storage_mb: i64::from(input.storage_mb),
                can_ssh: input.can_ssh,
                can_cron: input.can_cron,
                can_node_apps: input.can_node_apps,
            })
            .await
            .map_err(FerrumError::from)?;

        ctx.log(format!("created plan `{}`", plan.name));
        Ok(CreateOutput { plan })
    }
}

// ---------------------------------------------------------------------------
// plan.update
// ---------------------------------------------------------------------------

pub struct Update;

#[derive(Debug, Deserialize)]
pub struct UpdateInput {
    pub plan_id: i64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub max_sites: Option<u32>,
    #[serde(default)]
    pub max_dbs: Option<u32>,
    #[serde(default)]
    pub storage_mb: Option<u32>,
    #[serde(default)]
    pub can_ssh: Option<bool>,
    #[serde(default)]
    pub can_cron: Option<bool>,
    #[serde(default)]
    pub can_node_apps: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct UpdateOutput {
    pub plan: Plan,
}

#[async_trait]
impl TypedOperation for Update {
    type Input = UpdateInput;
    type Output = UpdateOutput;

    const NAME: &'static str = "plan.update";
    const PERMISSION: Permission = Permission::PlanManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let name = input.name.as_deref().map(validate_plan_name).transpose()?;

        // Lowering a limit below current usage is allowed on purpose: existing
        // sites keep serving (enforcement is at create time), the tenant just
        // cannot add more. Refusing would make "downgrade a delinquent tenant"
        // impossible, which is the operation's whole point.
        let plan = ctx
            .db()
            .plans(ctx.scope())
            .update(
                PlanId(input.plan_id),
                ferrum_db::plans::PlanUpdate {
                    name,
                    max_sites: input.max_sites.map(i64::from),
                    max_dbs: input.max_dbs.map(i64::from),
                    storage_mb: input.storage_mb.map(i64::from),
                    can_ssh: input.can_ssh,
                    can_cron: input.can_cron,
                    can_node_apps: input.can_node_apps,
                },
            )
            .await
            .map_err(FerrumError::from)?;

        ctx.log(format!("updated plan `{}`", plan.name));
        Ok(UpdateOutput { plan })
    }
}

// ---------------------------------------------------------------------------
// plan.delete
// ---------------------------------------------------------------------------

pub struct Delete;

#[derive(Debug, Deserialize)]
pub struct DeleteInput {
    pub plan_id: i64,
}

#[derive(Debug, Serialize)]
pub struct DeleteOutput {
    pub plan_id: i64,
}

#[async_trait]
impl TypedOperation for Delete {
    type Input = DeleteInput;
    type Output = DeleteOutput;

    const NAME: &'static str = "plan.delete";
    const PERMISSION: Permission = Permission::PlanManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // The repository refuses while subscriptions are on the plan
        // (`FER-1404 dependents_exist`), with the guard inside the DELETE
        // statement itself so a concurrent assignment cannot slip past it.
        ctx.db()
            .plans(ctx.scope())
            .delete(PlanId(input.plan_id))
            .await
            .map_err(FerrumError::from)?;
        Ok(DeleteOutput {
            plan_id: input.plan_id,
        })
    }
}

// ---------------------------------------------------------------------------
// plan.assign
// ---------------------------------------------------------------------------

pub struct Assign;

#[derive(Debug, Deserialize)]
pub struct AssignInput {
    pub subscription_id: i64,
    pub plan_id: i64,
}

#[derive(Debug, Serialize)]
pub struct AssignOutput {
    pub subscription_id: i64,
    pub plan_id: i64,
    pub plan_name: String,
    /// The subscription already holds more sites than the new plan allows.
    /// Assigning anyway is legitimate (downgrades happen); the flag lets the
    /// UI say so instead of the tenant discovering it at the next create.
    pub over_limit: bool,
}

#[async_trait]
impl TypedOperation for Assign {
    type Input = AssignInput;
    type Output = AssignOutput;

    const NAME: &'static str = "plan.assign";
    const PERMISSION: Permission = Permission::PlanManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();

        // Both halves resolve through the caller's scope, so a reseller can
        // neither hand out another reseller's plan nor touch a subscription
        // that is not theirs — either answers "not found", revealing nothing.
        let subscription = db
            .subscriptions(ctx.scope())
            .by_id(SubscriptionId(input.subscription_id))
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("subscription"))?;
        let plan = db
            .plans(ctx.scope())
            .by_id(PlanId(input.plan_id))
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("plan"))?;

        db.assign_plan(subscription.id, plan.id)
            .await
            .map_err(FerrumError::from)?;

        let used = db
            .quota_site_count(subscription.id)
            .await
            .map_err(FerrumError::from)?;

        ctx.log(format!(
            "assigned plan `{}` to subscription {}",
            plan.name, subscription.id
        ));
        Ok(AssignOutput {
            subscription_id: subscription.id.get(),
            plan_id: plan.id.get(),
            plan_name: plan.name,
            over_limit: used > plan.max_sites,
        })
    }
}

// ---------------------------------------------------------------------------
// subscription.suspend / subscription.unsuspend
// ---------------------------------------------------------------------------

/// How the suspension ops touch a site's vhost.
///
/// A trait rather than a direct call so tests can record the switches instead
/// of writing under `/etc`: the config engine's path root is process-global
/// (`paths::set_root` is once-per-process) and other tests in this binary
/// assert the default absolute paths, so a real render is not exercisable in
/// unit tests. The live implementation is a straight delegation with no logic
/// of its own to get wrong.
#[async_trait]
pub trait VhostSwitcher: Send + Sync {
    async fn switch(
        &self,
        ctx: &OpContext,
        site: &Site,
        linux_user: &LinuxUser,
        force_maintenance: bool,
    ) -> Result<()>;
}

pub struct LiveVhosts;

#[async_trait]
impl VhostSwitcher for LiveVhosts {
    async fn switch(
        &self,
        ctx: &OpContext,
        site: &Site,
        linux_user: &LinuxUser,
        force_maintenance: bool,
    ) -> Result<()> {
        crate::site::render_vhost_mode(ctx, site, linux_user, force_maintenance).await
    }
}

/// Load a subscription in the caller's scope and refuse states that must not
/// be toggled from here: `pending_delete` is on a deletion clock, and quietly
/// flipping it back to active would cancel a delete nobody asked to cancel.
async fn suspendable(ctx: &OpContext, id: i64) -> Result<Subscription> {
    let subscription = ctx
        .db()
        .subscriptions(ctx.scope())
        .by_id(SubscriptionId(id))
        .await
        .map_err(FerrumError::from)?
        .ok_or_else(|| FerrumError::not_found("subscription"))?;
    if subscription.status == SubscriptionStatus::PendingDelete {
        return Err(FerrumError::new(
            ErrorCode::Conflict,
            "this subscription is scheduled for deletion; cancel the deletion instead",
        ));
    }
    Ok(subscription)
}

/// Re-render every active site of a subscription, maintenance forced or not.
///
/// All sites are attempted even when one fails — stopping at the first failure
/// would leave the rest un-switched *and* untried. The first error is returned
/// (with the tally) so the task fails visibly and, both ops being idempotent,
/// a re-run converges the stragglers.
async fn switch_all_vhosts(
    ctx: &OpContext,
    vhosts: &dyn VhostSwitcher,
    subscription: &Subscription,
    force_maintenance: bool,
) -> Result<usize> {
    let linux_user = LinuxUser::parse(&subscription.linux_user)?;
    // The subscription's own scope, not the caller's: the caller was already
    // authorized against the subscription, and the sites listed here must be
    // exactly its sites regardless of how wide the caller can see.
    let scope = TenantScope::Subscription {
        subscription_id: subscription.id,
        customer_id: subscription.customer_id,
    };
    // 500 is the repository's hard page cap — and far beyond `max_sites` on
    // any sane plan; a subscription pushing it has bigger problems.
    let sites = ctx
        .db()
        .sites(&scope)
        .list(500, 0)
        .await
        .map_err(FerrumError::from)?;

    let mut switched = 0usize;
    let mut first_error: Option<(String, FerrumError)> = None;
    for site in &sites {
        // Only sites that are serving have a vhost worth switching: a
        // provisioning site has not rendered one yet, a failed one may have
        // nothing valid on disk.
        if site.status != SiteStatus::Active {
            continue;
        }
        match vhosts
            .switch(ctx, site, &linux_user, force_maintenance)
            .await
        {
            Ok(()) => {
                switched += 1;
                ctx.log(format!(
                    "{}: {}",
                    site.domain,
                    if force_maintenance {
                        "maintenance page up"
                    } else {
                        "serving normally again"
                    }
                ));
            }
            Err(e) => {
                ctx.log(format!("{}: vhost switch failed: {e}", site.domain));
                if first_error.is_none() {
                    first_error = Some((site.domain.clone(), e));
                }
            }
        }
    }

    if let Some((domain, error)) = first_error {
        return Err(FerrumError::new(
            error.code,
            format!(
                "the subscription's status is set, but switching the vhost for \
                 `{domain}` failed ({}); re-run to retry the remaining sites",
                error.detail
            ),
        ));
    }
    Ok(switched)
}

pub struct Suspend {
    vhosts: Arc<dyn VhostSwitcher>,
}

impl Suspend {
    pub fn live() -> Self {
        Self {
            vhosts: Arc::new(LiveVhosts),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SuspendInput {
    pub subscription_id: i64,
    /// Required: a tenant looking at a maintenance page deserves to find out
    /// why in the panel, and "suspended for no recorded reason" helps nobody.
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct SuspendOutput {
    pub subscription_id: i64,
    pub status: SubscriptionStatus,
    pub sites_switched: usize,
}

#[async_trait]
impl TypedOperation for Suspend {
    type Input = SuspendInput;
    type Output = SuspendOutput;

    const NAME: &'static str = "subscription.suspend";
    // UserManage, not PlanManage: suspension governs an account's service, not
    // the plan catalogue. Both roles that may suspend (admin, reseller) hold
    // it; a customer holds neither, so they can not unsuspend themselves.
    const PERMISSION: Permission = Permission::UserManage;
    // A task: one nginx reload per site is well past the immediate budget.
    // Idempotent, so a run that failed half-way can simply be re-run.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let reason = input.reason.trim();
        if reason.is_empty() || reason.chars().count() > 500 || reason.chars().any(char::is_control)
        {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "a suspension reason must be 1–500 characters of plain text",
            )
            .with_field("reason"));
        }

        let subscription = suspendable(ctx, input.subscription_id).await?;

        // Status first, renders second (spec §6.4). The order is the safety
        // property: once the row says suspended, nothing new can be created
        // under the subscription even if every render below fails — whereas
        // "renders first" could show maintenance pages for a tenant the
        // database still calls active. The op is idempotent, so a failed
        // render is cured by re-running, and re-suspending an already
        // suspended subscription just converges the vhosts.
        ctx.db()
            .set_subscription_status(subscription.id, SubscriptionStatus::Suspended, Some(reason))
            .await
            .map_err(FerrumError::from)?;
        ctx.log(format!(
            "subscription {} suspended: {reason}",
            subscription.id
        ));

        let sites_switched = switch_all_vhosts(ctx, self.vhosts.as_ref(), &subscription, true).await?;

        // Billing systems integrate through webhooks rather than through a
        // billing module the panel will never grow (spec §2.4), and
        // "this tenant is now suspended" is the event they exist for.
        crate::webhook::emit(
            ctx,
            "subscription.suspended",
            serde_json::json!({
                "subscription_id": subscription.id.get(),
                "linux_user": subscription.linux_user,
                "reason": reason,
                "sites_switched": sites_switched,
            }),
        )
        .await;

        Ok(SuspendOutput {
            subscription_id: subscription.id.get(),
            status: SubscriptionStatus::Suspended,
            sites_switched,
        })
    }
}

pub struct Unsuspend {
    vhosts: Arc<dyn VhostSwitcher>,
}

impl Unsuspend {
    pub fn live() -> Self {
        Self {
            vhosts: Arc::new(LiveVhosts),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UnsuspendInput {
    pub subscription_id: i64,
}

#[derive(Debug, Serialize)]
pub struct UnsuspendOutput {
    pub subscription_id: i64,
    pub status: SubscriptionStatus,
    pub sites_restored: usize,
}

#[async_trait]
impl TypedOperation for Unsuspend {
    type Input = UnsuspendInput;
    type Output = UnsuspendOutput;

    const NAME: &'static str = "subscription.unsuspend";
    const PERMISSION: Permission = Permission::UserManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let subscription = suspendable(ctx, input.subscription_id).await?;

        // Mirror image of suspend, same ordering logic: mark active first so a
        // failed render leaves a tenant who can at least create and retry, not
        // one locked out with the database claiming otherwise.
        ctx.db()
            .set_subscription_status(subscription.id, SubscriptionStatus::Active, None)
            .await
            .map_err(FerrumError::from)?;
        ctx.log(format!("subscription {} reinstated", subscription.id));

        // force_maintenance = false: each vhost renders from the site's own
        // stored flags, so a site the tenant had put in maintenance themselves
        // comes back in maintenance — suspension never rewrote their settings.
        let sites_restored = switch_all_vhosts(ctx, self.vhosts.as_ref(), &subscription, false).await?;

        Ok(UnsuspendOutput {
            subscription_id: subscription.id.get(),
            status: SubscriptionStatus::Active,
            sites_restored,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use crate::registry::{OpContext, OpRegistry};
    use ferrum_core::{Domain, Role, UserId};
    use ferrum_db::users::NewUser;
    use ferrum_db::{NewSite, SiteType};
    use serde_json::json;
    use std::sync::Mutex;

    fn db_of(reg: &OpRegistry) -> Db {
        reg.services().db.clone()
    }

    async fn make_reseller(db: &Db, name: &'static str) -> UserId {
        db.users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Reseller,
                email: ferrum_core::Email::parse(&format!("{name}@example.com")).unwrap(),
                username: ferrum_core::Username::parse(name).unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap()
            .id
    }

    async fn seed_site(db: &Db, sub: &Subscription, domain: &str, status: SiteStatus) -> Site {
        let site = db
            .create_site(NewSite {
                subscription_id: sub.id,
                domain: Domain::parse(domain).unwrap(),
                site_type: SiteType::Static,
                php_version: None,
                root_dir: format!("/home/{}/sites/{domain}/public", sub.linux_user),
                proxy_port: None,
                redirect_target: None,
            })
            .await
            .unwrap();
        db.set_site_status(site.id, status).await.unwrap();
        db.sites(&TenantScope::Global)
            .by_id(site.id)
            .await
            .unwrap()
            .unwrap()
    }

    // -- plans -------------------------------------------------------------

    #[tokio::test]
    async fn an_admins_plan_is_global_and_a_resellers_is_their_own() {
        let (reg, admin, _) = registry().await;
        let out = reg
            .dispatch(
                "plan.create",
                &auth_for(admin, Role::Admin),
                json!({ "name": "Starter", "max_sites": 3, "max_dbs": 1, "storage_mb": 1024 }),
                None,
            )
            .await
            .unwrap();
        assert!(out["plan"]["owner_user_id"].is_null(), "{out}");

        let reseller = make_reseller(&db_of(&reg), "resellera").await;
        let out = reg
            .dispatch(
                "plan.create",
                &auth_for(reseller, Role::Reseller),
                json!({ "name": "Bronze", "max_sites": 1, "max_dbs": 1, "storage_mb": 512 }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["plan"]["owner_user_id"], json!(reseller.get()));
    }

    #[tokio::test]
    async fn a_customer_cannot_touch_the_plan_catalogue() {
        let (reg, _, customer) = registry().await;
        for (op, input) in [
            ("plan.create", json!({ "name": "x", "max_sites": 1, "max_dbs": 1, "storage_mb": 1 })),
            ("plan.update", json!({ "plan_id": 1 })),
            ("plan.delete", json!({ "plan_id": 1 })),
            ("plan.assign", json!({ "subscription_id": 1, "plan_id": 1 })),
            ("plan.list", json!({})),
        ] {
            let err = reg
                .dispatch(op, &auth_for(customer, Role::Customer), input, None)
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied, "{op}");
        }
    }

    #[tokio::test]
    async fn a_plan_in_use_refuses_deletion_with_the_dependents_code() {
        let (reg, admin, customer) = registry().await;
        let db = db_of(&reg);
        let auth = auth_for(admin, Role::Admin);
        let out = reg
            .dispatch(
                "plan.create",
                &auth,
                json!({ "name": "Starter", "max_sites": 3, "max_dbs": 1, "storage_mb": 1024 }),
                None,
            )
            .await
            .unwrap();
        let plan_id = out["plan"]["id"].as_i64().unwrap();

        let sub = db.create_subscription(customer).await.unwrap();
        reg.dispatch(
            "plan.assign",
            &auth,
            json!({ "subscription_id": sub.id.get(), "plan_id": plan_id }),
            None,
        )
        .await
        .unwrap();

        let err = reg
            .dispatch("plan.delete", &auth, json!({ "plan_id": plan_id }), None)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::DependentsExist);
        assert_eq!(err.code.code(), "FER-1404");
        assert!(err.detail.contains("subscription"), "{}", err.detail);
    }

    #[tokio::test]
    async fn a_reseller_cannot_assign_another_resellers_plan_or_subscription() {
        let (reg, admin, _) = registry().await;
        let db = db_of(&reg);
        let a = make_reseller(&db, "resellera").await;
        let b = make_reseller(&db, "resellerb").await;

        // Reseller A's plan, and a direct (admin-owned) customer's subscription.
        let out = reg
            .dispatch(
                "plan.create",
                &auth_for(a, Role::Reseller),
                json!({ "name": "APlan", "max_sites": 1, "max_dbs": 1, "storage_mb": 1 }),
                None,
            )
            .await
            .unwrap();
        let a_plan = out["plan"]["id"].as_i64().unwrap();
        let foreign_sub = db.create_subscription(admin).await.unwrap();

        // B cannot see A's plan at all…
        let err = reg
            .dispatch(
                "plan.assign",
                &auth_for(b, Role::Reseller),
                json!({ "subscription_id": foreign_sub.id.get(), "plan_id": a_plan }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);

        // …and A, who owns the plan, still cannot reach a subscription that is
        // not under them. The answer stays "not found" — a reseller probing
        // ids must learn nothing about what exists outside their scope.
        let err = reg
            .dispatch(
                "plan.assign",
                &auth_for(a, Role::Reseller),
                json!({ "subscription_id": foreign_sub.id.get(), "plan_id": a_plan }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    // -- enforcement -------------------------------------------------------

    #[tokio::test]
    async fn a_subscription_at_its_site_limit_is_refused_by_name() {
        let (reg, admin, customer) = registry().await;
        let db = db_of(&reg);
        let auth = auth_for(admin, Role::Admin);

        let out = reg
            .dispatch(
                "plan.create",
                &auth,
                json!({ "name": "Solo", "max_sites": 1, "max_dbs": 1, "storage_mb": 1024 }),
                None,
            )
            .await
            .unwrap();
        let sub = db.create_subscription(customer).await.unwrap();
        db.assign_plan(sub.id, PlanId(out["plan"]["id"].as_i64().unwrap()))
            .await
            .unwrap();
        seed_site(&db, &sub, "first.example.com", SiteStatus::Active).await;

        // The refusal happens before any row or account exists, through the
        // whole dispatch path, and names the plan so the operator knows which
        // knob to turn (spec §10.5).
        let err = reg
            .dispatch(
                "site.create",
                &auth,
                json!({
                    "domain": "second.example.com",
                    "site_type": "static",
                    "subscription_id": sub.id.get(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::QuotaExceeded);
        assert!(err.detail.contains("Solo"), "{}", err.detail);
        assert!(
            db.sites(&TenantScope::Global)
                .by_domain("second.example.com")
                .await
                .unwrap()
                .is_none(),
            "the refused site must leave no row behind"
        );
    }

    #[tokio::test]
    async fn failed_sites_do_not_consume_the_quota() {
        // A failed create is retried by reclaiming its row; counting it would
        // burn a slot the tenant never got to use.
        let (reg, _, customer) = registry().await;
        let db = db_of(&reg);
        let plan = db
            .plans(&TenantScope::Global)
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
        let sub = db.create_subscription(customer).await.unwrap();
        db.assign_plan(sub.id, plan.id).await.unwrap();
        seed_site(&db, &sub, "broken.example.com", SiteStatus::Failed).await;

        let full = db
            .subscriptions(&TenantScope::Global)
            .by_id(sub.id)
            .await
            .unwrap()
            .unwrap();
        assert!(enforce_site_limit(&db, &full).await.is_ok());

        // With an *active* site the limit of one is reached.
        seed_site(&db, &sub, "live.example.com", SiteStatus::Active).await;
        let err = enforce_site_limit(&db, &full).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::QuotaExceeded);
    }

    #[tokio::test]
    async fn a_subscription_without_a_plan_stays_unlimited() {
        // The Phase 1 behavior, unchanged: no plan means no limit — existing
        // installs must not start refusing sites because plans now exist.
        let (reg, _, customer) = registry().await;
        let db = db_of(&reg);
        let sub = db.create_subscription(customer).await.unwrap();
        for i in 0..3 {
            seed_site(&db, &sub, &format!("s{i}.example.com"), SiteStatus::Active).await;
        }
        let full = db
            .subscriptions(&TenantScope::Global)
            .by_id(sub.id)
            .await
            .unwrap()
            .unwrap();
        assert!(enforce_site_limit(&db, &full).await.is_ok());
    }

    // -- suspension --------------------------------------------------------

    /// Records every vhost switch instead of writing under `/etc` (see the
    /// [`VhostSwitcher`] docs for why a real render is not testable here).
    #[derive(Default)]
    struct RecordingVhosts {
        calls: Mutex<Vec<(String, bool)>>,
    }

    #[async_trait]
    impl VhostSwitcher for RecordingVhosts {
        async fn switch(
            &self,
            _ctx: &OpContext,
            site: &Site,
            _linux_user: &LinuxUser,
            force_maintenance: bool,
        ) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push((site.domain.clone(), force_maintenance));
            Ok(())
        }
    }

    #[tokio::test]
    async fn suspend_forces_maintenance_on_active_sites_and_unsuspend_restores_them() {
        let (reg, admin, customer) = registry().await;
        let db = db_of(&reg);
        let sub = db.create_subscription(customer).await.unwrap();
        seed_site(&db, &sub, "live.example.com", SiteStatus::Active).await;
        // No working vhost to switch on these two: one never finished
        // provisioning, one failed.
        seed_site(&db, &sub, "half.example.com", SiteStatus::Provisioning).await;
        seed_site(&db, &sub, "broken.example.com", SiteStatus::Failed).await;

        let recorder = Arc::new(RecordingVhosts::default());
        let ctx = OpContext::new(
            reg.services().clone(),
            auth_for(admin, Role::Admin),
        );

        let suspend = Suspend {
            vhosts: recorder.clone(),
        };
        let out = suspend
            .run(
                &ctx,
                SuspendInput {
                    subscription_id: sub.id.get(),
                    reason: "unpaid invoice #42".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(out.sites_switched, 1);

        {
            let calls = recorder.calls.lock().unwrap();
            assert_eq!(
                *calls,
                vec![("live.example.com".to_string(), true)],
                "exactly the serving site, with maintenance forced on"
            );
        }

        let suspended = db
            .subscriptions(&TenantScope::Global)
            .by_id(sub.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(suspended.status, SubscriptionStatus::Suspended);
        assert_eq!(suspended.suspended_reason.as_deref(), Some("unpaid invoice #42"));
        assert!(suspended.suspended_at.is_some());
        // The site's own maintenance flag was never rewritten: the forced page
        // lives only in the rendered vhost, so reinstating cannot clobber a
        // tenant's own setting (spec §10.4 rule 3 spirit).
        let site = db
            .sites(&TenantScope::Global)
            .by_domain("live.example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(!site.maintenance_mode);

        let unsuspend = Unsuspend {
            vhosts: recorder.clone(),
        };
        let out = unsuspend
            .run(
                &ctx,
                UnsuspendInput {
                    subscription_id: sub.id.get(),
                },
            )
            .await
            .unwrap();
        assert_eq!(out.sites_restored, 1);

        {
            let calls = recorder.calls.lock().unwrap();
            assert_eq!(
                calls.last().unwrap(),
                &("live.example.com".to_string(), false)
            );
        }

        let restored = db
            .subscriptions(&TenantScope::Global)
            .by_id(sub.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.status, SubscriptionStatus::Active);
        assert!(restored.suspended_reason.is_none());
        assert!(restored.suspended_at.is_none());
    }

    #[tokio::test]
    async fn a_suspended_subscription_blocks_new_sites_but_not_the_panel_login() {
        let (reg, admin, customer) = registry().await;
        let db = db_of(&reg);
        let sub = db.create_subscription(customer).await.unwrap();

        // Through the whole dispatch path (no sites, so the live renderer has
        // nothing to write and the op completes cleanly).
        reg.dispatch(
            "subscription.suspend",
            &auth_for(admin, Role::Admin),
            json!({ "subscription_id": sub.id.get(), "reason": "abuse report" }),
            None,
        )
        .await
        .unwrap();

        // Nothing new can be created under it…
        let err = reg
            .dispatch(
                "site.create",
                &auth_for(admin, Role::Admin),
                json!({
                    "domain": "new.example.com",
                    "site_type": "static",
                    "subscription_id": sub.id.get(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::AccountSuspended);

        // …but the customer still reaches the panel: login blocking keys off
        // `users.status` (sessions.rs; registry::verify_auth), not the
        // subscription — a tenant suspended for non-payment must be able to
        // log in, read the reason, and pay.
        reg.dispatch(
            "site.list",
            &auth_for(customer, Role::Customer),
            json!({}),
            None,
        )
        .await
        .expect("a customer with a suspended subscription can still use the panel");
    }

    #[tokio::test]
    async fn suspending_twice_converges_instead_of_failing() {
        // Idempotency is what makes "re-run the task" the fix for a half-done
        // suspension, so the second run must succeed, not trip over the state.
        let (reg, admin, customer) = registry().await;
        let db = db_of(&reg);
        let sub = db.create_subscription(customer).await.unwrap();
        let auth = auth_for(admin, Role::Admin);
        let input = json!({ "subscription_id": sub.id.get(), "reason": "unpaid" });

        reg.dispatch("subscription.suspend", &auth, input.clone(), None)
            .await
            .unwrap();
        reg.dispatch("subscription.suspend", &auth, input, None)
            .await
            .unwrap();

        let status = db
            .subscriptions(&TenantScope::Global)
            .by_id(sub.id)
            .await
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, SubscriptionStatus::Suspended);
    }

    #[tokio::test]
    async fn a_customer_cannot_suspend_or_unsuspend_even_their_own_subscription() {
        // Unsuspending yourself would make suspension pointless; the guard is
        // the UserManage permission, which no customer holds.
        let (reg, _, customer) = registry().await;
        let db = db_of(&reg);
        let sub = db.create_subscription(customer).await.unwrap();

        for op in ["subscription.suspend", "subscription.unsuspend"] {
            let err = reg
                .dispatch(
                    op,
                    &auth_for(customer, Role::Customer),
                    json!({ "subscription_id": sub.id.get(), "reason": "x" }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied, "{op}");
        }
    }

    #[tokio::test]
    async fn a_reseller_cannot_suspend_a_subscription_outside_their_scope() {
        let (reg, admin, _) = registry().await;
        let db = db_of(&reg);
        let reseller = make_reseller(&db, "resellera").await;
        // A subscription belonging to a direct customer of the admin.
        let foreign = db.create_subscription(admin).await.unwrap();

        let err = reg
            .dispatch(
                "subscription.suspend",
                &auth_for(reseller, Role::Reseller),
                json!({ "subscription_id": foreign.id.get(), "reason": "not mine" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound, "existence must not leak");
    }

    #[tokio::test]
    async fn a_suspension_needs_a_real_reason() {
        let (reg, admin, customer) = registry().await;
        let db = db_of(&reg);
        let sub = db.create_subscription(customer).await.unwrap();
        let auth = auth_for(admin, Role::Admin);

        for bad in ["", "   ", "line\nbreak"] {
            let err = reg
                .dispatch(
                    "subscription.suspend",
                    &auth,
                    json!({ "subscription_id": sub.id.get(), "reason": bad }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "reason {bad:?}");
        }
        // And the refusal must have left the subscription alone.
        let status = db
            .subscriptions(&TenantScope::Global)
            .by_id(sub.id)
            .await
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, SubscriptionStatus::Active);
    }

    #[tokio::test]
    async fn negative_limits_never_reach_the_operation() {
        // u32 in the input type means the parser is the guard (spec §12 rule 3).
        let (reg, admin, _) = registry().await;
        let err = reg
            .dispatch(
                "plan.create",
                &auth_for(admin, Role::Admin),
                json!({ "name": "Broken", "max_sites": -1, "max_dbs": 1, "storage_mb": 1 }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
}
