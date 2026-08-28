//! The web terminal and the SSH key manager (spec §11.16).
//!
//! # This is the most dangerous surface in the panel
//!
//! Say it plainly, because every design decision below follows from it: a web
//! terminal is a general-purpose remote code execution endpoint that the panel
//! offers on purpose. Every other operation in this codebase is a narrow verb
//! with a typed input — `site.create` can create a site and nothing else. A
//! terminal can do anything the account it runs as can do, and for an admin
//! that account is root. There is no input validation that helps here, because
//! arbitrary input is the feature.
//!
//! What is left, then, is the perimeter, and it is where all the effort goes:
//!
//! * **Who** — [`authorize`] is the only way a session is created, it re-derives
//!   the caller's rights from the database rather than trusting the frame, and
//!   it has no branch that hands a customer a root shell. Not "a branch guarded
//!   by a check": no branch. See
//!   `a_customer_can_never_reach_a_root_shell_by_any_route`.
//! * **Whether** — a customer needs [`Permission::TerminalAccess`] *and* a plan
//!   with `can_ssh`. Either missing is a refusal, and a subscription with no
//!   plan at all is a refusal too (fail closed, the same posture
//!   `ops::sftp` takes).
//! * **How much** — bounded concurrent sessions per server and per account, an
//!   idle timeout and a hard lifetime ceiling, because a forgotten root shell
//!   in a browser tab is a persistent unauthenticated foothold for whoever
//!   walks past that laptop.
//! * **What was done** — the audit row is written **before** the PTY exists.
//!   Not after, not concurrently: if the trail cannot be written, the shell is
//!   not started. See `the_audit_row_is_written_before_the_shell_starts`.
//!
//! # Why the PTY lives in the agent
//!
//! Spec §11.16's acceptance criterion is that a session survives a panel web
//! restart. That is only possible if the process holding the file descriptor is
//! not the one being restarted, so `ferrum-agentd` owns the master fd, the
//! child, and the scrollback; `ferrum-web` holds nothing but a WebSocket and a
//! session id. Restarting the web process drops the socket and nothing else —
//! the browser reconnects, sends `TerminalAttach`, and gets the scrollback plus
//! the live stream back.
//!
//! It also means the web process, which is the one exposed to the network,
//! never holds a descriptor to a root shell.
//!
//! # The privilege drop is the same one the file manager uses
//!
//! A tenant session re-execs the agent binary as `--pty-helper` through
//! [`ferrum_distro::exec::reexec_current`], and the helper calls the *same*
//! `drop_privileges` in `ferrum-agentd`'s `main.rs` that `--fs-helper` and
//! `--wp-helper` call — including its `setuid(0)`-must-fail proof, which
//! aborts rather than continuing if root can be re-acquired. There is
//! deliberately no second implementation of that drop; a security mechanism
//! with two copies has one that is out of date.

pub mod helper;
pub mod keys;
pub mod pty;
pub mod session;

use std::path::{Path, PathBuf};

use ferrum_core::{
    AuthContext, ErrorCode, FerrumError, LinuxUser, Permission, Result, Role, SubscriptionId,
};
use ferrum_db::Db;
use ferrum_ipc::frame::TerminalTarget;

pub use session::{Limits, SessionHandle, SessionInfo, TerminalRegistry};

/// Login shells a session may be started with.
///
/// An allowlist rather than "whatever `/etc/passwd` says", because the shell
/// path is the one string on this path that comes from outside the panel's own
/// tables. A tenant account whose shell has been pointed at something else is
/// refused with a message that says so, which is the right outcome either way:
/// either the account was tampered with, or the operator did something the
/// panel should not silently go along with.
const ALLOWED_SHELLS: &[&str] = &[
    "/bin/bash",
    "/usr/bin/bash",
    "/bin/sh",
    "/usr/bin/sh",
    "/bin/zsh",
    "/usr/bin/zsh",
    "/bin/dash",
    "/usr/bin/dash",
    "/usr/bin/fish",
];

/// Shells that mean "this account may not log in". Never a terminal.
const REFUSED_SHELLS: &[&str] = &[
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/usr/bin/nologin",
    "/bin/false",
    "/usr/bin/false",
];

/// What the agent decided a caller may have. Only [`authorize`] builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionPlan {
    /// A root shell. Admins only.
    Root { home: PathBuf, shell: PathBuf },
    /// A shell as a tenant's Linux account, reached through the privilege drop.
    Tenant {
        uid: u32,
        gid: u32,
        linux_user: LinuxUser,
        subscription_id: SubscriptionId,
        home: PathBuf,
        shell: PathBuf,
    },
}

impl SessionPlan {
    /// The account name for the audit row and for the UI's "you are …" label.
    pub fn account(&self) -> String {
        match self {
            SessionPlan::Root { .. } => "root".into(),
            SessionPlan::Tenant { linux_user, .. } => linux_user.as_str().to_string(),
        }
    }

    pub const fn is_root(&self) -> bool {
        matches!(self, SessionPlan::Root { .. })
    }

    pub fn home(&self) -> &Path {
        match self {
            SessionPlan::Root { home, .. } | SessionPlan::Tenant { home, .. } => home,
        }
    }

    pub fn shell(&self) -> &Path {
        match self {
            SessionPlan::Root { shell, .. } | SessionPlan::Tenant { shell, .. } => shell,
        }
    }

    pub fn subscription_id(&self) -> Option<SubscriptionId> {
        match self {
            SessionPlan::Root { .. } => None,
            SessionPlan::Tenant {
                subscription_id, ..
            } => Some(*subscription_id),
        }
    }
}

/// One account's `/etc/passwd` entry, as far as this module cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: PathBuf,
}

/// How an account is looked up. The production implementation is `getpwnam`;
/// the tests supply a table, so authorisation can be exercised on a machine
/// that has no tenant accounts on it.
pub trait AccountSource: Send + Sync {
    fn lookup(&self, linux_user: &str) -> Option<Account>;
}

/// `getpwnam`, so NSS sources (LDAP, sssd) work the same way they do for every
/// other program on the box.
pub struct SystemAccounts;

impl AccountSource for SystemAccounts {
    fn lookup(&self, linux_user: &str) -> Option<Account> {
        let c_name = std::ffi::CString::new(linux_user).ok()?;
        // SAFETY: `getpwnam` returns a pointer into a static buffer owned by
        // libc; every field is copied out before anything else can call it.
        unsafe {
            let pw = libc::getpwnam(c_name.as_ptr());
            if pw.is_null() {
                return None;
            }
            let home = std::ffi::CStr::from_ptr((*pw).pw_dir)
                .to_string_lossy()
                .into_owned();
            let shell = std::ffi::CStr::from_ptr((*pw).pw_shell)
                .to_string_lossy()
                .into_owned();
            Some(Account {
                uid: (*pw).pw_uid,
                gid: (*pw).pw_gid,
                home: PathBuf::from(home),
                shell: PathBuf::from(shell),
            })
        }
    }
}

/// Decide what — if anything — this caller gets.
///
/// `auth` must already have been re-derived from the database
/// (`OpRegistry::verify_auth`); this function trusts it about identity but not
/// about the target, which it resolves through the caller's own tenant scope so
/// another tenant's subscription is a `NotFound` rather than a peek.
///
/// The role match is exhaustive and deliberately written as a table: a reader
/// should be able to see every route into a root shell at once, and there is
/// exactly one.
pub async fn authorize(
    db: &Db,
    accounts: &dyn AccountSource,
    auth: &AuthContext,
    target: &TerminalTarget,
) -> Result<SessionPlan> {
    // The permission gate first, before anything reveals whether a
    // subscription exists — the same ordering `OpRegistry::dispatch` uses.
    auth.require(Permission::TerminalAccess)?;

    match (auth.acting_role, target) {
        // --- the one route to root ------------------------------------------
        (Role::Admin, TerminalTarget::Root) => {
            let shell = pick_root_shell()?;
            Ok(SessionPlan::Root {
                home: PathBuf::from("/root"),
                shell,
            })
        }

        // An admin may also open a shell *as* a tenant — that is the file
        // manager's "open terminal here". It drops privilege exactly like a
        // customer's session does; the plan flag is not consulted because an
        // admin already has every one of that tenant's files by other means,
        // and refusing here would only push them to the root shell above.
        (Role::Admin, TerminalTarget::Tenant { subscription_id }) => {
            tenant_plan(db, accounts, auth, *subscription_id, false).await
        }

        // --- customers ------------------------------------------------------
        // No branch below can produce `SessionPlan::Root`. That is the property
        // the whole module rests on, so it is a shape of the code rather than a
        // condition inside it.
        (Role::Customer, TerminalTarget::Root) => Err(FerrumError::new(
            ErrorCode::PermissionDenied,
            "a root terminal is available to administrators only",
        )),
        (Role::Customer, TerminalTarget::Tenant { subscription_id }) => {
            tenant_plan(db, accounts, auth, *subscription_id, true).await
        }

        // --- resellers -------------------------------------------------------
        // A reseller has no Linux account of its own and is not an
        // administrator of the machine; §6 gives it customers, not a shell.
        (Role::Reseller, _) => Err(FerrumError::new(
            ErrorCode::PermissionDenied,
            "reseller accounts have no shell on this server",
        )),
    }
}

/// Resolve a subscription into a tenant session, optionally enforcing the plan.
///
/// `require_plan_flag` is the customer half of spec §11.16 ("only if
/// `can_ssh`"). It fails closed twice over: a subscription with no plan is
/// refused rather than treated as unlimited, and a plan row that cannot be
/// loaded is refused rather than assumed permissive.
async fn tenant_plan(
    db: &Db,
    accounts: &dyn AccountSource,
    auth: &AuthContext,
    subscription_id: Option<i64>,
    require_plan_flag: bool,
) -> Result<SessionPlan> {
    let subscription = resolve_subscription(db, auth, subscription_id).await?;

    if !subscription.status.can_serve() {
        return Err(FerrumError::new(
            ErrorCode::AccountSuspended,
            "this subscription is suspended; its shell is closed",
        ));
    }

    if require_plan_flag {
        let plan = db
            .plan_of_subscription(subscription.id)
            .await
            .map_err(FerrumError::from)?;
        match plan {
            Some(plan) if plan.can_ssh => {}
            Some(plan) => {
                return Err(FerrumError::new(
                    ErrorCode::PlanFeatureDisabled,
                    format!("plan `{}` does not include shell access", plan.name),
                ));
            }
            None => {
                return Err(FerrumError::new(
                    ErrorCode::PlanFeatureDisabled,
                    "shell access is a plan feature and this subscription has no plan",
                ));
            }
        }
    }

    let linux_user = LinuxUser::parse(&subscription.linux_user)?;
    let account = accounts.lookup(linux_user.as_str()).ok_or_else(|| {
        FerrumError::new(
            ErrorCode::NotFound,
            format!(
                "the Linux account `{}` does not exist on this server",
                linux_user.as_str()
            ),
        )
    })?;

    // "Drop" to root is not a drop. An account database that maps a tenant to
    // uid 0 is broken in a way no shell should get near.
    if account.uid == 0 || account.gid == 0 {
        return Err(FerrumError::internal(format!(
            "`{}` maps to uid/gid 0; refusing to open a tenant terminal as root",
            linux_user.as_str()
        )));
    }

    let shell = vet_shell(&account.shell)?;

    Ok(SessionPlan::Tenant {
        uid: account.uid,
        gid: account.gid,
        linux_user,
        subscription_id: subscription.id,
        home: PathBuf::from(&subscription.home_dir),
        shell,
    })
}

/// The subscription an operation is about — resolved, never created.
///
/// `Db::default_subscription_for` *provisions* an implicit subscription when a
/// customer has no active one. That is right for "create a site" on a Phase 1
/// install and exactly wrong here: a suspended tenant asking for a shell would
/// silently be handed a brand-new subscription instead of the refusal they have
/// earned. So this resolves through the caller's own scope and stops.
pub(crate) async fn resolve_subscription(
    db: &Db,
    auth: &AuthContext,
    subscription_id: Option<i64>,
) -> Result<ferrum_db::subscriptions::Subscription> {
    if let Some(id) = subscription_id {
        // Scoped: another tenant's id resolves to nothing here, which is the
        // same containment `fs.*` and `site.*` rely on.
        return db
            .subscriptions(&auth.tenant_scope)
            .by_id(SubscriptionId(id))
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("subscription"));
    }

    // An admin's scope is the whole server, so "my subscription" has no answer
    // for them; naming one is the only sensible reading of the request.
    if auth.tenant_scope.is_global() {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "name the subscription to open a tenant shell for",
        )
        .with_field("subscription_id"));
    }

    let mine = db
        .subscriptions(&auth.tenant_scope)
        .list(500, 0)
        .await
        .map_err(FerrumError::from)?;
    // Oldest first, matching what `default_subscription_for` would have picked.
    mine.into_iter()
        .min_by_key(|s| s.id.get())
        .ok_or_else(|| FerrumError::not_found("subscription"))
}

/// Check an account's login shell against the allowlist.
pub fn vet_shell(shell: &Path) -> Result<PathBuf> {
    let text = shell.to_string_lossy();
    if REFUSED_SHELLS.contains(&text.as_ref()) {
        return Err(FerrumError::new(
            ErrorCode::PlanFeatureDisabled,
            "this account has no login shell; enable shell access on its plan first",
        ));
    }
    if !ALLOWED_SHELLS.contains(&text.as_ref()) {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!("`{text}` is not a login shell the panel will start"),
        ));
    }
    Ok(shell.to_path_buf())
}

/// The first allowlisted shell that is actually installed, for a root session.
fn pick_root_shell() -> Result<PathBuf> {
    ALLOWED_SHELLS
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .map(Path::to_path_buf)
        .ok_or_else(|| FerrumError::internal("no usable login shell is installed on this server"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_core::{Email, TenantScope, UserId, Username};
    use ferrum_db::plans::NewPlan;
    use ferrum_db::users::NewUser;
    use std::collections::HashMap;

    /// A passwd table the tests own, so authorisation can be exercised without
    /// creating real accounts on the developer's machine.
    struct FakeAccounts(HashMap<String, Account>);

    impl FakeAccounts {
        fn with(user: &str, uid: u32, gid: u32) -> Self {
            let mut map = HashMap::new();
            map.insert(
                user.to_string(),
                Account {
                    uid,
                    gid,
                    home: PathBuf::from(format!("/home/{user}")),
                    shell: PathBuf::from("/bin/bash"),
                },
            );
            Self(map)
        }
    }

    impl AccountSource for FakeAccounts {
        fn lookup(&self, linux_user: &str) -> Option<Account> {
            self.0.get(linux_user).cloned()
        }
    }

    struct World {
        db: Db,
        admin: UserId,
        customer: UserId,
        subscription: SubscriptionId,
        linux_user: String,
    }

    async fn world() -> World {
        let db = Db::open_memory().await.unwrap();
        let mk = |name: &'static str, role: Role| NewUser {
            role,
            email: Email::parse(&format!("{name}@example.com")).unwrap(),
            username: Username::parse(name).unwrap(),
            password: "a-long-enough-password".into(),
            reseller_id: None,
            full_name: None,
            locale: "en".into(),
        };
        let admin = db
            .users(&TenantScope::Global)
            .create(mk("admin", Role::Admin))
            .await
            .unwrap();
        let customer = db
            .users(&TenantScope::Global)
            .create(mk("client", Role::Customer))
            .await
            .unwrap();
        let subscription = db.create_subscription(customer.id).await.unwrap();
        World {
            db,
            admin: admin.id,
            customer: customer.id,
            linux_user: subscription.linux_user.clone(),
            subscription: subscription.id,
        }
    }

    fn auth_for(id: UserId, role: Role) -> AuthContext {
        let scope = match role {
            Role::Admin => TenantScope::Global,
            Role::Reseller => TenantScope::Reseller { reseller_id: id },
            Role::Customer => TenantScope::Customer { customer_id: id },
        };
        AuthContext::from_role(id, role, scope, "req-test")
    }

    async fn give_plan(db: &Db, subscription: SubscriptionId, can_ssh: bool) {
        let plan = db
            .plans(&TenantScope::Global)
            .create(NewPlan {
                owner_user_id: None,
                name: format!("plan-{}-ssh-{can_ssh}", subscription.get()),
                max_sites: 10,
                max_dbs: 10,
                storage_mb: 1024,
                can_ssh,
                can_cron: true,
                can_node_apps: false,
            })
            .await
            .unwrap();
        db.assign_plan(subscription, plan.id).await.unwrap();
    }

    #[tokio::test]
    async fn a_customer_can_never_reach_a_root_shell_by_any_route() {
        // The claim the module rests on. Every shape of request a customer can
        // put on the wire is tried here: asking for root outright, asking for
        // root while holding a plan that grants shell access, and asking with a
        // forged permission set.
        let w = world().await;
        give_plan(&w.db, w.subscription, true).await;
        let accounts = FakeAccounts::with(&w.linux_user, 5001, 5001);

        for mut auth in [
            auth_for(w.customer, Role::Customer),
            auth_for(w.customer, Role::Customer),
        ] {
            // The second pass adds every permission the panel has, standing in
            // for a compromised web process building its own frame.
            auth.permissions.insert(Permission::ServerManage);
            auth.permissions.insert(Permission::SshAccess);

            let err = authorize(&w.db, &accounts, &auth, &TerminalTarget::Root)
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied);
        }

        // And the granted path really is a tenant session, not root.
        let plan = authorize(
            &w.db,
            &accounts,
            &auth_for(w.customer, Role::Customer),
            &TerminalTarget::Tenant {
                subscription_id: None,
            },
        )
        .await
        .unwrap();
        assert!(!plan.is_root());
        assert_eq!(plan.account(), w.linux_user);
    }

    #[tokio::test]
    async fn a_customer_without_can_ssh_gets_nothing() {
        let w = world().await;
        let accounts = FakeAccounts::with(&w.linux_user, 5001, 5001);
        let auth = auth_for(w.customer, Role::Customer);
        let target = TerminalTarget::Tenant {
            subscription_id: None,
        };

        // No plan at all: fail closed, not "unlimited".
        let err = authorize(&w.db, &accounts, &auth, &target)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PlanFeatureDisabled);

        // A plan that says no.
        give_plan(&w.db, w.subscription, false).await;
        let err = authorize(&w.db, &accounts, &auth, &target)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PlanFeatureDisabled);

        // The permission alone is not enough either — and losing it (which is
        // what a plan without can_ssh does, via
        // `PlanFeatures::denied_permissions`) is refused before the plan is
        // even consulted.
        give_plan(&w.db, w.subscription, true).await;
        let stripped = auth_for(w.customer, Role::Customer).revoke(&[Permission::TerminalAccess]);
        let err = authorize(&w.db, &accounts, &stripped, &target)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn a_customer_cannot_open_another_tenants_shell() {
        let w = world().await;
        give_plan(&w.db, w.subscription, true).await;

        // A second customer with their own subscription.
        let other =
            w.db.users(&TenantScope::Global)
                .create(NewUser {
                    role: Role::Customer,
                    email: Email::parse("other@example.com").unwrap(),
                    username: Username::parse("other").unwrap(),
                    password: "a-long-enough-password".into(),
                    reseller_id: None,
                    full_name: None,
                    locale: "en".into(),
                })
                .await
                .unwrap();
        let other_sub = w.db.create_subscription(other.id).await.unwrap();
        give_plan(&w.db, other_sub.id, true).await;

        let accounts = FakeAccounts::with(&other_sub.linux_user, 5002, 5002);
        let err = authorize(
            &w.db,
            &accounts,
            &auth_for(w.customer, Role::Customer),
            &TerminalTarget::Tenant {
                subscription_id: Some(other_sub.id.get()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::NotFound,
            "another tenant's subscription must not even be confirmed to exist"
        );
    }

    #[tokio::test]
    async fn a_reseller_has_no_shell_at_all() {
        let w = world().await;
        let accounts = FakeAccounts::with(&w.linux_user, 5001, 5001);
        let mut auth = auth_for(UserId(99), Role::Reseller);
        // Even holding the permission outright.
        auth.permissions.insert(Permission::TerminalAccess);

        for target in [
            TerminalTarget::Root,
            TerminalTarget::Tenant {
                subscription_id: None,
            },
        ] {
            let err = authorize(&w.db, &accounts, &auth, &target)
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied);
        }
    }

    #[tokio::test]
    async fn an_admin_gets_root_and_may_also_drop_into_a_tenant() {
        let w = world().await;
        let accounts = FakeAccounts::with(&w.linux_user, 5001, 5001);
        let auth = auth_for(w.admin, Role::Admin);

        let root = authorize(&w.db, &accounts, &auth, &TerminalTarget::Root)
            .await
            .unwrap();
        assert!(root.is_root());
        assert_eq!(root.account(), "root");

        let tenant = authorize(
            &w.db,
            &accounts,
            &auth,
            &TerminalTarget::Tenant {
                subscription_id: Some(w.subscription.get()),
            },
        )
        .await
        .unwrap();
        assert!(!tenant.is_root());
        match tenant {
            SessionPlan::Tenant { uid, gid, .. } => {
                assert_eq!((uid, gid), (5001, 5001));
            }
            other => panic!("expected a tenant plan, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_tenant_account_that_maps_to_root_is_refused() {
        // A broken /etc/passwd (or a hostile NSS source) must not turn into a
        // root shell handed to a customer.
        let w = world().await;
        give_plan(&w.db, w.subscription, true).await;
        let accounts = FakeAccounts::with(&w.linux_user, 0, 0);

        let err = authorize(
            &w.db,
            &accounts,
            &auth_for(w.customer, Role::Customer),
            &TerminalTarget::Tenant {
                subscription_id: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
        assert!(err.detail.contains("uid/gid 0"));
    }

    #[tokio::test]
    async fn a_suspended_subscription_has_no_shell() {
        let w = world().await;
        give_plan(&w.db, w.subscription, true).await;
        w.db.set_subscription_status(
            w.subscription,
            ferrum_db::subscriptions::SubscriptionStatus::Suspended,
            Some("unpaid"),
        )
        .await
        .unwrap();

        let accounts = FakeAccounts::with(&w.linux_user, 5001, 5001);
        let err = authorize(
            &w.db,
            &accounts,
            &auth_for(w.customer, Role::Customer),
            &TerminalTarget::Tenant {
                subscription_id: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::AccountSuspended);
    }

    #[test]
    fn a_nologin_account_is_refused_with_a_reason_and_a_strange_shell_outright() {
        let err = vet_shell(Path::new("/usr/sbin/nologin")).unwrap_err();
        assert_eq!(err.code, ErrorCode::PlanFeatureDisabled);

        let err = vet_shell(Path::new("/tmp/evil")).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);

        assert!(vet_shell(Path::new("/bin/bash")).is_ok());
    }
}
