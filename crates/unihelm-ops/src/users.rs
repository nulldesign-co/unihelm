//! Panel accounts: who may sign in, as what, and what leaves with them
//! (spec §6.1, §11.20).
//!
//! Until this existed the panel could not manage its own accounts. A second
//! administrator could only be made with `unihelm user create-admin`, which
//! refuses the moment any account exists — so in practice not at all — and
//! there was no way to change a role, suspend anybody, or remove an account
//! from the panel at all. Every one of those was a root shell and a SQLite
//! prompt.
//!
//! # What is here, and what deliberately is not
//!
//! Listing, creating, re-roling, suspending and deleting are
//! [`Permission::UserManage`] operations, scoped like every other repository
//! read: an admin sees the whole panel, a reseller sees itself and the accounts
//! beneath it, and a customer reaches none of it.
//!
//! **Changing your own password is not an operation.** Two reasons, and the
//! second is the one that decides it. It is not privileged work — it writes two
//! rows of the panel's own database and touches nothing on the host. And every
//! operation must name the one [`Permission`] its caller has to hold, while
//! there is no permission that means *your own account*: a customer holds
//! neither `user_manage` nor anything that could honestly stand in for it, so
//! the registry could only express this by filing it under a permission every
//! role happens to have — a false claim in the audit trail, in `unihelm ops
//! list` and in `docs/operations.md`. It lives in `unihelm_web::routes::users`
//! instead, beside login and logout, in the process that already owns the
//! session table and the argon2 budget.
//!
//! # Four refusals carry this module
//!
//! **The last administrator cannot be demoted, suspended or deleted.** The
//! count is of admins who can still *sign in* ([`active_admins`]), because
//! demoting down to one suspended admin leaves the panel with nobody who can
//! administer it and no way in short of a root shell. The refusal names the
//! account and says what to do first.
//!
//! **Nobody acts on their own account here.** Deleting, demoting or suspending
//! the account you are signed in as is never what the operator meant, and it is
//! irreversible from the panel. Changing your own password is the one thing you
//! do to yourself, and it is on the other route.
//!
//! **A reseller may only ever create and hold customers.** Ownership comes from
//! who is asking, never from the request body — the same rule `plan.create`
//! follows — so a reseller cannot mint an admin and cannot adopt somebody
//! else's customer by naming an id.
//!
//! **Deleting an account says what goes with it, before and after.** The three
//! things that block a delete — subscriptions, owned plans, customers beneath a
//! reseller — are `ON DELETE RESTRICT` in the schema, so without this the
//! operator's answer would be a foreign-key error. They are counted onto every
//! row [`List`] returns, so the UI can say why the item is disabled; they are
//! counted again inside [`Delete`], which refuses by name; and what the delete
//! *did* remove is counted in its own result rather than reported as "deleted".
//!
//! # Passwords
//!
//! [`Create`] takes a plaintext password and hands it to
//! `UserRepo::create`, which is the single place in the tree that hashes one
//! (`unihelm_db::password::hash_password`, argon2id at the parameters the login
//! path verifies against). Nothing here logs it, returns it, or puts it in an
//! audit detail.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unihelm_core::{
    Email, ErrorCode, Permission, Result, Role, TenantScope, UnihelmError, UserId, Username,
};
use unihelm_db::users::NewUser;
use unihelm_db::{Db, User, UserStatus};

use crate::registry::{Execution, OpContext, TypedOperation};

/// The locale every account is created with.
///
/// The panel is English-only, so the `users.locale` column is a schema
/// leftover rather than a choice to put on a form: a select with one option is
/// a question with no answer.
const LOCALE: &str = "en";

// ---------------------------------------------------------------------------
// Shared rules
// ---------------------------------------------------------------------------

fn db_error(e: sqlx::Error) -> UnihelmError {
    unihelm_db::DbError::from(e).into()
}

/// How many administrators can currently sign in.
///
/// `status = 'active'` is the load-bearing half. An admin who cannot log in
/// cannot administer, so counting suspended ones would let the panel be left
/// with one suspended administrator and no way back in through the panel.
async fn active_admins(db: &Db) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role = ?1 AND status = ?2")
        .bind(Role::Admin.as_str())
        .bind(UserStatus::Active.as_str())
        .fetch_one(db.pool())
        .await
        .map_err(db_error)?;
    Ok(row.0)
}

/// The account this operation is about, resolved through the caller's scope.
///
/// Scope first, always: a reseller naming an id outside their own tree gets
/// `not_found` — the same answer a non-existent id gives — so this cannot be
/// used to discover which accounts exist.
async fn target(ctx: &OpContext, id: i64) -> Result<User> {
    ctx.db()
        .users(ctx.scope())
        .by_id(UserId(id))
        .await
        .map_err(UnihelmError::from)?
        .ok_or_else(|| UnihelmError::not_found("user"))
}

/// Refuse an action aimed at the account the caller is signed in as.
///
/// `what` completes "you cannot … the account you are signed in as".
fn ensure_not_self(ctx: &OpContext, user: &User, what: &str) -> Result<()> {
    if ctx.auth().actor_user_id != user.id {
        return Ok(());
    }
    Err(UnihelmError::new(
        ErrorCode::PermissionDenied,
        format!(
            "you cannot {what} the account you are signed in as (`{}`). Ask another \
             administrator, or use a different account.",
            user.username.as_str()
        ),
    ))
}

/// Refuse an action that would leave the panel with no administrator who can
/// sign in.
///
/// `what` completes "`name` … cannot be …".
///
/// Checked **before** [`ensure_not_self`], which is the only ordering that
/// produces a true message. The reachable case is the sole administrator acting
/// on their own account, and "you cannot do this to the account you are signed
/// in as" would send them off to sign in as somebody else — when the thing they
/// actually have to do is create a second administrator. The advice differs by
/// who is asking for the same reason: once a second one exists, an operator
/// acting on their own account still cannot, and being told to "repeat this"
/// would be a second wasted trip.
async fn ensure_not_the_last_admin(ctx: &OpContext, user: &User, what: &str) -> Result<()> {
    if user.role != Role::Admin || user.status != UserStatus::Active {
        return Ok(());
    }
    if active_admins(ctx.db()).await? > 1 {
        return Ok(());
    }
    let advice = if ctx.auth().actor_user_id == user.id {
        "Create a second administrator first; it is that account that can then do this, \
         because nobody may act on the account they are signed in as."
    } else {
        "Create a second administrator first, then repeat this."
    };
    Err(UnihelmError::new(
        ErrorCode::DependentsExist,
        format!(
            "`{}` is the only administrator who can sign in, so it cannot be {what} — the \
             panel would have nobody left to administer it. {advice}",
            user.username.as_str()
        ),
    ))
}

/// The reseller a caller's new accounts belong to, and the roles they may hand
/// out.
///
/// `None` is the admin: global scope, any role, no owner. A reseller owns
/// everything it creates and may only create customers. Anything narrower does
/// not hold `user_manage` at all, so it is refused rather than left to fall
/// through some later check.
fn owner_for(ctx: &OpContext) -> Result<Option<UserId>> {
    match ctx.scope() {
        TenantScope::Global => Ok(None),
        TenantScope::Reseller { reseller_id } => Ok(Some(*reseller_id)),
        TenantScope::Customer { .. } | TenantScope::Subscription { .. } => Err(UnihelmError::new(
            ErrorCode::PermissionDenied,
            "only an administrator or a reseller can manage panel accounts",
        )),
    }
}

/// Refuse a role a reseller may not hand out.
fn ensure_role_allowed(owner: Option<UserId>, role: Role) -> Result<()> {
    if owner.is_none() || role == Role::Customer {
        return Ok(());
    }
    Err(UnihelmError::new(
        ErrorCode::PermissionDenied,
        format!(
            "a reseller may only manage customer accounts, and `{}` is not one. Only an \
                 administrator can create or promote administrators and resellers.",
            role.as_str()
        ),
    )
    .with_field("role"))
}

// ---------------------------------------------------------------------------
// The wire shape of an account
// ---------------------------------------------------------------------------

/// One account, as a client may see it.
///
/// A separate struct from [`User`] on purpose, and for the same reason
/// `unihelm_web::routes::auth::UserView` is: the model carries `pass_hash` and
/// `totp_secret`, and the way to guarantee those never reach a response is for
/// the response type not to have them (spec §12 rule 6). `User` is not even
/// `Serialize`.
#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: i64,
    pub role: Role,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub status: UserStatus,
    /// The reseller this account belongs to, when it belongs to one.
    pub reseller_id: Option<i64>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<time::OffsetDateTime>,
    /// Subscriptions this account owns. Deletion is refused above zero.
    pub subscriptions: i64,
    /// Plans this account owns (a reseller's own). Deletion is refused above
    /// zero.
    pub owned_plans: i64,
    /// Accounts beneath this one. Deletion is refused above zero.
    pub customers: i64,
}

/// Counts of the three things that stand between an account and deletion.
///
/// Three grouped queries rather than three per row: a list of five hundred
/// accounts would otherwise be fifteen hundred round trips to answer a question
/// about a button's disabled state. The counts are aggregates over rows the
/// caller's scope has already been checked against — they annotate accounts
/// this caller may see, and are never returned for one they may not.
#[derive(Debug, Default)]
struct Dependents {
    subscriptions: BTreeMap<i64, i64>,
    owned_plans: BTreeMap<i64, i64>,
    customers: BTreeMap<i64, i64>,
}

impl Dependents {
    async fn load(db: &Db) -> Result<Self> {
        async fn tally(db: &Db, sql: &str) -> Result<BTreeMap<i64, i64>> {
            let rows: Vec<(i64, i64)> = sqlx::query_as(sql)
                .fetch_all(db.pool())
                .await
                .map_err(db_error)?;
            Ok(rows.into_iter().collect())
        }

        Ok(Self {
            subscriptions: tally(
                db,
                "SELECT customer_id, COUNT(*) FROM subscriptions GROUP BY customer_id",
            )
            .await?,
            owned_plans: tally(
                db,
                "SELECT owner_user_id, COUNT(*) FROM plans
                  WHERE owner_user_id IS NOT NULL GROUP BY owner_user_id",
            )
            .await?,
            customers: tally(
                db,
                "SELECT reseller_id, COUNT(*) FROM users
                  WHERE reseller_id IS NOT NULL GROUP BY reseller_id",
            )
            .await?,
        })
    }

    fn view(&self, user: User) -> UserView {
        let id = user.id.get();
        UserView {
            id,
            role: user.role,
            username: user.username.as_str().to_string(),
            email: user.email.as_str().to_string(),
            full_name: user.full_name,
            status: user.status,
            reseller_id: user.reseller_id.map(|r| r.get()),
            created_at: user.created_at,
            last_login_at: user.last_login_at,
            subscriptions: self.subscriptions.get(&id).copied().unwrap_or(0),
            owned_plans: self.owned_plans.get(&id).copied().unwrap_or(0),
            customers: self.customers.get(&id).copied().unwrap_or(0),
        }
    }
}

// ---------------------------------------------------------------------------
// user.list
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
pub struct ListOutput {
    pub users: Vec<UserView>,
    /// Administrators who can sign in, panel-wide — the number the "last
    /// administrator" refusals are made of, so a client can disable the action
    /// with a reason instead of only learning on the click.
    ///
    /// `None` outside a global scope. A reseller's list contains no
    /// administrators at all, so the figure would drive nothing there, and a
    /// count of accounts outside their tree is not theirs to have.
    pub admin_count: Option<i64>,
}

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "user.list";
    const PERMISSION: Permission = Permission::UserManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();
        let users = db
            .users(ctx.scope())
            .list(input.limit.unwrap_or(200), input.offset.unwrap_or(0))
            .await
            .map_err(UnihelmError::from)?;

        let dependents = Dependents::load(db).await?;
        let admin_count = if ctx.scope().is_global() {
            Some(active_admins(db).await?)
        } else {
            None
        };

        Ok(ListOutput {
            users: users.into_iter().map(|u| dependents.view(u)).collect(),
            admin_count,
        })
    }
}

// ---------------------------------------------------------------------------
// user.create
// ---------------------------------------------------------------------------

pub struct Create;

#[derive(Debug, Deserialize)]
pub struct CreateInput {
    /// Parsed, not merely deserialised: `Username` and `Email` reject their bad
    /// values before the operation body runs (spec §12 rule 3).
    pub username: Username,
    pub email: Email,
    pub role: Role,
    /// Plaintext, hashed by the repository. Never logged, never echoed, never
    /// written to an audit detail.
    pub password: String,
    #[serde(default)]
    pub full_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateOutput {
    pub user: UserView,
}

#[async_trait]
impl TypedOperation for Create {
    type Input = CreateInput;
    type Output = CreateOutput;

    const NAME: &'static str = "user.create";
    const PERMISSION: Permission = Permission::UserManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let owner = owner_for(ctx)?;
        ensure_role_allowed(owner, input.role)?;

        let db = ctx.db();
        let created = db
            .users(&TenantScope::Global)
            .create(NewUser {
                role: input.role,
                email: input.email,
                username: input.username,
                // The password policy lives in `unihelm_db::password`, and
                // `create` runs it before it hashes: a password that fails it
                // leaves no row behind.
                password: input.password,
                // From the caller's scope, never from the body. A reseller owns
                // what it creates; an admin's accounts stand on their own.
                reseller_id: owner,
                full_name: input.full_name,
                locale: LOCALE.into(),
            })
            .await
            .map_err(UnihelmError::from)?;

        ctx.log(format!(
            "created {} account `{}`",
            created.role.as_str(),
            created.username.as_str()
        ));
        Ok(CreateOutput {
            user: Dependents::default().view(created),
        })
    }
}

// ---------------------------------------------------------------------------
// user.role.set
// ---------------------------------------------------------------------------

pub struct RoleSet;

#[derive(Debug, Deserialize)]
pub struct RoleSetInput {
    pub user_id: i64,
    pub role: Role,
}

#[derive(Debug, Serialize)]
pub struct RoleSetOutput {
    pub user: UserView,
    /// The account's sessions were revoked; see the operation body for why.
    pub sessions_ended: u64,
}

#[async_trait]
impl TypedOperation for RoleSet {
    type Input = RoleSetInput;
    type Output = RoleSetOutput;

    const NAME: &'static str = "user.role.set";
    const PERMISSION: Permission = Permission::UserManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let owner = owner_for(ctx)?;
        let user = target(ctx, input.user_id).await?;
        // Both directions: a reseller may not promote anybody, and may not
        // touch an account that is not a customer even to leave it as it was.
        ensure_role_allowed(owner, input.role)?;
        ensure_role_allowed(owner, user.role)?;

        if input.role != Role::Admin {
            ensure_not_the_last_admin(ctx, &user, "given another role").await?;
        }
        ensure_not_self(ctx, &user, "change the role of")?;

        let db = ctx.db();
        sqlx::query("UPDATE users SET role = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(user.id.get())
            .bind(input.role.as_str())
            .bind(
                time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|e| {
                        UnihelmError::internal(format!("could not format a timestamp: {e}"))
                    })?,
            )
            .execute(db.pool())
            .await
            .map_err(db_error)?;

        // A role decides what the panel draws as much as what the agent
        // permits. The agent re-derives rights per request, so a demoted admin
        // loses them immediately either way — but their open tab keeps the
        // sidebar it rendered at sign-in until something reloads it. Ending the
        // sessions makes the next thing they see the panel their new role
        // actually has.
        let sessions_ended = db
            .revoke_all_sessions(user.id)
            .await
            .map_err(UnihelmError::from)?;

        let updated = db
            .users(&TenantScope::Global)
            .by_id(user.id)
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("user"))?;

        ctx.log(format!(
            "`{}` is now {}",
            updated.username.as_str(),
            updated.role.as_str()
        ));
        Ok(RoleSetOutput {
            user: Dependents::load(db).await?.view(updated),
            sessions_ended,
        })
    }
}

// ---------------------------------------------------------------------------
// user.status.set
// ---------------------------------------------------------------------------

pub struct StatusSet;

/// The two states this operation may put an account in.
///
/// `users.status` also admits `locked`, which nothing in the panel sets and
/// which means something different — a throttle lifted with `unihelm user
/// unlock`, not an administrative decision. Accepting it here would offer an
/// operator a state they could not undo from the same screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Active,
    Suspended,
}

impl AccountStatus {
    const fn stored(self) -> UserStatus {
        match self {
            AccountStatus::Active => UserStatus::Active,
            AccountStatus::Suspended => UserStatus::Suspended,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct StatusSetInput {
    pub user_id: i64,
    pub status: AccountStatus,
}

#[derive(Debug, Serialize)]
pub struct StatusSetOutput {
    pub user: UserView,
    /// Sessions revoked by a suspension. Zero when reinstating.
    pub sessions_ended: u64,
}

#[async_trait]
impl TypedOperation for StatusSet {
    type Input = StatusSetInput;
    type Output = StatusSetOutput;

    const NAME: &'static str = "user.status.set";
    const PERMISSION: Permission = Permission::UserManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let owner = owner_for(ctx)?;
        let user = target(ctx, input.user_id).await?;
        ensure_role_allowed(owner, user.role)?;

        if input.status == AccountStatus::Suspended {
            ensure_not_the_last_admin(ctx, &user, "suspended").await?;
            ensure_not_self(ctx, &user, "suspend")?;
        }

        let db = ctx.db();
        db.users(ctx.scope())
            .set_status(user.id, input.status.stored())
            .await
            .map_err(UnihelmError::from)?;

        // `lookup_session` already refuses a session whose account cannot log
        // in, so a suspension takes effect on the next request either way.
        // Revoking is what makes it true in the session table too — otherwise
        // the rows sit there `revoked = 0`, the device list still shows them,
        // and reinstating the account silently hands every one of them back.
        let sessions_ended = if input.status == AccountStatus::Suspended {
            db.revoke_all_sessions(user.id)
                .await
                .map_err(UnihelmError::from)?
        } else {
            0
        };

        let updated = db
            .users(&TenantScope::Global)
            .by_id(user.id)
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| UnihelmError::not_found("user"))?;

        ctx.log(format!(
            "`{}` is now {}",
            updated.username.as_str(),
            updated.status.as_str()
        ));
        Ok(StatusSetOutput {
            user: Dependents::load(db).await?.view(updated),
            sessions_ended,
        })
    }
}

// ---------------------------------------------------------------------------
// user.delete
// ---------------------------------------------------------------------------

pub struct Delete;

#[derive(Debug, Deserialize)]
pub struct DeleteInput {
    pub user_id: i64,
    /// The account's own username, typed again by whoever is asking.
    ///
    /// Deleting an account is the one thing on this page that cannot be undone
    /// by clicking the other way, and an id in a URL is not something an
    /// operator can check by eye. `db.drop` takes the same kind of
    /// confirmation for the same reason.
    pub confirm_username: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteOutput {
    pub user_id: i64,
    pub username: String,
    /// Live sessions that went with the account.
    pub sessions_ended: i64,
    /// API tokens deleted with it (`ON DELETE CASCADE`).
    pub api_tokens_removed: i64,
    /// Webhooks deleted with it (`ON DELETE CASCADE`) — their deliveries stop.
    pub webhooks_removed: i64,
    /// Audit entries that remain. The trail keeps `actor_username`, so what
    /// this account did is still readable after the row is gone.
    pub audit_entries_kept: i64,
}

#[async_trait]
impl TypedOperation for Delete {
    type Input = DeleteInput;
    type Output = DeleteOutput;

    const NAME: &'static str = "user.delete";
    const PERMISSION: Permission = Permission::UserManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let owner = owner_for(ctx)?;
        let user = target(ctx, input.user_id).await?;
        ensure_role_allowed(owner, user.role)?;
        ensure_not_the_last_admin(ctx, &user, "deleted").await?;
        ensure_not_self(ctx, &user, "delete")?;

        let username = user.username.as_str().to_string();
        if input.confirm_username.trim() != username {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                format!(
                    "the confirmation does not match: account {} is `{username}`, and the \
                     request named `{}`. Nothing was deleted.",
                    user.id.get(),
                    input.confirm_username.trim()
                ),
            )
            .with_field("confirm_username"));
        }

        let db = ctx.db();
        let held = Dependents::load(db).await?;
        let view = held.view(user);
        // The schema says RESTRICT on all three, so without this the operator's
        // answer to "delete this account" would be a foreign-key error naming a
        // table. Each is also a thing they have to decide about rather than a
        // thing to cascade away: a subscription is somebody's sites.
        let mut blocked = Vec::new();
        if view.subscriptions > 0 {
            blocked.push(format!(
                "{} subscription(s) — move them to another account or delete them first",
                view.subscriptions
            ));
        }
        if view.owned_plans > 0 {
            blocked.push(format!(
                "{} plan(s) it owns — delete them or leave them with another reseller first",
                view.owned_plans
            ));
        }
        if view.customers > 0 {
            blocked.push(format!(
                "{} account(s) beneath it — reassign or delete them first",
                view.customers
            ));
        }
        if !blocked.is_empty() {
            return Err(UnihelmError::new(
                ErrorCode::DependentsExist,
                format!(
                    "`{username}` still holds {}. Nothing was deleted.",
                    blocked.join("; ")
                ),
            ));
        }

        let id = view.id;
        let counted = |sql: &'static str| async move {
            let row: (i64,) = sqlx::query_as(sql)
                .bind(id)
                .fetch_one(db.pool())
                .await
                .map_err(db_error)?;
            Ok::<i64, UnihelmError>(row.0)
        };
        // Counted before the delete, because after it there is nothing left to
        // count and the operator would be told a number nobody measured.
        let sessions_ended =
            counted("SELECT COUNT(*) FROM sessions WHERE user_id = ?1 AND revoked = 0").await?;
        let api_tokens_removed =
            counted("SELECT COUNT(*) FROM api_tokens WHERE user_id = ?1").await?;
        let webhooks_removed =
            counted("SELECT COUNT(*) FROM webhooks WHERE owner_user_id = ?1").await?;
        let audit_entries_kept =
            counted("SELECT COUNT(*) FROM audit_log WHERE actor_user_id = ?1").await?;

        // The repository has no `delete`, and the scope check that would have
        // been its job has already run above — `target` resolved this id
        // through the caller's own scope, and every refusal since has been
        // about this row.
        let removed = sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(id)
            .execute(db.pool())
            .await
            .map_err(db_error)?
            .rows_affected();
        if removed == 0 {
            return Err(UnihelmError::not_found("user"));
        }

        ctx.log(format!("deleted account `{username}`"));
        Ok(DeleteOutput {
            user_id: id,
            username,
            sessions_ended,
            api_tokens_removed,
            webhooks_removed,
            audit_entries_kept,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use crate::registry::{OpRegistry, Operation};
    use unihelm_core::AuthContext;
    use unihelm_db::sessions::DEFAULT_TTL;

    /// Seed one more account and hand back its id.
    async fn seed(db: &Db, name: &str, role: Role, reseller: Option<UserId>) -> User {
        db.users(&TenantScope::Global)
            .create(NewUser {
                role,
                email: Email::parse(&format!("{name}@example.com")).unwrap(),
                username: Username::parse(name).unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: reseller,
                full_name: None,
                locale: LOCALE.into(),
            })
            .await
            .unwrap()
    }

    /// Run an operation the way [`OpRegistry::dispatch`] runs one.
    ///
    /// The same sequence in the same order — the caller's rights re-derived
    /// from the database, then the permission, then the input parsed into the
    /// operation's own type — with the registry's name lookup replaced by the
    /// caller naming the type. That one step is what these tests cannot use:
    /// `registry.rs` is where the `register` line for these operations goes,
    /// and it is applied outside this file.
    async fn call<T: TypedOperation>(
        reg: &OpRegistry,
        op: &T,
        auth: &AuthContext,
        input: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let verified = reg.verify_auth(auth).await?;
        verified.require(T::PERMISSION)?;
        let ctx = OpContext::new(reg.services().clone(), verified);
        op.invoke(&ctx, input).await
    }

    #[tokio::test]
    async fn a_customer_cannot_reach_account_management_at_all() {
        let (reg, _, customer) = registry().await;
        let auth = auth_for(customer, Role::Customer);

        let err = call(&reg, &List, &auth, serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);

        let err = call(
            &reg,
            &Delete,
            &auth,
            serde_json::json!({ "user_id": 1, "confirm_username": "admin" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn creating_an_account_stores_a_hash_and_returns_no_password() {
        let (reg, admin, _) = registry().await;
        let out = call(
            &reg,
            &Create,
            &auth_for(admin, Role::Admin),
            serde_json::json!({
                "username": "second",
                "email": "second@example.com",
                "role": "admin",
                "password": "another-long-password",
            }),
        )
        .await
        .unwrap();

        let rendered = serde_json::to_string(&out).unwrap();
        assert!(
            !rendered.contains("another-long-password"),
            "the response must not carry the password: {rendered}"
        );
        assert!(!rendered.contains("pass_hash"), "{rendered}");

        let created = reg
            .services()
            .db
            .find_user_for_login("second")
            .await
            .unwrap()
            .unwrap();
        assert!(created.pass_hash.starts_with("$argon2id$"));
        assert!(unihelm_db::password::verify_password(
            "another-long-password",
            &created.pass_hash
        ));
    }

    #[tokio::test]
    async fn a_password_that_fails_the_policy_leaves_no_account_behind() {
        let (reg, admin, _) = registry().await;
        let err = call(
            &reg,
            &Create,
            &auth_for(admin, Role::Admin),
            serde_json::json!({
                "username": "weakling",
                "email": "weak@example.com",
                "role": "customer",
                "password": "short",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::PasswordTooWeak);
        assert!(
            reg.services()
                .db
                .find_user_for_login("weakling")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_reseller_may_only_create_customers_and_only_under_itself() {
        let (reg, ..) = registry().await;
        let db = reg.services().db.clone();
        let reseller = seed(&db, "shopfront", Role::Reseller, None).await;
        let auth = auth_for(reseller.id, Role::Reseller);

        let err = call(
            &reg,
            &Create,
            &auth,
            serde_json::json!({
                "username": "sneaky",
                "email": "sneaky@example.com",
                "role": "admin",
                "password": "a-long-enough-password",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(db.find_user_for_login("sneaky").await.unwrap().is_none());

        call(
            &reg,
            &Create,
            &auth,
            serde_json::json!({
                "username": "theirclient",
                "email": "theirclient@example.com",
                "role": "customer",
                "password": "a-long-enough-password",
            }),
        )
        .await
        .unwrap();
        let created = db
            .find_user_for_login("theirclient")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            created.reseller_id,
            Some(reseller.id),
            "ownership comes from the caller, not the body"
        );
    }

    #[tokio::test]
    async fn a_reseller_cannot_touch_an_account_outside_its_own_tree() {
        let (reg, admin, other) = registry().await;
        let db = reg.services().db.clone();
        let reseller = seed(&db, "shopfront", Role::Reseller, None).await;
        let auth = auth_for(reseller.id, Role::Reseller);

        for target_id in [admin.get(), other.get()] {
            let err = call(
                &reg,
                &StatusSet,
                &auth,
                serde_json::json!({ "user_id": target_id, "status": "suspended" }),
            )
            .await
            .unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::NotFound,
                "an id outside the scope must answer the same way a missing one does"
            );
        }
    }

    #[tokio::test]
    async fn the_only_administrator_cannot_be_demoted_suspended_or_deleted() {
        // The reachable shape of this: the sole administrator, acting on their
        // own account. Nobody else can — a second admin would make the rule
        // moot, and a reseller cannot see an administrator at all — which is
        // why this refusal is checked before the "not yourself" one, and why
        // the message has to say what actually unblocks it.
        let (reg, admin, _) = registry().await;
        let db = reg.services().db.clone();
        // A *suspended* second administrator, to pin the half that matters:
        // an admin who cannot sign in is not one the panel can be run by, so
        // counting rows rather than active rows would pass this by.
        let deputy = seed(&db, "deputy", Role::Admin, None).await;
        db.users(&TenantScope::Global)
            .set_status(deputy.id, UserStatus::Suspended)
            .await
            .unwrap();
        let auth = auth_for(admin, Role::Admin);

        let demote = call(
            &reg,
            &RoleSet,
            &auth,
            serde_json::json!({ "user_id": admin.get(), "role": "customer" }),
        )
        .await
        .unwrap_err();
        let suspend = call(
            &reg,
            &StatusSet,
            &auth,
            serde_json::json!({ "user_id": admin.get(), "status": "suspended" }),
        )
        .await
        .unwrap_err();
        let delete = call(
            &reg,
            &Delete,
            &auth,
            serde_json::json!({ "user_id": admin.get(), "confirm_username": "admin" }),
        )
        .await
        .unwrap_err();

        for err in [demote, suspend, delete] {
            assert_eq!(err.code, ErrorCode::DependentsExist);
            assert!(err.detail.contains("`admin`"), "{}", err.detail);
            assert!(
                err.detail.contains("Create a second administrator"),
                "the refusal has to say what unblocks it: {}",
                err.detail
            );
        }

        let still = db
            .users(&TenantScope::Global)
            .by_id(admin)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still.role, Role::Admin);
        assert_eq!(still.status, UserStatus::Active);
    }

    #[tokio::test]
    async fn nobody_may_delete_demote_or_suspend_the_account_they_are_signed_in_as() {
        let (reg, admin, _) = registry().await;
        let db = reg.services().db.clone();
        // A second active admin, so the "last administrator" rule is not what
        // produces the refusal.
        seed(&db, "deputy", Role::Admin, None).await;
        let auth = auth_for(admin, Role::Admin);

        let demote = call(
            &reg,
            &RoleSet,
            &auth,
            serde_json::json!({ "user_id": admin.get(), "role": "customer" }),
        )
        .await
        .unwrap_err();
        let suspend = call(
            &reg,
            &StatusSet,
            &auth,
            serde_json::json!({ "user_id": admin.get(), "status": "suspended" }),
        )
        .await
        .unwrap_err();
        let delete = call(
            &reg,
            &Delete,
            &auth,
            serde_json::json!({ "user_id": admin.get(), "confirm_username": "admin" }),
        )
        .await
        .unwrap_err();

        for err in [demote, suspend, delete] {
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert!(err.detail.contains("signed in as"), "{}", err.detail);
        }
    }

    #[tokio::test]
    async fn suspending_an_account_ends_its_sessions_and_reinstating_does_not_return_them() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let issued = db
            .create_session(customer, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();
        let auth = auth_for(admin, Role::Admin);

        let out = call(
            &reg,
            &StatusSet,
            &auth,
            serde_json::json!({ "user_id": customer.get(), "status": "suspended" }),
        )
        .await
        .unwrap();
        assert_eq!(out["sessions_ended"], 1);
        assert_eq!(out["user"]["status"], "suspended");
        assert!(db.lookup_session(&issued.token).await.unwrap().is_none());

        call(
            &reg,
            &StatusSet,
            &auth,
            serde_json::json!({ "user_id": customer.get(), "status": "active" }),
        )
        .await
        .unwrap();
        assert!(
            db.lookup_session(&issued.token).await.unwrap().is_none(),
            "a revoked session must not come back when the account does"
        );
    }

    #[tokio::test]
    async fn changing_a_role_ends_that_accounts_sessions() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let issued = db
            .create_session(customer, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();

        let out = call(
            &reg,
            &RoleSet,
            &auth_for(admin, Role::Admin),
            serde_json::json!({ "user_id": customer.get(), "role": "reseller" }),
        )
        .await
        .unwrap();
        assert_eq!(out["user"]["role"], "reseller");
        assert_eq!(out["sessions_ended"], 1);
        assert!(
            db.lookup_session(&issued.token).await.unwrap().is_none(),
            "the tab they left open must not keep the panel their old role drew"
        );
    }

    #[tokio::test]
    async fn deleting_an_account_that_owns_something_is_refused_and_says_what() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        db.create_subscription(customer).await.unwrap();

        let err = call(
            &reg,
            &Delete,
            &auth_for(admin, Role::Admin),
            serde_json::json!({ "user_id": customer.get(), "confirm_username": "client" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::DependentsExist);
        assert!(err.detail.contains("subscription"), "{}", err.detail);
        assert!(err.detail.contains("Nothing was deleted"), "{}", err.detail);
        assert!(
            db.users(&TenantScope::Global)
                .by_id(customer)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn the_list_carries_what_would_block_each_delete() {
        let (reg, admin, customer) = registry().await;
        reg.services()
            .db
            .create_subscription(customer)
            .await
            .unwrap();

        let out = call(
            &reg,
            &List,
            &auth_for(admin, Role::Admin),
            serde_json::json!({}),
        )
        .await
        .unwrap();
        assert_eq!(out["admin_count"], 1);
        let rows = out["users"].as_array().unwrap();
        let client = rows
            .iter()
            .find(|u| u["username"] == "client")
            .expect("the customer is listed");
        assert_eq!(client["subscriptions"], 1);
        assert_eq!(client["owned_plans"], 0);
        assert_eq!(client["customers"], 0);
        assert!(
            !serde_json::to_string(&out).unwrap().contains("$argon2id$"),
            "no listing may carry a password hash"
        );
    }

    #[tokio::test]
    async fn a_delete_needs_the_username_typed_back_and_reports_what_went_with_it() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        db.create_session(customer, None, None, DEFAULT_TTL, None)
            .await
            .unwrap();
        let auth = auth_for(admin, Role::Admin);

        let err = call(
            &reg,
            &Delete,
            &auth,
            serde_json::json!({ "user_id": customer.get(), "confirm_username": "clientt" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(
            db.users(&TenantScope::Global)
                .by_id(customer)
                .await
                .unwrap()
                .is_some(),
            "a mistyped confirmation must delete nothing"
        );

        let out = call(
            &reg,
            &Delete,
            &auth,
            serde_json::json!({ "user_id": customer.get(), "confirm_username": "client" }),
        )
        .await
        .unwrap();
        assert_eq!(out["username"], "client");
        assert_eq!(out["sessions_ended"], 1);
        assert!(
            db.users(&TenantScope::Global)
                .by_id(customer)
                .await
                .unwrap()
                .is_none()
        );
    }
}
