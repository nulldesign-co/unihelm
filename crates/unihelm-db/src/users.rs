//! The `users` repository.
//!
//! Reads go through [`UserRepo`], which is constructed from a
//! [`TenantScope`](unihelm_core::TenantScope) — there is no method that returns
//! "all users" without one.

use sqlx::Row;
use unihelm_core::{Email, Permission, Role, TenantScope, UserId, Username};

use crate::models::{User, UserRow, UserStatus};
use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, now, password, to_sql_time};

/// Fields needed to create an account.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub role: Role,
    pub email: Email,
    pub username: Username,
    /// Plaintext; hashed here so a caller cannot accidentally store it raw.
    pub password: String,
    pub reseller_id: Option<UserId>,
    pub full_name: Option<String>,
    pub locale: String,
}

pub struct UserRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn users(&self, scope: &TenantScope) -> UserRepo<'_> {
        UserRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    /// Look up an account by login name, **outside any tenant scope**.
    ///
    /// This is the one legitimate unscoped user query: at login time there is no
    /// session yet, so there is no scope to apply. It is a method on `Db` rather
    /// than on the repository precisely so it stands out in review.
    pub async fn find_user_for_login(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE username = ?1")
            .bind(username)
            .fetch_optional(self.pool())
            .await?;
        row.map(User::try_from).transpose()
    }

    /// True when no account exists yet — the installer uses this to decide
    /// whether to run first-time setup.
    pub async fn has_any_user(&self) -> Result<bool> {
        let row = sqlx::query("SELECT EXISTS (SELECT 1 FROM users) AS present")
            .fetch_one(self.pool())
            .await?;
        Ok(row.get::<i64, _>("present") != 0)
    }
}

impl UserRepo<'_> {
    /// Create an account. The password is hashed and policy-checked here.
    pub async fn create(&self, new: NewUser) -> Result<User> {
        let pass_hash = password::hash_password(&new.password)?;
        let ts = to_sql_time(now());

        let row = sqlx::query_as::<_, UserRow>(
            "INSERT INTO users (role, email, username, pass_hash, status, reseller_id,
                                permissions_json, full_name, locale, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'active', ?5, 'null', ?6, ?7, ?8, ?8)
             RETURNING *",
        )
        .bind(new.role.as_str())
        .bind(new.email.as_str())
        .bind(new.username.as_str())
        .bind(&pass_hash)
        .bind(new.reseller_id.map(|r| r.get()))
        .bind(&new.full_name)
        .bind(&new.locale)
        .bind(&ts)
        .fetch_one(self.db.pool())
        .await
        .map_err(map_unique_violation)?;

        User::try_from(row)
    }

    /// Fetch one account, if this scope may see it.
    pub async fn by_id(&self, id: UserId) -> Result<Option<User>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?1")
                    .bind(id.get())
                    .fetch_optional(self.db.pool())
                    .await?
            }
            // A reseller sees itself and the accounts it owns.
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, UserRow>(
                    "SELECT * FROM users WHERE id = ?1 AND (reseller_id = ?2 OR id = ?2)",
                )
                .bind(id.get())
                .bind(reseller_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            // A customer sees only itself.
            ScopeFilter::Customer(customer_id) | ScopeFilter::Subscription { customer_id, .. } => {
                sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?1 AND id = ?2")
                    .bind(id.get())
                    .bind(customer_id)
                    .fetch_optional(self.db.pool())
                    .await?
            }
        };
        row.map(User::try_from).transpose()
    }

    /// Accounts visible to this scope, newest first.
    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<User>> {
        let limit = limit.clamp(1, 500);
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, UserRow>(
                    "SELECT * FROM users ORDER BY id DESC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, UserRow>(
                    "SELECT * FROM users WHERE reseller_id = ?1 OR id = ?1
                     ORDER BY id DESC LIMIT ?2 OFFSET ?3",
                )
                .bind(reseller_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) | ScopeFilter::Subscription { customer_id, .. } => {
                sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?1")
                    .bind(customer_id)
                    .fetch_all(self.db.pool())
                    .await?
            }
        };
        rows.into_iter().map(User::try_from).collect()
    }

    pub async fn set_status(&self, id: UserId, status: UserStatus) -> Result<()> {
        self.ensure_visible(id).await?;
        sqlx::query("UPDATE users SET status = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(id.get())
            .bind(status.as_str())
            .bind(to_sql_time(now()))
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    /// Replace the password, enforcing the policy and re-hashing.
    pub async fn set_password(&self, id: UserId, new_password: &str) -> Result<()> {
        self.ensure_visible(id).await?;
        let hash = password::hash_password(new_password)?;
        sqlx::query("UPDATE users SET pass_hash = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(id.get())
            .bind(hash)
            .bind(to_sql_time(now()))
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    /// Narrow an account's permissions. `None` restores the role defaults.
    pub async fn set_permissions(&self, id: UserId, perms: Option<&[Permission]>) -> Result<()> {
        self.ensure_visible(id).await?;
        let json = serde_json::to_string(&perms).expect("permission lists always serialise");
        sqlx::query("UPDATE users SET permissions_json = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(id.get())
            .bind(json)
            .bind(to_sql_time(now()))
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    pub async fn record_login(&self, id: UserId) -> Result<()> {
        sqlx::query("UPDATE users SET last_login_at = ?2 WHERE id = ?1")
            .bind(id.get())
            .bind(to_sql_time(now()))
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    async fn ensure_visible(&self, id: UserId) -> Result<User> {
        self.by_id(id)
            .await?
            .ok_or(DbError::NotFound { what: "user" })
    }
}

/// SQLite reports a unique-index violation as a constraint error; turn it into
/// something the API can render as `UNI-1401`.
fn map_unique_violation(e: sqlx::Error) -> DbError {
    if let sqlx::Error::Database(db_err) = &e
        && db_err.message().contains("UNIQUE constraint failed")
    {
        let what = if db_err.message().contains("users.email") {
            "email"
        } else {
            "username"
        };
        return DbError::Conflict {
            what: if what == "email" { "email" } else { "username" },
        };
    }
    DbError::Sqlx(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use unihelm_core::SubscriptionId;

    async fn seed() -> (Db, UserId, UserId, UserId, UserId) {
        let db = Db::open_memory().await.unwrap();
        let global = TenantScope::Global;

        let admin = db
            .users(&global)
            .create(NewUser {
                role: Role::Admin,
                email: Email::parse("admin@example.com").unwrap(),
                username: Username::parse("admin").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();

        let reseller = db
            .users(&global)
            .create(NewUser {
                role: Role::Reseller,
                email: Email::parse("reseller@example.com").unwrap(),
                username: Username::parse("reseller").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();

        let mine = db
            .users(&global)
            .create(NewUser {
                role: Role::Customer,
                email: Email::parse("mine@example.com").unwrap(),
                username: Username::parse("mine").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: Some(reseller.id),
                full_name: None,
                locale: "fa".into(),
            })
            .await
            .unwrap();

        let theirs = db
            .users(&global)
            .create(NewUser {
                role: Role::Customer,
                email: Email::parse("theirs@example.com").unwrap(),
                username: Username::parse("theirs").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();

        (db, admin.id, reseller.id, mine.id, theirs.id)
    }

    #[tokio::test]
    async fn create_hashes_the_password() {
        let (db, admin, ..) = seed().await;
        let u = db
            .users(&TenantScope::Global)
            .by_id(admin)
            .await
            .unwrap()
            .unwrap();
        assert!(u.pass_hash.starts_with("$argon2id$"));
        assert!(!u.pass_hash.contains("a-long-enough-password"));
        assert!(password::verify_password(
            "a-long-enough-password",
            &u.pass_hash
        ));
    }

    #[tokio::test]
    async fn weak_passwords_are_refused_at_creation() {
        let db = Db::open_memory().await.unwrap();
        let err = db
            .users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Admin,
                email: Email::parse("a@example.com").unwrap(),
                username: Username::parse("weak").unwrap(),
                password: "short".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Domain(_)));
        assert!(
            !db.has_any_user().await.unwrap(),
            "nothing should have been written"
        );
    }

    #[tokio::test]
    async fn duplicate_username_and_email_are_conflicts() {
        let (db, ..) = seed().await;
        let dup = db
            .users(&TenantScope::Global)
            .create(NewUser {
                role: Role::Customer,
                email: Email::parse("new@example.com").unwrap(),
                username: Username::parse("admin").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await;
        assert!(matches!(dup, Err(DbError::Conflict { .. })));
    }

    #[tokio::test]
    async fn a_customer_can_only_see_itself() {
        let (db, admin, _reseller, mine, theirs) = seed().await;
        let scope = TenantScope::Customer { customer_id: mine };

        assert!(db.users(&scope).by_id(mine).await.unwrap().is_some());
        assert!(
            db.users(&scope).by_id(theirs).await.unwrap().is_none(),
            "cross-tenant read"
        );
        assert!(
            db.users(&scope).by_id(admin).await.unwrap().is_none(),
            "upward read"
        );
        assert_eq!(db.users(&scope).list(100, 0).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_reseller_sees_itself_and_its_customers_only() {
        let (db, admin, reseller, mine, theirs) = seed().await;
        let scope = TenantScope::Reseller {
            reseller_id: reseller,
        };

        assert!(db.users(&scope).by_id(reseller).await.unwrap().is_some());
        assert!(db.users(&scope).by_id(mine).await.unwrap().is_some());
        assert!(db.users(&scope).by_id(theirs).await.unwrap().is_none());
        assert!(db.users(&scope).by_id(admin).await.unwrap().is_none());

        let listed = db.users(&scope).list(100, 0).await.unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[tokio::test]
    async fn a_subscription_scope_behaves_like_its_customer() {
        let (db, _admin, _reseller, mine, theirs) = seed().await;
        let scope = TenantScope::Subscription {
            subscription_id: SubscriptionId(1),
            customer_id: mine,
        };
        assert!(db.users(&scope).by_id(mine).await.unwrap().is_some());
        assert!(db.users(&scope).by_id(theirs).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn writes_respect_the_scope_too() {
        let (db, _admin, _reseller, mine, theirs) = seed().await;
        let scope = TenantScope::Customer { customer_id: mine };

        let err = db
            .users(&scope)
            .set_status(theirs, UserStatus::Suspended)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DbError::NotFound { .. }),
            "a scoped write must not reach another tenant"
        );

        let err = db
            .users(&scope)
            .set_password(theirs, "a-long-enough-password")
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::NotFound { .. }));

        // The victim's password is untouched.
        let victim = db
            .users(&TenantScope::Global)
            .by_id(theirs)
            .await
            .unwrap()
            .unwrap();
        assert!(password::verify_password(
            "a-long-enough-password",
            &victim.pass_hash
        ));
    }

    #[tokio::test]
    async fn login_lookup_is_unscoped_by_design() {
        let (db, ..) = seed().await;
        assert!(db.find_user_for_login("admin").await.unwrap().is_some());
        assert!(db.find_user_for_login("nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn permission_overrides_round_trip() {
        let (db, admin, ..) = seed().await;
        let scope = TenantScope::Global;
        db.users(&scope)
            .set_permissions(admin, Some(&[Permission::SiteRead]))
            .await
            .unwrap();
        let u = db.users(&scope).by_id(admin).await.unwrap().unwrap();
        assert_eq!(u.effective_permissions(), vec![Permission::SiteRead]);

        db.users(&scope).set_permissions(admin, None).await.unwrap();
        let u = db.users(&scope).by_id(admin).await.unwrap().unwrap();
        assert_eq!(
            u.effective_permissions().len(),
            Role::Admin.default_permissions().len()
        );
    }

    #[tokio::test]
    async fn list_is_bounded_even_when_asked_for_everything() {
        let (db, ..) = seed().await;
        let all = db
            .users(&TenantScope::Global)
            .list(i64::MAX, 0)
            .await
            .unwrap();
        assert!(all.len() <= 500);
    }

    #[tokio::test]
    async fn has_any_user_drives_first_run_setup() {
        let db = Db::open_memory().await.unwrap();
        assert!(!db.has_any_user().await.unwrap());
        let (db, ..) = seed().await;
        assert!(db.has_any_user().await.unwrap());
    }
}
