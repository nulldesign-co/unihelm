//! Tenant databases and database users — metadata only (spec §11.4, §9).
//!
//! The engines hold the truth about what a database *contains*; these tables
//! hold only who owns what, so tenancy checks never require talking to MariaDB
//! or PostgreSQL. Passwords are deliberately absent — see the header of
//! `migrations/0005_databases.sql` for why the panel stores none, ever.

use serde::{Deserialize, Serialize};
use unihelm_core::{SubscriptionId, TenantScope};

use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

/// Which engine a database or database user lives in.
///
/// The strings `mysql` / `postgres` are stable in three places at once: the
/// `engine` CHECK constraints in migration 0005, the API wire format, and the
/// audit log. Renaming one means migrating all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbEngine {
    Mysql,
    Postgres,
}

impl DbEngine {
    pub const fn as_str(self) -> &'static str {
        match self {
            DbEngine::Mysql => "mysql",
            DbEngine::Postgres => "postgres",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "mysql" => DbEngine::Mysql,
            "postgres" => DbEngine::Postgres,
            other => {
                return Err(DbError::Corrupt {
                    field: "dbs.engine",
                    detail: format!("unknown engine `{other}`"),
                });
            }
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Database {
    pub id: i64,
    pub subscription_id: SubscriptionId,
    pub engine: DbEngine,
    pub name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DatabaseRow {
    pub id: i64,
    pub subscription_id: i64,
    pub engine: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<DatabaseRow> for Database {
    type Error = DbError;

    fn try_from(r: DatabaseRow) -> Result<Self> {
        Ok(Database {
            id: r.id,
            subscription_id: SubscriptionId(r.subscription_id),
            engine: DbEngine::parse(&r.engine)?,
            name: r.name,
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DbUser {
    pub id: i64,
    pub subscription_id: SubscriptionId,
    pub engine: DbEngine,
    pub username: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DbUserRow {
    pub id: i64,
    pub subscription_id: i64,
    pub engine: String,
    pub username: String,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<DbUserRow> for DbUser {
    type Error = DbError;

    fn try_from(r: DbUserRow) -> Result<Self> {
        Ok(DbUser {
            id: r.id,
            subscription_id: SubscriptionId(r.subscription_id),
            engine: DbEngine::parse(&r.engine)?,
            username: r.username,
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

/// What is needed to record a database. The name arrives already validated
/// (the op layer only holds a `DbName`), stored verbatim.
#[derive(Debug, Clone)]
pub struct NewDatabase {
    pub subscription_id: SubscriptionId,
    pub engine: DbEngine,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct NewDbUser {
    pub subscription_id: SubscriptionId,
    pub engine: DbEngine,
    pub username: String,
}

pub struct DatabaseRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

/// Turn a UNIQUE-index violation into a conflict the API can name, instead of
/// the generic "a database error occurred" that `DbError::Sqlx` becomes.
fn map_unique(e: sqlx::Error, what: &'static str) -> DbError {
    if e.as_database_error()
        .is_some_and(|d| d.is_unique_violation())
    {
        DbError::Conflict { what }
    } else {
        DbError::Sqlx(e)
    }
}

impl Db {
    pub fn databases(&self, scope: &TenantScope) -> DatabaseRepo<'_> {
        DatabaseRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    /// Record a database. Not scoped: the op layer has already checked that the
    /// subscription belongs to the caller (same contract as `create_site`).
    ///
    /// The UNIQUE index does the claiming, so two racing creates for one name
    /// produce exactly one row and one clean conflict — never two engine-level
    /// CREATE DATABASE attempts.
    pub async fn create_database(&self, new: NewDatabase) -> Result<Database> {
        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, DatabaseRow>(
            "INSERT INTO dbs (subscription_id, engine, name, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             RETURNING *",
        )
        .bind(new.subscription_id.get())
        .bind(new.engine.as_str())
        .bind(&new.name)
        .bind(&ts)
        .fetch_one(self.pool())
        .await
        .map_err(|e| map_unique(e, "database"))?;
        Database::try_from(row)
    }

    /// Record a database user. Same trust contract as [`Db::create_database`].
    pub async fn create_db_user(&self, new: NewDbUser) -> Result<DbUser> {
        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, DbUserRow>(
            "INSERT INTO db_users (subscription_id, engine, username, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             RETURNING *",
        )
        .bind(new.subscription_id.get())
        .bind(new.engine.as_str())
        .bind(&new.username)
        .bind(&ts)
        .fetch_one(self.pool())
        .await
        .map_err(|e| map_unique(e, "database user"))?;
        DbUser::try_from(row)
    }

    /// Who owns this name, regardless of the caller's scope?
    ///
    /// The global check exists for the same reason as `domain_owner`: a name
    /// taken by a tenant the caller cannot see is still taken, and answering
    /// "free" would let the engine-level create race the metadata insert.
    pub async fn database_by_name_global(&self, name: &str) -> Result<Option<Database>> {
        sqlx::query_as::<_, DatabaseRow>("SELECT * FROM dbs WHERE name = ?1")
            .bind(name)
            .fetch_optional(self.pool())
            .await?
            .map(Database::try_from)
            .transpose()
    }

    pub async fn db_user_by_name_global(&self, username: &str) -> Result<Option<DbUser>> {
        sqlx::query_as::<_, DbUserRow>("SELECT * FROM db_users WHERE username = ?1")
            .bind(username)
            .fetch_optional(self.pool())
            .await?
            .map(DbUser::try_from)
            .transpose()
    }

    /// A password reset changes nothing we store except "something happened",
    /// which is exactly what `updated_at` is for.
    pub async fn touch_db_user(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE db_users SET updated_at = ?2 WHERE id = ?1")
            .bind(id)
            .bind(to_sql_time(now()))
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

impl DatabaseRepo<'_> {
    pub async fn by_id(&self, id: i64) -> Result<Option<Database>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, DatabaseRow>("SELECT * FROM dbs WHERE id = ?1")
                    .bind(id)
                    .fetch_optional(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, DatabaseRow>(
                    "SELECT d.* FROM dbs d
                     JOIN subscriptions sub ON sub.id = d.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE d.id = ?1 AND u.reseller_id = ?2",
                )
                .bind(id)
                .bind(reseller_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, DatabaseRow>(
                    "SELECT d.* FROM dbs d
                     JOIN subscriptions sub ON sub.id = d.subscription_id
                     WHERE d.id = ?1 AND sub.customer_id = ?2",
                )
                .bind(id)
                .bind(customer_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, DatabaseRow>(
                    "SELECT * FROM dbs WHERE id = ?1 AND subscription_id = ?2",
                )
                .bind(id)
                .bind(subscription_id)
                .fetch_optional(self.db.pool())
                .await?
            }
        };
        row.map(Database::try_from).transpose()
    }

    /// Look a database up by name, inside the caller's scope. Someone else's
    /// database answers `None`, exactly like an id probe would.
    pub async fn by_name(&self, name: &str) -> Result<Option<Database>> {
        match self.db.database_by_name_global(name).await? {
            Some(found) => self.by_id(found.id).await,
            None => Ok(None),
        }
    }

    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<Database>> {
        let limit = limit.clamp(1, 500);
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, DatabaseRow>(
                    "SELECT * FROM dbs ORDER BY name ASC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, DatabaseRow>(
                    "SELECT d.* FROM dbs d
                     JOIN subscriptions sub ON sub.id = d.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE u.reseller_id = ?1 ORDER BY d.name ASC LIMIT ?2 OFFSET ?3",
                )
                .bind(reseller_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, DatabaseRow>(
                    "SELECT d.* FROM dbs d
                     JOIN subscriptions sub ON sub.id = d.subscription_id
                     WHERE sub.customer_id = ?1 ORDER BY d.name ASC LIMIT ?2 OFFSET ?3",
                )
                .bind(customer_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, DatabaseRow>(
                    "SELECT * FROM dbs WHERE subscription_id = ?1
                     ORDER BY name ASC LIMIT ?2 OFFSET ?3",
                )
                .bind(subscription_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(Database::try_from).collect()
    }

    /// Delete the metadata row. The op layer drops the engine-level database
    /// *first*, so a failure between the two leaves a row pointing at nothing —
    /// harmless, and the retry path (`DROP ... IF EXISTS`) cleans it up.
    pub async fn delete(&self, id: i64) -> Result<Database> {
        let found = self
            .by_id(id)
            .await?
            .ok_or(DbError::NotFound { what: "database" })?;
        sqlx::query("DELETE FROM dbs WHERE id = ?1")
            .bind(id)
            .execute(self.db.pool())
            .await?;
        Ok(found)
    }

    // --- users -------------------------------------------------------------

    pub async fn user_by_id(&self, id: i64) -> Result<Option<DbUser>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, DbUserRow>("SELECT * FROM db_users WHERE id = ?1")
                    .bind(id)
                    .fetch_optional(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, DbUserRow>(
                    "SELECT d.* FROM db_users d
                     JOIN subscriptions sub ON sub.id = d.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE d.id = ?1 AND u.reseller_id = ?2",
                )
                .bind(id)
                .bind(reseller_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, DbUserRow>(
                    "SELECT d.* FROM db_users d
                     JOIN subscriptions sub ON sub.id = d.subscription_id
                     WHERE d.id = ?1 AND sub.customer_id = ?2",
                )
                .bind(id)
                .bind(customer_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, DbUserRow>(
                    "SELECT * FROM db_users WHERE id = ?1 AND subscription_id = ?2",
                )
                .bind(id)
                .bind(subscription_id)
                .fetch_optional(self.db.pool())
                .await?
            }
        };
        row.map(DbUser::try_from).transpose()
    }

    pub async fn user_by_name(&self, username: &str) -> Result<Option<DbUser>> {
        match self.db.db_user_by_name_global(username).await? {
            Some(found) => self.user_by_id(found.id).await,
            None => Ok(None),
        }
    }

    pub async fn list_users(&self, limit: i64, offset: i64) -> Result<Vec<DbUser>> {
        let limit = limit.clamp(1, 500);
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, DbUserRow>(
                    "SELECT * FROM db_users ORDER BY username ASC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, DbUserRow>(
                    "SELECT d.* FROM db_users d
                     JOIN subscriptions sub ON sub.id = d.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE u.reseller_id = ?1 ORDER BY d.username ASC LIMIT ?2 OFFSET ?3",
                )
                .bind(reseller_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, DbUserRow>(
                    "SELECT d.* FROM db_users d
                     JOIN subscriptions sub ON sub.id = d.subscription_id
                     WHERE sub.customer_id = ?1 ORDER BY d.username ASC LIMIT ?2 OFFSET ?3",
                )
                .bind(customer_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, DbUserRow>(
                    "SELECT * FROM db_users WHERE subscription_id = ?1
                     ORDER BY username ASC LIMIT ?2 OFFSET ?3",
                )
                .bind(subscription_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(DbUser::try_from).collect()
    }

    pub async fn delete_user(&self, id: i64) -> Result<DbUser> {
        let found = self.user_by_id(id).await?.ok_or(DbError::NotFound {
            what: "database user",
        })?;
        sqlx::query("DELETE FROM db_users WHERE id = ?1")
            .bind(id)
            .execute(self.db.pool())
            .await?;
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::NewUser;
    use unihelm_core::{Email, Role, UserId, Username};

    async fn seed() -> (Db, SubscriptionId, SubscriptionId, UserId, UserId) {
        let db = Db::open_memory().await.unwrap();
        let mk = |name: &'static str| NewUser {
            role: Role::Customer,
            email: Email::parse(&format!("{name}@example.com")).unwrap(),
            username: Username::parse(name).unwrap(),
            password: "a-long-enough-password".into(),
            reseller_id: None,
            full_name: None,
            locale: "en".into(),
        };
        let a = db
            .users(&TenantScope::Global)
            .create(mk("alice"))
            .await
            .unwrap();
        let b = db
            .users(&TenantScope::Global)
            .create(mk("bobby"))
            .await
            .unwrap();
        let sa = db.create_subscription(a.id).await.unwrap();
        let sb = db.create_subscription(b.id).await.unwrap();
        (db, sa.id, sb.id, a.id, b.id)
    }

    fn mysql_db(sub: SubscriptionId, name: &str) -> NewDatabase {
        NewDatabase {
            subscription_id: sub,
            engine: DbEngine::Mysql,
            name: name.into(),
        }
    }

    fn mysql_user(sub: SubscriptionId, username: &str) -> NewDbUser {
        NewDbUser {
            subscription_id: sub,
            engine: DbEngine::Mysql,
            username: username.into(),
        }
    }

    #[tokio::test]
    async fn a_database_name_is_unique_across_the_whole_server() {
        // Even across engines: see the migration header for why one namespace.
        let (db, mine, theirs, ..) = seed().await;
        db.create_database(mysql_db(mine, "shop")).await.unwrap();

        let same_engine = db.create_database(mysql_db(theirs, "shop")).await;
        assert!(matches!(same_engine, Err(DbError::Conflict { .. })));

        let other_engine = db
            .create_database(NewDatabase {
                engine: DbEngine::Postgres,
                ..mysql_db(theirs, "shop")
            })
            .await;
        assert!(matches!(other_engine, Err(DbError::Conflict { .. })));
    }

    #[tokio::test]
    async fn a_db_username_is_unique_across_the_whole_server() {
        let (db, mine, theirs, ..) = seed().await;
        db.create_db_user(mysql_user(mine, "shop_rw"))
            .await
            .unwrap();
        let err = db.create_db_user(mysql_user(theirs, "shop_rw")).await;
        assert!(matches!(err, Err(DbError::Conflict { .. })));
    }

    #[tokio::test]
    async fn the_storage_layer_refuses_an_unknown_engine() {
        // The CHECK constraint is the second line of defence behind the enum.
        let (db, sub, ..) = seed().await;
        let bad = sqlx::query(
            "INSERT INTO dbs (subscription_id, engine, name, created_at, updated_at)
             VALUES (?1, 'mssql', 'x', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(sub.get())
        .execute(db.pool())
        .await;
        assert!(bad.is_err(), "an engine outside the CHECK must not store");
    }

    #[tokio::test]
    async fn one_customer_cannot_see_or_touch_anothers_databases() {
        let (db, mine, theirs, alice, _bobby) = seed().await;
        let victim = db
            .create_database(mysql_db(theirs, "victim"))
            .await
            .unwrap();
        db.create_database(mysql_db(mine, "minedb")).await.unwrap();

        let intruder = TenantScope::Customer { customer_id: alice };
        let repo = db.databases(&intruder);

        assert!(repo.by_id(victim.id).await.unwrap().is_none());
        assert!(repo.by_name("victim").await.unwrap().is_none());
        assert_eq!(repo.list(100, 0).await.unwrap().len(), 1);
        assert!(matches!(
            repo.delete(victim.id).await,
            Err(DbError::NotFound { .. })
        ));

        // The victim is untouched.
        assert!(
            db.databases(&TenantScope::Global)
                .by_id(victim.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn one_customer_cannot_see_or_touch_anothers_db_users() {
        let (db, mine, theirs, alice, _bobby) = seed().await;
        let victim = db
            .create_db_user(mysql_user(theirs, "victim_rw"))
            .await
            .unwrap();
        db.create_db_user(mysql_user(mine, "mine_rw"))
            .await
            .unwrap();

        let intruder = TenantScope::Customer { customer_id: alice };
        let repo = db.databases(&intruder);

        assert!(repo.user_by_id(victim.id).await.unwrap().is_none());
        assert!(repo.user_by_name("victim_rw").await.unwrap().is_none());
        assert_eq!(repo.list_users(100, 0).await.unwrap().len(), 1);
        assert!(matches!(
            repo.delete_user(victim.id).await,
            Err(DbError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn the_global_name_probe_sees_across_tenants() {
        // This is what makes "is this name free?" answer honestly before the
        // engine-level CREATE runs.
        let (db, _mine, theirs, ..) = seed().await;
        db.create_database(mysql_db(theirs, "takenname"))
            .await
            .unwrap();
        assert!(
            db.database_by_name_global("takenname")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            db.database_by_name_global("freename")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn no_password_shaped_column_exists() {
        // Guards the migration's core promise: if someone adds a password
        // column later, this fails and points at the design decision.
        let (db, ..) = seed().await;
        for table in ["dbs", "db_users"] {
            let cols: Vec<(i64, String, String, i64, Option<String>, i64)> =
                sqlx::query_as(&format!("PRAGMA table_info({table})"))
                    .fetch_all(db.pool())
                    .await
                    .unwrap();
            for (_, name, ..) in cols {
                let lower = name.to_ascii_lowercase();
                assert!(
                    !lower.contains("pass") && !lower.contains("secret") && !lower.contains("hash"),
                    "`{table}.{name}` looks like stored credential material; \
                     see migrations/0005_databases.sql for why there must be none"
                );
            }
        }
    }

    #[tokio::test]
    async fn touching_a_user_moves_only_updated_at() {
        let (db, sub, ..) = seed().await;
        let user = db
            .create_db_user(mysql_user(sub, "rotate_me"))
            .await
            .unwrap();
        // Ensure the clock can visibly advance (second resolution).
        sqlx::query("UPDATE db_users SET updated_at = '2020-01-01T00:00:00Z' WHERE id = ?1")
            .bind(user.id)
            .execute(db.pool())
            .await
            .unwrap();

        db.touch_db_user(user.id).await.unwrap();
        let after = db
            .databases(&TenantScope::Global)
            .user_by_id(user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(after.updated_at > after.created_at - time::Duration::days(3650));
        assert_eq!(after.username, "rotate_me");
        assert_ne!(to_sql_time(after.updated_at), "2020-01-01T00:00:00Z");
    }
}
