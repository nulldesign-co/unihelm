//! Sites and their aliases (spec §11.2).

use ferrum_core::{
    Domain, ErrorCode, FerrumError, PhpVersion, SiteId, SubscriptionId, TenantScope,
};
use serde::Serialize;

use crate::scope::ScopeFilter;
use crate::{Db, DbError, Result, from_sql_time, now, to_sql_time};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteType {
    Php,
    Static,
    Proxy,
    Redirect,
}

impl SiteType {
    pub const fn as_str(self) -> &'static str {
        match self {
            SiteType::Php => "php",
            SiteType::Static => "static",
            SiteType::Proxy => "proxy",
            SiteType::Redirect => "redirect",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "php" => SiteType::Php,
            "static" => SiteType::Static,
            "proxy" => SiteType::Proxy,
            "redirect" => SiteType::Redirect,
            other => {
                return Err(DbError::Corrupt {
                    field: "sites.site_type",
                    detail: format!("unknown site type `{other}`"),
                });
            }
        })
    }

    pub const fn needs_php(self) -> bool {
        matches!(self, SiteType::Php)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteStatus {
    Provisioning,
    Active,
    Suspended,
    Failed,
}

impl SiteStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            SiteStatus::Provisioning => "provisioning",
            SiteStatus::Active => "active",
            SiteStatus::Suspended => "suspended",
            SiteStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "provisioning" => SiteStatus::Provisioning,
            "active" => SiteStatus::Active,
            "suspended" => SiteStatus::Suspended,
            "failed" => SiteStatus::Failed,
            other => {
                return Err(DbError::Corrupt {
                    field: "sites.status",
                    detail: format!("unknown status `{other}`"),
                });
            }
        })
    }
}

/// What to do about the `www.` variant of a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WwwPolicy {
    /// Serve whatever the site is configured for and nothing else.
    None,
    /// Redirect the apex to `www.`.
    Add,
    /// Redirect `www.` to the apex.
    Strip,
}

impl WwwPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            WwwPolicy::None => "none",
            WwwPolicy::Add => "add",
            WwwPolicy::Strip => "strip",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "none" => WwwPolicy::None,
            "add" => WwwPolicy::Add,
            "strip" => WwwPolicy::Strip,
            other => {
                return Err(DbError::Corrupt {
                    field: "sites.www_policy",
                    detail: format!("unknown www policy `{other}`"),
                });
            }
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Site {
    pub id: SiteId,
    pub subscription_id: SubscriptionId,
    pub domain: String,
    pub site_type: SiteType,
    pub php_version: Option<PhpVersion>,
    pub root_dir: String,
    pub status: SiteStatus,
    pub www_policy: WwwPolicy,
    pub force_https: bool,
    pub http3: bool,
    pub maintenance_mode: bool,
    pub client_max_body_size: String,
    pub custom_nginx_snippet: Option<String>,
    pub php_ini_overrides: Option<String>,
    pub rate_limit_enabled: bool,
    pub rate_limit_rps: i64,
    pub rate_limit_burst: i64,
    pub conn_limit: i64,
    pub proxy_port: Option<i64>,
    pub redirect_target: Option<String>,
    pub redirect_code: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SiteRow {
    pub id: i64,
    pub subscription_id: i64,
    pub domain: String,
    pub site_type: String,
    pub php_version: Option<String>,
    pub root_dir: String,
    pub status: String,
    pub www_policy: String,
    pub force_https: i64,
    pub http3: i64,
    pub maintenance_mode: i64,
    pub client_max_body_size: String,
    pub custom_nginx_snippet: Option<String>,
    pub php_ini_overrides: Option<String>,
    pub rate_limit_enabled: i64,
    pub rate_limit_rps: i64,
    pub rate_limit_burst: i64,
    pub conn_limit: i64,
    pub proxy_port: Option<i64>,
    pub redirect_target: Option<String>,
    pub redirect_code: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl TryFrom<SiteRow> for Site {
    type Error = DbError;

    fn try_from(r: SiteRow) -> Result<Self> {
        Ok(Site {
            id: SiteId(r.id),
            subscription_id: SubscriptionId(r.subscription_id),
            domain: r.domain,
            site_type: SiteType::parse(&r.site_type)?,
            php_version: r
                .php_version
                .as_deref()
                .map(PhpVersion::parse)
                .transpose()
                .map_err(|e| DbError::Corrupt {
                    field: "sites.php_version",
                    detail: e.detail,
                })?,
            root_dir: r.root_dir,
            status: SiteStatus::parse(&r.status)?,
            www_policy: WwwPolicy::parse(&r.www_policy)?,
            force_https: r.force_https != 0,
            http3: r.http3 != 0,
            maintenance_mode: r.maintenance_mode != 0,
            client_max_body_size: r.client_max_body_size,
            custom_nginx_snippet: r.custom_nginx_snippet,
            php_ini_overrides: r.php_ini_overrides,
            rate_limit_enabled: r.rate_limit_enabled != 0,
            rate_limit_rps: r.rate_limit_rps,
            rate_limit_burst: r.rate_limit_burst,
            conn_limit: r.conn_limit,
            proxy_port: r.proxy_port,
            redirect_target: r.redirect_target,
            redirect_code: r.redirect_code,
            created_at: from_sql_time(&r.created_at)?,
            updated_at: from_sql_time(&r.updated_at)?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SiteAlias {
    pub id: i64,
    pub site_id: SiteId,
    pub domain: String,
    pub redirect: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SiteAliasRow {
    pub id: i64,
    pub site_id: i64,
    pub domain: String,
    pub redirect: i64,
    pub created_at: String,
}

impl From<SiteAliasRow> for SiteAlias {
    fn from(r: SiteAliasRow) -> Self {
        SiteAlias {
            id: r.id,
            site_id: SiteId(r.site_id),
            domain: r.domain,
            redirect: r.redirect != 0,
        }
    }
}

/// What is needed to create a site.
#[derive(Debug, Clone)]
pub struct NewSite {
    pub subscription_id: SubscriptionId,
    pub domain: Domain,
    pub site_type: SiteType,
    pub php_version: Option<PhpVersion>,
    pub root_dir: String,
    pub proxy_port: Option<u16>,
    pub redirect_target: Option<String>,
}

/// Which domain claimed a name, so a conflict can say where to look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainOwner {
    Site { id: SiteId, domain: String },
    Alias { site_id: SiteId, domain: String },
}

pub struct SiteRepo<'a> {
    db: &'a Db,
    scope: ScopeFilter,
}

impl Db {
    pub fn sites(&self, scope: &TenantScope) -> SiteRepo<'_> {
        SiteRepo {
            db: self,
            scope: ScopeFilter::from_scope(scope),
        }
    }

    /// Is this name already claimed, as a site or as an alias?
    ///
    /// Two unique indexes cannot express uniqueness *across* two tables, so the
    /// check lives here. Without it, two vhosts could claim one `server_name`
    /// and nginx would silently serve whichever it parsed first — which is the
    /// worst class of hosting bug, because it looks like a DNS problem.
    pub async fn domain_owner(&self, domain: &str) -> Result<Option<DomainOwner>> {
        if let Some(row) =
            sqlx::query_as::<_, (i64, String)>("SELECT id, domain FROM sites WHERE domain = ?1")
                .bind(domain)
                .fetch_optional(self.pool())
                .await?
        {
            return Ok(Some(DomainOwner::Site {
                id: SiteId(row.0),
                domain: row.1,
            }));
        }
        if let Some(row) = sqlx::query_as::<_, (i64, String)>(
            "SELECT site_id, domain FROM site_aliases WHERE domain = ?1",
        )
        .bind(domain)
        .fetch_optional(self.pool())
        .await?
        {
            return Ok(Some(DomainOwner::Alias {
                site_id: SiteId(row.0),
                domain: row.1,
            }));
        }
        Ok(None)
    }

    /// Take a failed site's row back so the same domain can be tried again.
    ///
    /// A provisioning failure leaves the row behind, marked failed, so the UI
    /// can say what went wrong. Without this the row then owns the domain for
    /// ever: fix the DNS, fix the disk, try again, and the panel answers
    /// "`example.com` is already a site". That was the single most confusing
    /// thing about the first live install.
    ///
    /// Only a **failed** row, and only for the **same subscription**. Letting a
    /// different tenant reclaim it would turn one customer's failed attempt into
    /// another customer's way of taking their domain.
    pub async fn reclaim_failed_site(&self, id: SiteId, new: &NewSite) -> Result<Site> {
        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, SiteRow>(
            "UPDATE sites
             SET site_type = ?2, php_version = ?3, root_dir = ?4, proxy_port = ?5,
                 redirect_target = ?6, status = 'provisioning', updated_at = ?7
             WHERE id = ?1 AND status = 'failed'
             RETURNING *",
        )
        .bind(id.get())
        .bind(new.site_type.as_str())
        .bind(new.php_version.map(|v| v.as_str()))
        .bind(&new.root_dir)
        .bind(new.proxy_port.map(i64::from))
        .bind(&new.redirect_target)
        .bind(&ts)
        .fetch_optional(self.pool())
        .await?
        // The `status = 'failed'` guard is in the statement rather than in a
        // prior read, so two retries racing cannot both win.
        .ok_or(DbError::Conflict { what: "site" })?;
        Site::try_from(row)
    }

    /// Create a site. Not scoped: the caller has already checked that the
    /// subscription belongs to them.
    pub async fn create_site(&self, new: NewSite) -> Result<Site> {
        if new.site_type.needs_php() && new.php_version.is_none() {
            return Err(DbError::Domain(
                FerrumError::new(ErrorCode::InvalidInput, "a PHP site needs a PHP version")
                    .with_field("php_version"),
            ));
        }
        if let Some(owner) = self.domain_owner(new.domain.as_str()).await? {
            let detail = match owner {
                DomainOwner::Site { domain, .. } => format!("`{domain}` is already a site"),
                DomainOwner::Alias { domain, .. } => {
                    format!("`{domain}` is already an alias of another site")
                }
            };
            return Err(DbError::Domain(FerrumError::new(
                ErrorCode::DomainAlreadyExists,
                detail,
            )));
        }

        let ts = to_sql_time(now());
        let row = sqlx::query_as::<_, SiteRow>(
            "INSERT INTO sites (subscription_id, domain, site_type, php_version, root_dir,
                                status, proxy_port, redirect_target, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'provisioning', ?6, ?7, ?8, ?8)
             RETURNING *",
        )
        .bind(new.subscription_id.get())
        .bind(new.domain.as_str())
        .bind(new.site_type.as_str())
        .bind(new.php_version.map(|v| v.as_str()))
        .bind(&new.root_dir)
        .bind(new.proxy_port.map(i64::from))
        .bind(&new.redirect_target)
        .bind(&ts)
        .fetch_one(self.pool())
        .await?;

        Site::try_from(row)
    }

    pub async fn set_site_status(&self, id: SiteId, status: SiteStatus) -> Result<()> {
        sqlx::query("UPDATE sites SET status = ?2, updated_at = ?3 WHERE id = ?1")
            .bind(id.get())
            .bind(status.as_str())
            .bind(to_sql_time(now()))
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Every site on the server, for rendering the whole nginx tree after a
    /// template upgrade (spec §11.2).
    pub async fn all_sites(&self) -> Result<Vec<Site>> {
        let rows = sqlx::query_as::<_, SiteRow>("SELECT * FROM sites ORDER BY id ASC")
            .fetch_all(self.pool())
            .await?;
        rows.into_iter().map(Site::try_from).collect()
    }
}

/// The fields a user may change after creation.
#[derive(Debug, Clone, Default)]
pub struct SiteUpdate {
    pub php_version: Option<PhpVersion>,
    pub www_policy: Option<WwwPolicy>,
    pub force_https: Option<bool>,
    pub http3: Option<bool>,
    pub maintenance_mode: Option<bool>,
    pub client_max_body_size: Option<String>,
    /// `Some(None)` clears the snippet; `None` leaves it alone.
    pub custom_nginx_snippet: Option<Option<String>>,
    pub php_ini_overrides: Option<Option<String>>,
    pub rate_limit_enabled: Option<bool>,
    pub proxy_port: Option<u16>,
    pub redirect_target: Option<String>,
}

impl SiteRepo<'_> {
    pub async fn by_id(&self, id: SiteId) -> Result<Option<Site>> {
        let row = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, SiteRow>("SELECT * FROM sites WHERE id = ?1")
                    .bind(id.get())
                    .fetch_optional(self.db.pool())
                    .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, SiteRow>(
                    "SELECT s.* FROM sites s
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE s.id = ?1 AND u.reseller_id = ?2",
                )
                .bind(id.get())
                .bind(reseller_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, SiteRow>(
                    "SELECT s.* FROM sites s
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     WHERE s.id = ?1 AND sub.customer_id = ?2",
                )
                .bind(id.get())
                .bind(customer_id)
                .fetch_optional(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id, ..
            } => {
                sqlx::query_as::<_, SiteRow>(
                    "SELECT * FROM sites WHERE id = ?1 AND subscription_id = ?2",
                )
                .bind(id.get())
                .bind(subscription_id)
                .fetch_optional(self.db.pool())
                .await?
            }
        };
        row.map(Site::try_from).transpose()
    }

    /// Look a site up by the name it serves.
    pub async fn by_domain(&self, domain: &str) -> Result<Option<Site>> {
        let Some(owner) = self.db.domain_owner(domain).await? else {
            return Ok(None);
        };
        let id = match owner {
            DomainOwner::Site { id, .. } => id,
            DomainOwner::Alias { site_id, .. } => site_id,
        };
        self.by_id(id).await
    }

    /// Every site on one subscription, within the caller's scope.
    ///
    /// The scope check is not redundant with the subscription id: a customer
    /// who guessed another tenant's id must get an empty list, not that
    /// tenant's domains.
    pub async fn for_subscription(&self, subscription_id: SubscriptionId) -> Result<Vec<Site>> {
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, SiteRow>(
                    "SELECT * FROM sites WHERE subscription_id = ?1 ORDER BY domain ASC",
                )
                .bind(subscription_id.get())
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, SiteRow>(
                    "SELECT s.* FROM sites s
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE s.subscription_id = ?1 AND u.reseller_id = ?2
                     ORDER BY s.domain ASC",
                )
                .bind(subscription_id.get())
                .bind(reseller_id)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, SiteRow>(
                    "SELECT s.* FROM sites s
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     WHERE s.subscription_id = ?1 AND sub.customer_id = ?2
                     ORDER BY s.domain ASC",
                )
                .bind(subscription_id.get())
                .bind(customer_id)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Subscription {
                subscription_id: scoped,
                ..
            } => {
                // Asking about a different subscription than the one in scope
                // is not an error, it is an empty answer.
                if scoped != subscription_id.get() {
                    return Ok(Vec::new());
                }
                sqlx::query_as::<_, SiteRow>(
                    "SELECT * FROM sites WHERE subscription_id = ?1 ORDER BY domain ASC",
                )
                .bind(subscription_id.get())
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(Site::try_from).collect()
    }

    pub async fn list(&self, limit: i64, offset: i64) -> Result<Vec<Site>> {
        let limit = limit.clamp(1, 500);
        let rows = match self.scope {
            ScopeFilter::All => {
                sqlx::query_as::<_, SiteRow>(
                    "SELECT * FROM sites ORDER BY domain ASC LIMIT ?1 OFFSET ?2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Reseller(reseller_id) => {
                sqlx::query_as::<_, SiteRow>(
                    "SELECT s.* FROM sites s
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     JOIN users u ON u.id = sub.customer_id
                     WHERE u.reseller_id = ?1 ORDER BY s.domain ASC LIMIT ?2 OFFSET ?3",
                )
                .bind(reseller_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
            ScopeFilter::Customer(customer_id) => {
                sqlx::query_as::<_, SiteRow>(
                    "SELECT s.* FROM sites s
                     JOIN subscriptions sub ON sub.id = s.subscription_id
                     WHERE sub.customer_id = ?1 ORDER BY s.domain ASC LIMIT ?2 OFFSET ?3",
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
                sqlx::query_as::<_, SiteRow>(
                    "SELECT * FROM sites WHERE subscription_id = ?1
                     ORDER BY domain ASC LIMIT ?2 OFFSET ?3",
                )
                .bind(subscription_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(self.db.pool())
                .await?
            }
        };
        rows.into_iter().map(Site::try_from).collect()
    }

    pub async fn count(&self) -> Result<i64> {
        Ok(self.list(500, 0).await?.len() as i64)
    }

    /// Apply a partial update. Every field is optional; only what is set moves.
    pub async fn update(&self, id: SiteId, update: SiteUpdate) -> Result<Site> {
        let current = self.require(id).await?;

        // A PHP version on a site that does not run PHP would render a pool
        // nothing points at.
        if update.php_version.is_some() && !current.site_type.needs_php() {
            return Err(DbError::Domain(
                FerrumError::new(
                    ErrorCode::InvalidInput,
                    format!("a {} site does not run PHP", current.site_type.as_str()),
                )
                .with_field("php_version"),
            ));
        }

        sqlx::query(
            "UPDATE sites SET
                 php_version          = COALESCE(?2,  php_version),
                 www_policy           = COALESCE(?3,  www_policy),
                 force_https          = COALESCE(?4,  force_https),
                 http3                = COALESCE(?5,  http3),
                 maintenance_mode     = COALESCE(?6,  maintenance_mode),
                 client_max_body_size = COALESCE(?7,  client_max_body_size),
                 rate_limit_enabled   = COALESCE(?8,  rate_limit_enabled),
                 proxy_port           = COALESCE(?9,  proxy_port),
                 redirect_target      = COALESCE(?10, redirect_target),
                 updated_at           = ?11
             WHERE id = ?1",
        )
        .bind(id.get())
        .bind(update.php_version.map(|v| v.as_str()))
        .bind(update.www_policy.map(|v| v.as_str()))
        .bind(update.force_https.map(i64::from))
        .bind(update.http3.map(i64::from))
        .bind(update.maintenance_mode.map(i64::from))
        .bind(update.client_max_body_size.as_deref())
        .bind(update.rate_limit_enabled.map(i64::from))
        .bind(update.proxy_port.map(i64::from))
        .bind(update.redirect_target.as_deref())
        .bind(to_sql_time(now()))
        .execute(self.db.pool())
        .await?;

        // The two nullable text fields need explicit handling: COALESCE cannot
        // distinguish "leave it alone" from "clear it".
        if let Some(snippet) = update.custom_nginx_snippet {
            sqlx::query("UPDATE sites SET custom_nginx_snippet = ?2 WHERE id = ?1")
                .bind(id.get())
                .bind(snippet)
                .execute(self.db.pool())
                .await?;
        }
        if let Some(overrides) = update.php_ini_overrides {
            sqlx::query("UPDATE sites SET php_ini_overrides = ?2 WHERE id = ?1")
                .bind(id.get())
                .bind(overrides)
                .execute(self.db.pool())
                .await?;
        }

        self.require(id).await
    }

    pub async fn delete(&self, id: SiteId) -> Result<Site> {
        let site = self.require(id).await?;
        sqlx::query("DELETE FROM sites WHERE id = ?1")
            .bind(id.get())
            .execute(self.db.pool())
            .await?;
        Ok(site)
    }

    // --- aliases ----------------------------------------------------------

    pub async fn aliases(&self, id: SiteId) -> Result<Vec<SiteAlias>> {
        self.require(id).await?;
        let rows = sqlx::query_as::<_, SiteAliasRow>(
            "SELECT * FROM site_aliases WHERE site_id = ?1 ORDER BY domain ASC",
        )
        .bind(id.get())
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows.into_iter().map(SiteAlias::from).collect())
    }

    pub async fn add_alias(
        &self,
        id: SiteId,
        domain: &Domain,
        redirect: bool,
    ) -> Result<SiteAlias> {
        self.require(id).await?;
        if let Some(owner) = self.db.domain_owner(domain.as_str()).await? {
            let detail = match owner {
                DomainOwner::Site { domain, .. } => format!("`{domain}` is already a site"),
                DomainOwner::Alias { domain, .. } => format!("`{domain}` is already an alias"),
            };
            return Err(DbError::Domain(FerrumError::new(
                ErrorCode::DomainAlreadyExists,
                detail,
            )));
        }

        let row = sqlx::query_as::<_, SiteAliasRow>(
            "INSERT INTO site_aliases (site_id, domain, redirect, created_at)
             VALUES (?1, ?2, ?3, ?4) RETURNING *",
        )
        .bind(id.get())
        .bind(domain.as_str())
        .bind(i64::from(redirect))
        .bind(to_sql_time(now()))
        .fetch_one(self.db.pool())
        .await?;
        Ok(SiteAlias::from(row))
    }

    pub async fn remove_alias(&self, id: SiteId, domain: &str) -> Result<bool> {
        self.require(id).await?;
        let affected = sqlx::query("DELETE FROM site_aliases WHERE site_id = ?1 AND domain = ?2")
            .bind(id.get())
            .bind(domain)
            .execute(self.db.pool())
            .await?
            .rows_affected();
        Ok(affected > 0)
    }

    /// Every name this site answers to, primary first — what goes into
    /// `server_name` and into a certificate's SAN list.
    pub async fn server_names(&self, id: SiteId) -> Result<Vec<String>> {
        let site = self.require(id).await?;
        let mut names = vec![site.domain.clone()];
        names.extend(self.aliases(id).await?.into_iter().map(|a| a.domain));
        Ok(names)
    }

    async fn require(&self, id: SiteId) -> Result<Site> {
        self.by_id(id)
            .await?
            .ok_or(DbError::NotFound { what: "site" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::NewUser;
    use ferrum_core::{Email, Role, UserId, Username};

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

    #[tokio::test]
    async fn a_customer_guessing_another_tenants_subscription_id_gets_nothing() {
        // `for_subscription` takes an id from the caller, so the scope filter is
        // the whole defence: without it, "list the sites on subscription 1"
        // would be a working cross-tenant read for anyone who can count.
        let (db, mine, theirs, my_user, _) = seed().await;
        db.create_site(php_site(theirs, "theirs.example")).await.unwrap();
        db.create_site(php_site(mine, "mine.example")).await.unwrap();

        let scope = TenantScope::Customer { customer_id: my_user };
        let stolen = db.sites(&scope).for_subscription(theirs).await.unwrap();
        assert!(stolen.is_empty(), "another tenant's sites must not be readable");

        let own = db.sites(&scope).for_subscription(mine).await.unwrap();
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].domain.as_str(), "mine.example");

        // And an admin sees each of them for what they are.
        assert_eq!(
            db.sites(&TenantScope::Global).for_subscription(theirs).await.unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn a_failed_site_can_be_tried_again_on_the_same_domain() {
        // Without this the first failed attempt owns the domain for ever: fix
        // the problem, try again, and the panel answers "already a site".
        let (db, sub, _other, _, _) = seed().await;
        let site = db.create_site(php_site(sub, "example.com")).await.unwrap();
        db.set_site_status(site.id, SiteStatus::Failed).await.unwrap();

        let mut retry = php_site(sub, "example.com");
        retry.php_version = Some(PhpVersion::V84);
        let again = db.reclaim_failed_site(site.id, &retry).await.unwrap();

        assert_eq!(again.id, site.id, "the retry reuses the row, keeping its history");
        assert_eq!(again.status, SiteStatus::Provisioning);
        assert_eq!(
            again.php_version,
            Some(PhpVersion::V84),
            "a retry with different settings uses the new ones"
        );
    }

    #[tokio::test]
    async fn another_subscription_cannot_reclaim_a_failed_site() {
        // Otherwise one customer's failed attempt becomes another customer's
        // route to their domain.
        let (db, sub, other, _, _) = seed().await;
        let site = db.create_site(php_site(sub, "example.com")).await.unwrap();
        db.set_site_status(site.id, SiteStatus::Failed).await.unwrap();

        // The op layer refuses this by comparing owners; the row keeps its owner
        // either way, so a reclaim can never move a site between subscriptions.
        let stolen = db
            .reclaim_failed_site(site.id, &php_site(other, "example.com"))
            .await
            .unwrap();
        assert_eq!(
            stolen.subscription_id, sub,
            "reclaiming must never reassign ownership"
        );
    }

    #[tokio::test]
    async fn only_a_failed_site_can_be_reclaimed() {
        let (db, sub, _other, _, _) = seed().await;
        let site = db.create_site(php_site(sub, "example.com")).await.unwrap();

        // Still provisioning.
        assert!(
            db.reclaim_failed_site(site.id, &php_site(sub, "example.com"))
                .await
                .is_err()
        );

        db.set_site_status(site.id, SiteStatus::Active).await.unwrap();
        assert!(
            db.reclaim_failed_site(site.id, &php_site(sub, "example.com"))
                .await
                .is_err(),
            "a live site must never be silently rebuilt under a retry"
        );

        db.set_site_status(site.id, SiteStatus::Suspended).await.unwrap();
        assert!(
            db.reclaim_failed_site(site.id, &php_site(sub, "example.com"))
                .await
                .is_err(),
            "a suspended site is somebody's, not free to take"
        );
    }

    #[tokio::test]
    async fn two_retries_racing_produce_one_winner() {
        // The status guard is inside the UPDATE, not a read followed by a write,
        // so a double-click cannot start two provisioning runs on one row.
        let (db, sub, _other, _, _) = seed().await;
        let site = db.create_site(php_site(sub, "example.com")).await.unwrap();
        db.set_site_status(site.id, SiteStatus::Failed).await.unwrap();

        let first = db.reclaim_failed_site(site.id, &php_site(sub, "example.com")).await;
        let second = db.reclaim_failed_site(site.id, &php_site(sub, "example.com")).await;
        assert!(first.is_ok());
        assert!(second.is_err(), "the second claim must lose");
    }

    fn php_site(sub: SubscriptionId, domain: &str) -> NewSite {
        NewSite {
            subscription_id: sub,
            domain: Domain::parse(domain).unwrap(),
            site_type: SiteType::Php,
            php_version: Some(PhpVersion::V83),
            root_dir: format!("/home/ft_x/sites/{domain}/public"),
            proxy_port: None,
            redirect_target: None,
        }
    }

    #[tokio::test]
    async fn a_new_site_starts_provisioning_not_active() {
        // Until nginx has actually been reloaded, calling it active would be a
        // lie the dashboard tells its operator.
        let (db, sub, ..) = seed().await;
        let site = db.create_site(php_site(sub, "example.com")).await.unwrap();
        assert_eq!(site.status, SiteStatus::Provisioning);
        assert_eq!(site.php_version, Some(PhpVersion::V83));
        assert!(
            site.force_https,
            "HTTPS should be the default, not an upgrade"
        );
    }

    #[tokio::test]
    async fn a_php_site_without_a_version_is_refused() {
        let (db, sub, ..) = seed().await;
        let mut spec = php_site(sub, "example.com");
        spec.php_version = None;
        let err = db.create_site(spec).await.unwrap_err();
        assert!(matches!(err, DbError::Domain(_)));
    }

    #[tokio::test]
    async fn a_domain_cannot_be_claimed_twice_even_across_tenants() {
        // The bug this prevents: two vhosts with the same server_name, where
        // nginx silently serves whichever it parsed first. It looks like a DNS
        // problem for days.
        let (db, mine, theirs, ..) = seed().await;
        db.create_site(php_site(mine, "example.com")).await.unwrap();

        let err = db
            .create_site(php_site(theirs, "example.com"))
            .await
            .unwrap_err();
        match err {
            DbError::Domain(e) => assert_eq!(e.code, ErrorCode::DomainAlreadyExists),
            other => panic!("expected DomainAlreadyExists, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_domain_cannot_be_a_site_and_someone_elses_alias() {
        let (db, mine, theirs, alice, ..) = seed().await;
        let site = db.create_site(php_site(mine, "example.com")).await.unwrap();
        let global = TenantScope::Global;
        db.sites(&global)
            .add_alias(site.id, &Domain::parse("shop.example.com").unwrap(), false)
            .await
            .unwrap();

        // Another tenant tries to take the alias as their own site.
        let err = db
            .create_site(php_site(theirs, "shop.example.com"))
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Domain(_)));

        // And the reverse.
        let other = db.create_site(php_site(theirs, "other.com")).await.unwrap();
        let err = db
            .sites(&global)
            .add_alias(other.id, &Domain::parse("example.com").unwrap(), false)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Domain(_)));
        let _ = alice;
    }

    #[tokio::test]
    async fn server_names_lists_the_primary_first() {
        let (db, sub, ..) = seed().await;
        let global = TenantScope::Global;
        let site = db.create_site(php_site(sub, "example.com")).await.unwrap();
        db.sites(&global)
            .add_alias(site.id, &Domain::parse("www.example.com").unwrap(), false)
            .await
            .unwrap();
        db.sites(&global)
            .add_alias(site.id, &Domain::parse("example.net").unwrap(), true)
            .await
            .unwrap();

        let names = db.sites(&global).server_names(site.id).await.unwrap();
        assert_eq!(names[0], "example.com", "the primary must come first");
        assert_eq!(names.len(), 3);
    }

    #[tokio::test]
    async fn deleting_a_site_takes_its_aliases_with_it() {
        let (db, sub, ..) = seed().await;
        let global = TenantScope::Global;
        let site = db.create_site(php_site(sub, "example.com")).await.unwrap();
        db.sites(&global)
            .add_alias(site.id, &Domain::parse("www.example.com").unwrap(), false)
            .await
            .unwrap();

        db.sites(&global).delete(site.id).await.unwrap();
        // The alias must be released, or the name is unusable forever.
        assert!(db.domain_owner("www.example.com").await.unwrap().is_none());
        assert!(db.domain_owner("example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn one_tenant_cannot_read_or_change_anothers_site() {
        let (db, mine, theirs, alice, _bobby) = seed().await;
        let victim = db
            .create_site(php_site(theirs, "victim.com"))
            .await
            .unwrap();
        db.create_site(php_site(mine, "mine.com")).await.unwrap();

        let intruder = TenantScope::Customer { customer_id: alice };
        assert!(
            db.sites(&intruder)
                .by_id(victim.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.sites(&intruder)
                .by_domain("victim.com")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(db.sites(&intruder).list(100, 0).await.unwrap().len(), 1);

        assert!(matches!(
            db.sites(&intruder).delete(victim.id).await,
            Err(DbError::NotFound { .. })
        ));
        assert!(matches!(
            db.sites(&intruder)
                .update(victim.id, SiteUpdate::default())
                .await,
            Err(DbError::NotFound { .. })
        ));
        assert!(matches!(
            db.sites(&intruder).aliases(victim.id).await,
            Err(DbError::NotFound { .. })
        ));

        // The victim is untouched.
        assert!(
            db.sites(&TenantScope::Global)
                .by_id(victim.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_partial_update_moves_only_what_it_names() {
        let (db, sub, ..) = seed().await;
        let global = TenantScope::Global;
        let site = db.create_site(php_site(sub, "example.com")).await.unwrap();

        let updated = db
            .sites(&global)
            .update(
                site.id,
                SiteUpdate {
                    maintenance_mode: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert!(updated.maintenance_mode);
        assert_eq!(
            updated.php_version, site.php_version,
            "untouched fields must not move"
        );
        assert_eq!(updated.client_max_body_size, site.client_max_body_size);
        assert_eq!(updated.force_https, site.force_https);
    }

    #[tokio::test]
    async fn a_snippet_can_be_set_and_then_cleared() {
        // COALESCE cannot tell "leave alone" from "clear", so this path is
        // handled separately and needs its own test.
        let (db, sub, ..) = seed().await;
        let global = TenantScope::Global;
        let site = db.create_site(php_site(sub, "example.com")).await.unwrap();

        let with = db
            .sites(&global)
            .update(
                site.id,
                SiteUpdate {
                    custom_nginx_snippet: Some(Some("location /x { return 204; }".into())),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(with.custom_nginx_snippet.is_some());

        let untouched = db
            .sites(&global)
            .update(
                site.id,
                SiteUpdate {
                    http3: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(
            untouched.custom_nginx_snippet.is_some(),
            "an unrelated update must not clear it"
        );

        let cleared = db
            .sites(&global)
            .update(
                site.id,
                SiteUpdate {
                    custom_nginx_snippet: Some(None),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(cleared.custom_nginx_snippet.is_none());
    }

    #[tokio::test]
    async fn a_static_site_cannot_be_given_a_php_version() {
        let (db, sub, ..) = seed().await;
        let global = TenantScope::Global;
        let site = db
            .create_site(NewSite {
                site_type: SiteType::Static,
                php_version: None,
                ..php_site(sub, "static.example.com")
            })
            .await
            .unwrap();

        let err = db
            .sites(&global)
            .update(
                site.id,
                SiteUpdate {
                    php_version: Some(PhpVersion::V84),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Domain(_)));
    }

    #[tokio::test]
    async fn the_storage_layer_refuses_an_incoherent_site_too() {
        // The CHECK constraints are a second line of defence behind the
        // application-level validation.
        let (db, sub, ..) = seed().await;
        let bad = sqlx::query(
            "INSERT INTO sites (subscription_id, domain, site_type, root_dir, created_at, updated_at)
             VALUES (?1, 'no-port.com', 'proxy', '/x', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(sub.get())
        .execute(db.pool())
        .await;
        assert!(
            bad.is_err(),
            "a proxy site without a port must not be storable"
        );
    }

    #[tokio::test]
    async fn all_sites_is_what_a_template_upgrade_iterates() {
        let (db, mine, theirs, ..) = seed().await;
        db.create_site(php_site(mine, "a.com")).await.unwrap();
        db.create_site(php_site(theirs, "b.com")).await.unwrap();
        assert_eq!(db.all_sites().await.unwrap().len(), 2);
    }
}
