//! The registry, the context operations run in, and the dispatch path.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use ferrum_core::{AuthContext, ErrorCode, FerrumError, Permission, Result, TaskId, TenantScope};
use ferrum_db::Db;
use ferrum_distro::Distro;
use ferrum_distro::pkg::{LogSink, NullLog};
use ferrum_metrics::Collector;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// How the agent should run an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Execution {
    /// Fast enough to answer in the same IPC round trip (< ~300 ms).
    Immediate,
    /// Becomes a Task: returns a task id immediately, streams logs (spec §10.1).
    Task {
        /// May the UI offer a cancel button?
        cancellable: bool,
        /// Safe to re-run after an agent restart?
        idempotent: bool,
    },
}

impl Execution {
    pub const fn is_task(self) -> bool {
        matches!(self, Execution::Task { .. })
    }
}

/// Long-lived things every operation may need.
pub struct Services {
    pub distro: Distro,
    pub db: Db,
    pub metrics: Arc<Collector>,
}

impl Services {
    pub fn new(distro: Distro, db: Db) -> Self {
        Self {
            distro,
            db,
            metrics: Arc::new(Collector::new()),
        }
    }
}

/// Everything an operation is allowed to reach.
///
/// Note what is *not* here: no raw socket, no arbitrary command runner, no
/// unscoped database handle. An operation gets the distro backends, a scoped
/// database, its caller's identity and a log sink.
pub struct OpContext {
    services: Arc<Services>,
    auth: AuthContext,
    task_id: Option<TaskId>,
    log: Arc<dyn LogSink>,
}

impl OpContext {
    pub fn new(services: Arc<Services>, auth: AuthContext) -> Self {
        Self {
            services,
            auth,
            task_id: None,
            log: Arc::new(NullLog),
        }
    }

    /// Attach the task this operation is running as, so its output streams.
    pub fn with_task(mut self, task_id: TaskId, log: Arc<dyn LogSink>) -> Self {
        self.task_id = Some(task_id);
        self.log = log;
        self
    }

    pub fn distro(&self) -> &Distro {
        &self.services.distro
    }

    pub fn db(&self) -> &Db {
        &self.services.db
    }

    pub fn metrics(&self) -> &Collector {
        &self.services.metrics
    }

    pub fn auth(&self) -> &AuthContext {
        &self.auth
    }

    pub fn scope(&self) -> &TenantScope {
        &self.auth.tenant_scope
    }

    pub fn task_id(&self) -> Option<TaskId> {
        self.task_id
    }

    /// Write a line to the task log. A no-op for immediate operations.
    pub fn log(&self, line: impl AsRef<str>) {
        self.log.line(line.as_ref());
    }

    /// The sink itself, for handing to a streaming command.
    pub fn log_sink(&self) -> &dyn LogSink {
        self.log.as_ref()
    }
}

/// The ergonomic way to write an operation: declare typed input and output and
/// the registry handles naming, permissions, parsing and error mapping.
#[async_trait]
pub trait TypedOperation: Send + Sync + 'static {
    /// Deserialised from the IPC frame's `input`. Every field should be a
    /// validated newtype or an enum, never a bare `String`.
    type Input: DeserializeOwned + Send;
    type Output: Serialize + Send;

    /// Registry key, e.g. `svc.status`. Dotted, lowercase, stable — it appears in
    /// audit rows, task records and the CLI.
    const NAME: &'static str;

    /// The permission a caller must hold.
    const PERMISSION: Permission;

    const EXECUTION: Execution;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output>;
}

/// The object-safe form the registry stores. Implemented for you by the blanket
/// impl below — write [`TypedOperation`] instead.
#[async_trait]
pub trait Operation: Send + Sync {
    fn name(&self) -> &'static str;
    fn required_permission(&self) -> Permission;
    fn execution(&self) -> Execution;
    async fn invoke(&self, ctx: &OpContext, input: serde_json::Value) -> Result<serde_json::Value>;
}

#[async_trait]
impl<T: TypedOperation> Operation for T {
    fn name(&self) -> &'static str {
        T::NAME
    }

    fn required_permission(&self) -> Permission {
        T::PERMISSION
    }

    fn execution(&self) -> Execution {
        T::EXECUTION
    }

    async fn invoke(&self, ctx: &OpContext, input: serde_json::Value) -> Result<serde_json::Value> {
        // Parsing *is* validation: newtypes reject their bad values here, before
        // a single line of the operation body runs.
        let typed: T::Input = serde_json::from_value(input).map_err(|e| {
            FerrumError::new(
                ErrorCode::InvalidInput,
                format!("invalid input for `{}`: {e}", T::NAME),
            )
            .with_field("input")
        })?;

        let output = self.run(ctx, typed).await?;

        serde_json::to_value(output).map_err(|e| {
            FerrumError::internal(format!(
                "`{}` produced output that will not serialise: {e}",
                T::NAME
            ))
        })
    }
}

/// The whitelist. If an operation is not in here, it does not exist.
pub struct OpRegistry {
    ops: BTreeMap<&'static str, Arc<dyn Operation>>,
    services: Arc<Services>,
}

impl OpRegistry {
    /// Every operation this build knows about.
    pub fn new(services: Arc<Services>) -> Self {
        let mut registry = Self {
            ops: BTreeMap::new(),
            services,
        };
        registry.register(crate::sys::Ping);
        registry.register(crate::svc::Status);
        registry.register(crate::svc::Action);
        registry.register(crate::metrics::Snapshot);
        registry
    }

    fn register<T: TypedOperation>(&mut self, op: T) {
        let previous = self.ops.insert(T::NAME, Arc::new(op));
        assert!(previous.is_none(), "duplicate operation name `{}`", T::NAME);
    }

    pub fn services(&self) -> &Arc<Services> {
        &self.services
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn Operation>> {
        self.ops.get(name)
    }

    /// Every registered name, for the CLI's `ferrum ops list` and for the docs.
    pub fn names(&self) -> Vec<&'static str> {
        self.ops.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Run an operation, having checked everything that must be checked.
    ///
    /// The order matters: unknown name, then identity, then permission, then
    /// input. A caller who is not allowed to use an operation learns only that
    /// they are not allowed — never whether their input would have been valid.
    pub async fn dispatch(
        &self,
        name: &str,
        auth: &AuthContext,
        input: serde_json::Value,
        task: Option<(TaskId, Arc<dyn LogSink>)>,
    ) -> Result<serde_json::Value> {
        let Some(op) = self.get(name) else {
            return Err(FerrumError::new(
                ErrorCode::UnknownOperation,
                format!("`{name}` is not a registered operation"),
            ));
        };

        // Defence in depth: the web process already authorised this, and we do
        // not take its word for it (spec §12 rule 4).
        let verified = self.verify_auth(auth).await?;
        verified.require(op.required_permission())?;

        let mut ctx = OpContext::new(self.services.clone(), verified);
        if let Some((task_id, log)) = task {
            ctx = ctx.with_task(task_id, log);
        }

        tracing::info!(
            op = name,
            actor = %auth.actor_user_id,
            request_id = %auth.request_id,
            "dispatching operation"
        );
        op.invoke(&ctx, input).await
    }

    /// Re-derive the caller's rights from the database.
    ///
    /// The returned context carries the *intersection* of what the web process
    /// claimed and what the account actually has, so a forged or stale frame can
    /// only ever lose privileges here, never gain them.
    async fn verify_auth(&self, claimed: &AuthContext) -> Result<AuthContext> {
        let user = self
            .services
            .db
            .users(&TenantScope::Global)
            .by_id(claimed.actor_user_id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| {
                FerrumError::new(
                    ErrorCode::PermissionDenied,
                    "the acting account no longer exists",
                )
            })?;

        if !user.status.can_log_in() {
            return Err(FerrumError::new(
                ErrorCode::AccountSuspended,
                "the acting account is not active",
            ));
        }

        if user.role != claimed.acting_role {
            return Err(FerrumError::new(
                ErrorCode::PermissionDenied,
                "the acting role does not match the account",
            ));
        }

        let actual = user.effective_permissions();
        Ok(claimed.clone().restrict_to(&actual))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use ferrum_core::{Email, Role, UserId, Username};
    use ferrum_db::users::NewUser;

    /// A registry over a mock distro and an in-memory database, plus the ids of
    /// a seeded admin and customer.
    pub async fn registry() -> (OpRegistry, UserId, UserId) {
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

        let services = Arc::new(Services::new(Distro::mock(), db));
        (OpRegistry::new(services), admin.id, customer.id)
    }

    pub fn auth_for(id: UserId, role: Role) -> AuthContext {
        let scope = match role {
            Role::Admin => TenantScope::Global,
            Role::Reseller => TenantScope::Reseller { reseller_id: id },
            Role::Customer => TenantScope::Customer { customer_id: id },
        };
        AuthContext::from_role(id, role, scope, "req-test")
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use ferrum_core::Role;

    #[tokio::test]
    async fn unknown_operations_are_refused_by_name() {
        let (reg, admin, _) = registry().await;
        let err = reg
            .dispatch(
                "site.delete.everything",
                &auth_for(admin, Role::Admin),
                serde_json::json!({}),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::UnknownOperation);
        assert_eq!(err.code.code(), "FER-1504");
    }

    #[tokio::test]
    async fn every_registered_name_is_dotted_and_lowercase() {
        let (reg, ..) = registry().await;
        assert!(!reg.is_empty());
        for name in reg.names() {
            assert!(name.contains('.'), "`{name}` should be namespaced");
            assert_eq!(
                name,
                name.to_ascii_lowercase(),
                "`{name}` should be lowercase"
            );
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'.'
                    || b == b'_'),
                "`{name}` has unexpected characters"
            );
        }
    }

    #[tokio::test]
    async fn a_customer_cannot_reach_an_admin_operation() {
        let (reg, _, customer) = registry().await;
        let err = reg
            .dispatch(
                "svc.action",
                &auth_for(customer, Role::Customer),
                serde_json::json!({ "unit": { "unit": "nginx" }, "action": "restart" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn a_forged_permission_set_gains_nothing() {
        // A compromised web process claims the customer holds ServerManage.
        let (reg, _, customer) = registry().await;
        let mut forged = auth_for(customer, Role::Customer);
        forged.permissions.insert(Permission::ServerManage);
        forged.permissions.insert(Permission::StackManage);

        let err = reg
            .dispatch(
                "svc.action",
                &forged,
                serde_json::json!({ "unit": { "unit": "nginx" }, "action": "restart" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::PermissionDenied,
            "the agent must re-derive rights from the database, not trust the frame"
        );
    }

    #[tokio::test]
    async fn a_forged_role_is_rejected_outright() {
        let (reg, _, customer) = registry().await;
        // Same user id, but claiming to be an admin.
        let forged = auth_for(customer, Role::Admin);
        let err = reg
            .dispatch("sys.ping", &forged, serde_json::json!({}), None)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert!(err.detail.contains("role"));
    }

    #[tokio::test]
    async fn a_suspended_account_cannot_run_operations() {
        let (reg, admin, _) = registry().await;
        reg.services()
            .db
            .users(&TenantScope::Global)
            .set_status(admin, ferrum_db::UserStatus::Suspended)
            .await
            .unwrap();

        let err = reg
            .dispatch(
                "sys.ping",
                &auth_for(admin, Role::Admin),
                serde_json::json!({}),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::AccountSuspended);
    }

    #[tokio::test]
    async fn a_deleted_account_cannot_run_operations() {
        let (reg, admin, _) = registry().await;
        sqlx_delete(reg.services().db.pool(), admin.get()).await;
        let err = reg
            .dispatch(
                "sys.ping",
                &auth_for(admin, Role::Admin),
                serde_json::json!({}),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn permission_is_checked_before_input_is_parsed() {
        // A caller who may not use an operation must not be able to use its
        // parser as an oracle.
        let (reg, _, customer) = registry().await;
        let err = reg
            .dispatch(
                "svc.action",
                &auth_for(customer, Role::Customer),
                serde_json::json!({ "total": "garbage" }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn malformed_input_for_a_permitted_operation_is_a_validation_error() {
        let (reg, admin, _) = registry().await;
        let err = reg
            .dispatch(
                "svc.status",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "unit": { "unit": "definitely-not-a-unit" } }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    async fn sqlx_delete(pool: &sqlx::SqlitePool, id: i64) {
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }
}
