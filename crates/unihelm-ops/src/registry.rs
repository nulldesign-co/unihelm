//! The registry, the context operations run in, and the dispatch path.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use serde::de::DeserializeOwned;
use unihelm_config::{ConfigEngine, TemplateSet};
use unihelm_core::{AuthContext, ErrorCode, Permission, Result, TaskId, TenantScope, UnihelmError};
use unihelm_db::Db;
use unihelm_distro::Distro;
use unihelm_distro::pkg::{LogSink, NullLog};
use unihelm_metrics::Collector;

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
    /// Renders, validates and activates every file the panel owns (spec §10.4).
    pub config: Arc<ConfigEngine>,
    /// Seals secrets at rest: ACME account keys, DNS credentials (spec §12 rule 6).
    pub master_key: Arc<unihelm_db::MasterKey>,
}

impl Services {
    /// Build the shared services, compiling every template on the way.
    ///
    /// A template that does not parse fails here, at startup, rather than the
    /// first time somebody creates a site.
    pub fn new(distro: Distro, db: Db, master_key: unihelm_db::MasterKey) -> Result<Self> {
        let mut templates = TemplateSet::load().map_err(UnihelmError::from)?;

        // Which HTTP/2 spelling this machine's nginx accepts. Read once here
        // rather than assumed: `http2 on;` arrived in 1.25.1, and Ubuntu 24.04 —
        // which this project supports and tests on — ships 1.24.0, where it is
        // an `unknown directive` that fails `nginx -t`. Every vhost the panel
        // rendered was invalid on that distribution until this existed.
        // Probed on a blocking thread: `Services::new` is synchronous and is
        // called while the agent starts, before there is a runtime to await on.
        let nginx = std::thread::spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()
                .and_then(|rt| rt.block_on(crate::nginx_survey::installed_version()))
        })
        .join()
        .unwrap_or(None);
        templates.set_http2_on(crate::nginx_survey::supports_http2_on(nginx));
        if let Some((a, b, c)) = nginx {
            tracing::info!(version = %format!("{a}.{b}.{c}"), "nginx detected");
        }

        let config = ConfigEngine::new(templates)
            .with_revisions(crate::services::DbRevisions::new(db.clone()));
        Ok(Self {
            distro,
            db,
            metrics: Arc::new(Collector::new()),
            config: Arc::new(config),
            master_key: Arc::new(master_key),
        })
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

    /// The configuration engine, for operations that write files the panel owns.
    pub fn config(&self) -> &ConfigEngine {
        &self.services.config
    }

    /// The key that seals secrets at rest.
    pub fn master_key(&self) -> &unihelm_db::MasterKey {
        &self.services.master_key
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
            UnihelmError::new(
                ErrorCode::InvalidInput,
                format!("invalid input for `{}`: {e}", T::NAME),
            )
            .with_field("input")
        })?;

        let output = self.run(ctx, typed).await?;

        serde_json::to_value(output).map_err(|e| {
            UnihelmError::internal(format!(
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
        registry.register(crate::stack::Status);
        registry.register(crate::stack::Install);
        registry.register(crate::stack::Remove);
        registry.register(crate::site::List);
        registry.register(crate::site::Create);
        registry.register(crate::site::Update);
        registry.register(crate::site::Delete);
        registry.register(crate::site::Drift);
        registry.register(crate::cert::Issue);
        registry.register(crate::cert::List);
        registry.register(crate::panel::Issue);
        registry.register(crate::adminer::Status);
        registry.register(crate::adminer::Enable::default());
        registry.register(crate::adminer::Disable);
        registry.register(crate::db::List);
        registry.register(crate::db::Create);
        registry.register(crate::db::Drop);
        registry.register(crate::db::UserCreate);
        registry.register(crate::db::UserDrop);
        registry.register(crate::db::UserPassword);
        registry.register(crate::db::Grant);
        registry.register(crate::fsops::ops::List);
        registry.register(crate::fsops::ops::Stat);
        registry.register(crate::fsops::ops::Read);
        registry.register(crate::fsops::ops::Write);
        registry.register(crate::fsops::ops::Mkdir);
        registry.register(crate::fsops::ops::Rename);
        registry.register(crate::fsops::ops::Copy);
        registry.register(crate::fsops::ops::Delete);
        registry.register(crate::fsops::ops::Chmod);
        registry.register(crate::fsops::ops::Search);
        registry.register(crate::fsops::ops::Compress);
        registry.register(crate::fsops::ops::Extract);
        registry.register(crate::fsops::ops::TrashList);
        registry.register(crate::fsops::ops::TrashRestore);
        registry.register(crate::fsops::ops::TrashPurge);
        registry.register(crate::fsops::ops::Usage);
        registry.register(crate::quota::Set);
        registry.register(crate::quota::Usage);
        registry.register(crate::quota::Backend);
        registry.register(crate::sftp::Enable);
        registry.register(crate::sftp::Disable);
        registry.register(crate::plan::List);
        registry.register(crate::plan::ListSubscriptions);
        registry.register(crate::plan::Create);
        registry.register(crate::plan::Update);
        registry.register(crate::plan::Delete);
        registry.register(crate::plan::Assign);
        registry.register(crate::plan::Suspend::live());
        registry.register(crate::plan::Unsuspend::live());
        registry.register(crate::fwops::PortOpen);
        registry.register(crate::fwops::PortClose);
        registry.register(crate::fwops::Rules);
        registry.register(crate::fwops::Ban);
        registry.register(crate::fwops::Unban);
        registry.register(crate::fwops::Bans);
        registry.register(crate::fwops::SettingsGet);
        registry.register(crate::fwops::SettingsSet);
        registry.register(crate::alerts::RulesList);
        registry.register(crate::alerts::RulesSet);
        registry.register(crate::alerts::EventsList);
        registry.register(crate::alerts::ChannelsList);
        registry.register(crate::alerts::ChannelsSet);
        registry.register(crate::alerts::ChannelsDelete);
        registry.register(crate::alerts::ChannelsTest::live());
        registry.register(crate::nodeapp::List);
        registry.register(crate::nodeapp::Create::live());
        registry.register(crate::nodeapp::Delete);
        registry.register(crate::nodeapp::Restart);
        registry.register(crate::nodeapp::Update);
        registry.register(crate::nodeapp::Logs);
        registry.register(crate::cron::List);
        registry.register(crate::cron::Set::live());
        registry.register(crate::cron::Delete::live());
        registry.register(crate::dns::Check);
        registry.register(crate::dns::ProviderSet);
        registry.register(crate::dns::IssueWildcard);
        registry.register(crate::backup::RepoInit::live());
        registry.register(crate::backup::RepoDelete);
        registry.register(crate::backup::ScheduleSet);
        registry.register(crate::backup::ScheduleDelete);
        registry.register(crate::backup::Run::live());
        registry.register(crate::backup::List::live());
        registry.register(crate::backup::Restore::live());
        registry.register(crate::wordpress::Install::live());
        registry.register(crate::wordpress::Detect);
        registry.register(crate::wordpress::Update);
        registry.register(crate::wordpress::PluginList);
        registry.register(crate::wordpress::PluginUpdate);
        registry.register(crate::wordpress::Cli);
        registry.register(crate::waf::Status);
        registry.register(crate::waf::Enable::live());
        registry.register(crate::waf::Disable);
        registry.register(crate::waf::RulesSet);
        registry.register(crate::posture::Posture);
        registry.register(crate::nginx_survey::Discover);
        registry.register(crate::runtimes::List);
        registry.register(crate::runtimes::Install);
        registry.register(crate::docker::List);
        registry.register(crate::webhook::List);
        registry.register(crate::webhook::Set);
        registry.register(crate::webhook::Delete);
        registry.register(crate::webhook::Test::live());
        registry.register(crate::plugin::List);
        registry.register(crate::plugin::Install);
        registry.register(crate::plugin::Enable);
        registry.register(crate::plugin::Disable);
        registry.register(crate::plugin::Remove);
        registry.register(crate::importer::Plan);
        registry.register(crate::importer::List);
        registry.register(crate::importer::Apply::live());
        registry.register(crate::mail::RelayGet);
        registry.register(crate::mail::DnsPublish);
        registry.register(crate::mail::RelaySet::live());
        registry.register(crate::mail::RelayTest);
        registry.register(crate::branding::Get);
        registry.register(crate::branding::Set);
        registry.register(crate::terminal::keys::List);
        registry.register(crate::terminal::keys::Add);
        registry.register(crate::terminal::keys::Remove);
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

    /// Every registered name, for the CLI's `unihelm ops list` and for the docs.
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
            return Err(UnihelmError::new(
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
    ///
    /// Public because the web terminal needs it too: a `TerminalOpen` control
    /// frame never reaches [`Self::dispatch`], so without this the agent would
    /// be taking the web process's word for who is asking — and a second copy
    /// of this logic would be a second copy that can rot (spec §11.16).
    pub async fn verify_auth(&self, claimed: &AuthContext) -> Result<AuthContext> {
        let user = self
            .services
            .db
            .users(&TenantScope::Global)
            .by_id(claimed.actor_user_id)
            .await
            .map_err(UnihelmError::from)?
            .ok_or_else(|| {
                UnihelmError::new(
                    ErrorCode::PermissionDenied,
                    "the acting account no longer exists",
                )
            })?;

        if !user.status.can_log_in() {
            return Err(UnihelmError::new(
                ErrorCode::AccountSuspended,
                "the acting account is not active",
            ));
        }

        if user.role != claimed.acting_role {
            return Err(UnihelmError::new(
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
    use unihelm_core::{Email, Role, UserId, Username};
    use unihelm_db::users::NewUser;

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

        let services = Arc::new(
            Services::new(Distro::mock(), db, unihelm_db::MasterKey::generate())
                .expect("templates compile"),
        );
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
    use unihelm_core::Role;

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
        assert_eq!(err.code.code(), "UNI-1504");
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
            .set_status(admin, unihelm_db::UserStatus::Suspended)
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
