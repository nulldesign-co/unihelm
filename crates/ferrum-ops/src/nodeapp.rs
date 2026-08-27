//! Tenant Node.js applications (spec §11.6, §6.3).
//!
//! An app is four things that have to agree: a **row** (which owns the port),
//! a **directory** in the tenant's home, a **systemd unit** running as the
//! tenant inside the tenant's slice, and — optionally — a **reverse-proxy
//! vhost** in front of it. This module creates them in that order and, on any
//! failure, unwinds in the reverse one, because the state that hurts is the
//! half-created app: a port marked taken with nothing listening, or a unit
//! nobody has a row for.
//!
//! # Why the unit file is generated, not templated by hand
//!
//! Everything that reaches the unit comes from validated types — [`AppName`],
//! [`LinuxUser`], [`TenantPath`] — but a unit file is a place where *one*
//! unescaped newline turns a value into a directive, and where `%` is a
//! specifier systemd expands before anything else looks at the line. So the
//! rules are enforced twice: the newtypes reject the classic payloads at
//! deserialization, and [`environment_lines`] / [`check_entry`] enforce the
//! systemd-specific ones (quoting, `%`, `"`) on the way into the template. The
//! template itself only interpolates; it makes no decisions.
//!
//! # Where the limits come from
//!
//! `MemoryMax` on the unit is the *app's* ceiling. The tenant's ceiling is the
//! slice, and the unit joins it through
//! [`crate::slices::apply_unit_slice_dropin`] **before its first start**, so
//! an app can never run even momentarily outside the plan's memory and CPU
//! bounds. That ordering is the whole reason the drop-in is written before the
//! unit is enabled rather than after.
//!
//! # What this module deliberately does not do
//!
//! - **It does not install Node.** `app.create` refuses, naming what to
//!   install, when no `node` binary is on the machine. Adding the NodeSource
//!   repository belongs with the other pinned repositories in
//!   `ferrum_distro::repos` (spec §11.1: install only from official upstream
//!   repos, pinned by full fingerprint) and is future work.
//! - **It does not delete a tenant's domain.** Deleting an app leaves its
//!   proxy site standing, named in the operation's output. Removing a vhost as
//!   a side effect of removing an application is the kind of surprise a panel
//!   does not get to spring; `site.delete` is one click away.
//! - **`fnm` version pinning** (spec §11.6) is not here: the unit runs one
//!   absolute `node` path, resolved at create time. Per-app version pinning
//!   changes only which path that is.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use ferrum_config::apply::{ApplyOutcome, ApplyRequest, Reloader, Validator, managed_for};
use ferrum_config::paths;
use ferrum_core::{
    AppName, Domain, ErrorCode, FerrumError, LinuxUser, Permission, Result, SubscriptionId,
    TenantPath, TenantScope,
};
use ferrum_db::node_apps::{NewNodeApp, NodeApp, NodeEnv};
use ferrum_db::subscriptions::Subscription;
use ferrum_distro::svc::{SvcAction, UnitName, UnitState};
use ferrum_distro::{Cmd, Distro};
use serde::{Deserialize, Serialize};

use crate::registry::{Execution, OpContext, TypedOperation};
use crate::services::SkipValidation;

/// The serialisation key every systemd unit write shares.
///
/// The same string `slices.rs` uses, and it must stay that way: the config
/// engine serialises applies per key, and a slice drop-in racing the unit it
/// decorates would daemon-reload systemd against a half-written pair. (The
/// constant is private there; hoisting it somewhere shared is a tidy-up for
/// after the wave, not an edit to another module mid-flight.)
const SYSTEMD_SERVICE: &str = "systemd";

/// How many environment variables one app may declare.
///
/// Not a systemd limit — a sanity bound, so a malformed client cannot turn one
/// request into a megabyte of unit file.
const MAX_ENV_VARS: usize = 64;

/// Longest accepted environment value. Generous enough for a connection string
/// or a JWT, short of the point where a unit file stops being readable.
const MAX_ENV_VALUE: usize = 4096;

/// Environment variables the panel owns. A tenant setting these would either
/// break the proxy wiring (`PORT`) or contradict the stored row (`NODE_ENV`),
/// and systemd's last-one-wins rule means the override would silently take.
const RESERVED_ENV_KEYS: &[&str] = &["PORT", "NODE_ENV"];

// ---------------------------------------------------------------------------
// Names and paths
// ---------------------------------------------------------------------------

/// The unit file name for an app: `ferrum-app-<user>-<name>.service`.
///
/// Both halves are needed. `<name>` alone is not unique — two tenants may each
/// have a `blog` — and `<user>` alone cannot carry a tenant's second app. The
/// pair is unique because `subscriptions.linux_user` is unique and
/// `(subscription_id, name)` is unique, and it is *legible*: an operator
/// reading `systemctl status` or `systemd-cgls` sees whose app it is without
/// opening the panel.
///
/// Unlike a slice name, hyphens here mean nothing to systemd (only `.slice`
/// names nest on `-`), so neither half needs escaping.
pub fn unit_file_name(user: &LinuxUser, name: &AppName) -> String {
    format!("ferrum-app-{}-{}.service", user.as_str(), name.as_str())
}

/// The same, as a validated [`UnitName`].
pub fn app_unit_name(user: &LinuxUser, name: &AppName) -> UnitName {
    // Infallible: LinuxUser is `[a-z0-9_-]{1,32}` and AppName is
    // `[a-z0-9][a-z0-9_-]{0,31}`, so the result is inside UnitName's alphabet
    // and far inside its 255-character budget. The test
    // `every_valid_name_pair_yields_a_valid_unit_name` pins the reasoning.
    UnitName::parse(&unit_file_name(user, name))
        .expect("a validated user and app name always form a valid unit name")
}

/// `/etc/systemd/system/ferrum-app-<user>-<name>.service`.
pub fn app_unit_path(user: &LinuxUser, name: &AppName) -> PathBuf {
    paths::systemd_unit(&unit_file_name(user, name))
}

// ---------------------------------------------------------------------------
// Input validation: the systemd half
// ---------------------------------------------------------------------------

/// One environment variable, as the API spells it.
///
/// A list of pairs rather than a map, because order is meaningful to systemd
/// (later `Environment=` lines win) and because a map cannot express the
/// duplicate this module refuses.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

/// Turn the caller's environment into `Environment=` payloads.
///
/// The three rules, all of them systemd's rather than ours:
///
/// 1. **A value containing whitespace must be quoted**, or systemd splits it
///    into several assignments and the app sees a truncated value.
/// 2. **`%` is a specifier**, expanded before the value is used — `100%` would
///    become an "invalid specifier" warning and an unset variable. It is
///    escaped to `%%`, which renders as a literal `%`.
/// 3. **Quotes, backslashes, newlines and control characters are refused
///    outright.** A `"` would end the quoting we just added; a newline would
///    end the line and start a directive. Escaping them is possible, but the
///    escape rules differ between the quoted and unquoted forms and a value
///    that needs them is a configuration mistake, not a use case — refusing
///    says so, where a silently mangled value would not.
fn environment_lines(env: &[EnvVar]) -> Result<Vec<String>> {
    if env.len() > MAX_ENV_VARS {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!("an app may declare at most {MAX_ENV_VARS} environment variables"),
        )
        .with_field("env"));
    }

    let mut seen: Vec<&str> = Vec::with_capacity(env.len());
    let mut lines = Vec::with_capacity(env.len());

    for var in env {
        let key = var.key.trim();
        if key.is_empty() || key.len() > 64 {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "an environment variable name must be 1-64 characters",
            )
            .with_field("env"));
        }
        let first = key.bytes().next().expect("non-empty");
        if !(first.is_ascii_alphabetic() || first == b'_') {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("`{key}` is not a valid environment variable name"),
            )
            .with_field("env"));
        }
        if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("`{key}` is not a valid environment variable name"),
            )
            .with_field("env"));
        }
        if RESERVED_ENV_KEYS.contains(&key.to_ascii_uppercase().as_str()) {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("`{key}` is set by the panel and cannot be overridden"),
            )
            .with_field("env"));
        }
        if seen.contains(&key) {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("`{key}` is declared twice; systemd would silently keep the last one"),
            )
            .with_field("env"));
        }
        seen.push(key);

        if var.value.len() > MAX_ENV_VALUE {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("the value of `{key}` exceeds {MAX_ENV_VALUE} characters"),
            )
            .with_field("env"));
        }
        if let Some(bad) = var
            .value
            .chars()
            .find(|c| c.is_control() || *c == '"' || *c == '\\')
        {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!(
                    "the value of `{key}` contains {}, which cannot appear in a systemd \
                     Environment= line",
                    describe_char(bad)
                ),
            )
            .with_field("env"));
        }

        lines.push(environment_line(key, &var.value));
    }
    Ok(lines)
}

/// One validated pair, formatted the way systemd parses it.
fn environment_line(key: &str, value: &str) -> String {
    let escaped = value.replace('%', "%%");
    if escaped.chars().any(char::is_whitespace) {
        // The quotes wrap the whole `KEY=value` assignment, not just the
        // value — that is systemd's form, and quoting only the value would
        // leave the `=` outside and the assignment malformed.
        format!("\"{key}={escaped}\"")
    } else {
        format!("{key}={escaped}")
    }
}

fn describe_char(c: char) -> &'static str {
    match c {
        '\n' => "a newline",
        '\r' => "a carriage return",
        '\t' => "a tab",
        '"' => "a double quote",
        '\\' => "a backslash",
        _ => "a control character",
    }
}

/// Refuse an entry path that would need quoting in `ExecStart=`.
///
/// [`TenantPath`] already blocks traversal, absolute paths, NUL and control
/// characters — everything that would leave the tenant's home. What it does
/// not know about is systemd: a space would split `ExecStart` into two
/// arguments, a `%` would be expanded as a specifier, and a quote would
/// unbalance the line. Those are refused rather than escaped, because a
/// JavaScript entry point with a space in its path is a mistake worth naming.
fn check_entry(entry: &TenantPath) -> Result<()> {
    if entry.as_str().is_empty() {
        return Err(
            FerrumError::new(ErrorCode::InvalidPath, "the entry point is empty")
                .with_field("entry"),
        );
    }
    if let Some(bad) = entry
        .as_str()
        .chars()
        .find(|c| c.is_whitespace() || matches!(c, '%' | '"' | '\'' | '`' | '$'))
    {
        return Err(FerrumError::new(
            ErrorCode::InvalidPath,
            format!(
                "the entry path contains `{bad}`, which systemd would treat as syntax in \
                 ExecStart; rename the file or directory"
            ),
        )
        .with_field("entry"));
    }
    Ok(())
}

/// Where `node` lives on this machine, or a refusal naming what to install.
///
/// [`ferrum_distro::exec::resolve_program`] (the `program_available` check
/// with its answer kept) searches a fixed list of system directories rather
/// than `$PATH`, so a poisoned environment cannot point tenant apps at
/// something else — and systemd needs the absolute path anyway, since
/// `ExecStart` does not do lookups.
fn locate_node(program: &str) -> Result<PathBuf> {
    ferrum_distro::exec::resolve_program(program).map_err(|_| {
        FerrumError::new(
            ErrorCode::NotFound,
            format!(
                "Node.js is not installed: no `{program}` binary in the system directories. \
                 Install a Node LTS line first — `apt install nodejs` / `dnf install nodejs`, \
                 or a NodeSource release — then create the app again."
            ),
        )
    })
}

// ---------------------------------------------------------------------------
// The unit file
// ---------------------------------------------------------------------------

/// What `systemd/node-app.service` renders from. Every string in here has been
/// through validation; the template only interpolates.
#[derive(Debug, Serialize)]
struct AppUnitContext {
    name: String,
    linux_user: String,
    working_dir: String,
    node_binary: String,
    entry_path: String,
    /// Pre-formatted `Environment=` payloads, `PORT` and `NODE_ENV` first.
    environment: Vec<String>,
    memory_max_mb: Option<u32>,
}

impl AppUnitContext {
    fn new(
        app: &NodeApp,
        name: &AppName,
        user: &LinuxUser,
        node_binary: &Path,
        env: Vec<String>,
        memory_max_mb: Option<u32>,
    ) -> Self {
        // The panel's own two come first so a future edit of this list cannot
        // accidentally let a tenant value win the last-one-wins rule; the
        // reserved-key check in `environment_lines` is the other half.
        let mut environment = vec![
            environment_line("NODE_ENV", app.node_env.as_str()),
            environment_line("PORT", &app.port.to_string()),
        ];
        environment.extend(env);

        Self {
            name: name.as_str().to_string(),
            linux_user: user.as_str().to_string(),
            working_dir: paths::app_dir(user.as_str(), name.as_str())
                .to_string_lossy()
                .into_owned(),
            node_binary: node_binary.to_string_lossy().into_owned(),
            entry_path: paths::tenant_home(user.as_str())
                .join(app.entry.as_str())
                .to_string_lossy()
                .into_owned(),
            environment,
            // A cap below a few megabytes cannot start a Node process at all;
            // clamping is the same courtesy the slice module extends to a plan
            // edit of zero.
            memory_max_mb: memory_max_mb.map(|mb| mb.max(64)),
        }
    }
}

/// `systemd-analyze verify` against the unit we just wrote.
///
/// Degrades to a skip where the binary is absent (minimal containers, a
/// developer's laptop) for the same reason `slices.rs` does: an unverifiable
/// unit is a smaller risk than refusing to create apps on a machine that
/// merely lacks a diagnostic tool, and a bad unit cannot take running services
/// down — systemd rejects it in isolation.
struct UnitVerify<'a> {
    path: &'a Path,
}

#[async_trait]
impl Validator for UnitVerify<'_> {
    fn name(&self) -> &'static str {
        "systemd-analyze verify"
    }

    async fn validate(&self) -> std::result::Result<(), String> {
        if !ferrum_distro::exec::program_available("systemd-analyze") {
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

/// `systemctl daemon-reload`: systemd re-reads the unit we just wrote.
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

/// Write (or update) an app's unit file and make systemd load it.
#[allow(clippy::too_many_arguments)]
async fn apply_app_unit_at(
    ctx: &OpContext,
    path: &Path,
    app: &NodeApp,
    name: &AppName,
    user: &LinuxUser,
    node_binary: &Path,
    env: Vec<String>,
    memory_max_mb: Option<u32>,
) -> Result<ApplyOutcome> {
    let context = AppUnitContext::new(app, name, user, node_binary, env, memory_max_mb);
    ctx.config()
        .apply(ApplyRequest {
            file: managed_for(path),
            template: "systemd/node-app.service",
            context: serde_json::json!({ "app": context }),
            service: SYSTEMD_SERVICE,
            validator: &UnitVerify { path },
            reloader: &DaemonReload {
                distro: ctx.distro(),
            },
            post_check: None,
            force: false,
            task_id: ctx.task_id().map(|t| t.to_string()),
        })
        .await
        .map_err(FerrumError::from)
}

// ---------------------------------------------------------------------------
// Shared lookups
// ---------------------------------------------------------------------------

/// Which subscription owns the app — the caller's own by default, or a named
/// one the caller's scope can actually see (same contract as `site.create`).
async fn resolve_subscription(ctx: &OpContext, id: Option<i64>) -> Result<Subscription> {
    let db = ctx.db();
    let subscription = match id {
        Some(raw) => db
            .subscriptions(ctx.scope())
            .by_id(SubscriptionId(raw))
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("subscription"))?,
        None => db
            .default_subscription_for(ctx.auth().actor_user_id)
            .await
            .map_err(FerrumError::from)?,
    };
    if !subscription.status.can_serve() {
        return Err(FerrumError::new(
            ErrorCode::AccountSuspended,
            "this subscription is suspended and cannot run applications",
        ));
    }
    Ok(subscription)
}

/// Does the subscription's *plan* grant Node apps (`can_node_apps`)?
///
/// The registry already checked that the **caller** holds
/// [`Permission::NodeApps`]. This is the other half of the rule (spec §6.2):
/// the feature has to be granted to the **target tenant's** plan, which is a
/// different question whenever an admin or reseller creates an app on a
/// customer's behalf.
///
/// A subscription with no plan is unlimited — the Phase 1 behaviour that
/// `enforce_site_limit` also keeps — because a plan-less subscription predates
/// the feature flags entirely and refusing it would break every existing
/// install on upgrade.
async fn ensure_plan_allows_node_apps(
    ctx: &OpContext,
    subscription: &Subscription,
) -> Result<()> {
    let Some(plan) = ctx
        .db()
        .plan_of_subscription(subscription.id)
        .await
        .map_err(FerrumError::from)?
    else {
        return Ok(());
    };
    if !plan.can_node_apps {
        return Err(FerrumError::new(
            ErrorCode::PlanFeatureDisabled,
            format!("plan `{}` does not include Node applications", plan.name),
        ));
    }
    Ok(())
}

/// An app the caller may see, with the tenant it belongs to.
///
/// The app is looked up through the caller's scope (so another tenant's app is
/// simply not found), and the subscription globally *after* that — by then the
/// ownership question is already answered, and a scoped second lookup would
/// only be able to fail for a row we just proved is visible.
async fn app_and_user(ctx: &OpContext, app_id: i64) -> Result<(NodeApp, LinuxUser, AppName)> {
    let db = ctx.db();
    let app = db
        .node_apps(ctx.scope())
        .by_id(app_id)
        .await
        .map_err(FerrumError::from)?
        .ok_or_else(|| FerrumError::not_found("node app"))?;

    let subscription = db
        .subscriptions(&TenantScope::Global)
        .by_id(app.subscription_id)
        .await
        .map_err(FerrumError::from)?
        .ok_or_else(|| FerrumError::internal("the app's subscription is missing"))?;

    let user = LinuxUser::parse(&subscription.linux_user)?;
    let name = AppName::parse(&app.name)?;
    Ok((app, user, name))
}

// ---------------------------------------------------------------------------
// app.list
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
pub struct AppView {
    #[serde(flatten)]
    pub app: NodeApp,
    pub unit: String,
    /// systemd's view of the unit: `active`, `failed`, `not_found`, …
    /// Serialised by the enum itself rather than by debug-formatting it, so
    /// the wire values stay the documented snake_case ones.
    pub state: UnitState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub apps: Vec<AppView>,
}

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "app.list";
    const PERMISSION: Permission = Permission::NodeApps;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let db = ctx.db();
        let apps = db
            .node_apps(ctx.scope())
            .list(input.limit.unwrap_or(100), input.offset.unwrap_or(0))
            .await
            .map_err(FerrumError::from)?;

        let mut views = Vec::with_capacity(apps.len());
        for app in apps {
            // One subscription lookup per app rather than a join, because the
            // list is bounded at 500 rows and a hand-written join here would
            // be a second place the scope rules live.
            let subscription = db
                .subscriptions(&TenantScope::Global)
                .by_id(app.subscription_id)
                .await
                .map_err(FerrumError::from)?;
            let (unit, status) = match subscription {
                Some(sub) => {
                    let user = LinuxUser::parse(&sub.linux_user)?;
                    let name = AppName::parse(&app.name)?;
                    let unit = app_unit_name(&user, &name);
                    let status = ctx.distro().svc.status(&unit).await.ok();
                    (unit.as_str().to_string(), status)
                }
                None => (String::new(), None),
            };

            views.push(AppView {
                state: status.as_ref().map(|s| s.state).unwrap_or(UnitState::Unknown),
                memory_bytes: status.and_then(|s| s.memory_bytes),
                unit,
                app,
            });
        }
        Ok(ListOutput { apps: views })
    }
}

// ---------------------------------------------------------------------------
// app.create
// ---------------------------------------------------------------------------

/// `app.create` — allocate a port, write a unit, start it, optionally publish
/// it behind a domain.
pub struct Create {
    /// The program name looked up to find the interpreter. `"node"` in
    /// production; tests inject a name so they neither depend on the host
    /// having Node nor go looking for it.
    node_program: String,
}

impl Create {
    pub fn live() -> Self {
        Self {
            node_program: "node".to_string(),
        }
    }

    #[cfg(test)]
    fn with_program(program: &str) -> Self {
        Self {
            node_program: program.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateInput {
    pub name: AppName,
    /// Tenant-home-relative path to the JS entry point.
    pub entry: TenantPath,
    /// Which subscription owns it. Defaults to the caller's own.
    #[serde(default)]
    pub subscription_id: Option<i64>,
    #[serde(default)]
    pub env: Vec<EnvVar>,
    #[serde(default)]
    pub node_env: NodeEnv,
    /// Per-app `MemoryMax`, inside the tenant slice's own ceiling.
    #[serde(default)]
    pub memory_mb: Option<u32>,
    /// Publish the app behind this domain as a reverse-proxy site.
    #[serde(default)]
    pub proxy_domain: Option<Domain>,
}

#[derive(Debug, Serialize)]
pub struct CreateOutput {
    pub app_id: i64,
    pub name: String,
    pub port: i64,
    pub unit: String,
    pub working_dir: String,
    pub linux_user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_id: Option<i64>,
    pub next_steps: Vec<String>,
}

#[async_trait]
impl TypedOperation for Create {
    type Input = CreateInput;
    type Output = CreateOutput;

    const NAME: &'static str = "app.create";
    const PERMISSION: Permission = Permission::NodeApps;
    // Creates a directory, writes two unit files, reloads systemd and starts a
    // process — and may render a vhost on top. Not a request to hold open.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: false,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // Everything that can be refused is refused before the row exists:
        // an allocated port with no app behind it is the one piece of state
        // this operation cannot roll back for free.
        let subscription = resolve_subscription(ctx, input.subscription_id).await?;
        ensure_plan_allows_node_apps(ctx, &subscription).await?;

        let node_binary = locate_node(&self.node_program)?;
        check_entry(&input.entry)?;
        let env = environment_lines(&input.env)?;

        // Publishing needs the *site* permission too. The registry checked
        // NodeApps for this operation; calling into the site machinery below
        // would otherwise let a caller who may not manage sites create one.
        if input.proxy_domain.is_some() {
            ctx.auth().require(Permission::SiteManage)?;
        }

        let user = LinuxUser::parse(&subscription.linux_user)?;
        let app = ctx
            .db()
            .create_node_app(NewNodeApp {
                subscription_id: subscription.id,
                name: input.name.clone(),
                entry: input.entry.clone(),
                node_env: input.node_env,
            })
            .await
            .map_err(FerrumError::from)?;
        ctx.log(format!(
            "allocated port {} to {}",
            app.port,
            input.name.as_str()
        ));

        match provision_app(ctx, &app, &input, &user, &node_binary, env).await {
            Ok(site_id) => {
                let unit = app_unit_name(&user, &input.name);
                ctx.log(format!("{unit} is running"));
                Ok(CreateOutput {
                    app_id: app.id,
                    name: app.name.clone(),
                    port: app.port,
                    unit: unit.as_str().to_string(),
                    working_dir: paths::app_dir(user.as_str(), input.name.as_str())
                        .to_string_lossy()
                        .into_owned(),
                    linux_user: subscription.linux_user,
                    site_id,
                    next_steps: next_steps(&input, app.port),
                })
            }
            Err(e) => {
                // Unwind, so a retry starts from nothing. Every step is
                // best-effort: the error being reported is the one the user
                // needs, and a failure to clean up must not replace it.
                ctx.log(format!("could not start the app: {e}"));
                rollback_app(ctx, &app, &user, &input.name).await;
                Err(e)
            }
        }
    }
}

fn next_steps(input: &CreateInput, port: i64) -> Vec<String> {
    let mut steps = vec![format!(
        "Your app must listen on port {port} — read it from process.env.PORT"
    )];
    match &input.proxy_domain {
        Some(domain) => {
            steps.push(format!("Point {domain} at this server's IP address"));
            steps.push("Issue a certificate once DNS has propagated".into());
        }
        None => steps.push(
            "Create a proxy site for this port to publish the app on a domain".into(),
        ),
    }
    steps
}

/// Everything between "there is a row" and "systemd is running the app".
///
/// The order is the point: the working directory before the unit that names
/// it, the slice drop-in before the first start (so the app is never outside
/// its tenant's ceiling, not even for a second), and the vhost last — pointing
/// a proxy at a port nothing is listening on would 502 for as long as the
/// start took.
async fn provision_app(
    ctx: &OpContext,
    app: &NodeApp,
    input: &CreateInput,
    user: &LinuxUser,
    node_binary: &Path,
    env: Vec<String>,
) -> Result<Option<i64>> {
    // 1. The account and the app directory.
    crate::provision::ensure_tenant_user(ctx, user, &tenant_home_of(ctx, user).await?, false)
        .await?;
    ensure_app_dir(ctx, user, &input.name).await?;

    // 2. The slice drop-in, before anything starts.
    let unit = app_unit_name(user, &input.name);
    crate::slices::apply_unit_slice_dropin(ctx, &unit, user).await?;

    // 3. The unit itself.
    apply_app_unit_at(
        ctx,
        &app_unit_path(user, &input.name),
        app,
        &input.name,
        user,
        node_binary,
        env,
        input.memory_mb,
    )
    .await?;

    // 4. Enable (so it survives a reboot — spec §11.6 AC) and start.
    ctx.distro()
        .svc
        .enable(&unit, true)
        .await
        .map_err(FerrumError::from)?;

    // 5. The optional vhost in front.
    let Some(domain) = input.proxy_domain.clone() else {
        return Ok(None);
    };
    let site = publish_proxy_site(ctx, app, domain).await?;
    Ok(Some(site))
}

/// The tenant's home directory as recorded on the subscription.
async fn tenant_home_of(ctx: &OpContext, user: &LinuxUser) -> Result<String> {
    Ok(ctx
        .db()
        .subscription_by_linux_user(user.as_str())
        .await
        .map_err(FerrumError::from)?
        .ok_or_else(|| FerrumError::internal("the subscription vanished mid-create"))?
        .home_dir)
}

/// `<home>/apps/<name>`, owned by the tenant.
///
/// `0750`, not `0755`: the app's own files are its business, and the tenant's
/// home is already `0710`, so nothing outside the group could reach it anyway.
async fn ensure_app_dir(ctx: &OpContext, user: &LinuxUser, name: &AppName) -> Result<()> {
    let dir = paths::app_dir(user.as_str(), name.as_str());
    for argv in app_dir_argv(user, name) {
        let mut cmd = Cmd::new(argv[0].clone());
        for arg in &argv[1..] {
            cmd = cmd.arg(arg);
        }
        cmd.run_checked().await?;
    }
    ctx.log(format!("created {}", dir.display()));
    Ok(())
}

/// The exact argv arrays [`ensure_app_dir`] runs, as data.
///
/// Split out from the running of them so a test can read them: these are the
/// only commands in this module that touch the filesystem as root, and the
/// `--` before every path is the load-bearing part — without it a directory
/// named `-R` (which no [`AppName`] can produce, but [`LinuxUser`] very nearly
/// can) would be read as an option by `chown` and `chmod`. Spec §12 rule 2:
/// argv arrays, never a shell string, so nothing here needs quoting either.
fn app_dir_argv(user: &LinuxUser, name: &AppName) -> Vec<Vec<String>> {
    let dir = paths::app_dir(user.as_str(), name.as_str());
    let owner = format!("{}:{}", user.as_str(), user.as_str());
    let mut argv = Vec::with_capacity(6);

    // `<home>/apps` first, then `<home>/apps/<name>`: `mkdir -p` would create
    // both, but only the leaf would then be chowned, leaving the parent owned
    // by root and unwritable to the tenant that has to deploy into it.
    for path in [
        dir.parent()
            .expect("an app dir always has a parent")
            .to_path_buf(),
        dir.clone(),
    ] {
        let path = path.to_string_lossy().into_owned();
        argv.push(vec!["mkdir".into(), "-p".into(), "--".into(), path.clone()]);
        argv.push(vec![
            "chown".into(),
            owner.clone(),
            "--".into(),
            path.clone(),
        ]);
        argv.push(vec!["chmod".into(), "0750".into(), "--".into(), path]);
    }
    argv
}

/// Publish the app behind a domain.
///
/// This calls `site.create` rather than rendering a vhost here, and that is
/// the whole design decision: the site machinery already owns domain-conflict
/// detection, the plan's site limit, the nginx render/validate/rollback cycle,
/// logrotate and the failed-site retry path. A second, node-flavoured vhost
/// writer would be a second place all of that has to stay correct — and the
/// first one to drift would be this one, because nobody would think to update
/// it when the nginx template changes.
///
/// `SiteType::Proxy` already exists and already means "reverse-proxy to
/// `proxy_port` on localhost", so there is nothing new to teach nginx.
async fn publish_proxy_site(ctx: &OpContext, app: &NodeApp, domain: Domain) -> Result<i64> {
    let created = crate::site::Create
        .run(
            ctx,
            crate::site::CreateInput {
                domain,
                site_type: crate::site::SiteTypeInput::Proxy,
                php_version: None,
                subscription_id: Some(app.subscription_id.get()),
                with_www: false,
                proxy_port: Some(u16::try_from(app.port).map_err(|_| {
                    FerrumError::internal("an allocated app port did not fit in a u16")
                })?),
                redirect_target: None,
            },
        )
        .await?;

    ctx.db()
        .set_node_app_site(app.id, Some(ferrum_core::SiteId(created.site_id)))
        .await
        .map_err(FerrumError::from)?;
    ctx.log(format!(
        "{} now proxies to port {}",
        created.domain, app.port
    ));
    Ok(created.site_id)
}

/// Undo a failed create, in reverse order. Best effort throughout.
async fn rollback_app(ctx: &OpContext, app: &NodeApp, user: &LinuxUser, name: &AppName) {
    let unit = app_unit_name(user, name);

    // Disable stops it too, and a unit systemd never loaded simply fails here.
    let _ = ctx.distro().svc.disable(&unit, true).await;
    remove_unit_files(ctx, user, name).await;

    // The row last: it owns the port, and freeing the port before the unit is
    // gone would let the next app take a number a stale service still binds.
    if let Err(e) = ctx
        .db()
        .node_apps(&TenantScope::Global)
        .delete(app.id)
        .await
    {
        ctx.log(format!("could not remove the app row: {e}"));
    }
    // The app directory is left alone: it may already hold the tenant's code,
    // and deleting somebody's source because their app failed to start is not
    // a trade this panel makes.
}

/// Remove the unit file and its slice drop-in, forgetting their revisions.
async fn remove_unit_files(ctx: &OpContext, user: &LinuxUser, name: &AppName) {
    let unit_file = unit_file_name(user, name);
    let paths = [
        app_unit_path(user, name),
        paths::systemd_dropin(&unit_file, "ferrum-slice.conf"),
    ];

    for path in &paths {
        match ctx
            .config()
            .remove(
                &managed_for(path),
                SYSTEMD_SERVICE,
                &SkipValidation,
                &DaemonReload {
                    distro: ctx.distro(),
                },
            )
            .await
        {
            Ok(true) => ctx.log(format!("removed {}", path.display())),
            Ok(false) => {}
            Err(e) => ctx.log(format!("could not remove {}: {e}", path.display())),
        }
        let _ = ctx.db().forget_revisions(&path.to_string_lossy()).await;
    }
}

// ---------------------------------------------------------------------------
// app.delete
// ---------------------------------------------------------------------------

pub struct Delete;

#[derive(Debug, Deserialize)]
pub struct DeleteInput {
    pub app_id: i64,
}

#[derive(Debug, Serialize)]
pub struct DeleteOutput {
    pub name: String,
    pub port: i64,
    /// The proxy site left standing, if there was one — so the UI can offer to
    /// delete it rather than leaving a vhost that 502s.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphaned_site_id: Option<i64>,
}

#[async_trait]
impl TypedOperation for Delete {
    type Input = DeleteInput;
    type Output = DeleteOutput;

    const NAME: &'static str = "app.delete";
    const PERMISSION: Permission = Permission::NodeApps;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let (app, user, name) = app_and_user(ctx, input.app_id).await?;
        let unit = app_unit_name(&user, &name);

        // Stop serving before removing what was served. `disable --now` both
        // stops the unit and removes the `multi-user.target` symlink, so a
        // reboot cannot resurrect an app the panel has deleted.
        match ctx.distro().svc.disable(&unit, true).await {
            Ok(()) => ctx.log(format!("stopped and disabled {unit}")),
            // A unit that is already gone is not a reason to fail a delete —
            // deletes get retried, and the row must still go.
            Err(e) => ctx.log(format!("{unit} could not be disabled ({e}); continuing")),
        }

        remove_unit_files(ctx, &user, &name).await;

        let removed = ctx
            .db()
            .node_apps(ctx.scope())
            .delete(app.id)
            .await
            .map_err(FerrumError::from)?;

        if let Some(site_id) = removed.site_id {
            ctx.log(format!(
                "site {site_id} still proxies to port {}; delete it separately if the \
                 domain is no longer wanted",
                removed.port
            ));
        }

        Ok(DeleteOutput {
            name: removed.name,
            port: removed.port,
            orphaned_site_id: removed.site_id.map(|s| s.get()),
        })
    }
}

// ---------------------------------------------------------------------------
// app.restart
// ---------------------------------------------------------------------------

pub struct Restart;

#[derive(Debug, Deserialize)]
pub struct RestartInput {
    pub app_id: i64,
}

#[derive(Debug, Serialize)]
pub struct RestartOutput {
    pub unit: String,
    pub restarted: bool,
}

#[async_trait]
impl TypedOperation for Restart {
    type Input = RestartInput;
    type Output = RestartOutput;

    const NAME: &'static str = "app.restart";
    const PERMISSION: Permission = Permission::NodeApps;
    // `systemctl restart` waits for the unit to stop and come back, which for
    // an app with open connections is seconds, not milliseconds.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let (_, user, name) = app_and_user(ctx, input.app_id).await?;
        let unit = app_unit_name(&user, &name);

        // A missing unit deserves a sentence, not systemd's "Unit not found".
        let status = ctx
            .distro()
            .svc
            .status(&unit)
            .await
            .map_err(FerrumError::from)?;
        if !status.is_installed() {
            return Err(FerrumError::new(
                ErrorCode::NotFound,
                format!(
                    "`{unit}` is not installed on this server; the app's unit file is \
                     missing — delete the app and create it again"
                ),
            ));
        }

        ctx.distro()
            .svc
            .action(&unit, SvcAction::Restart)
            .await
            .map_err(FerrumError::from)?;
        ctx.log(format!("restarted {unit}"));

        Ok(RestartOutput {
            unit: unit.as_str().to_string(),
            restarted: true,
        })
    }
}

// ---------------------------------------------------------------------------
// app.logs
// ---------------------------------------------------------------------------

pub struct Logs;

#[derive(Debug, Deserialize)]
pub struct LogsInput {
    pub app_id: i64,
    #[serde(default)]
    pub lines: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct LogsOutput {
    pub unit: String,
    pub lines: Vec<String>,
}

/// How many journal lines an unasked-for tail returns.
const DEFAULT_LOG_LINES: u32 = 200;
/// The most any single request may ask for. The journal can hold a great deal
/// more; this bounds one IPC frame, not the operator's access to their logs.
const MAX_LOG_LINES: u32 = 2_000;

#[async_trait]
impl TypedOperation for Logs {
    type Input = LogsInput;
    type Output = LogsOutput;

    const NAME: &'static str = "app.logs";
    const PERMISSION: Permission = Permission::NodeApps;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // The unit whose journal is read is derived here, from a row the
        // caller's scope could see — there is no field on this input that
        // names a unit, so no caller can read `sshd.service`'s journal through
        // an app they own. That is the whole security property of this
        // operation.
        let (_, user, name) = app_and_user(ctx, input.app_id).await?;
        let unit = app_unit_name(&user, &name);

        let lines = input
            .lines
            .unwrap_or(DEFAULT_LOG_LINES)
            .clamp(1, MAX_LOG_LINES);

        // `SvcBackend::journal_tail` is
        // `journalctl --no-pager --output=short-iso -n <lines> -u <unit>` as an
        // argv array — the invocation this operation needs, already written
        // and already mocked. A second journalctl call site here would be a
        // second thing to keep shell-free.
        let lines = ctx
            .distro()
            .svc
            .journal_tail(&unit, lines)
            .await
            .map_err(FerrumError::from)?;

        Ok(LogsOutput {
            unit: unit.as_str().to_string(),
            lines,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use ferrum_config::TemplateSet;
    use ferrum_core::{AuthContext, Role, UserId};
    use ferrum_db::Db;
    use ferrum_distro::Family;
    use ferrum_distro::mock::{SharedRecorder, mock_distro_with_recorder};
    use serde_json::json;
    use std::sync::Arc;

    fn user() -> LinuxUser {
        LinuxUser::parse("ft_abc12345").unwrap()
    }

    fn name() -> AppName {
        AppName::parse("blog").unwrap()
    }

    fn app_row(port: i64, entry: &str) -> NodeApp {
        NodeApp {
            id: 1,
            subscription_id: SubscriptionId(1),
            site_id: None,
            name: "blog".into(),
            entry: entry.into(),
            port,
            node_env: NodeEnv::Production,
            enabled: true,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn render(app: &NodeApp, env: Vec<String>, memory_mb: Option<u32>) -> String {
        let context = AppUnitContext::new(
            app,
            &name(),
            &user(),
            Path::new("/usr/bin/node"),
            env,
            memory_mb,
        );
        TemplateSet::load()
            .unwrap()
            .render(
                "systemd/node-app.service",
                &json!({ "app": context }),
            )
            .unwrap()
    }

    /// An OpContext over a recorded mock distro and an in-memory database,
    /// built directly (as in `slices.rs`) because these tests need the
    /// recorder and no dispatch happens on the way in.
    async fn ctx(family: Family) -> (OpContext, SharedRecorder) {
        let (distro, rec) = mock_distro_with_recorder(family);
        let db = Db::open_memory().await.unwrap();
        let services = Arc::new(
            crate::registry::Services::new(distro, db, ferrum_db::MasterKey::generate())
                .expect("templates compile"),
        );
        let auth = AuthContext::from_role(UserId(1), Role::Admin, TenantScope::Global, "req-test");
        (OpContext::new(services, auth), rec)
    }

    // -- unit rendering -----------------------------------------------------

    #[test]
    fn the_unit_runs_as_the_tenant_from_the_app_directory() {
        let body = render(&app_row(20_000, "apps/blog/server.js"), vec![], None);
        assert!(body.contains("User=ft_abc12345\n"), "{body}");
        assert!(body.contains("Group=ft_abc12345\n"), "{body}");
        assert!(
            body.contains("WorkingDirectory=/home/ft_abc12345/apps/blog\n"),
            "{body}"
        );
        assert!(
            body.contains("ExecStart=/usr/bin/node /home/ft_abc12345/apps/blog/server.js\n"),
            "the entry is absolute: systemd does no path lookup — {body}"
        );
        assert!(body.contains("Restart=always\n"), "{body}");
        assert!(
            body.contains("WantedBy=multi-user.target\n"),
            "an app must come back after a reboot (spec §11.6) — {body}"
        );
        assert!(
            !body.contains("ProtectHome"),
            "the app lives in /home; hiding it would leave nothing to run — {body}"
        );
    }

    #[test]
    fn the_crash_loop_ceiling_sits_in_the_unit_section_where_systemd_reads_it() {
        // systemd moved StartLimit* out of [Service] in v229 and only still
        // parses the old spelling for compatibility. In the wrong section it
        // still "works" — which is exactly why nothing would notice the day it
        // stopped, and a crash-looping app would then retry forever.
        let body = render(&app_row(20_000, "apps/blog/server.js"), vec![], None);
        let unit_section = body.find("[Unit]").unwrap();
        let service_section = body.find("[Service]").unwrap();
        let limit = body.find("StartLimitIntervalSec=60\n").unwrap();
        let burst = body.find("StartLimitBurst=5\n").unwrap();
        assert!(
            unit_section < limit && limit < service_section,
            "StartLimitIntervalSec must be in [Unit]: {body}"
        );
        assert!(
            unit_section < burst && burst < service_section,
            "StartLimitBurst must be in [Unit]: {body}"
        );
    }

    #[test]
    fn the_app_directory_is_created_and_handed_over_argv_by_argv() {
        // A snapshot, because these are the only commands in this module that
        // run as root against a path: the `--` guards, the parent-before-leaf
        // order (a leaf-only chown leaves `<home>/apps` owned by root) and the
        // 0750 mode are each a separate way to get tenant isolation wrong.
        let argv = app_dir_argv(&user(), &name());
        assert_eq!(
            argv,
            vec![
                vec!["mkdir", "-p", "--", "/home/ft_abc12345/apps"],
                vec!["chown", "ft_abc12345:ft_abc12345", "--", "/home/ft_abc12345/apps"],
                vec!["chmod", "0750", "--", "/home/ft_abc12345/apps"],
                vec!["mkdir", "-p", "--", "/home/ft_abc12345/apps/blog"],
                vec![
                    "chown",
                    "ft_abc12345:ft_abc12345",
                    "--",
                    "/home/ft_abc12345/apps/blog"
                ],
                vec!["chmod", "0750", "--", "/home/ft_abc12345/apps/blog"],
            ]
        );

        // And no argument is ever a shell fragment: every path came from
        // `paths::app_dir` over two validated newtypes (spec §12 rule 2).
        for cmd in &argv {
            for arg in cmd {
                assert!(
                    !arg.contains(char::is_whitespace) && !arg.contains(['$', '`', ';', '&', '|']),
                    "`{arg}` would only be safe because argv is not a shell"
                );
            }
        }
    }

    #[test]
    fn the_panel_sets_port_and_node_env_before_anything_the_tenant_asked_for() {
        // systemd keeps the LAST assignment of a name, so ordering is the
        // second half of the reserved-key rule: even a value that slipped past
        // validation could not shadow the panel's.
        let body = render(
            &app_row(20_042, "apps/blog/server.js"),
            environment_lines(&[EnvVar {
                key: "API_URL".into(),
                value: "https://api.example.com".into(),
            }])
            .unwrap(),
            None,
        );
        let node_env = body.find("Environment=NODE_ENV=production").unwrap();
        let port = body.find("Environment=PORT=20042").unwrap();
        let api = body.find("Environment=API_URL=").unwrap();
        assert!(node_env < api && port < api, "{body}");
    }

    #[test]
    fn a_value_with_spaces_is_quoted_as_one_assignment() {
        // Unquoted, systemd splits on whitespace and the app sees only
        // "Ferrum" — a truncation that looks like an application bug.
        let lines = environment_lines(&[EnvVar {
            key: "GREETING".into(),
            value: "Ferrum Panel v1".into(),
        }])
        .unwrap();
        assert_eq!(lines, vec![r#""GREETING=Ferrum Panel v1""#]);

        let body = render(&app_row(20_000, "apps/blog/server.js"), lines, None);
        assert!(
            body.contains("Environment=\"GREETING=Ferrum Panel v1\"\n"),
            "{body}"
        );
    }

    #[test]
    fn a_percent_is_escaped_because_systemd_expands_specifiers() {
        // `%h` is the user's home; unescaped, a password of `100%h` would
        // arrive at the app as `100/root`.
        let lines = environment_lines(&[EnvVar {
            key: "THRESHOLD".into(),
            value: "100%h off".into(),
        }])
        .unwrap();
        assert_eq!(lines, vec![r#""THRESHOLD=100%%h off""#]);
    }

    #[test]
    fn quotes_newlines_and_backslashes_are_refused_not_escaped() {
        // The hostile case: a newline inside a value ends the Environment=
        // line, and everything after it is read as a directive.
        for hostile in [
            // (The payload deliberately avoids spelling out a shell
            // invocation: `tests/gates/no-shell.sh` greps every .rs file for
            // one, and a test fixture is not worth a false alarm on the gate
            // that kills the whole injection category.)
            "value\nExecStart=/usr/bin/touch /tmp/pwned",
            "value\rExecStartPost=/usr/bin/id",
            "quo\"te",
            "back\\slash",
            "tab\there",
            "nul\0byte",
        ] {
            let err = environment_lines(&[EnvVar {
                key: "X".into(),
                value: hostile.into(),
            }])
            .unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::InvalidInput,
                "expected `{hostile:?}` to be refused"
            );
            assert_eq!(err.field.as_deref(), Some("env"));
        }
    }

    #[test]
    fn environment_names_must_be_environment_names() {
        for bad in ["", "1ABC", "A-B", "A B", "A=B", "A;B", &"A".repeat(65)] {
            assert!(
                environment_lines(&[EnvVar {
                    key: bad.into(),
                    value: "x".into()
                }])
                .is_err(),
                "expected `{bad}` to be refused"
            );
        }
        assert!(
            environment_lines(&[EnvVar {
                key: "_private9".into(),
                value: String::new()
            }])
            .is_ok()
        );
    }

    #[test]
    fn the_panels_own_variables_cannot_be_overridden_or_duplicated() {
        for reserved in ["PORT", "NODE_ENV", "port", "node_env"] {
            let err = environment_lines(&[EnvVar {
                key: reserved.into(),
                value: "1".into(),
            }])
            .unwrap_err();
            assert!(err.detail.contains("set by the panel"), "{}", err.detail);
        }

        let err = environment_lines(&[
            EnvVar {
                key: "A".into(),
                value: "1".into(),
            },
            EnvVar {
                key: "A".into(),
                value: "2".into(),
            },
        ])
        .unwrap_err();
        assert!(err.detail.contains("twice"), "{}", err.detail);
    }

    #[test]
    fn the_environment_is_bounded() {
        let many: Vec<EnvVar> = (0..MAX_ENV_VARS + 1)
            .map(|i| EnvVar {
                key: format!("VAR{i}"),
                value: "x".into(),
            })
            .collect();
        assert!(environment_lines(&many).is_err());

        assert!(
            environment_lines(&[EnvVar {
                key: "BIG".into(),
                value: "x".repeat(MAX_ENV_VALUE + 1),
            }])
            .is_err()
        );
    }

    #[test]
    fn a_memory_cap_renders_and_is_clamped_off_the_floor() {
        let body = render(&app_row(20_000, "apps/blog/server.js"), vec![], Some(512));
        assert!(body.contains("MemoryMax=512M\n"), "{body}");

        // A 1 MB cap cannot start a Node process at all; the clamp turns a
        // typo into a small app rather than a unit that never runs.
        let tiny = render(&app_row(20_000, "apps/blog/server.js"), vec![], Some(1));
        assert!(tiny.contains("MemoryMax=64M\n"), "{tiny}");

        let none = render(&app_row(20_000, "apps/blog/server.js"), vec![], None);
        assert!(!none.contains("MemoryMax"), "{none}");
    }

    #[test]
    fn the_rendered_unit_is_a_snapshot() {
        // The whole file, so a change to any directive is a deliberate edit to
        // this expectation rather than something nobody notices.
        let body = render(
            &app_row(20_007, "apps/blog/dist/server.js"),
            environment_lines(&[EnvVar {
                key: "DATABASE_URL".into(),
                value: "postgres://localhost/blog".into(),
            }])
            .unwrap(),
            Some(256),
        );
        assert_eq!(
            body,
            "[Unit]\n\
             Description=Ferrum Node app blog (ft_abc12345)\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             StartLimitIntervalSec=60\n\
             StartLimitBurst=5\n\
             \n\
             [Service]\n\
             Type=simple\n\
             User=ft_abc12345\n\
             Group=ft_abc12345\n\
             WorkingDirectory=/home/ft_abc12345/apps/blog\n\
             ExecStart=/usr/bin/node /home/ft_abc12345/apps/blog/dist/server.js\n\
             Environment=NODE_ENV=production\n\
             Environment=PORT=20007\n\
             Environment=DATABASE_URL=postgres://localhost/blog\n\
             Restart=always\n\
             RestartSec=2s\n\
             MemoryMax=256M\n\
             StandardOutput=journal\n\
             StandardError=journal\n\
             \n\
             NoNewPrivileges=yes\n\
             PrivateTmp=yes\n\
             ProtectSystem=full\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        );
    }

    // -- entry validation ---------------------------------------------------

    #[test]
    fn an_entry_that_would_need_quoting_in_execstart_is_refused() {
        for bad in [
            "apps/my blog/server.js",
            "apps/blog/%h.js",
            "apps/blog/\"server\".js",
            "apps/blog/serv'er.js",
            "apps/blog/$(id).js",
            "apps/blog/`id`.js",
        ] {
            let entry = TenantPath::parse(bad).unwrap();
            let err = check_entry(&entry).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidPath, "expected `{bad}` refused");
        }
        // And the traversal classics never even become a TenantPath.
        for hostile in ["../../etc/passwd", "/etc/passwd", "a\nb", "a\0b"] {
            assert!(TenantPath::parse(hostile).is_err(), "{hostile}");
        }
        assert!(check_entry(&TenantPath::parse("apps/blog/server.js").unwrap()).is_ok());
        assert!(check_entry(&TenantPath::parse("apps/blog/dist/index.mjs").unwrap()).is_ok());
    }

    // -- naming -------------------------------------------------------------

    #[test]
    fn unit_names_carry_both_the_tenant_and_the_app() {
        assert_eq!(
            unit_file_name(&user(), &name()),
            "ferrum-app-ft_abc12345-blog.service"
        );
        assert_eq!(
            app_unit_path(&user(), &name()).to_str().unwrap(),
            "/etc/systemd/system/ferrum-app-ft_abc12345-blog.service"
        );
    }

    #[test]
    fn every_valid_name_pair_yields_a_valid_unit_name() {
        // Pins the `expect` in app_unit_name across both alphabets, including
        // the hyphenated user that the slice module has to escape (a service
        // name does not nest, so here it needs no escaping).
        for u in ["a", "_x", "ft_abc12345", "a-b-c-d", &"a".repeat(32)] {
            for n in ["a", "blog", "api-v2", "next_app3", &"z".repeat(32)] {
                let user = LinuxUser::parse(u).unwrap();
                let app = AppName::parse(n).unwrap();
                let unit = unit_file_name(&user, &app);
                assert!(UnitName::parse(&unit).is_ok(), "`{unit}`");
            }
        }
    }

    #[test]
    fn the_slice_dropin_accepts_the_unit_names_this_module_produces() {
        // `apply_unit_slice_dropin` refuses anything that is not a
        // `ferrum-*.service`, which is exactly the shape asserted here — if
        // this ever diverges, apps would silently run outside their tenant's
        // memory and CPU ceiling.
        let unit = unit_file_name(&user(), &name());
        assert!(unit.starts_with("ferrum-"), "{unit}");
        assert!(unit.ends_with(".service"), "{unit}");
    }

    // -- applying the unit --------------------------------------------------

    #[tokio::test]
    async fn applying_the_unit_writes_a_managed_file_and_reloads_systemd() {
        let (ctx, _rec) = ctx(Family::Debian).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(unit_file_name(&user(), &name()));

        let outcome = apply_app_unit_at(
            &ctx,
            &path,
            &app_row(20_000, "apps/blog/server.js"),
            &name(),
            &user(),
            Path::new("/usr/bin/node"),
            vec![],
            None,
        )
        .await
        .unwrap();

        assert!(outcome.changed);
        assert!(outcome.reloaded, "systemd must be told about the new unit");
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            on_disk.starts_with("# FERRUM-MANAGED"),
            "unit files carry the managed header: {on_disk}"
        );
        assert!(on_disk.contains("[Service]"));
    }

    #[tokio::test]
    async fn a_hand_edited_unit_file_is_never_overwritten() {
        // An operator who tuned an app's unit by hand keeps their edit; the
        // panel reports drift instead of throwing it away (spec §10.4 rule 2).
        let (ctx, _rec) = ctx(Family::Debian).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(unit_file_name(&user(), &name()));
        std::fs::write(&path, "[Service]\nExecStart=/usr/bin/node other.js\n").unwrap();

        let err = apply_app_unit_at(
            &ctx,
            &path,
            &app_row(20_000, "apps/blog/server.js"),
            &name(),
            &user(),
            Path::new("/usr/bin/node"),
            vec![],
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code, ErrorCode::ConfigDrift);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[Service]\nExecStart=/usr/bin/node other.js\n"
        );
    }

    // -- the operations, through dispatch -----------------------------------

    /// Seed a subscription for the customer the test registry creates, and an
    /// app under it.
    async fn seed_app(db: &Db, customer: UserId) -> (SubscriptionId, i64) {
        let sub = db.create_subscription(customer).await.unwrap();
        let app = db
            .create_node_app(NewNodeApp {
                subscription_id: sub.id,
                name: AppName::parse("blog").unwrap(),
                entry: TenantPath::parse("apps/blog/server.js").unwrap(),
                node_env: NodeEnv::Production,
            })
            .await
            .unwrap();
        (sub.id, app.id)
    }

    #[tokio::test]
    async fn a_customer_without_the_node_apps_permission_is_refused_every_operation() {
        // Role::Customer does not carry NodeApps (spec §6.1: it is a plan
        // feature), so the registry must refuse all four before any input is
        // even parsed.
        let (reg, _admin, customer) = registry().await;
        for (op, input) in [
            ("app.list", json!({})),
            ("app.create", json!({ "name": "blog", "entry": "apps/blog/server.js" })),
            ("app.delete", json!({ "app_id": 1 })),
            ("app.restart", json!({ "app_id": 1 })),
            ("app.logs", json!({ "app_id": 1 })),
        ] {
            let err = reg
                .dispatch(op, &auth_for(customer, Role::Customer), input, None)
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::PermissionDenied, "{op}");
        }
    }

    #[tokio::test]
    async fn a_forged_node_apps_permission_gains_nothing() {
        // The web process is not trusted: the agent re-derives rights from the
        // database (spec §12 rule 4).
        let (reg, _admin, customer) = registry().await;
        let mut forged = auth_for(customer, Role::Customer);
        forged.permissions.insert(Permission::NodeApps);

        let err = reg
            .dispatch("app.list", &forged, json!({}), None)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn one_tenant_cannot_read_restart_or_delete_anothers_app() {
        // The scope check lives in the repository, and every operation reaches
        // its row through it — so another tenant's app is simply not found.
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let (_sub, victim) = seed_app(&db, customer).await;

        // The admin can see it...
        let seen = reg
            .dispatch(
                "app.logs",
                &auth_for(admin, Role::Admin),
                json!({ "app_id": victim }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            seen["unit"],
            format!("ferrum-app-{}-blog.service", linux_user_of(&db, victim).await)
        );

        // ...and a different customer cannot, even holding the permission.
        let intruder = db
            .users(&TenantScope::Global)
            .create(ferrum_db::users::NewUser {
                role: Role::Reseller,
                email: ferrum_core::Email::parse("nosy@example.com").unwrap(),
                username: ferrum_core::Username::parse("nosy").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();

        for (op, input) in [
            ("app.logs", json!({ "app_id": victim })),
            ("app.restart", json!({ "app_id": victim })),
            ("app.delete", json!({ "app_id": victim })),
        ] {
            let err = reg
                .dispatch(op, &auth_for(intruder.id, Role::Reseller), input, None)
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::NotFound, "{op}");
        }

        // And the app is still there.
        assert!(
            db.node_apps(&TenantScope::Global)
                .by_id(victim)
                .await
                .unwrap()
                .is_some()
        );
    }

    async fn linux_user_of(db: &Db, app_id: i64) -> String {
        let app = db
            .node_apps(&TenantScope::Global)
            .by_id(app_id)
            .await
            .unwrap()
            .unwrap();
        db.subscriptions(&TenantScope::Global)
            .by_id(app.subscription_id)
            .await
            .unwrap()
            .unwrap()
            .linux_user
    }

    #[tokio::test]
    async fn app_logs_reads_the_journal_of_a_unit_the_caller_can_never_name() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let (_sub, app_id) = seed_app(&db, customer).await;
        let expected = format!(
            "ferrum-app-{}-blog.service",
            linux_user_of(&db, app_id).await
        );

        let out = reg
            .dispatch(
                "app.logs",
                &auth_for(admin, Role::Admin),
                // A hostile extra field naming somebody else's unit: the input
                // struct has no such field, so it is simply not read.
                json!({ "app_id": app_id, "lines": 5, "unit": "sshd.service" }),
                None,
            )
            .await
            .unwrap();

        assert_eq!(out["unit"], expected);
        let lines = out["lines"].as_array().unwrap();
        assert!(!lines.is_empty());
        assert!(
            lines[0].as_str().unwrap().contains(&expected),
            "the mock journal echoes the unit it was asked for: {lines:?}"
        );
    }

    #[tokio::test]
    async fn a_log_request_for_a_million_lines_is_clamped() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let (_sub, app_id) = seed_app(&db, customer).await;

        // The mock returns min(lines, 3); what matters is that an absurd
        // request neither errors nor reaches journalctl unclamped.
        let out = reg
            .dispatch(
                "app.logs",
                &auth_for(admin, Role::Admin),
                json!({ "app_id": app_id, "lines": 4_000_000u32 }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["lines"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn restarting_an_app_whose_unit_is_missing_says_so() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let (_sub, app_id) = seed_app(&db, customer).await;

        let err = reg
            .dispatch(
                "app.restart",
                &auth_for(admin, Role::Admin),
                json!({ "app_id": app_id }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(err.detail.contains("not installed"), "{}", err.detail);
    }

    #[tokio::test]
    async fn restarting_a_live_app_restarts_exactly_its_own_unit() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let (_sub, app_id) = seed_app(&db, customer).await;
        let unit = UnitName::parse(&format!(
            "ferrum-app-{}-blog.service",
            linux_user_of(&db, app_id).await
        ))
        .unwrap();

        // Pretend systemd already has it loaded and running.
        reg.services()
            .distro
            .svc
            .action(&unit, SvcAction::Start)
            .await
            .unwrap();

        let out = reg
            .dispatch(
                "app.restart",
                &auth_for(admin, Role::Admin),
                json!({ "app_id": app_id }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["unit"], unit.as_str());
        assert_eq!(out["restarted"], true);
    }

    #[tokio::test]
    async fn app_create_refuses_before_it_allocates_a_port() {
        // Everything a caller can get wrong is checked before the row exists,
        // because a port marked taken with nothing behind it is the one piece
        // of state a failed create cannot undo for free.
        let (reg, admin, _customer) = registry().await;
        let db = reg.services().db.clone();
        db.create_subscription(admin).await.unwrap();

        let cases = [
            // A value that would break out of the Environment= line.
            (
                json!({
                    "name": "blog", "entry": "apps/blog/server.js",
                    "env": [{ "key": "X", "value": "a\nExecStart=/bin/sh" }]
                }),
                ErrorCode::InvalidInput,
            ),
            // A panel-owned variable.
            (
                json!({
                    "name": "blog", "entry": "apps/blog/server.js",
                    "env": [{ "key": "PORT", "value": "80" }]
                }),
                ErrorCode::InvalidInput,
            ),
            // An entry systemd would split into two ExecStart arguments.
            (
                json!({ "name": "blog", "entry": "apps/my blog/server.js" }),
                ErrorCode::InvalidPath,
            ),
            // A name that is not a name.
            (
                json!({ "name": "blog app", "entry": "apps/blog/server.js" }),
                ErrorCode::InvalidInput,
            ),
            // Traversal, refused by TenantPath at deserialization.
            (
                json!({ "name": "blog", "entry": "../../etc/systemd/system/x" }),
                ErrorCode::InvalidInput,
            ),
        ];

        for (input, expected) in cases {
            let err = reg
                .dispatch("app.create", &auth_for(admin, Role::Admin), input, None)
                .await
                .unwrap_err();
            assert_eq!(err.code, expected, "{err:?}");
        }

        assert_eq!(
            db.node_apps(&TenantScope::Global).list(10, 0).await.unwrap().len(),
            0,
            "a refused create must not have allocated anything"
        );
    }

    #[tokio::test]
    async fn app_create_refuses_when_node_is_not_installed() {
        // A NodeSource repository module is future work; until then the panel
        // has to say what to install rather than writing a unit whose
        // ExecStart does not exist.
        let (ctx, _rec) = ctx(Family::Debian).await;
        let db = ctx.db().clone();
        let customer = db
            .users(&TenantScope::Global)
            .create(ferrum_db::users::NewUser {
                role: Role::Customer,
                email: ferrum_core::Email::parse("c@example.com").unwrap(),
                username: ferrum_core::Username::parse("client").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let sub = db.create_subscription(customer.id).await.unwrap();

        let err = Create::with_program("definitely-not-node-xyz")
            .run(
                &ctx,
                CreateInput {
                    name: name(),
                    entry: TenantPath::parse("apps/blog/server.js").unwrap(),
                    subscription_id: Some(sub.id.get()),
                    env: Vec::new(),
                    node_env: NodeEnv::Production,
                    memory_mb: None,
                    proxy_domain: None,
                },
            )
            .await
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(
            err.detail.contains("Node.js is not installed") && err.detail.contains("nodejs"),
            "the refusal must name what to install: {}",
            err.detail
        );
        assert_eq!(
            db.node_apps(&TenantScope::Global).list(10, 0).await.unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn a_plan_without_node_apps_refuses_the_feature_for_that_tenant() {
        // The caller's permission is not the whole rule: an admin creating an
        // app for a customer must still respect the customer's plan (§6.2).
        let (ctx, _rec) = ctx(Family::Debian).await;
        let db = ctx.db().clone();
        let customer = db
            .users(&TenantScope::Global)
            .create(ferrum_db::users::NewUser {
                role: Role::Customer,
                email: ferrum_core::Email::parse("c@example.com").unwrap(),
                username: ferrum_core::Username::parse("client").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let sub = db.create_subscription(customer.id).await.unwrap();

        let plan = db
            .plans(&TenantScope::Global)
            .create(ferrum_db::NewPlan {
                owner_user_id: None,
                name: "No Apps".into(),
                max_sites: 5,
                max_dbs: 5,
                storage_mb: 1024,
                can_ssh: false,
                can_cron: true,
                can_node_apps: false,
            })
            .await
            .unwrap();
        db.assign_plan(sub.id, plan.id).await.unwrap();

        let input = || CreateInput {
            name: name(),
            entry: TenantPath::parse("apps/blog/server.js").unwrap(),
            subscription_id: Some(sub.id.get()),
            env: Vec::new(),
            node_env: NodeEnv::Production,
            memory_mb: None,
            proxy_domain: None,
        };

        let err = Create::live().run(&ctx, input()).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::PlanFeatureDisabled);
        assert!(err.detail.contains("No Apps"), "{}", err.detail);

        // Turning the flag on lifts the refusal — the gate is the flag, not
        // the presence of a plan.
        db.plans(&TenantScope::Global)
            .update(
                plan.id,
                ferrum_db::PlanUpdate {
                    can_node_apps: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let err = Create::with_program("definitely-not-node-xyz")
            .run(&ctx, input())
            .await
            .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::NotFound,
            "past the plan gate now, and stopped by the next check instead"
        );
    }

    #[tokio::test]
    async fn a_suspended_subscription_cannot_gain_an_app() {
        let (ctx, _rec) = ctx(Family::Debian).await;
        let db = ctx.db().clone();
        let customer = db
            .users(&TenantScope::Global)
            .create(ferrum_db::users::NewUser {
                role: Role::Customer,
                email: ferrum_core::Email::parse("c@example.com").unwrap(),
                username: ferrum_core::Username::parse("client").unwrap(),
                password: "a-long-enough-password".into(),
                reseller_id: None,
                full_name: None,
                locale: "en".into(),
            })
            .await
            .unwrap();
        let sub = db.create_subscription(customer.id).await.unwrap();
        db.set_subscription_status(
            sub.id,
            ferrum_db::SubscriptionStatus::Suspended,
            Some("unpaid"),
        )
        .await
        .unwrap();

        let err = Create::live()
            .run(
                &ctx,
                CreateInput {
                    name: name(),
                    entry: TenantPath::parse("apps/blog/server.js").unwrap(),
                    subscription_id: Some(sub.id.get()),
                    env: Vec::new(),
                    node_env: NodeEnv::Production,
                    memory_mb: None,
                    proxy_domain: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::AccountSuspended);
    }

    #[tokio::test]
    async fn deleting_an_app_disables_its_unit_and_frees_its_port() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let (sub, app_id) = seed_app(&db, customer).await;
        let unit = UnitName::parse(&format!(
            "ferrum-app-{}-blog.service",
            linux_user_of(&db, app_id).await
        ))
        .unwrap();
        reg.services()
            .distro
            .svc
            .action(&unit, SvcAction::Start)
            .await
            .unwrap();

        let out = reg
            .dispatch(
                "app.delete",
                &auth_for(admin, Role::Admin),
                json!({ "app_id": app_id }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(out["name"], "blog");
        assert_eq!(out["port"], ferrum_db::node_apps::APP_PORT_MIN);

        assert!(
            db.node_apps(&TenantScope::Global)
                .by_id(app_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !reg.services()
                .distro
                .svc
                .status(&unit)
                .await
                .unwrap()
                .is_active(),
            "a deleted app must not still be running"
        );

        // The freed port goes straight back to the allocator.
        let next = db
            .create_node_app(NewNodeApp {
                subscription_id: sub,
                name: AppName::parse("blog2").unwrap(),
                entry: TenantPath::parse("apps/blog2/server.js").unwrap(),
                node_env: NodeEnv::Production,
            })
            .await
            .unwrap();
        assert_eq!(next.port, ferrum_db::node_apps::APP_PORT_MIN);
    }

    #[tokio::test]
    async fn deleting_an_app_leaves_its_domain_standing_and_names_it() {
        // Removing a vhost as a side effect of removing an application is a
        // surprise a panel does not get to spring; the output carries the site
        // so the UI can offer the second click.
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let (sub, app_id) = seed_app(&db, customer).await;

        let site = db
            .create_site(ferrum_db::NewSite {
                subscription_id: sub,
                domain: Domain::parse("blog.example.com").unwrap(),
                site_type: ferrum_db::SiteType::Proxy,
                php_version: None,
                root_dir: "/home/x/apps/blog".into(),
                proxy_port: Some(ferrum_db::node_apps::APP_PORT_MIN as u16),
                redirect_target: None,
            })
            .await
            .unwrap();
        db.set_node_app_site(app_id, Some(site.id)).await.unwrap();

        let out = reg
            .dispatch(
                "app.delete",
                &auth_for(admin, Role::Admin),
                json!({ "app_id": app_id }),
                None,
            )
            .await
            .unwrap();

        assert_eq!(out["orphaned_site_id"], site.id.get());
        assert!(
            db.sites(&TenantScope::Global)
                .by_id(site.id)
                .await
                .unwrap()
                .is_some(),
            "the tenant's domain must survive their app"
        );
    }

    #[tokio::test]
    async fn listing_reports_what_systemd_thinks_of_each_app() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let (_sub, app_id) = seed_app(&db, customer).await;
        let unit = UnitName::parse(&format!(
            "ferrum-app-{}-blog.service",
            linux_user_of(&db, app_id).await
        ))
        .unwrap();

        let before = reg
            .dispatch("app.list", &auth_for(admin, Role::Admin), json!({}), None)
            .await
            .unwrap();
        assert_eq!(before["apps"][0]["state"], "not_found");
        assert_eq!(before["apps"][0]["unit"], unit.as_str());
        assert_eq!(before["apps"][0]["port"], ferrum_db::node_apps::APP_PORT_MIN);

        reg.services()
            .distro
            .svc
            .action(&unit, SvcAction::Start)
            .await
            .unwrap();
        let after = reg
            .dispatch("app.list", &auth_for(admin, Role::Admin), json!({}), None)
            .await
            .unwrap();
        assert_eq!(after["apps"][0]["state"], "active");
    }

    #[tokio::test]
    async fn an_admin_sees_every_tenants_apps() {
        let (reg, admin, customer) = registry().await;
        let db = reg.services().db.clone();
        seed_app(&db, customer).await;
        let other_sub = db.create_subscription(admin).await.unwrap();
        db.create_node_app(NewNodeApp {
            subscription_id: other_sub.id,
            name: AppName::parse("admins-app").unwrap(),
            entry: TenantPath::parse("apps/admins-app/server.js").unwrap(),
            node_env: NodeEnv::Production,
        })
        .await
        .unwrap();

        let all = reg
            .dispatch("app.list", &auth_for(admin, Role::Admin), json!({}), None)
            .await
            .unwrap();
        assert_eq!(all["apps"].as_array().unwrap().len(), 2);
    }
}
