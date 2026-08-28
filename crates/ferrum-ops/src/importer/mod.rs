//! Migration importers: cPanel and aaPanel (spec §11.15).
//!
//! # The dry run is the feature
//!
//! An import is two operations, and the first one changes nothing:
//!
//! * **`import.plan`** reads the source and produces the whole mapping — which
//!   domains become which sites, which databases and users, which files, and an
//!   explicit list of everything that does **not** map. The plan is stored and
//!   its id returned.
//! * **`import.apply`** takes that id and executes *the stored document*. It
//!   never re-scans. If apply meant "read the source again and do whatever it
//!   says now", the thing the operator approved and the thing that ran would be
//!   two different objects — so the source is opened again only to fetch
//!   payload bytes, and only after its SHA-256 still matches what the plan was
//!   derived from.
//!
//! `import.list` reads plans back, because a dry run nobody can re-read is not
//! a dry run.
//!
//! # What makes this safe to point at a stranger's backup
//!
//! A cpmove tarball is the most obviously attacker-controlled input in the
//! panel. Four things keep it boring:
//!
//! 1. **Nothing is extracted to plan.** [`scan`] walks the archive read-only
//!    with the file manager's own guards — entry-name validation, entry count,
//!    total size and compression ratio (`fsops::archive`).
//! 2. **Payload files reach the tenant through `fs.extract`, as the tenant.**
//!    Apply re-tars exactly the subtree the plan named, drops that staging
//!    archive in the home, and hands it to the existing `fs.extract`
//!    operation, which unpacks it in the privilege-dropped helper. No root
//!    process ever writes a file whose name came from the archive — which
//!    matters more than it looks: `O_NOFOLLOW` defeats a symlink but not a
//!    *hardlink*, and a root extractor that truncates a tenant's hardlink to
//!    `/etc/shadow` would be a server takeover. As the tenant, it is a
//!    permission error.
//! 3. **A dump is loaded as the database's own new user, never as root.** A
//!    dump is a script somebody else wrote; run as `root@localhost` it could
//!    drop another tenant's database or create an account. Run as the freshly
//!    created user, whose grants cover exactly one database, the worst it can
//!    do is corrupt the data it was supposed to be.
//! 4. **No credential is ever read.** Not cPanel's `shadow`, not its MySQL
//!    grant hashes, not aaPanel's plaintext `databases.password` column. Every
//!    imported database gets a new user with a new password, and the plan says
//!    so where the operator will read it.
//!
//! # What this build does not do
//!
//! No mail, no DNS zones, no certificates, no cron, no FTP accounts, no
//! PostgreSQL dumps — each is *reported*, per object, with a reason. There is
//! no UI page: the flow is API- and CLI-driven, because a two-step migration
//! that an operator reviews in a diff-like document is a worse fit for a form
//! than for `ferrum` on a terminal.

pub mod aapanel;
pub mod cpanel;
pub mod model;
pub mod scan;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ferrum_config::paths;
use ferrum_core::{
    DbName, Domain, ErrorCode, FerrumError, Permission, PhpVersion, Result, SubscriptionId,
};
use ferrum_db::databases::DbEngine;
use ferrum_db::imports::{ImportPlanRecord, ImportSource, NewImportPlan};
use ferrum_db::subscriptions::Subscription;
use ferrum_distro::CmdOutput;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fsops::archive::Limits;
use crate::fsops::safepath::{self, SafePath};
use crate::registry::{Execution, OpContext, TypedOperation};
use model::{ApplyOutcome, ApplyStep, DumpSource, FileSource, ImportPlan, PlannedSite};

/// The largest dump this importer will load in one piece.
///
/// The client reads its batch from stdin, which means the bytes are buffered in
/// the agent. 128 MiB is comfortably past a typical WordPress or shop database
/// and far short of a size that would hurt a 2 GB server. A dump above it is
/// reported in the *plan* — before anything is created — with the remedy, so
/// the limit is a documented boundary rather than a surprise at apply time.
pub const MAX_DUMP_BYTES: u64 = 128 * 1024 * 1024;

/// One database dump in or out.
const DUMP_TIMEOUT: Duration = Duration::from_secs(30 * 60);

// ---------------------------------------------------------------------------
// Where a plan comes from
// ---------------------------------------------------------------------------

/// The source to read. A tagged enum, so "which importer" is a parsing
/// decision rather than a string compared somewhere in the middle of the
/// operation.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SourceInput {
    /// A `cpmove`/full-backup tarball on this server.
    Cpanel { path: String },
    /// An aaPanel installation root — `/www` on a stock install.
    Aapanel {
        #[serde(default = "default_aapanel_root")]
        root: String,
    },
}

fn default_aapanel_root() -> String {
    "/www".into()
}

/// Validate an operator-supplied server path.
///
/// `import.*` needs `server_manage`, which is administrator-only, so this is
/// not a tenant boundary — an administrator can already read any file on the
/// box. It is a *shape* check: absolute, no traversal components, no NUL, and
/// the thing must exist. A relative path here would resolve against whatever
/// directory the agent happens to be running in, which is nobody's intent.
fn validated_source_path(raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(
            FerrumError::new(ErrorCode::InvalidPath, "the source path is empty").with_field("path"),
        );
    }
    if trimmed.contains('\0') {
        return Err(FerrumError::new(
            ErrorCode::InvalidPath,
            "the source path contains a NUL byte",
        )
        .with_field("path"));
    }
    let path = PathBuf::from(trimmed);
    if !path.is_absolute() {
        return Err(
            FerrumError::new(ErrorCode::InvalidPath, "the source path must be absolute")
                .with_field("path"),
        );
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(FerrumError::new(
            ErrorCode::InvalidPath,
            "the source path may not contain `..`",
        )
        .with_field("path"));
    }
    if !path.exists() {
        return Err(FerrumError::new(
            ErrorCode::NotFound,
            format!("{} is not there", path.display()),
        )
        .with_field("path"));
    }
    Ok(path)
}

/// SHA-256 of a file, streamed.
///
/// This is what makes "apply what was approved" checkable: the plan records it,
/// and apply refuses a source whose bytes have changed. It is not a defence
/// against a hostile source — every guard still runs on apply — but against
/// applying something nobody looked at.
fn fingerprint(path: &Path) -> Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| {
        FerrumError::new(
            ErrorCode::NotFound,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(|e| {
            FerrumError::new(
                ErrorCode::Internal,
                format!("cannot read {}: {e}", path.display()),
            )
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// What identifies a source, per importer.
///
/// * **cPanel** — the tarball's own bytes. It is a single immutable artifact,
///   so hashing it is both exact and cheap to explain.
/// * **aaPanel** — *not* the bytes of its `default.db`. That file belongs to a
///   panel that is still running and rewrites it constantly (task rows, log
///   rows, a heartbeat), so a byte hash would fail minutes after the plan was
///   made, for reasons that have nothing to do with the import. What must not
///   change is the *inventory the mapping was read from*, so the fingerprint is
///   taken over exactly that: each site's name and path, and each database's
///   name. A site added, removed or moved between plan and apply changes it; an
///   unrelated write does not.
async fn source_fingerprint(source: ImportSource, source_path: &Path) -> Result<String> {
    match source {
        ImportSource::Cpanel => {
            let path = source_path.to_path_buf();
            tokio::task::spawn_blocking(move || fingerprint(&path))
                .await
                .map_err(|e| FerrumError::internal(format!("fingerprint task panicked: {e}")))?
        }
        ImportSource::Aapanel => aapanel::inventory_fingerprint(source_path).await,
    }
}

// ---------------------------------------------------------------------------
// import.plan
// ---------------------------------------------------------------------------

pub struct Plan;

#[derive(Debug, Deserialize)]
pub struct PlanInput {
    pub source: SourceInput,
    /// Where the import will land. Required, not defaulted: an administrator
    /// running an import usually has no subscription of their own, and
    /// "wherever" is not an answer for the question of whose account this
    /// becomes.
    pub subscription_id: i64,
    /// The PHP version imported PHP sites get when the source's own version is
    /// unknown or is one Ferrum does not offer.
    #[serde(default)]
    pub php_version: Option<PhpVersion>,
}

#[derive(Debug, Serialize)]
pub struct PlanOutput {
    /// Hand this to `import.apply`.
    pub plan_id: i64,
    pub plan: ImportPlan,
}

#[async_trait]
impl TypedOperation for Plan {
    type Input = PlanInput;
    type Output = PlanOutput;

    const NAME: &'static str = "import.plan";
    // Administrator-only, and not because the mapping is dangerous: the input
    // is an arbitrary path on the server and the output describes what is in
    // it. That is a server-wide read, so it takes a server-wide permission.
    const PERMISSION: Permission = Permission::ServerManage;
    // Reading a multi-gigabyte tarball is minutes of work. Nothing is created,
    // so re-running it is always safe — it produces a second plan row.
    const EXECUTION: Execution = Execution::Task {
        cancellable: true,
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let subscription = resolve_subscription(ctx, input.subscription_id).await?;

        let (source_kind, path) = match &input.source {
            SourceInput::Cpanel { path } => (ImportSource::Cpanel, validated_source_path(path)?),
            SourceInput::Aapanel { root } => (ImportSource::Aapanel, validated_source_path(root)?),
        };

        ctx.log(format!(
            "reading {} as {}",
            path.display(),
            match source_kind {
                ImportSource::Cpanel => "a cPanel backup",
                ImportSource::Aapanel => "an aaPanel installation",
            }
        ));

        let fp = source_fingerprint(source_kind, &path).await?;

        let plan = match source_kind {
            ImportSource::Cpanel => {
                let path = path.clone();
                let sub = subscription.id.get();
                let php = input.php_version;
                // The scan is blocking file I/O over a large archive; keeping
                // it off the async workers is the same rule the file manager
                // follows.
                tokio::task::spawn_blocking(move || {
                    cpanel::plan(&path, sub, php, fp, Limits::default())
                })
                .await
                .map_err(|e| FerrumError::internal(format!("scan task panicked: {e}")))??
            }
            ImportSource::Aapanel => {
                aapanel::plan(&path, subscription.id.get(), input.php_version, fp).await?
            }
        };

        ctx.log(format!(
            "{} site(s), {} database(s), {} object(s) that do not map",
            plan.totals.sites, plan.totals.databases, plan.totals.unmapped
        ));

        let plan_json = serde_json::to_string(&plan)
            .map_err(|e| FerrumError::internal(format!("the plan will not serialise: {e}")))?;

        let record = ctx
            .db()
            .create_import_plan(NewImportPlan {
                source_kind,
                source_path: path.display().to_string(),
                source_fingerprint: plan.fingerprint.clone(),
                subscription_id: subscription.id,
                plan_json,
                created_by: Some(ctx.auth().actor_user_id),
            })
            .await
            .map_err(FerrumError::from)?;

        ctx.log(format!(
            "stored as plan {}; review it, then run import.apply",
            record.id
        ));

        Ok(PlanOutput {
            plan_id: record.id,
            plan,
        })
    }
}

// ---------------------------------------------------------------------------
// import.list
// ---------------------------------------------------------------------------

pub struct List;

#[derive(Debug, Deserialize)]
pub struct ListInput {
    /// One plan, with its full document and its outcome. Absent lists the
    /// recent ones without their documents.
    #[serde(default)]
    pub plan_id: Option<i64>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// One row of the list. The plan document is present only when a single plan
/// was asked for — a list page showing fifty full mappings would be megabytes
/// of JSON nobody reads.
#[derive(Debug, Serialize)]
pub struct PlanSummary {
    pub id: i64,
    pub source: ImportSource,
    pub source_path: String,
    pub subscription_id: i64,
    pub created_at: String,
    pub applied_at: Option<String>,
    pub applied_task_id: Option<String>,
    pub totals: Option<model::PlanTotals>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<ImportPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ApplyOutcome>,
}

#[derive(Debug, Serialize)]
pub struct ListOutput {
    pub plans: Vec<PlanSummary>,
}

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = ListOutput;

    const NAME: &'static str = "import.list";
    const PERMISSION: Permission = Permission::ServerManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let repo = ctx.db().import_plans(ctx.scope());
        let records = match input.plan_id {
            Some(id) => vec![
                repo.by_id(id)
                    .await
                    .map_err(FerrumError::from)?
                    .ok_or_else(|| FerrumError::not_found("import plan"))?,
            ],
            None => repo
                .list(input.limit, input.offset.max(0))
                .await
                .map_err(FerrumError::from)?,
        };

        let detailed = input.plan_id.is_some();
        Ok(ListOutput {
            plans: records
                .into_iter()
                .map(|record| summarise(record, detailed))
                .collect(),
        })
    }
}

fn summarise(record: ImportPlanRecord, detailed: bool) -> PlanSummary {
    // A plan that will not parse is not a reason to fail the listing: the row
    // exists, and the operator needs to see that it exists.
    let plan: Option<ImportPlan> = serde_json::from_str(&record.plan_json).ok();
    let outcome = record
        .outcome_json
        .as_deref()
        .and_then(|json| serde_json::from_str::<ApplyOutcome>(json).ok());

    PlanSummary {
        id: record.id,
        source: record.source_kind,
        source_path: record.source_path,
        subscription_id: record.subscription_id.get(),
        created_at: ferrum_db::to_sql_time(record.created_at),
        applied_at: record.applied_at.map(ferrum_db::to_sql_time),
        applied_task_id: record.applied_task_id,
        totals: plan.as_ref().map(|p| p.totals),
        plan: if detailed { plan } else { None },
        outcome,
    }
}

// ---------------------------------------------------------------------------
// import.apply
// ---------------------------------------------------------------------------

/// `import.apply`.
///
/// `state_root` is where the scratch directory for dumps and client credential
/// files goes. `None` means [`paths::state_dir`]; tests point it at a temporary
/// directory, because `paths::set_root` is a process-wide `OnceLock` a parallel
/// test cannot share (the same reason `backup::Run` carries one).
pub struct Apply {
    state_root: Option<PathBuf>,
}

impl Apply {
    pub fn live() -> Self {
        Self { state_root: None }
    }
}

#[derive(Debug, Deserialize)]
pub struct ApplyInput {
    /// The plan to execute. There is no way to apply a mapping that was not
    /// stored first.
    pub plan_id: i64,
}

#[derive(Debug, Serialize)]
pub struct ApplyOutput {
    pub plan_id: i64,
    pub sites_created: u64,
    pub databases_created: u64,
    pub failures: u64,
    pub outcome: ApplyOutcome,
    /// What the operator still has to do by hand.
    pub next_steps: Vec<String>,
}

#[async_trait]
impl TypedOperation for Apply {
    type Input = ApplyInput;
    type Output = ApplyOutput;

    const NAME: &'static str = "import.apply";
    const PERMISSION: Permission = Permission::ServerManage;
    // Creates Linux-visible state: sites, pools, vhosts, databases, files. Not
    // idempotent and not cancellable — a cancel between "database created" and
    // "dump loaded" leaves exactly the half-state the outcome record exists to
    // describe.
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        idempotent: false,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let record = ctx
            .db()
            .import_plans(ctx.scope())
            .by_id(input.plan_id)
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("import plan"))?;

        if record.is_applied() {
            return Err(FerrumError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "plan {} was already applied at {}. Make a fresh plan rather than applying \
                     this one twice — a second apply would try to create the same sites and \
                     databases again",
                    record.id,
                    record
                        .applied_at
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "an earlier time".into())
                ),
            ));
        }

        let plan: ImportPlan = serde_json::from_str(&record.plan_json).map_err(|e| {
            FerrumError::new(
                ErrorCode::Conflict,
                format!("plan {} cannot be read back: {e}", record.id),
            )
        })?;

        // The source must still be the source. Anything else and "apply what
        // was approved" is not a claim this operation can make.
        let source_path = validated_source_path(&record.source_path)?;
        let observed = source_fingerprint(record.source_kind, &source_path).await?;
        if observed != record.source_fingerprint {
            return Err(FerrumError::new(
                ErrorCode::Conflict,
                format!(
                    "{} has changed since plan {} was made (SHA-256 {}, expected {}). Re-run \
                     import.plan and review the new mapping",
                    source_path.display(),
                    record.id,
                    &observed[..observed.len().min(16)],
                    &record.source_fingerprint[..record.source_fingerprint.len().min(16)],
                ),
            ));
        }

        // Claim before doing anything: two administrators pressing apply on the
        // same plan must not both proceed.
        let task = ctx.task_id().map(|t| t.to_string());
        if !ctx
            .db()
            .claim_import_plan(record.id, task.as_deref())
            .await
            .map_err(FerrumError::from)?
        {
            return Err(FerrumError::new(
                ErrorCode::Conflict,
                format!("plan {} is already being applied", record.id),
            ));
        }

        let subscription = resolve_subscription(ctx, record.subscription_id.get()).await?;
        let outcome = execute(
            ctx,
            &record,
            &plan,
            &subscription,
            &source_path,
            self.state_root.as_deref(),
        )
        .await;

        // Recorded whatever happened, including a partial run: the half-state
        // is the thing somebody has to clean up, so it has to be readable.
        if let Ok(json) = serde_json::to_string(&outcome) {
            let _ = ctx.db().set_import_outcome(record.id, &json).await;
        }

        let sites_created = outcome
            .steps
            .iter()
            .filter(|s| s.stage == "site" && s.ok)
            .count() as u64;
        let databases_created = outcome
            .steps
            .iter()
            .filter(|s| s.stage == "database" && s.ok)
            .count() as u64;

        Ok(ApplyOutput {
            plan_id: record.id,
            sites_created,
            databases_created,
            failures: outcome.failures() as u64,
            next_steps: next_steps(&plan, &outcome),
            outcome,
        })
    }
}

fn next_steps(plan: &ImportPlan, outcome: &ApplyOutcome) -> Vec<String> {
    let mut steps = vec![
        "Point each imported domain's DNS at this server, then issue certificates \
         (`cert.issue`)"
            .to_string(),
    ];
    if !plan.databases.is_empty() {
        steps.push(
            "Set a password for each imported database user with `db.user.password` (it shows \
             the new password once), then put the new database name, user and password into the \
             application's configuration — wp-config.php, .env"
                .to_string(),
        );
    }
    if plan.source == ImportSource::Aapanel {
        steps.push(
            "Remove aaPanel's vhosts (or stop its nginx) before Ferrum can serve these domains"
                .to_string(),
        );
    }
    if !plan.unmapped.is_empty() {
        steps.push(format!(
            "{} object(s) were not imported (mail, DNS zones, certificates, cron); the plan lists \
             each one with a reason",
            plan.unmapped.len()
        ));
    }
    if !outcome.ok() {
        steps.push(
            "Some steps failed — read the outcome on the plan before retrying anything by hand"
                .to_string(),
        );
    }
    steps
}

/// Run the plan. Never returns an error: a failure at any step is *recorded*
/// and the next object is attempted, because an import that stops on the third
/// of ten sites and says nothing about the other seven is worse than one that
/// tells you exactly which three worked.
async fn execute(
    ctx: &OpContext,
    record: &ImportPlanRecord,
    plan: &ImportPlan,
    subscription: &Subscription,
    source_path: &Path,
    state_root: Option<&Path>,
) -> ApplyOutcome {
    let mut outcome = ApplyOutcome::default();

    for (index, site) in plan.sites.iter().enumerate() {
        match create_site(ctx, subscription, site).await {
            Ok(site_id) => {
                outcome
                    .record(ApplyStep::ok("site", site.domain.clone(), "created").with_id(site_id));
                match copy_files(ctx, record, subscription, site, source_path, index).await {
                    Ok((files, bytes)) => outcome.record(ApplyStep::ok(
                        "files",
                        site.domain.clone(),
                        format!("copied {files} file(s), {bytes} byte(s)"),
                    )),
                    Err(e) => outcome.record(ApplyStep::failed(
                        "files",
                        site.domain.clone(),
                        e.detail.clone(),
                    )),
                }
            }
            Err(e) => outcome.record(ApplyStep::failed(
                "site",
                site.domain.clone(),
                e.detail.clone(),
            )),
        }
    }

    for database in &plan.databases {
        match create_database(ctx, subscription, database).await {
            Ok(created) => {
                outcome.record(
                    ApplyStep::ok(
                        "database",
                        database.target_name.clone(),
                        format!(
                            "created as `{}`, owned by `{}` — set its password with \
                             db.user.password",
                            database.target_name, database.target_user
                        ),
                    )
                    .with_id(created.database_id),
                );
                match load_data(ctx, database, &created, source_path, state_root).await {
                    Ok(bytes) => outcome.record(ApplyStep::ok(
                        "dump",
                        database.target_name.clone(),
                        format!("loaded {bytes} byte(s)"),
                    )),
                    Err(e) => outcome.record(ApplyStep::failed(
                        "dump",
                        database.target_name.clone(),
                        e.detail.clone(),
                    )),
                }
            }
            Err(e) => outcome.record(ApplyStep::failed(
                "database",
                database.target_name.clone(),
                e.detail.clone(),
            )),
        }
    }

    outcome
}

// ---------------------------------------------------------------------------
// sites
// ---------------------------------------------------------------------------

/// Create one imported site through `site.create`.
///
/// Deliberately the existing operation rather than a private copy: it is what
/// enforces the plan's site limit, refuses a suspended subscription, creates
/// the Linux account and the directory tree, renders the vhost and the FPM
/// pool, and reloads nginx. An importer that reimplemented any of that would be
/// a second, worse copy that quietly skipped the quota check.
async fn create_site(
    ctx: &OpContext,
    subscription: &Subscription,
    planned: &PlannedSite,
) -> Result<i64> {
    let domain = Domain::parse(&planned.domain)?;
    let php = planned
        .target_php
        .as_deref()
        .map(PhpVersion::parse)
        .transpose()?;

    let created = crate::site::Create
        .run(
            ctx,
            crate::site::CreateInput {
                domain,
                site_type: if php.is_some() {
                    crate::site::SiteTypeInput::Php
                } else {
                    crate::site::SiteTypeInput::Static
                },
                php_version: php,
                subscription_id: Some(subscription.id.get()),
                with_www: false,
                proxy_port: None,
                redirect_target: None,
            },
        )
        .await?;

    // Aliases second, then one `site.update` to re-render the vhost with them
    // in it. A parked domain that is already taken is not a reason to fail the
    // site it was parked on.
    let mut added = 0;
    for alias in &planned.aliases {
        let Ok(alias) = Domain::parse(alias) else {
            continue;
        };
        match ctx
            .db()
            .sites(ctx.scope())
            .add_alias(ferrum_core::SiteId(created.site_id), &alias, false)
            .await
        {
            Ok(_) => {
                added += 1;
                ctx.log(format!("{}: added alias {alias}", planned.domain));
            }
            Err(e) => ctx.log(format!(
                "{}: could not add alias {alias}: {e}",
                planned.domain
            )),
        }
    }
    if added > 0 {
        crate::site::Update
            .run(
                ctx,
                crate::site::UpdateInput {
                    site_id: created.site_id,
                    php_version: None,
                    force_https: None,
                    http3: None,
                    maintenance_mode: None,
                    client_max_body_size: None,
                    custom_nginx_snippet: None,
                    php_ini_overrides: None,
                    rate_limit_enabled: None,
                    www_policy: None,
                },
            )
            .await?;
    }

    Ok(created.site_id)
}

/// Put one site's files in place.
///
/// Two steps, and the split is the security design:
///
/// 1. **Stage.** Build a *new* archive holding only the subtree the plan named,
///    written into the tenant's home with `O_CREAT|O_EXCL|O_NOFOLLOW` so a name
///    the tenant planted first cannot be written through.
/// 2. **Extract, as the tenant.** Hand it to `fs.extract`, which runs in the
///    privilege-dropped helper and applies every archive guard again.
///
/// The staging archive stays root-owned and mode 0644: the helper only needs to
/// *read* it, and leaving it root-owned keeps it out of the tenant's disk quota
/// while it exists. It is removed as soon as the extract returns.
async fn copy_files(
    ctx: &OpContext,
    record: &ImportPlanRecord,
    subscription: &Subscription,
    planned: &PlannedSite,
    source_path: &Path,
    index: usize,
) -> Result<(u64, u64)> {
    let home = PathBuf::from(&subscription.home_dir);
    let relative_docroot = tenant_relative_docroot(&home, planned, subscription)?;

    // A name nothing else writes, distinct per site so two sites in one plan
    // cannot collide.
    let staging_name = format!(".ferrum-import-{}-{index}.tar.gz", record.id);
    let (parent, name) = safepath::resolve_new(&home, Path::new(&staging_name))
        .map_err(|e| FerrumError::new(ErrorCode::InvalidPath, e.message))?;
    let staged = safepath::child(&parent, &name)
        .map_err(|e| FerrumError::new(ErrorCode::InvalidPath, e.message))?;

    let build = {
        let staged = staged.clone();
        let files = planned.files.clone();
        let source_path = source_path.to_path_buf();
        tokio::task::spawn_blocking(move || build_staging_archive(&files, &source_path, &staged))
            .await
            .map_err(|e| FerrumError::internal(format!("staging task panicked: {e}")))?
    };

    let result = match build {
        Ok(counts) => {
            ctx.log(format!(
                "{}: staged {} file(s) into {}",
                planned.domain, counts.0, staging_name
            ));
            make_readable(&staged)?;
            let extract = crate::fsops::ops::Extract
                .run(
                    ctx,
                    crate::fsops::ops::ExtractInput {
                        subscription_id: Some(subscription.id.get()),
                        archive: ferrum_core::TenantPath::parse(&staging_name)?,
                        dest: Some(relative_docroot),
                    },
                )
                .await;
            extract.map(|out| (out.files, out.bytes))
        }
        Err(e) => Err(e),
    };

    // Always: a staging archive left in a tenant's home is a copy of their
    // whole site sitting in a file they did not ask for.
    let _ = std::fs::remove_file(staged.as_path());
    result
}

/// Turn the created site's document root into a path relative to the home.
///
/// `site.create` derives the root from `paths::site_public`, so this is a
/// strip, not a guess — but it is checked rather than assumed, because a home
/// that is not a prefix of the document root would otherwise silently extract
/// into the wrong place.
fn tenant_relative_docroot(
    home: &Path,
    planned: &PlannedSite,
    subscription: &Subscription,
) -> Result<ferrum_core::TenantPath> {
    let root = paths::site_public(&subscription.linux_user, &planned.domain);
    let relative = root.strip_prefix(home).map_err(|_| {
        FerrumError::internal(format!(
            "{}'s document root ({}) is not inside its home ({})",
            planned.domain,
            root.display(),
            home.display()
        ))
    })?;
    ferrum_core::TenantPath::parse(&relative.to_string_lossy())
}

/// Build the staging archive for one site, from whichever kind of source the
/// plan named.
fn build_staging_archive(
    files: &FileSource,
    source_path: &Path,
    staged: &SafePath,
) -> Result<(u64, u64)> {
    match files {
        FileSource::TarSubtree { prefix } => {
            scan::restage_subtree(source_path, prefix, staged, Limits::default())
        }
        FileSource::Directory { path } => {
            // The file manager's own compressor: it walks the tree, skips every
            // symlink it meets, and writes through the same `create_new` +
            // `O_NOFOLLOW` open. Reusing it means an aaPanel site's `uploads ->
            // /etc` is not followed here for exactly the reason it is not
            // followed there.
            let dir = Path::new(path);
            let root = safepath::home_root(dir)
                .map_err(|e| FerrumError::new(ErrorCode::InvalidPath, e.message))?;
            let mut entries = Vec::new();
            let read = std::fs::read_dir(dir).map_err(|e| {
                FerrumError::new(
                    ErrorCode::NotFound,
                    format!("cannot read {}: {e}", dir.display()),
                )
            })?;
            for item in read.flatten() {
                if let Some(name) = item.file_name().to_str() {
                    entries.push(name.to_string());
                }
            }
            if entries.is_empty() {
                return Err(FerrumError::new(
                    ErrorCode::NotFound,
                    format!("{} is empty", dir.display()),
                ));
            }
            let bytes = crate::fsops::archive::compress(
                &root,
                &entries,
                staged,
                crate::fsops::proto::ArchiveFormat::TarGz,
            )
            .map_err(|e| FerrumError::new(ErrorCode::Internal, e.message))?;
            Ok((entries.len() as u64, bytes))
        }
    }
}

/// Make the staging archive readable by the tenant's helper.
///
/// Through the open file descriptor, with `O_NOFOLLOW` on the way in: a
/// path-based `chmod` here would follow a symlink the tenant could put in place
/// of the file between the write and the chmod, and chmod-ing an arbitrary path
/// as root is how a home-directory race becomes a privilege bug.
fn make_readable(staged: &SafePath) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(staged.as_path())
        .map_err(|e| {
            FerrumError::new(
                ErrorCode::Internal,
                format!("cannot reopen the staging archive: {e}"),
            )
        })?;
    file.set_permissions(std::fs::Permissions::from_mode(0o644))
        .map_err(|e| {
            FerrumError::new(
                ErrorCode::Internal,
                format!("cannot make the staging archive readable: {e}"),
            )
        })
}

// ---------------------------------------------------------------------------
// databases
// ---------------------------------------------------------------------------

/// Create the database and its user through the existing `db.*` operations, so
/// the plan's `max_dbs` limit, the engine-ready check and the name-collision
/// refusal all apply to an import exactly as they do to a click.
async fn create_database(
    ctx: &OpContext,
    subscription: &Subscription,
    planned: &model::PlannedDatabase,
) -> Result<CreatedDatabase> {
    let name = DbName::parse(&planned.target_name)?;
    let user = DbName::parse(&planned.target_user)?;

    let created_user = crate::db::UserCreate
        .run(
            ctx,
            crate::db::UserCreateInput {
                username: user.clone(),
                engine: DbEngine::Mysql,
                subscription_id: Some(subscription.id.get()),
            },
        )
        .await?;

    match crate::db::Create
        .run(
            ctx,
            crate::db::CreateInput {
                name: name.clone(),
                engine: DbEngine::Mysql,
                subscription_id: Some(subscription.id.get()),
                owner: Some(user.clone()),
            },
        )
        .await
    {
        Ok(created) => Ok(CreatedDatabase {
            database_id: created.database_id,
            name: created.name,
            user: created_user.username,
            // Held for the length of this import and then dropped. It is never
            // logged and never stored — see [`CreatedDatabase`].
            password: created_user.password,
        }),
        Err(e) => {
            // Unwind the user, or its name is burned and the next attempt fails
            // on a leftover nobody can see (`wp.install` unwinds the same way).
            let _ = crate::db::UserDrop
                .run(ctx, crate::db::UserDropInput { username: user })
                .await;
            Err(e)
        }
    }
}

/// A database the import just created, and the one-time password its owner was
/// given.
///
/// The password lives **only here**, for as long as it takes to load the dump.
/// `import.apply` is a Task, and a Task's input, logs and stored outcome all
/// persist (`ferrum_ops::db`'s module docs spell out why that rules out a
/// password); its return value, meanwhile, never reaches the caller at all,
/// because a Task answers with a task id. So there is no honest channel for
/// this value to travel on, and the import does not try to invent one: it uses
/// the password to load the dump, drops it, and tells the operator to set a
/// fresh one with `db.user.password`, which is Immediate and shows it once.
struct CreatedDatabase {
    database_id: i64,
    name: String,
    user: String,
    password: String,
}

/// Get the data into the new database.
async fn load_data(
    ctx: &OpContext,
    planned: &model::PlannedDatabase,
    created: &CreatedDatabase,
    source_path: &Path,
    state_root: Option<&Path>,
) -> Result<u64> {
    let sql = match &planned.payload {
        DumpSource::TarMember { path } => {
            let source = source_path.to_path_buf();
            let member = path.clone();
            tokio::task::spawn_blocking(move || {
                scan::read_member(&source, &member, MAX_DUMP_BYTES, Limits::default())
            })
            .await
            .map_err(|e| FerrumError::internal(format!("dump read panicked: {e}")))??
        }
        DumpSource::LocalMysql { name } => dump_local_database(ctx, name, state_root).await?,
    };

    if sql.is_empty() {
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            "the dump is empty; nothing was loaded",
        ));
    }
    let bytes = sql.len() as u64;

    // The credential file lives in the panel's own state directory, mode 0600
    // inside a 0700 directory, and is removed before this function returns.
    // The alternative — `--password=` on the argv — would publish it in
    // `/proc/<pid>/cmdline` to every account on the box.
    let workdir = import_workdir(state_root)?;
    let defaults = write_defaults_file(&workdir, &created.name, &created.user)?;
    if let Err(e) = write_password(&defaults, &created.password) {
        let _ = std::fs::remove_file(&defaults);
        return Err(e);
    }

    let argv = mysql_load_argv(&defaults, &created.name);
    let result = loader().run(&LoadJob { argv, stdin: sql }).await;
    let _ = std::fs::remove_file(&defaults);

    let output = result?;
    if !output.success() {
        return Err(FerrumError::new(
            ErrorCode::CommandFailed,
            format!(
                "loading the dump into `{}` failed (exit {}): {}",
                created.name,
                output.status,
                first_lines(&output.failure_text(), 5)
            ),
        ));
    }
    Ok(bytes)
}

fn first_lines(text: &str, n: usize) -> String {
    text.lines().take(n).collect::<Vec<_>>().join(" / ")
}

// ---------------------------------------------------------------------------
// running the client
// ---------------------------------------------------------------------------

/// One client invocation: an argv array and the bytes for its stdin.
///
/// Bytes, not a `String`, on purpose: a mysqldump of a table with binary
/// columns is not valid UTF-8, and lossily converting it would silently corrupt
/// the data being imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadJob {
    pub argv: Vec<String>,
    pub stdin: Vec<u8>,
}

/// The seam between "which client, with what input" and "actually running it",
/// so the argv and the stdin can be asserted without MariaDB installed. Same
/// shape as `ferrum_ops::db::DbShell`, and for the same reason.
#[async_trait]
pub trait SqlLoader: Send + Sync {
    async fn run(&self, job: &LoadJob) -> Result<CmdOutput>;
}

struct SystemLoader;

#[async_trait]
impl SqlLoader for SystemLoader {
    async fn run(&self, job: &LoadJob) -> Result<CmdOutput> {
        let (program, args) = job
            .argv
            .split_first()
            .ok_or_else(|| FerrumError::internal("a LoadJob must carry a program"))?;
        ferrum_distro::Cmd::new(program.clone())
            .args(args)
            .timeout(DUMP_TIMEOUT)
            .stdin_data(job.stdin.clone())
            .run()
            .await
            .map_err(FerrumError::from)
    }
}

fn loader() -> Arc<dyn SqlLoader> {
    #[cfg(test)]
    if let Some(l) = testing::installed_loader() {
        return l;
    }
    Arc::new(SystemLoader)
}

/// `mariadb --defaults-file=… --database=…`, reading the dump from stdin.
///
/// `--defaults-file` must come first, and it is the whole point: the user and
/// password are read from a 0600 file rather than from an argv every process on
/// the machine can see. `--database` binds the session to one schema, so a dump
/// that says `USE somebody_else` fails on privileges rather than succeeding.
fn mysql_load_argv(defaults: &Path, database: &str) -> Vec<String> {
    vec![
        "mariadb".to_string(),
        format!("--defaults-file={}", defaults.display()),
        format!("--database={database}"),
        "--batch".to_string(),
    ]
}

/// Dump a database that is live in this server's own MariaDB (the aaPanel
/// case).
///
/// Written to a file and read back rather than captured from stdout, because
/// `CmdOutput::stdout` is a lossy `String` and a dump is bytes.
async fn dump_local_database(
    ctx: &OpContext,
    name: &str,
    state_root: Option<&Path>,
) -> Result<Vec<u8>> {
    // The source name comes from another panel's database. It is validated as
    // a `DbName` before it reaches an argv, exactly like every other identifier
    // (spec §12 rule 3).
    let source = DbName::parse(name).map_err(|e| e.with_field("source database"))?;
    let workdir = import_workdir(state_root)?;
    let target = workdir.join(format!("{}.sql", source.as_str()));
    let _ = std::fs::remove_file(&target);

    let socket = mysql_socket(ctx);
    let output = ferrum_distro::Cmd::new("mariadb-dump")
        .args([
            "--no-defaults".to_string(),
            "--protocol=socket".to_string(),
            format!("--socket={socket}"),
            "--user=root".to_string(),
            // A consistent snapshot without locking the live site out of its
            // own database while the copy runs.
            "--single-transaction".to_string(),
            "--quick".to_string(),
            // Routines and triggers carry a DEFINER, which a non-superuser
            // cannot recreate; leaving them out makes the load succeed and the
            // omission explicit rather than failing the whole dump.
            "--skip-routines".to_string(),
            "--skip-triggers".to_string(),
            format!("--result-file={}", target.display()),
            source.as_str().to_string(),
        ])
        .timeout(DUMP_TIMEOUT)
        .run()
        .await
        .map_err(FerrumError::from)?;

    if !output.success() {
        let _ = std::fs::remove_file(&target);
        return Err(FerrumError::new(
            ErrorCode::CommandFailed,
            format!(
                "mariadb-dump of `{}` failed (exit {}): {}",
                source.as_str(),
                output.status,
                first_lines(&output.failure_text(), 5)
            ),
        ));
    }

    let size = std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0);
    if size > MAX_DUMP_BYTES {
        let _ = std::fs::remove_file(&target);
        return Err(FerrumError::new(
            ErrorCode::InvalidInput,
            format!(
                "`{}` dumps to {size} bytes, past the {MAX_DUMP_BYTES} byte limit this importer \
                 loads in one piece",
                source.as_str()
            ),
        ));
    }
    let bytes = std::fs::read(&target).map_err(|e| {
        FerrumError::new(
            ErrorCode::Internal,
            format!("cannot read the dump of `{}`: {e}", source.as_str()),
        )
    })?;
    let _ = std::fs::remove_file(&target);
    Ok(bytes)
}

fn mysql_socket(ctx: &OpContext) -> &'static str {
    match ctx.distro().info.family {
        ferrum_distro::Family::Debian => "/run/mysqld/mysqld.sock",
        ferrum_distro::Family::Rhel => "/var/lib/mysql/mysql.sock",
    }
}

/// A root-only scratch directory for dumps and credential files.
fn import_workdir(state_root: Option<&Path>) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let dir = state_root
        .map(Path::to_path_buf)
        .unwrap_or_else(paths::state_dir)
        .join("import");
    std::fs::create_dir_all(&dir).map_err(|e| {
        FerrumError::new(
            ErrorCode::Internal,
            format!("cannot create {}: {e}", dir.display()),
        )
    })?;
    // 0700: this directory holds database credentials and other tenants' data
    // while an import runs.
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    Ok(dir)
}

/// Create the client credential file, with the user in it and a placeholder for
/// the password. Split from [`write_password`] so the file's *mode* is set
/// before any secret is written into it.
fn write_defaults_file(dir: &Path, database: &str, user: &str) -> Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let path = dir.join(format!("{database}.cnf"));
    let _ = std::fs::remove_file(&path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| {
            FerrumError::new(
                ErrorCode::Internal,
                format!("cannot create the client credential file: {e}"),
            )
        })?;
    writeln!(file, "[client]\nuser={user}").map_err(|e| {
        FerrumError::new(
            ErrorCode::Internal,
            format!("cannot write the client credential file: {e}"),
        )
    })?;
    Ok(path)
}

/// Append the password line.
///
/// The password comes from [`crate::db::generate_password`], whose alphabet is
/// `[A-Za-z0-9]`. That is asserted rather than assumed: a value containing a
/// quote, `#` or a newline would change the meaning of the file it is written
/// into, and this is the one place a generated secret meets a config parser.
fn write_password(path: &Path, password: &str) -> Result<()> {
    use std::io::Write;

    if !password.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(FerrumError::internal(
            "refusing to write a password containing characters a my.cnf parser would reinterpret",
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|e| {
            FerrumError::new(
                ErrorCode::Internal,
                format!("cannot write the client credential file: {e}"),
            )
        })?;
    writeln!(file, "password={password}").map_err(|e| {
        FerrumError::new(
            ErrorCode::Internal,
            format!("cannot write the client credential file: {e}"),
        )
    })
}

async fn resolve_subscription(ctx: &OpContext, id: i64) -> Result<Subscription> {
    ctx.db()
        .subscriptions(ctx.scope())
        .by_id(SubscriptionId(id))
        .await
        .map_err(FerrumError::from)?
        .ok_or_else(|| FerrumError::not_found("subscription"))
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::cell::RefCell;
    use std::sync::Mutex;

    thread_local! {
        static LOADER: RefCell<Option<Arc<dyn SqlLoader>>> = const { RefCell::new(None) };
    }

    pub fn install_loader(loader: Arc<dyn SqlLoader>) {
        LOADER.with(|l| *l.borrow_mut() = Some(loader));
    }

    pub fn installed_loader() -> Option<Arc<dyn SqlLoader>> {
        LOADER.with(|l| l.borrow().clone())
    }

    #[derive(Default)]
    pub struct RecordingLoader {
        pub jobs: Mutex<Vec<LoadJob>>,
    }

    impl RecordingLoader {
        pub fn recorded(&self) -> Vec<LoadJob> {
            self.jobs.lock().expect("loader mutex").clone()
        }
    }

    #[async_trait]
    impl SqlLoader for RecordingLoader {
        async fn run(&self, job: &LoadJob) -> Result<CmdOutput> {
            self.jobs.lock().expect("loader mutex").push(job.clone());
            Ok(CmdOutput {
                program: job.argv.first().cloned().unwrap_or_default(),
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
                duration: Duration::from_millis(1),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::importer::scan::tests::tar_gz;
    use crate::registry::testing::{auth_for, registry};
    use ferrum_core::Role;
    use ferrum_db::imports::ImportSource as Src;

    /// A tarball whose account maps to *nothing*: `userdata/main` names a
    /// domain, but the per-domain file that would give it a document root is
    /// absent, so the plan has no sites and no databases.
    ///
    /// That is exactly what the apply tests need — the plan machinery
    /// (fingerprint, claim, refusal to re-apply) can be exercised end to end
    /// without a MariaDB, an nginx or a `useradd`.
    fn empty_plan_tarball(dir: &Path) -> PathBuf {
        let path = dir.join("cpmove-empty.tar.gz");
        tar_gz(
            &path,
            &[
                ("bob/cp/bob", 0o600, b"USER=bob\n" as &[u8]),
                (
                    "bob/userdata/main",
                    0o644,
                    b"main_domain: example.com\nsub_domains: []\n",
                ),
                ("bob/dnszones/example.com.db", 0o644, b"$TTL 14400"),
            ],
        );
        path
    }

    async fn seed_subscription(
        reg: &crate::registry::OpRegistry,
        owner: ferrum_core::UserId,
    ) -> i64 {
        reg.services()
            .db
            .create_subscription(owner)
            .await
            .expect("subscription")
            .id
            .get()
    }

    async fn plan_it(
        reg: &crate::registry::OpRegistry,
        admin: ferrum_core::UserId,
        path: &Path,
    ) -> serde_json::Value {
        let subscription = seed_subscription(reg, admin).await;
        reg.dispatch(
            "import.plan",
            &auth_for(admin, Role::Admin),
            serde_json::json!({
                "source": { "kind": "cpanel", "path": path.display().to_string() },
                "subscription_id": subscription,
            }),
            None,
        )
        .await
        .expect("plan")
    }

    #[tokio::test]
    async fn a_dry_run_stores_the_plan_and_hands_back_an_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = empty_plan_tarball(dir.path());
        let (reg, admin, _) = registry().await;

        let out = plan_it(&reg, admin, &path).await;
        let plan_id = out["plan_id"].as_i64().expect("a plan id");

        // The stored document is what `import.list` reads back, byte for byte.
        let listed = reg
            .dispatch(
                "import.list",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "plan_id": plan_id }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(listed["plans"][0]["id"].as_i64(), Some(plan_id));
        assert_eq!(
            listed["plans"][0]["plan"]["fingerprint"],
            out["plan"]["fingerprint"]
        );
        assert!(
            listed["plans"][0]["plan"]["unmapped"]
                .as_array()
                .is_some_and(|u| !u.is_empty()),
            "the DNS zone in the fixture must be reported: {listed}"
        );
    }

    /// A tarball with one database dump and no mappable site: enough to drive
    /// the whole database half of an apply with neither MariaDB nor nginx.
    fn dump_only_tarball(dir: &Path) -> PathBuf {
        let path = dir.join("cpmove-db.tar.gz");
        tar_gz(
            &path,
            &[
                ("bob/cp/bob", 0o600, b"USER=bob\n" as &[u8]),
                (
                    "bob/userdata/main",
                    0o644,
                    b"main_domain: example.com\nsub_domains: []\n",
                ),
                (
                    "bob/mysql/bob_wp.sql",
                    0o644,
                    b"CREATE TABLE wp_posts (id INT);\nINSERT INTO wp_posts VALUES (1);\n",
                ),
            ],
        );
        path
    }

    #[tokio::test]
    async fn a_dump_is_loaded_as_the_new_database_user_with_its_bytes_intact() {
        // The two claims this test exists for (spec §11.15, §12 rule 6):
        //
        //  * the dump reaches the client on **stdin**, byte for byte from the
        //    archive member the plan named — no lossy string conversion, no
        //    re-quoting, nothing on the argv;
        //  * it is run as the *new* database user through a private
        //    `--defaults-file`, not as `root@localhost`. A dump is a script
        //    somebody else wrote, and root would let it touch every other
        //    tenant's database.
        let dir = tempfile::tempdir().unwrap();
        let path = dump_only_tarball(dir.path());
        let (reg, admin, _) = registry().await;

        // The Stack Manager's own record of an installed engine, and a
        // recorder in place of the real client.
        for slug in ["mariadb"] {
            let db = &reg.services().db;
            db.claim_component(slug, ferrum_db::ComponentStatus::Installing, "test-task")
                .await
                .unwrap();
            db.component_installed(slug, Some("1.0-mock"))
                .await
                .unwrap();
        }
        crate::db::testing::install_shell(Arc::new(crate::db::testing::RecordingShell::default()));
        let loader = Arc::new(testing::RecordingLoader::default());
        testing::install_loader(loader.clone());

        let plan_id = plan_it(&reg, admin, &path).await["plan_id"]
            .as_i64()
            .unwrap();

        let state_root = dir.path().join("state");
        let ctx = OpContext::new(reg.services().clone(), auth_for(admin, Role::Admin));
        let out = Apply {
            state_root: Some(state_root.clone()),
        }
        .run(&ctx, ApplyInput { plan_id })
        .await
        .expect("apply");

        assert_eq!(out.databases_created, 1, "{:#?}", out.outcome);
        assert_eq!(out.failures, 0, "{:#?}", out.outcome);

        let jobs = loader.recorded();
        assert_eq!(jobs.len(), 1, "one dump, one client invocation");
        assert_eq!(
            jobs[0].stdin, b"CREATE TABLE wp_posts (id INT);\nINSERT INTO wp_posts VALUES (1);\n",
            "the dump must reach the client unmodified"
        );
        assert!(jobs[0].argv.iter().any(|a| a == "--database=bob_wp"));
        let defaults = jobs[0]
            .argv
            .iter()
            .find_map(|a| a.strip_prefix("--defaults-file="))
            .expect("credentials come from a file");
        assert!(
            !jobs[0].argv.iter().any(|a| a.contains("user=root")),
            "the dump must not run as root: {:?}",
            jobs[0].argv
        );
        assert!(
            !Path::new(defaults).exists(),
            "the credential file must be removed once the load is over"
        );
    }

    #[tokio::test]
    async fn apply_refuses_a_plan_id_that_was_never_stored() {
        // The whole point of storing the plan: "apply" cannot mean "re-scan
        // and hope".
        let (reg, admin, _) = registry().await;
        let err = reg
            .dispatch(
                "import.apply",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "plan_id": 4242 }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn a_plan_cannot_be_applied_twice() {
        let dir = tempfile::tempdir().unwrap();
        let path = empty_plan_tarball(dir.path());
        let (reg, admin, _) = registry().await;
        let plan_id = plan_it(&reg, admin, &path).await["plan_id"]
            .as_i64()
            .unwrap();

        let first = reg
            .dispatch(
                "import.apply",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "plan_id": plan_id }),
                None,
            )
            .await
            .expect("the first apply");
        assert_eq!(first["failures"].as_u64(), Some(0));

        let err = reg
            .dispatch(
                "import.apply",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "plan_id": plan_id }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::AlreadyExists, "{}", err.detail);
        assert!(err.detail.contains("already applied"), "{}", err.detail);
    }

    #[tokio::test]
    async fn apply_refuses_a_source_that_changed_after_the_plan_was_made() {
        // The operator approved a mapping derived from *these* bytes. A tarball
        // that has been swapped since is a different account's data wearing the
        // same filename.
        let dir = tempfile::tempdir().unwrap();
        let path = empty_plan_tarball(dir.path());
        let (reg, admin, _) = registry().await;
        let plan_id = plan_it(&reg, admin, &path).await["plan_id"]
            .as_i64()
            .unwrap();

        tar_gz(
            &path,
            &[
                ("bob/cp/bob", 0o600, b"USER=bob\n" as &[u8]),
                (
                    "bob/userdata/main",
                    0o644,
                    b"main_domain: swapped.example\nsub_domains: []\n",
                ),
            ],
        );

        let err = reg
            .dispatch(
                "import.apply",
                &auth_for(admin, Role::Admin),
                serde_json::json!({ "plan_id": plan_id }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict, "{}", err.detail);
        assert!(err.detail.contains("has changed"), "{}", err.detail);
    }

    #[tokio::test]
    async fn a_customer_cannot_point_the_importer_at_a_server_path() {
        // `import.*` reads arbitrary absolute paths and reports what is in
        // them, so it takes the server-wide permission — a tenant with
        // `site_manage` must not be able to enumerate /root through it.
        let (reg, _, customer) = registry().await;
        let err = reg
            .dispatch(
                "import.plan",
                &auth_for(customer, Role::Customer),
                serde_json::json!({
                    "source": { "kind": "cpanel", "path": "/etc/shadow" },
                    "subscription_id": 1,
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn a_relative_or_traversing_source_path_is_refused() {
        let (reg, admin, _) = registry().await;
        let subscription = seed_subscription(&reg, admin).await;
        for path in ["relative/backup.tar.gz", "/var/backups/../../etc/shadow"] {
            let err = reg
                .dispatch(
                    "import.plan",
                    &auth_for(admin, Role::Admin),
                    serde_json::json!({
                        "source": { "kind": "cpanel", "path": path },
                        "subscription_id": subscription,
                    }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidPath, "{path} was accepted");
        }
    }

    #[tokio::test]
    async fn an_import_into_a_subscription_that_does_not_exist_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = empty_plan_tarball(dir.path());
        let (reg, admin, _) = registry().await;
        let err = reg
            .dispatch(
                "import.plan",
                &auth_for(admin, Role::Admin),
                serde_json::json!({
                    "source": { "kind": "cpanel", "path": path.display().to_string() },
                    "subscription_id": 9999,
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    // -- the client invocation ------------------------------------------------

    #[test]
    fn the_dump_client_reads_its_credentials_from_a_file_never_from_the_argv() {
        let argv = mysql_load_argv(Path::new("/var/lib/ferrum/state/import/wp.cnf"), "wp");
        assert_eq!(argv[0], "mariadb");
        assert_eq!(
            argv[1], "--defaults-file=/var/lib/ferrum/state/import/wp.cnf",
            "--defaults-file must come first for mariadb to honour it"
        );
        assert!(argv.iter().any(|a| a == "--database=wp"));
        assert!(
            !argv.iter().any(|a| a.contains("password")),
            "a password on the argv is world-readable in /proc: {argv:?}"
        );
    }

    #[test]
    fn the_credential_file_is_private_and_refuses_a_password_it_cannot_quote() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = write_defaults_file(dir.path(), "wp", "wp_user").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "got {mode:o}");

        // The generated alphabet is `[A-Za-z0-9]`; anything else could change
        // the meaning of the file it is written into.
        assert!(write_password(&path, "aB3xyz").is_ok());
        assert!(write_password(&path, "pa ss#word\nuser=root").is_err());
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("user=wp_user"));
        assert!(written.contains("password=aB3xyz"));
        assert!(!written.contains("user=root"));
    }

    #[test]
    fn a_generated_password_is_always_one_the_credential_file_accepts() {
        // Ties this module's assertion to the generator it depends on: if
        // `db::generate_password` ever gains a symbol, this fails here rather
        // than at 3am on somebody's import.
        for _ in 0..32 {
            let password = crate::db::generate_password();
            assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }

    // -- staging --------------------------------------------------------------

    #[test]
    fn staging_a_local_directory_skips_symlinks_out_of_the_tree() {
        // The aaPanel path. `uploads -> /etc` inside a source site must not
        // become a copy of /etc in the tenant's document root.
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let source = root.join("site");
        std::fs::create_dir_all(source.join("wp-content")).unwrap();
        std::fs::write(source.join("index.php"), b"<?php").unwrap();
        std::fs::write(source.join("wp-content/a.css"), b"body{}").unwrap();
        std::os::unix::fs::symlink("/etc", source.join("leak")).unwrap();

        let home = root.join("home");
        std::fs::create_dir(&home).unwrap();
        let (parent, name) = safepath::resolve_new(&home, Path::new("staged.tar.gz")).unwrap();
        let staged = safepath::child(&parent, &name).unwrap();

        build_staging_archive(
            &FileSource::Directory {
                path: source.display().to_string(),
            },
            Path::new("/nonexistent"),
            &staged,
        )
        .unwrap();

        let file = std::fs::File::open(staged.as_path()).unwrap();
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
        let names: Vec<String> = tar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(
            !names.iter().any(|n| n.starts_with("leak")),
            "a symlink was archived: {names:?}"
        );
        assert!(names.iter().any(|n| n.ends_with("index.php")));
    }

    #[test]
    fn the_staging_archive_is_left_readable_for_the_tenants_helper() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let source = root.join("acct.tar.gz");
        tar_gz(
            &source,
            &[("bob/homedir/public_html/i.php", 0o644, b"x" as &[u8])],
        );

        let home = root.join("home");
        std::fs::create_dir(&home).unwrap();
        let (parent, name) = safepath::resolve_new(&home, Path::new("staged.tar.gz")).unwrap();
        let staged = safepath::child(&parent, &name).unwrap();

        build_staging_archive(
            &FileSource::TarSubtree {
                prefix: "bob/homedir/public_html".into(),
            },
            &source,
            &staged,
        )
        .unwrap();
        // Written 0600 by the restager; the helper runs as the tenant and only
        // needs to read it.
        make_readable(&staged).unwrap();
        let mode = std::fs::metadata(staged.as_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644, "got {mode:o}");
    }

    #[test]
    fn the_document_root_is_addressed_relative_to_the_tenant_home() {
        let subscription = ferrum_db::subscriptions::Subscription {
            id: SubscriptionId(1),
            customer_id: ferrum_core::UserId(1),
            plan_id: None,
            linux_user: "ft_abc".into(),
            home_dir: "/home/ft_abc".into(),
            status: ferrum_db::SubscriptionStatus::Active,
            suspended_reason: None,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            suspended_at: None,
        };
        let planned = PlannedSite {
            domain: "example.com".into(),
            role: model::DomainRole::Main,
            aliases: vec![],
            source_docroot: "/home/bob/public_html".into(),
            files: FileSource::TarSubtree {
                prefix: "bob/homedir/public_html".into(),
            },
            detected_php: None,
            target_php: None,
            file_count: 1,
            bytes: 1,
        };
        let relative =
            tenant_relative_docroot(Path::new("/home/ft_abc"), &planned, &subscription).unwrap();
        assert_eq!(relative.as_str(), "sites/example.com/public");
    }

    #[test]
    fn a_source_kind_is_a_closed_set() {
        assert!(serde_json::from_str::<SourceInput>(r#"{"kind":"cpanel","path":"/x"}"#).is_ok());
        assert!(serde_json::from_str::<SourceInput>(r#"{"kind":"aapanel"}"#).is_ok());
        assert!(serde_json::from_str::<SourceInput>(r#"{"kind":"plesk","path":"/x"}"#).is_err());
        assert_eq!(Src::Cpanel.as_str(), "cpanel");
    }
}
