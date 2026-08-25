//! The `fs.*` operations (spec §11.7): the file manager as the registry sees it.
//!
//! Every operation here resolves a subscription to its Linux account and home
//! through the caller's [`TenantScope`] — the same road `site.*` takes — so a
//! caller can only ever reach a home their scope can see. The path *inside*
//! the home arrives as a [`TenantPath`], which rejected `..`, absolute paths
//! and control characters at deserialisation; the helper then re-resolves it
//! under the tenant's own uid (spec §5.2 rule 3).
//!
//! File content crosses the operation JSON as base64, capped at
//! [`MAX_CHUNK`] decoded bytes per call. Big transfers are *chunked*: reads
//! pass an `offset`, writes pass `append: true` — which is how a 2 GB upload
//! fits through a panel whose agent never buffers more than one chunk
//! (spec §11.7 AC).

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ferrum_core::{
    ErrorCode, FerrumError, Permission, Result, SubscriptionId, TenantPath,
};
use serde::{Deserialize, Serialize};

use super::proto::{ArchiveFormat, EntryKind, FsData, FsEntry, FsRequest};
use super::{FsRunner, TRASH_DIR};
use crate::registry::{Execution, OpContext, TypedOperation};

/// The most decoded file content one call may carry, in either direction.
///
/// 8 MB keeps any single IPC frame comfortably bounded while still moving a
/// 2 GB upload in ~256 calls.
pub const MAX_CHUNK: u64 = 8 * 1024 * 1024;

/// Immediate operations answer inside an IPC round trip; a minute is already
/// generous for a rename, and a hard stop for a hung helper.
const IMMEDIATE_TIMEOUT: Duration = Duration::from_secs(60);

/// Compress/extract run as tasks and may chew through gigabytes.
const ARCHIVE_TIMEOUT: Duration = Duration::from_secs(60 * 60);

// ---------------------------------------------------------------------------
// resolving whose files these are
// ---------------------------------------------------------------------------

/// A resolved tenant filesystem: the home to operate under and the runner
/// that will do it (privilege-dropped helper in production, in-process when
/// the agent itself is unprivileged — dev mode and tests).
struct TenantFs {
    home: PathBuf,
    runner: FsRunner,
}

impl TenantFs {
    async fn call(
        &self,
        request: FsRequest,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> Result<(FsData, Vec<u8>)> {
        self.runner.call(&self.home, request, payload, timeout).await
    }
}

/// Resolve the subscription the caller named (or their default one) into a
/// [`TenantFs`], through the caller's scope — the same containment `site.*`
/// relies on, so a subscription outside the scope is a `NotFound`, never a
/// peek at someone else's home.
async fn tenant_fs(ctx: &OpContext, subscription_id: Option<i64>) -> Result<TenantFs> {
    let db = ctx.db();
    let subscription = match subscription_id {
        Some(id) => db
            .subscriptions(ctx.scope())
            .by_id(SubscriptionId(id))
            .await
            .map_err(FerrumError::from)?
            .ok_or_else(|| FerrumError::not_found("subscription"))?,
        None => db
            .default_subscription_for(ctx.auth().actor_user_id)
            .await
            .map_err(FerrumError::from)?,
    };

    Ok(TenantFs {
        home: PathBuf::from(&subscription.home_dir),
        runner: runner_for(&subscription.linux_user)?,
    })
}

/// Pick how requests for this account get executed.
///
/// Root agent → re-exec with a privilege drop to the account's uid/gid.
/// Unprivileged agent (dev mode, tests) → in-process: `setuid` is a root-only
/// call, so there is no privilege to drop — and nothing to protect either,
/// since a dev home is a scratch directory owned by the current user.
fn runner_for(linux_user: &str) -> Result<FsRunner> {
    // SAFETY: `geteuid` reads process state and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(FsRunner::Local);
    }

    let (uid, gid) = passwd_entry(linux_user).ok_or_else(|| {
        FerrumError::new(
            ErrorCode::NotFound,
            format!("the Linux account `{linux_user}` does not exist on this server"),
        )
    })?;
    // A tenant resolving to uid or gid 0 means the account database is wrong
    // in a way no file operation should get near: "drop" to root is not a drop.
    if uid == 0 || gid == 0 {
        return Err(FerrumError::internal(format!(
            "`{linux_user}` maps to uid/gid 0; refusing to run tenant file operations as root"
        )));
    }
    Ok(FsRunner::Tenant { uid, gid })
}

/// Resolve an account through `getpwnam`, so NSS sources (LDAP, sssd) work the
/// same way they do for every other program on the box.
fn passwd_entry(username: &str) -> Option<(u32, u32)> {
    let c_name = std::ffi::CString::new(username).ok()?;
    // SAFETY: `getpwnam` returns a pointer into a static buffer owned by libc;
    // we read it immediately and copy out the two integers we need.
    unsafe {
        let pw = libc::getpwnam(c_name.as_ptr());
        if pw.is_null() {
            return None;
        }
        Some(((*pw).pw_uid, (*pw).pw_gid))
    }
}

// ---------------------------------------------------------------------------
// small shared pieces
// ---------------------------------------------------------------------------

/// A `TenantPath` (or, absent, the home root) as the helper wants it.
fn rel(path: Option<&TenantPath>) -> PathBuf {
    path.map(|p| PathBuf::from(p.as_str())).unwrap_or_default()
}

fn expect_entries(data: FsData) -> Result<Vec<FsEntry>> {
    match data {
        FsData::Entries(entries) => Ok(entries),
        other => Err(FerrumError::internal(format!(
            "the fs helper answered out of shape: {other:?}"
        ))),
    }
}

fn expect_entry(data: FsData) -> Result<FsEntry> {
    match data {
        FsData::Entry(entry) => Ok(entry),
        other => Err(FerrumError::internal(format!(
            "the fs helper answered out of shape: {other:?}"
        ))),
    }
}

fn expect_bytes(data: FsData) -> Result<u64> {
    match data {
        FsData::Bytes(n) => Ok(n),
        other => Err(FerrumError::internal(format!(
            "the fs helper answered out of shape: {other:?}"
        ))),
    }
}

/// Is this path the recycle bin, or inside it?
fn in_trash(path: &TenantPath) -> bool {
    path.as_str() == TRASH_DIR || path.as_str().starts_with(".trash/")
}

/// Validate a single file *name* (one component, no separators) coming from
/// the API — trash entries and compress selections travel as bare names.
fn check_name(name: &str, field: &'static str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 255
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.chars().any(|c| c.is_control())
    {
        return Err(
            FerrumError::new(ErrorCode::InvalidPath, format!("`{name}` is not a usable name"))
                .with_field(field),
        );
    }
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `<unix-ts>-<original-name>` → (deleted_at, original name).
fn parse_trash_name(name: &str) -> (Option<i64>, &str) {
    if let Some((prefix, rest)) = name.split_once('-')
        && !rest.is_empty()
        && !prefix.is_empty()
        && prefix.bytes().all(|b| b.is_ascii_digit())
        && let Ok(ts) = prefix.parse::<i64>()
    {
        return (Some(ts), rest);
    }
    (None, name)
}

#[derive(Debug, Serialize)]
pub struct DoneOutput {
    pub done: bool,
}

// ---------------------------------------------------------------------------
// fs.list
// ---------------------------------------------------------------------------

pub struct List;

#[derive(Debug, Deserialize)]
pub struct ListInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// Directory to list; the home root when absent.
    #[serde(default)]
    pub path: Option<TenantPath>,
    #[serde(default)]
    pub show_hidden: bool,
}

#[derive(Debug, Serialize)]
pub struct EntriesOutput {
    pub entries: Vec<FsEntry>,
}

#[async_trait]
impl TypedOperation for List {
    type Input = ListInput;
    type Output = EntriesOutput;

    const NAME: &'static str = "fs.list";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let (data, _) = fs
            .call(
                FsRequest::List {
                    path: rel(input.path.as_ref()),
                    show_hidden: input.show_hidden,
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
        Ok(EntriesOutput {
            entries: expect_entries(data)?,
        })
    }
}

// ---------------------------------------------------------------------------
// fs.stat
// ---------------------------------------------------------------------------

pub struct Stat;

#[derive(Debug, Deserialize)]
pub struct StatInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    #[serde(default)]
    pub path: Option<TenantPath>,
}

#[derive(Debug, Serialize)]
pub struct EntryOutput {
    pub entry: FsEntry,
}

#[async_trait]
impl TypedOperation for Stat {
    type Input = StatInput;
    type Output = EntryOutput;

    const NAME: &'static str = "fs.stat";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let (data, _) = fs
            .call(
                FsRequest::Stat {
                    path: rel(input.path.as_ref()),
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
        Ok(EntryOutput {
            entry: expect_entry(data)?,
        })
    }
}

// ---------------------------------------------------------------------------
// fs.read
// ---------------------------------------------------------------------------

pub struct Read;

#[derive(Debug, Deserialize)]
pub struct ReadInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    pub path: TenantPath,
    /// Byte offset for chunked downloads; the editor reads from zero.
    #[serde(default)]
    pub offset: u64,
    /// Requested bytes; capped at [`MAX_CHUNK`] regardless.
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ReadOutput {
    /// The chunk, base64-encoded.
    pub content_b64: String,
    /// Total file size — what a chunked download sizes its progress bar with.
    pub size: u64,
    pub offset: u64,
    /// More bytes exist past this chunk.
    pub truncated: bool,
    /// The chunk is not valid UTF-8; the editor must refuse to open it.
    pub binary: bool,
}

#[async_trait]
impl TypedOperation for Read {
    type Input = ReadInput;
    type Output = ReadOutput;

    const NAME: &'static str = "fs.read";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let max_bytes = input.max_bytes.unwrap_or(MAX_CHUNK).min(MAX_CHUNK);
        let (data, payload) = fs
            .call(
                FsRequest::Read {
                    path: PathBuf::from(input.path.as_str()),
                    max_bytes,
                    offset: input.offset,
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
        let FsData::Content {
            size,
            truncated,
            binary,
        } = data
        else {
            return Err(FerrumError::internal("the fs helper answered out of shape"));
        };
        Ok(ReadOutput {
            content_b64: BASE64.encode(&payload),
            size,
            offset: input.offset,
            truncated,
            binary,
        })
    }
}

// ---------------------------------------------------------------------------
// fs.write
// ---------------------------------------------------------------------------

pub struct Write;

#[derive(Debug, Deserialize)]
pub struct WriteInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    pub path: TenantPath,
    /// The chunk, base64-encoded; at most [`MAX_CHUNK`] bytes decoded.
    pub content_b64: String,
    /// Append instead of replace — chunks two and later of an upload.
    #[serde(default)]
    pub append: bool,
    #[serde(default)]
    pub create_parents: bool,
}

#[derive(Debug, Serialize)]
pub struct WriteOutput {
    pub written: u64,
}

#[async_trait]
impl TypedOperation for Write {
    type Input = WriteInput;
    type Output = WriteOutput;

    const NAME: &'static str = "fs.write";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        // Refuse by length before decoding: a caller cannot make the agent
        // allocate the decoded buffer just to be told it is too big.
        if input.content_b64.len() as u64 > MAX_CHUNK / 3 * 4 + 4 {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("a single write may carry at most {MAX_CHUNK} bytes; send more chunks with `append`"),
            )
            .with_field("content_b64"));
        }
        let content = BASE64.decode(&input.content_b64).map_err(|e| {
            FerrumError::new(ErrorCode::InvalidInput, format!("content_b64: {e}"))
                .with_field("content_b64")
        })?;
        if content.len() as u64 > MAX_CHUNK {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                format!("a single write may carry at most {MAX_CHUNK} bytes"),
            )
            .with_field("content_b64"));
        }

        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let written = content.len() as u64;
        fs.call(
            FsRequest::Write {
                path: PathBuf::from(input.path.as_str()),
                len: written,
                create_parents: input.create_parents,
                append: input.append,
            },
            content,
            IMMEDIATE_TIMEOUT,
        )
        .await?;
        Ok(WriteOutput { written })
    }
}

// ---------------------------------------------------------------------------
// fs.mkdir
// ---------------------------------------------------------------------------

pub struct Mkdir;

#[derive(Debug, Deserialize)]
pub struct MkdirInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    pub path: TenantPath,
}

#[async_trait]
impl TypedOperation for Mkdir {
    type Input = MkdirInput;
    type Output = EntryOutput;

    const NAME: &'static str = "fs.mkdir";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let (data, _) = fs
            .call(
                FsRequest::Mkdir {
                    path: PathBuf::from(input.path.as_str()),
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
        Ok(EntryOutput {
            entry: expect_entry(data)?,
        })
    }
}

// ---------------------------------------------------------------------------
// fs.rename
// ---------------------------------------------------------------------------

pub struct Rename;

#[derive(Debug, Deserialize)]
pub struct RenameInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    pub from: TenantPath,
    pub to: TenantPath,
}

#[async_trait]
impl TypedOperation for Rename {
    type Input = RenameInput;
    type Output = EntryOutput;

    const NAME: &'static str = "fs.rename";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let (data, _) = fs
            .call(
                FsRequest::Rename {
                    from: PathBuf::from(input.from.as_str()),
                    to: PathBuf::from(input.to.as_str()),
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
        Ok(EntryOutput {
            entry: expect_entry(data)?,
        })
    }
}

// ---------------------------------------------------------------------------
// fs.copy
// ---------------------------------------------------------------------------

pub struct Copy;

#[derive(Debug, Deserialize)]
pub struct CopyInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    pub from: TenantPath,
    pub to: TenantPath,
}

#[derive(Debug, Serialize)]
pub struct BytesOutput {
    pub bytes: u64,
}

#[async_trait]
impl TypedOperation for Copy {
    type Input = CopyInput;
    type Output = BytesOutput;

    const NAME: &'static str = "fs.copy";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let (data, _) = fs
            .call(
                FsRequest::Copy {
                    from: PathBuf::from(input.from.as_str()),
                    to: PathBuf::from(input.to.as_str()),
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
        Ok(BytesOutput {
            bytes: expect_bytes(data)?,
        })
    }
}

// ---------------------------------------------------------------------------
// fs.delete — into the recycle bin, never gone (spec §11.7)
// ---------------------------------------------------------------------------

pub struct Delete;

#[derive(Debug, Deserialize)]
pub struct DeleteInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    pub path: TenantPath,
}

#[derive(Debug, Serialize)]
pub struct DeleteOutput {
    /// The entry's name inside `.trash`, for an immediate "undo".
    pub trashed_as: String,
}

#[async_trait]
impl TypedOperation for Delete {
    type Input = DeleteInput;
    type Output = DeleteOutput;

    const NAME: &'static str = "fs.delete";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        if in_trash(&input.path) {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "the recycle bin is emptied with fs.trash.purge, not deleted into itself",
            )
            .with_field("path"));
        }

        let fs = tenant_fs(ctx, input.subscription_id).await?;
        ensure_trash(&fs).await?;

        let original = input
            .path
            .as_str()
            .rsplit('/')
            .next()
            .unwrap_or(input.path.as_str());
        let now = unix_now();

        // `<unix-ts>-<name>`; on a same-second collision, bump the timestamp.
        // The prefix is what `fs.trash.list` parses back into "deleted at",
        // and what the 7-day purge measures against.
        for attempt in 0..20 {
            let trashed_as = format!("{}-{}", now + attempt, original);
            let result = fs
                .call(
                    FsRequest::Rename {
                        from: PathBuf::from(input.path.as_str()),
                        to: PathBuf::from(format!("{TRASH_DIR}/{trashed_as}")),
                    },
                    Vec::new(),
                    IMMEDIATE_TIMEOUT,
                )
                .await;
            match result {
                Ok(_) => return Ok(DeleteOutput { trashed_as }),
                Err(e) if e.code == ErrorCode::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(FerrumError::new(
            ErrorCode::Conflict,
            "could not find a free name in the recycle bin",
        ))
    }
}

/// Make sure `.trash` exists as a 0700 directory.
///
/// 0700 matters: the tenant's site runs as the same account, but other local
/// users (and a web server following a stray path) have no business reading
/// what a tenant deleted.
async fn ensure_trash(fs: &TenantFs) -> Result<()> {
    let stat = fs
        .call(
            FsRequest::Stat {
                path: PathBuf::from(TRASH_DIR),
            },
            Vec::new(),
            IMMEDIATE_TIMEOUT,
        )
        .await;

    match stat {
        Ok((FsData::Entry(entry), _)) if entry.kind == EntryKind::Dir => Ok(()),
        Ok(_) => Err(FerrumError::new(
            ErrorCode::Conflict,
            "something that is not a directory is occupying the `.trash` name",
        )),
        Err(e) if e.code == ErrorCode::NotFound => {
            fs.call(
                FsRequest::Mkdir {
                    path: PathBuf::from(TRASH_DIR),
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
            fs.call(
                FsRequest::Chmod {
                    path: PathBuf::from(TRASH_DIR),
                    mode: 0o700,
                    recursive: false,
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// fs.chmod
// ---------------------------------------------------------------------------

pub struct Chmod;

#[derive(Debug, Deserialize)]
pub struct ChmodInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    pub path: TenantPath,
    /// Permission bits only; the helper refuses setuid/setgid/sticky.
    pub mode: u32,
    #[serde(default)]
    pub recursive: bool,
}

#[async_trait]
impl TypedOperation for Chmod {
    type Input = ChmodInput;
    type Output = DoneOutput;

    const NAME: &'static str = "fs.chmod";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fs = tenant_fs(ctx, input.subscription_id).await?;
        fs.call(
            FsRequest::Chmod {
                path: PathBuf::from(input.path.as_str()),
                mode: input.mode,
                recursive: input.recursive,
            },
            Vec::new(),
            IMMEDIATE_TIMEOUT,
        )
        .await?;
        Ok(DoneOutput { done: true })
    }
}

// ---------------------------------------------------------------------------
// fs.search
// ---------------------------------------------------------------------------

pub struct Search;

#[derive(Debug, Deserialize)]
pub struct SearchInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// Substring of the file name, case-insensitive.
    pub query: String,
    #[serde(default)]
    pub root: Option<TenantPath>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[async_trait]
impl TypedOperation for Search {
    type Input = SearchInput;
    type Output = EntriesOutput;

    const NAME: &'static str = "fs.search";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let query = input.query.trim();
        if query.is_empty() || query.len() > 255 {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "the search query must be between 1 and 255 characters",
            )
            .with_field("query"));
        }

        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let (data, _) = fs
            .call(
                FsRequest::Search {
                    root: rel(input.root.as_ref()),
                    query: query.to_string(),
                    limit: input.limit.unwrap_or(100).min(500),
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
        Ok(EntriesOutput {
            entries: expect_entries(data)?,
        })
    }
}

// ---------------------------------------------------------------------------
// fs.compress / fs.extract — tasks: gigabytes take time (spec §10.1)
// ---------------------------------------------------------------------------

pub struct Compress;

#[derive(Debug, Deserialize)]
pub struct CompressInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// Directory the selection lives in; the home root when absent.
    #[serde(default)]
    pub root: Option<TenantPath>,
    /// Names (one level, no separators) under `root` to include.
    pub entries: Vec<String>,
    /// Where the archive lands. The extension should match `format`.
    pub archive: TenantPath,
    pub format: ArchiveFormat,
}

#[derive(Debug, Serialize)]
pub struct CompressOutput {
    pub archive: String,
    pub bytes: u64,
}

#[async_trait]
impl TypedOperation for Compress {
    type Input = CompressInput;
    type Output = CompressOutput;

    const NAME: &'static str = "fs.compress";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        // Re-running fails on the existing archive rather than rebuilding it.
        idempotent: false,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        if input.entries.is_empty() || input.entries.len() > 1000 {
            return Err(FerrumError::new(
                ErrorCode::InvalidInput,
                "select between 1 and 1000 entries to compress",
            )
            .with_field("entries"));
        }
        for name in &input.entries {
            check_name(name, "entries")?;
        }

        let fs = tenant_fs(ctx, input.subscription_id).await?;
        ctx.log(format!(
            "compressing {} entr{} into {}",
            input.entries.len(),
            if input.entries.len() == 1 { "y" } else { "ies" },
            input.archive.as_str()
        ));
        let (data, _) = fs
            .call(
                FsRequest::Compress {
                    root: rel(input.root.as_ref()),
                    entries: input.entries,
                    archive: PathBuf::from(input.archive.as_str()),
                    format: input.format,
                },
                Vec::new(),
                ARCHIVE_TIMEOUT,
            )
            .await?;
        let bytes = expect_bytes(data)?;
        ctx.log(format!("wrote {} ({bytes} bytes)", input.archive.as_str()));
        Ok(CompressOutput {
            archive: input.archive.as_str().to_string(),
            bytes,
        })
    }
}

pub struct Extract;

#[derive(Debug, Deserialize)]
pub struct ExtractInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    pub archive: TenantPath,
    /// Directory to extract into; the home root when absent. Must exist.
    #[serde(default)]
    pub dest: Option<TenantPath>,
}

#[derive(Debug, Serialize)]
pub struct ExtractOutput {
    pub files: u64,
    pub bytes: u64,
}

#[async_trait]
impl TypedOperation for Extract {
    type Input = ExtractInput;
    type Output = ExtractOutput;

    const NAME: &'static str = "fs.extract";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Task {
        cancellable: false,
        // Overwrites what it already extracted; a re-run converges.
        idempotent: true,
    };

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fs = tenant_fs(ctx, input.subscription_id).await?;
        ctx.log(format!("extracting {}", input.archive.as_str()));
        let (data, _) = fs
            .call(
                FsRequest::Extract {
                    archive: PathBuf::from(input.archive.as_str()),
                    dest: rel(input.dest.as_ref()),
                },
                Vec::new(),
                ARCHIVE_TIMEOUT,
            )
            .await?;
        let FsData::Extracted { files, bytes } = data else {
            return Err(FerrumError::internal("the fs helper answered out of shape"));
        };
        ctx.log(format!("extracted {files} files ({bytes} bytes)"));
        Ok(ExtractOutput { files, bytes })
    }
}

// ---------------------------------------------------------------------------
// fs.trash.* — the recycle bin
// ---------------------------------------------------------------------------

pub struct TrashList;

#[derive(Debug, Deserialize)]
pub struct TrashListInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TrashEntry {
    /// The raw name inside `.trash` — what restore and purge address.
    pub name: String,
    /// The name the file had before deletion.
    pub original_name: String,
    /// Unix seconds; `None` for an entry whose name did not carry one.
    pub deleted_at: Option<i64>,
    pub kind: EntryKind,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct TrashListOutput {
    pub entries: Vec<TrashEntry>,
}

#[async_trait]
impl TypedOperation for TrashList {
    type Input = TrashListInput;
    type Output = TrashListOutput;

    const NAME: &'static str = "fs.trash.list";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let entries = list_trash(&fs).await?;
        Ok(TrashListOutput { entries })
    }
}

/// List `.trash`, treating "no `.trash` yet" as simply empty — a tenant who
/// never deleted anything has an empty bin, not an error.
async fn list_trash(fs: &TenantFs) -> Result<Vec<TrashEntry>> {
    let listed = fs
        .call(
            FsRequest::List {
                path: PathBuf::from(TRASH_DIR),
                show_hidden: true,
            },
            Vec::new(),
            IMMEDIATE_TIMEOUT,
        )
        .await;
    let entries = match listed {
        Ok((data, _)) => expect_entries(data)?,
        Err(e) if e.code == ErrorCode::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut out: Vec<TrashEntry> = entries
        .into_iter()
        .map(|entry| {
            let (deleted_at, original) = parse_trash_name(&entry.name);
            TrashEntry {
                original_name: original.to_string(),
                deleted_at,
                kind: entry.kind,
                size: entry.size,
                name: entry.name,
            }
        })
        .collect();
    // Newest first: the thing just deleted is the thing being looked for.
    out.sort_by_key(|a| std::cmp::Reverse(a.deleted_at));
    Ok(out)
}

pub struct TrashRestore;

#[derive(Debug, Deserialize)]
pub struct TrashRestoreInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// The entry's name inside `.trash`, from `fs.trash.list`.
    pub name: String,
    /// Where to restore to; defaults to the original name in the home root.
    #[serde(default)]
    pub to: Option<TenantPath>,
}

#[async_trait]
impl TypedOperation for TrashRestore {
    type Input = TrashRestoreInput;
    type Output = EntryOutput;

    const NAME: &'static str = "fs.trash.restore";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        check_name(&input.name, "name")?;

        let to = match &input.to {
            Some(path) => {
                if in_trash(path) {
                    return Err(FerrumError::new(
                        ErrorCode::InvalidInput,
                        "restoring into the recycle bin is not a restore",
                    )
                    .with_field("to"));
                }
                PathBuf::from(path.as_str())
            }
            None => {
                let (_, original) = parse_trash_name(&input.name);
                check_name(original, "name")?;
                PathBuf::from(original)
            }
        };

        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let (data, _) = fs
            .call(
                FsRequest::Rename {
                    from: PathBuf::from(format!("{TRASH_DIR}/{}", input.name)),
                    to,
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
        Ok(EntryOutput {
            entry: expect_entry(data)?,
        })
    }
}

pub struct TrashPurge;

#[derive(Debug, Deserialize)]
pub struct TrashPurgeInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// Only purge entries deleted at least this many days ago. Zero (the
    /// default) empties the bin; the scheduled auto-purge passes 7
    /// (spec §11.7).
    #[serde(default)]
    pub older_than_days: u32,
}

#[derive(Debug, Serialize)]
pub struct TrashPurgeOutput {
    pub removed: u64,
}

#[async_trait]
impl TypedOperation for TrashPurge {
    type Input = TrashPurgeInput;
    type Output = TrashPurgeOutput;

    const NAME: &'static str = "fs.trash.purge";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let cutoff = unix_now() - i64::from(input.older_than_days) * 86_400;

        let mut removed = 0u64;
        for entry in list_trash(&fs).await? {
            // An entry with no parseable timestamp is purged on "empty the
            // bin" (cutoff = now) and left alone by the aged purge — deleting
            // something whose age we cannot prove is how data loss stories
            // start.
            let old_enough = match entry.deleted_at {
                Some(ts) => ts <= cutoff,
                None => input.older_than_days == 0,
            };
            if !old_enough {
                continue;
            }
            fs.call(
                FsRequest::Remove {
                    path: PathBuf::from(format!("{TRASH_DIR}/{}", entry.name)),
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
            removed += 1;
        }
        Ok(TrashPurgeOutput { removed })
    }
}

// ---------------------------------------------------------------------------
// fs.usage
// ---------------------------------------------------------------------------

pub struct Usage;

#[derive(Debug, Deserialize)]
pub struct UsageInput {
    #[serde(default)]
    pub subscription_id: Option<i64>,
    /// Subtree to measure; the whole home when absent.
    #[serde(default)]
    pub path: Option<TenantPath>,
}

#[derive(Debug, Serialize)]
pub struct UsageOutput {
    /// Disk blocks used by the subtree, in bytes. Includes the recycle bin
    /// when measuring the whole home — the bin is quota-counted (spec §11.7).
    pub bytes: u64,
    /// The recycle bin's share, so the UI can say "N MB of that is trash".
    pub trash_bytes: u64,
}

#[async_trait]
impl TypedOperation for Usage {
    type Input = UsageInput;
    type Output = UsageOutput;

    const NAME: &'static str = "fs.usage";
    const PERMISSION: Permission = Permission::FileManage;
    const EXECUTION: Execution = Execution::Immediate;

    async fn run(&self, ctx: &OpContext, input: Self::Input) -> Result<Self::Output> {
        let fs = tenant_fs(ctx, input.subscription_id).await?;
        let (data, _) = fs
            .call(
                FsRequest::Usage {
                    path: rel(input.path.as_ref()),
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await?;
        let bytes = expect_bytes(data)?;

        let trash_bytes = match fs
            .call(
                FsRequest::Usage {
                    path: PathBuf::from(TRASH_DIR),
                },
                Vec::new(),
                IMMEDIATE_TIMEOUT,
            )
            .await
        {
            Ok((data, _)) => expect_bytes(data)?,
            Err(e) if e.code == ErrorCode::NotFound => 0,
            Err(e) => return Err(e),
        };

        Ok(UsageOutput { bytes, trash_bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::testing::{auth_for, registry};
    use crate::registry::OpRegistry;
    use ferrum_core::{Role, UserId};

    /// A registry whose seeded customer's subscription points at a real,
    /// throwaway home directory.
    async fn registry_with_home() -> (OpRegistry, UserId, tempfile::TempDir, std::path::PathBuf)
    {
        let (reg, _admin, customer) = registry().await;
        let db = reg.services().db.clone();
        let subscription = db.default_subscription_for(customer).await.unwrap();

        let dir = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(dir.path()).unwrap();
        sqlx::query("UPDATE subscriptions SET home_dir = ?1 WHERE id = ?2")
            .bind(home.to_str().unwrap())
            .bind(subscription.id.get())
            .execute(db.pool())
            .await
            .unwrap();

        (reg, customer, dir, home)
    }

    async fn run(
        reg: &OpRegistry,
        user: UserId,
        op: &str,
        input: serde_json::Value,
    ) -> ferrum_core::Result<serde_json::Value> {
        reg.dispatch(op, &auth_for(user, Role::Customer), input, None)
            .await
    }

    fn b64(bytes: &[u8]) -> String {
        BASE64.encode(bytes)
    }

    #[tokio::test]
    async fn a_write_reads_back_through_the_registry() {
        let (reg, user, _g, home) = registry_with_home().await;

        let out = run(
            &reg,
            user,
            "fs.write",
            serde_json::json!({
                "path": "site/index.php",
                "content_b64": b64(b"<?php echo 'hi';"),
                "create_parents": true,
            }),
        )
        .await
        .unwrap();
        assert_eq!(out["written"], 16);
        assert!(home.join("site/index.php").is_file());

        let out = run(
            &reg,
            user,
            "fs.read",
            serde_json::json!({ "path": "site/index.php" }),
        )
        .await
        .unwrap();
        assert_eq!(out["binary"], false);
        assert_eq!(out["truncated"], false);
        assert_eq!(
            BASE64.decode(out["content_b64"].as_str().unwrap()).unwrap(),
            b"<?php echo 'hi';"
        );
    }

    #[tokio::test]
    async fn a_chunked_upload_appends_in_order() {
        let (reg, user, _g, home) = registry_with_home().await;

        for (i, chunk) in [&b"AAAA"[..], b"BBBB", b"CC"].iter().enumerate() {
            run(
                &reg,
                user,
                "fs.write",
                serde_json::json!({
                    "path": "upload.bin",
                    "content_b64": b64(chunk),
                    "append": i > 0,
                }),
            )
            .await
            .unwrap();
        }
        assert_eq!(std::fs::read(home.join("upload.bin")).unwrap(), b"AAAABBBBCC");
    }

    #[tokio::test]
    async fn a_traversal_path_dies_at_deserialisation() {
        // Spec §11.7 AC: traversal attempts fail safely. The `..` never even
        // reaches the operation body — TenantPath refuses to exist for it.
        let (reg, user, _g, _home) = registry_with_home().await;
        for bad in ["../../etc/passwd", "a/../b", "/etc/passwd"] {
            let err = run(&reg, user, "fs.read", serde_json::json!({ "path": bad }))
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{bad}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_out_of_the_home_cannot_be_read_through() {
        let (reg, user, _g, home) = registry_with_home().await;
        std::os::unix::fs::symlink("/etc", home.join("escape")).unwrap();

        let err = run(
            &reg,
            user,
            "fs.read",
            serde_json::json!({ "path": "escape/passwd" }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidPath);
    }

    #[tokio::test]
    async fn deleted_files_land_in_the_trash_and_restore_by_name() {
        let (reg, user, _g, home) = registry_with_home().await;
        run(
            &reg,
            user,
            "fs.write",
            serde_json::json!({ "path": "precious.txt", "content_b64": b64(b"keep me") }),
        )
        .await
        .unwrap();

        let out = run(
            &reg,
            user,
            "fs.delete",
            serde_json::json!({ "path": "precious.txt" }),
        )
        .await
        .unwrap();
        let trashed_as = out["trashed_as"].as_str().unwrap().to_string();
        assert!(!home.join("precious.txt").exists());
        assert!(home.join(".trash").join(&trashed_as).is_file());

        // The bin is 0700, and hidden from a normal listing.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(home.join(".trash"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        let listed = run(&reg, user, "fs.list", serde_json::json!({ "show_hidden": true }))
            .await
            .unwrap();
        assert!(
            listed["entries"]
                .as_array()
                .unwrap()
                .iter()
                .all(|e| e["name"] != ".trash"),
            "the bin has its own view"
        );

        let listed = run(&reg, user, "fs.trash.list", serde_json::json!({}))
            .await
            .unwrap();
        let entries = listed["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["original_name"], "precious.txt");
        assert!(entries[0]["deleted_at"].as_i64().is_some());

        run(
            &reg,
            user,
            "fs.trash.restore",
            serde_json::json!({ "name": trashed_as }),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(home.join("precious.txt")).unwrap(), b"keep me");
    }

    #[tokio::test]
    async fn deleting_the_same_name_twice_keeps_both_copies() {
        let (reg, user, _g, _home) = registry_with_home().await;
        for content in ["v1", "v2"] {
            run(
                &reg,
                user,
                "fs.write",
                serde_json::json!({ "path": "a.txt", "content_b64": b64(content.as_bytes()) }),
            )
            .await
            .unwrap();
            run(&reg, user, "fs.delete", serde_json::json!({ "path": "a.txt" }))
                .await
                .unwrap();
        }
        let listed = run(&reg, user, "fs.trash.list", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(listed["entries"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn purge_zero_days_empties_the_bin_and_aged_purge_spares_the_young() {
        let (reg, user, _g, _home) = registry_with_home().await;
        run(
            &reg,
            user,
            "fs.write",
            serde_json::json!({ "path": "young.txt", "content_b64": b64(b"x") }),
        )
        .await
        .unwrap();
        run(&reg, user, "fs.delete", serde_json::json!({ "path": "young.txt" }))
            .await
            .unwrap();

        // Deleted seconds ago: a 7-day purge must not touch it.
        let out = run(
            &reg,
            user,
            "fs.trash.purge",
            serde_json::json!({ "older_than_days": 7 }),
        )
        .await
        .unwrap();
        assert_eq!(out["removed"], 0);

        let out = run(&reg, user, "fs.trash.purge", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(out["removed"], 1);
        let listed = run(&reg, user, "fs.trash.list", serde_json::json!({}))
            .await
            .unwrap();
        assert!(listed["entries"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_bin_cannot_be_deleted_into_itself() {
        let (reg, user, _g, _home) = registry_with_home().await;
        for bad in [".trash", ".trash/anything"] {
            let err = run(&reg, user, "fs.delete", serde_json::json!({ "path": bad }))
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput, "{bad}");
        }
    }

    #[tokio::test]
    async fn compress_and_extract_round_trip_through_the_registry() {
        let (reg, user, _g, home) = registry_with_home().await;
        run(
            &reg,
            user,
            "fs.write",
            serde_json::json!({
                "path": "src/app.js",
                "content_b64": b64(b"console.log(1)"),
                "create_parents": true,
            }),
        )
        .await
        .unwrap();

        let out = run(
            &reg,
            user,
            "fs.compress",
            serde_json::json!({
                "entries": ["src"],
                "archive": "src.zip",
                "format": "zip",
            }),
        )
        .await
        .unwrap();
        assert!(out["bytes"].as_u64().unwrap() > 0);

        run(&reg, user, "fs.mkdir", serde_json::json!({ "path": "restored" }))
            .await
            .unwrap();
        let out = run(
            &reg,
            user,
            "fs.extract",
            serde_json::json!({ "archive": "src.zip", "dest": "restored" }),
        )
        .await
        .unwrap();
        assert_eq!(out["files"], 1);
        assert_eq!(
            std::fs::read(home.join("restored/src/app.js")).unwrap(),
            b"console.log(1)"
        );
    }

    #[tokio::test]
    async fn another_tenants_subscription_is_out_of_scope() {
        use ferrum_core::{Email, TenantScope, Username};
        use ferrum_db::users::NewUser;

        let (reg, user, _g, _home) = registry_with_home().await;
        let db = reg.services().db.clone();
        let other = db
            .users(&TenantScope::Global)
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
        let other_sub = db.default_subscription_for(other.id).await.unwrap();

        let err = run(
            &reg,
            user,
            "fs.list",
            serde_json::json!({ "subscription_id": other_sub.id.get() }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::NotFound,
            "a subscription outside the caller's scope must not even be acknowledged"
        );
    }

    #[tokio::test]
    async fn an_oversized_chunk_is_refused_before_it_is_decoded() {
        let (reg, user, _g, home) = registry_with_home().await;
        let too_big = "A".repeat((MAX_CHUNK / 3 * 4 + 8) as usize);
        let err = run(
            &reg,
            user,
            "fs.write",
            serde_json::json!({ "path": "big.bin", "content_b64": too_big }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(!home.join("big.bin").exists());
    }

    #[tokio::test]
    async fn usage_reports_the_trash_share_separately() {
        let (reg, user, _g, _home) = registry_with_home().await;
        run(
            &reg,
            user,
            "fs.write",
            serde_json::json!({ "path": "junk.bin", "content_b64": b64(&[0u8; 4096]) }),
        )
        .await
        .unwrap();
        run(&reg, user, "fs.delete", serde_json::json!({ "path": "junk.bin" }))
            .await
            .unwrap();

        let out = run(&reg, user, "fs.usage", serde_json::json!({}))
            .await
            .unwrap();
        let total = out["bytes"].as_u64().unwrap();
        let trash = out["trash_bytes"].as_u64().unwrap();
        assert!(trash > 0, "the deleted file still costs quota");
        assert!(total >= trash);
    }

    #[test]
    fn trash_names_parse_back_into_time_and_name() {
        assert_eq!(parse_trash_name("1724567890-a.txt"), (Some(1724567890), "a.txt"));
        assert_eq!(
            parse_trash_name("1724567890-with-dashes.txt"),
            (Some(1724567890), "with-dashes.txt")
        );
        assert_eq!(parse_trash_name("no-timestamp"), (None, "no-timestamp"));
        assert_eq!(parse_trash_name("plain"), (None, "plain"));
        assert_eq!(parse_trash_name("123-"), (None, "123-"));
    }

    #[test]
    fn restore_names_must_be_single_components() {
        for bad in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
            assert!(check_name(bad, "name").is_err(), "{bad:?}");
        }
        assert!(check_name("1724567890-a.txt", "name").is_ok());
    }
}
