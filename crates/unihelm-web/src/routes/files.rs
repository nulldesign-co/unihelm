//! The file manager API (spec §11.7).
//!
//! This layer is deliberately thin: every byte that touches a tenant's disk
//! does so in the agent, as the tenant's uid, behind the agent's own path
//! canonicalisation. What the web layer owns is the *shape* of the HTTP
//! surface, and three properties that must hold before a request ever reaches
//! the agent:
//!
//! 1. **Paths are [`TenantPath`]s at deserialization.** A traversal attempt
//!    (`../../etc/passwd`, an absolute path, a NUL byte) dies in serde with
//!    `FER-1204` and never becomes an op call. The agent re-validates — it does
//!    not trust us (spec §5.2 rule 3) — but rejecting here means hostile input
//!    cannot even *reach* the privileged process.
//! 2. **Bodies are bounded.** The JSON envelope is capped at 12 MiB and the
//!    raw content of one write/upload chunk at [`MAX_CONTENT_BYTES`], sized so
//!    the base64-inflated IPC frame fits the transport's hard limit. Large
//!    files move as many small chunks, never as one large buffer — that is
//!    what lets a 2 GB upload cross a 1 GB RAM server (spec §11.7 AC).
//! 3. **Downloads stream in constant memory.** The response body is produced
//!    by looping `fs.read` one chunk at a time; at no point does the whole
//!    file exist in this process.
//!
//! Uploads are resumable without server-side sessions: the client sends
//! `{path, offset, content_b64, done}` chunks, the first chunk truncates and
//! every later chunk appends. Append is inherently monotonic, and a stat
//! before each append confirms the file is exactly `offset` bytes long, so a
//! retried or reordered chunk gets `FER-1403` instead of silently corrupting
//! the file.

use axum::extract::{ConnectInfo, DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, header};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures::Stream;
use serde::Deserialize;
use serde_json::{Value, json};
use std::future::Future;
use std::net::SocketAddr;
use unihelm_core::{ErrorCode, Permission, TenantPath, UnihelmError};
use unihelm_db::audit::NewAuditEntry;

use crate::auth::{CurrentUser, client_ip};
use crate::error::{ApiError, ApiResult};
use crate::routes::ops;
use crate::state::SharedState;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Cap on one `/api/files` JSON request body.
///
/// Larger than the panel-wide 2 MiB default because a chunk of file content
/// rides inside the JSON; still a hard ceiling so a client cannot make us
/// buffer without bound. Applied per-route via [`DefaultBodyLimit`] below.
pub const MAX_BODY_BYTES: usize = 12 * 1024 * 1024;

/// Cap on the *decoded* content of one write/upload chunk, and the size of one
/// download chunk.
///
/// Chosen so a chunk survives the trip to the agent: base64 inflates by 4/3,
/// and the whole IPC frame must stay under
/// [`unihelm_ipc::codec::MAX_FRAME_BYTES`]. A client that wants to move more
/// than this sends more chunks, not bigger ones.
pub const MAX_CONTENT_BYTES: usize = 4 * 1024 * 1024;

// If someone shrinks the IPC frame limit, this stops compiling instead of
// letting every upload chunk start failing at runtime.
const _: () = assert!(
    (MAX_CONTENT_BYTES / 3 + 1) * 4 + 64 * 1024 < unihelm_ipc::codec::MAX_FRAME_BYTES,
    "a base64 content chunk plus JSON envelope must fit one IPC frame"
);

/// Search results are for a picker, not an export; a bounded list keeps the
/// op's runtime and the response size predictable.
const MAX_SEARCH_LIMIT: u32 = 500;
const DEFAULT_SEARCH_LIMIT: u32 = 100;

/// The recycle bin auto-purges at 7 days (spec §11.7); an explicit purge with
/// a horizon beyond ten years is a client bug, not a policy.
const MAX_PURGE_DAYS: u32 = 3650;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/api/files/list", get(list))
        .route("/api/files/stat", get(stat))
        .route("/api/files/read", get(read))
        .route("/api/files/write", put(write))
        .route("/api/files/download", get(download))
        .route("/api/files/upload", post(upload))
        .route("/api/files/mkdir", post(mkdir))
        .route("/api/files/rename", post(rename))
        .route("/api/files/copy", post(copy))
        .route("/api/files/delete", post(delete))
        .route("/api/files/chmod", post(chmod))
        .route("/api/files/search", post(search))
        .route("/api/files/compress", post(compress))
        .route("/api/files/extract", post(extract))
        .route("/api/files/usage", get(usage))
        .route("/api/files/trash", get(trash_list))
        .route("/api/files/trash/restore", post(trash_restore))
        .route("/api/files/trash/purge", post(trash_purge))
        // The panel-wide body limit is 2 MiB; file content rides in JSON here,
        // so these routes get their own ceiling. NOTE: `main.rs` still wraps
        // everything in a 2 MiB `RequestBodyLimitLayer`, which the integrator
        // must lift for `/api/files` for this larger bound to take effect.
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// Deserialize a path that may be empty, meaning the tenant home itself.
///
/// `TenantPath::parse` rejects the empty string on purpose — for `read` or
/// `delete`, "the home directory" is never a valid target. Listing and
/// searching it is, so those fields opt in through this.
fn path_or_root<'de, D>(deserializer: D) -> Result<TenantPath, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        return Ok(TenantPath::root());
    }
    TenantPath::parse(&s).map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default = "TenantPath::root", deserialize_with = "path_or_root")]
    pub path: TenantPath,
    #[serde(default)]
    pub hidden: bool,
    /// Which tenant, when the caller's scope spans more than one.
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

/// A path that must name a file, not the home directory.
///
/// `TenantPath` treats the empty string as the home itself, which is right for
/// listing and wrong for everything that opens a file: "read the home" is not a
/// request the agent should be asked to refuse, it is a request that should not
/// have been built. Rejecting it here turns a 503 round trip into a 400 with a
/// reason.
fn file_path<'de, D>(deserializer: D) -> Result<TenantPath, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path = TenantPath::deserialize(deserializer)?;
    if path.as_str().is_empty() {
        return Err(serde::de::Error::custom(
            "this operation needs a file, and an empty path means the home directory",
        ));
    }
    Ok(path)
}

#[derive(Debug, Deserialize)]
pub struct PathQuery {
    #[serde(deserialize_with = "file_path")]
    pub path: TenantPath,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ReadQuery {
    #[serde(deserialize_with = "file_path")]
    pub path: TenantPath,
    #[serde(default)]
    pub offset: u64,
    /// Clamped to [`MAX_CONTENT_BYTES`]; the client pages, it does not ask
    /// for the whole file in one reply.
    #[serde(default)]
    pub max_bytes: Option<u64>,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UsageQuery {
    #[serde(default = "TenantPath::root", deserialize_with = "path_or_root")]
    pub path: TenantPath,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct WriteRequest {
    pub path: TenantPath,
    #[serde(default)]
    pub append: bool,
    pub content_b64: String,
    #[serde(default)]
    pub create_parents: bool,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UploadChunk {
    pub path: TenantPath,
    #[serde(default)]
    pub offset: u64,
    pub content_b64: String,
    /// Purely informational for the response; append semantics make an
    /// explicit "commit" unnecessary.
    #[serde(default)]
    pub done: bool,
    #[serde(default)]
    pub create_parents: bool,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct PathRequest {
    pub path: TenantPath,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct FromToRequest {
    pub from: TenantPath,
    pub to: TenantPath,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ChmodRequest {
    pub path: TenantPath,
    pub mode: u32,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct SearchRequest {
    #[serde(default = "TenantPath::root", deserialize_with = "path_or_root")]
    pub root: TenantPath,
    pub query: String,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CompressRequest {
    #[serde(default = "TenantPath::root", deserialize_with = "path_or_root")]
    pub root: TenantPath,
    /// Names directly under `root` — one level, no separators. The op resolves
    /// them; we only refuse the obviously hostile shapes.
    pub entries: Vec<String>,
    pub archive: TenantPath,
    /// Passed through verbatim; the op owns the list of supported formats, so
    /// an unknown one is its 400 to give, not ours to guess wrong.
    pub format: String,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ExtractRequest {
    pub archive: TenantPath,
    #[serde(default = "TenantPath::root", deserialize_with = "path_or_root")]
    pub dest: TenantPath,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct PurgeRequest {
    /// `0` (the default) empties the bin; the 7-day auto-purge is the
    /// scheduler's job, not this endpoint's.
    #[serde(default)]
    pub older_than_days: u32,
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

// ---------------------------------------------------------------------------
// Read endpoints
// ---------------------------------------------------------------------------

pub async fn list(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "fs.list",
        json!({
            "path": q.path.as_str(),
            "show_hidden": q.hidden,
            "subscription_id": q.subscription_id,
        }),
    )
    .await?;
    Ok(Json(data))
}

pub async fn stat(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<PathQuery>,
) -> ApiResult<Json<Value>> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "fs.stat",
        json!({ "path": q.path.as_str(), "subscription_id": q.subscription_id }),
    )
    .await?;
    Ok(Json(data))
}

/// One chunk of a file, for the editor. The response is the op's own JSON
/// (`{size, eof, binary, content_b64}`); the editor pages through a large file
/// with successive offsets rather than asking for it whole.
pub async fn read(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<ReadQuery>,
) -> ApiResult<Json<Value>> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    let max_bytes = q
        .max_bytes
        .unwrap_or(MAX_CONTENT_BYTES as u64)
        .clamp(1, MAX_CONTENT_BYTES as u64);
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "fs.read",
        json!({
            "path": q.path.as_str(),
            "offset": q.offset,
            "max_bytes": max_bytes,
            "subscription_id": q.subscription_id,
        }),
    )
    .await?;
    Ok(Json(data))
}

pub async fn usage(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<UsageQuery>,
) -> ApiResult<Json<Value>> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "fs.usage",
        json!({ "path": q.path.as_str(), "subscription_id": q.subscription_id }),
    )
    .await?;
    Ok(Json(data))
}

#[derive(Debug, Deserialize)]
pub struct TrashQuery {
    #[serde(default)]
    pub subscription_id: Option<i64>,
}

pub async fn trash_list(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<TrashQuery>,
) -> ApiResult<Json<Value>> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    let data = ops::invoke_now(
        &state,
        &current.auth,
        "fs.trash.list",
        json!({ "subscription_id": q.subscription_id }),
    )
    .await?;
    Ok(Json(data))
}

// ---------------------------------------------------------------------------
// Download — a constant-memory chunk loop
// ---------------------------------------------------------------------------

/// One decoded chunk of a streamed download.
#[derive(Debug, PartialEq)]
pub(crate) struct ReadChunk {
    pub bytes: Vec<u8>,
    pub eof: bool,
}

/// Interpret an `fs.read` reply. Anything malformed is `FER-1501` — the agent
/// speaking a shape we do not recognise is a protocol failure, not user error.
pub(crate) fn parse_read_chunk(data: &Value) -> Result<ReadChunk, UnihelmError> {
    let content = data
        .get("content_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            UnihelmError::new(ErrorCode::AgentProtocol, "fs.read reply has no content_b64")
        })?;
    let eof = data.get("eof").and_then(Value::as_bool).ok_or_else(|| {
        UnihelmError::new(ErrorCode::AgentProtocol, "fs.read reply has no eof flag")
    })?;
    let bytes = BASE64.decode(content).map_err(|e| {
        UnihelmError::new(
            ErrorCode::AgentProtocol,
            format!("fs.read content is not valid base64: {e}"),
        )
    })?;
    Ok(ReadChunk { bytes, eof })
}

/// The download body: yield `first`, then keep fetching from where it ended
/// until a chunk says `eof`.
///
/// Only one chunk is ever held at a time — that is the constant-memory claim
/// of spec §11.7, and the tests pin it by observing that the next fetch does
/// not happen until the previous chunk has been consumed. A peer that returns
/// an empty chunk without `eof` would loop us forever, so that shape is an
/// error, not a retry.
pub(crate) fn chunk_stream<F, Fut>(
    first: ReadChunk,
    fetch: F,
) -> impl Stream<Item = Result<axum::body::Bytes, UnihelmError>> + Send
where
    F: Fn(u64) -> Fut + Send + 'static,
    Fut: Future<Output = Result<ReadChunk, UnihelmError>> + Send,
{
    async_stream::try_stream! {
        let mut offset = first.bytes.len() as u64;
        let mut eof = first.eof;
        if first.bytes.is_empty() && !eof {
            Err(UnihelmError::new(
                ErrorCode::AgentProtocol,
                "fs.read returned an empty chunk before eof",
            ))?;
        }
        if !first.bytes.is_empty() {
            yield axum::body::Bytes::from(first.bytes);
        }
        while !eof {
            let chunk = fetch(offset).await?;
            eof = chunk.eof;
            if chunk.bytes.is_empty() {
                if eof {
                    break;
                }
                Err(UnihelmError::new(
                    ErrorCode::AgentProtocol,
                    "fs.read returned an empty chunk before eof",
                ))?;
            }
            offset += chunk.bytes.len() as u64;
            yield axum::body::Bytes::from(chunk.bytes);
        }
    }
}

/// Refuse to stream anything that is not a plain file.
///
/// The agent enforces this too; checking the stat here turns "download a
/// directory" into a 400 with words instead of a 200 that dies mid-stream —
/// once the status line has gone out, there is no way left to say what went
/// wrong.
pub(crate) fn ensure_downloadable(stat: &Value) -> Result<(), UnihelmError> {
    // Tolerate the entry arriving bare or wrapped as `{entry: {...}}`.
    let entry = stat.get("entry").filter(|v| v.is_object()).unwrap_or(stat);
    if entry
        .get("escapes")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        // A symlink pointing out of the tenant home is displayed as broken and
        // never followed (spec §11.7 AC on symlink traversal).
        return Err(UnihelmError::new(
            ErrorCode::InvalidPath,
            "this link points outside your home directory",
        ));
    }
    match entry.get("kind").and_then(Value::as_str) {
        Some("file") | Some("symlink") => Ok(()),
        Some("dir") => Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "this is a directory — compress it to download it as an archive",
        )),
        Some(_) => Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            "only regular files can be downloaded",
        )),
        None => Err(UnihelmError::new(
            ErrorCode::AgentProtocol,
            "fs.stat reply has no kind",
        )),
    }
}

/// `Content-Disposition` that survives hostile file names.
///
/// The quoted `filename` is the ASCII fallback with anything header-breaking
/// replaced, and the real name travels RFC 5987-encoded in `filename*` — a
/// name like `evil"; url=x.txt` must not be able to splice new parameters
/// into the header.
pub(crate) fn content_disposition(name: &str) -> String {
    let fallback: String = name
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' | ' ' => c,
            _ => '_',
        })
        .collect();
    let fallback = if fallback.trim().is_empty() {
        "download".to_string()
    } else {
        fallback
    };

    let mut encoded = String::with_capacity(name.len());
    for b in name.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'&'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~' => encoded.push(b as char),
            _ => encoded.push_str(&format!("%{b:02X}")),
        }
    }
    format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
}

pub async fn download(
    State(state): State<SharedState>,
    current: CurrentUser,
    Query(q): Query<PathQuery>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;

    // Stat first: "no such file" must be a 404 with a body, which is only
    // possible before the streaming response has committed to a 200.
    let stat = ops::invoke_now(
        &state,
        &current.auth,
        "fs.stat",
        json!({ "path": q.path.as_str(), "subscription_id": q.subscription_id }),
    )
    .await?;
    ensure_downloadable(&stat).map_err(ApiError::new)?;

    let auth = current.auth.clone();
    let path = q.path.clone();
    let subscription_id = q.subscription_id;
    let fetch_state = state.clone();
    let fetch = move |offset: u64| {
        let state = fetch_state.clone();
        let auth = auth.clone();
        let path = path.clone();
        async move {
            let data = ops::invoke_now(
                &state,
                &auth,
                "fs.read",
                json!({
                    "path": path.as_str(),
                    "offset": offset,
                    "max_bytes": MAX_CONTENT_BYTES as u64,
                    "subscription_id": subscription_id,
                }),
            )
            .await
            .map_err(|e| e.inner)?;
            parse_read_chunk(&data)
        }
    };

    // Fetch the first chunk eagerly for the same reason as the stat: a file
    // that cannot be read should fail with a status code, not a torn stream.
    let first = fetch(0).await.map_err(ApiError::new)?;
    let stream = chunk_stream(first, fetch);

    let name = q.path.as_str().rsplit('/').next().unwrap_or("download");
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, content_disposition(name))
        .body(axum::body::Body::from_stream(stream))
        .map_err(|e| ApiError::code(ErrorCode::Internal, format!("response build failed: {e}")))
}

// ---------------------------------------------------------------------------
// Write & upload
// ---------------------------------------------------------------------------

/// Validate one chunk's base64 payload and return its decoded length.
///
/// The length pre-check runs before the decode so an oversized chunk is
/// refused by arithmetic, not by allocating it first.
pub(crate) fn checked_content_len(content_b64: &str) -> Result<u64, UnihelmError> {
    // 4 base64 characters encode 3 bytes; a little slack for padding.
    if content_b64.len() > (MAX_CONTENT_BYTES / 3 + 1) * 4 + 4 {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!("one chunk may carry at most {MAX_CONTENT_BYTES} bytes — send more chunks"),
        )
        .with_field("content_b64"));
    }
    let bytes = BASE64.decode(content_b64).map_err(|e| {
        UnihelmError::new(
            ErrorCode::InvalidInput,
            format!("content_b64 is not valid base64: {e}"),
        )
        .with_field("content_b64")
    })?;
    if bytes.len() > MAX_CONTENT_BYTES {
        return Err(UnihelmError::new(
            ErrorCode::InvalidInput,
            format!("one chunk may carry at most {MAX_CONTENT_BYTES} bytes — send more chunks"),
        )
        .with_field("content_b64"));
    }
    Ok(bytes.len() as u64)
}

/// May this chunk be applied to a file that is currently `existing_size` bytes
/// long (`None`: does not exist)?
///
/// The upload protocol keeps no server-side session; monotonicity comes from
/// append itself, and this check is what turns a duplicated or reordered
/// chunk into `FER-1403` instead of a corrupted file. Offset zero always
/// starts over — that *is* the resume-from-scratch path.
pub(crate) fn plan_upload_chunk(
    offset: u64,
    existing_size: Option<u64>,
) -> Result<(), UnihelmError> {
    if offset == 0 {
        return Ok(());
    }
    match existing_size {
        None => Err(UnihelmError::new(
            ErrorCode::Conflict,
            "nothing has been uploaded to this path yet — restart from offset 0",
        )),
        Some(size) if size == offset => Ok(()),
        Some(size) => Err(UnihelmError::new(
            ErrorCode::Conflict,
            format!(
                "upload offset {offset} does not match the {size} bytes already on disk — resume from {size} or restart from 0"
            ),
        )),
    }
}

/// The size of the regular file described by an `fs.stat` reply.
pub(crate) fn regular_file_size(stat: &Value) -> Result<u64, UnihelmError> {
    let entry = stat.get("entry").filter(|v| v.is_object()).unwrap_or(stat);
    match entry.get("kind").and_then(Value::as_str) {
        Some("file") => {}
        Some(_) => {
            return Err(UnihelmError::new(
                ErrorCode::InvalidInput,
                "the upload target exists and is not a regular file",
            ));
        }
        None => {
            return Err(UnihelmError::new(
                ErrorCode::AgentProtocol,
                "fs.stat reply has no kind",
            ));
        }
    }
    entry
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| UnihelmError::new(ErrorCode::AgentProtocol, "fs.stat reply has no size"))
}

/// The editor's save path (spec §11.7: Monaco edit with save-revision).
pub async fn write(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<WriteRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    checked_content_len(&body.content_b64).map_err(ApiError::new)?;

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "file.write",
        body.path.as_str(),
        json!({ "append": body.append }),
    )
    .await?;

    ops::invoke(
        &state,
        &current.auth,
        "fs.write",
        json!({
            "path": body.path.as_str(),
            "append": body.append,
            "content_b64": body.content_b64,
            "create_parents": body.create_parents,
            "subscription_id": body.subscription_id,
        }),
    )
    .await
}

/// One chunk of a resumable upload. See the module docs for the protocol.
pub async fn upload(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<UploadChunk>,
) -> ApiResult<Json<Value>> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    let chunk_len = checked_content_len(&body.content_b64).map_err(ApiError::new)?;

    if body.offset == 0 {
        // One audit row per uploaded file, not one per chunk — the trail
        // should read "alice uploaded backup.tar.gz", not drown in 4 MiB
        // increments.
        audit(
            &state,
            &current,
            &headers,
            &peer,
            "file.upload",
            body.path.as_str(),
            json!({ "create_parents": body.create_parents }),
        )
        .await?;
    } else {
        let existing = match ops::invoke_now(
            &state,
            &current.auth,
            "fs.stat",
            json!({ "path": body.path.as_str(), "subscription_id": body.subscription_id }),
        )
        .await
        {
            Ok(data) => Some(regular_file_size(&data).map_err(ApiError::new)?),
            // The partial file vanishing is a legitimate state (trash purge,
            // another window) — the client hears "restart", not "500".
            Err(e) if e.inner.code == ErrorCode::NotFound => None,
            Err(e) => return Err(e),
        };
        plan_upload_chunk(body.offset, existing).map_err(ApiError::new)?;
    }

    let append = body.offset > 0;
    ops::invoke_now(
        &state,
        &current.auth,
        "fs.write",
        json!({
            "path": body.path.as_str(),
            "append": append,
            "content_b64": body.content_b64,
            // Parents can only be missing before the first chunk creates the file.
            "create_parents": body.create_parents && !append,
            "subscription_id": body.subscription_id,
        }),
    )
    .await?;

    Ok(Json(json!({
        "path": body.path.as_str(),
        "size": body.offset + chunk_len,
        "done": body.done,
    })))
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

pub async fn mkdir(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<PathRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "file.mkdir",
        body.path.as_str(),
        json!({}),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "fs.mkdir",
        json!({ "path": body.path.as_str(), "subscription_id": body.subscription_id }),
    )
    .await
}

pub async fn rename(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<FromToRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "file.rename",
        body.from.as_str(),
        json!({ "to": body.to.as_str() }),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "fs.rename",
        json!({
            "from": body.from.as_str(),
            "to": body.to.as_str(),
            "subscription_id": body.subscription_id,
        }),
    )
    .await
}

pub async fn copy(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<FromToRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "file.copy",
        body.from.as_str(),
        json!({ "to": body.to.as_str() }),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "fs.copy",
        json!({
            "from": body.from.as_str(),
            "to": body.to.as_str(),
            "subscription_id": body.subscription_id,
        }),
    )
    .await
}

/// Move to the recycle bin. The op decides where the trash lives; permanent
/// removal only ever happens through `trash/purge`.
pub async fn delete(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<PathRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "file.delete",
        body.path.as_str(),
        json!({}),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "fs.delete",
        json!({ "path": body.path.as_str(), "subscription_id": body.subscription_id }),
    )
    .await
}

pub async fn chmod(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<ChmodRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;

    // The "safe subset" of spec §11.7: permission bits and the sticky bit.
    // setuid/setgid have no legitimate use inside a tenant home, and the agent
    // refuses them too — rejecting here just gives the error a field name.
    if body.mode & !0o1777 != 0 {
        return Err(ApiError::new(
            UnihelmError::new(
                ErrorCode::InvalidInput,
                "mode may only contain permission bits and the sticky bit (max 1777)",
            )
            .with_field("mode"),
        ));
    }

    audit(
        &state,
        &current,
        &headers,
        &peer,
        "file.chmod",
        body.path.as_str(),
        json!({ "mode": format!("{:o}", body.mode), "recursive": body.recursive }),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "fs.chmod",
        json!({
            "path": body.path.as_str(),
            "mode": body.mode,
            "recursive": body.recursive,
            "subscription_id": body.subscription_id,
        }),
    )
    .await
}

pub async fn search(
    State(state): State<SharedState>,
    current: CurrentUser,
    Json(body): Json<SearchRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    let query = body.query.trim();
    if query.is_empty() || query.len() > 256 {
        return Err(ApiError::new(
            UnihelmError::new(
                ErrorCode::InvalidInput,
                "search query must be between 1 and 256 characters",
            )
            .with_field("query"),
        ));
    }
    let limit = body
        .limit
        .unwrap_or(DEFAULT_SEARCH_LIMIT)
        .clamp(1, MAX_SEARCH_LIMIT);
    ops::invoke(
        &state,
        &current.auth,
        "fs.search",
        json!({
            "root": body.root.as_str(),
            "query": query,
            "limit": limit,
            "subscription_id": body.subscription_id,
        }),
    )
    .await
}

/// One name directly under the compression root.
///
/// The proto contract is "one level, no separators": anything with a `/` (or
/// the dot-navigation names) could address outside the chosen root, which is
/// exactly the crafted-archive-entry class of attack spec §11.7's AC tests.
pub(crate) fn validate_archive_entry(name: &str) -> Result<(), UnihelmError> {
    let bad = name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.chars().any(char::is_control);
    if bad {
        return Err(UnihelmError::new(
            ErrorCode::InvalidPath,
            format!(
                "`{}` is not a plain name inside the folder",
                name.escape_debug()
            ),
        )
        .with_field("entries"));
    }
    Ok(())
}

pub async fn compress(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<CompressRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    if body.entries.is_empty() {
        return Err(ApiError::new(
            UnihelmError::new(ErrorCode::InvalidInput, "nothing selected to compress")
                .with_field("entries"),
        ));
    }
    for entry in &body.entries {
        validate_archive_entry(entry).map_err(ApiError::new)?;
    }
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "file.compress",
        body.archive.as_str(),
        json!({ "root": body.root.as_str(), "entries": body.entries.len(), "format": body.format }),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "fs.compress",
        json!({
            "root": body.root.as_str(),
            "entries": body.entries,
            "archive": body.archive.as_str(),
            "format": body.format,
            "subscription_id": body.subscription_id,
        }),
    )
    .await
}

pub async fn extract(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<ExtractRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "file.extract",
        body.archive.as_str(),
        json!({ "dest": body.dest.as_str() }),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "fs.extract",
        json!({
            "archive": body.archive.as_str(),
            "dest": body.dest.as_str(),
            "subscription_id": body.subscription_id,
        }),
    )
    .await
}

pub async fn trash_restore(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<PathRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "file.trash.restore",
        body.path.as_str(),
        json!({}),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "fs.trash.restore",
        json!({ "path": body.path.as_str(), "subscription_id": body.subscription_id }),
    )
    .await
}

/// Permanently remove trashed entries. This is the only permanent deletion in
/// the file manager, which is why it gets its own verb and its own audit row.
pub async fn trash_purge(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    current: CurrentUser,
    Json(body): Json<PurgeRequest>,
) -> ApiResult<Response> {
    current
        .auth
        .require(Permission::FileManage)
        .map_err(ApiError::from)?;
    if body.older_than_days > MAX_PURGE_DAYS {
        return Err(ApiError::new(
            UnihelmError::new(ErrorCode::InvalidInput, "older_than_days is out of range")
                .with_field("older_than_days"),
        ));
    }
    audit(
        &state,
        &current,
        &headers,
        &peer,
        "file.trash.purge",
        "trash",
        json!({ "older_than_days": body.older_than_days }),
    )
    .await?;
    ops::invoke(
        &state,
        &current.auth,
        "fs.trash.purge",
        json!({
            "older_than_days": body.older_than_days,
            "subscription_id": body.subscription_id,
        }),
    )
    .await
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

async fn audit(
    state: &SharedState,
    current: &CurrentUser,
    headers: &HeaderMap,
    peer: &SocketAddr,
    action: &str,
    target: &str,
    detail: Value,
) -> ApiResult<()> {
    state
        .db
        .record_audit(NewAuditEntry {
            actor_user_id: Some(current.user.id),
            actor_username: current.user.username.as_str().to_string(),
            impersonator_id: current.session.impersonator_id,
            ip: Some(client_ip(Some(peer), headers)),
            action: action.to_string(),
            target: Some(target.to_string()),
            detail,
            request_id: Some(current.auth.request_id.clone()),
            subscription_id: current.auth.tenant_scope.subscription_id(),
        })
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use futures::StreamExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;
    use unihelm_core::{Email, Role, TenantScope, Username};
    use unihelm_db::Db;
    use unihelm_db::users::NewUser;

    // -- the streamed download loop -------------------------------------

    fn chunk(bytes: &[u8], eof: bool) -> ReadChunk {
        ReadChunk {
            bytes: bytes.to_vec(),
            eof,
        }
    }

    /// A scripted fetch: pops the next chunk, records the offset asked for.
    fn scripted_fetch(
        script: Vec<Result<ReadChunk, UnihelmError>>,
        offsets: Arc<std::sync::Mutex<Vec<u64>>>,
    ) -> impl Fn(
        u64,
    )
        -> std::pin::Pin<Box<dyn Future<Output = Result<ReadChunk, UnihelmError>> + Send>>
    + Send
    + 'static {
        let script = Arc::new(std::sync::Mutex::new(script));
        move |offset| {
            let script = script.clone();
            let offsets = offsets.clone();
            Box::pin(async move {
                offsets.lock().unwrap().push(offset);
                let mut s = script.lock().unwrap();
                if s.is_empty() {
                    panic!("fetch called after the script ran out (offset {offset})");
                }
                s.remove(0)
            })
        }
    }

    #[tokio::test]
    async fn the_download_loop_stitches_chunks_in_order_and_stops_at_eof() {
        let offsets = Arc::new(std::sync::Mutex::new(Vec::new()));
        let fetch = scripted_fetch(
            vec![Ok(chunk(b" world", false)), Ok(chunk(b"!", true))],
            offsets.clone(),
        );
        let out: Vec<_> = chunk_stream(chunk(b"hello", false), fetch).collect().await;

        let bytes: Vec<u8> = out
            .into_iter()
            .flat_map(|r| r.expect("no error in this script").to_vec())
            .collect();
        assert_eq!(bytes, b"hello world!");
        // Each fetch asked for exactly where the previous chunk ended — the
        // loop never re-reads and never skips.
        assert_eq!(*offsets.lock().unwrap(), vec![5, 11]);
    }

    #[tokio::test]
    async fn the_download_loop_holds_one_chunk_at_a_time() {
        // The constant-memory claim of spec §11.7: the next fs.read must not
        // happen until the previous chunk has been consumed by the client.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let fetch = move |offset: u64| {
            let calls = calls2.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(chunk(&[0u8; 8], offset >= 16))
            }) as std::pin::Pin<Box<dyn Future<Output = _> + Send>>
        };

        let stream = chunk_stream(chunk(b"12345678", false), fetch);
        let mut stream = Box::pin(stream);

        // The first chunk was fetched by the handler, not the stream.
        assert_eq!(stream.next().await.unwrap().unwrap().len(), 8);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing prefetched");

        assert_eq!(stream.next().await.unwrap().unwrap().len(), 8);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one consumed, one fetched");
    }

    #[tokio::test]
    async fn an_empty_file_downloads_as_an_empty_body() {
        let offsets = Arc::new(std::sync::Mutex::new(Vec::new()));
        let fetch = scripted_fetch(vec![], offsets.clone());
        let out: Vec<_> = chunk_stream(chunk(b"", true), fetch).collect().await;
        assert!(out.is_empty());
        assert!(offsets.lock().unwrap().is_empty(), "no fetch was needed");
    }

    #[tokio::test]
    async fn a_peer_that_sends_empty_chunks_before_eof_cannot_spin_the_loop() {
        // Without this guard a confused agent answering `{eof:false, ""}`
        // forever would pin a worker and the connection with it.
        let offsets = Arc::new(std::sync::Mutex::new(Vec::new()));
        let fetch = scripted_fetch(vec![Ok(chunk(b"", false))], offsets.clone());
        let out: Vec<_> = chunk_stream(chunk(b"data", false), fetch).collect().await;

        assert_eq!(out.len(), 2, "the data chunk, then the error");
        assert!(out[0].is_ok());
        assert_eq!(out[1].as_ref().unwrap_err().code, ErrorCode::AgentProtocol);
    }

    #[tokio::test]
    async fn a_mid_stream_error_ends_the_stream_instead_of_truncating_silently() {
        let offsets = Arc::new(std::sync::Mutex::new(Vec::new()));
        let fetch = scripted_fetch(
            vec![Err(UnihelmError::new(ErrorCode::NotFound, "vanished"))],
            offsets.clone(),
        );
        let out: Vec<_> = chunk_stream(chunk(b"part", false), fetch).collect().await;
        assert!(out[0].is_ok());
        assert_eq!(out[1].as_ref().unwrap_err().code, ErrorCode::NotFound);
    }

    // -- parsing the agent's replies ------------------------------------

    #[test]
    fn a_read_chunk_decodes_and_carries_eof() {
        let data = json!({ "size": 5, "eof": true, "binary": false, "content_b64": "aGVsbG8=" });
        let c = parse_read_chunk(&data).unwrap();
        assert_eq!(c.bytes, b"hello");
        assert!(c.eof);
    }

    #[test]
    fn a_malformed_read_reply_is_a_protocol_error_not_a_panic() {
        for bad in [
            json!({}),
            json!({ "content_b64": "aGVsbG8=" }), // no eof
            json!({ "eof": false }),              // no content
            json!({ "eof": false, "content_b64": "@@@" }), // not base64
            json!({ "eof": "yes", "content_b64": "" }), // eof not a bool
        ] {
            let err = parse_read_chunk(&bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::AgentProtocol, "{bad}");
        }
    }

    #[test]
    fn only_regular_files_are_downloadable() {
        assert!(ensure_downloadable(&json!({ "kind": "file", "size": 3 })).is_ok());
        // Tolerates the wrapped shape too.
        assert!(ensure_downloadable(&json!({ "entry": { "kind": "file" } })).is_ok());

        let dir = ensure_downloadable(&json!({ "kind": "dir" })).unwrap_err();
        assert_eq!(dir.code, ErrorCode::InvalidInput);

        let odd = ensure_downloadable(&json!({ "kind": "other" })).unwrap_err();
        assert_eq!(odd.code, ErrorCode::InvalidInput);

        let shapeless = ensure_downloadable(&json!({})).unwrap_err();
        assert_eq!(shapeless.code, ErrorCode::AgentProtocol);
    }

    #[test]
    fn an_escaping_symlink_is_never_streamed() {
        // The UI shows these as broken; the download path must agree with it
        // (spec §11.7 AC on symlink traversal).
        let err = ensure_downloadable(&json!({ "kind": "symlink", "escapes": true })).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidPath);
        // A link that stays inside the home is fine — the agent re-checks.
        assert!(ensure_downloadable(&json!({ "kind": "symlink", "escapes": false })).is_ok());
    }

    #[test]
    fn hostile_file_names_cannot_splice_the_disposition_header() {
        let h = content_disposition("evil\"; url=x.txt");
        // The quoted fallback contains no quote characters at all, so nothing
        // can close it early and start a new parameter.
        assert!(!h.replace("filename=\"", "").contains("evil\";"));
        assert_eq!(h.matches('"').count(), 2, "exactly the two quoting quotes");
        assert!(h.is_ascii());

        let fa = content_disposition("گزارش.pdf");
        assert!(fa.is_ascii(), "header values must be ASCII");
        assert!(
            fa.contains("filename*=UTF-8''%DA%AF"),
            "the real name survives encoded: {fa}"
        );

        // A name with no printable ASCII at all still labels the attachment.
        assert!(content_disposition("   ").contains("filename=\"download\""));
    }

    // -- upload chunk planning ------------------------------------------

    #[test]
    fn the_first_chunk_always_starts_over() {
        assert!(plan_upload_chunk(0, None).is_ok());
        // Restarting over a stale partial file is the resume path, not a
        // conflict.
        assert!(plan_upload_chunk(0, Some(999)).is_ok());
    }

    #[test]
    fn a_chunk_that_matches_the_bytes_on_disk_appends() {
        assert!(plan_upload_chunk(4096, Some(4096)).is_ok());
    }

    #[test]
    fn a_replayed_or_reordered_chunk_is_a_conflict_not_a_corruption() {
        // The retried chunk (client resent after a timeout whose write in
        // fact landed) would double its bytes if we appended blindly.
        let replay = plan_upload_chunk(4096, Some(8192)).unwrap_err();
        assert_eq!(replay.code, ErrorCode::Conflict);

        // A chunk from the future means an earlier one was lost.
        let gap = plan_upload_chunk(8192, Some(4096)).unwrap_err();
        assert_eq!(gap.code, ErrorCode::Conflict);
    }

    #[test]
    fn continuing_an_upload_whose_file_vanished_says_restart() {
        let err = plan_upload_chunk(4096, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.detail.contains("restart"), "{}", err.detail);
    }

    #[test]
    fn upload_continuation_only_appends_to_regular_files() {
        assert_eq!(
            regular_file_size(&json!({ "kind": "file", "size": 7 })).unwrap(),
            7
        );
        let dir = regular_file_size(&json!({ "kind": "dir", "size": 0 })).unwrap_err();
        assert_eq!(dir.code, ErrorCode::InvalidInput);
        let no_size = regular_file_size(&json!({ "kind": "file" })).unwrap_err();
        assert_eq!(no_size.code, ErrorCode::AgentProtocol);
    }

    // -- content validation ----------------------------------------------

    #[test]
    fn chunk_content_is_capped_before_it_is_decoded() {
        // Over the cap by arithmetic alone: the base64 text for >4 MiB.
        let oversized = "A".repeat((MAX_CONTENT_BYTES / 3 + 2) * 4 + 8);
        let err = checked_content_len(&oversized).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(err.field.as_deref(), Some("content_b64"));
    }

    #[test]
    fn garbage_base64_is_invalid_input_not_a_500() {
        let err = checked_content_len("not@@base64!").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(checked_content_len("aGVsbG8=").unwrap(), 5);
        assert_eq!(checked_content_len("").unwrap(), 0);
    }

    #[test]
    fn archive_entries_must_be_plain_names() {
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "..\\x",
            "a\0b",
            "x\ny",
            &"n".repeat(256),
        ] {
            let err = validate_archive_entry(bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidPath, "{bad:?}");
        }
        for good in ["notes.txt", "public_html", "..hidden", "با فاصله.txt"] {
            assert!(validate_archive_entry(good).is_ok(), "{good:?}");
        }
    }

    // -- the helper's error kinds land on the right HTTP statuses --------

    /// The taxonomy contract for `FsErrorKind` (fsops proto): the ops layer
    /// converts each kind to one of these codes before the error crosses the
    /// IPC boundary, and this route module passes the code through untouched
    /// (`ops::invoke*` → `ApiError::new`). Pinned here because the *status a
    /// client sees* is this layer's promise, whoever produced the error.
    fn expected_code_for_fs_kind(kind: &str) -> ErrorCode {
        match kind {
            "not_found" => ErrorCode::NotFound,
            "permission_denied" => ErrorCode::PermissionDenied,
            "already_exists" => ErrorCode::AlreadyExists,
            // Escapes are a validation failure of the path, not a hint that
            // the target exists.
            "escape" => ErrorCode::InvalidPath,
            "not_a_directory" | "is_a_directory" | "invalid" => ErrorCode::InvalidInput,
            "too_large" => ErrorCode::InvalidInput,
            "unsafe_archive" => ErrorCode::InvalidInput,
            "io" => ErrorCode::Internal,
            other => panic!("unmapped FsErrorKind `{other}`"),
        }
    }

    #[test]
    fn every_fs_error_kind_maps_to_a_sane_http_status() {
        for (kind, status) in [
            ("not_found", 404),
            ("permission_denied", 403),
            ("already_exists", 409),
            ("escape", 400),
            ("not_a_directory", 400),
            ("is_a_directory", 400),
            ("invalid", 400),
            ("too_large", 400),
            ("unsafe_archive", 400),
            ("io", 500),
        ] {
            assert_eq!(
                expected_code_for_fs_kind(kind).http_status(),
                status,
                "{kind}"
            );
        }
    }

    // -- route-level behavior --------------------------------------------

    struct Panel {
        app: axum::Router,
        cookie: String,
        csrf: String,
    }

    /// The files router with a real database-backed session and no agent —
    /// anything that *passes* validation fails 503 at the socket, which makes
    /// "was it rejected before the op call" directly observable.
    async fn panel() -> Panel {
        let db = Db::open_memory().await.unwrap();
        let user = db
            .users(&TenantScope::Global)
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
        let issued = db
            .create_session(user.id, None, None, unihelm_db::sessions::DEFAULT_TTL, None)
            .await
            .unwrap();

        let mut config = unihelm_core::UnihelmConfig::default();
        // Point the agent socket somewhere that certainly does not exist.
        config.agent.socket = std::path::PathBuf::from("/nonexistent/unihelm-agent.sock");

        let state: SharedState = Arc::new(crate::state::AppState::new(db, config));
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let app = router()
            // `into_make_service_with_connect_info` provides this in
            // production; tests inject it as the extension it becomes.
            .layer(axum::Extension(ConnectInfo(peer)))
            .with_state(state);

        Panel {
            app,
            cookie: format!("{}={}", crate::auth::SESSION_COOKIE, issued.token),
            csrf: issued.csrf,
        }
    }

    fn get(p: &Panel, uri: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("cookie", &p.cookie)
            .body(Body::empty())
            .unwrap()
    }

    fn post_json(p: &Panel, uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method(if uri.ends_with("/write") {
                "PUT"
            } else {
                "POST"
            })
            .uri(uri)
            .header("cookie", &p.cookie)
            .header(crate::auth::CSRF_HEADER, &p.csrf)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn body_text(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn every_files_route_requires_a_session() {
        let p = panel().await;
        for (method, uri) in [
            ("GET", "/api/files/list?path=a"),
            ("GET", "/api/files/download?path=a.txt"),
            ("PUT", "/api/files/write"),
            ("POST", "/api/files/upload"),
            ("POST", "/api/files/delete"),
            ("POST", "/api/files/trash/purge"),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let resp = p.app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {uri}");
        }
    }

    #[tokio::test]
    async fn mutations_without_a_csrf_token_are_refused() {
        let p = panel().await;
        let req = Request::builder()
            .method("POST")
            .uri("/api/files/mkdir")
            .header("cookie", &p.cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"path":"newdir"}"#))
            .unwrap();
        let resp = p.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(body_text(resp).await.contains("FER-1107"));
    }

    #[tokio::test]
    async fn traversal_paths_die_in_deserialization_not_in_the_agent() {
        let p = panel().await;
        // No agent is running: a request that *passed* validation would come
        // back 503. Anything 4xx here therefore never became an op call.
        for uri in [
            "/api/files/list?path=../../etc/passwd",
            "/api/files/list?path=a/../../b",
            "/api/files/read?path=/etc/passwd",
            "/api/files/download?path=..",
            "/api/files/stat?path=a%00b",
            "/api/files/usage?path=sites/./x",
        ] {
            let resp = p.app.clone().oneshot(get(&p, uri)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    #[tokio::test]
    async fn traversal_paths_in_json_bodies_are_rejected_too() {
        let p = panel().await;
        for (uri, body) in [
            ("/api/files/mkdir", r#"{"path":"../../root/.ssh"}"#),
            (
                "/api/files/write",
                r#"{"path":"/etc/passwd","content_b64":""}"#,
            ),
            (
                "/api/files/rename",
                r#"{"from":"ok.txt","to":"../../escape"}"#,
            ),
            ("/api/files/delete", r#"{"path":".."}"#),
            (
                "/api/files/extract",
                r#"{"archive":"a.zip","dest":"../.."}"#,
            ),
            ("/api/files/trash/restore", r#"{"path":"a\\b"}"#),
        ] {
            let resp = p
                .app
                .clone()
                .oneshot(post_json(&p, uri, body))
                .await
                .unwrap();
            assert!(
                resp.status() == StatusCode::BAD_REQUEST
                    || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
                "{uri} gave {}",
                resp.status()
            );
        }
    }

    #[tokio::test]
    async fn a_valid_request_reaches_for_the_agent_and_gets_503_without_one() {
        // The counterpart of the rejection tests: this is what "passed
        // validation" looks like in this harness.
        let p = panel().await;
        let resp = p
            .app
            .clone()
            .oneshot(get(&p, "/api/files/list?path=public_html&hidden=true"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(body_text(resp).await.contains("FER-1500"));
    }

    #[tokio::test]
    async fn an_empty_path_lists_the_home_directory_itself() {
        let p = panel().await;
        for uri in ["/api/files/list", "/api/files/list?path="] {
            let resp = p.app.clone().oneshot(get(&p, uri)).await.unwrap();
            // Reached the (absent) agent — so the empty path deserialized.
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        }
        // But reading "the home itself" is meaningless and stays a 400.
        let resp = p
            .app
            .clone()
            .oneshot(get(&p, "/api/files/read?path="))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_request_body_cap_is_twelve_megabytes() {
        let p = panel().await;

        // Over the cap: refused with 413 while the body is still arriving.
        let huge = format!(
            r#"{{"path":"big.bin","content_b64":"{}"}}"#,
            "A".repeat(13 * 1024 * 1024)
        );
        let resp = p
            .app
            .clone()
            .oneshot(post_json(&p, "/api/files/upload", &huge))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Under the files cap but over the panel-wide 2 MiB default: accepted
        // by this router (fails 503 at the absent agent), which proves the
        // per-route limit is the one in effect here.
        let medium = format!(
            r#"{{"path":"ok.bin","content_b64":"{}"}}"#,
            "A".repeat(3 * 1024 * 1024)
        );
        let resp = p
            .app
            .clone()
            .oneshot(post_json(&p, "/api/files/upload", &medium))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn an_upload_chunk_over_the_content_cap_is_refused_with_a_field() {
        let p = panel().await;
        // Fits the 12 MiB body, but decodes to more than MAX_CONTENT_BYTES.
        let b64 = BASE64.encode(vec![0u8; MAX_CONTENT_BYTES + 1]);
        let body = format!(r#"{{"path":"big.bin","content_b64":"{b64}"}}"#);
        let resp = p
            .app
            .clone()
            .oneshot(post_json(&p, "/api/files/upload", &body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let text = body_text(resp).await;
        assert!(text.contains("FER-1200"), "{text}");
        assert!(text.contains("content_b64"), "{text}");
    }

    #[tokio::test]
    async fn hostile_compress_entries_are_refused_before_any_op_call() {
        let p = panel().await;
        let body = r#"{"root":"public_html","entries":["../../etc/passwd"],"archive":"out.zip","format":"zip"}"#;
        let resp = p
            .app
            .clone()
            .oneshot(post_json(&p, "/api/files/compress", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("FER-1204"));
    }

    #[tokio::test]
    async fn setuid_bits_never_leave_the_web_layer() {
        let p = panel().await;
        let resp = p
            .app
            .clone()
            .oneshot(post_json(
                &p,
                "/api/files/chmod",
                r#"{"path":"bin/tool","mode":2541}"#, // 04755
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("FER-1200"));

        // 0755 (=493) is an ordinary mode and passes through to the agent.
        let resp = p
            .app
            .clone()
            .oneshot(post_json(
                &p,
                "/api/files/chmod",
                r#"{"path":"bin/tool","mode":493}"#,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn an_empty_search_query_is_refused() {
        let p = panel().await;
        let resp = p
            .app
            .clone()
            .oneshot(post_json(&p, "/api/files/search", r#"{"query":"   "}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_text(resp).await.contains("query"));
    }
}
