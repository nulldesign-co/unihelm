//! The tenant file manager's backend (spec §11.7).
//!
//! Layout, from the outside in:
//!
//! * [`ops`] — the registered `fs.*` operations. They resolve a subscription to
//!   its Linux account and home, and speak [`proto`] to a helper.
//! * the runner (this module) — one [`FsRunner::call`] per request. In
//!   production it re-execs the agent binary as `--fs-helper`, which drops to
//!   the tenant's uid **before** reading a byte (spec §5.2 rule 3).
//! * [`helper`] — the child side: resolves paths with [`safepath`], does the
//!   filesystem work as the tenant, answers on stdout.
//! * [`archive`] — compress/extract with zip-bomb and traversal guards.
//!
//! The privilege drop is the design's backstop, not its only wall: every path
//! is still component-walked and symlink-refused, so an escape has to beat the
//! checks *and* the OS permission model at once.

pub mod archive;
pub mod helper;
pub mod ops;
pub mod proto;
pub mod safepath;

use std::io::{self, BufRead};
use std::path::Path;
use std::time::Duration;

use ferrum_core::{ErrorCode, FerrumError};
use proto::{FsCall, FsData, FsErrorKind, FsReply, FsRequest, MAX_HEADER};

/// The per-tenant recycle bin, at the top of the home (spec §11.7).
///
/// `fs.delete` renames into it, `fs.trash.*` manage it, and the helper's
/// directory listing hides it from the normal browse view.
pub const TRASH_DIR: &str = ".trash";

/// The most reply payload the agent will buffer from a helper.
///
/// The helper's own editor backstop is 16 MB ([`helper::MAX_EDITABLE`]); double
/// that is generous headroom, and a hard stop against a confused child that
/// declares a huge payload.
const MAX_REPLY_PAYLOAD: u64 = 32 * 1024 * 1024;

/// How one tenant's filesystem requests get executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsRunner {
    /// Re-exec the agent binary and drop to this uid/gid before any I/O.
    /// The production path; requires the agent itself to be root, because
    /// `setuid` to another account is a root-only call.
    Tenant { uid: u32, gid: u32 },
    /// Run [`helper::serve_one`] in-process, with **no privilege drop**.
    ///
    /// This exists because tests and `--dev` instances are not root: they
    /// *cannot* drop privilege (setuid would fail), and the homes they touch
    /// are throwaway directories owned by the very user already running the
    /// process — so there is no privilege to shed. A root agent never selects
    /// this variant ([`ops`] picks the runner from `geteuid`).
    Local,
}

impl FsRunner {
    /// Execute one request against `home`, sending `payload` (file content for
    /// writes) and returning the reply's data and payload (content for reads).
    ///
    /// A helper-reported failure comes back as the mapped [`FerrumError`], so
    /// callers never see [`FsReply::Err`] directly.
    pub async fn call(
        &self,
        home: &Path,
        request: FsRequest,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> ferrum_core::Result<(FsData, Vec<u8>)> {
        let call = FsCall {
            home: home.to_path_buf(),
            request,
            payload_len: payload.len() as u64,
        };

        let (reply, reply_payload) = match self {
            FsRunner::Local => {
                // File I/O is blocking; keep it off the agent's async workers.
                let handle = tokio::task::spawn_blocking(move || run_local(&call, &payload));
                match tokio::time::timeout(timeout, handle).await {
                    Err(_) => {
                        return Err(FerrumError::new(
                            ErrorCode::AgentTimeout,
                            "the file operation did not finish in time",
                        ));
                    }
                    Ok(joined) => joined
                        .map_err(|e| FerrumError::internal(format!("fs task panicked: {e}")))?
                        .map_err(|e| {
                            FerrumError::internal(format!("local fs helper failed: {e}"))
                        })?,
                }
            }
            FsRunner::Tenant { uid, gid } => {
                run_helper_process(*uid, *gid, &call, &payload, timeout).await?
            }
        };

        match reply {
            FsReply::Ok { data, .. } => Ok((data, reply_payload)),
            FsReply::Err { kind, message } => Err(reply_error(kind, message)),
        }
    }
}

/// Map a helper-reported failure onto the panel's error taxonomy (spec §10.5).
fn reply_error(kind: FsErrorKind, message: String) -> FerrumError {
    let code = match kind {
        FsErrorKind::NotFound => ErrorCode::NotFound,
        FsErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        FsErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
        // An escape *attempt* is an invalid path, and saying so (rather than
        // pretending "not found") is fine: the caller sent the path, so its
        // shape is nothing they do not already know.
        FsErrorKind::Escape => ErrorCode::InvalidPath,
        FsErrorKind::NotADirectory
        | FsErrorKind::IsADirectory
        | FsErrorKind::TooLarge
        | FsErrorKind::UnsafeArchive
        | FsErrorKind::Invalid => ErrorCode::InvalidInput,
        FsErrorKind::Io => ErrorCode::Internal,
    };
    FerrumError::new(code, message)
}

/// Run one request in-process — the [`FsRunner::Local`] path, and the seam the
/// tests drive directly.
pub fn run_local(call: &FsCall, payload: &[u8]) -> io::Result<(FsReply, Vec<u8>)> {
    let mut input = payload;
    let mut out = Vec::new();
    helper::serve_one(call, &mut input, &mut out)?;
    read_reply(&mut io::BufReader::new(out.as_slice()))
}

/// Read the helper's reply: one bounded JSON line, then its declared payload.
fn read_reply(reader: &mut impl BufRead) -> io::Result<(FsReply, Vec<u8>)> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the reply ended before its newline",
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > MAX_HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the reply header is too long",
            ));
        }
    }
    let reply: FsReply =
        serde_json::from_slice(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let payload_len = match &reply {
        FsReply::Ok { payload_len, .. } => *payload_len,
        FsReply::Err { .. } => 0,
    };
    if payload_len > MAX_REPLY_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the reply payload exceeds the agent's limit",
        ));
    }
    let mut payload = vec![0u8; payload_len as usize];
    reader.read_exact(&mut payload)?;
    Ok((reply, payload))
}

/// Spawn `ferrum-agentd --fs-helper` for one request and speak the pipe
/// protocol with it.
///
/// The argv is fixed and numeric — uid, gid, and the home path the caller
/// already validated — and the child receives an empty environment. The home
/// also rides in the [`FsCall`] header; carrying it on the argv as well makes
/// `ps` show *whose* helper this is, which matters the day one hangs.
async fn run_helper_process(
    uid: u32,
    gid: u32,
    call: &FsCall,
    payload: &[u8],
    timeout: Duration,
) -> ferrum_core::Result<(FsReply, Vec<u8>)> {
    use std::ffi::OsString;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

    let args: Vec<OsString> = vec![
        "--fs-helper".into(),
        "--uid".into(),
        uid.to_string().into(),
        "--gid".into(),
        gid.to_string().into(),
        "--home".into(),
        call.home.as_os_str().to_os_string(),
    ];
    let mut cmd = ferrum_distro::exec::reexec_current(&args).map_err(FerrumError::from)?;
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // If the agent (or this future) dies mid-request, the helper must not
        // linger holding a tenant's uid.
        .kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .map_err(|e| FerrumError::internal(format!("could not spawn the fs helper: {e}")))?;

    let header = serde_json::to_vec(call)
        .map_err(|e| FerrumError::internal(format!("unserialisable fs call: {e}")))?;

    let exchange = async {
        // Write the whole request, then close stdin so the child sees EOF.
        // The helper never replies before consuming its request, so writing
        // first cannot deadlock against a full stdout pipe.
        let mut stdin = child.stdin.take().expect("stdin was piped");
        stdin.write_all(&header).await?;
        stdin.write_all(b"\n").await?;
        stdin.write_all(payload).await?;
        stdin.shutdown().await?;
        drop(stdin);

        let stdout = child.stdout.take().expect("stdout was piped");
        let mut reader = tokio::io::BufReader::new(stdout);

        // Bounded line read: even our own child does not get to make the agent
        // buffer without limit.
        let mut line = Vec::new();
        let mut limited = (&mut reader).take(MAX_HEADER as u64 + 1);
        limited.read_until(b'\n', &mut line).await?;
        if line.last() != Some(&b'\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the helper's reply header never ended",
            ));
        }
        line.pop();
        let reply: FsReply = serde_json::from_slice(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let payload_len = match &reply {
            FsReply::Ok { payload_len, .. } => *payload_len,
            FsReply::Err { .. } => 0,
        };
        if payload_len > MAX_REPLY_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the helper's reply payload exceeds the agent's limit",
            ));
        }
        let mut reply_payload = vec![0u8; payload_len as usize];
        reader.read_exact(&mut reply_payload).await?;

        // Drain stderr (the helper only writes there when the drop itself
        // failed) and reap the child.
        let mut stderr_text = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut stderr_text).await;
        }
        let status = child.wait().await?;
        Ok::<_, io::Error>((reply, reply_payload, status, stderr_text))
    };

    match tokio::time::timeout(timeout, exchange).await {
        Err(_) => {
            // kill_on_drop reaps it; report the timeout in IPC terms.
            Err(FerrumError::new(
                ErrorCode::AgentTimeout,
                "the file helper did not finish in time",
            ))
        }
        Ok(Err(e)) => Err(FerrumError::internal(format!(
            "the file helper broke off mid-reply: {e}"
        ))),
        Ok(Ok((reply, reply_payload, status, stderr_text))) => {
            if !status.success() {
                // A non-zero exit outranks whatever half-reply we read: it
                // means the helper itself failed — most importantly, that the
                // privilege drop refused to proceed.
                return Err(FerrumError::internal(format!(
                    "the file helper exited with {status}: {}",
                    stderr_text.trim()
                )));
            }
            Ok((reply, reply_payload))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_home() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path()).unwrap();
        (dir, path)
    }

    async fn local(
        home: &Path,
        request: FsRequest,
        payload: &[u8],
    ) -> ferrum_core::Result<(FsData, Vec<u8>)> {
        FsRunner::Local
            .call(home, request, payload.to_vec(), Duration::from_secs(10))
            .await
    }

    #[tokio::test]
    async fn a_file_written_through_the_runner_reads_back() {
        let (_g, home) = temp_home();
        let (data, _) = local(
            &home,
            FsRequest::Write {
                path: PathBuf::from("hello.txt"),
                len: 5,
                create_parents: false,
                append: false,
            },
            b"hello",
        )
        .await
        .unwrap();
        assert!(matches!(data, FsData::Done));

        let (data, payload) = local(
            &home,
            FsRequest::Read {
                path: PathBuf::from("hello.txt"),
                max_bytes: 1024,
                offset: 0,
            },
            b"",
        )
        .await
        .unwrap();
        assert!(matches!(
            data,
            FsData::Content {
                size: 5,
                truncated: false,
                binary: false
            }
        ));
        assert_eq!(payload, b"hello");
    }

    #[tokio::test]
    async fn a_chunked_append_write_assembles_the_file_in_order() {
        // This is the upload path: chunk one creates, later chunks append.
        // 2 GB works because no chunk is ever held whole beyond its own call
        // (spec §11.7 AC) — here three small chunks prove the mechanism.
        let (_g, home) = temp_home();
        for (i, chunk) in [&b"part-one|"[..], b"part-two|", b"part-three"]
            .iter()
            .enumerate()
        {
            local(
                &home,
                FsRequest::Write {
                    path: PathBuf::from("upload.bin"),
                    len: chunk.len() as u64,
                    create_parents: false,
                    append: i > 0,
                },
                chunk,
            )
            .await
            .unwrap();
        }

        assert_eq!(
            std::fs::read(home.join("upload.bin")).unwrap(),
            b"part-one|part-two|part-three"
        );
    }

    #[tokio::test]
    async fn a_read_with_an_offset_returns_the_right_window() {
        let (_g, home) = temp_home();
        std::fs::write(home.join("data.txt"), b"0123456789").unwrap();

        let (data, payload) = local(
            &home,
            FsRequest::Read {
                path: PathBuf::from("data.txt"),
                max_bytes: 4,
                offset: 3,
            },
            b"",
        )
        .await
        .unwrap();
        assert_eq!(payload, b"3456");
        assert!(matches!(
            data,
            FsData::Content {
                size: 10,
                truncated: true,
                ..
            }
        ));

        // Past the end: an empty, final read — how the downloader knows to stop.
        let (data, payload) = local(
            &home,
            FsRequest::Read {
                path: PathBuf::from("data.txt"),
                max_bytes: 4,
                offset: 10,
            },
            b"",
        )
        .await
        .unwrap();
        assert!(payload.is_empty());
        assert!(matches!(data, FsData::Content { truncated: false, .. }));
    }

    #[tokio::test]
    async fn a_traversal_attempt_maps_to_an_invalid_path_error() {
        let (_g, home) = temp_home();
        let err = local(
            &home,
            FsRequest::Read {
                path: PathBuf::from("../../etc/passwd"),
                max_bytes: 1024,
                offset: 0,
            },
            b"",
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidPath);
    }

    #[tokio::test]
    async fn the_full_browse_cycle_works_end_to_end_in_a_temp_home() {
        let (_g, home) = temp_home();

        // mkdir, write into it, list, rename, delete.
        local(&home, FsRequest::Mkdir { path: "site".into() }, b"")
            .await
            .unwrap();
        local(
            &home,
            FsRequest::Write {
                path: "site/index.html".into(),
                len: 6,
                create_parents: false,
                append: false,
            },
            b"<html>",
        )
        .await
        .unwrap();

        let (data, _) = local(
            &home,
            FsRequest::List {
                path: "site".into(),
                show_hidden: false,
            },
            b"",
        )
        .await
        .unwrap();
        let FsData::Entries(entries) = data else {
            panic!("expected entries")
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "index.html");

        local(
            &home,
            FsRequest::Rename {
                from: "site/index.html".into(),
                to: "site/home.html".into(),
            },
            b"",
        )
        .await
        .unwrap();
        local(&home, FsRequest::Remove { path: "site".into() }, b"")
            .await
            .unwrap();
        assert!(!home.join("site").exists());
    }

    #[test]
    fn the_reply_parser_stops_at_a_runaway_header() {
        let mut endless = io::BufReader::new(io::repeat(b'x'));
        let err = read_reply(&mut endless).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_reply_that_declares_an_absurd_payload_is_refused() {
        let line = format!(
            "{}\n",
            serde_json::json!({
                "ok": { "data": { "content": { "size": 1, "truncated": false, "binary": false } },
                         "payload_len": u64::MAX }
            })
        );
        let err = read_reply(&mut io::BufReader::new(line.as_bytes())).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
