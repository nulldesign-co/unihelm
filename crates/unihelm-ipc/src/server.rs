//! The agent side of the socket.
//!
//! Responsibilities that belong here and nowhere else:
//! - create the socket with credentials nobody but the panel user can use,
//! - verify the peer with `SO_PEERCRED` on every accept,
//! - reject frames from a protocol version we do not speak,
//! - hand well-formed requests to the operation registry, one task per request so
//!   a slow install never blocks the connection's read loop (spec §10.1).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::frame::{
    ClientFrame, ControlFrame, EventFrame, PROTOCOL_VERSION, RequestFrame, ResponseBody,
    ResponseFrame, ServerFrame,
};
use unihelm_core::UnihelmError;

use crate::peercred::{PeerCred, PeerPolicy, peer_cred};
use crate::transport::{FrameTransport, StreamTransport, recv_json, send_json};
use crate::{IpcError, Result};

/// Buffered server→client frames per connection.
const OUTBOUND_CAPACITY: usize = 1024;

/// Handle used by an operation to push progress out to whoever is watching.
#[derive(Clone)]
pub struct EventSink {
    tx: mpsc::Sender<ServerFrame>,
}

impl EventSink {
    /// Push an event. Returns `false` if the peer is gone or too far behind —
    /// task execution must continue regardless, since the log is also persisted.
    pub async fn emit(&self, event: EventFrame) -> bool {
        self.tx.send(ServerFrame::Event(event)).await.is_ok()
    }

    /// Non-blocking variant for use inside a hot loop.
    pub fn try_emit(&self, event: EventFrame) -> bool {
        self.tx.try_send(ServerFrame::Event(event)).is_ok()
    }
}

/// Builds the handler for a newly accepted connection.
///
/// A factory rather than one shared handler, because per-connection state is
/// real: each client tracks which tasks it wants live events for, and that set
/// must die with the connection.
#[async_trait]
pub trait HandlerFactory: Send + Sync + 'static {
    async fn accept(&self, peer: PeerCred, events: EventSink) -> Arc<dyn RequestHandler>;
}

/// Hands every connection the same handler — for servers with no per-connection
/// state, and for tests.
pub struct SharedHandler<H>(pub Arc<H>);

#[async_trait]
impl<H: RequestHandler> HandlerFactory for SharedHandler<H> {
    async fn accept(&self, _peer: PeerCred, _events: EventSink) -> Arc<dyn RequestHandler> {
        self.0.clone()
    }
}

/// What the agent does with a well-formed frame. Implemented by `unihelm-agentd`
/// on top of the operation registry.
#[async_trait]
pub trait RequestHandler: Send + Sync + 'static {
    /// Execute (or enqueue) an operation. Must not panic; return an error body.
    async fn handle_request(
        &self,
        req: RequestFrame,
        peer: PeerCred,
        events: EventSink,
    ) -> ResponseBody;

    /// Handle a control frame. Returning `None` means "nothing to reply".
    async fn handle_control(&self, ctl: ControlFrame, peer: PeerCred, events: EventSink);
}

pub struct IpcServer {
    listener: UnixListener,
    path: PathBuf,
    policy: PeerPolicy,
}

impl IpcServer {
    /// Bind the socket and lock it down before anyone can reach it.
    ///
    /// Order matters: bind, tighten to 0600 (root only), hand ownership to the
    /// panel user, then widen to 0700 for that user. At no point is the socket
    /// reachable by a third account.
    pub fn bind(
        path: impl AsRef<Path>,
        owner: Option<(u32, u32)>,
        policy: PeerPolicy,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // A leftover socket from an unclean shutdown would make bind() fail.
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::warn!(path = %path.display(), "removed a stale agent socket"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }

        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

        if let Some((uid, gid)) = owner {
            chown(&path, uid, gid)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }

        tracing::info!(path = %path.display(), "agent socket listening");
        Ok(Self {
            listener,
            path,
            policy,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept loop. Runs until `shutdown` resolves.
    pub async fn serve<F: HandlerFactory>(
        self,
        factory: Arc<F>,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("ipc server shutting down");
                    break;
                }
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let cred = match peer_cred(&stream) {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::warn!(error = %e, "could not read peer credentials; dropping");
                                    continue;
                                }
                            };
                            if let Err(e) = self.policy.check(cred) {
                                tracing::warn!(uid = cred.uid, error = %e, "rejected ipc peer");
                                continue;
                            }
                            let factory = factory.clone();
                            tokio::spawn(async move {
                                if let Err(e) = serve_connection(stream, cred, factory).await {
                                    tracing::debug!(error = %e, "ipc connection ended");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "accept failed");
                        }
                    }
                }
            }
        }
        // Best-effort cleanup; systemd recreates the runtime dir anyway.
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn serve_connection<F: HandlerFactory>(
    stream: UnixStream,
    peer: PeerCred,
    factory: Arc<F>,
) -> Result<()> {
    let (mut writer, mut reader) = StreamTransport::new(stream).split();
    let (out_tx, mut out_rx) = mpsc::channel::<ServerFrame>(OUTBOUND_CAPACITY);

    let writer_task = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let Err(e) = send_json(writer.as_mut(), &frame).await else {
                continue;
            };

            // Only a broken socket ends the connection. Breaking on every error
            // wedged the panel: an over-sized reply is rejected by the codec
            // before a byte reaches the wire, so the socket was still perfectly
            // good — but this task exited, the peer never saw EOF because the
            // read half stayed open, and from then on every reply was dropped
            // silently. Each privileged call in the panel then timed out after
            // 30s, for every user, until somebody restarted the agent.
            if matches!(e, IpcError::Io(_) | IpcError::Closed) {
                tracing::debug!(error = %e, "ipc write failed; closing the connection");
                break;
            }

            tracing::warn!(error = %e, "could not send an ipc frame");

            // A request that produced an unsendable reply still needs an answer,
            // or the caller waits out its timeout for nothing.
            if let ServerFrame::Response(resp) = &frame {
                let replacement = ServerFrame::Response(ResponseFrame::err(
                    resp.id,
                    UnihelmError::internal(format!("the response could not be sent: {e}")),
                ));
                if let Err(e) = send_json(writer.as_mut(), &replacement).await {
                    tracing::debug!(error = %e, "could not send the replacement error either");
                    break;
                }
            }
        }
    });

    let sink = EventSink { tx: out_tx.clone() };
    let handler = factory.accept(peer, sink.clone()).await;

    loop {
        let frame: ClientFrame = match recv_json(reader.as_mut()).await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(IpcError::Malformed(detail)) => {
                // A frame we cannot parse has no id to reply to; log and keep the
                // connection, since the next frame may be perfectly fine.
                tracing::warn!(uid = peer.uid, detail, "dropping malformed ipc frame");
                continue;
            }
            Err(e) => return Err(e),
        };

        if frame.version() != PROTOCOL_VERSION {
            let err = unihelm_core::UnihelmError::new(
                unihelm_core::ErrorCode::AgentProtocol,
                format!(
                    "agent speaks protocol v{PROTOCOL_VERSION}, peer sent v{}",
                    frame.version()
                ),
            );
            let _ = out_tx
                .send(ServerFrame::Response(ResponseFrame::err(frame.id(), err)))
                .await;
            continue;
        }

        match frame {
            ClientFrame::Request(req) => {
                // One task per request: a 4-minute package install must not stop
                // us reading the next frame (the "fast lane" in spec §10.1).
                let handler = handler.clone();
                let out_tx = out_tx.clone();
                let sink = sink.clone();
                tokio::spawn(async move {
                    let id = req.id;
                    let op = req.op.clone();
                    let body = handler.handle_request(req, peer, sink).await;
                    if let ResponseBody::Err { error } = &body {
                        tracing::info!(op = %op, code = %error.code.code(), "operation failed");
                    }
                    let _ = out_tx
                        .send(ServerFrame::Response(ResponseFrame {
                            v: PROTOCOL_VERSION,
                            id,
                            body,
                        }))
                        .await;
                });
            }
            ClientFrame::Control(ctl) => {
                handler.handle_control(ctl, peer, sink.clone()).await;
            }
        }
    }

    drop(out_tx);
    drop(sink);
    let _ = writer_task.await;
    Ok(())
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| IpcError::Malformed("socket path contains a NUL byte".into()))?;
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call.
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}
