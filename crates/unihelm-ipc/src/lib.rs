//! `unihelm-ipc` — the typed channel between the unprivileged web process and the
//! root agent (spec §5.3).
//!
//! Wire format: **length-prefixed JSON**. A 4-byte big-endian length, then that
//! many bytes of UTF-8 JSON. Simple enough to read with `nc` while debugging
//! (`unihelm dev ipc-tap`), self-delimiting, and trivially bounded.
//!
//! Every envelope carries `v` from day one and unknown fields are ignored, so an
//! agent and a web process at different versions degrade instead of exploding
//! (spec §5.3).
//!
//! The transport is behind [`FrameTransport`] on purpose: the only thing v1 ships
//! is a Unix socket, but a future `mTLS TcpTransport` becomes a new impl rather
//! than a rewrite (spec §5.4).

pub mod client;
pub mod codec;
pub mod frame;
pub mod peercred;
pub mod server;
pub mod transport;

pub use client::IpcClient;
pub use frame::{
    ClientFrame, ControlFrame, ControlKind, EventFrame, EventKind, PROTOCOL_VERSION, RequestFrame,
    ResponseBody, ResponseFrame, ServerFrame, TerminalTarget,
};
pub use server::{HandlerFactory, IpcServer, RequestHandler, SharedHandler};
pub use transport::{FrameTransport, StreamTransport};

/// Errors that arise from the channel itself, distinct from an operation that
/// ran and failed.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("malformed frame: {0}")]
    Malformed(String),

    #[error("frame of {size} bytes exceeds the {max} byte limit")]
    FrameTooLarge { size: usize, max: usize },

    #[error("peer closed the connection")]
    Closed,

    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),

    #[error("timed out waiting for the agent")]
    Timeout,

    #[error("peer credentials rejected: {0}")]
    PeerRejected(String),
}

impl From<IpcError> for unihelm_core::UnihelmError {
    fn from(e: IpcError) -> Self {
        use unihelm_core::ErrorCode::*;
        let code = match &e {
            IpcError::Io(_) | IpcError::Closed => AgentUnavailable,
            IpcError::Malformed(_)
            | IpcError::FrameTooLarge { .. }
            | IpcError::UnsupportedVersion(_) => AgentProtocol,
            IpcError::Timeout => AgentTimeout,
            IpcError::PeerRejected(_) => PeerCredentialRejected,
        };
        unihelm_core::UnihelmError::new(code, e.to_string())
    }
}

pub type Result<T, E = IpcError> = std::result::Result<T, E>;
