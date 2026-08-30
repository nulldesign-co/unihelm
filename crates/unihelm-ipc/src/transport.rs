//! Transport abstraction (spec §5.4).
//!
//! v1 ships exactly one implementation — a Unix socket — but everything above
//! this module talks to [`FrameWriter`] / [`FrameReader`], so adding an mTLS TCP
//! transport for remote agents later is a new `StreamTransport<TlsStream<..>>`
//! and nothing else.

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::codec::{MAX_FRAME_BYTES, read_frame, write_frame};
use crate::{IpcError, Result};

#[async_trait]
pub trait FrameWriter: Send {
    async fn send_frame(&mut self, payload: &[u8]) -> Result<()>;
}

#[async_trait]
pub trait FrameReader: Send {
    /// `Ok(None)` on a clean close.
    async fn recv_frame(&mut self) -> Result<Option<Vec<u8>>>;
}

/// A connection that can be torn into independent read and write halves, so one
/// task can stream task logs out while another keeps reading requests in.
pub trait FrameTransport: Send {
    fn split(self) -> (Box<dyn FrameWriter>, Box<dyn FrameReader>);
}

/// Framing over any byte stream.
pub struct StreamTransport<S> {
    stream: S,
    max_frame: usize,
}

impl<S> StreamTransport<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            max_frame: MAX_FRAME_BYTES,
        }
    }

    pub fn with_max_frame(mut self, max: usize) -> Self {
        self.max_frame = max;
        self
    }
}

impl<S> FrameTransport for StreamTransport<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    fn split(self) -> (Box<dyn FrameWriter>, Box<dyn FrameReader>) {
        let max = self.max_frame;
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(HalfWriter { inner: w }),
            Box::new(HalfReader { inner: r, max }),
        )
    }
}

struct HalfWriter<W> {
    inner: W,
}

#[async_trait]
impl<W: AsyncWrite + Send + Unpin> FrameWriter for HalfWriter<W> {
    async fn send_frame(&mut self, payload: &[u8]) -> Result<()> {
        write_frame(&mut self.inner, payload).await
    }
}

struct HalfReader<R> {
    inner: R,
    max: usize,
}

#[async_trait]
impl<R: AsyncRead + Send + Unpin> FrameReader for HalfReader<R> {
    async fn recv_frame(&mut self) -> Result<Option<Vec<u8>>> {
        read_frame(&mut self.inner, self.max).await
    }
}

/// Serialise and send a typed frame.
pub async fn send_json<T: serde::Serialize + ?Sized>(
    w: &mut dyn FrameWriter,
    value: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|e| IpcError::Malformed(e.to_string()))?;
    w.send_frame(&bytes).await
}

/// Receive and parse a typed frame. `Ok(None)` on a clean close.
pub async fn recv_json<T: serde::de::DeserializeOwned>(
    r: &mut dyn FrameReader,
) -> Result<Option<T>> {
    let Some(bytes) = r.recv_frame().await? else {
        return Ok(None);
    };
    let value = serde_json::from_slice(&bytes).map_err(|e| {
        // The payload may contain secrets, so report the parse position, not the body.
        IpcError::Malformed(format!("{e} (frame of {} bytes)", bytes.len()))
    })?;
    Ok(Some(value))
}
