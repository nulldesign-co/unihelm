//! Length-prefixed framing: `u32` big-endian length, then that many bytes of JSON.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{IpcError, Result};

/// Hard ceiling on a single frame.
///
/// The agent is root and the socket is local, but a bounded reader is what keeps
/// a buggy (or hostile) peer from turning a length prefix into an allocation of
/// its choosing.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

pub async fn write_frame<W>(w: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if payload.len() > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge {
            size: payload.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let len = u32::try_from(payload.len()).expect("checked against MAX_FRAME_BYTES above");
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Read one frame. `Ok(None)` means the peer closed cleanly between frames.
pub async fn read_frame<R>(r: &mut R, max: usize) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        // Do not read the body: the whole point is not to allocate it.
        return Err(IpcError::FrameTooLarge { size: len, max });
    }
    if len == 0 {
        return Err(IpcError::Malformed("zero-length frame".into()));
    }

    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            IpcError::Malformed("frame truncated mid-body".into())
        } else {
            IpcError::Io(e)
        }
    })?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, b"{\"a\":1}").await.unwrap();
        write_frame(&mut buf, b"{\"b\":2}").await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(
            read_frame(&mut cursor, MAX_FRAME_BYTES)
                .await
                .unwrap()
                .unwrap(),
            b"{\"a\":1}"
        );
        assert_eq!(
            read_frame(&mut cursor, MAX_FRAME_BYTES)
                .await
                .unwrap()
                .unwrap(),
            b"{\"b\":2}"
        );
        assert!(
            read_frame(&mut cursor, MAX_FRAME_BYTES)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn oversized_length_prefix_is_refused_without_allocating() {
        // 4 GiB announced, nothing following it.
        let bytes = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let mut cursor = std::io::Cursor::new(bytes);
        let err = read_frame(&mut cursor, MAX_FRAME_BYTES).await.unwrap_err();
        assert!(matches!(err, IpcError::FrameTooLarge { .. }));
    }

    #[tokio::test]
    async fn truncated_body_is_an_error_not_a_silent_eof() {
        let mut bytes = 10u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"abc");
        let mut cursor = std::io::Cursor::new(bytes);
        let err = read_frame(&mut cursor, MAX_FRAME_BYTES).await.unwrap_err();
        assert!(matches!(err, IpcError::Malformed(_)));
    }

    #[tokio::test]
    async fn zero_length_frame_is_rejected() {
        let mut cursor = std::io::Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(matches!(
            read_frame(&mut cursor, MAX_FRAME_BYTES).await.unwrap_err(),
            IpcError::Malformed(_)
        ));
    }
}
