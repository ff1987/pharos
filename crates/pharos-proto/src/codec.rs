use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtoError;
use crate::frame::{Frame, MAX_PAYLOAD, PROTO_VERSION};

pub const HEADER_LEN: usize = 6;

/// Encode one frame: `version:u8 | type:u8 | length:u32be | payload`.
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, ProtoError> {
    let len = u32::try_from(frame.payload.len()).unwrap_or(u32::MAX);
    if len > MAX_PAYLOAD {
        return Err(ProtoError::TooLarge(len, MAX_PAYLOAD));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + frame.payload.len());
    out.push(frame.version);
    out.push(frame.ty);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&frame.payload);
    Ok(out)
}

/// Decode one frame from the front of `buf`.
///
/// Returns `Ok(None)` when `buf` does not yet contain a full frame.
pub fn decode_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, ProtoError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    let version = buf[0];
    let ty = buf[1];
    let len = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
    if len > MAX_PAYLOAD {
        return Err(ProtoError::TooLarge(len, MAX_PAYLOAD));
    }
    let total = HEADER_LEN + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    let payload = bytes::Bytes::copy_from_slice(&buf[HEADER_LEN..total]);
    Ok(Some((
        Frame {
            version,
            ty,
            payload,
        },
        total,
    )))
}

pub async fn read_frame<R>(reader: &mut R) -> Result<Frame, ProtoError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let version = header[0];
    let ty = header[1];
    let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]);
    if len > MAX_PAYLOAD {
        return Err(ProtoError::TooLarge(len, MAX_PAYLOAD));
    }
    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    if version != PROTO_VERSION {
        return Err(ProtoError::Version(version));
    }
    Ok(Frame {
        version,
        ty,
        payload: bytes::Bytes::from(payload),
    })
}

pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<(), ProtoError>
where
    W: AsyncWrite + Unpin,
{
    let bytes = encode_frame(frame)?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn write_loop<W>(mut writer: W, mut frames: tokio::sync::mpsc::Receiver<Frame>)
where
    W: AsyncWrite + Unpin,
{
    while let Some(frame) = frames.recv().await {
        if write_frame(&mut writer, &frame).await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Auth, FrameType, RegisterTunnel, TUNNEL_TCP};

    #[test]
    fn rejects_truncated_and_oversized_headers() {
        assert!(decode_frame(&[1, 2, 0, 0, 0, 5, 1, 2]).unwrap().is_none());
        let mut huge = vec![PROTO_VERSION, FrameType::Data as u8];
        huge.extend_from_slice(&(MAX_PAYLOAD + 1).to_be_bytes());
        match decode_frame(&huge) {
            Err(ProtoError::TooLarge(_, _)) => {}
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn concatenates_two_frames() {
        let a = Auth {
            token: "alpha".into(),
        }
        .to_frame()
        .unwrap();
        let b = RegisterTunnel {
            name: "ssh".into(),
            kind: TUNNEL_TCP,
            local: "127.0.0.1:22".into(),
            remote_port: 2222,
            hostname: String::new(),
        }
        .to_frame()
        .unwrap();
        let mut buf = encode_frame(&a).unwrap();
        buf.extend(encode_frame(&b).unwrap());
        let (first, n) = decode_frame(&buf).unwrap().unwrap();
        let (second, m) = decode_frame(&buf[n..]).unwrap().unwrap();
        assert_eq!(n + m, buf.len());
        assert_eq!(first.ty, FrameType::Auth as u8);
        assert_eq!(second.ty, FrameType::RegisterTunnel as u8);
        assert!(decode_frame(&buf[n + m..]).unwrap().is_none());
    }

    #[tokio::test]
    async fn async_read_write_roundtrip() {
        let frame = Auth {
            token: "s3cret".into(),
        }
        .to_frame()
        .unwrap();
        let encoded = encode_frame(&frame).unwrap();
        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = read_frame(&mut cursor).await.unwrap();
        assert_eq!(decoded, frame);
    }
}
