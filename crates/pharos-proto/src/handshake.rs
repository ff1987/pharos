use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::codec::{read_frame, write_frame};
use crate::error::ProtoError;
use crate::frame::{
    code, Auth, AuthFail, AuthOk, ErrorBody, FrameType, Hello, ROLE_CLIENT, ROLE_SERVER,
    VERSION_MAJOR,
};
use crate::token_accepted;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn next_session_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let tick = crate::frame::monotonic_ms();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    tick ^ n.rotate_left(17) ^ u64::from(std::process::id()).rotate_left(32)
}

/// Client half of the control handshake: Hello, then Auth.
pub async fn client_authenticate<R, W>(
    reader: &mut R,
    writer: &mut W,
    token: &str,
    name: &str,
) -> Result<AuthOk, ProtoError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let fut = async {
        let hello = Hello::new(ROLE_CLIENT, name);
        write_frame(writer, &hello.to_frame()?).await?;
        let frame = read_frame(reader).await?;
        if frame.ty != FrameType::Hello as u8 {
            if frame.ty == FrameType::Error as u8 {
                let body = ErrorBody::decode(&frame.payload)?;
                return Err(ProtoError::Message(body.message));
            }
            return Err(ProtoError::BadType(frame.ty));
        }
        let server_hello = Hello::decode(&frame.payload)?;
        if server_hello.major != VERSION_MAJOR {
            return Err(ProtoError::Message(format!(
                "server protocol major {} is not supported",
                server_hello.major
            )));
        }
        write_frame(
            writer,
            &Auth {
                token: token.to_string(),
            }
            .to_frame()?,
        )
        .await?;
        let frame = read_frame(reader).await?;
        match FrameType::from_u8(frame.ty) {
            Some(FrameType::AuthOk) => AuthOk::decode(&frame.payload),
            Some(FrameType::AuthFail) => {
                let fail = AuthFail::decode(&frame.payload)?;
                Err(ProtoError::AuthFailed(fail.reason))
            }
            Some(_) => Err(ProtoError::Message(
                "unexpected frame during authentication".into(),
            )),
            None => Err(ProtoError::BadType(frame.ty)),
        }
    };
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await {
        Ok(result) => result,
        Err(_) => Err(ProtoError::Timeout),
    }
}

pub struct ServerHandshake {
    pub session_id: u64,
    pub peer_name: String,
}

/// Server half of the control handshake. On a bad token this writes `AuthFail`
/// and returns an error after flushing, so the peer can observe the rejection.
pub async fn server_authenticate<R, W>(
    reader: &mut R,
    writer: &mut W,
    expected_tokens: &[String],
    check_token: bool,
    heartbeat_interval_ms: u32,
) -> Result<ServerHandshake, ProtoError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let fut = async {
        let frame = read_frame(reader).await?;
        if frame.ty != FrameType::Hello as u8 {
            let err = ErrorBody {
                code: code::BAD_FRAME,
                message: "expected Hello".into(),
            };
            write_frame(writer, &err.to_frame()?).await?;
            return Err(ProtoError::BadType(frame.ty));
        }
        let hello = Hello::decode(&frame.payload)?;
        if hello.major != VERSION_MAJOR || hello.role != ROLE_CLIENT {
            let err = ErrorBody {
                code: code::BAD_VERSION,
                message: format!("unsupported protocol major {}", hello.major),
            };
            write_frame(writer, &err.to_frame()?).await?;
            return Err(ProtoError::Message(err.message));
        }
        let response = Hello::new(ROLE_SERVER, "pharos-server");
        write_frame(writer, &response.to_frame()?).await?;
        let frame = read_frame(reader).await?;
        if frame.ty != FrameType::Auth as u8 {
            let err = ErrorBody {
                code: code::BAD_FRAME,
                message: "expected Auth".into(),
            };
            write_frame(writer, &err.to_frame()?).await?;
            return Err(ProtoError::BadType(frame.ty));
        }
        let auth = Auth::decode(&frame.payload)?;
        if check_token && !token_accepted(expected_tokens, &auth.token) {
            let fail = AuthFail {
                code: code::AUTH_FAILED,
                reason: "authentication failed".into(),
            };
            write_frame(writer, &fail.to_frame()?).await?;
            writer.flush().await?;
            return Err(ProtoError::AuthFailed(fail.reason));
        }
        let session_id = next_session_id();
        let ok = AuthOk {
            session_id,
            heartbeat_interval_ms,
        };
        write_frame(writer, &ok.to_frame()?).await?;
        Ok(ServerHandshake {
            session_id,
            peer_name: hello.name,
        })
    };
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await {
        Ok(result) => result,
        Err(_) => Err(ProtoError::Timeout),
    }
}
