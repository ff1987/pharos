use bytes::Bytes;

use crate::buf::{Put, Take};
use crate::error::ProtoError;

/// Frame version written on every frame. Version 1 is the only dialect in 0.1.
pub const PROTO_VERSION: u8 = 1;

/// Hello major. Peers reject any other major.
pub const VERSION_MAJOR: u16 = 1;

/// Hello minor. Additive, optional fields would bump this without breaking major 1.
pub const VERSION_MINOR: u16 = 0;

/// Largest accepted payload. Data is chunked well below this.
pub const MAX_PAYLOAD: u32 = 1024 * 1024;

/// Preferred chunk size for TCP payload frames on the TLS multiplex.
pub const DATA_CHUNK: usize = 16 * 1024;

/// Application-level error codes carried by [`ErrorBody`].
pub mod code {
    pub const BAD_VERSION: u16 = 1;
    pub const AUTH_FAILED: u16 = 2;
    pub const ACL_DENIED: u16 = 3;
    pub const BIND_FAILED: u16 = 4;
    pub const BAD_FRAME: u16 = 5;
    pub const NOT_AVAILABLE: u16 = 6;
    pub const LIMIT: u16 = 7;
    pub const BAD_REQUEST: u16 = 8;
}

/// Close reasons carried by [`Close`].
pub mod close_reason {
    pub const NORMAL: u16 = 0;
    pub const DIAL_FAILED: u16 = 1;
    pub const TIMEOUT: u16 = 2;
    pub const RESET: u16 = 3;
}

pub const ROLE_CLIENT: u8 = 1;
pub const ROLE_SERVER: u8 = 2;

pub const TUNNEL_TCP: u8 = 1;
pub const TUNNEL_HTTP: u8 = 2;
pub const TUNNEL_UDP: u8 = 3;

/// Mandatory frame types. Types with the high bit set (`0x80`–`0xFE`) are optional
/// and must be ignored by receivers that do not understand them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 1,
    Auth = 2,
    AuthOk = 3,
    AuthFail = 4,
    RegisterTunnel = 5,
    RegisterOk = 6,
    RegisterFail = 7,
    Heartbeat = 8,
    HeartbeatAck = 9,
    OpenStream = 10,
    StreamReady = 11,
    Data = 12,
    Close = 13,
    Error = 14,
    SessionReady = 15,
    ReadyAck = 16,
    /// Client asks the server to drop a tunnel, or the server tells the client it dropped one.
    Unregister = 17,
    UnregisterOk = 18,
}

impl FrameType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Hello,
            2 => Self::Auth,
            3 => Self::AuthOk,
            4 => Self::AuthFail,
            5 => Self::RegisterTunnel,
            6 => Self::RegisterOk,
            7 => Self::RegisterFail,
            8 => Self::Heartbeat,
            9 => Self::HeartbeatAck,
            10 => Self::OpenStream,
            11 => Self::StreamReady,
            12 => Self::Data,
            13 => Self::Close,
            14 => Self::Error,
            15 => Self::SessionReady,
            16 => Self::ReadyAck,
            17 => Self::Unregister,
            18 => Self::UnregisterOk,
            _ => return None,
        })
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Types in `0x80`..=`0xFE` are ignorable extensions. `0xFF` is reserved and fatal.
pub fn is_optional_type(ty: u8) -> bool {
    (0x80..0xFF).contains(&ty)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub ty: u8,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(ty: FrameType, payload: Bytes) -> Self {
        Self {
            version: PROTO_VERSION,
            ty: ty.as_u8(),
            payload,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub major: u16,
    pub minor: u16,
    pub role: u8,
    pub name: String,
}

impl Hello {
    pub fn new(role: u8, name: impl Into<String>) -> Self {
        Self {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            role,
            name: name.into(),
        }
    }

    pub fn to_frame(&self) -> Result<Frame, ProtoError> {
        let mut put = Put::new();
        put.u16(self.major);
        put.u16(self.minor);
        put.u8(self.role);
        put.str(&self.name)?;
        Ok(Frame::new(FrameType::Hello, put.finish()))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let hello = Self {
            major: take.u16()?,
            minor: take.u16()?,
            role: take.u8()?,
            name: take.str()?,
        };
        take.expect_exhausted()?;
        Ok(hello)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    pub token: String,
}

impl Auth {
    pub fn to_frame(&self) -> Result<Frame, ProtoError> {
        let mut put = Put::new();
        put.str(&self.token)?;
        Ok(Frame::new(FrameType::Auth, put.finish()))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let auth = Self { token: take.str()? };
        take.expect_exhausted()?;
        Ok(auth)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOk {
    pub session_id: u64,
    pub heartbeat_interval_ms: u32,
}

impl AuthOk {
    pub fn to_frame(&self) -> Result<Frame, ProtoError> {
        let mut put = Put::new();
        put.u64(self.session_id);
        put.u32(self.heartbeat_interval_ms);
        Ok(Frame::new(FrameType::AuthOk, put.finish()))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            session_id: take.u64()?,
            heartbeat_interval_ms: take.u32()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFail {
    pub code: u16,
    pub reason: String,
}

impl AuthFail {
    pub fn to_frame(&self) -> Result<Frame, ProtoError> {
        let mut put = Put::new();
        put.u16(self.code);
        put.str(&self.reason)?;
        Ok(Frame::new(FrameType::AuthFail, put.finish()))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            code: take.u16()?,
            reason: take.str()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterTunnel {
    pub name: String,
    pub kind: u8,
    pub local: String,
    pub remote_port: u16,
    pub hostname: String,
}

impl RegisterTunnel {
    pub fn to_frame(&self) -> Result<Frame, ProtoError> {
        let mut put = Put::new();
        put.str(&self.name)?;
        put.u8(self.kind);
        put.str(&self.local)?;
        put.u16(self.remote_port);
        put.str(&self.hostname)?;
        Ok(Frame::new(FrameType::RegisterTunnel, put.finish()))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            name: take.str()?,
            kind: take.u8()?,
            local: take.str()?,
            remote_port: take.u16()?,
            hostname: take.str()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterOk {
    pub name: String,
    pub tunnel_id: u32,
    pub public_endpoint: String,
}

impl RegisterOk {
    pub fn to_frame(&self) -> Result<Frame, ProtoError> {
        let mut put = Put::new();
        put.str(&self.name)?;
        put.u32(self.tunnel_id);
        put.str(&self.public_endpoint)?;
        Ok(Frame::new(FrameType::RegisterOk, put.finish()))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            name: take.str()?,
            tunnel_id: take.u32()?,
            public_endpoint: take.str()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterFail {
    pub name: String,
    pub code: u16,
    pub reason: String,
}

impl RegisterFail {
    pub fn to_frame(&self) -> Result<Frame, ProtoError> {
        let mut put = Put::new();
        put.str(&self.name)?;
        put.u16(self.code);
        put.str(&self.reason)?;
        Ok(Frame::new(FrameType::RegisterFail, put.finish()))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            name: take.str()?,
            code: take.u16()?,
            reason: take.str()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unregister {
    pub name: String,
    pub tunnel_id: u32,
}

impl Unregister {
    pub fn to_frame(&self) -> Result<Frame, ProtoError> {
        let mut put = Put::new();
        put.str(&self.name)?;
        put.u32(self.tunnel_id);
        Ok(Frame::new(FrameType::Unregister, put.finish()))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            name: take.str()?,
            tunnel_id: take.u32()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnregisterOk {
    pub name: String,
    pub tunnel_id: u32,
}

impl UnregisterOk {
    pub fn to_frame(&self) -> Result<Frame, ProtoError> {
        let mut put = Put::new();
        put.str(&self.name)?;
        put.u32(self.tunnel_id);
        Ok(Frame::new(FrameType::UnregisterOk, put.finish()))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            name: take.str()?,
            tunnel_id: take.u32()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heartbeat {
    pub monotonic_ms: u64,
}

impl Heartbeat {
    pub fn to_frame(&self) -> Frame {
        let mut put = Put::new();
        put.u64(self.monotonic_ms);
        Frame::new(FrameType::Heartbeat, put.finish())
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            monotonic_ms: take.u64()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatAck {
    pub echo_monotonic_ms: u64,
}

impl HeartbeatAck {
    pub fn to_frame(&self) -> Frame {
        let mut put = Put::new();
        put.u64(self.echo_monotonic_ms);
        Frame::new(FrameType::HeartbeatAck, put.finish())
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            echo_monotonic_ms: take.u64()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenStream {
    pub stream_id: u32,
    pub tunnel_id: u32,
}

impl OpenStream {
    pub fn to_frame(&self) -> Frame {
        let mut put = Put::new();
        put.u32(self.stream_id);
        put.u32(self.tunnel_id);
        Frame::new(FrameType::OpenStream, put.finish())
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            stream_id: take.u32()?,
            tunnel_id: take.u32()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamReady {
    pub stream_id: u32,
}

impl StreamReady {
    pub fn to_frame(&self) -> Frame {
        let mut put = Put::new();
        put.u32(self.stream_id);
        Frame::new(FrameType::StreamReady, put.finish())
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            stream_id: take.u32()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Close {
    pub stream_id: u32,
    pub reason: u16,
}

impl Close {
    pub fn to_frame(&self) -> Frame {
        let mut put = Put::new();
        put.u32(self.stream_id);
        put.u16(self.reason);
        Frame::new(FrameType::Close, put.finish())
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            stream_id: take.u32()?,
            reason: take.u16()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorBody {
    pub code: u16,
    pub message: String,
}

impl ErrorBody {
    pub fn to_frame(&self) -> Result<Frame, ProtoError> {
        let mut put = Put::new();
        put.u16(self.code);
        put.str(&self.message)?;
        Ok(Frame::new(FrameType::Error, put.finish()))
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let mut take = Take::new(payload);
        let body = Self {
            code: take.u16()?,
            message: take.str()?,
        };
        take.expect_exhausted()?;
        Ok(body)
    }
}

pub fn data_frame(stream_id: u32, bytes: Bytes) -> Frame {
    let mut put = Put::new();
    put.u32(stream_id);
    let mut payload = put.finish().to_vec();
    payload.extend_from_slice(&bytes);
    Frame::new(FrameType::Data, Bytes::from(payload))
}

pub fn decode_data(payload: &[u8]) -> Result<(u32, Bytes), ProtoError> {
    let mut take = Take::new(payload);
    let stream_id = take.u32()?;
    let rest = Bytes::copy_from_slice(take.rest());
    Ok((stream_id, rest))
}

pub fn empty_frame(ty: FrameType) -> Frame {
    Frame::new(ty, Bytes::new())
}

pub fn monotonic_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_payload(frame: &Frame) -> Frame {
        let bytes = crate::codec::encode_frame(frame).unwrap();
        let (decoded, n) = crate::codec::decode_frame(&bytes).unwrap().unwrap();
        assert_eq!(n, bytes.len());
        decoded
    }

    #[test]
    fn auth_and_register_roundtrip() {
        let auth = Auth {
            token: "correct-horse".into(),
        };
        let frame = auth.to_frame().unwrap();
        let decoded = roundtrip_payload(&frame);
        assert_eq!(Auth::decode(&decoded.payload).unwrap(), auth);

        let reg = RegisterTunnel {
            name: "ssh".into(),
            kind: TUNNEL_TCP,
            local: "127.0.0.1:22".into(),
            remote_port: 2222,
            hostname: String::new(),
        };
        let frame = reg.to_frame().unwrap();
        let decoded = roundtrip_payload(&frame);
        assert_eq!(RegisterTunnel::decode(&decoded.payload).unwrap(), reg);

        let http = RegisterTunnel {
            name: "web".into(),
            kind: TUNNEL_HTTP,
            local: "127.0.0.1:3000".into(),
            remote_port: 0,
            hostname: "demo.local".into(),
        };
        let frame = http.to_frame().unwrap();
        let decoded = roundtrip_payload(&frame);
        assert_eq!(RegisterTunnel::decode(&decoded.payload).unwrap(), http);

        let udp = RegisterTunnel {
            name: "dns".into(),
            kind: TUNNEL_UDP,
            local: "127.0.0.1:53".into(),
            remote_port: 5353,
            hostname: String::new(),
        };
        let frame = udp.to_frame().unwrap();
        let decoded = roundtrip_payload(&frame);
        assert_eq!(RegisterTunnel::decode(&decoded.payload).unwrap(), udp);
    }

    #[test]
    fn control_messages_roundtrip() {
        let samples = vec![
            Hello::new(ROLE_CLIENT, "pharos-client").to_frame().unwrap(),
            AuthOk {
                session_id: 99,
                heartbeat_interval_ms: 15_000,
            }
            .to_frame()
            .unwrap(),
            AuthFail {
                code: code::AUTH_FAILED,
                reason: "authentication failed".into(),
            }
            .to_frame()
            .unwrap(),
            RegisterOk {
                name: "ssh".into(),
                tunnel_id: 7,
                public_endpoint: "127.0.0.1:2222".into(),
            }
            .to_frame()
            .unwrap(),
            RegisterFail {
                name: "ssh".into(),
                code: code::ACL_DENIED,
                reason: "port 22 is not in the ACL".into(),
            }
            .to_frame()
            .unwrap(),
            Heartbeat { monotonic_ms: 1234 }.to_frame(),
            HeartbeatAck {
                echo_monotonic_ms: 1234,
            }
            .to_frame(),
            OpenStream {
                stream_id: 3,
                tunnel_id: 1,
            }
            .to_frame(),
            StreamReady { stream_id: 3 }.to_frame(),
            Close {
                stream_id: 3,
                reason: close_reason::NORMAL,
            }
            .to_frame(),
            ErrorBody {
                code: code::BAD_VERSION,
                message: "major 9".into(),
            }
            .to_frame()
            .unwrap(),
            empty_frame(FrameType::SessionReady),
            empty_frame(FrameType::ReadyAck),
            Unregister {
                name: "ssh".into(),
                tunnel_id: 7,
            }
            .to_frame()
            .unwrap(),
            UnregisterOk {
                name: "ssh".into(),
                tunnel_id: 7,
            }
            .to_frame()
            .unwrap(),
            data_frame(4, Bytes::from_static(b"ping")),
        ];
        for frame in samples {
            let decoded = roundtrip_payload(&frame);
            assert_eq!(decoded.version, PROTO_VERSION);
            assert_eq!(decoded.ty, frame.ty);
            assert_eq!(decoded.payload, frame.payload);
        }
        let (id, bytes) = decode_data(&data_frame(4, Bytes::from_static(b"ping")).payload).unwrap();
        assert_eq!(id, 4);
        assert_eq!(bytes.as_ref(), b"ping");
    }

    #[test]
    fn optional_types_are_the_high_bit_range() {
        assert!(!is_optional_type(FrameType::Hello as u8));
        assert!(is_optional_type(0x80));
        assert!(is_optional_type(0xFE));
        assert!(!is_optional_type(0xFF));
        assert!(FrameType::from_u8(0x20).is_none());
    }
}
