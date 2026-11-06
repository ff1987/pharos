use std::io;

use thiserror::Error;

/// Protocol, codec, and configuration errors.
#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("frame payload {0} exceeds the {1} byte limit")]
    TooLarge(u32, u32),
    #[error("truncated frame payload")]
    Truncated,
    #[error("invalid utf-8 in frame")]
    Utf8,
    #[error("unsupported frame version {0}")]
    Version(u8),
    #[error("unknown mandatory frame type {0}")]
    BadType(u8),
    #[error("protocol timeout")]
    Timeout,
    #[error("connection closed")]
    Closed,
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("certificate: {0}")]
    Cert(String),
    #[error("{0}")]
    Message(String),
}

impl From<rustls::Error> for ProtoError {
    fn from(value: rustls::Error) -> Self {
        ProtoError::Tls(value.to_string())
    }
}

impl From<rcgen::Error> for ProtoError {
    fn from(value: rcgen::Error) -> Self {
        ProtoError::Cert(value.to_string())
    }
}
