//! Pharos wire protocol.
//!
//! Control messages and, on the TLS fallback, multiplexed data share one
//! length-prefixed frame layout documented in `PROTOCOL.md`. QUIC carries the
//! same control frames on a dedicated stream and raw bytes on per-connection
//! streams. The dialect is not compatible with frp, rathole, or any mesh VPN.

#![forbid(unsafe_code)]

mod bistream;
mod buf;
mod codec;
mod config;
mod error;
mod frame;
mod handshake;
mod hostname;
mod mux;
mod proxy;
mod tlsutil;
mod udp;

pub use bistream::BiStream;
pub use codec::{decode_frame, encode_frame, read_frame, write_frame, write_loop, HEADER_LEN};
pub use config::{
    token_accepted, tokens_equal, AclConfig, AuthMode, ClientAuthConfig, ClientConfig, ConfigError,
    HeartbeatConfig, HttpBind, HttpsBind, LimitsConfig, LogConfig, LogFormat, ReconnectConfig,
    ServerAuthConfig, ServerConfig, ShutdownConfig, TransportMode, TunnelConfig, TunnelKind,
};
pub use hostname::{
    is_wildcard_hostname, normalize_http_hostname, resolve_hostname_key,
    single_label_wildcard_matches,
};
pub use error::ProtoError;
pub use frame::{
    close_reason, code, data_frame, decode_data, empty_frame, is_optional_type, monotonic_ms, Auth,
    AuthFail, AuthOk, Close, ErrorBody, Frame, FrameType, Heartbeat, HeartbeatAck, Hello,
    OpenStream, RegisterFail, RegisterOk, RegisterTunnel, StreamReady, Unregister, UnregisterOk,
    DATA_CHUNK, MAX_PAYLOAD, PROTO_VERSION, ROLE_CLIENT, ROLE_SERVER, TUNNEL_HTTP, TUNNEL_TCP, TUNNEL_UDP,
    VERSION_MAJOR, VERSION_MINOR,
};
pub use handshake::{client_authenticate, server_authenticate, ServerHandshake};
pub use mux::{Demux, MuxHandle, StreamEvent};
pub use proxy::{bridge_mux, bridge_raw, wait_ready, BytePacer, NoPace, Traffic};
pub use udp::{
    bridge_udp_assoc_mux, bridge_udp_assoc_raw, bridge_udp_mux, bridge_udp_raw, encode_datagram,
    udp_idle, DatagramBuf, MAX_UDP_DATAGRAM, UDP_ASSOC_IDLE_SECS,
};
pub use tlsutil::{
    certs_from_pem, client_config_insecure, client_config_with_ca, generate_dev_identity,
    https_terminator_config, identity_from_files, identity_from_pem, install_ring,
    issue_client_certificate, server_config, server_name, Identity, IssuedClient, ALPN,
};
