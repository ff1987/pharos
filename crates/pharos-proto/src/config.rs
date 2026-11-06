use std::collections::HashSet;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

/// How the client reaches the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportMode {
    /// Try QUIC, then TLS over TCP.
    #[default]
    Auto,
    Quic,
    Tls,
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Auto => "auto",
            Self::Quic => "quic",
            Self::Tls => "tls",
        })
    }
}

/// How a session is authenticated.
///
/// `token` is the default and keeps the original pre-shared key behavior.
/// `mtls` requires a client certificate and does not check the token.
/// `token+mtls` requires both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum AuthMode {
    #[default]
    #[serde(rename = "token")]
    Token,
    #[serde(rename = "mtls")]
    Mtls,
    #[serde(rename = "token+mtls")]
    TokenAndMtls,
}

impl AuthMode {
    pub fn requires_token(self) -> bool {
        matches!(self, Self::Token | Self::TokenAndMtls)
    }

    pub fn requires_client_cert(self) -> bool {
        matches!(self, Self::Mtls | Self::TokenAndMtls)
    }
}

impl std::fmt::Display for AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Token => "token",
            Self::Mtls => "mtls",
            Self::TokenAndMtls => "token+mtls",
        })
    }
}

/// Server authentication policy. Absent `[auth]` means `mode = "token"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerAuthConfig {
    pub mode: AuthMode,
    /// PEM trust anchor for client certificates. Required when `mode` is
    /// `mtls` or `token+mtls`. Changing this or `mode` needs a process restart;
    /// the TLS verifier is built at startup.
    pub client_ca_file: Option<PathBuf>,
    /// In-memory client CA PEM for tests and embedders.
    #[serde(skip)]
    pub client_ca_pem: Option<String>,
}

impl Default for ServerAuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Token,
            client_ca_file: None,
            client_ca_pem: None,
        }
    }
}

/// Client authentication material. Absent `[auth]` means `mode = "token"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClientAuthConfig {
    pub mode: AuthMode,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    /// In-memory client certificate PEM for tests and embedders.
    #[serde(skip)]
    pub cert_pem: Option<String>,
    /// In-memory client private key PEM for tests and embedders.
    #[serde(skip)]
    pub key_pem: Option<String>,
}

impl Default for ClientAuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Token,
            cert_file: None,
            key_file: None,
            cert_pem: None,
            key_pem: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelKind {
    Tcp,
    Http,
    Udp,
}

impl TunnelKind {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Tcp => crate::frame::TUNNEL_TCP,
            Self::Http => crate::frame::TUNNEL_HTTP,
            Self::Udp => crate::frame::TUNNEL_UDP,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            crate::frame::TUNNEL_TCP => Some(Self::Tcp),
            crate::frame::TUNNEL_HTTP => Some(Self::Http),
            crate::frame::TUNNEL_UDP => Some(Self::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Pretty,
    Json,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default)]
    pub format: LogFormat,
    /// Tracing filter used when `RUST_LOG` is unset.
    #[serde(default = "default_log_filter")]
    pub filter: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Pretty,
            filter: default_log_filter(),
        }
    }
}

fn default_log_filter() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatConfig {
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_interval(),
            timeout_secs: default_timeout(),
        }
    }
}

impl HeartbeatConfig {
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

fn default_interval() -> u64 {
    15
}

fn default_timeout() -> u64 {
    45
}

fn default_drain_secs() -> u64 {
    5
}

/// How long existing data streams may finish after a shutdown signal.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownConfig {
    /// Seconds to drain accepted streams before forcing the process to exit.
    /// `0` skips the drain and exits immediately.
    #[serde(default = "default_drain_secs")]
    pub drain_secs: u64,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_secs: default_drain_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Active tunnels for one authenticated client. `0` means no per-client cap.
    #[serde(default = "default_max_tunnels")]
    pub max_tunnels: u32,
    /// Concurrent data streams for one authenticated client. `0` means no per-client cap.
    #[serde(default = "default_max_streams")]
    pub max_streams: u32,
    /// Active tunnels across every client. `0` means no global cap.
    #[serde(default)]
    pub max_tunnels_global: u32,
    /// Concurrent data streams across every client. `0` means no global cap.
    #[serde(default)]
    pub max_streams_global: u32,
    /// Public-to-origin bytes per second for one client. `0` means unlimited.
    #[serde(default)]
    pub bytes_in_per_sec: u64,
    /// Origin-to-public bytes per second for one client. `0` means unlimited.
    #[serde(default)]
    pub bytes_out_per_sec: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_tunnels: default_max_tunnels(),
            max_streams: default_max_streams(),
            max_tunnels_global: 0,
            max_streams_global: 0,
            bytes_in_per_sec: 0,
            bytes_out_per_sec: 0,
        }
    }
}

fn default_max_tunnels() -> u32 {
    64
}

fn default_max_streams() -> u32 {
    256
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclConfig {
    /// TCP and UDP `remote_port` values a client may bind. Empty denies every
    /// port unless [`Self::allow_any_port`] is set. The same ACL list covers
    /// both tunnel kinds; TCP and UDP may still share a port number.
    #[serde(default)]
    pub allow_ports: Vec<u16>,
    /// HTTP hostnames a client may claim. Empty denies every name unless
    /// [`Self::allow_any_hostname`] is set. Matching is case-insensitive.
    #[serde(default)]
    pub allow_hostnames: Vec<String>,
    /// Permit any TCP or UDP port, including ephemeral `remote_port = 0`.
    #[serde(default)]
    pub allow_any_port: bool,
    /// Permit any HTTP hostname.
    #[serde(default)]
    pub allow_any_hostname: bool,
}

impl AclConfig {
    pub fn permits_port(&self, port: u16) -> bool {
        if self.allow_any_port {
            return true;
        }
        // Port 0 asks the server to bind an ephemeral port. That is only
        // available when every port is allowed; an explicit list cannot name
        // the port that will be chosen.
        if port == 0 {
            return false;
        }
        self.allow_ports.contains(&port)
    }

    pub fn permits_hostname(&self, hostname: &str) -> bool {
        if self.allow_any_hostname {
            return true;
        }
        self.allow_hostnames
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(hostname))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpBind {
    pub bind: String,
}

/// Public HTTPS listener. TLS is terminated here; Host routing uses the same
/// table as plaintext `[http]`. Certificates default to the server identity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsBind {
    pub bind: String,
    /// Optional override. When set, `key_file` must be set too.
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// In-memory cert PEM for tests and embedders (https override).
    #[serde(skip)]
    pub cert_pem: Option<String>,
    /// In-memory key PEM for tests and embedders (https override).
    #[serde(skip)]
    pub key_pem: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Shared secret. Required for `auth.mode` `token` and `token+mtls`.
    /// May be empty when `mode` is `mtls`. Never logged.
    pub token: String,
    /// UDP address for the QUIC control listener. Omit to disable QUIC.
    #[serde(default)]
    pub quic_bind: Option<String>,
    /// TCP address for the TLS control listener. Omit to disable TLS.
    #[serde(default)]
    pub tls_bind: Option<String>,
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// Generate a process-local certificate and write `pharos-dev.crt` beside
    /// the config file. Refuses to be the only identity story in production;
    /// the server logs a warning on every start.
    #[serde(default)]
    pub dev_ephemeral_cert: bool,
    /// Local address used when binding TCP reverse-tunnel ports.
    #[serde(default = "default_tcp_bind_ip")]
    pub tcp_bind_ip: String,
    #[serde(default)]
    pub http: Option<HttpBind>,
    /// Public HTTPS listener (TLS termination + Host routing). Restart-only.
    #[serde(default)]
    pub https: Option<HttpsBind>,
    #[serde(default)]
    pub acl: AclConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    #[serde(default)]
    pub shutdown: ShutdownConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub auth: ServerAuthConfig,
    /// Optional `host:port` that serves a Prometheus text exposition.
    #[serde(default)]
    pub metrics_bind: Option<String>,
    /// PEM certificate supplied by tests or an embedding process.
    #[serde(skip)]
    pub cert_pem: Option<String>,
    /// PEM private key supplied by tests or an embedding process.
    #[serde(skip)]
    pub key_pem: Option<String>,
    /// Set by [`ServerConfig::load_path`] so ACL and token can be re-read.
    #[serde(skip)]
    pub config_path: Option<PathBuf>,
}

fn default_tcp_bind_ip() -> String {
    "0.0.0.0".into()
}

impl ServerConfig {
    pub fn parse_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_path(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut cfg = Self::parse_toml(&text)?;
        cfg.config_path = Some(path.to_path_buf());
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.auth.mode.requires_token() && self.token.is_empty() {
            return Err(ConfigError::Invalid(
                "token is required and must not be empty when auth.mode is token or token+mtls"
                    .into(),
            ));
        }
        if self.token.len() > crate::buf::MAX_STRING {
            return Err(ConfigError::Invalid("token is too long".into()));
        }
        if self.auth.mode.requires_client_cert()
            && self.auth.client_ca_file.is_none()
            && self.auth.client_ca_pem.is_none()
        {
            return Err(ConfigError::Invalid(
                "auth.client_ca_file is required when auth.mode is mtls or token+mtls".into(),
            ));
        }
        if self.quic_bind.is_none() && self.tls_bind.is_none() {
            return Err(ConfigError::Invalid(
                "set quic_bind, tls_bind, or both".into(),
            ));
        }
        if let Some(addr) = &self.quic_bind {
            parse_socket_addr(addr, "quic_bind")?;
        }
        if let Some(addr) = &self.tls_bind {
            parse_socket_addr(addr, "tls_bind")?;
        }
        if let Some(http) = &self.http {
            parse_socket_addr(&http.bind, "http.bind")?;
        }
        if let Some(https) = &self.https {
            parse_socket_addr(&https.bind, "https.bind")?;
            if https.cert_file.is_some() != https.key_file.is_some() {
                return Err(ConfigError::Invalid(
                    "https.cert_file and https.key_file must be set together".into(),
                ));
            }
            if https.cert_pem.is_some() != https.key_pem.is_some() {
                return Err(ConfigError::Invalid(
                    "https.cert_pem and https.key_pem must be set together".into(),
                ));
            }
            let https_inline = https.cert_pem.is_some() && https.key_pem.is_some();
            let https_files = https.cert_file.is_some() && https.key_file.is_some();
            let server_inline = self.cert_pem.is_some() && self.key_pem.is_some();
            let server_files = self.cert_file.is_some() && self.key_file.is_some();
            if !https_inline
                && !https_files
                && !server_inline
                && !server_files
                && !self.dev_ephemeral_cert
            {
                return Err(ConfigError::Invalid(
                    "https requires cert_file and key_file (or https.cert_file/https.key_file), or dev_ephemeral_cert = true"
                        .into(),
                ));
            }
        }
        if let Some(metrics) = &self.metrics_bind {
            parse_socket_addr(metrics, "metrics_bind")?;
        }
        self.tcp_bind_ip
            .parse::<std::net::IpAddr>()
            .map_err(|err| ConfigError::Invalid(format!("tcp_bind_ip: {err}")))?;
        let has_inline = self.cert_pem.is_some() && self.key_pem.is_some();
        let has_files = self.cert_file.is_some() && self.key_file.is_some();
        if self.cert_file.is_some() != self.key_file.is_some() {
            return Err(ConfigError::Invalid(
                "cert_file and key_file must be set together".into(),
            ));
        }
        if self.cert_pem.is_some() != self.key_pem.is_some() {
            return Err(ConfigError::Invalid(
                "cert_pem and key_pem must be set together".into(),
            ));
        }
        if !has_inline && !has_files && !self.dev_ephemeral_cert {
            return Err(ConfigError::Invalid(
                "provide cert_file and key_file, or set dev_ephemeral_cert = true".into(),
            ));
        }
        validate_heartbeat(&self.heartbeat)?;
        Ok(())
    }

    pub fn quic_addr(&self) -> Result<Option<SocketAddr>, ConfigError> {
        optional_addr(self.quic_bind.as_deref(), "quic_bind")
    }

    pub fn tls_addr(&self) -> Result<Option<SocketAddr>, ConfigError> {
        optional_addr(self.tls_bind.as_deref(), "tls_bind")
    }

    pub fn http_addr(&self) -> Result<Option<SocketAddr>, ConfigError> {
        match &self.http {
            Some(http) => Ok(Some(parse_socket_addr(&http.bind, "http.bind")?)),
            None => Ok(None),
        }
    }

    pub fn https_addr(&self) -> Result<Option<SocketAddr>, ConfigError> {
        match &self.https {
            Some(https) => Ok(Some(parse_socket_addr(&https.bind, "https.bind")?)),
            None => Ok(None),
        }
    }

    pub fn metrics_addr(&self) -> Result<Option<SocketAddr>, ConfigError> {
        optional_addr(self.metrics_bind.as_deref(), "metrics_bind")
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconnectConfig {
    /// When false, the client exits after the first session ends.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_reconnect_min")]
    pub min_secs: u64,
    #[serde(default = "default_reconnect_max")]
    pub max_secs: u64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_secs: default_reconnect_min(),
            max_secs: default_reconnect_max(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_reconnect_min() -> u64 {
    1
}

fn default_reconnect_max() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: TunnelKind,
    pub local: String,
    #[serde(default)]
    pub remote_port: u16,
    #[serde(default)]
    pub hostname: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// `host:port` of the Pharos server.
    pub server: String,
    pub token: String,
    #[serde(default)]
    pub transport: TransportMode,
    /// Name checked against the server certificate. Not the dial address.
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// Skip certificate verification. Logs a warning. Do not use on untrusted networks.
    #[serde(default)]
    pub tls_insecure: bool,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    #[serde(default)]
    pub shutdown: ShutdownConfig,
    #[serde(default)]
    pub reconnect: ReconnectConfig,
    #[serde(default)]
    pub tunnels: Vec<TunnelConfig>,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub auth: ClientAuthConfig,
    /// PEM CA material supplied by tests. This is the server trust anchor.
    #[serde(skip)]
    pub ca_pem: Option<String>,
    /// Set by [`ClientConfig::load_path`] so the tunnel list can be re-read.
    #[serde(skip)]
    pub config_path: Option<PathBuf>,
}

fn default_server_name() -> String {
    "localhost".into()
}

impl ClientConfig {
    pub fn parse_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_path(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut cfg = Self::parse_toml(&text)?;
        cfg.config_path = Some(path.to_path_buf());
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.auth.mode.requires_token() && self.token.is_empty() {
            return Err(ConfigError::Invalid(
                "token is required and must not be empty when auth.mode is token or token+mtls"
                    .into(),
            ));
        }
        if self.token.len() > crate::buf::MAX_STRING {
            return Err(ConfigError::Invalid("token is too long".into()));
        }
        if self.auth.mode.requires_client_cert() {
            let has_pem = self.auth.cert_pem.is_some() && self.auth.key_pem.is_some();
            let has_files = self.auth.cert_file.is_some() && self.auth.key_file.is_some();
            if self.auth.cert_file.is_some() != self.auth.key_file.is_some() {
                return Err(ConfigError::Invalid(
                    "auth.cert_file and auth.key_file must be set together".into(),
                ));
            }
            if self.auth.cert_pem.is_some() != self.auth.key_pem.is_some() {
                return Err(ConfigError::Invalid(
                    "auth.cert_pem and auth.key_pem must be set together".into(),
                ));
            }
            if !has_pem && !has_files {
                return Err(ConfigError::Invalid(
                    "auth.cert_file and auth.key_file are required when auth.mode is mtls or token+mtls"
                        .into(),
                ));
            }
        }
        if self.server_name.is_empty() {
            return Err(ConfigError::Invalid("server_name must not be empty".into()));
        }
        parse_host_port(&self.server, "server")?;
        if !self.tls_insecure && self.ca_file.is_none() && self.ca_pem.is_none() {
            return Err(ConfigError::Invalid(
                "set ca_file to the server certificate, or tls_insecure = true for a trusted lab"
                    .into(),
            ));
        }
        validate_heartbeat(&self.heartbeat)?;
        if self.reconnect.min_secs == 0 || self.reconnect.max_secs < self.reconnect.min_secs {
            return Err(ConfigError::Invalid(
                "reconnect.min_secs must be >= 1 and reconnect.max_secs must be >= min_secs".into(),
            ));
        }
        let mut names = HashSet::new();
        for tunnel in &self.tunnels {
            if tunnel.name.is_empty() || tunnel.name.len() > 64 {
                return Err(ConfigError::Invalid(
                    "tunnel name must be 1..=64 characters".into(),
                ));
            }
            if !names.insert(tunnel.name.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate tunnel name '{}'",
                    tunnel.name
                )));
            }
            if tunnel.local.parse::<SocketAddr>().is_err() {
                return Err(ConfigError::Invalid(format!(
                    "tunnel '{}': local must be host:port (for example 127.0.0.1:22)",
                    tunnel.name
                )));
            }
            match tunnel.kind {
                TunnelKind::Tcp | TunnelKind::Udp => {}
                TunnelKind::Http => {
                    if tunnel.hostname.is_empty() {
                        return Err(ConfigError::Invalid(format!(
                            "tunnel '{}': http tunnels require hostname",
                            tunnel.name
                        )));
                    }
                    if tunnel.hostname.len() > 253 {
                        return Err(ConfigError::Invalid(format!(
                            "tunnel '{}': hostname is too long",
                            tunnel.name
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

fn validate_heartbeat(heartbeat: &HeartbeatConfig) -> Result<(), ConfigError> {
    if heartbeat.interval_secs == 0 || heartbeat.timeout_secs == 0 {
        return Err(ConfigError::Invalid(
            "heartbeat interval_secs and timeout_secs must be at least 1".into(),
        ));
    }
    if heartbeat.timeout_secs < heartbeat.interval_secs {
        // Allowed so operators (and tests) can drop a silent peer faster than
        // the send interval. The server logs a warning when this is set.
    }
    Ok(())
}

fn optional_addr(value: Option<&str>, field: &str) -> Result<Option<SocketAddr>, ConfigError> {
    match value {
        Some(value) => Ok(Some(parse_socket_addr(value, field)?)),
        None => Ok(None),
    }
}

pub fn parse_socket_addr(value: &str, field: &str) -> Result<SocketAddr, ConfigError> {
    value
        .parse()
        .map_err(|err| ConfigError::Invalid(format!("{field}: {err}")))
}

fn parse_host_port(value: &str, field: &str) -> Result<(), ConfigError> {
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(ConfigError::Invalid(format!("{field} must be host:port")));
    };
    if host.is_empty() {
        return Err(ConfigError::Invalid(format!("{field} is missing a host")));
    }
    if port.parse::<u16>().is_err() {
        return Err(ConfigError::Invalid(format!("{field} has an invalid port")));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("{0}")]
    Invalid(String),
}

/// Compare tokens without leaking the configured secret through an early length check
/// on the raw strings. Both sides are hashed, then the digests are compared in constant time.
pub fn tokens_equal(expected: &str, presented: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let left = Sha256::digest(expected.as_bytes());
    let right = Sha256::digest(presented.as_bytes());
    left.ct_eq(&right).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_token_is_rejected() {
        let toml = r#"
            quic_bind = "127.0.0.1:7600"
            dev_ephemeral_cert = true
        "#;
        let err = ServerConfig::parse_toml(toml).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("token") || rendered.contains("missing field"),
            "{rendered}"
        );
    }

    #[test]
    fn empty_token_is_rejected() {
        let toml = r#"
            token = ""
            tls_bind = "127.0.0.1:7600"
            dev_ephemeral_cert = true
        "#;
        let err = ServerConfig::parse_toml(toml).unwrap_err();
        assert!(err.to_string().contains("token"), "{err}");
    }

    #[test]
    fn client_missing_token_is_rejected() {
        let toml = r#"
            server = "127.0.0.1:7600"
            tls_insecure = true
        "#;
        let err = ClientConfig::parse_toml(toml).unwrap_err();
        assert!(err.to_string().contains("token"), "{err}");
    }

    #[test]
    fn acl_is_fail_closed() {
        let acl = AclConfig::default();
        assert!(!acl.permits_port(2222));
        assert!(!acl.permits_port(0));
        assert!(!acl.permits_hostname("demo.local"));
        let acl = AclConfig {
            allow_ports: vec![2222],
            allow_hostnames: vec!["Demo.Local".into()],
            allow_any_port: false,
            allow_any_hostname: false,
        };
        assert!(acl.permits_port(2222));
        assert!(!acl.permits_port(2223));
        assert!(acl.permits_hostname("demo.local"));
    }

    #[test]
    fn token_compare_ignores_timing_of_length() {
        assert!(tokens_equal("abc", "abc"));
        assert!(!tokens_equal("abc", "abd"));
        assert!(!tokens_equal("abc", ""));
        assert!(!tokens_equal("abc", "abcd"));
    }

    #[test]
    fn examples_parse() {
        let server = include_str!("../../../examples/server.toml");
        ServerConfig::parse_toml(server).expect("examples/server.toml");
        let client = include_str!("../../../examples/client.toml");
        ClientConfig::parse_toml(client).expect("examples/client.toml");
        let mtls_server = include_str!("../../../examples/mtls-server.toml");
        ServerConfig::parse_toml(mtls_server).expect("examples/mtls-server.toml");
        let mtls_client = include_str!("../../../examples/mtls-client.toml");
        ClientConfig::parse_toml(mtls_client).expect("examples/mtls-client.toml");
    }

    #[test]
    fn mtls_mode_requires_a_client_ca_and_allows_an_empty_token() {
        let missing_ca = r#"
            token = ""
            tls_bind = "127.0.0.1:7600"
            dev_ephemeral_cert = true
            [auth]
            mode = "mtls"
        "#;
        let err = ServerConfig::parse_toml(missing_ca).unwrap_err();
        assert!(err.to_string().contains("client_ca_file"), "{err}");

        let ok = r#"
            token = ""
            tls_bind = "127.0.0.1:7600"
            dev_ephemeral_cert = true
            [auth]
            mode = "mtls"
            client_ca_file = "certs/client-ca.crt"
        "#;
        let cfg = ServerConfig::parse_toml(ok).expect("mtls with empty token");
        assert_eq!(cfg.auth.mode, AuthMode::Mtls);
        assert!(!cfg.auth.mode.requires_token());
        assert!(cfg.auth.mode.requires_client_cert());
    }

    #[test]
    fn https_bind_required_when_section_present() {
        let toml = r#"
            token = "x"
            tls_bind = "127.0.0.1:7600"
            dev_ephemeral_cert = true
            [https]
        "#;
        let err = ServerConfig::parse_toml(toml).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("bind") || rendered.contains("missing field"),
            "{rendered}"
        );
    }

    #[test]
    fn https_reuses_server_identity_when_no_override() {
        let toml = r#"
            token = "x"
            tls_bind = "127.0.0.1:7600"
            dev_ephemeral_cert = true
            [https]
            bind = "127.0.0.1:7443"
        "#;
        let cfg = ServerConfig::parse_toml(toml).expect("https with shared identity");
        assert_eq!(cfg.https.as_ref().unwrap().bind, "127.0.0.1:7443");
        assert!(cfg.https_addr().unwrap().is_some());
    }

    #[test]
    fn https_cert_override_must_be_paired() {
        let toml = r#"
            token = "x"
            tls_bind = "127.0.0.1:7600"
            dev_ephemeral_cert = true
            [https]
            bind = "127.0.0.1:7443"
            cert_file = "certs/https.crt"
        "#;
        let err = ServerConfig::parse_toml(toml).unwrap_err();
        assert!(
            err.to_string().contains("https.cert_file") && err.to_string().contains("key_file"),
            "{err}"
        );
    }

    #[test]
    fn udp_tunnel_parses_like_tcp() {
        let toml = r#"
            server = "127.0.0.1:7600"
            token = "x"
            tls_insecure = true
            [[tunnels]]
            name = "dns"
            type = "udp"
            local = "127.0.0.1:53"
            remote_port = 5353
        "#;
        let cfg = ClientConfig::parse_toml(toml).expect("udp tunnel");
        assert_eq!(cfg.tunnels[0].kind, TunnelKind::Udp);
        assert_eq!(cfg.tunnels[0].remote_port, 5353);
    }

}
