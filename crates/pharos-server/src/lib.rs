//! Pharos server. Authenticates clients with a required PSK, then publishes
//! TCP ports and HTTP hostnames they register.

#![forbid(unsafe_code)]

mod http;
mod metrics_srv;
mod pace;
mod quic;
mod session;
mod state;
mod tls;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use pharos_proto::{
    generate_dev_identity, https_terminator_config, identity_from_files, identity_from_pem,
    install_ring, server_config, Identity, LogConfig, LogFormat, ServerConfig,
};
use state::{AppState, Metrics, Shutdown};
use tokio::net::{TcpListener, TcpSocket};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

pub use pharos_proto::ServerConfig as Config;

pub struct ServerHandle {
    pub quic_addr: Option<SocketAddr>,
    pub tls_addr: Option<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
    pub https_addr: Option<SocketAddr>,
    pub metrics_addr: Option<SocketAddr>,
    pub shutdown: Shutdown,
    join: Option<JoinHandle<anyhow::Result<()>>>,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

impl ServerHandle {
    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        self.shutdown.cancel();
        if let Some(join) = self.join.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), join).await {
                Ok(Ok(result)) => result,
                Ok(Err(err)) => Err(err.into()),
                Err(_) => Ok(()),
            }
        } else {
            Ok(())
        }
    }
}

pub fn load_config(path: &Path) -> anyhow::Result<ServerConfig> {
    Ok(ServerConfig::load_path(path)?)
}

pub fn init_tracing(log: &LogConfig) -> anyhow::Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log.filter.clone()));
    match log.format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .with_target(true)
                .try_init()
                .ok();
        }
        LogFormat::Pretty => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(true)
                .try_init()
                .ok();
        }
    }
    Ok(())
}

pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    let drain = std::time::Duration::from_secs(config.shutdown.drain_secs);
    let mut handle = spawn(config).await?;
    let join = handle
        .join
        .take()
        .ok_or_else(|| anyhow::anyhow!("server task missing"))?;
    tokio::pin!(join);
    tokio::select! {
        _ = wait_for_exit_signal() => {
            tracing::info!(
                phase = "draining",
                drain_secs = drain.as_secs(),
                "shutdown: stopping new connections and registrations"
            );
            handle.shutdown.begin_drain();
            if !drain.is_zero() {
                tokio::select! {
                    _ = tokio::time::sleep(drain) => {}
                    result = &mut join => {
                        tracing::info!(phase = "stopped", "shutdown: server task ended during drain");
                        return match result {
                            Ok(inner) => inner,
                            Err(err) => Err(err.into()),
                        };
                    }
                }
            }
            tracing::info!(phase = "stopped", "shutdown: drain finished, forcing exit");
            handle.shutdown.cancel();
            match tokio::time::timeout(std::time::Duration::from_secs(2), &mut join).await {
                Ok(Ok(inner)) => inner,
                Ok(Err(err)) => Err(err.into()),
                Err(_) => Ok(()),
            }
        }
        result = &mut join => {
            match result {
                Ok(inner) => inner,
                Err(err) => Err(err.into()),
            }
        }
    }
}

async fn wait_for_exit_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(err) = result {
                            tracing::warn!(error = %err, "interrupt handler failed");
                        }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "SIGTERM handler unavailable");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %err, "interrupt handler failed");
        }
    }
}

pub async fn spawn(config: ServerConfig) -> anyhow::Result<ServerHandle> {
    config.validate()?;
    install_ring();
    if config.heartbeat.timeout_secs < config.heartbeat.interval_secs {
        tracing::warn!(
            "heartbeat timeout is shorter than the interval; idle sessions will be dropped"
        );
    }
    let identity = load_identity(&config)?;
    let client_ca = load_client_ca(&config)?;
    let shutdown = Shutdown::new();
    tracing::info!(auth = %config.auth.mode, "authentication mode");

    let tls_listener = match config.tls_addr()? {
        Some(addr) => Some(bind_listener(addr)?),
        None => None,
    };
    let tls_bound = local_addr(tls_listener.as_ref())?;
    let quic_endpoint = match config.quic_addr()? {
        Some(addr) => {
            let server_config =
                quic::server_quic_config(&identity, client_ca.as_deref(), &config.heartbeat)?;
            Some(quinn::Endpoint::server(server_config, addr)?)
        }
        None => None,
    };
    let quic_bound = match &quic_endpoint {
        Some(endpoint) => Some(endpoint.local_addr()?),
        None => None,
    };
    let http_listener = match config.http_addr()? {
        Some(addr) => Some(bind_listener(addr)?),
        None => None,
    };
    let http_bound = local_addr(http_listener.as_ref())?;
    let https_identity = load_https_identity(&config, &identity)?;
    let https_listener = match config.https_addr()? {
        Some(addr) => Some(bind_listener(addr)?),
        None => None,
    };
    let https_bound = local_addr(https_listener.as_ref())?;
    let https_acceptor = match (&https_listener, https_identity.as_ref()) {
        (Some(_), Some(https_id)) => Some(TlsAcceptor::from(Arc::new(
            https_terminator_config(https_id)?,
        ))),
        (Some(_), None) => {
            anyhow::bail!("https listener requires a certificate identity");
        }
        _ => None,
    };
    let metrics_listener = match config.metrics_addr()? {
        Some(addr) => Some(bind_listener(addr)?),
        None => None,
    };
    let metrics_bound = local_addr(metrics_listener.as_ref())?;

    let tcp_bind_ip = config
        .tcp_bind_ip
        .parse()
        .map_err(|err| anyhow::anyhow!("tcp_bind_ip: {err}"))?;
    let app = Arc::new(AppState {
        auth_mode: config.auth.mode,
        tokens: RwLock::new(config.accepted_tokens()),
        acl: RwLock::new(config.acl.clone()),
        heartbeat: RwLock::new(config.heartbeat.clone()),
        limits: Arc::new(RwLock::new(config.limits.clone())),
        tcp_bind_ip,
        http_routes: Arc::new(RwLock::new(std::collections::HashMap::new())),
        http_advertise: http_bound,
        https_advertise: https_bound,
        metrics: Arc::new(Metrics::default()),
        metrics_token: Arc::new(RwLock::new(config.metrics_token.clone())),
        shutdown: shutdown.clone(),
        acl_watchers: Mutex::new(Vec::new()),
    });

    let acceptor = TlsAcceptor::from(Arc::new(server_config(&identity, client_ca.as_deref())?));
    let app_task = app.clone();
    let shutdown_task = shutdown.clone();
    let config_path = config.config_path.clone();
    let baseline = ListenerBaseline::from_config(&config);
    let join = tokio::spawn(async move {
        serve(
            app_task,
            shutdown_task,
            tls_listener,
            acceptor,
            quic_endpoint,
            http_listener,
            https_listener,
            https_acceptor,
            metrics_listener,
            config_path,
            baseline,
        )
        .await
    });

    tracing::info!(
        quic = ?quic_bound,
        tls = ?tls_bound,
        http = ?http_bound,
        https = ?https_bound,
        metrics = ?metrics_bound,
        version = env!("CARGO_PKG_VERSION"),
        "pharos-server listening"
    );
    Ok(ServerHandle {
        quic_addr: quic_bound,
        tls_addr: tls_bound,
        http_addr: http_bound,
        https_addr: https_bound,
        metrics_addr: metrics_bound,
        shutdown,
        join: Some(join),
    })
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    app: Arc<AppState>,
    shutdown: Shutdown,
    tls_listener: Option<TcpListener>,
    acceptor: TlsAcceptor,
    quic_endpoint: Option<quinn::Endpoint>,
    http_listener: Option<TcpListener>,
    https_listener: Option<TcpListener>,
    https_acceptor: Option<TlsAcceptor>,
    metrics_listener: Option<TcpListener>,
    config_path: Option<PathBuf>,
    baseline: ListenerBaseline,
) -> anyhow::Result<()> {
    let mut tasks = JoinSet::new();
    if let Some(listener) = tls_listener {
        let app = app.clone();
        let shutdown = shutdown.clone();
        let acceptor = acceptor.clone();
        tasks.spawn(async move {
            tls::tls_loop(listener, acceptor, app, shutdown).await;
        });
    }
    if let Some(endpoint) = quic_endpoint {
        let app = app.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            quic::quic_loop(endpoint, app, shutdown).await;
        });
    }
    if let Some(listener) = http_listener {
        let app = app.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            http::http_loop(listener, app, shutdown).await;
        });
    }
    if let (Some(listener), Some(https_acceptor)) = (https_listener, https_acceptor) {
        let app = app.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            http::https_loop(listener, https_acceptor, app, shutdown).await;
        });
    }
    if let Some(listener) = metrics_listener {
        let metrics = app.metrics.clone();
        let metrics_token = app.metrics_token.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            metrics_srv::metrics_loop(listener, metrics, metrics_token, shutdown).await;
        });
    }
    if let Some(path) = config_path {
        let app = app.clone();
        let shutdown = shutdown.clone();
        let baseline = baseline.clone();
        tasks.spawn(async move {
            reload_loop(path, app, shutdown, baseline).await;
        });
    }

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            next = tasks.join_next() => {
                match next {
                    None => break,
                    Some(Ok(())) => {}
                    Some(Err(err)) => {
                        shutdown.cancel();
                        return Err(err.into());
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
struct ListenerBaseline {
    quic_bind: Option<String>,
    tls_bind: Option<String>,
    http_bind: Option<String>,
    https_bind: Option<String>,
    https_cert_file: Option<PathBuf>,
    https_key_file: Option<PathBuf>,
    metrics_bind: Option<String>,
    tcp_bind_ip: String,
    auth_mode: String,
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
    client_ca_file: Option<PathBuf>,
    dev_ephemeral_cert: bool,
}

impl ListenerBaseline {
    fn from_config(config: &ServerConfig) -> Self {
        Self {
            quic_bind: config.quic_bind.clone(),
            tls_bind: config.tls_bind.clone(),
            http_bind: config.http.as_ref().map(|http| http.bind.clone()),
            https_bind: config.https.as_ref().map(|https| https.bind.clone()),
            https_cert_file: config
                .https
                .as_ref()
                .and_then(|https| https.cert_file.clone()),
            https_key_file: config
                .https
                .as_ref()
                .and_then(|https| https.key_file.clone()),
            metrics_bind: config.metrics_bind.clone(),
            tcp_bind_ip: config.tcp_bind_ip.clone(),
            auth_mode: config.auth.mode.to_string(),
            cert_file: config.cert_file.clone(),
            key_file: config.key_file.clone(),
            client_ca_file: config.auth.client_ca_file.clone(),
            dev_ephemeral_cert: config.dev_ephemeral_cert,
        }
    }

    fn warn_if_restart_required(&self, config: &ServerConfig) {
        let next = Self::from_config(config);
        if self == &next {
            return;
        }
        tracing::warn!(
            metrics_bind = ?next.metrics_bind,
            "listener and identity settings are not hot-reloaded; restart pharos-server to apply quic_bind, tls_bind, http.bind, https.bind, metrics_bind, tcp_bind_ip, certificates, or auth.mode"
        );
    }
}

async fn reload_loop(
    path: PathBuf,
    app: Arc<AppState>,
    shutdown: Shutdown,
    baseline: ListenerBaseline,
) {
    let mut seen = std::fs::read(&path).ok();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(std::time::Duration::from_millis(400)) => {}
        }
        if shutdown.is_cancelled() {
            break;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if seen.as_ref() == Some(&bytes) {
            continue;
        }
        match ServerConfig::load_path(&path) {
            Ok(cfg) => {
                seen = Some(bytes);
                baseline.warn_if_restart_required(&cfg);
                *app.tokens.write().expect("tokens") = cfg.accepted_tokens();
                *app.metrics_token.write().expect("metrics_token") = cfg.metrics_token.clone();
                *app.acl.write().expect("acl") = cfg.acl.clone();
                *app.heartbeat.write().expect("heartbeat") = cfg.heartbeat;
                *app.limits.write().expect("limits") = cfg.limits;
                let mut watchers = app.acl_watchers.lock().expect("acl watchers");
                watchers.retain(|tx| tx.send(cfg.acl.clone()).is_ok());
                tracing::info!("reloaded tokens, metrics_token, ACL, heartbeat, and limits");
            }
            Err(err) => {
                tracing::error!(error = %err, "config reload failed; keeping the previous settings");
            }
        }
    }
}

fn load_client_ca(config: &ServerConfig) -> anyhow::Result<Option<String>> {
    if !config.auth.mode.requires_client_cert() {
        return Ok(None);
    }
    if let Some(pem) = &config.auth.client_ca_pem {
        return Ok(Some(pem.clone()));
    }
    if let Some(path) = &config.auth.client_ca_file {
        return Ok(Some(std::fs::read_to_string(path).map_err(|err| {
            anyhow::anyhow!("read client CA {}: {err}", path.display())
        })?));
    }
    anyhow::bail!("auth.client_ca_file is required for mTLS");
}

fn load_https_identity(
    config: &ServerConfig,
    server_identity: &Identity,
) -> anyhow::Result<Option<Identity>> {
    let Some(https) = &config.https else {
        return Ok(None);
    };
    if let (Some(cert), Some(key)) = (&https.cert_pem, &https.key_pem) {
        return Ok(Some(identity_from_pem(cert, key)?));
    }
    if let (Some(cert), Some(key)) = (&https.cert_file, &https.key_file) {
        return Ok(Some(identity_from_files(cert, key)?));
    }
    let _ = https;
    Ok(Some(server_identity.clone()))
}

fn load_identity(config: &ServerConfig) -> anyhow::Result<Identity> {
    if let (Some(cert), Some(key)) = (&config.cert_pem, &config.key_pem) {
        return Ok(identity_from_pem(cert, key)?);
    }
    if let (Some(cert), Some(key)) = (&config.cert_file, &config.key_file) {
        return Ok(identity_from_files(cert, key)?);
    }
    if config.dev_ephemeral_cert {
        let identity = generate_dev_identity()?;
        if let Some(path) = &config.config_path {
            let dest = path.with_file_name("pharos-dev.crt");
            match std::fs::write(&dest, &identity.cert_pem) {
                Ok(()) => tracing::warn!(
                    path = %dest.display(),
                    "wrote a development certificate; do not use it in production"
                ),
                Err(err) => tracing::warn!(
                    path = %dest.display(),
                    error = %err,
                    "could not write the development certificate"
                ),
            }
        } else {
            tracing::warn!(
                "generated an in-memory development certificate; do not use it in production"
            );
        }
        return Ok(identity);
    }
    anyhow::bail!("no TLS certificate configured");
}

pub(crate) fn bind_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

fn local_addr(listener: Option<&TcpListener>) -> anyhow::Result<Option<SocketAddr>> {
    match listener {
        Some(listener) => Ok(Some(listener.local_addr()?)),
        None => Ok(None),
    }
}
