use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pharos_proto::{
    client_authenticate, client_config_insecure, client_config_with_ca, close_reason, empty_frame,
    identity_from_files, identity_from_pem, read_frame, server_name, write_frame, AuthOk, BiStream,
    ClientConfig, Close, Demux, ErrorBody, FrameType, Heartbeat, HeartbeatAck, Identity, MuxHandle,
    NoPace, OpenStream, RegisterFail, RegisterOk, RegisterTunnel, StreamReady, Traffic,
    TransportMode, TunnelKind, Unregister, UnregisterOk,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownPhase {
    Running,
    Draining,
    Stopped,
}

#[derive(Clone)]
pub struct Shutdown {
    tx: Arc<watch::Sender<ShutdownPhase>>,
    rx: watch::Receiver<ShutdownPhase>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(ShutdownPhase::Running);
        Self {
            tx: Arc::new(tx),
            rx,
        }
    }

    pub fn begin_drain(&self) {
        if *self.tx.borrow() == ShutdownPhase::Running {
            let _ = self.tx.send(ShutdownPhase::Draining);
        }
    }

    pub fn cancel(&self) {
        let _ = self.tx.send(ShutdownPhase::Stopped);
    }

    pub fn is_draining(&self) -> bool {
        *self.tx.borrow() != ShutdownPhase::Running
    }

    pub fn is_cancelled(&self) -> bool {
        *self.tx.borrow() == ShutdownPhase::Stopped
    }

    pub async fn draining(&self) {
        let mut rx = self.rx.clone();
        if self.is_draining() {
            return;
        }
        let _ = rx.wait_for(|phase| *phase != ShutdownPhase::Running).await;
    }

    pub async fn cancelled(&self) {
        let mut rx = self.rx.clone();
        if self.is_cancelled() {
            return;
        }
        let _ = rx.wait_for(|phase| *phase == ShutdownPhase::Stopped).await;
    }
}

#[derive(Debug, Clone)]
pub enum ClientEvent {
    Authenticated {
        session_id: u64,
    },
    Registered {
        name: String,
        tunnel_id: u32,
        public_endpoint: String,
    },
    RegisterFailed {
        name: String,
        code: u16,
        reason: String,
    },
    Ready,
    SessionEnded {
        error: Option<String>,
    },
}

enum CtrlMsg {
    RegisterOk(RegisterOk),
    RegisterFail(RegisterFail),
    UnregisterOk(UnregisterOk),
    ReadyAck,
    Fatal(String),
}

struct RegisteredTunnel {
    id: u32,
    local: String,
    kind: TunnelKind,
    remote_port: u16,
    hostname: String,
}

struct TunnelTable {
    by_id: HashMap<u32, String>,
    by_name: HashMap<String, RegisteredTunnel>,
}

impl TunnelTable {
    fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    fn local(&self, id: u32) -> Option<String> {
        self.by_id.get(&id).cloned()
    }

    fn insert(&mut self, name: String, tunnel: RegisteredTunnel) {
        self.by_id.insert(tunnel.id, tunnel.local.clone());
        self.by_name.insert(name, tunnel);
    }

    fn remove_id(&mut self, id: u32) {
        self.by_name.retain(|_, tunnel| tunnel.id != id);
        self.by_id.remove(&id);
    }

    fn set_local(&mut self, name: &str, local: &str) {
        if let Some(tunnel) = self.by_name.get_mut(name) {
            tunnel.local = local.to_string();
            self.by_id.insert(tunnel.id, local.to_string());
        }
    }
}

pub async fn client_loop(
    mut config: ClientConfig,
    events: mpsc::UnboundedSender<ClientEvent>,
    shutdown: Shutdown,
) {
    let min = Duration::from_secs(config.reconnect.min_secs);
    let max = Duration::from_secs(config.reconnect.max_secs);
    let mut delay = min;
    let mut attempt = 0u64;
    loop {
        if shutdown.is_draining() {
            tracing::info!(phase = "draining", "client shutdown: not reconnecting");
            break;
        }
        attempt += 1;
        refresh_config(&mut config);
        let ready = Arc::new(AtomicBool::new(false));
        tracing::info!(
            attempt,
            server = %config.server,
            tunnels = config.tunnels.len(),
            "dialing control connection"
        );
        match run_session(&config, &events, &shutdown, &ready).await {
            Ok(()) => {
                tracing::info!(attempt, "client stopped");
                let _ = events.send(ClientEvent::SessionEnded { error: None });
                break;
            }
            Err(err) => {
                let reason = err.to_string();
                let established = ready.load(Ordering::Relaxed);
                tracing::warn!(
                    attempt,
                    reason = %reason,
                    established,
                    "control connection lost"
                );
                let _ = events.send(ClientEvent::SessionEnded {
                    error: Some(reason.clone()),
                });
                if shutdown.is_draining() {
                    tracing::info!(phase = "draining", "client shutdown: skipping reconnect");
                    break;
                }
                if !config.reconnect.enabled {
                    break;
                }
                if established {
                    delay = min;
                }
                let wait = jitter(delay);
                tracing::info!(
                    attempt,
                    backoff_ms = wait.as_millis() as u64,
                    reason = %reason,
                    "waiting to reconnect"
                );
                tokio::select! {
                    _ = shutdown.draining() => {
                        tracing::info!(phase = "draining", "client shutdown: reconnect wait cancelled");
                        break;
                    }
                    _ = tokio::time::sleep(wait) => {}
                }
                delay = (delay * 2).min(max);
            }
        }
    }
}

fn refresh_config(config: &mut ClientConfig) {
    let Some(path) = config.config_path.clone() else {
        return;
    };
    let ca_pem = config.ca_pem.clone();
    let insecure = config.tls_insecure;
    let cert_pem = config.auth.cert_pem.clone();
    let key_pem = config.auth.key_pem.clone();
    match ClientConfig::load_path(&path) {
        Ok(mut fresh) => {
            fresh.ca_pem = ca_pem;
            fresh.auth.cert_pem = cert_pem;
            fresh.auth.key_pem = key_pem;
            if fresh.ca_pem.is_some() || fresh.auth.cert_pem.is_some() {
                fresh.tls_insecure = insecure;
            }
            if let Err(err) = fresh.validate() {
                tracing::warn!(
                    error = %err,
                    "reconnect kept the previous client config"
                );
                return;
            }
            *config = fresh;
        }
        Err(err) => {
            tracing::warn!(error = %err, "reconnect kept the previous client config");
        }
    }
}

async fn run_session(
    config: &ClientConfig,
    events: &mpsc::UnboundedSender<ClientEvent>,
    shutdown: &Shutdown,
    ready: &AtomicBool,
) -> anyhow::Result<()> {
    let addr = resolve(&config.server).await?;
    tracing::info!(
        server = %config.server,
        resolved = %addr,
        transport = %config.transport,
        tunnels = config.tunnels.len(),
        "connecting"
    );
    match dial(config, addr).await? {
        Link::Tls(stream) => {
            let (mut reader, mut writer) = tokio::io::split(*stream);
            let auth =
                client_authenticate(&mut reader, &mut writer, &config.token, "pharos-client")
                    .await?;
            finish_session(config, events, shutdown, reader, writer, auth, None, ready).await
        }
        Link::Quic {
            endpoint,
            conn,
            mut send,
            mut recv,
        } => {
            let auth =
                client_authenticate(&mut recv, &mut send, &config.token, "pharos-client").await?;
            let result = finish_session(
                config,
                events,
                shutdown,
                recv,
                send,
                auth,
                Some(conn.clone()),
                ready,
            )
            .await;
            conn.close(quinn::VarInt::from_u32(0), b"session ended");
            endpoint.close(quinn::VarInt::from_u32(0), b"session ended");
            result
        }
    }
}

enum Link {
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Quic {
        endpoint: quinn::Endpoint,
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
}

async fn dial(config: &ClientConfig, addr: SocketAddr) -> anyhow::Result<Link> {
    match config.transport {
        TransportMode::Tls => Ok(Link::Tls(Box::new(connect_tls(config, addr).await?))),
        TransportMode::Quic => connect_quic(config, addr).await,
        TransportMode::Auto => {
            match tokio::time::timeout(Duration::from_secs(3), connect_quic(config, addr)).await {
                Ok(Ok(link)) => Ok(link),
                Ok(Err(err)) => {
                    tracing::warn!(error = %err, "QUIC failed; falling back to TLS");
                    Ok(Link::Tls(Box::new(connect_tls(config, addr).await?)))
                }
                Err(_) => {
                    tracing::warn!("QUIC timed out; falling back to TLS");
                    Ok(Link::Tls(Box::new(connect_tls(config, addr).await?)))
                }
            }
        }
    }
}

async fn connect_tls(
    config: &ClientConfig,
    addr: SocketAddr,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tls = rustls_config(config)?;
    let connector = TlsConnector::from(Arc::new(tls));
    let tcp = TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    let name = server_name(&config.server_name)?;
    let stream = connector.connect(name, tcp).await?;
    Ok(stream)
}

async fn connect_quic(config: &ClientConfig, addr: SocketAddr) -> anyhow::Result<Link> {
    let crypto = rustls_config(config)?;
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|err| anyhow::anyhow!("quic client crypto: {err}"))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(config.heartbeat.interval()));
    let idle = Duration::from_secs(config.heartbeat.timeout_secs.saturating_add(30));
    if let Ok(idle) = quinn::IdleTimeout::try_from(idle) {
        transport.max_idle_timeout(Some(idle));
    }
    client_config.transport_config(Arc::new(transport));
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config);
    let connecting = endpoint
        .connect(addr, &config.server_name)
        .map_err(|err| anyhow::anyhow!("quic connect: {err}"))?;
    let conn = tokio::time::timeout(Duration::from_secs(10), connecting)
        .await
        .map_err(|_| anyhow::anyhow!("quic handshake timed out"))?
        .map_err(|err| anyhow::anyhow!("quic handshake: {err}"))?;
    let (send, recv) = conn.open_bi().await?;
    Ok(Link::Quic {
        endpoint,
        conn,
        send,
        recv,
    })
}

fn rustls_config(config: &ClientConfig) -> anyhow::Result<rustls::ClientConfig> {
    let client_identity = load_client_identity(config)?;
    let client_identity = client_identity.as_ref();
    if config.tls_insecure {
        return Ok(client_config_insecure(client_identity)?);
    }
    if let Some(pem) = &config.ca_pem {
        return Ok(client_config_with_ca(pem, client_identity)?);
    }
    if let Some(path) = &config.ca_file {
        let pem = std::fs::read_to_string(path)?;
        return Ok(client_config_with_ca(&pem, client_identity)?);
    }
    anyhow::bail!("no certificate authority configured");
}

fn load_client_identity(config: &ClientConfig) -> anyhow::Result<Option<Identity>> {
    if !config.auth.mode.requires_client_cert() {
        return Ok(None);
    }
    if let (Some(cert), Some(key)) = (&config.auth.cert_pem, &config.auth.key_pem) {
        return Ok(Some(identity_from_pem(cert, key)?));
    }
    if let (Some(cert), Some(key)) = (&config.auth.cert_file, &config.auth.key_file) {
        return Ok(Some(identity_from_files(cert, key)?));
    }
    anyhow::bail!("auth.cert_file and auth.key_file are required for mTLS");
}

async fn resolve(server: &str) -> anyhow::Result<SocketAddr> {
    tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {server}"))
}

#[allow(clippy::too_many_arguments)]
async fn finish_session<R, W>(
    config: &ClientConfig,
    events: &mpsc::UnboundedSender<ClientEvent>,
    shutdown: &Shutdown,
    reader: R,
    writer: W,
    auth: AuthOk,
    quic: Option<quinn::Connection>,
    ready: &AtomicBool,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let _ = events.send(ClientEvent::Authenticated {
        session_id: auth.session_id,
    });
    tracing::info!(session = auth.session_id, "authenticated");
    let (tx, rx) = mpsc::channel(256);
    let mux = MuxHandle::new(tx);
    let writer_task = tokio::spawn(pharos_proto::write_loop(writer, rx));
    let tunnels: Arc<Mutex<TunnelTable>> = Arc::new(Mutex::new(TunnelTable::new()));
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel();
    let allow_data = quic.is_none();
    let reader_shutdown = shutdown.clone();
    let reader_mux = mux.clone();
    let reader_tunnels = tunnels.clone();
    let reader_ctrl = ctrl_tx.clone();
    let read_timeout = config.heartbeat.timeout();
    let reader_task = tokio::spawn(async move {
        client_read_loop(
            reader,
            reader_mux,
            reader_ctrl,
            reader_shutdown,
            reader_tunnels,
            allow_data,
            read_timeout,
        )
        .await
    });
    if let Some(conn) = quic.clone() {
        let map = tunnels.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            accept_quic(conn, map, shutdown).await;
        });
    }

    let mut registered = 0usize;
    for tunnel in &config.tunnels {
        if register_one(tunnel, &mux, &mut ctrl_rx, &tunnels, events).await? {
            registered += 1;
        }
    }
    if registered == 0 && !config.tunnels.is_empty() {
        anyhow::bail!("no tunnels registered");
    }
    mux.send(empty_frame(FrameType::SessionReady)).await?;
    let message = tokio::time::timeout(Duration::from_secs(5), ctrl_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for ReadyAck"))?
        .ok_or_else(|| anyhow::anyhow!("control connection closed before ReadyAck"))?;
    match message {
        CtrlMsg::ReadyAck => {}
        CtrlMsg::Fatal(message) => anyhow::bail!(message),
        CtrlMsg::RegisterOk(_) | CtrlMsg::RegisterFail(_) | CtrlMsg::UnregisterOk(_) => {
            anyhow::bail!("unexpected register response after SessionReady");
        }
    }
    ready.store(true, Ordering::Relaxed);
    let _ = events.send(ClientEvent::Ready);
    tracing::info!("session ready; tunnels registered");

    let server_interval = Duration::from_millis(u64::from(auth.heartbeat_interval_ms.max(1000)));
    let interval = server_interval.min(config.heartbeat.interval());
    let beat_mux = mux.clone();
    let beat_shutdown = shutdown.clone();
    let heartbeat = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = beat_shutdown.cancelled() => break,
                _ = tokio::time::sleep(interval) => {
                    let frame = Heartbeat { monotonic_ms: pharos_proto::monotonic_ms() }.to_frame();
                    if beat_mux.send(frame).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    tokio::pin!(reader_task);
    let watch_path = config.config_path.clone();
    let mut seen = watch_path
        .as_ref()
        .and_then(|path| std::fs::read(path).ok());
    let outcome = loop {
        let pause = async {
            if watch_path.is_some() {
                tokio::time::sleep(Duration::from_millis(400)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break Ok(()),
            result = &mut reader_task => {
                break match result {
                    Ok(Ok(())) => Err(anyhow::anyhow!("control connection closed")),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(err.into()),
                };
            }
            _ = pause => {
                if let Some(path) = &watch_path {
                    if let Err(err) = sync_tunnels(
                        path,
                        &mut seen,
                        config,
                        &mux,
                        &mut ctrl_rx,
                        &tunnels,
                        events,
                    )
                    .await
                    {
                        tracing::warn!(error = %err, "tunnel reload failed; keeping the control connection");
                    }
                }
            }
        }
    };
    heartbeat.abort();
    writer_task.abort();
    outcome
}

async fn register_one(
    tunnel: &pharos_proto::TunnelConfig,
    mux: &MuxHandle,
    ctrl_rx: &mut mpsc::UnboundedReceiver<CtrlMsg>,
    tunnels: &Arc<Mutex<TunnelTable>>,
    events: &mpsc::UnboundedSender<ClientEvent>,
) -> anyhow::Result<bool> {
    let frame = RegisterTunnel {
        name: tunnel.name.clone(),
        kind: tunnel.kind.as_u8(),
        local: tunnel.local.clone(),
        remote_port: tunnel.remote_port,
        hostname: tunnel.hostname.clone(),
    }
    .to_frame()?;
    mux.send(frame).await?;
    let message = tokio::time::timeout(Duration::from_secs(5), ctrl_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for registration of {}", tunnel.name))?
        .ok_or_else(|| anyhow::anyhow!("control connection closed during registration"))?;
    match message {
        CtrlMsg::RegisterOk(ok) if ok.name == tunnel.name => {
            tunnels.lock().expect("tunnels").insert(
                ok.name.clone(),
                RegisteredTunnel {
                    id: ok.tunnel_id,
                    local: tunnel.local.clone(),
                    kind: tunnel.kind,
                    remote_port: tunnel.remote_port,
                    hostname: tunnel.hostname.clone(),
                },
            );
            tracing::info!(
                tunnel = %ok.name,
                id = ok.tunnel_id,
                public = %ok.public_endpoint,
                "tunnel registered"
            );
            let _ = events.send(ClientEvent::Registered {
                name: ok.name,
                tunnel_id: ok.tunnel_id,
                public_endpoint: ok.public_endpoint,
            });
            Ok(true)
        }
        CtrlMsg::RegisterFail(fail) => {
            tracing::error!(tunnel = %fail.name, code = fail.code, reason = %fail.reason, "tunnel rejected");
            let _ = events.send(ClientEvent::RegisterFailed {
                name: fail.name,
                code: fail.code,
                reason: fail.reason,
            });
            Ok(false)
        }
        CtrlMsg::Fatal(message) => anyhow::bail!(message),
        CtrlMsg::RegisterOk(_) | CtrlMsg::ReadyAck | CtrlMsg::UnregisterOk(_) => {
            anyhow::bail!("unexpected registration response");
        }
    }
}

async fn unregister_one(
    name: &str,
    tunnel_id: u32,
    mux: &MuxHandle,
    ctrl_rx: &mut mpsc::UnboundedReceiver<CtrlMsg>,
    tunnels: &Arc<Mutex<TunnelTable>>,
) -> anyhow::Result<()> {
    mux.send(
        Unregister {
            name: name.to_string(),
            tunnel_id,
        }
        .to_frame()?,
    )
    .await?;
    let message = tokio::time::timeout(Duration::from_secs(5), ctrl_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timed out unregistering {name}"))?
        .ok_or_else(|| anyhow::anyhow!("control connection closed while unregistering {name}"))?;
    match message {
        CtrlMsg::UnregisterOk(ok) => {
            tunnels.lock().expect("tunnels").remove_id(ok.tunnel_id);
            tracing::info!(tunnel = %ok.name, id = ok.tunnel_id, "tunnel unregistered");
            Ok(())
        }
        CtrlMsg::Fatal(message) => anyhow::bail!(message),
        CtrlMsg::RegisterOk(_) | CtrlMsg::RegisterFail(_) | CtrlMsg::ReadyAck => {
            anyhow::bail!("unexpected response while unregistering {name}")
        }
    }
}

async fn sync_tunnels(
    path: &std::path::Path,
    seen: &mut Option<Vec<u8>>,
    live: &ClientConfig,
    mux: &MuxHandle,
    ctrl_rx: &mut mpsc::UnboundedReceiver<CtrlMsg>,
    tunnels: &Arc<Mutex<TunnelTable>>,
    events: &mpsc::UnboundedSender<ClientEvent>,
) -> anyhow::Result<()> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "could not read client config");
            return Ok(());
        }
    };
    if seen.as_ref() == Some(&bytes) {
        return Ok(());
    }
    let text = match String::from_utf8(bytes.clone()) {
        Ok(text) => text,
        Err(err) => {
            *seen = Some(bytes);
            tracing::error!(error = %err, "client config is not utf-8; keeping the current tunnels");
            return Ok(());
        }
    };
    let fresh = match ClientConfig::parse_toml(&text) {
        Ok(cfg) => cfg,
        Err(err) => {
            *seen = Some(bytes);
            tracing::error!(error = %err, "client config reload failed; keeping the current tunnels");
            return Ok(());
        }
    };
    *seen = Some(bytes);
    if fresh.server != live.server
        || fresh.token != live.token
        || fresh.transport != live.transport
        || fresh.auth.mode != live.auth.mode
    {
        tracing::warn!(
            "server, token, transport, or auth.mode changed; restart pharos-client to apply them"
        );
    }
    let desired = fresh.tunnels;
    let current: Vec<(String, RegisteredTunnel)> = {
        let table = tunnels.lock().expect("tunnels");
        table
            .by_name
            .iter()
            .map(|(name, tunnel)| {
                (
                    name.clone(),
                    RegisteredTunnel {
                        id: tunnel.id,
                        local: tunnel.local.clone(),
                        kind: tunnel.kind,
                        remote_port: tunnel.remote_port,
                        hostname: tunnel.hostname.clone(),
                    },
                )
            })
            .collect()
    };
    for (name, existing) in &current {
        let Some(next) = desired.iter().find(|tunnel| &tunnel.name == name) else {
            unregister_one(name, existing.id, mux, ctrl_rx, tunnels).await?;
            continue;
        };
        let rebound = existing.kind != next.kind
            || existing.remote_port != next.remote_port
            || existing.hostname != next.hostname;
        if rebound {
            unregister_one(name, existing.id, mux, ctrl_rx, tunnels).await?;
            let _ = register_one(next, mux, ctrl_rx, tunnels, events).await?;
        } else if existing.local != next.local {
            tunnels
                .lock()
                .expect("tunnels")
                .set_local(name, &next.local);
            tracing::info!(tunnel = %name, local = %next.local, "updated local address");
        }
    }
    for next in &desired {
        let known = tunnels
            .lock()
            .expect("tunnels")
            .by_name
            .contains_key(&next.name);
        if !known {
            let _ = register_one(next, mux, ctrl_rx, tunnels, events).await?;
        }
    }
    Ok(())
}

async fn client_read_loop<R>(
    mut reader: R,
    mux: MuxHandle,
    ctrl: mpsc::UnboundedSender<CtrlMsg>,
    shutdown: Shutdown,
    tunnels: Arc<Mutex<TunnelTable>>,
    allow_data: bool,
    timeout: Duration,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            read = tokio::time::timeout(timeout, read_frame(&mut reader)) => {
                let frame = match read {
                    Err(_) => anyhow::bail!("heartbeat timeout"),
                    Ok(Err(err)) => return Err(err.into()),
                    Ok(Ok(frame)) => frame,
                };
                if !allow_data && frame.ty == FrameType::Data as u8 {
                    anyhow::bail!("data frames are not allowed on the QUIC control stream");
                }
                match mux.dispatch(frame).await? {
                    Demux::Handled => {}
                    Demux::Control(frame) => match FrameType::from_u8(frame.ty) {
                        Some(FrameType::Heartbeat) => {
                            let beat = Heartbeat::decode(&frame.payload)?;
                            mux.send(HeartbeatAck { echo_monotonic_ms: beat.monotonic_ms }.to_frame()).await?;
                        }
                        Some(FrameType::HeartbeatAck) => {}
                        Some(FrameType::RegisterOk) => {
                            let ok = RegisterOk::decode(&frame.payload)?;
                            let _ = ctrl.send(CtrlMsg::RegisterOk(ok));
                        }
                        Some(FrameType::RegisterFail) => {
                            let fail = RegisterFail::decode(&frame.payload)?;
                            let _ = ctrl.send(CtrlMsg::RegisterFail(fail));
                        }
                        Some(FrameType::ReadyAck) => {
                            let _ = ctrl.send(CtrlMsg::ReadyAck);
                        }
                        Some(FrameType::UnregisterOk) => {
                            let body = UnregisterOk::decode(&frame.payload)?;
                            let _ = ctrl.send(CtrlMsg::UnregisterOk(body));
                        }
                        Some(FrameType::Unregister) => {
                            let body = Unregister::decode(&frame.payload)?;
                            tunnels.lock().expect("tunnels").remove_id(body.tunnel_id);
                            tracing::info!(tunnel = %body.name, id = body.tunnel_id, "server closed tunnel");
                        }
                        Some(FrameType::OpenStream) if allow_data => {
                            let open = OpenStream::decode(&frame.payload)?;
                            let mux = mux.clone();
                            let tunnels = tunnels.clone();
                            tokio::spawn(async move {
                                handle_mux_open(open, mux, tunnels).await;
                            });
                        }
                        Some(FrameType::Error) => {
                            let body = ErrorBody::decode(&frame.payload)?;
                            let message = format!("server error {}: {}", body.code, body.message);
                            let _ = ctrl.send(CtrlMsg::Fatal(message.clone()));
                            anyhow::bail!(message);
                        }
                        Some(other) => anyhow::bail!("unexpected control frame {other:?}"),
                        None => anyhow::bail!("unknown frame type {}", frame.ty),
                    },
                }
            }
        }
    }
}

async fn handle_mux_open(open: OpenStream, mux: MuxHandle, tunnels: Arc<Mutex<TunnelTable>>) {
    let local = tunnels.lock().expect("tunnels").local(open.tunnel_id);
    let Some(local) = local else {
        tracing::warn!(
            stream = open.stream_id,
            tunnel = open.tunnel_id,
            "open for unknown tunnel"
        );
        let _ = mux
            .send(
                Close {
                    stream_id: open.stream_id,
                    reason: close_reason::DIAL_FAILED,
                }
                .to_frame(),
            )
            .await;
        return;
    };
    let events = mux.register_route(open.stream_id);
    match TcpStream::connect(&local).await {
        Ok(sock) => {
            if mux
                .send(
                    StreamReady {
                        stream_id: open.stream_id,
                    }
                    .to_frame(),
                )
                .await
                .is_err()
            {
                mux.unregister(open.stream_id);
                return;
            }
            if let Err(err) = pharos_proto::bridge_mux(
                sock,
                open.stream_id,
                events,
                mux.clone(),
                &[],
                discard_traffic(),
                &NoPace,
            )
            .await
            {
                tracing::debug!(stream = open.stream_id, error = %err, "local bridge ended");
            }
            mux.unregister(open.stream_id);
        }
        Err(err) => {
            mux.unregister(open.stream_id);
            tracing::warn!(%local, error = %err, "dial failed");
            let _ = mux
                .send(
                    Close {
                        stream_id: open.stream_id,
                        reason: close_reason::DIAL_FAILED,
                    }
                    .to_frame(),
                )
                .await;
        }
    }
}

async fn accept_quic(
    conn: quinn::Connection,
    tunnels: Arc<Mutex<TunnelTable>>,
    shutdown: Shutdown,
) {
    loop {
        tokio::select! {
            _ = shutdown.draining() => break,
            incoming = conn.accept_bi() => {
                match incoming {
                    Ok((send, recv)) => {
                        let tunnels = tunnels.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_quic_stream(send, recv, tunnels).await {
                                tracing::debug!(error = %err, "quic data stream ended");
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

async fn handle_quic_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    tunnels: Arc<Mutex<TunnelTable>>,
) -> anyhow::Result<()> {
    let frame = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut recv))
        .await
        .map_err(|_| anyhow::anyhow!("timed out reading OpenStream"))??;
    if frame.ty != FrameType::OpenStream as u8 {
        anyhow::bail!("expected OpenStream");
    }
    let open = OpenStream::decode(&frame.payload)?;
    let local = tunnels.lock().expect("tunnels").local(open.tunnel_id);
    let Some(local) = local else {
        let _ = send.reset(quinn::VarInt::from_u32(1));
        anyhow::bail!("unknown tunnel {}", open.tunnel_id);
    };
    let tcp = TcpStream::connect(&local).await.map_err(|err| {
        let _ = send.reset(quinn::VarInt::from_u32(close_reason::DIAL_FAILED as u32));
        anyhow::anyhow!("dial {local}: {err}")
    })?;
    write_frame(
        &mut send,
        &StreamReady {
            stream_id: open.stream_id,
        }
        .to_frame(),
    )
    .await?;
    let remote = BiStream {
        reader: recv,
        writer: send,
    };
    pharos_proto::bridge_raw(tcp, remote, &[], discard_traffic(), &NoPace).await?;
    Ok(())
}

fn discard_traffic() -> Traffic<'static> {
    use std::sync::atomic::AtomicU64;
    static FROM_TCP: AtomicU64 = AtomicU64::new(0);
    static TO_TCP: AtomicU64 = AtomicU64::new(0);
    Traffic {
        from_tcp: &FROM_TCP,
        to_tcp: &TO_TCP,
    }
}

fn jitter(base: Duration) -> Duration {
    let millis = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::from(duration.subsec_nanos()))
        .unwrap_or(0);
    let extra = nanos % (millis / 3 + 1);
    base + Duration::from_millis(extra)
}
