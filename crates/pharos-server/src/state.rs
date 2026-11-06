use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::pace::ClientPace;
use pharos_proto::{
    close_reason, read_frame, wait_ready, write_frame, AclConfig, AuthMode, BiStream, Close,
    FrameType, HeartbeatConfig, LimitsConfig, MuxHandle, OpenStream, StreamReady,
};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownPhase {
    Running,
    Draining,
    Stopped,
}

/// Cooperative shutdown shared by listeners and sessions.
///
/// Draining stops new work. Stopped ends the process and aborts what is left.
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

#[derive(Default)]
pub struct Metrics {
    pub auth_ok: AtomicU64,
    pub auth_fail: AtomicU64,
    /// Tunnels accepted since process start.
    pub tunnels: AtomicU64,
    /// Tunnels registered by sessions that are still connected.
    pub tunnels_active: AtomicU64,
    pub acl_deny: AtomicU64,
    pub streams_opened: AtomicU64,
    pub streams_active: AtomicU64,
    /// Register or OpenStream rejected because a limit was already reached.
    pub limits_rejected: AtomicU64,
    /// Times a byte cap delayed forwarding instead of closing the tunnel.
    pub throttle_events: AtomicU64,
    /// Bytes read from public TCP connections.
    pub bytes_in: AtomicU64,
    /// Bytes written to public TCP connections.
    pub bytes_out: AtomicU64,
}

impl Metrics {
    pub fn render(&self) -> String {
        format!(
            "\
# HELP pharos_auth_success_total Sessions that presented a valid token
# TYPE pharos_auth_success_total counter
pharos_auth_success_total {auth_ok}
# HELP pharos_auth_failure_total Sessions rejected for a bad token
# TYPE pharos_auth_failure_total counter
pharos_auth_failure_total {auth_fail}
# HELP pharos_tunnels_active Tunnels registered by connected clients
# TYPE pharos_tunnels_active gauge
pharos_tunnels_active {tunnels_active}
# HELP pharos_tunnels_registered_total Tunnels accepted after ACL checks
# TYPE pharos_tunnels_registered_total counter
pharos_tunnels_registered_total {tunnels}
# HELP pharos_acl_denied_total Tunnel registrations rejected by ACL
# TYPE pharos_acl_denied_total counter
pharos_acl_denied_total {acl}
# HELP pharos_streams_opened_total Data streams opened toward clients
# TYPE pharos_streams_opened_total counter
pharos_streams_opened_total {opened}
# HELP pharos_streams_active Data streams currently bridged
# TYPE pharos_streams_active gauge
pharos_streams_active {active}
# HELP pharos_bytes_in_total Bytes read from public connections
# TYPE pharos_bytes_in_total counter
pharos_bytes_in_total {bytes_in}
# HELP pharos_bytes_out_total Bytes written to public connections
# TYPE pharos_bytes_out_total counter
pharos_bytes_out_total {bytes_out}
# HELP pharos_limits_rejected_total Tunnel registrations or streams rejected by a limit
# TYPE pharos_limits_rejected_total counter
pharos_limits_rejected_total {limits_rejected}
# HELP pharos_throttle_events_total Times traffic waited for a byte-rate token
# TYPE pharos_throttle_events_total counter
pharos_throttle_events_total {throttle_events}
",
            auth_ok = self.auth_ok.load(Ordering::Relaxed),
            auth_fail = self.auth_fail.load(Ordering::Relaxed),
            tunnels_active = self.tunnels_active.load(Ordering::Relaxed),
            tunnels = self.tunnels.load(Ordering::Relaxed),
            acl = self.acl_deny.load(Ordering::Relaxed),
            opened = self.streams_opened.load(Ordering::Relaxed),
            active = self.streams_active.load(Ordering::Relaxed),
            bytes_in = self.bytes_in.load(Ordering::Relaxed),
            bytes_out = self.bytes_out.load(Ordering::Relaxed),
            limits_rejected = self.limits_rejected.load(Ordering::Relaxed),
            throttle_events = self.throttle_events.load(Ordering::Relaxed),
        )
    }
}

pub struct AppState {
    pub auth_mode: AuthMode,
    pub token: RwLock<String>,
    pub acl: RwLock<AclConfig>,
    pub heartbeat: RwLock<HeartbeatConfig>,
    pub limits: Arc<RwLock<LimitsConfig>>,
    pub tcp_bind_ip: IpAddr,
    pub http_routes: Arc<RwLock<HashMap<String, HttpRoute>>>,
    pub http_advertise: Option<SocketAddr>,
    pub https_advertise: Option<SocketAddr>,
    pub metrics: Arc<Metrics>,
    pub shutdown: Shutdown,
    /// Sessions that should re-check the ACL after a reload.
    pub acl_watchers: Mutex<Vec<mpsc::UnboundedSender<AclConfig>>>,
}

#[derive(Clone)]
pub struct HttpRoute {
    pub plane: DataPlane,
    pub tunnel_id: u32,
}

pub struct TrackedTunnel {
    pub name: String,
    pub remote_port: u16,
    pub hostname: String,
    pub task: Option<JoinHandle<()>>,
    pub host: Option<String>,
}

pub struct SessionGuard {
    tracked: Mutex<HashMap<u32, TrackedTunnel>>,
    routes: Arc<RwLock<HashMap<String, HttpRoute>>>,
    metrics: Arc<Metrics>,
    tunnels: AtomicU32,
}

impl SessionGuard {
    pub fn new(routes: Arc<RwLock<HashMap<String, HttpRoute>>>, metrics: Arc<Metrics>) -> Self {
        Self {
            tracked: Mutex::new(HashMap::new()),
            routes,
            metrics,
            tunnels: AtomicU32::new(0),
        }
    }

    pub fn track(&self, id: u32, tunnel: TrackedTunnel) {
        self.tunnels.fetch_add(1, Ordering::Relaxed);
        self.metrics.tunnels_active.fetch_add(1, Ordering::Relaxed);
        self.tracked.lock().expect("tracked").insert(id, tunnel);
    }

    /// Drop one tunnel. Returns its name when it was still tracked.
    pub fn release(&self, id: u32) -> Option<String> {
        let tunnel = self.tracked.lock().expect("tracked").remove(&id)?;
        if let Some(task) = tunnel.task {
            task.abort();
        }
        if let Some(host) = &tunnel.host {
            self.routes.write().expect("routes").remove(host);
        }
        self.tunnels.fetch_sub(1, Ordering::Relaxed);
        self.metrics.tunnels_active.fetch_sub(1, Ordering::Relaxed);
        Some(tunnel.name)
    }

    pub fn denied_ids(&self, acl: &AclConfig) -> Vec<u32> {
        self.tracked
            .lock()
            .expect("tracked")
            .iter()
            .filter_map(|(id, tunnel)| {
                let allowed = if tunnel.host.is_some() {
                    acl.permits_hostname(&tunnel.hostname)
                } else {
                    acl.permits_port(tunnel.remote_port)
                };
                if allowed {
                    None
                } else {
                    Some(*id)
                }
            })
            .collect()
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let active = u64::from(self.tunnels.load(Ordering::Relaxed));
        self.metrics
            .tunnels_active
            .fetch_sub(active, Ordering::Relaxed);
        let mut tracked = self.tracked.lock().expect("tracked");
        for (_, tunnel) in tracked.drain() {
            if let Some(task) = tunnel.task {
                task.abort();
            }
            if let Some(host) = tunnel.host {
                self.routes.write().expect("routes").remove(&host);
            }
        }
    }
}

pub struct TcpPending {
    pub listener: TcpListener,
    pub tunnel_id: u32,
    pub name: String,
    pub remote_port: u16,
}

pub struct HttpPending {
    pub host: String,
    pub tunnel_id: u32,
    pub name: String,
}

pub struct Pending {
    pub tcp: Vec<TcpPending>,
    pub http: Vec<HttpPending>,
}

enum PlaneKind {
    Tls(MuxHandle),
    Quic(quinn::Connection),
}

struct PlaneInner {
    kind: PlaneKind,
    next_stream: AtomicU32,
    session_streams: AtomicU32,
    limits: Arc<RwLock<LimitsConfig>>,
    metrics: Arc<Metrics>,
    pace: Arc<ClientPace>,
}

/// Reserve one slot. `limit == 0` means unlimited. Returns false when the cap is already met.
fn try_admit(counter: &AtomicU64, limit: u32) -> bool {
    if limit == 0 {
        counter.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    let limit = u64::from(limit);
    loop {
        let current = counter.load(Ordering::Relaxed);
        if current >= limit {
            return false;
        }
        if counter
            .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

fn try_admit_session(counter: &AtomicU32, limit: u32) -> bool {
    if limit == 0 {
        counter.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    loop {
        let current = counter.load(Ordering::Relaxed);
        if current >= limit {
            return false;
        }
        if counter
            .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

/// Opens one public connection onto the client, either as TLS mux frames or a QUIC stream.
#[derive(Clone)]
pub struct DataPlane {
    inner: Arc<PlaneInner>,
}

pub enum Pipe {
    Mux {
        id: u32,
        events: tokio::sync::mpsc::Receiver<pharos_proto::StreamEvent>,
        mux: MuxHandle,
    },
    Quic {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
}

struct StreamPermit {
    inner: Arc<PlaneInner>,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        self.inner.session_streams.fetch_sub(1, Ordering::Relaxed);
        self.inner
            .metrics
            .streams_active
            .fetch_sub(1, Ordering::Relaxed);
    }
}

struct ReleaseOnDrop<'a> {
    inner: &'a PlaneInner,
    active: bool,
}

impl Drop for ReleaseOnDrop<'_> {
    fn drop(&mut self) {
        if self.active {
            self.inner.session_streams.fetch_sub(1, Ordering::Relaxed);
            self.inner
                .metrics
                .streams_active
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
}

pub struct Opened {
    pub pipe: Pipe,
    permit: StreamPermit,
}

impl DataPlane {
    pub fn tls(mux: MuxHandle, limits: Arc<RwLock<LimitsConfig>>, metrics: Arc<Metrics>) -> Self {
        Self::from_kind(PlaneKind::Tls(mux), limits, metrics)
    }

    pub fn quic(
        conn: quinn::Connection,
        limits: Arc<RwLock<LimitsConfig>>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self::from_kind(PlaneKind::Quic(conn), limits, metrics)
    }

    fn from_kind(
        kind: PlaneKind,
        limits: Arc<RwLock<LimitsConfig>>,
        metrics: Arc<Metrics>,
    ) -> Self {
        let pace = Arc::new(ClientPace::new(limits.clone(), metrics.clone()));
        Self {
            inner: Arc::new(PlaneInner {
                kind,
                next_stream: AtomicU32::new(1),
                session_streams: AtomicU32::new(0),
                limits,
                metrics,
                pace,
            }),
        }
    }

    pub async fn open(&self, tunnel_id: u32) -> anyhow::Result<Opened> {
        let limits = self.inner.limits.read().expect("limits").clone();
        if !try_admit_session(&self.inner.session_streams, limits.max_streams) {
            self.inner
                .metrics
                .limits_rejected
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                tunnel_id,
                limit = limits.max_streams,
                scope = "per-client",
                "rejected stream: per-client limit reached"
            );
            anyhow::bail!("per-client stream limit reached ({})", limits.max_streams);
        }
        if !try_admit(
            &self.inner.metrics.streams_active,
            limits.max_streams_global,
        ) {
            self.inner.session_streams.fetch_sub(1, Ordering::Relaxed);
            self.inner
                .metrics
                .limits_rejected
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                tunnel_id,
                limit = limits.max_streams_global,
                scope = "global",
                "rejected stream: global limit reached"
            );
            anyhow::bail!(
                "global stream limit reached ({})",
                limits.max_streams_global
            );
        }
        let mut reserved = ReleaseOnDrop {
            inner: &self.inner,
            active: true,
        };
        let stream_id = self.inner.next_stream.fetch_add(1, Ordering::Relaxed);
        let pipe = match &self.inner.kind {
            PlaneKind::Tls(mux) => {
                let (events, ready) = mux.open_wait(tunnel_id, stream_id).await?;
                if let Err(err) = wait_ready(ready, Duration::from_secs(10)).await {
                    mux.unregister(stream_id);
                    let _ = mux
                        .send(
                            Close {
                                stream_id,
                                reason: close_reason::TIMEOUT,
                            }
                            .to_frame(),
                        )
                        .await;
                    return Err(err.into());
                }
                Pipe::Mux {
                    id: stream_id,
                    events,
                    mux: mux.clone(),
                }
            }
            PlaneKind::Quic(conn) => {
                let (mut send, mut recv) = conn.open_bi().await?;
                write_frame(
                    &mut send,
                    &OpenStream {
                        stream_id,
                        tunnel_id,
                    }
                    .to_frame(),
                )
                .await?;
                let frame = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut recv))
                    .await
                    .map_err(|_| anyhow::anyhow!("stream open timed out"))??;
                if frame.ty != FrameType::StreamReady as u8 {
                    anyhow::bail!("expected StreamReady on the QUIC data stream");
                }
                let ready = StreamReady::decode(&frame.payload)?;
                if ready.stream_id != stream_id {
                    anyhow::bail!("stream id mismatch");
                }
                Pipe::Quic { send, recv }
            }
        };
        self.inner
            .metrics
            .streams_opened
            .fetch_add(1, Ordering::Relaxed);
        reserved.active = false;
        Ok(Opened {
            pipe,
            permit: StreamPermit {
                inner: self.inner.clone(),
            },
        })
    }
}

pub async fn bridge_public<S>(
    stream: S,
    opened: Opened,
    prefix: &[u8],
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Opened { pipe, permit } = opened;
    let pace = permit.inner.pace.clone();
    let traffic = pharos_proto::Traffic {
        from_tcp: &permit.inner.metrics.bytes_in,
        to_tcp: &permit.inner.metrics.bytes_out,
    };
    match pipe {
        Pipe::Mux { id, events, mux } => {
            pharos_proto::bridge_mux(stream, id, events, mux, prefix, traffic, pace.as_ref())
                .await?;
        }
        Pipe::Quic { send, recv } => {
            let remote = BiStream {
                reader: recv,
                writer: send,
            };
            pharos_proto::bridge_raw(stream, remote, prefix, traffic, pace.as_ref()).await?;
        }
    }
    Ok(())
}
