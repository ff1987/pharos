use pharos_proto::{
    code, empty_frame, server_authenticate, ErrorBody, Frame, FrameType, Heartbeat, HeartbeatAck,
    MuxHandle, ProtoError, RegisterFail, RegisterOk, RegisterTunnel, ServerHandshake, TunnelKind,
    Unregister, UnregisterOk,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::Instrument;

use crate::state::{
    bridge_public, AppState, DataPlane, HttpPending, HttpRoute, Pending, SessionGuard, Shutdown,
    TcpPending, TrackedTunnel,
};

pub struct SessionCtx {
    pub peer: SocketAddr,
    pub session_id: u64,
    pub app: Arc<AppState>,
    pub mux: MuxHandle,
    pub plane: DataPlane,
    pub ready_tx: watch::Sender<bool>,
    pub ready_rx: watch::Receiver<bool>,
    pub guard: SessionGuard,
    pub pending: Mutex<Pending>,
    pub next_tunnel: AtomicU32,
    pub tunnel_count: AtomicU32,
    pub allow_data: bool,
}

pub async fn authenticate_and_serve<R, W>(
    mut reader: R,
    mut writer: W,
    peer: SocketAddr,
    app: Arc<AppState>,
    plane_of: impl FnOnce(MuxHandle) -> DataPlane,
    allow_data: bool,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let interval_ms = heartbeat_ms(&app);
    let token = app.token.read().expect("token").clone();
    let check_token = app.auth_mode.requires_token();
    let handshake =
        match server_authenticate(&mut reader, &mut writer, &token, check_token, interval_ms).await
        {
            Ok(handshake) => handshake,
            Err(ProtoError::AuthFailed(_)) => {
                app.metrics.auth_fail.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%peer, "authentication rejected");
                anyhow::bail!("authentication failed");
            }
            Err(err) => {
                tracing::debug!(%peer, error = %err, "handshake failed");
                return Err(err.into());
            }
        };
    app.metrics.auth_ok.fetch_add(1, Ordering::Relaxed);
    tracing::info!(
        %peer,
        session = handshake.session_id,
        client = %handshake.peer_name,
        "authenticated"
    );
    let span = tracing::info_span!("session", %peer, session = handshake.session_id);
    serve_authenticated(reader, writer, peer, app, plane_of, allow_data, handshake)
        .instrument(span)
        .await
}

pub async fn serve_authenticated<R, W>(
    reader: R,
    writer: W,
    peer: SocketAddr,
    app: Arc<AppState>,
    plane_of: impl FnOnce(MuxHandle) -> DataPlane,
    allow_data: bool,
    handshake: ServerHandshake,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(256);
    let mux = MuxHandle::new(tx);
    let writer_task = tokio::spawn(pharos_proto::write_loop(writer, rx));
    let (ready_tx, ready_rx) = watch::channel(false);
    let plane = plane_of(mux.clone());
    let ctx = Arc::new(SessionCtx {
        peer,
        session_id: handshake.session_id,
        app: app.clone(),
        mux: mux.clone(),
        plane,
        ready_tx,
        ready_rx,
        guard: SessionGuard::new(app.http_routes.clone(), app.metrics.clone()),
        pending: Mutex::new(Pending {
            tcp: Vec::new(),
            http: Vec::new(),
        }),
        next_tunnel: AtomicU32::new(1),
        tunnel_count: AtomicU32::new(0),
        allow_data,
    });
    let (acl_tx, mut acl_rx) = tokio::sync::mpsc::unbounded_channel();
    app.acl_watchers
        .lock()
        .expect("acl watchers")
        .push(acl_tx.clone());
    let acl_ctx = ctx.clone();
    let acl_shutdown = app.shutdown.clone();
    let acl_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = acl_shutdown.cancelled() => break,
                incoming = acl_rx.recv() => {
                    let Some(acl) = incoming else { break };
                    close_forbidden(&acl_ctx, &acl).await;
                }
            }
        }
    });
    let heartbeat = tokio::spawn(heartbeat_loop(mux, app.clone(), app.shutdown.clone()));
    let read = server_read_loop(reader, ctx.clone()).await;
    heartbeat.abort();
    {
        let mut watchers = app.acl_watchers.lock().expect("acl watchers");
        watchers.retain(|watcher| !watcher.same_channel(&acl_tx));
    }
    drop(acl_tx);
    acl_task.abort();
    drop(ctx);
    writer_task.abort();
    read
}

async fn close_forbidden(ctx: &SessionCtx, acl: &pharos_proto::AclConfig) {
    let denied = ctx.guard.denied_ids(acl);
    for id in denied {
        let Some(name) = ctx.guard.release(id) else {
            continue;
        };
        if ctx.tunnel_count.load(Ordering::Relaxed) > 0 {
            ctx.tunnel_count.fetch_sub(1, Ordering::Relaxed);
        }
        tracing::info!(peer = %ctx.peer, tunnel = %name, tunnel_id = id, "closed tunnel removed from the ACL");
        if let Ok(frame) = (Unregister {
            name,
            tunnel_id: id,
        })
        .to_frame()
        {
            if ctx.mux.send(frame).await.is_err() {
                break;
            }
        }
    }
}

async fn heartbeat_loop(mux: MuxHandle, app: Arc<AppState>, shutdown: Shutdown) {
    loop {
        let interval = app.heartbeat.read().expect("heartbeat").interval();
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(interval) => {
                let frame = Heartbeat {
                    monotonic_ms: pharos_proto::monotonic_ms(),
                }
                .to_frame();
                if mux.send(frame).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn server_read_loop<R>(mut reader: R, ctx: Arc<SessionCtx>) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let timeout = ctx.app.heartbeat.read().expect("heartbeat").timeout();
        tokio::select! {
            _ = ctx.app.shutdown.cancelled() => break,
            read = tokio::time::timeout(timeout, pharos_proto::read_frame(&mut reader)) => {
                match read {
                    Err(_) => {
                        tracing::warn!(
                            peer = %ctx.peer,
                            session = ctx.session_id,
                            "heartbeat timeout"
                        );
                        break;
                    }
                    Ok(Err(err)) => {
                        tracing::info!(
                            peer = %ctx.peer,
                            session = ctx.session_id,
                            error = %err,
                            "control connection closed"
                        );
                        break;
                    }
                    Ok(Ok(frame)) => {
                        if let Err(err) = handle_frame(&ctx, frame).await {
                            tracing::warn!(
                                peer = %ctx.peer,
                                session = ctx.session_id,
                                error = %err,
                                "closing session"
                            );
                            if let Ok(frame) = (ErrorBody {
                                code: code::BAD_FRAME,
                                message: err.to_string(),
                            })
                            .to_frame()
                            {
                                let _ = ctx.mux.send(frame).await;
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_frame(ctx: &SessionCtx, frame: Frame) -> anyhow::Result<()> {
    if !ctx.allow_data && frame.ty == FrameType::Data as u8 {
        anyhow::bail!("data frames are not allowed on the QUIC control stream");
    }
    match ctx.mux.dispatch(frame).await? {
        pharos_proto::Demux::Handled => Ok(()),
        pharos_proto::Demux::Control(frame) => match FrameType::from_u8(frame.ty) {
            Some(FrameType::Heartbeat) => {
                let beat = Heartbeat::decode(&frame.payload)?;
                ctx.mux
                    .send(
                        HeartbeatAck {
                            echo_monotonic_ms: beat.monotonic_ms,
                        }
                        .to_frame(),
                    )
                    .await?;
                Ok(())
            }
            Some(FrameType::HeartbeatAck) => Ok(()),
            Some(FrameType::RegisterTunnel) => {
                let request = RegisterTunnel::decode(&frame.payload)?;
                let response = register(ctx, request).await;
                ctx.mux.send(response).await?;
                Ok(())
            }
            Some(FrameType::Unregister) => {
                let request = Unregister::decode(&frame.payload)?;
                let name = ctx
                    .guard
                    .release(request.tunnel_id)
                    .unwrap_or_else(|| request.name.clone());
                if ctx.tunnel_count.load(Ordering::Relaxed) > 0 {
                    ctx.tunnel_count.fetch_sub(1, Ordering::Relaxed);
                }
                tracing::info!(peer = %ctx.peer, tunnel = %name, id = request.tunnel_id, "tunnel unregistered");
                ctx.mux
                    .send(
                        UnregisterOk {
                            name,
                            tunnel_id: request.tunnel_id,
                        }
                        .to_frame()?,
                    )
                    .await?;
                Ok(())
            }
            Some(FrameType::SessionReady) => {
                publish(ctx).await;
                let _ = ctx.ready_tx.send(true);
                ctx.mux.send(empty_frame(FrameType::ReadyAck)).await?;
                tracing::info!(peer = %ctx.peer, session = ctx.session_id, "session ready");
                Ok(())
            }
            Some(FrameType::Error) => {
                let body = ErrorBody::decode(&frame.payload)?;
                anyhow::bail!("client error {}: {}", body.code, body.message);
            }
            Some(other) => anyhow::bail!("unexpected control frame {other:?}"),
            None => anyhow::bail!("unknown frame type {}", frame.ty),
        },
    }
}

async fn register(ctx: &SessionCtx, request: RegisterTunnel) -> Frame {
    let name = request.name.clone();
    let fail = |code_value: u16, reason: String| {
        RegisterFail {
            name: name.clone(),
            code: code_value,
            reason,
        }
        .to_frame()
        .unwrap_or_else(|_| empty_frame(FrameType::Error))
    };
    if ctx.app.shutdown.is_draining() {
        tracing::info!(
            peer = %ctx.peer,
            tunnel = %request.name,
            phase = "draining",
            "rejected tunnel registration"
        );
        return fail(code::NOT_AVAILABLE, "server is shutting down".into());
    }
    if request.name.is_empty() || request.name.len() > 64 {
        return fail(code::BAD_REQUEST, "invalid tunnel name".into());
    }
    let limits = ctx.app.limits.read().expect("limits").clone();
    if limits.max_tunnels > 0 && ctx.tunnel_count.load(Ordering::Relaxed) >= limits.max_tunnels {
        ctx.app
            .metrics
            .limits_rejected
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            peer = %ctx.peer,
            tunnel = %request.name,
            limit = limits.max_tunnels,
            scope = "per-client",
            "rejected tunnel registration"
        );
        return fail(
            code::LIMIT,
            format!("per-client tunnel limit reached ({})", limits.max_tunnels),
        );
    }
    if limits.max_tunnels_global > 0
        && ctx.app.metrics.tunnels_active.load(Ordering::Relaxed)
            >= u64::from(limits.max_tunnels_global)
    {
        ctx.app
            .metrics
            .limits_rejected
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            peer = %ctx.peer,
            tunnel = %request.name,
            limit = limits.max_tunnels_global,
            scope = "global",
            "rejected tunnel registration"
        );
        return fail(
            code::LIMIT,
            format!(
                "global tunnel limit reached ({})",
                limits.max_tunnels_global
            ),
        );
    }
    let acl = ctx.app.acl.read().expect("acl").clone();
    let tunnel_id = ctx.next_tunnel.fetch_add(1, Ordering::Relaxed);
    match TunnelKind::from_u8(request.kind) {
        Some(TunnelKind::Tcp) => {
            if !acl.permits_port(request.remote_port) {
                ctx.app.metrics.acl_deny.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    peer = %ctx.peer,
                    tunnel = %request.name,
                    port = request.remote_port,
                    "acl denied tcp port"
                );
                return fail(
                    code::ACL_DENIED,
                    format!("port {} is not in the ACL", request.remote_port),
                );
            }
            let addr = SocketAddr::new(ctx.app.tcp_bind_ip, request.remote_port);
            let listener = match crate::bind_listener(addr) {
                Ok(listener) => listener,
                Err(err) => {
                    return fail(code::BIND_FAILED, format!("bind {addr}: {err}"));
                }
            };
            let bound = match listener.local_addr() {
                Ok(bound) => bound,
                Err(err) => return fail(code::BIND_FAILED, err.to_string()),
            };
            let bound_port = bound.port();
            if *ctx.ready_rx.borrow() {
                spawn_tcp(ctx, listener, tunnel_id, request.name.clone(), bound_port);
            } else {
                ctx.pending.lock().expect("pending").tcp.push(TcpPending {
                    listener,
                    tunnel_id,
                    name: request.name.clone(),
                    remote_port: bound_port,
                });
            }
            ctx.tunnel_count.fetch_add(1, Ordering::Relaxed);
            ctx.app.metrics.tunnels.fetch_add(1, Ordering::Relaxed);
            tracing::info!(peer = %ctx.peer, tunnel = %request.name, %bound, "tcp tunnel registered");
            RegisterOk {
                name: request.name,
                tunnel_id,
                public_endpoint: bound.to_string(),
            }
            .to_frame()
            .unwrap_or_else(|_| empty_frame(FrameType::Error))
        }
        Some(TunnelKind::Http) => {
            if ctx.app.http_advertise.is_none() {
                return fail(
                    code::NOT_AVAILABLE,
                    "this server is not listening for HTTP".into(),
                );
            }
            let host = request.hostname.trim().to_ascii_lowercase();
            if host.is_empty() || host.len() > 253 || !acl.permits_hostname(&host) {
                ctx.app.metrics.acl_deny.fetch_add(1, Ordering::Relaxed);
                tracing::info!(peer = %ctx.peer, tunnel = %request.name, %host, "acl denied hostname");
                return fail(
                    code::ACL_DENIED,
                    format!("hostname {host} is not in the ACL"),
                );
            }
            if hostname_taken(ctx, &host) {
                return fail(
                    code::BIND_FAILED,
                    format!("hostname {host} is already registered"),
                );
            }
            if *ctx.ready_rx.borrow() {
                insert_http(ctx, &host, tunnel_id, request.name.clone());
            } else {
                ctx.pending.lock().expect("pending").http.push(HttpPending {
                    host: host.clone(),
                    tunnel_id,
                    name: request.name.clone(),
                });
            }
            ctx.tunnel_count.fetch_add(1, Ordering::Relaxed);
            ctx.app.metrics.tunnels.fetch_add(1, Ordering::Relaxed);
            let via = ctx
                .app
                .http_advertise
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "http".into());
            let endpoint = format!("{host} via {via}");
            tracing::info!(peer = %ctx.peer, tunnel = %request.name, %endpoint, "http tunnel registered");
            RegisterOk {
                name: request.name,
                tunnel_id,
                public_endpoint: endpoint,
            }
            .to_frame()
            .unwrap_or_else(|_| empty_frame(FrameType::Error))
        }
        None => fail(code::BAD_REQUEST, "unknown tunnel type".into()),
    }
}

fn hostname_taken(ctx: &SessionCtx, host: &str) -> bool {
    if ctx
        .app
        .http_routes
        .read()
        .expect("routes")
        .contains_key(host)
    {
        return true;
    }
    ctx.pending
        .lock()
        .expect("pending")
        .http
        .iter()
        .any(|pending| pending.host == host)
}

fn insert_http(ctx: &SessionCtx, host: &str, tunnel_id: u32, name: String) {
    ctx.app.http_routes.write().expect("routes").insert(
        host.to_string(),
        HttpRoute {
            plane: ctx.plane.clone(),
            tunnel_id,
        },
    );
    ctx.guard.track(
        tunnel_id,
        TrackedTunnel {
            name,
            remote_port: 0,
            hostname: host.to_string(),
            task: None,
            host: Some(host.to_string()),
        },
    );
}

fn spawn_tcp(
    ctx: &SessionCtx,
    listener: TcpListener,
    tunnel_id: u32,
    tunnel: String,
    remote_port: u16,
) {
    let plane = ctx.plane.clone();
    let mut ready = ctx.ready_rx.clone();
    let shutdown = ctx.app.shutdown.clone();
    let tunnel_for_span = tunnel.clone();
    let task = tokio::spawn(async move {
        if !*ready.borrow() {
            let _ = ready.wait_for(|value| *value).await;
        }
        loop {
            tokio::select! {
                _ = shutdown.draining() => break,
                accepted = listener.accept() => {
                    let Ok((sock, peer)) = accepted else { break };
                    let plane = plane.clone();
                    let tunnel = tunnel_for_span.clone();
                    let span = tracing::info_span!("tunnel_stream", %peer, %tunnel);
                    tokio::spawn(
                        async move {
                            match plane.open(tunnel_id).await {
                                Ok(opened) => {
                                    if let Err(err) = bridge_public(sock, opened, &[]).await {
                                        tracing::debug!(error = %err, "tcp bridge ended");
                                    }
                                }
                                Err(err) => {
                                    tracing::debug!(error = %err, "tcp stream refused");
                                }
                            }
                        }
                        .instrument(span),
                    );
                }
            }
        }
    });
    ctx.guard.track(
        tunnel_id,
        TrackedTunnel {
            name: tunnel,
            remote_port,
            hostname: String::new(),
            task: Some(task),
            host: None,
        },
    );
}

async fn publish(ctx: &SessionCtx) {
    let pending = {
        let mut pending = ctx.pending.lock().expect("pending");
        Pending {
            tcp: std::mem::take(&mut pending.tcp),
            http: std::mem::take(&mut pending.http),
        }
    };
    for tcp in pending.tcp {
        spawn_tcp(ctx, tcp.listener, tcp.tunnel_id, tcp.name, tcp.remote_port);
    }
    for http in pending.http {
        if ctx
            .app
            .http_routes
            .read()
            .expect("routes")
            .contains_key(&http.host)
        {
            tracing::warn!(host = %http.host, "dropping http tunnel; hostname taken");
            continue;
        }
        insert_http(ctx, &http.host, http.tunnel_id, http.name);
    }
}

pub fn heartbeat_ms(app: &AppState) -> u32 {
    let secs = app.heartbeat.read().expect("heartbeat").interval_secs;
    u32::try_from(secs.saturating_mul(1000)).unwrap_or(u32::MAX)
}
