use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use pharos_proto::{server_config, HeartbeatConfig, Identity};

use crate::session::authenticate_and_serve;
use crate::state::{AppState, DataPlane, Shutdown};

pub fn server_quic_config(
    identity: &Identity,
    client_ca_pem: Option<&str>,
    heartbeat: &HeartbeatConfig,
) -> anyhow::Result<quinn::ServerConfig> {
    let crypto = server_config(identity, client_ca_pem)?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .map_err(|err| anyhow::anyhow!("quic crypto: {err}"))?,
    ));
    let transport = Arc::get_mut(&mut server.transport).expect("fresh transport config");
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    // The application limiter is authoritative so a rejection can be logged.
    // QUIC only needs a ceiling above any configured cap.
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(65_535));
    let idle = Duration::from_secs(heartbeat.timeout_secs.saturating_add(30));
    if let Ok(idle) = quinn::IdleTimeout::try_from(idle) {
        transport.max_idle_timeout(Some(idle));
    }
    transport.keep_alive_interval(Some(heartbeat.interval()));
    Ok(server)
}

pub async fn quic_loop(endpoint: quinn::Endpoint, app: Arc<AppState>, shutdown: Shutdown) {
    loop {
        tokio::select! {
            _ = shutdown.draining() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let app = app.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            if let Err(err) = quic_session(conn, app).await {
                                tracing::debug!(error = %err, "quic session ended");
                            }
                        }
                        Err(err) => {
                            app.metrics.auth_fail.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!(error = %err, "quic handshake failed");
                        }
                    }
                });
            }
        }
    }
}

async fn quic_session(conn: quinn::Connection, app: Arc<AppState>) -> anyhow::Result<()> {
    let peer = conn.remote_address();
    let (send, recv) = tokio::time::timeout(Duration::from_secs(10), conn.accept_bi())
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for the control stream"))??;
    let metrics = app.metrics.clone();
    let limits = app.limits.clone();
    let connection = conn.clone();
    let result = authenticate_and_serve(
        recv,
        send,
        peer,
        app,
        move |mux| {
            let _ = mux;
            DataPlane::quic(connection, limits, metrics)
        },
        false,
    )
    .await;
    conn.close(quinn::VarInt::from_u32(0), b"session ended");
    result
}
