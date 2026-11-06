//! Pharos client. Dials a server over QUIC (or TLS), proves a PSK, and bridges
//! local TCP services into the tunnels the server publishes.

#![forbid(unsafe_code)]

mod session;

use std::time::Duration;

use pharos_proto::{LogConfig, LogFormat};
use session::client_loop;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

pub use pharos_proto::ClientConfig;
pub use session::ClientEvent;
use session::Shutdown;

pub struct ClientHandle {
    pub events: mpsc::UnboundedReceiver<ClientEvent>,
    shutdown: Shutdown,
    join: Option<JoinHandle<()>>,
}

impl Drop for ClientHandle {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

impl ClientHandle {
    pub async fn shutdown(mut self) {
        self.shutdown.cancel();
        if let Some(join) = self.join.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), join).await;
        }
    }
}

pub fn load_config(path: &std::path::Path) -> anyhow::Result<ClientConfig> {
    Ok(ClientConfig::load_path(path)?)
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

pub async fn spawn(config: ClientConfig) -> anyhow::Result<ClientHandle> {
    config.validate()?;
    if config.tls_insecure {
        tracing::warn!("tls_insecure is enabled; the server certificate is not verified");
    }
    tracing::info!(auth = %config.auth.mode, "authentication mode");
    if config.heartbeat.timeout_secs < config.heartbeat.interval_secs {
        tracing::warn!(
            "heartbeat timeout is shorter than the interval; idle sessions will be dropped"
        );
    }
    let shutdown = Shutdown::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let task_shutdown = shutdown.clone();
    let join = tokio::spawn(async move {
        client_loop(config, tx, task_shutdown).await;
    });
    Ok(ClientHandle {
        events: rx,
        shutdown,
        join: Some(join),
    })
}

pub async fn run(config: ClientConfig) -> anyhow::Result<()> {
    let drain = Duration::from_secs(config.shutdown.drain_secs);
    let mut handle = spawn(config).await?;
    let join = handle
        .join
        .take()
        .ok_or_else(|| anyhow::anyhow!("client task missing"))?;
    tokio::pin!(join);
    tokio::select! {
        _ = wait_for_exit_signal() => {
            tracing::info!(
                phase = "draining",
                drain_secs = drain.as_secs(),
                "shutdown: finishing open streams and not reconnecting"
            );
            handle.shutdown.begin_drain();
            if !drain.is_zero() {
                tokio::select! {
                    _ = tokio::time::sleep(drain) => {}
                    _ = &mut join => {
                        tracing::info!(phase = "stopped", "shutdown: client task ended during drain");
                        return Ok(());
                    }
                }
            }
            tracing::info!(phase = "stopped", "shutdown: drain finished, forcing exit");
            handle.shutdown.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut join).await;
        }
        _ = &mut join => {}
    }
    Ok(())
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
