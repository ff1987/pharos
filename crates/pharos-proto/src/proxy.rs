use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::bistream::BiStream;
use crate::error::ProtoError;
use crate::frame::{close_reason, data_frame, Close, DATA_CHUNK};
use crate::mux::{MuxHandle, StreamEvent};

/// Optional byte pacing. The client passes [`NoPace`]. The server uses a token bucket.
pub trait BytePacer: Send + Sync {
    fn pace_from_tcp(&self, n: usize) -> impl std::future::Future<Output = ()> + Send;
    fn pace_to_tcp(&self, n: usize) -> impl std::future::Future<Output = ()> + Send;
}

/// Does not delay traffic.
pub struct NoPace;

impl BytePacer for NoPace {
    async fn pace_from_tcp(&self, _n: usize) {}
    async fn pace_to_tcp(&self, _n: usize) {}
}

/// Byte counters for one bridged TCP socket.
///
/// `from_tcp` is bytes read from that socket. `to_tcp` is bytes written to it.
/// On the server the socket is the public connection, so these are bytes in and out.
pub struct Traffic<'a> {
    pub from_tcp: &'a AtomicU64,
    pub to_tcp: &'a AtomicU64,
}

/// Copy bytes between a public (or local) TCP socket and a TLS-multiplexed stream.
///
/// `prefix` is written first. HTTP host routing uses it for the request head that
/// was already consumed to choose the tunnel.
pub async fn bridge_mux(
    tcp: TcpStream,
    stream_id: u32,
    mut events: mpsc::Receiver<StreamEvent>,
    mux: MuxHandle,
    prefix: &[u8],
    traffic: Traffic<'_>,
    pace: &impl BytePacer,
) -> Result<(), ProtoError> {
    let _ = tcp.set_nodelay(true);
    traffic
        .from_tcp
        .fetch_add(prefix.len() as u64, Ordering::Relaxed);
    if !prefix.is_empty() {
        pace.pace_from_tcp(prefix.len()).await;
    }
    for chunk in prefix.chunks(DATA_CHUNK) {
        mux.send(data_frame(stream_id, Bytes::copy_from_slice(chunk)))
            .await?;
    }
    let (mut reader, mut writer) = tcp.into_split();
    let from_tcp = traffic.from_tcp;
    let to_tcp = traffic.to_tcp;
    let outbound = async {
        let mut buf = vec![0u8; DATA_CHUNK];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                let _ = mux
                    .send(
                        Close {
                            stream_id,
                            reason: close_reason::NORMAL,
                        }
                        .to_frame(),
                    )
                    .await;
                break;
            }
            from_tcp.fetch_add(n as u64, Ordering::Relaxed);
            pace.pace_from_tcp(n).await;
            mux.send(data_frame(stream_id, Bytes::copy_from_slice(&buf[..n])))
                .await?;
        }
        Ok::<(), ProtoError>(())
    };
    let inbound = async {
        while let Some(event) = events.recv().await {
            match event {
                StreamEvent::Data(bytes) => {
                    pace.pace_to_tcp(bytes.len()).await;
                    writer.write_all(&bytes).await?;
                    to_tcp.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                }
                StreamEvent::Eof => {
                    let _ = writer.shutdown().await;
                    break;
                }
            }
        }
        Ok::<(), ProtoError>(())
    };
    let (out_res, in_res) = tokio::join!(outbound, inbound);
    out_res?;
    in_res?;
    Ok(())
}

/// Copy bytes between a TCP socket and a dedicated QUIC (or other) byte stream.
pub async fn bridge_raw<R, W>(
    tcp: TcpStream,
    remote: BiStream<R, W>,
    prefix: &[u8],
    traffic: Traffic<'_>,
    pace: &impl BytePacer,
) -> Result<(), ProtoError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let _ = tcp.set_nodelay(true);
    traffic
        .from_tcp
        .fetch_add(prefix.len() as u64, Ordering::Relaxed);
    let (mut reader, mut writer) = tcp.into_split();
    let (mut remote_reader, mut remote_writer) = tokio::io::split(remote);
    if !prefix.is_empty() {
        pace.pace_from_tcp(prefix.len()).await;
        remote_writer.write_all(prefix).await?;
    }
    let from_tcp = traffic.from_tcp;
    let to_tcp = traffic.to_tcp;
    let outbound = async {
        let mut buf = vec![0u8; DATA_CHUNK];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                let _ = remote_writer.shutdown().await;
                break;
            }
            from_tcp.fetch_add(n as u64, Ordering::Relaxed);
            pace.pace_from_tcp(n).await;
            remote_writer.write_all(&buf[..n]).await?;
        }
        Ok::<(), ProtoError>(())
    };
    let inbound = async {
        let mut buf = vec![0u8; DATA_CHUNK];
        loop {
            let n = remote_reader.read(&mut buf).await?;
            if n == 0 {
                let _ = writer.shutdown().await;
                break;
            }
            pace.pace_to_tcp(n).await;
            writer.write_all(&buf[..n]).await?;
            to_tcp.fetch_add(n as u64, Ordering::Relaxed);
        }
        Ok::<(), ProtoError>(())
    };
    let (out_res, in_res) = tokio::join!(outbound, inbound);
    out_res?;
    in_res?;
    Ok(())
}

pub async fn wait_ready(
    ready: tokio::sync::oneshot::Receiver<Result<(), ()>>,
    timeout: Duration,
) -> Result<(), ProtoError> {
    match tokio::time::timeout(timeout, ready).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(()))) => Err(ProtoError::Message(
            "stream closed before it was ready".into(),
        )),
        Ok(Err(_)) => Err(ProtoError::Closed),
        Err(_) => Err(ProtoError::Timeout),
    }
}
