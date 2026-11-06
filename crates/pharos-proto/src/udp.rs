//! UDP datagram framing on an OpenStream association.
//!
//! After `StreamReady`, each datagram is `u16` big-endian length then that many
//! payload bytes. Associations are connectionless: an idle timer closes the
//! stream when neither side has forwarded a datagram.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::bistream::BiStream;
use crate::error::ProtoError;
use crate::frame::{close_reason, data_frame, Close, DATA_CHUNK};
use crate::mux::{MuxHandle, StreamEvent};
use crate::proxy::{BytePacer, Traffic};

/// Largest UDP payload Pharos will forward on one association stream.
pub const MAX_UDP_DATAGRAM: usize = 65_535;

/// Default idle lifetime for a public-peer UDP association (seconds).
pub const UDP_ASSOC_IDLE_SECS: u64 = 60;

pub fn udp_idle() -> Duration {
    Duration::from_secs(UDP_ASSOC_IDLE_SECS)
}

pub fn encode_datagram(payload: &[u8]) -> Result<Bytes, ProtoError> {
    if payload.len() > MAX_UDP_DATAGRAM {
        return Err(ProtoError::Message(format!(
            "udp datagram {} bytes exceeds max {MAX_UDP_DATAGRAM}",
            payload.len()
        )));
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(Bytes::from(out))
}

#[derive(Default)]
pub struct DatagramBuf {
    buf: Vec<u8>,
}

impl DatagramBuf {
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Bytes>, ProtoError> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if len > MAX_UDP_DATAGRAM {
                return Err(ProtoError::Message(format!(
                    "udp length prefix {len} exceeds max {MAX_UDP_DATAGRAM}"
                )));
            }
            if self.buf.len() < 2 + len {
                break;
            }
            out.push(Bytes::copy_from_slice(&self.buf[2..2 + len]));
            self.buf.drain(..2 + len);
        }
        Ok(out)
    }
}

async fn write_framed_mux(
    mux: &MuxHandle,
    stream_id: u32,
    payload: &[u8],
    traffic_from: &AtomicU64,
    pace: &impl BytePacer,
) -> Result<(), ProtoError> {
    let framed = encode_datagram(payload)?;
    traffic_from.fetch_add(payload.len() as u64, Ordering::Relaxed);
    pace.pace_from_tcp(payload.len()).await;
    for chunk in framed.chunks(DATA_CHUNK) {
        mux.send(data_frame(stream_id, Bytes::copy_from_slice(chunk)))
            .await?;
    }
    Ok(())
}

async fn write_framed_raw(
    writer: &mut (impl AsyncWrite + Unpin),
    payload: &[u8],
    traffic_from: &AtomicU64,
    pace: &impl BytePacer,
) -> Result<(), ProtoError> {
    let framed = encode_datagram(payload)?;
    traffic_from.fetch_add(payload.len() as u64, Ordering::Relaxed);
    pace.pace_from_tcp(payload.len()).await;
    writer.write_all(&framed).await?;
    Ok(())
}

/// Bridge a connected local UDP socket to a TLS-multiplexed association.
pub async fn bridge_udp_mux(
    sock: UdpSocket,
    stream_id: u32,
    mut events: mpsc::Receiver<StreamEvent>,
    mux: MuxHandle,
    traffic: Traffic<'_>,
    pace: &impl BytePacer,
    idle: Duration,
) -> Result<(), ProtoError> {
    let mut decoder = DatagramBuf::default();
    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
    let idle_sleep = tokio::time::sleep(idle);
    tokio::pin!(idle_sleep);
    loop {
        tokio::select! {
            _ = &mut idle_sleep => {
                let _ = mux.send(Close { stream_id, reason: close_reason::TIMEOUT }.to_frame()).await;
                break;
            }
            recv = sock.recv(&mut buf) => {
                let n = recv?;
                write_framed_mux(&mux, stream_id, &buf[..n], traffic.from_tcp, pace).await?;
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle);
            }
            event = events.recv() => {
                match event {
                    Some(StreamEvent::Data(bytes)) => {
                        let datagrams = decoder.push(&bytes)?;
                        for datagram in datagrams {
                            pace.pace_to_tcp(datagram.len()).await;
                            sock.send(&datagram).await?;
                            traffic.to_tcp.fetch_add(datagram.len() as u64, Ordering::Relaxed);
                        }
                        idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle);
                    }
                    Some(StreamEvent::Eof) | None => break,
                }
            }
        }
    }
    Ok(())
}

/// Bridge a connected local UDP socket to a raw (QUIC) association stream.
pub async fn bridge_udp_raw<R, W>(
    sock: UdpSocket,
    remote: BiStream<R, W>,
    traffic: Traffic<'_>,
    pace: &impl BytePacer,
    idle: Duration,
) -> Result<(), ProtoError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let (mut remote_reader, mut remote_writer) = tokio::io::split(remote);
    let mut decoder = DatagramBuf::default();
    let mut udp_buf = vec![0u8; MAX_UDP_DATAGRAM];
    let mut stream_buf = vec![0u8; DATA_CHUNK];
    let idle_sleep = tokio::time::sleep(idle);
    tokio::pin!(idle_sleep);
    loop {
        tokio::select! {
            _ = &mut idle_sleep => {
                let _ = remote_writer.shutdown().await;
                break;
            }
            recv = sock.recv(&mut udp_buf) => {
                let n = recv?;
                write_framed_raw(&mut remote_writer, &udp_buf[..n], traffic.from_tcp, pace).await?;
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle);
            }
            read = remote_reader.read(&mut stream_buf) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                let datagrams = decoder.push(&stream_buf[..n])?;
                for datagram in datagrams {
                    pace.pace_to_tcp(datagram.len()).await;
                    sock.send(&datagram).await?;
                    traffic.to_tcp.fetch_add(datagram.len() as u64, Ordering::Relaxed);
                }
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle);
            }
        }
    }
    Ok(())
}

/// Server-side association: public peer datagrams on `inbound` and replies via `send_to`.
pub async fn bridge_udp_assoc_mux(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut inbound: mpsc::Receiver<Bytes>,
    stream_id: u32,
    mut events: mpsc::Receiver<StreamEvent>,
    mux: MuxHandle,
    traffic: Traffic<'_>,
    pace: &impl BytePacer,
    idle: Duration,
) -> Result<(), ProtoError> {
    let mut decoder = DatagramBuf::default();
    let idle_sleep = tokio::time::sleep(idle);
    tokio::pin!(idle_sleep);
    loop {
        tokio::select! {
            _ = &mut idle_sleep => {
                let _ = mux.send(Close { stream_id, reason: close_reason::TIMEOUT }.to_frame()).await;
                break;
            }
            packet = inbound.recv() => {
                let Some(packet) = packet else { break };
                write_framed_mux(&mux, stream_id, &packet, traffic.from_tcp, pace).await?;
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle);
            }
            event = events.recv() => {
                match event {
                    Some(StreamEvent::Data(bytes)) => {
                        let datagrams = decoder.push(&bytes)?;
                        for datagram in datagrams {
                            pace.pace_to_tcp(datagram.len()).await;
                            socket.send_to(&datagram, peer).await?;
                            traffic.to_tcp.fetch_add(datagram.len() as u64, Ordering::Relaxed);
                        }
                        idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle);
                    }
                    Some(StreamEvent::Eof) | None => break,
                }
            }
        }
    }
    Ok(())
}

/// Server-side association over a raw QUIC stream.
pub async fn bridge_udp_assoc_raw<R, W>(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut inbound: mpsc::Receiver<Bytes>,
    remote: BiStream<R, W>,
    traffic: Traffic<'_>,
    pace: &impl BytePacer,
    idle: Duration,
) -> Result<(), ProtoError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let (mut remote_reader, mut remote_writer) = tokio::io::split(remote);
    let mut decoder = DatagramBuf::default();
    let mut stream_buf = vec![0u8; DATA_CHUNK];
    let idle_sleep = tokio::time::sleep(idle);
    tokio::pin!(idle_sleep);
    loop {
        tokio::select! {
            _ = &mut idle_sleep => {
                let _ = remote_writer.shutdown().await;
                break;
            }
            packet = inbound.recv() => {
                let Some(packet) = packet else { break };
                write_framed_raw(&mut remote_writer, &packet, traffic.from_tcp, pace).await?;
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle);
            }
            read = remote_reader.read(&mut stream_buf) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                let datagrams = decoder.push(&stream_buf[..n])?;
                for datagram in datagrams {
                    pace.pace_to_tcp(datagram.len()).await;
                    socket.send_to(&datagram, peer).await?;
                    traffic.to_tcp.fetch_add(datagram.len() as u64, Ordering::Relaxed);
                }
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_roundtrip_through_buffer() {
        let mut buf = DatagramBuf::default();
        let a = encode_datagram(b"ping").unwrap();
        let b = encode_datagram(b"pong").unwrap();
        let mut wire = a.to_vec();
        wire.extend_from_slice(&b);
        // Split across pushes.
        let mid = 3;
        let first = buf.push(&wire[..mid]).unwrap();
        assert!(first.is_empty());
        let second = buf.push(&wire[mid..]).unwrap();
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].as_ref(), b"ping");
        assert_eq!(second[1].as_ref(), b"pong");
    }
}
