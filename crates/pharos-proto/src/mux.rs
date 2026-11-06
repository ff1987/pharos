use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::error::ProtoError;
use crate::frame::{
    decode_data, is_optional_type, Close, Frame, FrameType, OpenStream, StreamReady, PROTO_VERSION,
};

/// Bytes or EOF for one multiplexed stream on the TLS transport.
#[derive(Debug)]
pub enum StreamEvent {
    Data(Bytes),
    Eof,
}

/// What the control reader should do with a frame after demux.
#[derive(Debug)]
pub enum Demux {
    /// Frame was data, close, stream-ready, or an optional unknown type.
    Handled,
    /// A control-plane frame the session state machine still has to interpret.
    Control(Frame),
}

#[derive(Clone)]
pub struct MuxHandle {
    inner: Arc<MuxInner>,
}

struct MuxInner {
    tx: mpsc::Sender<Frame>,
    routes: Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>,
    ready: Mutex<HashMap<u32, oneshot::Sender<Result<(), ()>>>>,
}

impl MuxHandle {
    pub fn new(tx: mpsc::Sender<Frame>) -> Self {
        Self {
            inner: Arc::new(MuxInner {
                tx,
                routes: Mutex::new(HashMap::new()),
                ready: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub async fn send(&self, frame: Frame) -> Result<(), ProtoError> {
        self.inner
            .tx
            .send(frame)
            .await
            .map_err(|_| ProtoError::Closed)
    }

    pub fn register_route(&self, stream_id: u32) -> mpsc::Receiver<StreamEvent> {
        let (tx, rx) = mpsc::channel(32);
        self.inner
            .routes
            .lock()
            .expect("mux routes")
            .insert(stream_id, tx);
        rx
    }

    pub fn arm_ready(&self, stream_id: u32) -> oneshot::Receiver<Result<(), ()>> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .ready
            .lock()
            .expect("mux ready")
            .insert(stream_id, tx);
        rx
    }

    pub fn unregister(&self, stream_id: u32) {
        self.inner
            .routes
            .lock()
            .expect("mux routes")
            .remove(&stream_id);
        self.inner
            .ready
            .lock()
            .expect("mux ready")
            .remove(&stream_id);
    }

    /// Route data and close frames. Control frames are returned to the caller.
    ///
    /// Awaiting a full per-stream channel applies backpressure to the whole TLS
    /// connection. That head-of-line blocking is specific to the single-socket
    /// fallback; QUIC data uses independent streams and does not pass through here.
    pub async fn dispatch(&self, frame: Frame) -> Result<Demux, ProtoError> {
        if frame.version != PROTO_VERSION {
            return Err(ProtoError::Version(frame.version));
        }
        match FrameType::from_u8(frame.ty) {
            Some(FrameType::Data) => {
                let (id, bytes) = decode_data(&frame.payload)?;
                let sender = self
                    .inner
                    .routes
                    .lock()
                    .expect("mux routes")
                    .get(&id)
                    .cloned();
                if let Some(sender) = sender {
                    if sender.send(StreamEvent::Data(bytes)).await.is_err() {
                        self.unregister(id);
                    }
                }
                Ok(Demux::Handled)
            }
            Some(FrameType::Close) => {
                let close = Close::decode(&frame.payload)?;
                let sender = self
                    .inner
                    .routes
                    .lock()
                    .expect("mux routes")
                    .remove(&close.stream_id);
                let waiter = self
                    .inner
                    .ready
                    .lock()
                    .expect("mux ready")
                    .remove(&close.stream_id);
                if let Some(waiter) = waiter {
                    let _ = waiter.send(Err(()));
                }
                if let Some(sender) = sender {
                    let _ = sender.send(StreamEvent::Eof).await;
                }
                Ok(Demux::Handled)
            }
            Some(FrameType::StreamReady) => {
                let ready = StreamReady::decode(&frame.payload)?;
                if let Some(waiter) = self
                    .inner
                    .ready
                    .lock()
                    .expect("mux ready")
                    .remove(&ready.stream_id)
                {
                    let _ = waiter.send(Ok(()));
                }
                Ok(Demux::Handled)
            }
            Some(_) => Ok(Demux::Control(frame)),
            None if is_optional_type(frame.ty) => Ok(Demux::Handled),
            None => Err(ProtoError::BadType(frame.ty)),
        }
    }

    pub async fn open_wait(
        &self,
        tunnel_id: u32,
        stream_id: u32,
    ) -> Result<
        (
            mpsc::Receiver<StreamEvent>,
            oneshot::Receiver<Result<(), ()>>,
        ),
        ProtoError,
    > {
        let rx = self.register_route(stream_id);
        let ready = self.arm_ready(stream_id);
        let frame = OpenStream {
            stream_id,
            tunnel_id,
        }
        .to_frame();
        if let Err(err) = self.send(frame).await {
            self.unregister(stream_id);
            return Err(err);
        }
        Ok((rx, ready))
    }
}
