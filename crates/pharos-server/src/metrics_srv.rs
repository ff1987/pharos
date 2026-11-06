use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::state::{Metrics, Shutdown};

pub async fn metrics_loop(listener: TcpListener, metrics: Arc<Metrics>, shutdown: Shutdown) {
    loop {
        tokio::select! {
            _ = shutdown.draining() => break,
            accepted = listener.accept() => {
                let Ok((mut sock, _)) = accepted else { break };
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        sock.read(&mut buf),
                    )
                    .await;
                    let body = metrics.render();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                });
            }
        }
    }
}
