use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::state::{Metrics, Shutdown};

pub async fn metrics_loop(listener: TcpListener, metrics: Arc<Metrics>, shutdown: Shutdown) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((sock, _)) = accepted else { break };
                let metrics = metrics.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    serve_one(sock, metrics, shutdown).await;
                });
            }
        }
    }
}

async fn serve_one(mut sock: TcpStream, metrics: Arc<Metrics>, shutdown: Shutdown) {
    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(2), sock.read(&mut buf)).await
    {
        Ok(Ok(n)) => n,
        _ => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let (method, path) = match parse_request_line(&req) {
        Some(parts) => parts,
        None => {
            let _ = write_response(&mut sock, 400, "text/plain", "bad request\n").await;
            return;
        }
    };

    let head = method.eq_ignore_ascii_case("HEAD");
    let get = method.eq_ignore_ascii_case("GET");
    if !get && !head {
        let _ = write_response(&mut sock, 405, "text/plain", "method not allowed\n").await;
        return;
    }

    match path.as_str() {
        "/metrics" => {
            let body = metrics.render();
            let _ = write_response_maybe_body(
                &mut sock,
                200,
                "text/plain; version=0.0.4",
                &body,
                head,
            )
            .await;
        }
        "/health" => {
            let _ = write_response_maybe_body(&mut sock, 200, "text/plain", "ok\n", head).await;
        }
        "/ready" => {
            if shutdown.is_draining() {
                let _ = write_response_maybe_body(
                    &mut sock,
                    503,
                    "text/plain",
                    "not ready\n",
                    head,
                )
                .await;
            } else {
                let _ =
                    write_response_maybe_body(&mut sock, 200, "text/plain", "ready\n", head).await;
            }
        }
        _ => {
            let _ = write_response_maybe_body(&mut sock, 404, "text/plain", "not found\n", head)
                .await;
        }
    }
}

fn parse_request_line(req: &str) -> Option<(String, String)> {
    let line = req.lines().next()?.trim_end_matches('\r');
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let path = target.split('?').next().unwrap_or(target).to_string();
    Some((method, path))
}

async fn write_response(
    sock: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    write_response_maybe_body(sock, status, content_type, body, false).await
}

async fn write_response_maybe_body(
    sock: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
    head: bool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let payload = if head { "" } else { body };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        body.len()
    );
    sock.write_all(response.as_bytes()).await
}
