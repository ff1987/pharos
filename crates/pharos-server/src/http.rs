use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

use crate::state::{bridge_public, AppState, Shutdown};

const NOT_FOUND: &[u8] = b"\
HTTP/1.1 404 Not Found\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Length: 9\r\n\
Connection: close\r\n\
\r\n\
not found";

const BAD_REQUEST: &[u8] = b"\
HTTP/1.1 400 Bad Request\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Length: 11\r\n\
Connection: close\r\n\
\r\n\
bad request";

const UNAVAILABLE: &[u8] = b"\
HTTP/1.1 503 Service Unavailable\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Length: 14\r\n\
Connection: close\r\n\
\r\n\
no tunnel slot";

pub async fn http_loop(listener: TcpListener, app: Arc<AppState>, shutdown: Shutdown) {
    loop {
        tokio::select! {
            _ = shutdown.draining() => break,
            accepted = listener.accept() => {
                let Ok((sock, peer)) = accepted else {
                    break;
                };
                let _ = sock.set_nodelay(true);
                let app = app.clone();
                tokio::spawn(async move {
                    let span = tracing::info_span!("http_proxy", %peer);
                    if let Err(err) = handle_http(sock, app).instrument(span).await {
                        tracing::debug!(%peer, error = %err, "http proxy ended");
                    }
                });
            }
        }
    }
}

/// Public HTTPS: terminate TLS, then Host-route on the same table as plaintext HTTP.
pub async fn https_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: Arc<AppState>,
    shutdown: Shutdown,
) {
    loop {
        tokio::select! {
            _ = shutdown.draining() => break,
            accepted = listener.accept() => {
                let Ok((sock, peer)) = accepted else {
                    break;
                };
                let _ = sock.set_nodelay(true);
                let acceptor = acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    let span = tracing::info_span!("https_proxy", %peer);
                    async move {
                        match acceptor.accept(sock).await {
                            Ok(tls) => {
                                if let Err(err) = handle_http(tls, app).await {
                                    tracing::debug!(%peer, error = %err, "https proxy ended");
                                }
                            }
                            Err(err) => {
                                tracing::debug!(%peer, error = %err, "https handshake failed");
                            }
                        }
                    }
                    .instrument(span)
                    .await;
                });
            }
        }
    }
}

async fn handle_http<S>(mut sock: S, app: Arc<AppState>) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = match read_head(&mut sock).await {
        Ok(head) => head,
        Err(err) => {
            let _ = write_and_close(&mut sock, BAD_REQUEST).await;
            return Err(err);
        }
    };
    let Some(host) = parse_host(&head) else {
        write_and_close(&mut sock, BAD_REQUEST).await?;
        return Ok(());
    };
    let route = {
        let map = app.http_routes.read().expect("routes");
        map.get(&host).cloned()
    };
    let Some(route) = route else {
        tracing::info!(tunnel = %host, "http host not registered");
        write_and_close(&mut sock, NOT_FOUND).await?;
        return Ok(());
    };
    tracing::info!(tunnel = %host, "http host routed");
    let opened = match route.plane.open(route.tunnel_id).await {
        Ok(opened) => opened,
        Err(err) => {
            tracing::debug!(%host, error = %err, "http tunnel busy or unavailable");
            write_and_close(&mut sock, UNAVAILABLE).await?;
            return Ok(());
        }
    };
    bridge_public(sock, opened, &head).await?;
    Ok(())
}

async fn write_and_close<S: AsyncWrite + Unpin>(sock: &mut S, bytes: &[u8]) -> anyhow::Result<()> {
    sock.write_all(bytes).await?;
    let _ = sock.shutdown().await;
    Ok(())
}

async fn read_head<S: AsyncRead + Unpin>(sock: &mut S) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > 16 * 1024 {
            anyhow::bail!("http headers exceed 16KiB");
        }
        let n = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut tmp))
            .await
            .map_err(|_| anyhow::anyhow!("timed out reading http headers"))??;
        if n == 0 {
            anyhow::bail!("connection closed before http headers");
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

pub fn parse_host(head: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let header_block = text.split("\r\n\r\n").next().unwrap_or(text);
    for line in header_block.split("\r\n").skip(1) {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("host") {
            continue;
        }
        let value = value.trim();
        if let Some(rest) = value.strip_prefix('[') {
            let end = rest.find(']')?;
            let host = &rest[..end];
            if host.is_empty() {
                return None;
            }
            return Some(host.to_ascii_lowercase());
        }
        let host = value.split(':').next().unwrap_or(value).trim();
        if host.is_empty() {
            return None;
        }
        return Some(host.to_ascii_lowercase());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::parse_host;

    #[test]
    fn host_header_strips_port_and_case() {
        let raw = b"GET / HTTP/1.1\r\nHost: Demo.Local:7680\r\n\r\n";
        assert_eq!(parse_host(raw).as_deref(), Some("demo.local"));
        let v6 = b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n";
        assert_eq!(parse_host(v6).as_deref(), Some("::1"));
        assert!(parse_host(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }
}
