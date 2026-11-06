use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::session::authenticate_and_serve;
use crate::state::{AppState, DataPlane, Shutdown};

pub async fn tls_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: Arc<AppState>,
    shutdown: Shutdown,
) {
    loop {
        tokio::select! {
            _ = shutdown.draining() => break,
            accepted = listener.accept() => {
                let Ok((sock, peer)) = accepted else { break };
                let _ = sock.set_nodelay(true);
                let acceptor = acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    match acceptor.accept(sock).await {
                        Ok(tls) => {
                            let (reader, writer) = tokio::io::split(tls);
                            let metrics = app.metrics.clone();
                            let limits = app.limits.clone();
                            if let Err(err) = authenticate_and_serve(
                                reader,
                                writer,
                                peer,
                                app,
                                move |mux| DataPlane::tls(mux, limits, metrics),
                                true,
                            )
                            .await
                            {
                                tracing::debug!(%peer, error = %err, "tls session ended");
                            }
                        }
                        Err(err) => {
                            app.metrics.auth_fail.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!(%peer, error = %err, "tls handshake failed");
                        }
                    }
                });
            }
        }
    }
}
