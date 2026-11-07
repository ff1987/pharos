use std::net::SocketAddr;
use std::time::Duration;

use pharos_client::{ClientConfig, ClientEvent, ClientHandle};
use pharos_proto::{generate_dev_identity, issue_client_certificate, ServerConfig};
use pharos_server::ServerHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

struct IdentityPem {
    cert: String,
    key: String,
}

fn identity() -> IdentityPem {
    let generated = generate_dev_identity().expect("dev cert");
    IdentityPem {
        cert: generated.cert_pem,
        key: generated.key_pem,
    }
}

async fn boot_server(token: &str, body: &str, id: &IdentityPem) -> ServerHandle {
    let raw = format!(
        "token = \"{token}\"\ndev_ephemeral_cert = true\ntcp_bind_ip = \"127.0.0.1\"\n{body}\n"
    );
    let mut config = ServerConfig::parse_toml(&raw).expect("server toml");
    config.cert_pem = Some(id.cert.clone());
    config.key_pem = Some(id.key.clone());
    config.dev_ephemeral_cert = false;
    pharos_server::spawn(config).await.expect("spawn server")
}

fn client_config(
    token: &str,
    server: SocketAddr,
    transport: &str,
    cert: &str,
    tunnels: &str,
    heartbeat: &str,
) -> ClientConfig {
    let raw = format!(
        r#"
server = "{server}"
token = "{token}"
transport = "{transport}"
server_name = "localhost"
tls_insecure = true
[reconnect]
enabled = false
min_secs = 1
max_secs = 1
{heartbeat}
{tunnels}
"#
    );
    let mut config = ClientConfig::parse_toml(&raw).expect("client toml");
    config.tls_insecure = false;
    config.ca_pem = Some(cert.to_string());
    config.validate().expect("client config");
    config
}

async fn recv(client: &mut ClientHandle) -> ClientEvent {
    tokio::time::timeout(Duration::from_secs(8), client.events.recv())
        .await
        .expect("timed out waiting for a client event")
        .expect("client event channel closed")
}

async fn until_settled(client: &mut ClientHandle) -> Vec<ClientEvent> {
    let mut events = Vec::new();
    loop {
        let event = recv(client).await;
        let stop = matches!(event, ClientEvent::Ready | ClientEvent::SessionEnded { .. });
        events.push(event);
        if stop {
            break;
        }
    }
    events
}

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut reader, mut writer) = sock.into_split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

async fn spawn_hello() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
                let body = b"hello";
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(body).await;
            });
        }
    });
    addr
}

fn https_connector(ca_pem: &str) -> tokio_rustls::TlsConnector {
    pharos_proto::install_ring();
    let mut roots = rustls::RootCertStore::empty();
    for cert in pharos_proto::certs_from_pem(ca_pem).expect("ca pem") {
        roots.add(cert).expect("trust anchor");
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
}

async fn https_connect(
    connector: &tokio_rustls::TlsConnector,
    addr: SocketAddr,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let name = pharos_proto::server_name("localhost").expect("server name");
    let mut last = String::new();
    for _ in 0..25 {
        match TcpStream::connect(addr).await {
            Ok(sock) => {
                let _ = sock.set_nodelay(true);
                match connector.connect(name.clone(), sock).await {
                    Ok(tls) => return tls,
                    Err(err) => last = err.to_string(),
                }
            }
            Err(err) => last = err.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    panic!("https connect {addr} failed: {last}");
}

async fn read_http_body<S>(sock: &mut S) -> Vec<u8>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut body = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut body)).await;
    match result {
        Ok(Ok(_)) => body,
        Ok(Err(_)) if !body.is_empty() => body,
        Ok(Err(err)) => panic!("https read failed with empty body: {err}"),
        Err(_) => panic!("https read timed out"),
    }
}

async fn connect_retry(addr: SocketAddr) -> TcpStream {
    let mut last = String::new();
    for _ in 0..25 {
        match TcpStream::connect(addr).await {
            Ok(sock) => return sock,
            Err(err) => {
                last = err.to_string();
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        }
    }
    panic!("connect {addr} failed: {last}");
}

fn endpoint_of(events: &[ClientEvent], name: &str) -> String {
    events
        .iter()
        .find_map(|event| match event {
            ClientEvent::Registered {
                name: got,
                public_endpoint,
                ..
            } if got == name => Some(public_endpoint.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("tunnel {name} was not registered: {events:?}"))
}

const SLOW_HEARTBEAT: &str = "[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_rejects_wrong_token() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let config = client_config(
        "wrong-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        "",
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    match events.last() {
        Some(ClientEvent::SessionEnded { error: Some(error) }) => {
            assert!(
                error.contains("authentication failed"),
                "unexpected error: {error}"
            );
        }
        other => panic!("expected auth failure, got {other:?}"),
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_accepts_token_without_tunnels() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let config = client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        "",
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );
    client.shutdown().await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_tcp_reverse_echo() {
    tcp_echo("tls").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_tcp_reverse_echo() {
    tcp_echo("quic").await;
}

async fn tcp_echo(transport: &str) {
    let id = identity();
    let echo = spawn_echo().await;
    let bind = if transport == "quic" {
        "quic_bind = \"127.0.0.1:0\"\n"
    } else {
        "tls_bind = \"127.0.0.1:0\"\n"
    };
    let server = boot_server(
        "correct-token",
        &format!("{bind}[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n"),
        &id,
    )
    .await;
    let server_addr = if transport == "quic" {
        server.quic_addr.expect("quic")
    } else {
        server.tls_addr.expect("tls")
    };
    let tunnels = format!(
        "[[tunnels]]\nname = \"echo\"\ntype = \"tcp\"\nlocal = \"{echo}\"\nremote_port = 0\n"
    );
    let config = client_config(
        "correct-token",
        server_addr,
        transport,
        &id.cert,
        &tunnels,
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );
    let public: SocketAddr = endpoint_of(&events, "echo").parse().unwrap();
    let mut sock = connect_retry(public).await;
    sock.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"ping");
    drop(sock);
    client.shutdown().await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acl_denies_unlisted_port() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[acl]\nallow_ports = [1]\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let tunnels =
        "[[tunnels]]\nname = \"nope\"\ntype = \"tcp\"\nlocal = \"127.0.0.1:9\"\nremote_port = 9\n";
    let config = client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        tunnels,
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        events.iter().any(|event| matches!(
            event,
            ClientEvent::RegisterFailed { reason, .. } if reason.contains("ACL")
        )),
        "{events:?}"
    );
    match events.last() {
        Some(ClientEvent::SessionEnded { error: Some(error) }) => {
            assert!(error.contains("no tunnels"), "{error}");
        }
        other => panic!("expected session failure, got {other:?}"),
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_host_routing_and_unknown_host() {
    let id = identity();
    let origin = spawn_hello().await;
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[http]\nbind = \"127.0.0.1:0\"\n[acl]\nallow_any_hostname = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let http_addr = server.http_addr.expect("http");
    let tunnels = format!(
        "[[tunnels]]\nname = \"web\"\ntype = \"http\"\nlocal = \"{origin}\"\nhostname = \"demo.local\"\n"
    );
    let config = client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        &tunnels,
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );

    let mut sock = connect_retry(http_addr).await;
    sock.write_all(b"GET / HTTP/1.1\r\nHost: demo.local\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut body))
        .await
        .expect("http timed out")
        .unwrap();
    assert!(
        body.windows(5).any(|window| window == b"hello"),
        "body: {}",
        String::from_utf8_lossy(&body)
    );

    let mut missing = connect_retry(http_addr).await;
    missing
        .write_all(b"GET / HTTP/1.1\r\nHost: nope.local\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut denied = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), missing.read_to_end(&mut denied))
        .await
        .expect("404 timed out")
        .unwrap();
    let text = String::from_utf8_lossy(&denied);
    assert!(text.contains("404"), "{text}");

    client.shutdown().await;
    server.shutdown().await.unwrap();
}

async fn spawn_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_udp_reverse_echo() {
    udp_echo("tls").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_udp_reverse_echo() {
    udp_echo("quic").await;
}

async fn udp_echo(transport: &str) {
    let id = identity();
    let echo = spawn_udp_echo().await;
    let bind = if transport == "quic" {
        "quic_bind = \"127.0.0.1:0\"\n"
    } else {
        "tls_bind = \"127.0.0.1:0\"\n"
    };
    let server = boot_server(
        "correct-token",
        &format!("{bind}[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n"),
        &id,
    )
    .await;
    let server_addr = if transport == "quic" {
        server.quic_addr.expect("quic")
    } else {
        server.tls_addr.expect("tls")
    };
    let tunnels = format!(
        "[[tunnels]]\nname = \"dns\"\ntype = \"udp\"\nlocal = \"{echo}\"\nremote_port = 0\n"
    );
    let config = client_config(
        "correct-token",
        server_addr,
        transport,
        &id.cert,
        &tunnels,
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );
    let public: SocketAddr = endpoint_of(&events, "dns").parse().unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(b"ping", public).await.unwrap();
    let mut buf = [0u8; 16];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("udp echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"ping");
    // Second datagram on the same association.
    sock.send_to(b"pong", public).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("udp second echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"pong");
    client.shutdown().await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acl_denies_unlisted_udp_port() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[acl]\nallow_ports = [1]\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let tunnels =
        "[[tunnels]]\nname = \"nope\"\ntype = \"udp\"\nlocal = \"127.0.0.1:9\"\nremote_port = 9\n";
    let config = client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        tunnels,
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        events.iter().any(|event| matches!(
            event,
            ClientEvent::RegisterFailed { reason, .. } if reason.contains("ACL")
        )),
        "{events:?}"
    );
    match events.last() {
        Some(ClientEvent::SessionEnded { error: Some(error) }) => {
            assert!(error.contains("no tunnels"), "{error}");
        }
        other => panic!("expected session failure, got {other:?}"),
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_host_routing_and_unknown_host() {
    let id = identity();
    let origin = spawn_hello().await;
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[https]\nbind = \"127.0.0.1:0\"\n[acl]\nallow_any_hostname = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let https_addr = server.https_addr.expect("https");
    let tunnels = format!(
        "[[tunnels]]\nname = \"web\"\ntype = \"http\"\nlocal = \"{origin}\"\nhostname = \"demo.local\"\n"
    );
    let config = client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        &tunnels,
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );

    let connector = https_connector(&id.cert);
    let mut sock = https_connect(&connector, https_addr).await;
    sock.write_all(b"GET / HTTP/1.1\r\nHost: demo.local\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let body = read_http_body(&mut sock).await;
    assert!(
        body.windows(5).any(|window| window == b"hello"),
        "body: {}",
        String::from_utf8_lossy(&body)
    );

    let mut missing = https_connect(&connector, https_addr).await;
    missing
        .write_all(b"GET / HTTP/1.1\r\nHost: nope.local\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let denied = read_http_body(&mut missing).await;
    let text = String::from_utf8_lossy(&denied);
    assert!(text.contains("404"), "{text}");

    client.shutdown().await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heartbeat_timeout_closes_silent_client() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 30\ntimeout_secs = 2\n",
        &id,
    )
    .await;
    let config = client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        "",
        "[heartbeat]\ninterval_secs = 30\ntimeout_secs = 30\n",
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );
    let ended = recv(&mut client).await;
    match ended {
        ClientEvent::SessionEnded { error: Some(error) } => {
            assert!(!error.is_empty(), "{error}");
        }
        other => panic!("expected the server to drop the idle session, got {other:?}"),
    }
    server.shutdown().await.unwrap();
}

fn client_with_cert(
    token: &str,
    server: SocketAddr,
    transport: &str,
    server_cert: &str,
    mode: &str,
    client: &pharos_proto::Identity,
    tunnels: &str,
) -> ClientConfig {
    let raw = format!(
        r#"
server = "{server}"
token = "{token}"
transport = "{transport}"
server_name = "localhost"
tls_insecure = true
[reconnect]
enabled = false
min_secs = 1
max_secs = 1
[heartbeat]
interval_secs = 15
timeout_secs = 45
[auth]
mode = "{mode}"
cert_file = "unused.crt"
key_file = "unused.key"
{tunnels}
"#
    );
    let mut config = ClientConfig::parse_toml(&raw).expect("mtls client toml");
    config.tls_insecure = false;
    config.ca_pem = Some(server_cert.to_string());
    config.auth.cert_pem = Some(client.cert_pem.clone());
    config.auth.key_pem = Some(client.key_pem.clone());
    config.validate().expect("mtls client config");
    config
}

async fn boot_mtls(
    token: &str,
    mode: &str,
    client_ca: &str,
    id: &IdentityPem,
    quic: bool,
) -> ServerHandle {
    let quic_line = if quic {
        "quic_bind = \"127.0.0.1:0\"\n"
    } else {
        ""
    };
    let raw = format!(
        r#"
token = "{token}"
tls_bind = "127.0.0.1:0"
{quic_line}dev_ephemeral_cert = true
tcp_bind_ip = "127.0.0.1"
[acl]
allow_any_port = true
[heartbeat]
interval_secs = 15
timeout_secs = 45
[auth]
mode = "{mode}"
client_ca_file = "unused-ca.crt"
"#
    );
    let mut config = ServerConfig::parse_toml(&raw).expect("mtls server toml");
    config.cert_pem = Some(id.cert.clone());
    config.key_pem = Some(id.key.clone());
    config.dev_ephemeral_cert = false;
    config.auth.client_ca_pem = Some(client_ca.to_string());
    config.validate().expect("mtls server config");
    pharos_server::spawn(config)
        .await
        .expect("spawn mtls server")
}

async fn tcp_echo_on(_transport: &str, config: ClientConfig) {
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );
    let public: SocketAddr = endpoint_of(&events, "echo").parse().unwrap();
    let mut sock = connect_retry(public).await;
    sock.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"ping");
    drop(sock);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_rejects_untrusted_client_certificate() {
    let id = identity();
    let trusted = issue_client_certificate().unwrap();
    let stranger = issue_client_certificate().unwrap();
    let server = boot_mtls("correct-token", "mtls", &trusted.ca_pem, &id, false).await;
    let config = client_with_cert(
        "",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        "mtls",
        &stranger.identity,
        "",
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    match events.last() {
        Some(ClientEvent::SessionEnded { error: Some(error) }) => {
            assert!(
                error.to_lowercase().contains("cert")
                    || error.to_lowercase().contains("handshake")
                    || error.to_lowercase().contains("tls")
                    || error.to_lowercase().contains("unknown")
                    || error.to_lowercase().contains("alert"),
                "untrusted client certificate was not rejected clearly: {error}"
            );
        }
        other => panic!("expected handshake rejection, got {other:?}"),
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_tcp_reverse_with_trusted_certificate() {
    mtls_tcp("tls", "mtls", "").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_mtls_tcp_reverse_with_trusted_certificate() {
    mtls_tcp("quic", "mtls", "").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_and_mtls_rejects_wrong_token() {
    let id = identity();
    let issued = issue_client_certificate().unwrap();
    let server = boot_mtls("correct-token", "token+mtls", &issued.ca_pem, &id, false).await;
    let config = client_with_cert(
        "wrong-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        "token+mtls",
        &issued.identity,
        "",
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    match events.last() {
        Some(ClientEvent::SessionEnded { error: Some(error) }) => {
            assert!(
                error.contains("authentication failed"),
                "unexpected error: {error}"
            );
        }
        other => panic!("expected token rejection, got {other:?}"),
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_and_mtls_tcp_reverse() {
    mtls_tcp("tls", "token+mtls", "correct-token").await;
}

async fn mtls_tcp(transport: &str, mode: &str, token: &str) {
    let id = identity();
    let issued = issue_client_certificate().unwrap();
    let echo = spawn_echo().await;
    let server_token = if mode == "mtls" { "" } else { "correct-token" };
    let server = boot_mtls(server_token, mode, &issued.ca_pem, &id, transport == "quic").await;
    let server_addr = if transport == "quic" {
        server.quic_addr.expect("quic")
    } else {
        server.tls_addr.expect("tls")
    };
    let tunnels = format!(
        "[[tunnels]]\nname = \"echo\"\ntype = \"tcp\"\nlocal = \"{echo}\"\nremote_port = 0\n"
    );
    let config = client_with_cert(
        token,
        server_addr,
        transport,
        &id.cert,
        mode,
        &issued.identity,
        &tunnels,
    );
    tcp_echo_on(transport, config).await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_endpoint_exposes_auth_failure_counter() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\nmetrics_bind = \"127.0.0.1:0\"\n[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let metrics_addr = server.metrics_addr.expect("metrics");
    let config = client_config(
        "wrong-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        "",
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(
            events.last(),
            Some(ClientEvent::SessionEnded { error: Some(_) })
        ),
        "{events:?}"
    );

    let mut sock = TcpStream::connect(metrics_addr).await.unwrap();
    sock.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut body))
        .await
        .expect("metrics timed out")
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    for name in [
        "pharos_tunnels_active",
        "pharos_auth_failure_total",
        "pharos_streams_opened_total",
        "pharos_bytes_in_total",
        "pharos_bytes_out_total",
    ] {
        assert!(
            text.lines()
                .any(|line| line.starts_with(name) && line.contains(' ')),
            "missing {name} in {text}"
        );
    }
    let failures = text
        .lines()
        .find(|line| line.starts_with("pharos_auth_failure_total "))
        .expect("auth failure sample");
    let count: u64 = failures.split_whitespace().nth(1).unwrap().parse().unwrap();
    assert!(count >= 1, "{failures}");
    server.shutdown().await.unwrap();
}


async fn metrics_http(addr: SocketAddr, method: &str, path: &str) -> (u16, String, String) {
    metrics_http_auth(addr, method, path, None).await
}

async fn metrics_http_auth(
    addr: SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
) -> (u16, String, String) {
    let (status, content_type, _www, payload) =
        metrics_http_raw(addr, method, path, bearer).await;
    (status, content_type, payload)
}

async fn metrics_http_raw(
    addr: SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
) -> (u16, String, String, String) {
    let mut sock = TcpStream::connect(addr).await.unwrap();
    let auth = match bearer {
        Some(token) => format!("Authorization: Bearer {token}\r\n"),
        None => String::new(),
    };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n"
    );
    sock.write_all(req.as_bytes()).await.unwrap();
    let mut body = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut body))
        .await
        .expect("metrics http timed out")
        .unwrap();
    let text = String::from_utf8_lossy(&body).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let content_type = text
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-type:"))
        .map(|line| line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string())
        .unwrap_or_default();
    let www_authenticate = text
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("www-authenticate:"))
        .map(|line| line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string())
        .unwrap_or_default();
    let payload = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, content_type, www_authenticate, payload)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_bind_serves_health_ready_and_404() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\nmetrics_bind = \"127.0.0.1:0\"\n[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let metrics_addr = server.metrics_addr.expect("metrics");

    let (status, _ct, body) = metrics_http(metrics_addr, "GET", "/health").await;
    assert_eq!(status, 200, "health status");
    assert_eq!(body, "ok\n");

    let (status, _ct, body) = metrics_http(metrics_addr, "HEAD", "/health").await;
    assert_eq!(status, 200, "health HEAD status");
    assert!(body.is_empty(), "HEAD body should be empty: {body:?}");

    let (status, _ct, body) = metrics_http(metrics_addr, "GET", "/ready").await;
    assert_eq!(status, 200, "ready status");
    assert_eq!(body, "ready\n");

    let (status, ct, body) = metrics_http(metrics_addr, "GET", "/metrics").await;
    assert_eq!(status, 200, "metrics status");
    assert!(
        ct.starts_with("text/plain"),
        "metrics content-type: {ct}"
    );
    assert!(
        body.contains("pharos_tunnels_active"),
        "metrics body missing gauge: {body}"
    );

    let (status, _ct, body) = metrics_http(metrics_addr, "GET", "/nope").await;
    assert_eq!(status, 404, "unknown path status");
    assert_eq!(body, "not found\n");

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_ready_goes_503_during_drain_while_health_stays_200() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\nmetrics_bind = \"127.0.0.1:0\"\n[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let metrics_addr = server.metrics_addr.expect("metrics");

    let (status, _ct, body) = metrics_http(metrics_addr, "GET", "/ready").await;
    assert_eq!(status, 200);
    assert_eq!(body, "ready\n");

    server.shutdown.begin_drain();
    // Drain is signalled asynchronously via watch; give the listener a tick.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (status, _ct, body) = metrics_http(metrics_addr, "GET", "/ready").await;
    assert_eq!(status, 503, "ready during drain");
    assert_eq!(body, "not ready\n");

    let (status, _ct, body) = metrics_http(metrics_addr, "GET", "/health").await;
    assert_eq!(status, 200, "health during drain");
    assert_eq!(body, "ok\n");

    let (status, _ct, body) = metrics_http(metrics_addr, "HEAD", "/ready").await;
    assert_eq!(status, 503, "ready HEAD during drain");
    assert!(body.is_empty());

    server.shutdown().await.unwrap();
}



#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_token_rejects_missing_and_wrong_bearer() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\nmetrics_bind = \"127.0.0.1:0\"\nmetrics_token = \"ops-secret\"\n[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let metrics_addr = server.metrics_addr.expect("metrics");

    let (status, _ct, www, body) =
        metrics_http_raw(metrics_addr, "GET", "/health", None).await;
    assert_eq!(status, 401, "health without bearer");
    assert_eq!(www, "Bearer");
    assert_eq!(body, "unauthorized\n");

    let (status, _ct, www, body) =
        metrics_http_raw(metrics_addr, "GET", "/metrics", None).await;
    assert_eq!(status, 401, "metrics without bearer");
    assert_eq!(www, "Bearer");
    assert_eq!(body, "unauthorized\n");

    let (status, _ct, www, body) =
        metrics_http_raw(metrics_addr, "GET", "/health", Some("wrong")).await;
    assert_eq!(status, 401, "health wrong bearer");
    assert_eq!(www, "Bearer");
    assert_eq!(body, "unauthorized\n");

    let (status, _ct, www, body) =
        metrics_http_raw(metrics_addr, "GET", "/metrics", Some("wrong")).await;
    assert_eq!(status, 401, "metrics wrong bearer");
    assert_eq!(www, "Bearer");
    assert_eq!(body, "unauthorized\n");

    let (status, _ct, _www, body) =
        metrics_http_raw(metrics_addr, "GET", "/nope", None).await;
    assert_eq!(status, 401, "unknown path still 401 before path leak");
    assert_eq!(body, "unauthorized\n");

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_token_accepts_correct_bearer() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\nmetrics_bind = \"127.0.0.1:0\"\nmetrics_token = \"ops-secret\"\n[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let metrics_addr = server.metrics_addr.expect("metrics");

    let (status, _ct, body) =
        metrics_http_auth(metrics_addr, "GET", "/health", Some("ops-secret")).await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok\n");

    let (status, _ct, body) =
        metrics_http_auth(metrics_addr, "HEAD", "/health", Some("ops-secret")).await;
    assert_eq!(status, 200);
    assert!(body.is_empty());

    let (status, ct, body) =
        metrics_http_auth(metrics_addr, "GET", "/metrics", Some("ops-secret")).await;
    assert_eq!(status, 200);
    assert!(ct.starts_with("text/plain"), "{ct}");
    assert!(body.contains("pharos_tunnels_active"), "{body}");

    let (status, _ct, body) =
        metrics_http_auth(metrics_addr, "GET", "/ready", Some("ops-secret")).await;
    assert_eq!(status, 200);
    assert_eq!(body, "ready\n");

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_without_token_still_allows_health() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\nmetrics_bind = \"127.0.0.1:0\"\n[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let metrics_addr = server.metrics_addr.expect("metrics");

    let (status, _ct, body) = metrics_http(metrics_addr, "GET", "/health").await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok\n");

    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_hot_reload_adds_a_tcp_tunnel() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let dir = std::env::temp_dir().join(format!(
        "pharos-client-reload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("client.toml");
    let head = format!(
        r#"
server = "{}"
token = "correct-token"
transport = "tls"
server_name = "localhost"
tls_insecure = true
[reconnect]
enabled = false
min_secs = 1
max_secs = 1
[heartbeat]
interval_secs = 15
timeout_secs = 45
"#,
        server.tls_addr.expect("tls")
    );
    std::fs::write(&path, &head).unwrap();
    let mut cfg = ClientConfig::load_path(&path).unwrap();
    cfg.tls_insecure = false;
    cfg.ca_pem = Some(id.cert.clone());
    cfg.validate().unwrap();
    let mut client = pharos_client::spawn(cfg).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );

    let echo = spawn_echo().await;
    let updated = format!(
        "{head}\n[[tunnels]]\nname = \"echo\"\ntype = \"tcp\"\nlocal = \"{echo}\"\nremote_port = 0\n"
    );
    let tmp = dir.join("client.toml.tmp");
    std::fs::write(&tmp, updated).unwrap();
    std::fs::rename(&tmp, &path).unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    let mut public = None;
    while tokio::time::Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remain.is_zero() {
            break;
        }
        match tokio::time::timeout(remain, client.events.recv()).await {
            Ok(Some(ClientEvent::Registered {
                name,
                public_endpoint,
                ..
            })) if name == "echo" => {
                public = Some(public_endpoint);
                break;
            }
            Ok(Some(_)) => continue,
            _ => break,
        }
    }
    let public: SocketAddr = public
        .expect("reloaded tunnel was not registered")
        .parse()
        .unwrap();
    let mut sock = connect_retry(public).await;
    sock.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"ping");
    client.shutdown().await;
    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

fn reserve_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

async fn try_ping(addr: SocketAddr) -> bool {
    let Ok(mut sock) = TcpStream::connect(addr).await else {
        return false;
    };
    if sock.write_all(b"ping").await.is_err() {
        return false;
    }
    let mut buf = [0u8; 4];
    matches!(
        tokio::time::timeout(Duration::from_millis(800), sock.read_exact(&mut buf)).await,
        Ok(Ok(_)) if &buf == b"ping"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_reconnects_and_restores_tcp_mapping() {
    let id = identity();
    let control = reserve_port();
    let public = reserve_port();
    let body = format!(
        "tls_bind = \"127.0.0.1:{control}\"\n[acl]\nallow_any_port = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n"
    );
    let server = boot_server("correct-token", &body, &id).await;
    let echo = spawn_echo().await;
    let tunnels = format!(
        "[[tunnels]]\nname = \"echo\"\ntype = \"tcp\"\nlocal = \"{echo}\"\nremote_port = {public}\n"
    );
    let mut config = client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        &tunnels,
        SLOW_HEARTBEAT,
    );
    config.reconnect.enabled = true;
    config.reconnect.min_secs = 1;
    config.reconnect.max_secs = 4;
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );
    assert!(try_ping(format!("127.0.0.1:{public}").parse().unwrap()).await);

    server.shutdown().await.unwrap();
    let server = boot_server("correct-token", &body, &id).await;
    let addr: SocketAddr = format!("127.0.0.1:{public}").parse().unwrap();
    let mut restored = false;
    for _ in 0..24 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if try_ping(addr).await {
            restored = true;
            break;
        }
    }
    assert!(
        restored,
        "public mapping did not recover after control reconnect"
    );
    client.shutdown().await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_client_tunnel_limit_rejects_the_extra_mapping() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[acl]\nallow_any_port = true\n[limits]\nmax_tunnels = 1\nmax_streams = 8\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let echo = spawn_echo().await;
    let tunnels = format!(
        "[[tunnels]]\nname = \"one\"\ntype = \"tcp\"\nlocal = \"{echo}\"\nremote_port = 0\n[[tunnels]]\nname = \"two\"\ntype = \"tcp\"\nlocal = \"{echo}\"\nremote_port = 0\n"
    );
    let config = client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        &tunnels,
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );
    let allowed = endpoint_of(&events, "one");
    assert!(
        events.iter().any(|event| matches!(
            event,
            ClientEvent::RegisterFailed { name, reason, .. }
                if name == "two" && reason.contains("per-client tunnel limit")
        )),
        "{events:?}"
    );
    let public: SocketAddr = allowed.parse().unwrap();
    let mut sock = connect_retry(public).await;
    sock.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut buf))
        .await
        .expect("allowed tunnel timed out")
        .unwrap();
    assert_eq!(&buf, b"ping");
    client.shutdown().await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_rate_limit_slows_the_public_upload() {
    let id = identity();
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[acl]\nallow_any_port = true\n[limits]\nbytes_in_per_sec = 20000\nbytes_out_per_sec = 0\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let echo = spawn_echo().await;
    let tunnels = format!(
        "[[tunnels]]\nname = \"echo\"\ntype = \"tcp\"\nlocal = \"{echo}\"\nremote_port = 0\n"
    );
    let config = client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        &tunnels,
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );
    let public: SocketAddr = endpoint_of(&events, "echo").parse().unwrap();
    let mut sock = connect_retry(public).await;
    let payload = vec![0x5au8; 60_000];
    let started = std::time::Instant::now();
    sock.write_all(&payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(15), sock.read_exact(&mut got))
        .await
        .expect("throttled echo timed out")
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(got, payload);
    assert!(
        elapsed >= Duration::from_millis(1500),
        "20KB/s cap did not slow 60KB: {elapsed:?}"
    );
    sock.write_all(b"ping").await.unwrap();
    let mut tail = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut tail))
        .await
        .expect("tunnel closed after throttle")
        .unwrap();
    assert_eq!(&tail, b"ping");
    client.shutdown().await;
    server.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_stops_the_server_without_hanging() {
    let port = reserve_port();
    let dir = std::env::temp_dir().join(format!(
        "pharos-shutdown-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("server.toml");
    std::fs::write(
        &path,
        format!(
            r#"
token = "correct-token"
tls_bind = "127.0.0.1:{port}"
dev_ephemeral_cert = true
tcp_bind_ip = "127.0.0.1"
[shutdown]
drain_secs = 1
[heartbeat]
interval_secs = 15
timeout_secs = 45
"#
        ),
    )
    .unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_pharos-server"))
        .arg("-c")
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn pharos-server");
    let mut stdout = child.stdout.take().expect("stdout");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stdout.read(&mut tmp).unwrap_or(0);
            if n == 0 {
                let _ = ready_tx.send(false);
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(9).any(|window| window == b"listening") {
                let _ = ready_tx.send(true);
            }
        }
    });
    let ready = ready_rx
        .recv_timeout(Duration::from_secs(15))
        .unwrap_or(false);
    assert!(ready, "server did not report that it is listening");
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() > Duration::from_secs(8) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("server did not exit within 8s of SIGTERM");
            }
            Ok(None) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(err) => panic!("wait failed: {err}"),
        }
    };
    assert!(status.success(), "server exit status: {status}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_token_accepts_primary_and_list_entries() {
    let id = identity();
    let raw = format!(
        r#"
token = "primary-token"
dev_ephemeral_cert = true
tcp_bind_ip = "127.0.0.1"
tls_bind = "127.0.0.1:0"
[auth]
tokens = ["list-alpha", "list-beta"]
[acl]
allow_any_port = true
[heartbeat]
interval_secs = 15
timeout_secs = 45
"#
    );
    let mut config = ServerConfig::parse_toml(&raw).expect("server toml");
    config.cert_pem = Some(id.cert.clone());
    config.key_pem = Some(id.key.clone());
    config.dev_ephemeral_cert = false;
    let server = pharos_server::spawn(config).await.expect("spawn server");
    let addr = server.tls_addr.expect("tls");

    for token in ["primary-token", "list-alpha", "list-beta"] {
        let config = client_config(token, addr, "tls", &id.cert, "", SLOW_HEARTBEAT);
        let mut client = pharos_client::spawn(config).await.unwrap();
        let events = until_settled(&mut client).await;
        assert!(
            matches!(events.last(), Some(ClientEvent::Ready)),
            "token {token} should authenticate: {events:?}"
        );
        client.shutdown().await;
    }

    let config = client_config("wrong-token", addr, "tls", &id.cert, "", SLOW_HEARTBEAT);
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    match events.last() {
        Some(ClientEvent::SessionEnded { error: Some(error) }) => {
            assert!(
                error.contains("authentication failed"),
                "unexpected error: {error}"
            );
        }
        other => panic!("expected auth failure, got {other:?}"),
    }
    client.shutdown().await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_token_hot_reload_replaces_accepted_set() {
    let id = identity();
    let dir = std::env::temp_dir().join(format!(
        "pharos-token-reload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("server.toml");
    let initial = r#"
token = "old-token"
dev_ephemeral_cert = true
tcp_bind_ip = "127.0.0.1"
tls_bind = "127.0.0.1:0"
[acl]
allow_any_port = true
[heartbeat]
interval_secs = 15
timeout_secs = 45
"#;
    std::fs::write(&path, initial).unwrap();
    let mut config = ServerConfig::load_path(&path).expect("load server");
    config.cert_pem = Some(id.cert.clone());
    config.key_pem = Some(id.key.clone());
    config.dev_ephemeral_cert = false;
    let server = pharos_server::spawn(config).await.expect("spawn server");
    let addr = server.tls_addr.expect("tls");

    let config = client_config("old-token", addr, "tls", &id.cert, "", SLOW_HEARTBEAT);
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "old token before reload: {events:?}"
    );
    client.shutdown().await;

    let updated = r#"
token = "new-token"
dev_ephemeral_cert = true
tcp_bind_ip = "127.0.0.1"
tls_bind = "127.0.0.1:0"
[auth]
tokens = ["also-new"]
[acl]
allow_any_port = true
[heartbeat]
interval_secs = 15
timeout_secs = 45
"#;
    let tmp = dir.join("server.toml.tmp");
    std::fs::write(&tmp, updated).unwrap();
    std::fs::rename(&tmp, &path).unwrap();

    // Reload polls about every 400ms; wait until old token is rejected.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    let mut old_rejected = false;
    while tokio::time::Instant::now() < deadline {
        let config = client_config("old-token", addr, "tls", &id.cert, "", SLOW_HEARTBEAT);
        let mut client = pharos_client::spawn(config).await.unwrap();
        let events = until_settled(&mut client).await;
        client.shutdown().await;
        if matches!(
            events.last(),
            Some(ClientEvent::SessionEnded { error: Some(error) })
                if error.contains("authentication failed")
        ) {
            old_rejected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(old_rejected, "old token should fail after reload");

    for token in ["new-token", "also-new"] {
        let config = client_config(token, addr, "tls", &id.cert, "", SLOW_HEARTBEAT);
        let mut client = pharos_client::spawn(config).await.unwrap();
        let events = until_settled(&mut client).await;
        assert!(
            matches!(events.last(), Some(ClientEvent::Ready)),
            "token {token} after reload: {events:?}"
        );
        client.shutdown().await;
    }

    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

async fn spawn_hello_body(body: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(body).await;
            });
        }
    });
    addr
}

async fn http_get(addr: SocketAddr, host: &str) -> Vec<u8> {
    let mut sock = connect_retry(addr).await;
    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).await.unwrap();
    let mut body = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut body))
        .await
        .expect("http timed out")
        .unwrap();
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_wildcard_host_routing() {
    let id = identity();
    let origin = spawn_hello_body(b"wild-ok").await;
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[http]\nbind = \"127.0.0.1:0\"\n[acl]\nallow_any_hostname = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let http_addr = server.http_addr.expect("http");
    let tunnels = format!(
        "[[tunnels]]\nname = \"web\"\ntype = \"http\"\nlocal = \"{origin}\"\nhostname = \"*.example.com\"\n"
    );
    let config = client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        &tunnels,
        SLOW_HEARTBEAT,
    );
    let mut client = pharos_client::spawn(config).await.unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );

    let hit = http_get(http_addr, "app.example.com").await;
    assert!(
        hit.windows(7).any(|w| w == b"wild-ok"),
        "body: {}",
        String::from_utf8_lossy(&hit)
    );

    let other = http_get(http_addr, "app.other.com").await;
    assert!(
        String::from_utf8_lossy(&other).contains("404"),
        "{}",
        String::from_utf8_lossy(&other)
    );

    let nested = http_get(http_addr, "a.b.example.com").await;
    assert!(
        String::from_utf8_lossy(&nested).contains("404"),
        "single-label wildcard must not match nested host: {}",
        String::from_utf8_lossy(&nested)
    );

    client.shutdown().await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_exact_beats_wildcard() {
    let id = identity();
    let wild_origin = spawn_hello_body(b"from-wild").await;
    let exact_origin = spawn_hello_body(b"from-exact").await;
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[http]\nbind = \"127.0.0.1:0\"\n[acl]\nallow_any_hostname = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let http_addr = server.http_addr.expect("http");
    let tls = server.tls_addr.expect("tls");

    let wild_tunnels = format!(
        "[[tunnels]]\nname = \"wild\"\ntype = \"http\"\nlocal = \"{wild_origin}\"\nhostname = \"*.example.com\"\n"
    );
    let mut wild_client = pharos_client::spawn(client_config(
        "correct-token",
        tls,
        "tls",
        &id.cert,
        &wild_tunnels,
        SLOW_HEARTBEAT,
    ))
    .await
    .unwrap();
    assert!(matches!(
        until_settled(&mut wild_client).await.last(),
        Some(ClientEvent::Ready)
    ));

    let exact_tunnels = format!(
        "[[tunnels]]\nname = \"exact\"\ntype = \"http\"\nlocal = \"{exact_origin}\"\nhostname = \"app.example.com\"\n"
    );
    let mut exact_client = pharos_client::spawn(client_config(
        "correct-token",
        tls,
        "tls",
        &id.cert,
        &exact_tunnels,
        SLOW_HEARTBEAT,
    ))
    .await
    .unwrap();
    assert!(matches!(
        until_settled(&mut exact_client).await.last(),
        Some(ClientEvent::Ready)
    ));

    let body = http_get(http_addr, "app.example.com").await;
    assert!(
        body.windows(10).any(|w| w == b"from-exact"),
        "exact must beat wildcard: {}",
        String::from_utf8_lossy(&body)
    );
    let other = http_get(http_addr, "other.example.com").await;
    assert!(
        other.windows(9).any(|w| w == b"from-wild"),
        "wildcard still serves siblings: {}",
        String::from_utf8_lossy(&other)
    );

    exact_client.shutdown().await;
    wild_client.shutdown().await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_same_hostname_round_robin() {
    let id = identity();
    let a = spawn_hello_body(b"backend-a").await;
    let b = spawn_hello_body(b"backend-b").await;
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[http]\nbind = \"127.0.0.1:0\"\n[acl]\nallow_any_hostname = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let http_addr = server.http_addr.expect("http");
    let tls = server.tls_addr.expect("tls");

    let mut client_a = pharos_client::spawn(client_config(
        "correct-token",
        tls,
        "tls",
        &id.cert,
        &format!(
            "[[tunnels]]\nname = \"a\"\ntype = \"http\"\nlocal = \"{a}\"\nhostname = \"demo.local\"\n"
        ),
        SLOW_HEARTBEAT,
    ))
    .await
    .unwrap();
    assert!(matches!(
        until_settled(&mut client_a).await.last(),
        Some(ClientEvent::Ready)
    ));

    let mut client_b = pharos_client::spawn(client_config(
        "correct-token",
        tls,
        "tls",
        &id.cert,
        &format!(
            "[[tunnels]]\nname = \"b\"\ntype = \"http\"\nlocal = \"{b}\"\nhostname = \"demo.local\"\n"
        ),
        SLOW_HEARTBEAT,
    ))
    .await
    .unwrap();
    assert!(matches!(
        until_settled(&mut client_b).await.last(),
        Some(ClientEvent::Ready)
    ));

    let mut saw_a = false;
    let mut saw_b = false;
    for _ in 0..20 {
        let body = http_get(http_addr, "demo.local").await;
        if body.windows(9).any(|w| w == b"backend-a") {
            saw_a = true;
        }
        if body.windows(9).any(|w| w == b"backend-b") {
            saw_b = true;
        }
        if saw_a && saw_b {
            break;
        }
    }
    assert!(saw_a && saw_b, "expected both LB backends across requests");

    client_a.shutdown().await;
    // Give the server a moment to drop A's backend.
    tokio::time::sleep(Duration::from_millis(100)).await;
    for _ in 0..8 {
        let body = http_get(http_addr, "demo.local").await;
        assert!(
            body.windows(9).any(|w| w == b"backend-b"),
            "remaining backend should still serve: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            !body.windows(9).any(|w| w == b"backend-a"),
            "disconnected backend must not serve: {}",
            String::from_utf8_lossy(&body)
        );
    }

    client_b.shutdown().await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_wildcard_host_routing() {
    let id = identity();
    let origin = spawn_hello_body(b"https-wild").await;
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[https]\nbind = \"127.0.0.1:0\"\n[acl]\nallow_any_hostname = true\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let https_addr = server.https_addr.expect("https");
    let tunnels = format!(
        "[[tunnels]]\nname = \"web\"\ntype = \"http\"\nlocal = \"{origin}\"\nhostname = \"*.example.com\"\n"
    );
    let mut client = pharos_client::spawn(client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        &tunnels,
        SLOW_HEARTBEAT,
    ))
    .await
    .unwrap();
    assert!(matches!(
        until_settled(&mut client).await.last(),
        Some(ClientEvent::Ready)
    ));

    let connector = https_connector(&id.cert);
    let mut sock = https_connect(&connector, https_addr).await;
    sock.write_all(b"GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let body = read_http_body(&mut sock).await;
    assert!(
        body.windows(10).any(|w| w == b"https-wild"),
        "body: {}",
        String::from_utf8_lossy(&body)
    );

    let mut missing = https_connect(&connector, https_addr).await;
    missing
        .write_all(b"GET / HTTP/1.1\r\nHost: a.b.example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let denied = read_http_body(&mut missing).await;
    assert!(
        String::from_utf8_lossy(&denied).contains("404"),
        "{}",
        String::from_utf8_lossy(&denied)
    );

    client.shutdown().await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acl_allows_listed_wildcard_pattern() {
    let id = identity();
    let origin = spawn_hello_body(b"acl-wild").await;
    let server = boot_server(
        "correct-token",
        "tls_bind = \"127.0.0.1:0\"\n[http]\nbind = \"127.0.0.1:0\"\n[acl]\nallow_hostnames = [\"*.example.com\"]\n[heartbeat]\ninterval_secs = 15\ntimeout_secs = 45\n",
        &id,
    )
    .await;
    let tunnels = format!(
        "[[tunnels]]\nname = \"web\"\ntype = \"http\"\nlocal = \"{origin}\"\nhostname = \"*.example.com\"\n"
    );
    let mut client = pharos_client::spawn(client_config(
        "correct-token",
        server.tls_addr.expect("tls"),
        "tls",
        &id.cert,
        &tunnels,
        SLOW_HEARTBEAT,
    ))
    .await
    .unwrap();
    let events = until_settled(&mut client).await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Ready)),
        "{events:?}"
    );
    let body = http_get(server.http_addr.expect("http"), "app.example.com").await;
    assert!(
        body.windows(8).any(|w| w == b"acl-wild"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    client.shutdown().await;
    server.shutdown().await.unwrap();
}
