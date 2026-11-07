# Pharos

Pharos is a self-hosted intranet tunnel. A `pharos-client` inside the private network dials out to `pharos-server` and publishes local TCP and UDP services, including SSH, plus HTTP virtual hosts. Visitors connect to the server; the server bridges them back through the client.

Pharos（灯塔）是自建的内网穿透：客户端从内网主动连出，把本机 TCP/UDP 和按 Host 区分的 HTTP 服务发布到你自己的服务器上。协议是自研的，不兼容 frp，也不是 mesh VPN。

**Version 0.2.0.** That is the workspace version in `Cargo.toml`, the heading in [CHANGELOG.md](CHANGELOG.md), and the product line in [PROTOCOL.md](PROTOCOL.md) and [SECURITY.md](SECURITY.md).

## What it is not

- Not a WireGuard or Tailscale-style mesh.
- Not an frp-compatible agent. The frame layout is in [PROTOCOL.md](PROTOCOL.md).
- Not a hosted SaaS. You run the server.

## How it compares

| | Pharos | frp | rathole | Cloudflare Tunnel | chisel |
|---|---|---|---|---|---|
| License | Apache-2.0 | Apache-2.0 | Apache-2.0 | Apache-2.0 | MIT |
| You run the server | Yes | Yes | Yes | No, traffic goes to Cloudflare | Yes |
| Wire protocol | Pharos frames | frp | Noise | Cloudflare's QUIC | SSH or WebSocket |
| Default transport | QUIC, TLS/TCP fallback | TCP (also KCP, QUIC, WebSocket) | TLS | QUIC | HTTP |
| Auth in this version | PSK, optional mTLS | Token | Noise public key | Cloudflare account | SSH user or key |
| HTTP `Host` routing | Yes | Yes | No, it forwards ports | Yes | HTTP reverse proxy |

## Install

Rust 1.88 or newer (stable is the intended toolchain; `rust-toolchain.toml` selects stable). From a checkout:

```bash
cargo build --release --locked
```

The binaries are `target/release/pharos-server` and `target/release/pharos-client`.

## Build and release

The locked check and the release build are one script:

```bash
bash scripts/ci.sh
```

That runs `cargo test --workspace --locked`, then `cargo build --workspace --release --locked`.

Continuous integration has two paths, because this repository is hosted on Origin and is not a GitHub mirror:

| Path | Where it runs | Platforms |
|---|---|---|
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | GitHub Actions, and on Origin after the Depot or Buildkite app is connected from the repository Apps tab | `ubuntu-latest`, `macos-latest`, `windows-latest` |
| [`origin.ci.ts`](origin.ci.ts) | Origin CI, which reads only this file | Linux, image `rust:bookworm` |

Origin does not execute `.github/workflows` by itself. The Actions workflow is still the cross-platform definition: each OS runs `scripts/ci.sh` and uploads `pharos-server` and `pharos-client`. A tag whose name starts with `v` also opens a GitHub Release with those binaries when the workflow runs on GitHub. Origin CI runs the same script on Linux and does not publish a release.

Tag by hand after the versions match. Do not tag until `Cargo.toml` (`version = "0.2.0"`), the version line at the top of this file, and the `0.2.0` heading in `CHANGELOG.md` are the same.

```bash
cargo test --workspace --locked
git tag -a v0.2.0 -m "Pharos 0.2.0"
git push origin v0.2.0
```

On Origin, the tag is the release. The GitHub Release job does not run there. Attach binaries from a local `cargo build --workspace --release --locked` if you need them next to the tag.

## Loopback demo

The sample configs listen only on `127.0.0.1`, use a throwaway token, and set `tls_insecure` / `dev_ephemeral_cert`. Read [SECURITY.md](SECURITY.md) before pointing either process at a real network.

Terminal 1, a local TCP echo:

```bash
python3 examples/echo.py
```

Terminal 2, the server (QUIC and TLS on port 7600, HTTP on 7680):

```bash
./target/release/pharos-server -c examples/server.toml
```

Terminal 3, the client. It tries QUIC first, then TLS:

```bash
./target/release/pharos-client -c examples/client.toml
```

Terminal 4, through the published port:

```bash
python3 -c 'import socket; s=socket.create_connection(("127.0.0.1", 2222), 5); s.sendall(b"ping"); print(s.recv(4))'
```

That prints `b'ping'`. For HTTP, start an origin and request it by name:

```bash
python3 -m http.server 3000 --bind 127.0.0.1
curl -sS -H 'Host: demo.local' http://127.0.0.1:7680/
# With [https] bind = "127.0.0.1:7443" and the lab cert:
# curl -sS --cacert pharos-dev.crt -H 'Host: demo.local' https://127.0.0.1:7443/
```

`demo.local` does not need a DNS record. The server routes on the `Host` header. Any other name gets `404`.

To verify the certificate instead of skipping it, point the client at the `pharos-dev.crt` the server writes next to `examples/server.toml`:

```toml
tls_insecure = false
ca_file = "examples/pharos-dev.crt"
```

## Configuration

Both programs take `-c FILE`. The client always needs a non-empty `token`. On the server, `token` and/or `auth.tokens` must supply at least one non-empty secret when `auth.mode` is `token` or `token+mtls`.

Server (see `examples/server.toml`):

- `quic_bind` and `tls_bind` are independent. Set either or both. QUIC is UDP, TLS is TCP, so they can share a port number.
- `cert_file` and `key_file` are the production identity. `dev_ephemeral_cert = true` is only for a lab.
- `[acl]` lists `allow_ports` and `allow_hostnames`. `allow_ports` covers both TCP and UDP `remote_port` values. If the list is empty and the matching `allow_any_*` flag is false, that class of tunnel is denied.
- `[http] bind` is the public HTTP listener. Without `[http]` and without `[https]`, `type = "http"` registrations fail.
- `[https] bind` is an optional public HTTPS listener. The server terminates TLS there and routes by `Host` on the same table as `[http]`. Certificates default to the server `cert_file` / `key_file` (or `dev_ephemeral_cert`); set `https.cert_file` and `https.key_file` to override. The client still uses `type = "http"` with a plaintext local origin.
- `tcp_bind_ip` is the address used for reverse TCP and UDP ports.
- `metrics_bind` is off unless set. See [Metrics](#metrics).
- `token` is the primary pre-shared secret. Optional `auth.tokens = ["…", "…"]` adds more accepted secrets; any match authenticates. The accepted set is the union of a non-empty `token` and every `auth.tokens` entry.
- `[heartbeat]` closes a session that receives no frame for `timeout_secs`. The server re-reads the accepted token set, ACL, and heartbeat from the file every couple of seconds. Bind addresses stay as they were at startup.

Client (see `examples/client.toml`):

- `server` is `host:port`. `server_name` is the name checked against the certificate.
- `transport` is `auto` (default), `quic`, or `tls`.
- `ca_file` trusts the server certificate. `tls_insecure = true` does not.
- `[auth] mode` is `token` (default), `mtls`, or `token+mtls`. See [mTLS](#mtls) below.
- Each `[[tunnels]]` entry is `type = "tcp"` or `type = "udp"` with `local` and `remote_port`, or `type = "http"` with `local` and `hostname`. `local` is `host:port`, for example `127.0.0.1:22`. UDP opens one association stream per public peer and closes it after 60 seconds idle.
- The client reconnects with exponential backoff unless `reconnect.enabled = false`.

A TCP or UDP tunnel with `remote_port = 0` asks for an ephemeral port. The server only allows that when `allow_any_port = true`, and it reports the chosen port in the log.

## mTLS

Client certificates are optional until you ask for them. The default `auth.mode = "token"` is unchanged: only the PSK is checked, and the server does not request a certificate.

| `auth.mode` | PSK | Client certificate |
|---|---|---|
| `token` | required | not requested |
| `mtls` | ignored (may be `""`) | required |
| `token+mtls` | required | required |

The server trusts client certificates that chain to `auth.client_ca_file`. The client presents `auth.cert_file` and `auth.key_file`, and still uses `ca_file` to trust the server. A certificate from any other CA fails the QUIC or TLS handshake. In `token+mtls`, a good certificate with the wrong token still gets `AuthFail`.

Create a lab set:

```bash
bash examples/gen-mtls-certs.sh
./target/release/pharos-server -c examples/mtls-server.toml
./target/release/pharos-client -c examples/mtls-client.toml
```

`examples/mtls-server.toml` is `token+mtls` on `127.0.0.1:7601`. To use certificates alone, set `mode = "mtls"` on both sides and `token = ""`. Changing `mode` or the client CA needs a restart.

## Hot reload

Both processes re-read their config file about twice a second. A file that fails to parse is ignored and the previous settings stay in effect.

The server applies a new accepted token set (`token` plus `auth.tokens`), the ACL (`allow_ports`, `allow_hostnames`, and the `allow_any_*` flags), and heartbeat intervals without dropping live sessions. A port or hostname removed from the ACL stops accepting new connections immediately. Adding a port to the ACL does not publish it by itself; the client still has to register that mapping.

The client applies tunnel list edits on the open control connection: new `[[tunnels]]` entries are registered, removed entries are unregistered, and a changed `local` address is used for the next stream. Changing `remote_port`, `hostname`, or `type` unregisters the old mapping and registers the new one. `server`, `token`, `transport`, and `auth.mode` stay as they were for the current session. The next automatic reconnect reads them from the file. Set `reconnect.enabled = false` when a live session must ignore the file until you restart the process.

These are read at startup only and need a restart: `quic_bind`, `tls_bind`, `http.bind`, `https.bind`, `metrics_bind`, `tcp_bind_ip`, certificate files (including `https.cert_file` / `https.key_file`), `auth.mode`, and `auth.client_ca_file`. `metrics_bind` in particular is not switched on or moved by a reload, so a config edit cannot open that port by surprise.

## Reconnect

With `reconnect.enabled = true` (the default), the client dials again after the control connection drops: network loss, a server restart, or a heartbeat timeout. `reconnect.min_secs` (default 1) and `reconnect.max_secs` (default 30) bound an exponential backoff with jitter. A session that reached ready resets the next wait to `min_secs`. Each new session registers the configured tunnels again. In-flight visitor connections are not resumed; with a fixed `remote_port` the same public port accepts new connections after registration. `remote_port = 0` may bind a different port after each reconnect.

Reconnect logs include `attempt`, `backoff_ms`, and `reason`. A clean interrupt stops the process and does not dial again. `server`, `token`, `transport`, and `auth.mode` are taken from the config file on that new dial. They are not swapped on the connection that is already up. Certificate material supplied only in memory, not in the file, is kept across that reload.

## Limits

`[limits]` caps how much one client, and optionally every client together, may publish.

| Field | Default | Meaning |
|---|---|---|
| `max_tunnels` | 64 | Active tunnels for one authenticated client |
| `max_streams` | 256 | Concurrent data streams for one client |
| `max_tunnels_global` | 0 | Active tunnels across all clients |
| `max_streams_global` | 0 | Concurrent data streams across all clients |

`0` means that cap is off. A new `RegisterTunnel` past a tunnel cap is answered with `RegisterFail` and code 7. A new public connection past a stream cap is closed and logged. Neither failure drops the control connection, and tunnels already under the cap keep forwarding. `pharos_limits_rejected_total` counts both kinds of refusal. Editing `[limits]` in the server file applies to later registrations and streams.

`bytes_in_per_sec` and `bytes_out_per_sec` are per-client token buckets on the public side of every tunnel that client owns. `0` (the default) means unlimited. Over the rate, forwarding waits; the tunnel stays up. A one-second burst is allowed so small interactive writes are not delayed. `pharos_throttle_events_total` counts those waits, and the log line is `throttling client bandwidth`.

## Shutdown

`SIGINT` (Ctrl+C) and, on Unix, `SIGTERM` start a drain. The server stops accepting public connections and new tunnel registrations. The client does not dial again. Streams that are already open may finish until `[shutdown] drain_secs` (default 5). Then the process forces an exit. `drain_secs = 0` skips the wait. Logs use `phase = "draining"` and then `phase = "stopped"`. Windows handles Ctrl+C; a service stop signal is not available there.

## Logging

Logs go through `tracing`. `RUST_LOG` overrides the filter in the config file. `[log] format = "json"` switches to one JSON object per line. The token is not a log field.

Session and forward paths carry `peer` and, once a tunnel is chosen, `tunnel` (the configured name, or the HTTP `Host`). A `session` span covers an authenticated connection. Each public TCP connection is a `tunnel_stream` span. Each UDP peer association is a `udp_assoc` span. Each HTTP connection is an `http_proxy` span. Each HTTPS connection is an `https_proxy` span.

## Metrics

Leave `metrics_bind` unset and the server does not open a metrics port. Set it to scrape Prometheus text and to expose process probes on the same listener (no separate bind):

```toml
metrics_bind = "127.0.0.1:9099"
```

| Path | Methods | Meaning |
|---|---|---|
| `/metrics` | GET, HEAD | Prometheus text exposition |
| `/health` | GET, HEAD | Liveness. Always `200` + `ok` while the process is up, including during graceful drain |
| `/ready` | GET, HEAD | Readiness. `200` + `ready` while accepting work; `503` + `not ready` once drain starts |

`GET /metrics` includes, among others:

| Series | Kind | Meaning |
|---|---|---|
| `pharos_tunnels_active` | gauge | Tunnels held by connected clients |
| `pharos_auth_failure_total` | counter | Bad tokens and failed QUIC/TLS handshakes |
| `pharos_streams_opened_total` | counter | Data streams opened toward a client |
| `pharos_bytes_in_total` | counter | Bytes read from public connections |
| `pharos_bytes_out_total` | counter | Bytes written to public connections |

The scrape and probes have no authentication of their own. Bind `metrics_bind` to a trusted address (localhost or a management network). The exposition does not contain the token or certificate material. Changing `metrics_bind` still needs a restart.

## Tests

```bash
cargo test --workspace
```

The integration tests bring up a real server and client on `127.0.0.1` and cover rejected tokens, accepted tokens (including multi-token and token-set hot reload), TCP and UDP echo over TLS and over QUIC, ACL denials, HTTP/HTTPS host routing (including an unknown host), and an idle heartbeat timeout.

## Further reading

- [PROTOCOL.md](PROTOCOL.md) — frame bytes
- [SECURITY.md](SECURITY.md) — what the transport does and does not protect
- [CHANGELOG.md](CHANGELOG.md)
- [docs/design.md](docs/design.md) — product design notes

## License

Apache-2.0. See [LICENSE](LICENSE).
