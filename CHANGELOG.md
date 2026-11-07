# Changelog

## Unreleased

- Optional `metrics_token` on the server: when set, every request on `metrics_bind` (`/metrics`, `/health`, `/ready`) must present `Authorization: Bearer <token>` (401 + `WWW-Authenticate: Bearer` otherwise). Unset/empty keeps the previous open listener. Compared with the same constant-time digest path as tunnel tokens. Hot-reloaded; independent of the tunnel PSK. `metrics_bind` itself remains restart-only.

## 0.2.0 — 2026-11-07

- Management probes on `metrics_bind`: `GET /health` (liveness, always `200` while up) and `GET /ready` (`200` until drain, then `503`). Same listener as `/metrics`; unknown paths return `404`. No new bind key.
- Multi-token auth: keep top-level `token`, add optional `auth.tokens = ["…", "…"]`. The accepted set is their union; any match returns `AuthOk`. Empty auth is still forbidden in `token` / `token+mtls`. Hot reload replaces the whole accepted set for later handshakes (no per-token ACL).

- UDP reverse tunnels: client `type = "udp"` with `local` and `remote_port`. The server binds UDP on `tcp_bind_ip:remote_port`, opens one association stream per public peer, and forwards length-prefixed datagrams. `allow_ports` / `allow_any_port` apply to UDP as well as TCP. Idle associations time out after 60 seconds.
- Public HTTPS listener: optional `[https] bind` terminates TLS on the server and routes by `Host` on the same table as plaintext `[http]`. Certificates reuse the server identity unless `https.cert_file` / `https.key_file` override them. Clients keep `type = "http"`. `https.bind` and certs are restart-only.

## 0.1.0 — 2026-11-06

First release of Pharos. Workspace version `0.1.0`.

- `pharos-server` and `pharos-client` in one Cargo workspace. Apache-2.0. The wire protocol is in `PROTOCOL.md` and is not compatible with frp.
- PSK authentication on every session. `[auth] mode` is `token` (default), `mtls`, or `token+mtls`. The server checks client certificates against `auth.client_ca_file`. Token-only configs keep working. Anonymous tunnels are not implemented.
- TCP reverse tunnels, then HTTP routing by the `Host` header.
- QUIC by default, with a TLS-over-TCP fallback and `transport = "auto"`.
- TOML configuration and structured `tracing` logs. Session logs include `peer` and `tunnel`.
- Optional Prometheus text on `metrics_bind` (off by default): active tunnels, auth failures, streams opened, and public bytes in and out.
- Hot reload. The server applies token, ACL, heartbeat, and limit changes, and closes tunnels the ACL no longer allows. The client adds, removes, and retargets tunnels on the open control connection. Listener addresses, `metrics_bind`, certificates, and auth mode still need a restart.
- The client reconnects with exponential backoff after the control connection drops, then registers its tunnels again. Backoff resets after a session that became ready.
- Server concurrency caps: per-client `max_tunnels` / `max_streams` (defaults 64 and 256) and optional global caps (`0` means unlimited). Over-limit registrations and streams are rejected and counted.
- Per-client byte rates `bytes_in_per_sec` and `bytes_out_per_sec` (`0` means unlimited) throttle public traffic without closing the tunnel.
- Graceful shutdown. SIGINT and, on Unix, SIGTERM drain accepted streams for `shutdown.drain_secs` (default 5). The client does not reconnect during that window.
- CI runs `cargo test --workspace --locked` and a release build. See the build and release section of `README.md`.
