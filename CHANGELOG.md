# Changelog

## Unreleased

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
