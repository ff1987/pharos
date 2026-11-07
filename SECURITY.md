# Security

Pharos publishes a machine that is otherwise private. Treat a running server as a remote-access service.

## What 0.2.0 guarantees

- There is no anonymous mode. `auth.mode` is `token` (default), `mtls`, or `token+mtls`.
- `token` and `token+mtls` require at least one pre-shared secret from the top-level `token` and/or `auth.tokens`. An empty accepted set is rejected at startup for those modes. Each presented secret is hashed with SHA-256 and compared against every configured digest without an early exit on the raw strings.
- `mtls` and `token+mtls` require a client certificate signed by `auth.client_ca_file`, with the clientAuth extended key usage. rustls checks the chain before any Pharos frame is read. A wrong certificate fails the handshake. `mtls` does not check the token; keep a token as well with `token+mtls` unless you have decided certificates are the only credential.
- Logs record the peer address and the result. They do not record the token or private keys.
- The control connection is QUIC or TLS with ALPN `pharos/1`. Certificate verification is on unless the client sets `tls_insecure = true`.
- The server ACL is fail-closed. A TCP or UDP `remote_port` is published only if it is listed in `allow_ports` or `allow_any_port` is set. An HTTP hostname or `*.suffix` pattern is published only if that exact string is listed in `allow_hostnames` (case-insensitive) or `allow_any_hostname` is set. Listing a wildcard does not imply every concrete name under it. `remote_port = 0` (ephemeral) requires `allow_any_port`.
- Frame sizes, tunnel counts, and concurrent streams are capped. A bad mandatory frame closes the session.
- The server can re-read the accepted token set, ACL, and heartbeat settings from the config file. A broken file keeps the previous settings. Listener addresses do not change until restart.

## What you must do

- Generate long random tokens and keep `server.toml` and `client.toml` readable only by the accounts that run Pharos. Anyone with an accepted token can register any tunnel the ACL allows. In `token+mtls` they also need a certificate from your client CA. Protect `client.key` the same way. Use `auth.tokens` (with or without top-level `token`) when rotating secrets so more than one value is valid during a cutover.
- `auth.mode` and `auth.client_ca_file` are applied when the process starts. Reloading the file updates the accepted token set, ACL, and heartbeat only. Restart to turn mTLS on or to rotate the client CA.
- Use a certificate you control (`cert_file` / `key_file` on the server, `ca_file` on the client). `dev_ephemeral_cert = true` writes `pharos-dev.crt` and is a lab identity. `tls_insecure = true` accepts any certificate and is a machine-in-the-middle hole; the client logs a warning when it is set.
- Leave `allow_any_port` and `allow_any_hostname` off outside tests. List the ports, exact hostnames, and `*.suffix` patterns you mean to expose.
- Bind the server where you intend it to be reachable. The examples listen on `127.0.0.1` on purpose.
- Remember the server operator can see tunneled bytes. QUIC and TLS protect the path between `pharos-client` and `pharos-server`. They are not end-to-end encryption between a visitor and the origin service. Put TLS on the origin itself when the bytes are sensitive.
- Optional `[https]` terminates visitor TLS on the server, then forwards plaintext HTTP through the tunnel to the client origin. That is edge TLS, not end-to-end HTTPS to the origin. The control-plane certificate (and optional `https.cert_file`) is what visitors see.
- Prefer QUIC. The TLS fallback multiplexes every stream on one TCP connection, so a stalled consumer delays the others.
- UDP associations are idle-timed (60 seconds). There is no authenticity check on public UDP datagrams beyond reaching the published port; treat UDP tunnels like any other open UDP service.

## Hot reload

A reload can change the accepted token set (`token` and `auth.tokens`), `metrics_token`, the ACL, and heartbeat timers. Removing a port or hostname from the ACL closes that published listener even if a client registered it earlier. It cannot change where the process listens. `quic_bind`, `tls_bind`, `http.bind`, `https.bind`, `metrics_bind`, `tcp_bind_ip`, certificate files (including optional `https.cert_file` / `https.key_file`), `auth.mode`, and the client CA stay as they were at startup; restart the process to apply them. That includes turning metrics on or moving `metrics_bind`. A bad config file does not replace the settings that are already running.

The client can add, remove, and retarget tunnels on the existing control connection. A new server address, token, transport, or auth mode is not applied to that connection. The next automatic reconnect reads them from the config file. Set `reconnect.enabled = false` to keep dialing with the settings from process start until you restart the client. Reconnect does not splice visitor sockets back together; those connections end when the control session ends.

## Limits

`[limits]` is the concurrency hook. `max_tunnels` and `max_streams` apply to each authenticated client (defaults 64 and 256). `max_tunnels_global` and `max_streams_global` apply to the whole process and default to `0`, which means no global cap. A client that hits a cap is refused only for the new tunnel or stream; its control connection and the mappings already accepted stay up. The refusal is logged with `scope` `per-client` or `global` and counted in `pharos_limits_rejected_total`.

`bytes_in_per_sec` and `bytes_out_per_sec` throttle one client's public traffic instead of cutting it. They default to `0` (unlimited). A client sharing several tunnels shares one bucket in each direction. Throttle waits are logged and counted in `pharos_throttle_events_total`. This is a coarse byte rate, not a guarantee against bursts of one second.

## Metrics

`metrics_bind` is off by default. The same TCP HTTP listener serves `GET /metrics`, `GET /health`, and `GET /ready` (HEAD is accepted too). It does not check the tunnel PSK. When `metrics_token` is unset or empty, anyone who can open that port can see tunnel counts, auth-failure counts, stream counts, and coarse byte totals, and can read liveness/readiness — bind it to localhost or a management network, not the public tunnel address. When `metrics_token` is set, every request on that listener must present `Authorization: Bearer <token>` (missing or wrong yields `401` with `WWW-Authenticate: Bearer`); use a different secret from the tunnel PSK. Enabling `metrics_token` is recommended whenever the bind is not loopback-only. The exposition does not include tokens, keys, or certificate bytes. Logs add `peer` and `tunnel` and likewise omit secrets.

## Threat notes

| Threat | 0.1 behavior |
|---|---|
| Anonymous tunnel | Rejected. `AuthFail`, then the connection closes. |
| Stolen token, `token` mode | Full use of the ACL until you remove that secret from `token` / `auth.tokens`. Reloading the file updates the accepted set for later handshakes. |
| Stolen token, `token+mtls` | Useless without a certificate signed by the configured client CA. |
| Client certificate from another CA | Handshake fails. No tunnel is registered. |
| Guessing the token | Same error string for every failure. Every configured secret is hashed and compared; the match index is not leaked by an early return on the raw strings. |
| Unsolicited public port | Not bound. Ports are bound only after a successful register, and accept starts only after `SessionReady`. |
| Oversized frame | Rejected before the payload is buffered past 1 MiB. |
| Connection exhaustion | Per-client and global tunnel and stream caps. Extra `RegisterTunnel` frames get `RegisterFail`. Extra public connections are closed. See `[limits]`. |
| Silent or half-dead peer | Dropped after `heartbeat.timeout_secs` without a frame. |
| Malicious client after auth | Still constrained by the ACL, the stream cap, and the server's bind address. |

Richer per-tunnel quotas and identity are later. Do not put an unauthenticated listener in front of this protocol and call it Pharos. `tls_insecure` does not skip the client-certificate check when the server requires mTLS.

## Reporting

Open a private security report with the maintainers of the repository you cloned. Give the version (`pharos-server --version`), the transport, and enough of a config to reproduce the issue with the token redacted.
