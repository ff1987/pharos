# Pharos protocol

Version 1. This document is the wire contract for `pharos-server` and `pharos-client` 0.2.0. The protocol is original. It does not speak frp, rathole, chisel, or WireGuard.

## Transport

A session is one encrypted connection:

| Mode | Socket | How streams are carried |
|---|---|---|
| QUIC (default) | UDP | Control frames on the client-opened bidirectional stream. Each TCP, HTTP, or UDP association is a new bidirectional QUIC stream: a single `OpenStream` frame, a single `StreamReady` frame, then the data plane below. |
| TLS | TCP | Every control message and every data chunk is a frame on the one TLS connection. |

Both modes use ALPN `pharos/1`. There is no anonymous mode. The default is a pre-shared token. `auth.mode = "mtls"` or `"token+mtls"` also requires a client certificate during this handshake, before any frame is read.

QUIC is preferred. A client with `transport = "auto"` tries QUIC for a few seconds, then connects with TLS. `transport = "quic"` or `transport = "tls"` forces one.

## Frame layout

Every frame, including the header on a QUIC data stream, is:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| version       | type          | length (uint32 big-endian)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| length cont.  | payload (length bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Rule |
|---|---|---|
| version | u8 | `1`. Any other version is fatal. |
| type | u8 | See the table below. |
| length | u32 BE | Payload size. Maximum `1_048_576` (1 MiB). Larger lengths are fatal and the connection closes. |
| payload | bytes | Type-specific. |

Integers are big-endian. A string is a u16 length followed by that many UTF-8 bytes, and the length must be ≤ 4096.

### Types

| Value | Name | Direction | Payload |
|---|---|---|---|
| 1 | Hello | both | `u16 major, u16 minor, u8 role, string name` |
| 2 | Auth | client → server | `string token` |
| 3 | AuthOk | server → client | `u64 session_id, u32 heartbeat_interval_ms` |
| 4 | AuthFail | server → client | `u16 code, string reason` |
| 5 | RegisterTunnel | client → server | `string name, u8 kind, string local, u16 remote_port, string hostname` |
| 6 | RegisterOk | server → client | `string name, u32 tunnel_id, string public_endpoint` |
| 7 | RegisterFail | server → client | `string name, u16 code, string reason` |
| 8 | Heartbeat | both | `u64 monotonic_ms` |
| 9 | HeartbeatAck | both | `u64 echo_monotonic_ms` |
| 10 | OpenStream | server → client | `u32 stream_id, u32 tunnel_id` |
| 11 | StreamReady | client → server | `u32 stream_id` |
| 12 | Data | both, TLS only | `u32 stream_id` then the raw chunk |
| 13 | Close | both | `u32 stream_id, u16 reason` |
| 14 | Error | both | `u16 code, string message` |
| 15 | SessionReady | client → server | empty |
| 16 | ReadyAck | server → client | empty |
| 17 | Unregister | both | `string name, u32 tunnel_id` |
| 18 | UnregisterOk | server → client | `string name, u32 tunnel_id` |

`kind` is `1` for TCP, `2` for HTTP, and `3` for UDP. `role` is `1` for the client and `2` for the server. Major `1` is the only major this document defines. Minor is informational in 0.1 (`0`).

Types `0x80` through `0xFE` are optional. A peer that does not recognize one skips it. Every other unknown type is fatal: the receiver sends `Error` and closes. `0xFF` is reserved and fatal.

### Error codes

| Code | Meaning |
|---|---|
| 1 | Bad version |
| 2 | Authentication failed |
| 3 | ACL denied |
| 4 | Bind failed (port in use, or hostname taken) |
| 5 | Bad frame |
| 6 | Feature not available (for example HTTP with no HTTP listener) |
| 7 | Tunnel or stream limit |
| 8 | Bad request |

`Close.reason`: `0` normal end, `1` local dial failed, `2` timeout, `3` reset.

Authentication failures use a fixed reason string. The server does not say whether the token was empty, short, or almost right.

## Session

1. Client sends `Hello` (`major = 1`, `role = 1`).
2. Server checks the major. On success it sends `Hello` (`role = 2`). On failure it sends `Error` and closes.
3. Client sends `Auth`. In `token` and `token+mtls` the payload is the pre-shared token. In `mtls` the payload may be empty; the certificate already authenticated the peer.
4. When the mode checks a token, the server compares SHA-256 digests in constant time and sends `AuthOk` or `AuthFail`. `AuthFail` ends the session. A certificate the server does not trust never reaches this step: rustls aborts the QUIC or TLS handshake, so there is no `AuthFail` frame.
5. Client sends one `RegisterTunnel` at a time and waits for `RegisterOk` or `RegisterFail`.
6. Client sends `SessionReady` only after it can accept `OpenStream`.
7. Server starts accepting public connections, then sends `ReadyAck`.

After `ReadyAck` the same control connection stays up. The client may send more `RegisterTunnel` frames to add or replace a mapping, and `Unregister` to remove one. The server answers `UnregisterOk`. The server also sends `Unregister` when a reload removes that port or hostname from the ACL. Changing only the client's `local` address does not need a frame; the next stream dials the new address. Existing streams stay on the sockets they already opened.

Public traffic before `SessionReady` is not forwarded. That keeps `OpenStream` from racing the client's tunnel table.

`remote_port = 0` asks for an ephemeral TCP or UDP port. The server allows it only when `allow_any_port` is set, and `RegisterOk.public_endpoint` is the bound `ip:port`. HTTP's `public_endpoint` is `{hostname} via {http listener}`.

Either side may send `Heartbeat`. The peer answers with `HeartbeatAck` echoing `monotonic_ms`. Any received frame resets the idle timer. If no frame arrives within `heartbeat.timeout_secs`, the session closes.

## Data plane

### TLS multiplex

`OpenStream`, `StreamReady`, `Data`, and `Close` share the control connection. `Data` chunks are at most 16 KiB. A slow stream blocks the single TCP connection (head-of-line). QUIC does not have that limitation.

The server registers the stream, sends `OpenStream`, and waits up to 10 seconds for `StreamReady` or `Close`. The client dials `local`, then sends `StreamReady`, then copies bytes in both directions. EOF sends `Close` with reason `0`.

### QUIC streams

The server calls open on a new bidirectional stream and writes one `OpenStream` frame. The client dials `local`, writes one `StreamReady` frame, and both sides then copy raw bytes for the rest of that stream. `Data` frames on the QUIC control stream are a protocol error.

### HTTP

The server reads the request head (up to 16 KiB, up to the first `\r\n\r\n`), takes the hostname from `Host`, and ignores a trailing `:port` or the brackets of an IPv6 literal. A known host is bridged to that tunnel, including the bytes already read. An unknown host gets `404` and the connection closes. A missing host gets `400`. A full stream table gets `503`.

### UDP

UDP reuses `OpenStream` / `StreamReady` / `Close` (and TLS `Data` frames). The server binds a UDP socket on `tcp_bind_ip:remote_port`. Each distinct public peer address becomes one association stream toward the client. After `StreamReady`, both sides exchange length-prefixed datagrams: `u16` big-endian length, then that many payload bytes (at most 65535). The ACL field `allow_ports` covers UDP `remote_port` the same way it covers TCP. An association that forwards no datagram for 60 seconds is closed with `Close.reason = timeout` (or the QUIC stream is shut down). There is no connection teardown signal from UDP itself.

## Limits

Defaults are 64 tunnels and 256 concurrent streams per session. Frames over 1 MiB are rejected. The handshake must finish within 10 seconds.
