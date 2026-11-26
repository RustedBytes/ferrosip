# sip-transport

The network layer of ferrosip. It receives SIP messages from the network and
sends them out again. You use it to set up listeners, tune connection limits
and configure TLS and WebSocket. It contains:

- the UDP [workers](../../docs/glossary.md#worker);
- the TCP/TLS connection manager;
- [WebSocket](../../docs/glossary.md#websocket) (WS/WSS, RFC 7118) on top of
  that connection manager;
- the TLS configuration;
- `Net`, the send-side API (`sip_core::Outbound`). Every worker, module and
  timer thread sends through it.

It corresponds to [Kamailio](../../docs/glossary.md#kamailio)'s
`udp_server.c`, `tcp_main.c` / `tcp_read.c`, the `tls` module and the
`websocket` module (`ws_handshake.c`, `ws_frame.c`).

It depends on `sip-parser` and `sip-core`, plus `mio`, `socket2`, `rustls`
with the `ring` provider, `flate2`, `memchr` and `bumpalo`. Other parts use
it like this:

- `bin/ferrosip` calls `start()` with the compiled script as the `Handler`.
- `tools/sipflood` reuses the TLS loader and the WebSocket codec.
- the `ws` fuzz target exercises `ws.rs`.

The routing logic never sees the transport, except through `ctx.src.proto`.
The crate is `#![forbid(unsafe_code)]`.

## Contents

| File | Provides |
|---|---|
| `src/lib.rs` | `Config`, `Listen`, `start()`, `Net` (implements `Outbound`), the shared `dispatch` (parses and runs the handler) and the `core:*` receive counters |
| `src/udp.rs` | `bind_reuseport`, `run_workers`: one `SO_REUSEPORT` socket and one thread per UDP worker |
| `src/tcp.rs` | `TcpOpts`, `TcpService`, `Conn`: the `tcp-main` accept thread, the `tcp-reader-N` epoll threads, the connection table, async connects and writes, WebSocket session handling |
| `src/tls.rs` | `TlsFiles`, `TlsConfig`, `load()`: rustls server and client configs, SNI certificates, profiles in the style of `tls.cfg`, session resumption |
| `src/ws.rs` | A pure WebSocket codec: `server_handshake`, `client_request` / `client_handshake`, `parse_frame`, `frame_header`, `encode`, `apply_mask`, permessage-deflate (`negotiate_deflate`, `Inflater`, `with_deflated`) |

## Key types and APIs

### Starting the transports

```rust
use sip_transport::{Config, Listen, TcpOpts, TlsFiles};

let cfg = Config {
    listen: vec![Listen::parse("udp:127.0.0.1:5060")?, Listen::parse("tls:127.0.0.1:5061")?],
    udp_workers: 4,
    tcp: TcpOpts { readers: 2, ..TcpOpts::default() },
    tls: TlsFiles { cert: Some("server.pem".into()), key: Some("server.key.pem".into()), ..Default::default() },
    advertise_ip: None,
};
// handler: Arc<dyn sip_core::Handler>, e.g. the sip_script::Live engine
let (net, threads) = sip_transport::start(&cfg, handler)?;
```

`start()` does four things:

1. It binds every listener. Bind errors are returned before any thread
   starts.
2. It loads TLS when a `tls:`/`wss:` listener exists or any TLS file is
   given.
3. It spawns the workers.
4. It returns the shared `Arc<Net>` and the thread handles.

A thread that can't be started is an error too. So is a listener that can't
be registered with the accept poller. `ferrosip` exits with that error.

`Listen::parse` takes `udp:`, `tcp:`, `tls:`, `ws:` or `wss:` followed by
`ip:port`. A bare `ip:port` is UDP. `advertise_ip` replaces the bind address
in our [Via](../../docs/glossary.md#via). This is Kamailio's `advertise`.

### `Net` (the `Outbound` implementation)

- `send(&dst, data)`: applies the `sip-core` send filter and taps. Then it
  does a UDP `send_to` on the first UDP socket, or a `TcpService::send` for
  stream protocols. UDP workers send replies on their own socket via
  `Ctx::send`.
- `advertise(proto)`: the address to put in our Via. When no listener exists
  for that transport, it falls back to any listener's address. An example is
  TLS that is only used outbound.
- `accepts_aliases()` / `add_alias(conn, addr)`: RFC 5923 connection reuse.
  `dispatch` aliases the Via *port* on the connection's own source IP. The
  Via host is controlled by the peer and is never trusted.
- `conn_to(dst)`: the open connection that a send to `dst` would use now.
  [tm](../../docs/glossary.md#tm) uses it to ignore close events for an
  address that already has a newer connection.
- `net.tcp()` gives the `TcpService`. It has `active_connections()`, and
  `close_all()` for [graceful shutdown](../../docs/glossary.md#graceful-shutdown).
  `close_all()` sends a TLS close_notify, then closes.

### `TcpOpts`

The fields are named after the Kamailio core parameters:

| Field | Kamailio | Default |
|---|---|---|
| `readers` | `tcp_children` | 2 (`bin/ferrosip` uses half the CPUs, rounded up) |
| `max_connections` | `tcp_max_connections` | 4096 |
| `connection_lifetime` | `tcp_connection_lifetime` | 120 s |
| `conn_wq_max` | `tcp_conn_wq_max` | 256 KiB |
| `max_msg_size` | – | 64 KiB |
| `connect_timeout` | `tcp_connect_timeout` | 10 s |
| `keepalive` | `tcp_keepalive` + `tcp_keepidle` | off |
| `accept_aliases` | `tcp_accept_aliases` | false |
| `ws` | – | `WsOpts { allowed_origins: [], deflate: false }` |

### TLS (`tls.rs`)

`TlsFiles` holds `cert`, `key`, `ca`, `verify_client`, `sni` (name, cert,
key), `profile`, `session_cache` and `tickets`.

`tls::load(&files, need_server)` returns a `TlsConfig`. It has the default
`server` / `client` configs. It also has `server_by_local` and
`client_by_peer` maps, built from the profile file. `server_for(local)` and
`client_for(peer)` pick the right config.

### WebSocket codec (`ws.rs`)

The functions are pure: they do no I/O. This keeps them easy to unit-test and
fuzz.

- `server_handshake(buf, &WsOpts)` returns `Handshake::{Incomplete,
  Accept { len, response, deflate }, Reject { response }}`.
- `parse_frame(&mut buf, max_len, expect_masked, allow_rsv1)` returns
  `Parsed::{Incomplete, Frame(FrameHdr), Error(close_code, reason)}`. It
  unmasks the payload in place.
- `frame_header` builds a header for a payload that is written separately.

## Limits and failure handling

- **Connection slots.** `tcp_max_connections` covers both inbound and
  outbound connections. It is a `sip_core::limit::Limiter`. `reserve()`
  hands out an RAII `Permit`, and `adopt` keeps it. Any early return gives
  the permit back.
- **Per source IP.** `tcp_accept_iplimit` (`TcpOpts::accept_iplimit`) is a
  `KeyedLimiter<IpAddr>`. The default is 1024, and 0 turns it off. An
  inbound connection takes a unit (an `IpUnit` guard) before it takes the
  global slot. `release` gives the unit back on close. Refusals count in
  `tcp:rejected_iplimit`.
- **Handshake deadline.** `established` means the connection is usable: TCP
  is connected, the TLS handshake is done, and for WS/WSS the 101 was sent or
  received. `tcp_connect_timeout` closes connections that don't get there,
  inbound ones included.
- **Bounded reads.** `read_available` stops at `max_msg_size` + 64 KiB. The
  reader processes the complete messages, then reads again. The socket is
  still drained, as edge-triggered polling requires. A single message over
  the cap closes the connection.
- **Activity.** Only a fully consumed buffer refreshes `last_active`. So
  partial messages don't extend `tcp_connection_lifetime`.
- **Panics.** A panic while processing one connection closes that
  connection, not the reader. This covers framing, the handshake hook and the
  script. `dispatch` runs each message inside `sip_core::panic::catch`,
  parsing included.
- **Shutdown.** While `sip_core::shutdown::draining()` is true, accepted
  connections are dropped. New [initial requests](../../docs/glossary.md#initial-request)
  get 503 with Retry-After.
- **[Statistics](../../docs/glossary.md#statistics):**
  - `tcp:active_connections` (gauge), `tcp:accepted`, `tcp:rejected`;
  - `udp:recv_errors`;
  - `core:rcv_requests`, `core:rcv_replies`, `core:bad_msgs`.
- **Log rate limits.** "max_connections reached" is logged at most once a
  second, with a count. A UDP receive error that keeps happening is logged at
  power-of-two counts. After 16 in a row there is a 100 ms backoff.

## Design notes

- **UDP: `SO_REUSEPORT`, one socket per worker.** Each `udp-worker-N` thread
  owns a socket bound to the same address. It requests 8 MiB socket buffers.
  The kernel hashes each source to one socket, so there is no dispatcher
  thread and no queue. Each worker keeps its receive buffer, `bumpalo` arena,
  lumps and output buffer for its whole life. The arena is reset for each
  message.
- **Panic isolation.** `dispatch` runs the handler under `catch_unwind`. A
  bad message is logged and dropped instead of killing the thread. Kamailio
  gets the same effect from separate processes.
- **TCP: threads instead of processes.** `tcp-main` only accepts. It hands
  an `Arc<Conn>` to the least-loaded `tcp-reader`. Each reader has its own
  `mio` poll, edge-triggered and interested in both directions. The
  connection stays with that reader for its lifetime.
- **Sharded connection table.** `by_id` and `by_addr` are `ShardedMap`s. So
  any thread finds a connection without asking `tcp-main`. A send tries these
  in order:
  1. the exact connection the request came in on;
  2. any connection to the same address and transport;
  3. a new non-blocking connect.
- **Writes in the sending thread.** A sender writes directly under the
  connection's lock. Only bytes the kernel doesn't take are queued. For TLS
  this queue is rustls' own buffer, limited with `set_buffer_limit`. The
  owning reader flushes on EPOLLOUT. Going over `conn_wq_max` closes the
  connection, so a slow peer never blocks a worker.
- **Framing.** `sip_parser::stream_frame` splits the read buffer by
  Content-Length. So several pipelined messages are handled per `read()`. A
  double-CRLF ping gets a CRLF pong.
- **Lifetime sweep.** Every 250 ms a reader closes idle connections
  (`connection_lifetime`). It also closes outbound connections that did not
  become usable within `connect_timeout`. Closes are reported to the modules
  as `TransportEvent::Closed { outbound, established }`. tm then fails
  waiting [transactions](../../docs/glossary.md#transaction) with 477, and
  [usrloc](../../docs/glossary.md#usrloc) drops contacts.
- **TLS with rustls + ring.** Outbound servers are verified against
  `--tls-ca`. The name checked is the profile's `server_name`, else the host
  name the destination was configured with, else the IP. Our certificate
  also serves as a client certificate. Inbound connections pick the
  listener's profile config by local address. SNI selects among the
  `--tls-sni` certificates, with the default as fallback.
- **WebSocket on the same connections.** After the upgrade, a reader
  de-frames instead of using Content-Length. Inbound frames must be masked.
  An unfragmented message is unmasked in place, 8 bytes at a time, and
  parsed straight from the read buffer. Each outgoing message is one frame:
  TEXT if it is valid UTF-8, else BINARY. It is written as header + payload
  without a copy. Idle open WS connections are pinged at half the lifetime.
- **Outbound WebSocket.** Sending to a `ws:`/`wss:` destination with no
  connection dials one. It sends the upgrade with a random key and queues SIP
  messages until the 101 arrives. It masks its own frames.
- **permessage-deflate.** The answer always includes
  `server_no_context_takeover`. So any thread can compress, with a
  thread-local compressor. Inbound uses an `Inflater` per connection, with a
  size cap. Messages under 128 bytes are sent uncompressed.

## Command-line options (`bin/ferrosip`)

| Option | Sets |
|---|---|
| `-l PROTO:IP:PORT` | a listener (`udp`, `tcp`, `tls`, `ws`, `wss`); default `udp:127.0.0.1:5060` and `tcp:127.0.0.1:5060` |
| `-a IP` | `Config::advertise_ip` |
| `-n N` | `udp_workers` (default: number of CPUs) |
| `--tcp-readers N`, `--tcp-max-conns N`, `--tcp-lifetime SECS`, `--tcp-wq-max BYTES` | the `TcpOpts` fields above |
| `--tcp-connect-timeout S`, `--tcp-keepalive SECS`, `--tcp-accept-aliases` | `connect_timeout`, `keepalive`, `accept_aliases` |
| `--tls-cert PEM`, `--tls-key PEM`, `--tls-ca PEM` | certificate chain, key, CA bundle |
| `--tls-verify-client` | require and verify client certificates (needs `--tls-ca`) |
| `--tls-sni NAME=CERT,KEY` | an extra certificate selected by SNI (repeatable) |
| `--tls-profile FILE` | Kamailio `tls.cfg` sections (below) |
| `--tls-session-cache N` | server session cache size (0 turns off resumption by session id) |
| `--tls-tickets` | stateless session tickets |
| `--ws-origin ORIGIN` | an allowed browser `Origin` (repeatable; an empty list allows any) |
| `--ws-deflate` | accept permessage-deflate (RFC 7692) |

TLS profile sections:

- `[server:IP:PORT]`: one listener's certificate and client-certificate
  policy.
- `[client:IP:PORT]`: our certificate, CA list, verification and
  `server_name` for one peer.
- `[server:default]` and `[client:default]`.

Keys: `certificate`, `private_key`, `ca_list`, `verify_certificate`,
`require_certificate`, `server_name`. Relative paths are relative to the
profile file.

WebSocket handshake rules:

- The request is a `GET` with `Upgrade: websocket` and `Connection:
  Upgrade`.
- It uses version 13, else the answer is 426.
- It asks for the `sip` subprotocol, else the answer is 400.
- If it sends an `Origin`, that origin is allowed, else the answer is 403.

After these checks the `Handler` may still refuse the handshake
(`event_route[websocket:handshake]`, 403). See
[event route](../../docs/glossary.md#event-route). Protocol violations close
with 1002, invalid UTF-8 in TEXT with 1007, and oversize messages with 1009.

## Testing

- Unit tests: `cargo test -p sip-transport`. They cover the WebSocket accept
  key, the RFC 6455 example frames, lengths and partial frames, protocol
  violations, server and client handshakes, and deflate negotiation and
  round trips.
- Fuzz target: `fuzz/fuzz_targets/ws.rs`. It runs `parse_frame` in both
  directions, `server_handshake` and `client_handshake`. Run it with
  `cd fuzz && cargo +nightly fuzz run ws`.
- End-to-end:
  - `tests/e2e_stream.py` (TCP/TLS): framing, pipelining, ping/pong, mutual
    TLS, SNI, profiles, resumption, lifetime, connection limits, the write
    queue limit, connect timeouts and 477, keep-alive, RFC 5923 aliases.
  - `tests/e2e_ws.py`: WS/WSS handshake, masking, fragmentation, control
    frames, deflate, Origin, UTF-8, outbound WebSocket.
  - `tests/interop_sipp.py`: [SIPp](../../docs/glossary.md#sipp) over
    UDP/TCP/TLS.

  [`tools/sipflood`](../../docs/glossary.md#sipflood) is the load generator
  for benchmarks.
