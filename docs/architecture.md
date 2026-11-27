# Architecture

How ferrosip is built: the source layout, how each of Kamailio's performance choices maps to a crate, and the transport and WebSocket design.

## Source layout

```
ferrosip/
├── Cargo.toml                 workspace; release = opt-level 3, fat LTO, 1 CGU
├── etc/schema/                postgres.sql, mysql.sql (Kamailio table names)
├── etc/ferrosip.cfg           routing script (Kamailio-like language)
├── etc/tls/gen-certs.sh       test CA + certs (server/client, SNI, wrong-name) for local TLS runs
├── bin/ferrosip/              main: cfg parse → module init → fixups → spawn workers
├── crates/
│   ├── sip-parser/            zero-copy, lazy SIP parser (+ URI / Contact parsing)
│   ├── sip-core/
│   │   ├── lumps.rs           edit list applied in one pass at send time
│   │   ├── shm.rs             sharded, per-bucket-locked shared tables + FxHash
│   │   ├── timer.rs           timer wheel
│   │   ├── sync.rs / time.rs  poison-tolerant lock/read/write; Unix-time helpers
│   │   ├── module.rs          Ctx (≈ struct sip_msg), Module trait, exports + fixups, RC_OK/RC_ERR/RC_DROP
│   │   ├── net.rs             Proto, Dest (≈ dest_info), Outbound trait (≈ msg_send)
│   │   ├── route.rs           RouteHub: modules run failure/onreply/branch/event routes
│   │   ├── pv.rs / pvcore.rs  pseudo-variables, transformations, templates; core $vars
│   │   ├── rpc.rs / stats.rs  JSON-RPC control socket; counters and gauges
│   │   ├── json.rs            JSON paths for {json.parse} and jansson
│   │   ├── blst.rs            destination blocklist (dst_blocklist)
│   │   ├── dns.rs             DNS client + cache, RFC 3263 resolve_uri (NAPTR → SRV → A)
│   │   ├── rr.rs              Record-Route/Path requests, rendered per branch by tm
│   │   ├── reply.rs           stateless replies (≈ sl module)
│   │   └── corefns.rs         reply / sl_reply_error / append_hdr / remove_hdr / ruri_user_prefix / log
│   ├── sip-db/                db layer: db_text, SQLite, MySQL/MariaDB, PostgreSQL (pooled)
│   ├── sip-script/            lexer → AST → compile (fixups) → Action trees: request,
│   │                          failure_route[x], onreply_route[x], reply_route
│   ├── sip-transport/
│   │   ├── udp.rs             SO_REUSEPORT UDP workers, recv→parse→route→send loop
│   │   ├── tcp.rs             tcp_main + reader threads, conn table, async writes/connects
│   │   ├── tls.rs             rustls (ring) server/client config
│   │   ├── ws.rs              WebSocket codec + RFC 7118 handshake (pure, unit-tested)
│   │   └── lib.rs             Net (send over any transport), dispatch, start()
│   ├── mod-txn/               transactions + forking: t_relay, §16.7 aggregation, CANCEL, timers
│   ├── mod-maxfwd/            mf_process()
│   ├── mod-auth/              digest auth (+ auth_db, auth_ephemeral): www/proxy_authorize, challenges
│   ├── mod-sip/               sl, textops(x), siputils, sanity, xlog, cfgutils, corex, kex,
│   │                          statistics, pv, ipops (one file per group)
│   ├── mod-routing/           rr, path, nathelper, dispatcher, permissions, domain,
│   │                          alias_db, group
│   ├── mod-limits/            htable, pike, ratelimit, pipelimit, secfilter, userblocklist
│   ├── mod-dialog/            dialog: state machine, timeouts + BYEs, profiles, $dlg_var, db
│   ├── mod-media/             rtpengine (ng protocol, bencode)
│   ├── mod-carrier/           dialplan, lcr (+ Sipwise patches), acc, uac, topoh, topos
│   ├── mod-presence/          presence, presence_xml, presence_dialoginfo, pua, pua_dialoginfo,
│   │                          sca, msilo, rls (+ the shared SUBSCRIBE/NOTIFY notifier)
│   ├── mod-extra/             siptrace, cnxcc, tmx, uac_redirect, avpops, sqlops, mtree,
│   │                          prefix_route, speeddial, enum, outbound, tsilo, rtimer, xhttp,
│   │                          xhttp_prom, ndb_redis
│   ├── mod-async/             async, http_async_client, http_client, jansson, json, jsonrpcs
│   ├── mod-ops/               keepalive, sipdump (text + pcap), evapi
│   ├── mod-lua/               app_lua (Lua 5.4 via mlua, KEMI-style KSR API)
│   ├── mod-webui/             webui: read-only admin UI (Preact + TypeScript SPA, embedded)
│   ├── mod-ai/                ai: answer calls with OpenAI Realtime / Gemini Live
│   ├── sip-ua/                sans-IO SIP UA engine (UAC/UAS dialogs) for B2BUAs (docs/sip-ua.md)
│   ├── mod-prometheus/        prometheus: exporter with labels, latency histograms
│   ├── sip-diameter/          Diameter base (RFC 6733): codec, peers (CER/DWR), Kamailio XML config
│   ├── mod-ims/               cdp, ims_auth, ims_usrloc/registrar_scscf (+ reg event), ims_isc,
│   │                          ims_icscf, ims_usrloc/registrar_pcscf, ims_ipsec_pcscf,
│   │                          ims_qos (Rx), ims_charging (Ro)
│   └── mod-location/          location: registrar save() / lookup() (RFC 3261 §10.3, RFC 5626) + the usrloc table
├── tests/e2e_stream.py        TCP/TLS end-to-end checks (framing, keepalive, limits…)
├── tests/e2e_ws.py            WS/WSS end-to-end checks (handshake, deflate, Origin, UTF-8…)
├── tests/e2e_registrar.py     registrar/usrloc checks (NAT, TCP, WS browsers, RFC 5626…)
├── tests/e2e_auth.py          digest auth checks (MD5/SHA-256, replay, stale, identity…)
├── tests/e2e_fork.py          forking checks (parallel, serial by q, CANCEL, best response…)
├── tests/e2e_routes.py        failure_route / onreply_route / reply_route checks
├── tests/e2e_script.py        expressions, pseudo-variables, route(), branch_route, RPC
├── tests/e2e_utils.py         the Phase 1 utility modules
├── tests/e2e_routing.py       rr/path/nathelper/dispatcher/permissions/domain/alias_db/group
├── tests/e2e_state.py         htable/pike/limits/secfilter/userblocklist/dialog/db persistence
├── tests/e2e_dialog.py        dialog: dlg_flag, rr cookie, flags, dlg_get/refer/bridge, RPCs
├── tests/e2e_carrier.py       rtpengine (fake ng server), dialplan, lcr, acc, uac, topoh/topos
├── tests/e2e_presence.py      PUBLISH/SUBSCRIBE/NOTIFY, dialog-info, RLS, SCA, msilo
├── tests/e2e_extra.py         Phase 6 modules (fake HEP collector, DNS server and Redis)
├── tests/e2e_async.py         t_suspend/t_continue, async_*, http_async_query (fake HTTP backend)
├── tests/e2e_tm.py            CANCEL retransmission/timeout, ACK reuse, RFC 5626 flow failover
├── tests/e2e_reload.py        cfg.reload: new routes, stable route indices, refusals
├── tests/e2e_ops.py           keepalive probes/events, sipdump files, evapi round trips
├── tests/e2e_sqldb.py         the same proxy on PostgreSQL and MariaDB (servers started by the test)
├── tests/e2e_json.py          http_client, jansson/json, jsonrpcs (REST server decides the route)
├── tests/e2e_dns.py           NAPTR/SRV routing, DNS failover, t_load/next_contacts (fake DNS server)
├── tests/e2e_ims.py           P-/I-/S-CSCF + AS with a scripted HSS/PCRF/OCS; reg event, IPsec agreement
├── tests/e2e_sip_ua.py        sip-ua example B2BUA between independent UAs (sipkit; SIPp when installed)
├── tests/e2e_shutdown.py       graceful shutdown: 503 while draining, in-flight calls finish, exit 0
├── tests/e2e_limits.py         per-IP connection limit, unit accounting
├── tests/interop_sipp.py      SIPp interop: calls over UDP/TCP/TLS, digest REGISTER, CANCEL (tests/sipp/)
├── tests/soak.py              sustained SIPp load; RSS, transactions and dialogs checked for leaks
├── fuzz/                      cargo-fuzz targets: SIP parser, script, WS, Diameter, DNS, bencode, XML, pv
├── .github/workflows/ci.yml   build + clippy + unit tests, e2e + interop + soak, fuzz smoke; nightly long runs
├── tools/ferroctl/            RPC client (like kamcmd): ferroctl ul.dump, stats.get_statistics …;
│                              ferroctl fmt formats routing scripts
├── tools/sipflood/            load generator (bench) + dummy UAS, UDP/TCP/TLS (+ WS client)
└── bench/kamailio/            ferrosip vs Kamailio benchmark harness (same box, same load)
```

## Kamailio → ferrosip mapping

| Kamailio | ferrosip | Why it's fast |
|---|---|---|
| `children=N` forked UDP processes, `udp_rcv_loop()` | N threads, each with **its own** `SO_REUSEPORT` socket (`sip-transport`) | kernel load-balances; no dispatcher thread, no queue between threads |
| `pkg` memory (per-process, lock-free) | `bumpalo::Bump` per worker, `reset()` after every message | allocation = pointer bump; freeing = one store |
| `shm` memory + per-bucket locks (`fastlock.h`) | `ShardedMap`: 1024 × `Mutex<HashMap>` (futex) | uncontended lock = 1 atomic, workers rarely collide |
| `parse_headers(msg, HDR_xxx_F)` lazy parsing, `str{s,len}` | `Msg::parse_headers(HdrFlags)`, `&'a [u8]` slices | relayed messages never get fully parsed; nothing is copied |
| `data_lump.c` / `msg_translator.c` | `Lumps` | the outgoing message is the original buffer plus splices |
| `cfg.y` + fixups (`route.c`) | `sip-script`: names → fn pointers, args → typed values at startup | no string lookups or re-parsing per message |
| `cmd_export_t`, `mod_init`, `child_init` | `Module` trait, `Registry::export(name, fixup, func)` | modules statically linked → LTO inlines across crates |
| timer process + tm timer lists | `tm-timer` thread, timer wheel, per-worker inboxes drained per tick | workers never wake the timer thread |
| process isolation on crash | `catch_unwind` per message, poisoning ignored (`sip_core::sync::lock`) | one bad packet can't kill a worker |
| `tcp_main` + `tcp_children` readers | `tcp-main` thread accepts, hands `Arc<Conn>` to least-loaded `tcp-reader` (own epoll) | accept never competes with reading; each reader polls only its own conns |
| `tcpconn` id/alias hashes in shm | `by_id` / `by_addr` sharded maps | any thread finds a connection without asking tcp_main |
| async write (`tcp_async`, `tcp_conn_wq_max`) | sender writes directly; on EAGAIN queues (bounded) and the owner flushes on EPOLLOUT | a slow peer never blocks a worker; overflow closes the conn |
| `modparam`, `load_ul_api()` / `bind_*` | `modparam(...)` in the script; `Registry::provide/api::<T>()` | module APIs are typed `Arc<T>`s resolved once at startup |
| usrloc hash table in shm | `mod-location` (`store`) on the same `ShardedMap` | REGISTERs/lookups for different users never contend |
| `tcp_read.c` framing | `sip_parser::stream_frame()` | many pipelined messages per `read()` |
| `websocket` module (ws_handshake.c, ws_frame.c) | `ws.rs` + a WS layer in the TCP readers | payload unmasked in place and parsed straight from the read buffer; replies framed with a header-only write |

## TCP/TLS design

> Full reference: [`sip-transport`](../crates/sip-transport/README.md).

```
             accept()                       Arc<Conn> + wake
 listeners ──────────► tcp-main ────────────────────────────────┐
                        (least-loaded reader, max_connections)   ▼
 any thread ── send() ─► conn table ─► direct write        tcp-reader-0..N
 (UDP workers,           by_id/by_addr  (per-conn lock)     epoll, edge-triggered:
  readers, tm timer)        │           EAGAIN → bounded    read → frame by
                            │           queue               Content-Length → route;
                            └─ miss → non-blocking connect  EPOLLOUT → flush queue;
                                      adopted by a reader   idle-lifetime sweep
```

- **Threads instead of processes.** Kamailio passes file descriptors
  between `tcp_main` and reader processes over unix sockets, and idle
  connections go back to `tcp_main`. With threads, a connection is handed
  over once as an `Arc<Conn>` and stays with one reader for its lifetime.
- **Writes happen in the sending thread.** A reply goes out from whichever
  thread produced it, under a per-connection lock. Only data that doesn't fit
  in the kernel buffer is queued. The owning reader is subscribed to EPOLLOUT
  edges and drains the queue when the socket becomes writable, so no
  cross-thread message is needed.
- **TLS**: the rustls session sits behind the same per-connection lock. The
  reader decrypts into its own buffer and releases the lock before routing,
  so the handler can immediately send a reply on the same connection.
- **Replies take the arrival path.** `ctx.src` holds the connection id. If
  that connection is gone, the proxy falls back to any connection to the same
  address, then to a new connection.
- **tm and reliable transports**: no retransmissions on TCP/TLS (RFC 3261
  §17.1.1.2). The final-response timer still applies.
- **Failed connects fail fast.** Readers report every closed connection to
  the modules. If an outbound connection never became usable (refused, TLS
  handshake or certificate failure, `--tcp-connect-timeout`), tm answers the
  waiting transactions with 477 immediately instead of 408 after 32 s.
  Synchronous failures make `t_relay()` return false, and tm answers 477
  when the script ends (`sl_reply_error()` sends nothing meanwhile), as in
  Kamailio.
- **TLS**: `--tls-verify-client` requires and verifies client certificates
  (mutual TLS). Our certificate is also presented on outbound TLS.
  `--tls-profile FILE` takes Kamailio `tls.cfg` sections:
  - `[server:IP:PORT]` gives one listener its own certificate and
    client-certificate policy (`verify_certificate`, `require_certificate`).
  - `[client:IP:PORT]` gives one peer our certificate, CA list,
    verification and a `server_name` to verify and send as SNI.
  - `[server:default]` / `[client:default]` change the defaults.

  Session resumption: rustls' session cache (`--tls-session-cache N`) and
  stateless tickets (`--tls-tickets`).
  `--tls-sni NAME=CERT,KEY` adds per-SNI certificates, with the default as
  fallback. Outbound connections are verified by host name when the
  destination was configured by name (`t_relay("tls:sip.example.com:5061")`),
  otherwise by IP.
- **Options** (Kamailio names): `--tcp-readers` (tcp_children),
  `--tcp-max-conns`, `--tcp-lifetime`, `--tcp-wq-max`, `--tcp-connect-timeout`,
  `--tcp-keepalive` (kernel keep-alive), `--tcp-accept-aliases` (RFC 5923
  Via `;alias` connection reuse, aliasing the Via *port* on the connection's
  own IP, as Kamailio does), `--tls-cert/--tls-key/--tls-ca`,
  `--tls-verify-client`, `--tls-sni`.

## WebSocket (RFC 7118)

> Full reference: [`sip-transport`](../crates/sip-transport/README.md).

`-l ws:IP:PORT` and `-l wss:IP:PORT` (WSS uses `--tls-cert/--tls-key`) run
on the same reader threads and connection table as TCP/TLS. Only the
per-connection framing differs:

- **Handshake**: `GET` + `Upgrade: websocket`, version 13. The client must
  offer the `sip` subprotocol, otherwise 400 (RFC 7118 §4). An unsupported
  version gets 426.
- **Inbound frames**: must be masked (else close 1002). The mask is removed
  in place, 8 bytes at a time, and an unfragmented message is parsed
  directly from the reader's buffer without copying. Fragmented messages
  are reassembled, and control frames may arrive between fragments. Each
  WebSocket message carries exactly one SIP message, so Content-Length isn't
  needed.
- **Outbound**: one frame per SIP message: TEXT if the message is valid UTF-8,
  otherwise BINARY. Header and payload are written together under the
  connection lock, with no copy. Nothing is sent before the 101.
- **Control frames**: PING → PONG, CLOSE is echoed and the connection closed.
  Frames that are too big get close 1009.
- **Keep-alive**: idle WS clients are pinged at half of
  `--tcp-lifetime`, and the pong counts as activity. This matches Kamailio's
  `keepalive_mechanism=1`. A client that doesn't answer is closed at the
  lifetime.
- **Origin**: `--ws-origin https://app.example` (repeatable) gives 403 to
  browsers from other origins. Clients that send no `Origin` (not browsers)
  are allowed.
- **UTF-8**: TEXT messages must be valid UTF-8, otherwise close 1007.
- **permessage-deflate** (RFC 7692, opt-in with `--ws-deflate`): the first
  acceptable offer wins. We always answer `server_no_context_takeover`, so
  any thread can compress an outgoing message with a thread-local
  compressor. Inbound messages use a per-connection inflater (with context
  takeover unless the client opted out). Decompressed size is capped, and
  messages under 128 bytes go uncompressed. It roughly halves throughput on
  a loaded box, which is why it's off by default (Kamailio has no deflate).
- **Outbound WebSocket** (Kamailio can't do this):
  - `t_relay("ws:…")` / `"wss:…"` reuses a connection to that peer, or dials
    one: an HTTP upgrade with `Sec-WebSocket-Protocol: sip`, and the
    `Sec-WebSocket-Accept` is verified.
  - SIP messages wait until the 101 arrives; our frames are masked, as a
    client's must be.
  - A refused connection makes `t_relay()` fail at once (see the 503
    fallback in `tests/e2e_ws.py`).
- **`event_route[websocket:handshake]`** runs on each upgrade request that
  passed the built-in checks, as a faked request: `$hdr(Origin)`,
  `$hdr(User-Agent)`, `$hdr(Cookie)`, the path in `$hdr(X-WS-Path)`, and
  `$si`/`$sp`. `drop` refuses the upgrade with 403.
