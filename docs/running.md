# Running ferrosip

Building and running: command line, `ferrosip.toml`, `.fsr` routing, containers, management, and how the server behaves under limits, failures and shutdown.

## Run

The default build has everything except the MySQL and PostgreSQL drivers
and mimalloc. `cargo build --release --features ferrosip/db-all` adds the
two drivers (about 95 more crates), for a `mysql://` or `postgres://`
db_url. `cargo build --release -p ferrosip --no-default-features` also
leaves out SQLite, Lua, the HTTP client, the web UI, the AI and Prometheus
modules. `ferrosip --version` prints the features a binary has, and
`bin/ferrosip/README.md` lists them. The Docker image has every feature.

> Full reference: [`ferrosip`](../bin/ferrosip/README.md), [`sipflood`](../tools/sipflood/README.md).

```bash
cargo build --release && etc/tls/gen-certs.sh
T=etc/tls
target/release/sipflood uas udp:127.0.0.1:5070 &                                    # downstreams
target/release/sipflood uas tcp:127.0.0.1:5071 &
target/release/sipflood uas tls:127.0.0.1:5072 --cert $T/server.pem --key $T/server.key.pem &
target/release/ferrosip -l udp:127.0.0.1:5060 -l tcp:127.0.0.1:5060 -l tls:127.0.0.1:5061 \
    -l ws:127.0.0.1:8080 -l wss:127.0.0.1:8443 \
    --tls-cert $T/server.pem --tls-key $T/server.key.pem --tls-ca $T/ca.pem &
target/release/sipflood bench udp:127.0.0.1:5060 300000 64 OPTIONS                  # stateless
target/release/sipflood bench tls:127.0.0.1:5061 200000 64 MESSAGE tcpuser --ca $T/ca.pem  # TLS in → TCP out
target/release/sipflood bench wss:127.0.0.1:8443 200000 64 MESSAGE udpuser --ca $T/ca.pem # browser-like WSS client
target/release/sipflood bench udp:127.0.0.1:5060 200000 64 REGISTER user          # 200k distinct AoRs
python3 tests/e2e_stream.py && python3 tests/e2e_ws.py && python3 tests/e2e_registrar.py
```

### With ferrosip.toml

> Reference: [`docs/config-toml.md`](config-toml.md) (design and
> phase 1 scope), [`docs/modules-reference.md`](modules-reference.md)
> (every parameter; `ferrosip schema`), [`examples/toml`](../examples/toml/).

The declarative layer of the configuration redesign. `ferrosip.toml` says
what runs, and the routing file it names (`[routing] entry`, a `.fsr` or
a `.cfg`) says how messages are routed.
Plain `.cfg` files keep working.

```toml
[[listen]]
proto = "udp"
addr = "${SIP_ADDR:-0.0.0.0}:5060"

[modules.txn]                 # tm
fr_inv_timer = "90s"          # typed durations

[modules.location]            # usrloc + registrar
db_mode = "write-back"        # validated enums
max_expires = "2h"

[modules.nat]
enabled = "${feature.nat}"    # feature switches

[routing]
entry = "routes/main.fsr"     # or a Kamailio-style routes/main.cfg
```

```bash
ferrosip --config ferrosip.toml --overlay envs/prod.toml --set modules.txn.fr_timer=10s
ferrosip check --config ferrosip.toml --explain     # effective config, source of each value
ferrosip schema txn location                        # parameters, types, defaults, docs
```

**Parameters:**
- Every parameter is checked against the module's schema, declared in Rust
  next to the module.
- A wrong type, unit or enum value, or an unknown key or module, is
  reported with a "did you mean", all problems at once.

**Modules:**
- They take their ferrosip names (`txn`, `location`, `route_set`,
  `balancer`, `limits`, `cdr`, `acl`, `nat`, `media`…) or the Kamailio
  ones.
- They load in dependency order, implicitly when another needs them, and
  when the routing script uses their functions (no `loadmodule` needed
  under `--config`).

**Reload:** `ferroctl cfg.reload` also re-reads the TOML. Reloadable
parameters (timers, expiries, limits) change live, and the rest is
reported as needing a restart.

### Routing in `.fsr`

> Reference: [`docs/fsr.md`](fsr.md) (the language),
> [`docs/functions-reference.md`](functions-reference.md) (every
> function, typed; `ferrosip schema --fsr`), [`examples/fsr`](../examples/fsr/).

`[routing] entry` may also name a `.fsr` file: ferrosip's typed routing
language. It compiles to the same route tree as a `.cfg` (same functions,
reload and speed), and `.cfg` stays supported.

```rust
import location
import { features } from config

route main(msg: Request) {
    guard msg.max_forwards > 0 else reply(TooManyHops)
    match msg.method {
        REGISTER => location.save(msg)
        INVITE => call(msg)
        _ => reply(MethodNotAllowed)
    }
}

fn call(msg: Request) -> Action {
    guard location.lookup() else reply(NotFound)
    // the transaction's result is a value: no failure_route
    let res = await txn.relay(msg, timeout: 30s)
    match res {
        Final(r) if r.code == BusyHere => voicemail(msg)
        Timeout => reply(TemporarilyUnavailable)
        Final(r) => forward(r)
    }
}

fn voicemail(msg: Request) -> Action {
    msg.ruri = "sip:vm@10.0.0.9"
    relay(msg)
}
```

- **Checked before it runs:** message fields, flags, every module function
  (argument types, constants, where it may be called) and `match`
  exhaustiveness; every error at once, as `file:line:col` with a caret and
  a "did you mean".
- **`await`:** the code after `await txn.relay(…)` runs at the final reply,
  with its `let` values intact; it can reply, relay again (voicemail,
  the next gateway) or forward the reply. `await` works anywhere, in `if`,
  `match`, `for` loops and called functions, so failover over gateways is
  an ordinary loop.
- **Events and state:** `on dialog.ended(d)`, `on timer(every: 30s)`,
  `on http(req) where req.path == "/api/…"`, destination and flood events;
  `shared table bans: Map<Str, Bool> ttl 10m` and `dialog var caller: Str`.
- **Tests:** `test "name" { send(…); answer(BusyHere); assert(relay_uri(2) == …) }`
  blocks run with `ferrosip test`: the real modules, a recording network,
  mocks (`location.lookup = false`); no sockets or database.
- **Tooling:** `ferrosip check --lowered` prints the `.cfg` it compiles
  to; `ferrosip fmt routes/` formats; `cfg.reload` reloads `.fsr` files.
- **From Kamailio:** `ferrosip import kamailio.cfg` writes the
  `ferrosip.toml` and `.fsr` for an existing config, with the same
  behaviour ([docs/import.md](import.md)).
- **Lints:** `ferrosip lint` gives clippy-style suggestions for
  ferrosip.toml and the routing (`.fsr` or `.cfg`), and `--fix` applies
  the mechanical ones ([docs/lint.md](lint.md)). It covers:
  - unused variables, imports and functions;
  - loops that never end;
  - an open relay, a REGISTER saved without auth, or no Max-Forwards
    check;
  - parameters set to their default;
  - passwords written in the config.

  Levels can be changed with `-A/-W/-D`, a `[lint]` section, or a
  `// lint: allow(…)` comment.

### In a container (Alpine, musl)

```bash
docker compose up -d --build        # docker-compose.yml: host network, ./etc/docker mounted
docker compose exec ferrosip ferroctl -s /run/ferrosip/rpc.sock stats.get_statistics all
docker build -t ferrosip . && docker run --rm --network host ferrosip   # without compose
```

- **Image** (`Dockerfile`): a static musl build of `ferrosip` and `ferroctl`
  on `alpine:3.24`. It is 39 MB, or 31 MB with `--build-arg
  FEATURES=mimalloc`, which leaves out the DB drivers, Lua and HTTP.
- **Runtime:** runs as an unprivileged user, with a healthcheck over the
  RPC socket and graceful shutdown on `docker stop`.
- **Allocator:** mimalloc. With musl's own malloc, stateful relaying and
  REGISTER used 36–85% more CPU per request than the glibc build; with
  mimalloc that drops to within 5–30% (`bench/ab.sh`, sandbox).
- **Configuration:** `etc/docker/ferrosip.toml` (listeners, core settings,
  module parameters) and `etc/docker/routes/main.fsr`, an open registrar
  and proxy to start from. The image carries a copy; compose mounts the
  directory, so edits take effect with `ferroctl cfg.reload`.
- **Networking:** compose uses the host network, because SIP puts addresses
  in Via, Contact and Record-Route. `docker-compose.yml` shows the bridge
  alternative (published ports plus `advertise` on the listeners).
- **CI** builds the image, answers OPTIONS over UDP and TCP, waits for
  `healthy` and checks a clean stop.
- **With HOMER:** [`examples/homer`](../examples/homer/README.md) runs
  ferrosip with heplify-server, homer-app and TimescaleDB, so all SIP
  traffic is searchable in HOMER (`siptrace`, HEPv3).

The sample script handles REGISTER with `save()`, routes registered users
with `lookup()` + `t_relay()`, and otherwise picks the downstream transport
from the R-URI user prefix (`tls…` → TLS, `tcp…` → TCP, otherwise UDP).

Measured on a shared 4-vCPU container with the proxy, UAS and load
generator on the same box (2 proxy workers):

| path | throughput | p50 / p99 |
|---|---|---|
| stateless `reply(200)` | ~280k req/s | 0.21 / 0.52 ms |
| stateful `t_relay` → UAS → back | ~97k txn/s (≈ 390k packets/s through the proxy) | 0.43 / 1.4 ms |

With 4 concurrent clients per transport (proxy: 2 UDP workers, 2 TCP
readers; 7 processes on 4 vCPUs, so treat these as rough):

| inbound | stateless OPTIONS | stateful MESSAGE (same transport out) |
|---|---|---|
| UDP | ~140k/s | ~57k txn/s |
| TCP | ~286k/s (pipelined reads) | ~56k txn/s |
| TLS | ~247k/s | ~58k txn/s |

All 9 inbound × outbound combinations ran 100k transactions each with no
losses.

Registrar (one client, 200k REGISTERs, each a new AoR + binding, no losses):

| inbound | REGISTER → 200 |
|---|---|
| UDP | ~158k/s |
| TCP | ~109k/s |

SIP over WebSocket, one client (50k each, no losses):

| inbound | stateless OPTIONS | → UDP | → TCP | → TLS |
|---|---|---|---|---|
| WS | ~126k/s | ~75k txn/s | ~70k txn/s | ~59k txn/s |
| WSS | ~138k/s | ~65k txn/s | ~55k txn/s | ~72k txn/s |

## Management: RPC, statistics, database

> Full reference: [`sip-core`](../crates/sip-core/README.md), [`sip-db`](../crates/sip-db/README.md), [`ferroctl`](../tools/ferroctl/README.md).

- **`ferroctl`** (like `kamcmd`) talks JSON-RPC 2.0 to `--rpc-socket`
  (default `/tmp/ferrosip-rpc.sock`). Commands so far: `system.listMethods`,
  `core.uptime/version`, `core.info` (process, script, listeners, modules),
  `core.connections` (open TCP/TLS/WS connections), `core.log_tail` (the
  log ring, when the webui turns it on), `stats.get_statistics` (all, `group:`,
  `group:name`), `stats.reset_statistics`, `tm.stats`, `ul.dump`,
  `ul.lookup`, `ul.rm`, `dispatcher.*`, `permissions.*`, `domain.*`,
  `htable.*`, `pike.top`, `rl.*`, `pl.*`, `secfilter.*`, `userblocklist.*`, `dlg.*`,
  `rtpengine.*`, `dialplan.*`, `lcr.*`, `uac.*`, `presence.*`, `pua.publish`,
  `sca.*`, `msilo.count`, `rls.*`, `siptrace.status`, `cnxcc.*`, `mtree.*`,
  `prefix_route.*`, `ts.dump`, `app_lua.reload`, `cdp.list_peers`,
  `ulscscf.*`, `ulpcscf.showcontacts`, `ro.sessions`; also served as JSON-RPC over
  HTTP at `/RPC` when xhttp is loaded.
  Every module adds its own.
- **Statistics** use Kamailio's names: `core:rcv_requests`, `tm:total`,
  `tm:2xx` … `tm:6xx`, `tm:current`, `usrloc:registered_users` …
  Counters are lock-free atomics; gauges are computed when read.
- **sip-db**: one `DbConn` interface, four drivers chosen by `db_url`:
  - `text:///dir`: Kamailio's db_text format, re-read when the file changes
    and rewritten atomically.
  - `sqlite:///file`: bundled rusqlite.
  - `mysql://user:pass@host[:port]/db`: MySQL / MariaDB via the `mysql`
    crate.
  - `postgres://user:pass@host[:port]/db`: the `postgres` crate.
    Parameters are sent as text, so Postgres converts them to the column's
    type. Results are decoded by type, timestamps included.

  The SQL drivers share one query builder (quoting and placeholders per
  dialect) and keep a small connection pool. A connection broken at the
  transport level is replaced and the statement retried once, so a
  restarted database is picked up without restarting ferrosip. All drivers
  except db_text run raw SQL (`sqlops`).

  Table and column names follow Kamailio's schema. `etc/schema/postgres.sql`
  and `etc/schema/mysql.sql` create the tables the modules use. Times such
  as `expires` are stored as Unix seconds (BIGINT). `tests/e2e_sqldb.py` runs
  against real Postgres 16 and MariaDB servers that it starts itself, both
  requiring TLS.

  TLS to the database:
  - `postgres://…?sslmode=require` encrypts without verifying the server,
    as libpq does. `sslmode=verify-full&sslrootcert=/path/ca.pem` also
    verifies it.
  - `mysql://…?ssl=1&ssl_ca=/path/ca.pem` verifies against the CA
    (`ssl_verify=0` encrypts only).
- **tm UAC API** (`Tm::t_uac`, script `t_uac_send`): requests that ferrosip
  originates itself (probes, BYEs, NOTIFYs), with retransmissions, timeouts
  and a completion callback.

## Production behaviour: limits, failures, shutdown

**Connections.**
- `--tcp-max-conns` is one budget for inbound and outbound connections. A
  slot is reserved atomically before a connection is accepted or dialled,
  and given back on every failure path.
- `--tcp-accept-iplimit` (default 1024, Kamailio `tcp_accept_iplimit`)
  caps inbound connections per source IP. It is checked before the global
  budget, so one host can't exhaust it. Refusals are counted in
  `tcp:rejected_iplimit`.
- Both limits use `sip_core::limit`, whose concurrency is checked with loom
  models in CI.
- A connection counts as established only once it is usable: TCP
  connected, TLS handshake done, and for WS/WSS the upgrade done.
  `--tcp-connect-timeout` closes connections that don't get there, inbound
  included, so a client that connects and never sends a ClientHello or an
  upgrade can't hold a slot.
- Reads are capped at `max_msg_size` + 64 KiB at a time, and a single
  message larger than that closes its connection.
- Only complete messages count as activity for `--tcp-lifetime`, so a
  client trickling one endless message is closed too.
- Write queues are bounded by `--tcp-wq-max`, including messages queued
  before a WebSocket 101.

**Peer-controlled caches.**
- The R-URI host cache, the DNS record cache and the destination
  blocklist sweep expired entries as they grow, and stop admitting new
  keys at 65,536 live entries.
- At most 64 inbound Diameter connections are served, and a peer that
  stays silent for 3 × Tw is dropped (RFC 3539).

**Panics.**
- A panic while handling one message, RPC call, route callback, timer or
  connection drops that unit of work and is counted in `core:panics`; the
  thread carries on.
- A panic anywhere else, in a long-lived service thread, aborts the
  process so a supervisor restarts it cleanly, instead of leaving it
  running without that thread.

**Graceful shutdown** (SIGTERM or SIGINT; `--shutdown-timeout`, default 5 s):
1. New TCP/TLS/WS connections are refused.
2. New initial requests are answered `503 Service Unavailable` with
   `Retry-After: 5`. Replies, in-dialog requests, ACK and CANCEL still
   flow.
3. Transactions still waiting for a final reply get until the timeout to
   finish.
4. usrloc flushes write-back changes, TLS peers get close_notify, and the
   control socket is removed.
5. The process exits 0. A second signal exits at once.

**Metrics** (RPC `stats.get_statistics`, Prometheus via `xhttp_prom`, where
counters are typed `counter`):
- `tcp:active_connections`, `tcp:accepted`, `tcp:rejected`,
  `tcp:rejected_iplimit`
- `udp:recv_errors`
- `tm:current`, `tm:retransmissions`, `tm:timeouts`
- `core:panics`
- `core:send_errors`: messages a transport (UDP, TCP, TLS, WS) failed to
  send, whatever sent them (relay, reply, keepalive, local request). Each
  failure is also logged at `ERROR`, at most one line per second; the
  next line says how many were left out.
- plus the existing `core:`, `sl:`, `tm:`, `usrloc:` and `dialog:`
  statistics.

Throughput, CPU, allocation and memory measurements with all of this in
place are in `bench/BASELINE.md` (`bench/ab.sh`, `bench/allocs.sh`).
