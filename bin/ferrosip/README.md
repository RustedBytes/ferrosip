# ferrosip (binary)

The server executable. This is the program you run to start a ferrosip
[proxy](../../docs/glossary.md#proxy). It does five things at startup:

1. It parses the routing script.
2. It loads the [modules](../../docs/glossary.md#module) the script asks for.
3. It compiles the routes.
4. It opens the control socket.
5. It starts the transports.

The order follows [Kamailio](../../docs/glossary.md#kamailio)'s `main.c`:
parse the config, apply [modparams](../../docs/glossary.md#modparam), run
`mod_init`, run [fixups](../../docs/glossary.md#fixup), then start the
[workers](../../docs/glossary.md#worker).

```bash
cargo build --release
target/release/ferrosip -f etc/ferrosip.cfg -l udp:0.0.0.0:5060 -l tcp:0.0.0.0:5060
```

## Startup sequence

1. **Preprocess and parse** the script given by `-f`. The default is
   `etc/ferrosip.cfg`, a [`.cfg`](../../docs/glossary.md#cfg) script.
   `sip_script::preprocess` handles Kamailio's `#!` directives,
   `include_file`/`import_file` and `--define`s (see
   [preprocessor](../../docs/glossary.md#preprocessor)). It lifts top-level
   core parameters (`listen=`, `children=`, …). It keeps one output line per
   input line. `sip_script::parse` follows. A syntax error stops the program
   with the file name and line. This works inside includes too.
2. **Core parameters** are applied (`apply_core`).
   - An option given on the command line wins over the same setting in the
     config file.
   - Parameters with no ferrosip equivalent are listed once as ignored.
   - `group.name = value desc "…"` lines declare custom config variables.
   - `modparam("tls", …)` fills in the TLS settings that options didn't
     give.
3. **Load the core**: `sip_core::corefns::CoreModule` is always loaded. It
   provides the core functions,
   [pseudo-variables](../../docs/glossary.md#pseudo-variable-pv) and
   [RPCs](../../docs/glossary.md#rpc).
4. **Load the modules** in `loadmodule` order. `module_by_name` in
   `src/main.rs` resolves each name:
   - `tm`, `maxfwd`, `usrloc`, `registrar`, `auth`, `auth_db`,
     `auth_ephemeral` and `dialog` directly;
   - every other name via the `module()` lookup of `mod-sip`,
     `mod-routing`, `mod-limits`, `mod-media`, `mod-carrier`,
     `mod-presence`, `mod-extra`, `mod-lua`, `mod-ims`, `mod-async` and
     `mod-ops`;
   - Kamailio modules whose job ferrosip does natively (`ctl`, `tls`,
     `websocket`, `db_mysql`, …) via `compat::builtin_module`, as no-ops.

   A module's `modparam`s are applied before it registers. So, as in
   Kamailio, a module that uses another module's API must be loaded after it
   (`usrloc` before `registrar`). `modparam("a|b", …)` goes to each listed
   module. A Kamailio parameter listed in `compat::NO_EFFECT` is accepted
   with a notice. These are all startup errors:
   - a `modparam` for a module that isn't loaded;
   - an unknown parameter;
   - an unknown module name;
   - a modparam whose value is a variable.
5. **Compile** the routes (`sip_script::Engine::compile`). This runs every
   function's fixup. So a bad argument or an unknown function stops the
   program before any socket is bound. With `-c` the program stops here and
   prints `config OK`. Databases are not opened in that mode. `db_url`s are
   only checked for a known scheme.
6. **Control socket**: the JSON-RPC Unix socket (`--rpc-socket`) is served
   for [`ferroctl`](../../tools/ferroctl/README.md). `cfg.reload` is
   registered here.
7. **Transports** start (`sip_transport::start`). Then each module's
   background tasks start (`Module::spawn`): timers, DB flushes,
   [Diameter peers](../../docs/glossary.md#diameter-peer) and so on. A
   module that cannot start stops ferrosip with exit status 1. Examples are a
   thread, or a listener such as the web UI's or the metrics port.
8. One line per listener is logged:
   `ferrosip: listening on udp:127.0.0.1:5060 (4 workers)`. The test harness
   waits for these lines.

Modules are linked statically and selected by `loadmodule`. Kamailio
dlopen()s shared objects instead. Static linking is simpler, and LTO can
inline module code into the core.

## Build features

Everything is built by default except the MySQL and PostgreSQL drivers and
mimalloc. `ferrosip --version` prints the features a binary was built with.

| Feature | Brings in | Without it |
|---|---|---|
| `db-sqlite` | `sqlite://` db_url and raw SQL (`sqlops`), with a bundled SQLite | `sqlite://` URLs fail at startup, naming the feature |
| `db-mysql` (off by default) | `mysql://` (MySQL/MariaDB driver) | same, for `mysql://` |
| `db-postgres` (off by default) | `postgres://` (postgres + tokio + rustls) | same, for `postgres://` |
| `db-all` | all three database drivers | |
| `lua` | `app_lua` (vendored Lua 5.4) | `loadmodule "app_lua"` fails, naming the feature |
| `http` | `http_client`, `http_async_client` (ureq) | `loadmodule` of either fails, naming the feature |
| `webui` | the read-only admin [web UI](../../docs/glossary.md#web-ui) (`loadmodule "webui"`) | `loadmodule "webui"` fails, naming the feature |
| `mimalloc` (off by default) | mimalloc as the global allocator | the system allocator |

`text://` databases and every other module are always built in.

`mimalloc` is meant for musl builds. The Docker image turns it on. Below is
an A/B in the sandbox with `bench/ab.sh`: 5 rounds, CPU µs per request. It
compares the glibc build with the static musl build, with and without
mimalloc:

| scenario | glibc | musl | musl + mimalloc |
|---|---|---|---|
| stateless reply (UDP) | 5.1 | 5.8 | 5.0 |
| `t_relay` UDP → UDP | 21.1 | 28.7 | 22.3 |
| `t_relay` TCP → TCP | 29.7 | 51.8 | 33.6 |
| REGISTER → `save()` | 6.7 | 12.4 | 8.8 |

The musl and mimalloc columns come from two A/B runs. So they are close but
not exactly paired.

```bash
cargo build --release -p ferrosip --features db-all                           # with MySQL and PostgreSQL
cargo build --release -p ferrosip --no-default-features                       # leanest
cargo build --release -p ferrosip --no-default-features --features db-sqlite  # plus SQLite
```

Third-party crates linked into the binary (`cargo tree -e normal`), and
the release binary (fat LTO, `debug = 1`, so with debug info):

| | crates | binary |
|---|---|---|
| default | 78 | 103 MiB |
| `--features db-all` | 174 | 112 MiB |
| `--no-default-features` | 50 | 78 MiB |

## Command-line options

| Option | Default | Meaning |
|---|---|---|
| `-f FILE` | `etc/ferrosip.cfg` | Routing script |
| `-c` | | Check the script (preprocess, parse, modules, modparams, fixups) and exit, like `kamailio -c` |
| `--define NAME[=VALUE]` | | Preprocessor define, as `#!define NAME VALUE` (Kamailio's `-A`), repeatable |
| `-l PROTO:IP:PORT` | `udp:127.0.0.1:5060` and `tcp:127.0.0.1:5060` | Listen socket, repeatable. PROTO is `udp`, `tcp`, `tls`, `ws` or `wss` |
| `-a IP` | bind address | IP to advertise in Via |
| `-n N` | number of CPUs | UDP workers per UDP socket (Kamailio `children`) |
| `-A HOST` | | Treat HOST as "myself" too (Kamailio `alias`), repeatable |
| `--debug LEVEL` | `info` | Log level: `alert`, `crit`, `err`, `warn`, `notice`, `info`, `debug`, or -5..3 |
| `--rpc-socket PATH` | `/tmp/ferrosip-rpc.sock` | JSON-RPC control socket. `none` turns it off |
| `--shutdown-timeout SECS` | 5 | On SIGTERM/SIGINT, how long transactions in flight get to finish |
| `--tcp-readers N` | CPUs / 2 | TCP/TLS/WS reader threads (`tcp_children`) |
| `--tcp-max-conns N` | 4096 | `tcp_max_connections`, counting inbound and outbound |
| `--tcp-accept-iplimit N` | 1024 | `tcp_accept_iplimit`: inbound connections per source IP (0 = no limit) |
| `--tcp-lifetime SECS` | 120 | `tcp_connection_lifetime`: idle connections are closed after this |
| `--tcp-wq-max BYTES` | 262144 | `tcp_conn_wq_max`: a connection whose write queue grows past this is dropped |
| `--tcp-connect-timeout S` | 10 | Outbound connect timeout, TLS handshake included. When it expires, tm answers 477 |
| `--tcp-keepalive SECS` | off | TCP keep-alive probes after SECS idle |
| `--tcp-accept-aliases` | off | Honour Via `;alias` (RFC 5923) for connection reuse |
| `--tls-cert PEM` / `--tls-key PEM` | | Certificate chain and key for `tls:` and `wss:` listeners |
| `--tls-ca PEM` | | CA bundle to verify servers on outbound TLS, and clients with `--tls-verify-client` |
| `--tls-verify-client` | off | Require and verify client certificates (mutual TLS) |
| `--tls-sni NAME=CERT,KEY` | | Extra certificate chosen by SNI server name, repeatable |
| `--tls-profile FILE` | | Per-listener `[server:IP:PORT]` and per-peer `[client:IP:PORT]` settings in Kamailio `tls.cfg` syntax |
| `--tls-session-cache N` | | Server session cache entries (0 turns off resumption by session id) |
| `--tls-tickets` | off | Issue stateless TLS session tickets |
| `--ws-origin ORIGIN` | any | Allowed browser `Origin` on `ws:` and `wss:`, repeatable |
| `--ws-deflate` | off | Accept permessage-deflate (RFC 7692) |
| `-h`, `--help` | | Print usage |
| `-V`, `--version` | | Print the version and the optional features the binary was built with |

"myself" is the script's [`myself`](../../docs/glossary.md#myself) check.
The Via is the proxy's own [Via](../../docs/glossary.md#via) header.

## Core parameters in the script

Kamailio's global settings at the top of a config apply when the matching
option isn't given on the command line:

| Parameter | Option |
|---|---|
| `listen=proto:ip:port` (repeatable; `advertise …` is ignored) | `-l` |
| `children=N` | `-n` |
| `tcp_children=N` | `--tcp-readers` |
| `tcp_max_connections`, `tcp_accept_iplimit`, `tcp_connection_lifetime`, `tcp_connect_timeout`, `tcp_conn_wq_max`, `tcp_accept_aliases` | the `--tcp-*` options of the same name |
| `tcp_keepalive=no`, `tcp_keepidle=S` | `--tcp-keepalive` |
| `debug=N` | `--debug` |
| `alias=host` | `-A` |
| `group.name = value desc "…"` | a custom config variable (`$sel(cfg_get.group.name)`, `cfg.*` RPCs) |

Logging, memory, process and DNS-cache settings (`log_stderror`, `fork`,
`mhomed`, `dns_cache_init`, `enable_tls`, …) have no equivalent. They are
listed once as ignored. An unknown parameter gets a warning.

## Reloading the script

`ferroctl cfg.reload` re-reads the file given by `-f`. It swaps in the new
routes without dropping traffic (`sip_script::Live`, an `ArcSwap`). See
[live reload](../../docs/glossary.md#live-reload).

Modules are already initialised. So the reload is refused if any
`loadmodule` or `modparam` line changed. The error lists the lines that
differ. Those changes need a restart. A reload with a syntax or fixup error
is refused too, and the running routes stay in place.

## Signals and shutdown

The main thread waits for SIGTERM or SIGINT (`signal-hook`). Then it drains
([graceful shutdown](../../docs/glossary.md#graceful-shutdown)):

1. New TCP/TLS/WS connections are refused.
2. New [initial requests](../../docs/glossary.md#initial-request) get
   `503 Service Unavailable` with `Retry-After: 5`. These are requests with
   no To-tag that are not ACK/CANCEL. Everything that belongs to work in
   progress still flows.
3. It waits until no module reports busy work (`Module::busy()`), for up to
   `--shutdown-timeout`. For tm, busy work means
   [transactions](../../docs/glossary.md#transaction) without a
   [final reply](../../docs/glossary.md#final-reply).
4. It runs each module's `shutdown()`. For example, usrloc flushes its
   write-back changes. It sends TLS close_notify, removes the control socket
   and exits 0.

A second signal exits immediately with status 1.

## Panics

`main` installs `sip_core::panic::install_hook()`:

- A panic inside a recoverable unit of work is caught, logged and counted
  (`core:panics`). A unit of work is a message, an RPC call, a route
  callback, a timer or a connection.
- A panic on a per-connection helper thread ends that thread.
- A panic anywhere else aborts the process. A supervisor such as systemd's
  `Restart=` then restarts it cleanly.

## Exit codes

| Code | When |
|---|---|
| 0 | Graceful shutdown after SIGTERM/SIGINT. This holds even if transactions were left unfinished at the timeout. The log says how many |
| 1 | Any startup error (config, module, bind or control socket), or a second signal during shutdown. The message goes to stderr, prefixed `ferrosip:` |
| 134 (SIGABRT) | A panic outside a recoverable section |

## Testing

- **Unit tests** (`cargo test -p ferrosip`) cross-check the binary's
  tables with the modules:
  - every module has a parameter [schema](../../docs/glossary.md#schema),
    and every schema parameter is accepted by its module's `set_param`;
  - every exported function has an [`.fsr`](../../docs/glossary.md#fsr)
    signature, and every signature matches the function. A call built from
    the signature passes the fixup;
  - the module groups (`config::ALIASES`) and dependencies name real
    modules.
- **End to end**: every `tests/e2e_*.py` suite starts this binary.
  [docs/testing.md](../../docs/testing.md) lists them.

## Related

- [`sip-script`](../../crates/sip-script/README.md): script language.
- [`sip-transport`](../../crates/sip-transport/README.md): listeners and
  connection handling.
- [`sip-core`](../../crates/sip-core/README.md): core functions,
  pseudo-variables and RPCs.
- `etc/ferrosip.cfg`: the sample script.
- `etc/tls/gen-certs.sh`: test certificates.
