# sip-core

The shared runtime that every other part of ferrosip is built on. You use it
when you write a module or anything else that handles a SIP message. It gives
you:

- the per-message context, `Ctx`. It is roughly Kamailio's `struct sip_msg`.
- the module API: exported functions with
  [fixups](../../docs/glossary.md#fixup) and typed APIs between modules.
- [pseudo-variables](../../docs/glossary.md#pseudo-variable-pv) and
  [transformations](../../docs/glossary.md#transformation).
- message editing with [lumps](../../docs/glossary.md#lumps).
- stateless replies.
- sharded shared tables and the timer wheel.
- [statistics](../../docs/glossary.md#statistics).
- the [JSON-RPC](../../docs/glossary.md#rpc) control socket.
- the [DNS resolver](../../docs/glossary.md#dns-resolution) and the
  [destination blocklist](../../docs/glossary.md#destination-blocklist).

In [Kamailio](../../docs/glossary.md#kamailio) terms it covers most of
`src/core`: `sr_module`, `data_lump` / `msg_translator`, `pvapi`, `timer`,
`counters`, `resolve.c` / `dns_cache.c`, `dst_blocklist` and `forward.c`'s
`dest_info`. It also covers the basics of the `pv`,
[`sl`](../../docs/glossary.md#sl), `ctl`/`jsonrpcs` and `outbound` modules.

It depends only on `sip-parser`, plus `bumpalo`, `ring` and `serde_json`.
Everything else in the workspace builds on it: `sip-script`, `sip-transport`,
every `mod-*` crate, `bin/ferrosip`, `tools/sipflood` and the fuzz targets.
The crate is `#![forbid(unsafe_code)]`.

## Contents

| File | Provides |
|---|---|
| `src/lib.rs` | Module list and re-exports (`Ctx`, `Module`, `Registry`, `Lumps`, `Dest`, `Proto`, `ShardedMap`, `TimerWheel`, `RouteHub`, `Val`, …) |
| `src/module.rs` | `Ctx`. The `Module` and `Handler` traits. The script return codes (`RC_OK` 1, `RC_ERR` -1, `RC_DROP` 0, `rc(bool)`). `Registry` (`export`, `pv`, `provide`/`api`, `rpc`, `hub`). `Arg`/`DynStr`/`DynInt`, `Branch`. Per-message extension types (`BodyOverride`, `ReplyExtra`, `ReplyCapture`, `FakedMsg`, `RuriPath`, …) |
| `src/net.rs` | `Proto` (UDP/TCP/TLS/WS/WSS), `Dest` (≈ `dest_info`), the `Outbound` send trait, `TransportEvent`, the filter and taps on outgoing messages, `alias=` hosts and `is_myself` |
| `src/lumps.rs` | `Lumps`: edits recorded against the receive buffer and applied in one pass. Edits stay in push order, so `truncate(mark)` after `apply` removes exactly the temporary edits. Out-of-range offsets are clipped |
| `src/limit.rs` | `Limiter` (a counted budget) and `KeyedLimiter` (a budget per key), each with an RAII `Permit`. Used for `tcp_max_connections` and `tcp_accept_iplimit`. Built on `loom::sync` under `--cfg loom`. Loom models check every interleaving (`RUSTFLAGS="--cfg loom" cargo test -p sip-core --release loom`) |
| `src/panic.rs` | Panic policy: `catch` (a recoverable unit of work, counted in `core:panics`), `expendable` (per-connection threads), `install_hook` (other panics abort) |
| `src/shutdown.rs` | Graceful-shutdown state: `begin`, `draining`, `starts_new_work`. While draining, initial requests are refused with 503 |
| `src/reply.rs` | `build_reply*`: stateless replies (≈ `sl_send_reply`) |
| `src/pv.rs` | Pseudo-variable engine: `Val`, `PvSpec`, `PvRef`, `Fmt` templates, `parse_pv` / `parse_fmt`, transformations (`apply_tr`) |
| `src/pvcore.rs` | The core variables (`$ru`, `$fU`, `$hdr(...)`, `$var`, `$avp`, `$xavp`, `$shv`, …), `TxnVars`, URI helpers (`rebuild_uri`, `dest_from_uri`, `dest_to_uri`) |
| `src/corefns.rs` | `CoreModule`: core script functions and RPCs |
| `src/route.rs` | `RouteHub` / `RouteRunner`: lets modules run `failure_route`, `onreply_route`, `branch_route`, `event_route` and `route`. `Continuation` / `AsyncPending` for suspended scripts |
| `src/rr.rs` | `RecordRoute` / `RrEntry`: Record-Route and Path headers rendered per branch (double RR, `r2=on`) |
| `src/flow.rs` | RFC 5626 flow tokens (HMAC-SHA256, base32hex) for the `outbound` module |
| `src/shm.rs` | `ShardedMap` (≈ shm hash tables with a lock per bucket) and `FxHasher` / `fx_hash` |
| `src/timer.rs` | `TimerWheel<T>` |
| `src/sync.rs` | `lock` / `read` / `write`: `Mutex` and `RwLock` guards that recover from poisoning. A panic caught for one message must not wedge a shared table |
| `src/time.rs` | `unix_secs`, `unix_ms`, `unix_secs_f64`: wall-clock time since the Unix epoch |
| `src/stats.rs` | Named `group:name` counters and computed gauges |
| `src/rpc.rs` | `RpcTable`: JSON-RPC 2.0 dispatch, UNIX socket server, `str_param` / `int_param` helpers |
| `src/dns.rs` | DNS client (A, AAAA, SRV, NAPTR) with a TTL cache and RFC 3263 `resolve_uri` |
| `src/blst.rs` | Destination blocklist (≈ `dst_blocklist`) |
| `src/json.rs` | JSON paths (`a.b[2].c`) used by `{json.parse}` and jansson |
| `src/log.rs` | Kamailio log levels (`L_ALERT` … `L_DBG`), `set_level`, `parse`, `log` |

## Key types and APIs

### `Ctx` — one message being processed

`Ctx<'a, 'm>` holds everything about the message being processed:

- the parsed message (`msg: &mut Msg`) and its `lumps`;
- a reusable output buffer;
- the sender (`net: &dyn Outbound`) and the receiving UDP
  [worker](../../docs/glossary.md#worker)'s own socket;
- the source `Dest`, including the TCP/TLS connection id;
- the script state: `new_ruri` (`$ru`), `dst` (`$du`), `rc` (`$rc`),
  `branches` (the [destination set](../../docs/glossary.md#destination-set)),
  `ruri_q`, and `last_error` (for `sl_reply_error()`).

Modules attach their own per-message state by type through `ext`. Use
`ctx.ext::<T>()`, `ctx.ext_get_mut::<T>()` and `ctx.ext_mut::<T>()`. The last
one creates the value with `Default` on first use. The vector stays empty
unless a module uses it, so it costs nothing on the fast path.

- `ctx.send_reply(code, reason)`: sl's `send_reply()`. While tm answers
  for the request (a `TxnReply` in `ext`: a failure route, or a request
  route whose relay failed), the reply goes through the transaction, which
  may refuse it once it has its final; else it is stateless (`ctx.reply()`).
- `DelayedReply` in `ext`: tm answers a failed relay when the script ends
  (Kamailio's `FL_DELAYED_REPLY`); `sl_reply_error()` sends nothing then.
- `ctx.at_script_end(f)`: runs `f` once `request_route` has ended
  (Kamailio's post-script callbacks); the script engine calls
  `ctx.run_script_end()`.

- `ctx.render()` / `ctx.render_uri(Some(uri))`: writes the original buffer
  plus the lumps into `ctx.out`. It also applies the
  [R-URI](../../docs/glossary.md#r-uri) rewrite and the body override.
- `ctx.send(&dst, data)`, `ctx.send_rendered(&dst)`: UDP goes out on the
  worker's own socket. Everything else goes through `Outbound::send`.
- `ctx.reply(code, reason)`, `ctx.reply_with(code, reason, extra_hdrs)`:
  send a stateless reply to the source. This bumps the `sl:*` counters.
- `ctx.body()`, `ctx.set_body(body, ctype)`: body rewrites compose. The
  Content-Length and Content-Type are fixed when the message is rendered.

### `Module` and `Registry` — exported functions with fixups

A [module](../../docs/glossary.md#module) implements `Module`. It must
provide `name` and `register`. It may also provide `set_param`, `on_reply`,
`spawn`, `on_transport_event`, and `observes` / `observe_request` /
`observe_reply`.

In `register` the module exports script functions with
`Registry::export(module, name, fixup, func)`. The fixup runs once at startup
on the literal arguments. The function runs for each message with the fixed
value. Return values follow Kamailio's
[return code convention](../../docs/glossary.md#return-code-convention):
`> 0` is true, `< 0` is false, and `0` ends the route.

A function or variable registered twice makes `Registry::load` fail. The
first registration is kept. `spawn` returns `Result<(), String>`. An error
there is a startup error, and ferrosip exits 1.

```rust
use sip_core::{want_args, Arg, Ctx, Module, Registry};
use std::sync::Arc;

struct Hello;

impl Module for Hello {
    fn name(&self) -> &'static str { "hello" }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let hits = sip_core::stats::counter("hello", "hits");
        // has_prefix("+49"): the argument is converted once, at startup.
        reg.export(
            "hello",
            "has_prefix",
            |a: &[Arg]| { want_args(a, 1)?; Ok(a[0].str()?.as_bytes().to_vec()) },
            move |ctx: &mut Ctx, p: &Vec<u8>| {
                sip_core::stats::inc(hits);
                if ctx.ruri().starts_with(p) { 1 } else { -1 }
            },
        );
        reg.rpc.add("hello.ping", "Answers pong", |_| Ok(sip_core::serde_json::json!("pong")));
        Ok(())
    }
}
```

An `Arg` is `Str`, `Int` or `Fmt`. A `Fmt` is a template with variables in it.
A fixup uses `a.str()` / `a.int()` for constants. It uses `a.dyn_str()` /
`a.dyn_int()` to accept variables, which are then evaluated for each message
with `DynStr::eval(ctx)` / `DynInt::eval(ctx)`.

Modules can also offer typed APIs to each other, like Kamailio's `bind_*` /
`load_*_api`. A module publishes one with `reg.provide(Arc<T>)`, and another
looks it up with `reg.api::<T>()`.

### Pseudo-variables

`reg.pv(name, PvSpec)` registers `$name` / `$name(param)`. `PvSpec::ro(get)`
and `PvSpec::rw(get, set)` take closures over `(&mut Ctx, &PvParam)`.
`.with_param()` requires the `(param)` form. `.with_fix(...)` pre-computes
from the parameter at startup.

`parse_pv(s, table)` resolves one variable, with its index and
transformations, into a `PvRef`. `parse_fmt(s, table)` compiles a string with
embedded variables into a `Fmt`. In such a string `$$` is a literal `$`.
Values are `Val::{Null, Int, Str}`, with Kamailio's rules for what counts as
true.

### Lumps and replies

```rust
use sip_core::Lumps;

let mut l = Lumps::default();
l.delete(2, 3);
l.insert(0, "A");
l.replace(7, 1, "XYZ");
let mut out = Vec::new();
l.apply(b"0123456789", &mut out); // b"A0156XYZ89"
```

Edits at the same offset keep their insertion order.

`reply::build_reply`, `build_reply_with` and `build_reply_body` copy
Via/From/Call-ID/CSeq/To from the request. For codes above 100 they add a
deterministic To-[tag](../../docs/glossary.md#tag): a hash of the Call-ID.
So a retransmitted request gets an identical reply without any state.

### Shared state, timers, statistics

`shm::Bounded` gates inserts into caches whose keys come from data a peer
controls, such as the DNS caches and the blocklist. Every 1024 admissions it
sweeps out expired entries. Once it holds `cap` live entries, it stops
admitting new keys.

`stats::get_kinds` reports whether each statistic is a
[counter](../../docs/glossary.md#counter) or a
[gauge](../../docs/glossary.md#gauge). The
[Prometheus](../../docs/glossary.md#prometheus-metric) output uses this for
its types. `Module::busy()` and `Module::shutdown()` are the hooks for
[graceful shutdown](../../docs/glossary.md#graceful-shutdown).

```rust
use sip_core::{ShardedMap, TimerWheel};

let m: ShardedMap<String, u32> = ShardedMap::new(1024); // rounded up to a power of two
m.insert("alice".into(), 1);
m.with("alice", |v| *v += 1);            // only that shard is locked
let removed = m.remove_if("alice", |v| *v > 1);

let mut w = TimerWheel::new(8192);
w.schedule(3, "retransmit");
let mut due = Vec::new();
w.advance(&mut due);                      // one tick
```

`ShardedMap` also has `insert_if_absent`, `get_cloned`, `alter`, `retain`,
`for_each_mut` and `len`. `alter` is a read-modify-write under the shard
lock.

- `stats::counter(group, name)` returns a `&'static AtomicI64`. The same
  name always gives the same counter.
- `stats::gauge(group, name, f)` registers a computed value.
- `stats::get(spec)` / `stats::reset(spec)` take `all`, `group:`,
  `group:name` or a bare `name`.

### Networking

- `Dest::parse("tls:sip.example.com:5061")` resolves the address once. A
  bare `host:port` is UDP. When the host was a name, `Dest` remembers it, so
  outbound TLS can verify the certificate by name.
- `Outbound` (`send`, `advertise`, `accepts_aliases`, `add_alias`) is
  implemented by `sip-transport`. Modules and timer threads send through it.
- `net::set_send_filter` installs one rewrite filter for every outgoing
  message. [Topology hiding](../../docs/glossary.md#topology-hiding)
  (topoh/topos) uses it. `net::add_send_tap` adds observers, such as
  [siptrace](../../docs/glossary.md#siptrace).
- `net::is_myself(net, host)` answers
  `X == myself` ([myself](../../docs/glossary.md#myself)). It checks the
  advertised addresses and the aliases added with `net::add_alias`. Aliases
  come from `-A` and from the domain module.

### Routes triggered by modules

Modules can't depend on the script engine. So the engine registers itself
in `Registry::hub`, which is a `RouteHub`. It registers the route names
first, so that `t_on_failure("x")` resolves to an index during fixups. Then
it registers a `RouteRunner`.

Modules use `hub.failure_index(name)`, `hub.event_index(name)`,
`hub.run_event_with(name, net, msg, prepare)` and `hub.run_route_with(...)`.
When the event has no SIP message, the last two build a faked
[OPTIONS](../../docs/glossary.md#options) request to run on.

A function that [suspends](../../docs/glossary.md#suspend-and-resume) a
message pushes an `AsyncPending` into the `Ctx` and returns 0. The engine
then hands it a `Continuation`, which `RouteRunner::resume` accepts.

### DNS and blocklist

`dns::resolver()` is the resolver for the whole process.
`resolve_uri(host, port, proto, secure)` follows RFC 3263:

1. IP literals, an explicit port and names in `/etc/hosts` go straight to
   address lookup.
2. Otherwise it tries NAPTR. It does so only when `try_naptr` is set and no
   transport was given.
3. Then SRV (`_sip._udp`, `_sip._tcp`, `_sips._tcp`).
4. Then A/AAAA.

Addresses come from the SRV answer's additional section when present. Next
it asks the configured nameserver, and last the system resolver.

Tunables: `set_server`, `set_timeout` (default 1000 ms), `set_negative_ttl`
(default 60 s), and the `srv_lb`, `try_naptr` and `srv_lookup` flags.

`blst::blocklist()` offers `add(&dest, secs)`, `is_blocked`, `del`, `list`
and `flush`. Entries last 60 s by default (`set_expire`).

## Design notes

- **Fixups, not lookups.** Function names, arguments and variables are
  resolved once at startup (`Registry::export`, `PvSpec::with_fix`). For each
  message only function pointers and pre-parsed values are used.
- **Lumps instead of re-serialisation.** The outgoing message is the receive
  buffer plus splices (`Lumps::apply`), like Kamailio's `data_lump.c`. The
  R-URI rewrite and the body override are added as temporary lumps at render
  time. So they can still change before the next render.
- **Sharded shared tables.** `ShardedMap` splits a map into shards that are
  locked independently (`std::sync::Mutex`, a futex on Linux). Poisoning is
  ignored, so a panicking worker can't wedge the others.
- **FxHash with a finalizer.** `FxHasher` is a fast non-cryptographic hasher.
  Its `finish()` adds a splitmix64 step. SIP
  [branch](../../docs/glossary.md#branch-parameter) ids differ mostly in
  their tail bytes, and without this step they would collide in the low bits.
  A unit test checks the bucket spread.
- **Timer wheel.** `schedule` is O(1). Each tick costs O(entries in slot).
  Items more than one revolution away stay in their slot. Drained slots give
  their buffer back. This fixed an RSS growth that the soak test found.
- **Lock-free counters.** Statistics are `AtomicI64`s bumped with relaxed
  ordering. Gauges are closures, evaluated only when read.
- **Blocklist and taps cost nothing when unused.** While the list is empty,
  `is_blocked` checks one atomic flag. `filtered()` checks one flag before it
  touches the tap list.
- **RPC isolation.** Each RPC handler runs under `catch_unwind`. A panic
  becomes a JSON-RPC error.
- **Untrusted input.** JSON paths never create more than 1024 `null`s to
  reach an index. DNS responses are parsed defensively, and a truncated UDP
  answer is retried over TCP.

## Script-visible features

`CoreModule` (`src/corefns.rs`) is loaded before any module. It registers:

| Kind | Names |
|---|---|
| Functions | `setflag(n)`, `resetflag(n)`, `isflagset(n)` (0..63), `setbflag(n[, 0])`, `resetbflag`, `isbflagset` (0..31, R-URI branch only), `reply(code, reason)`, `sl_reply_error()`, `append_hdr("Name: value")`, `remove_hdr("Name")`, `ruri_user_prefix("+49")`, `append_branch(uri[, q])` (-1 once the destination set holds `max_branches - 1` entries, as Kamailio's core `dset.c`), `rewriteuri(uri)`, `log(text)`, `force_rport()`, `add_rport()` (no-op). `force_rport()` sends replies to this request to its source port even without `;rport`. It matters only with `[core] force_rport = false` |
| RPC | `core.uptime`, `core.version`, `stats.get_statistics`, `stats.reset_statistics`. `RpcTable` itself answers `system.listMethods` and `system.methodHelp` |
| Statistics | `sl:sent_replies`, `sl:1xx_replies` … `sl:6xx_replies` (bumped by `Ctx::reply_with`) |

The functions cover [flags](../../docs/glossary.md#flags),
[branch flags](../../docs/glossary.md#branch-flags) and
[rport](../../docs/glossary.md#rport).

Pseudo-variables from `src/pvcore.rs`:

- Request-URI and next hop: `$ru $rU $rd $rp` (writable), `$rz` (scheme),
  `$du` (writable, the [destination URI](../../docs/glossary.md#destination-uri)).
- From/To: `$fu $fU $fd $fn $ft`, `$tu $tU $td $tn $tt`.
- Message: `$ci $cs $rm $rs $rr $ua $ct $cT $rb $ml $mb $hdr(Name) $hdrc(Name)`.
  `$hdr(Name)[i]` picks one header. Negative indexes count from the end, and
  `[*]` joins all.
- Transport: `$si $sp $pr $proto $af $conid $Ri $Rp`.
- Storage:
  - `$var(x)` lives for one message.
  - `$avp(x)` and `$xavp(root[i]=>field)` live in `TxnVars`.
    [tm](../../docs/glossary.md#tm) carries them into the transaction. See
    [AVP](../../docs/glossary.md#avp) and [xavp](../../docs/glossary.md#xavp).
  - `$shv(x)` is shared by all workers.
- Misc: `$rc $retcode $null $Ts $RANDOM $pp $env(NAME)`.

Transformations (`src/pv.rs`): `s.len s.int s.tolower s.toupper s.trim s.rtrim
s.ltrim s.substr s.select s.strip s.striptail s.prefixes s.replace s.unquote
s.numeric`, `uri.user uri.host uri.port uri.transport uri.scheme uri.params
uri.param`, `param.value param.exist param.count`, `nameaddr.uri
nameaddr.name`, `tobody.uri tobody.tag`, `json.parse`. They chain from left to
right: `$(fU{s.substr,0,3}{s.len})`.

## Testing

- Unit tests: `cargo test -p sip-core`. They cover lumps, the timer wheel,
  the hash spread of the sharded map, stats, RPC dispatch, pseudo-variable
  parsing and transformations, URI rebuild, flow tokens, the blocklist, JSON
  paths and DNS parsing.
- Fuzz targets:
  - `fuzz/fuzz_targets/pv.rs` runs `parse_fmt` / `parse_pv` against a
    registry with `CoreModule`.
  - `fuzz/fuzz_targets/dns.rs` runs `dns::parse` and `json::get`.

  Run one with `cd fuzz && cargo +nightly fuzz run pv`, or all targets with
  `fuzz/run.sh`.
- End-to-end:
  - `tests/e2e_script.py`: pseudo-variables, flags/AVPs in failure routes,
    the RPC socket.
  - `tests/e2e_utils.py`: statistics.
  - `tests/e2e_dns.py`: NAPTR/SRV resolution, the blocklist and failover.
