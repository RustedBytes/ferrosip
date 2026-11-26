# mod-ops

Operations modules: tools that help you run and watch a ferrosip proxy in
production. The crate has three:

- `keepalive` sends [OPTIONS](../../docs/glossary.md#options) health checks
  to any destinations you list, and tracks whether each is up or down.
- `sipdump` dumps every SIP message received and sent. It writes them as
  text or [pcap](../../docs/glossary.md#pcap), or hands them to an
  [event route](../../docs/glossary.md#event-route). See
  [sipdump](../../docs/glossary.md#sipdump).
- `evapi` is an event API. It pushes data to external applications over TCP
  and takes their answers. An answer can, for example,
  [resume](../../docs/glossary.md#suspend-and-resume) a suspended
  [transaction](../../docs/glossary.md#transaction).

`keepalive` and `evapi_async_relay` use the [tm](../../docs/glossary.md#tm)
module, so load `tm` first.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `keepalive` | `keepalive` | Periodic OPTIONS probes, up/down state, events |
| `sip_dump` | `sipdump` | Every SIP message in and out, to `.data` / `.pcap` files, stderr or an event route |
| `events` | `evapi` | TCP event API: send events to apps, receive their messages |

## keepalive

Every `ping_interval` seconds, each destination gets an OPTIONS request
through the tm [UAC](../../docs/glossary.md#uac) API.

- A 2xx reply marks it up.
- Anything else marks it down. This includes the tm timeout.
- A destination without a `sip:`/`sips:` scheme gets `sip:` prepended.
- When the state changes, the matching event route runs with the
  destination in `$ru`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `destination` | none | URI to monitor. Repeat the parameter for more (owner "config") |
| `ping_interval` | 30 | Seconds between probe rounds (min 1) |
| `ping_from` | `sip:keepalive@ferrosip` | From URI of the probes |
| `delete_counter` | 0 | Remove a destination after this many failed probes in a row. 0 = never |

**Functions**

| Signature | Description |
|---|---|
| `is_alive(uri)` | 1 = up, -1 = down, -2 = not probed yet or not monitored |

**Event routes**

| Route | When |
|---|---|
| `event_route[keepalive:dst-up]` | A destination changed to up (`$ru` = destination) |
| `event_route[keepalive:dst-down]` | A destination changed to down (`$ru` = destination) |

**RPC commands**

| Command | Description |
|---|---|
| `keepalive.list` | All destinations: uri, owner, state (up/down/unknown), failures, last_up, last_down |
| `keepalive.get <uri>` | One destination |
| `keepalive.add <uri> [owner]` | Add a destination (owner defaults to "rpc") and probe it now |
| `keepalive.del <uri>` | Remove a destination |
| `keepalive.flush` | Remove all destinations |

**Example**

```toml
[modules.keepalive]
destination = ["sip:10.0.0.5:5060"]
ping_interval = "10s"
```

```rust
import keepalive

on keepalive.down(e: Destination) {    // event_route[keepalive:dst-down]
    log.warn("{e.uri} is down\n")
}

route main(msg: Request) {
    if keepalive.is_alive("sip:10.0.0.5:5060") {   // false: down or not probed yet
        txn.relay("udp:10.0.0.5:5060")
    }
    reply(ServiceUnavailable, "Unavailable")
}
```

## sip_dump (sipdump)

While it is enabled, it records every SIP message:

- received messages, requests and replies, with the tag `rcv`;
- sent messages, with the tag `snd`. A send tap catches these.

Records go through a channel to a writer thread. So file I/O stays off the
SIP [workers](../../docs/glossary.md#worker).

`mode` is a bitmask of outputs:

- 1: Kamailio's text format, in `<folder>/<fprefix><YYYY-MM-DD--HH-MM-SS>.data`;
- 2: run `event_route[sipdump:msg]` for every record, on the writer thread;
- 4: pcap, in `<folder>/<fprefix><date>.pcap`. It uses LINKTYPE_RAW, with
  IPv4/IPv6 and UDP/TCP headers built from the addresses, so Wireshark
  decodes the SIP;
- 8: the text format, to stderr.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `enable` | 0 | Dump from startup. Switch it at run time with `sipdump.enable` |
| `mode` | 1 | Output bitmask, see above |
| `folder` | `/tmp` | Directory for the files |
| `fprefix` | `ferrosip-sipdump-` | File name prefix |
| `rotate` | 7200 | Open new files after this many seconds |

`wait`, `fage` and `event_callback` are accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `sipdump_send(tag)` | Record the current message with `tag`, whether or not dumping is enabled. Returns 1 |

**Pseudo-variables** (in `event_route[sipdump:msg]`)

`$sipdump(tag)`, `$sipdump(data)` (alias `buf`), `$sipdump(len)`,
`$sipdump(proto)`, `$sipdump(af)`, `$sipdump(src_ip)`,
`$sipdump(src_port)`, `$sipdump(dst_ip)`, `$sipdump(dst_port)`,
`$sipdump(time)` (Unix seconds).

**Event routes**: `event_route[sipdump:msg]` (mode 2).

**RPC commands**

| Command | Description |
|---|---|
| `sipdump.enable [0\|1]` | Sets the switch if a value is given. Returns `{"enable": 0\|1}` |

**Example**

```toml
[modules.sip_dump]
enable = true
mode = 5                          # text + pcap
folder = "/var/log/ferrosip"
```

```rust
import sip_dump

route main(msg: Request) {
    if msg.ruri.user == "debug" { sip_dump.send("mytag") }
    …
}
```

[`.fsr`](../../docs/glossary.md#fsr) has no `sipdump:msg` event. Mode 2
needs a [`.cfg`](../../docs/glossary.md#cfg) event route.

## events (evapi)

A TCP listener on `bind_addr`.

- Messages are netstrings (`len:data,`). With `netstring_format` 0 they are
  one message per line instead.
- Each client runs on its own thread.
- Each message from a client runs `event_route[evapi:message-received]`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `bind_addr` | `127.0.0.1:8448` | Listen address |
| `netstring_format` | 1 | 1 = netstrings (max 1 MB), 0 = newline-terminated |

`workers`, `max_clients`, `wait_idle` and `wait_increase` are accepted and
ignored.

**Functions**

| Signature | Description |
|---|---|
| `evapi_relay(data)` | Send to every client. 1 if at least one got it, else -1 |
| `evapi_unicast(data, tag)` | Send to the first client with that tag. 1 / -1 |
| `evapi_multicast(data, tag)` | Send to every client with that tag. 1 / -1 |
| `evapi_async_relay(data)` | Suspend the transaction (tm), then send `data` to every client. `data` is evaluated after suspending, so it can carry `$T(id_index)` / `$T(id_label)`. Exits the script. Resume with `t_continue()` |
| `evapi_set_tag(tag)` | Tag the client of the current evapi event (use it in `evapi:connection-new`). 1 / -1 |
| `evapi_close()` | Close the client of the current evapi event. 1 / -1 |

**Pseudo-variables** (in the evapi event routes)

`$evapi(msg)`, `$evapi(srcaddr)`, `$evapi(srcport)`, `$evapi(conidx)`.

**Event routes**: `event_route[evapi:connection-new]`,
`event_route[evapi:connection-closed]`,
`event_route[evapi:message-received]`.

**RPC commands**

| Command | Description |
|---|---|
| `evapi.clients` | Connected clients: conidx, addr, tag |

**Example** (from `tests/e2e_ops.py`; the app answers
`continue:<index>:<label>`)

```toml
[modules.events]
bind_addr = "127.0.0.1:8448"
```

This example is a Kamailio-style `.cfg`, for three reasons:

- `.fsr` has no evapi events;
- `$evapi(msg)` is a [pseudo-variable](../../docs/glossary.md#pseudo-variable-pv);
- `evapi_async_relay` / `t_continue` resume in a named route.

`.fsr` has `evapi.relay`, `unicast` and `multicast`.

```
event_route[evapi:connection-new] { evapi_set_tag("app"); }
event_route[evapi:message-received] {
    if ($(evapi(msg){s.select,0,:}) == "continue") {
        t_continue("$(evapi(msg){s.select,1,:})", "$(evapi(msg){s.select,2,:})", "RESUME");
    }
    if ($evapi(msg) == "bye") { evapi_close(); }
}

request_route {
    evapi_async_relay("route:$T(id_index):$T(id_label):$rU");
    exit;
}
route[RESUME] { t_relay(); }
```

**Differences from Kamailio**: there is no worker pool and no client limit.
`workers` and `max_clients` are ignored. Each client has its own thread.

## Testing

- `tests/e2e_ops.py`:
  - keepalive: OPTIONS probes, `is_alive` return codes, dst-up/dst-down
    events, RPC;
  - sipdump: text and pcap files, `sipdump_send`, the mode 2 event route,
    `sipdump.enable`;
  - evapi: netstring clients, tags, unicast, `evapi_async_relay` +
    `t_continue`, `evapi_close`, `evapi.clients`.
- Unit tests: evapi netstring parsing; sipdump text and pcap records (IPv4
  header checksum, record length, file name timestamps).
