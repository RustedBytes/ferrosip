# sipflood

`sipflood` measures how fast ferrosip relays SIP. It is a load generator
plus a dummy [UAS](../../docs/glossary.md#uas) that answers everything. Use
it to benchmark ferrosip over UDP, TCP, TLS,
[WS and WSS](../../docs/glossary.md#websocket), or to compare two builds.
All numbers in the top-level README were measured with it.

It uses ferrosip's own parser (`sip-parser`), reply builder (`sip-core`)
and TLS/WebSocket code (`sip-transport`). So it is fast enough to saturate
the proxy on the same box.

```bash
sipflood uas   <proto:ip:port> [--cert C --key K]
sipflood bench <proto:ip:port> [total] [window] [METHOD] [ruri-user] [--ca CA] [--ws-deflate]
```

## `uas`: answer everything

| Argument | Default | Meaning |
|---|---|---|
| `proto:ip:port` | `udp:127.0.0.1:5070` | Where to listen (`udp`, `tcp`, `tls`) |
| `--cert`, `--key` | | Server certificate and key, required for `tls:` |

It answers every request except [ACK](../../docs/glossary.md#ack) with
`200 OK`, built with `sip_core::reply::build_reply`. Replies get no answer.
UDP uses one socket with an 8 MB receive buffer. TCP and TLS use one thread
per connection, with RFC 3261 stream framing (`stream_frame`).

## `bench`: measure throughput and latency

| Argument | Default | Meaning |
|---|---|---|
| `proto:ip:port` | `udp:127.0.0.1:5060` | Target: `udp`, `tcp`, `tls`, `ws` or `wss` |
| `total` | 100000 | Requests to send |
| `window` | 200 | Maximum requests in flight |
| `METHOD` | `OPTIONS` | Request method |
| `ruri-user` | `bench` | R-URI user, which the script can route on (for example by prefix) |
| `--ca CA` | | CA bundle to verify a `tls:`/`wss:` target |
| `--ws-deflate` | off | Offer permessage-deflate on `ws:`/`wss:` |

`ruri-user` is the user part of the [R-URI](../../docs/glossary.md#r-uri).

Each request gets a [branch](../../docs/glossary.md#branch-parameter) that
is unique across runs, built from the process id and a timestamp. So the
proxy never mistakes a new run for
[retransmissions](../../docs/glossary.md#retransmission).

With `REGISTER`, every request uses its own
[AoR](../../docs/glossary.md#aor) and [Contact](../../docs/glossary.md#contact)
(`{user}{n}`). So the [registrar's](../../docs/glossary.md#registrar)
[location table](../../docs/glossary.md#location-service) grows to `total`
bindings.

On `ws:` and `wss:` it behaves like a browser: HTTP Upgrade, masked frames.

A request outstanding for more than 2 s counts as lost. The result is one
line:

```
100000 OPTIONS over UDP in 0.36s → 280000 req/s | 200: 100000, other: 0, lost: 0 | p50 210.4µs p99 518.9µs
```

## Typical setup

```bash
cargo build --release && etc/tls/gen-certs.sh
target/release/sipflood uas udp:127.0.0.1:5070 &
target/release/ferrosip -f target/bench1.cfg -l udp:127.0.0.1:5090 -n 2 &
#   bench1.cfg:  loadmodule "tm"
#                request_route { t_relay("udp:127.0.0.1:5070"); }
target/release/sipflood bench udp:127.0.0.1:5090 100000 200          # stateful relay
target/release/sipflood bench tls:127.0.0.1:5061 200000 64 MESSAGE tcpuser --ca etc/tls/ca.pem
```

For before/after comparisons, run the old and new builds alternately
several times and compare medians. On shared machines the results come in
clusters, so a single run means little.
