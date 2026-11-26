# s02-static-relay (small)

This scenario models the simplest useful proxy: a static relay. Every
request from a trusted source goes to one upstream. It proves that the
proxy handles a silent, slow or unreachable upstream with the right
timeouts, and that it sets the reply address fields on the way through.

```
UA ──UDP──▶ ferrosip ──UDP──▶ upstream (features.upstream)
            │ Via on top, Max-Forwards − 1, received/rport on the UA's Via
            │ silent upstream: 408 after fr_timer (1s) / fr_inv_timer (3s, after a 1xx)
            │ untrusted source: 403
```

**Shows**:
- `msg.dst_uri = features.upstream` (the
  [destination URI](../../../docs/glossary.md#destination-uri)) and a
  stateful `relay(msg)` (see
  [stateful proxy](../../../docs/glossary.md#stateful-proxy));
- `[modules.txn]` timers (see
  [final response timer](../../../docs/glossary.md#final-response-timer));
- `ip.in_subnet(msg.src.ip, …)` as the source check.

**Edge cases checked** (`tests/scenarios/s02_static_relay.py`):
- The relayed request has the proxy's [Via](../../../docs/glossary.md#via)
  (z9hG4bK [branch](../../../docs/glossary.md#branch-parameter)) on top
  and Max-Forwards 69. The reply comes back with that Via removed.
- Via handling (RFC 3261 §18.2, RFC 3581), with
  [`received`](../../../docs/glossary.md#received) and
  [`rport`](../../../docs/glossary.md#rport):
  - A Via with `;rport` gets `rport=<source port>` and `received=` in the
    relayed copy. The reply goes to the source port even when sent-by
    names another one.
  - Without `;rport` the reply still goes to the source address. By
    default ferrosip routes responses symmetrically, as if `force_rport()`
    were on (see docs/sip.md).
  - A second proxy has `[core] force_rport = false`. It shows the
    RFC 3261 §18.2.2 / [Kamailio](../../../docs/glossary.md#kamailio)
    behaviour. Without `;rport` the reply goes to the Via sent-by port.
    With `;rport` it goes to the source port.
  - A host name as sent-by gets `received=<source IP>`.
- A silent upstream:
  - A [MESSAGE](../../../docs/glossary.md#message) gets 408 after about
    `fr_timer` (1s). It is
    [retransmitted](../../../docs/glossary.md#retransmission) meanwhile on
    one branch.
  - An [INVITE](../../../docs/glossary.md#invite) gets the proxy's 100,
    then 408 after `fr_timer`, not `fr_inv_timer`.
  - The caller's [ACK](../../../docs/glossary.md#ack) to that 408 is
    absorbed.
- An upstream that rings and never answers gets 408 after `fr_inv_timer`
  (3s). The proxy sends a [CANCEL](../../../docs/glossary.md#cancel) to
  the ringing branch (RFC 3261 §16.8, timer C).
- A CANCEL from the caller: 200 for the CANCEL, 487 for the INVITE, and
  the CANCEL is relayed.
- The upstream's port is closed (ICMP port unreachable). The caller gets
  408 after `fr_timer`, as in Kamailio. UDP send errors aren't reported
  back. RFC 3261 §18.4 only says SHOULD treat them as a 503.
- A source outside `TRUSTED` gets `403 Not trusted`, and nothing is
  relayed.

**Run it by hand**: `ferrosip --config ferrosip.toml`. It listens on port
5060, with upstream `sip:127.0.0.1:5080`. Set `SIP_PORT`, `UPSTREAM`,
`TRUSTED` to change them.
