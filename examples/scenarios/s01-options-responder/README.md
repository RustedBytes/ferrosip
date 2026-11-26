# s01-options-responder (small)

This scenario models a small proxy that answers health checks itself and
passes everything else to one upstream server. Phones and other proxies
send [OPTIONS](../../../docs/glossary.md#options) requests as a
[keepalive](../../../docs/glossary.md#keepalive). This proxy answers them
locally. It proves that the proxy refuses looping, malformed and untrusted
requests before relaying anything.

```
UA ──UDP──▶ ferrosip ──▶ upstream (features.upstream)
            │ OPTIONS to the proxy: 200 here
            │ Max-Forwards 0: 483 · malformed: 400 · untrusted source: 403
```

**Shows**:
- `guard` chains;
- `sip.check()` (sanity);
- `sip.options_reply()`;
- `ip.in_subnet(msg.src.ip, …)` as the source check;
- [`[feature]`](../../../docs/glossary.md#feature-switch) values for peers.

**Edge cases checked** (`tests/scenarios/s01_options_responder.py`):
- OPTIONS without a user part is answered by the proxy and never relayed.
- `Max-Forwards: 0` gets 483 (see
  [Max-Forwards](../../../docs/glossary.md#max-forwards)).
- A request whose [CSeq](../../../docs/glossary.md#cseq) method doesn't
  match the request line gets sanity's 400. It is not relayed.
- A relayed request has Max-Forwards decremented and the proxy's
  [Via](../../../docs/glossary.md#via) on top. The reply comes back with
  that Via removed.
- A UTF-8 body keeps its bytes and its Content-Length.

**Run it by hand**: `ferrosip --config ferrosip.toml`. It listens on port
5060, with upstream `sip:127.0.0.1:5080`. Set `SIP_PORT`, `UPSTREAM`,
`TRUSTED` to change them.
