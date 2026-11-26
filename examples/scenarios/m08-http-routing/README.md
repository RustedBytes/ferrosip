# m08-http-routing (medium)

This scenario models routing decided by an external HTTP service. For each
call, the proxy asks the service where the call should go. Use this
pattern when routing data lives in another system. It proves that the
proxy uses the service's answer, falls back safely when the service fails
or is slow, and never passes unsafe input to it.

```
caller ──▶ ferrosip ── GET {routing}/route/<ruri user>?caller=<from user> ──▶ routing service
             │          X-Call-ID, X-Caller headers; 1s timeout             │
             │◀──────────────── 200 "ip:port" ──────────────────────────────┘
             ├─▶ sip:<ip:port>                     (the service's answer)
             └─▶ features.fallback + X-Routing-Fallback: <why>
                   404 / 500 / a body that isn't ip:port / too slow / down
```

**Shows**:
- `await http.get(url, headers, timeout: 1s)`, with the URL and the
  headers templated from message fields (see
  [await](../../../docs/glossary.md#await));
- the `HttpResponse` fields (`ok`, `status`, `body`, `error`, `ms`);
- a regex check of the answer (`=~`);
- `route_set.record()` before the `await`, kept on the relayed
  [INVITE](../../../docs/glossary.md#invite);
- `[modules.http_async_client] workers`.

The [R-URI](../../../docs/glossary.md#r-uri) user goes into the URL path.
So it is checked first (`^\+?[0-9A-Za-z]+$`, else 484). A SIP user part
may contain `&`, `=`, `;`, `?` and `/` (RFC 3261 `user-unreserved`). Those
would add parameters or path segments to the query. There is no
URL-encoding function in `.fsr`. A path segment keeps a leading `+`
literal. In a query string it would decode as a space.

`ferrosip fmt` writes a header list with `\n` as a `"""…"""` string over
two lines. That is the canonical layout.

**Edge cases checked** (`tests/scenarios/m08_http_routing.py`):
- The service's target gets the call:
  - the service saw one GET with the templated path, query, `X-Call-ID`
    and `X-Caller`;
  - the INVITE has the [Record-Route](../../../docs/glossary.md#record-route),
    and the [BYE](../../../docs/glossary.md#bye) follows it.
- `+4930123` reaches the service as `/route/+4930123`.
- Each of these goes to the fallback, with `X-Routing-Fallback` naming the
  status or the error, and keeps the Record-Route:
  - 404;
  - 500;
  - a 200 whose body isn't `ip:port`;
  - a service slower than the timeout (the call doesn't wait for it);
  - a closed port (fallback at once).
- User parts with `&`, `%` or `;` get 484. The service never sees them.
- A [CANCEL](../../../docs/glossary.md#cancel) while the query is in
  flight: 200 for the CANCEL, 487 for the INVITE, and no relay when the
  late answer comes in.
- A non-INVITE gets 405.

**Run it by hand**: `ferrosip --config ferrosip.toml`. `SIP_PORT` is 5060,
`ROUTING_URL` is `http://127.0.0.1:8090`, and `FALLBACK` is
`sip:127.0.0.1:5090`.
