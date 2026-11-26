# m07-load-balancer (medium)

This scenario models a load balancer in front of a pool of three
application servers. It uses the balancer module, which is
[Kamailio's](../../../docs/glossary.md#kamailio)
[dispatcher](../../../docs/glossary.md#dispatcher). It proves that calls
are spread over the live servers, that dead servers are detected and
skipped, and that they rejoin the pool when they come back.

```
                          ┌─▶ as1 ┐
caller ──▶ ferrosip ──────┼─▶ as2 ├─ round robin (alg 4) over the active ones
           balancer.select│   as3 ┘  ✗ dead: probes fail → inactive, skipped
           await + next   │
           OPTIONS probes every 1s ─▶ on balancer.down / up ─▶ shared table
                                                                │
           GET /balancer?<uri> (on http) ◀──────────────────────┘
```

**Shows**:
- `[modules.balancer]` with a `list_file` from the environment
  (`DS_LIST`);
- probing of every destination with [OPTIONS](../../../docs/glossary.md#options)
  (`ds_probing_mode = "all"`, `ds_ping_interval = "1s"`);
- `balancer.select(1, 4)` (round robin);
- a failover loop with `await txn.relay` and `balancer.next()` (see
  [await](../../../docs/glossary.md#await));
- `balancer.mark("ip")` for a server that never answered;
- `on balancer.down` / `on balancer.up` writing a
  [`shared table`](../../../docs/glossary.md#shared-table) that an
  `on http` handler serves (see
  [event handler](../../../docs/glossary.md#event-handler));
- `ip.in_subnet` as the trusted-source check. The balancer only takes
  traffic from the front-end proxies.

The failover marks a server inactive only when it did not answer at all
(`Timeout`). A 5xx means the server is alive but unable to take this call.
So the next server is tried without taking the first one out of the pool.

**Edge cases checked** (`tests/scenarios/m07_load_balancer.py`):
- A server that answers neither probes nor calls is found by probing
  (`on balancer.down`, `I` in `dispatcher.list`). It never gets a call.
  The live servers raise no event.
- Round robin with one dead server: both live servers get calls.
  Kamailio gives the dead one's turn to the next active one, so 4/2 is as
  right as 3/3.
- A 503 from the chosen server → the other one answers:
  - one [INVITE](../../../docs/glossary.md#invite) each;
  - the 503 doesn't mark the server down;
  - the failover [branch](../../../docs/glossary.md#branch) must carry the
    [Record-Route](../../../docs/glossary.md#record-route) added before the
    `await`, so the [BYE](../../../docs/glossary.md#bye) can follow it.
- Both live servers send 503 → `503 All servers failed`. The dead one is
  never tried.
- A server that answers probes but not the INVITE:
  - timeout after `fr_timer` (see
    [final response timer](../../../docs/glossary.md#final-response-timer));
  - the call goes to the other one;
  - `balancer.mark("ip")` raises `on balancer.down`;
  - the next probe raises `on balancer.up`.
- The dead server comes back: `on balancer.up`, it is active again, and
  round robin over all three gives 2 calls each.
- Every server down: `503 No server available` at once, and no INVITE is
  sent.
- A never-incremented `Counter` reads 0 (docs/fsr.md).
- A [MESSAGE](../../../docs/glossary.md#message) gets 405. An HTTP path
  that no handler matches gets 404.

**Run it by hand**: `ferrosip --config ferrosip.toml` from this directory.
`SIP_PORT` is 5060, `HTTP_PORT` 8080, and `DS_LIST` defaults to
`dispatcher.list`, with servers on 127.0.0.1:5071…5073. Then run
`curl 'http://127.0.0.1:8080/balancer?sip:127.0.0.1:5073'`.
