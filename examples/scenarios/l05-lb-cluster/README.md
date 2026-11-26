# l05-lb-cluster (large)

This scenario models a ferrosip load balancer in front of three ferrosip
application proxies, which relay to one [UAS](../../../docs/glossary.md#uas).
It proves that calls are spread evenly, that a proxy killed mid-test is
detected and skipped, that it rejoins after a restart, and that calls
already set up are not rerouted.

```
             ┌──────────── OPTIONS probes every 1s ───────────┐
             │                                                ▼
caller ──▶ lb ── round robin (balancer set 1) ──▶ app1 ┐
             │   no answer / 5xx: mark, next ───▶ app2 ├──X-App──▶ UAS
             │                                   app3 ┘
             └ on balancer.down / up: log
```

`app/` is one configuration started three times (`APP_PORT`,
`APP_NAME`). The test writes the balancer's list file for the ports it
was given (`DISPATCHER_LIST`). `lb/dispatcher.list` is the default for a
run by hand.

**Shows**:
- **lb:**
  - `balancer.select(1, 4)` (round robin; see
    [dispatcher](../../../docs/glossary.md#dispatcher));
  - then a `while true` loop around `await txn.relay`, with
    `balancer.mark("ip")` and `balancer.next()` on a 5xx, a 408 or no
    answer (`fr_timer = 1s`);
  - probing with [OPTIONS](../../../docs/glossary.md#options):
    `ds_ping_interval`, `ds_probing_mode = "all"`;
  - the `on balancer.down` / `on balancer.up` events;
  - [Record-Route](../../../docs/glossary.md#record-route), and
    `route_set.follow()` for
    [in-dialog requests](../../../docs/glossary.md#in-dialog-request).
    They go back through the app proxy that took the call, with no
    failover;
  - the source ACL is `ip.in_subnet`.
- **app:** `sip.options_reply()` answers the probes. It stamps
  `X-App: <name>` and relays to the UAS.

**Edge cases checked** (`tests/scenarios/l05_lb_cluster.py`):
- All three app proxies are active at start, and 6 calls are spread
  2/2/2.
- A call is held up through app2, then app2 is killed (`Proxy.kill()`).
  A UDP socket that never answers takes its address, to show what the
  balancer still sends there.
- Right after the kill, 3 calls all succeed through app1 / app3. At most
  one was tried on app2 first, and failed over after `fr_timer`.
- The held call's [BYE](../../../docs/glossary.md#bye) follows the route
  set to app2 and fails with 408. In-dialog requests are not rerouted.
- Probing marks app2 inactive (`dispatcher.list` flags `I…`), and
  `on balancer.down` logs it. The next 4 calls go to app1 and app3 only.
  None is sent to app2's address. Round robin skips the inactive one to
  the next active one, as [Kamailio's](../../../docs/glossary.md#kamailio)
  does, so app3 may get two in a row.
- app2 restarts. Probing marks it active, `on balancer.up` logs it, and 6
  calls are spread 2/2/2 again.
- All three killed: all inactive, and a call gets `503 No app server` at
  once.

**Run it by hand**: start `app` three times from `app/`. Use `APP_PORT`
5071, 5072, 5073 with `APP_NAME` app1…app3, and `UAS` (default
`sip:127.0.0.1:5080`). Then start `lb` from `lb/` (`LB_PORT` 5060).
