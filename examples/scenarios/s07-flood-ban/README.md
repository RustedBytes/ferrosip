# s07-flood-ban (small)

This scenario models flood protection per source address. A source that
sends too many requests in one second is banned for a while. An HTTP API
lists and clears the bans. It proves that the rate window resets every
second, that a ban expires on time even while the source keeps sending,
and that the API changes only what it should.

```
UA ──UDP──▶ ferrosip ─ hits[ip:port] > 10 in this second? ─ ban 5s, drop
            │ banned: drop                 on timer(every: 1s): hits.clear()
            │ OPTIONS: 200 here · else: relay ──▶ upstream
HTTP ──────▶ GET /bans (count) · GET /bans?ip:port · DELETE /bans[?ip:port] · GET /stats
```

**Shows**:
- [`shared table`](../../../docs/glossary.md#shared-table) counters
  (`hits.incr`) and a ban table with a ttl;
- `on timer(every: 1s)`;
- `on http(req)` handlers with `where` on path and method, and a
  catch-all (see [event handler](../../../docs/glossary.md#event-handler));
- `[modules.http] listen`.

Design notes:
- **Why the timer:** a table's ttl runs from an item's *last update*. So a
  counter that keeps being incremented never expires, and the ttl can't be
  the rate window. The timer empties `hits` every second instead. The ttl
  only forgets quiet sources.
- **The ban time** is written in the routing (`ttl 5s`, a cool-down). A
  [`[feature]`](../../../docs/glossary.md#feature-switch) is a Bool, Int
  or Str, never a Duration, so it can't feed a ttl. A banned source is
  dropped before its item is touched. So the ban expires 5s after it was
  set, even if the source keeps sending. Tables expire in whole seconds,
  as [Kamailio's](../../../docs/glossary.md#kamailio)
  [htable](../../../docs/glossary.md#htable) does: 5 to 6 s.
- **Counting the bans:** `.fsr` has no way to walk a table. So `GET
  /bans` counts the keys with htable's `$shtcn` through the
  [escape hatch](../../../docs/glossary.md#escape-hatch) (`pv(…)`). The
  `raw_kamailio` lint for that is pedantic, off by default. You can list
  the bans themselves with `ferroctl htable.dump bans`.

**Edge cases checked** (`tests/scenarios/s07_flood_ban.py`):
- The timer runs: the `sweeps` counter grows about 1 per second.
- 20 requests at ~6/s are all answered. That is more than the limit in
  all, but under it per second. The sweep resets the window.
- A burst of 30 at once:
  - 10 to 20 are answered, because the sweep may fall inside the burst;
  - then the source is dropped, [OPTIONS](../../../docs/glossary.md#options)
    and relayed requests alike;
  - another port on the same IP is still served and relayed.
- `GET /bans?ip:port` is 200 for the flooder and 404 for a good source.
  `GET /bans` counts 1. `/stats` counts the ban.
- The ban expires after 5s although the source kept sending. The expired
  item is no longer counted.
- `DELETE /bans?ip:port` lifts one ban. The source is served once its
  window is swept. Otherwise its old count bans it again at once.
  `DELETE /bans` lifts two.
- `POST /bans` and unknown paths get the catch-all 404 and change
  nothing.

**Run it by hand**: `ferrosip --config ferrosip.toml`. SIP is on 5060 and
HTTP on 8080, with upstream `sip:127.0.0.1:5080`. Set `SIP_PORT`,
`HTTP_PORT`, `UPSTREAM`, `TRUSTED`.
