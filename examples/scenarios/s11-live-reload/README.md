# s11-live-reload (small)

This scenario models a relay whose routing and timers change while it
runs, without a restart. The change goes through
`ferroctl -s <socket> cfg.reload` (see
[live reload](../../../docs/glossary.md#live-reload) and
[ferroctl](../../../docs/glossary.md#ferroctl)). It proves that a good
reload applies at once under traffic, that a bad one changes nothing, and
that calls in progress finish in the routing they started in.

```
UA ──▶ ferrosip ── X-Routing: v1 · X-Release: features.release ──▶ upstream
        │ INVITE: Record-Route, await txn.relay → 486: "Busy v1"
        │
        └ cfg.reload: routes/main.fsr and ferrosip.toml re-read
          reloadable (fr_timer, [feature] values, the routing): applied at once
          not reloadable (workers, listeners…): reported, the running value kept
          anything that doesn't check: refused, nothing changes
```

**Shows**:
- `cfg.reload` re-reading both layers.
- [`[feature]`](../../../docs/glossary.md#feature-switch) values are
  compiled into the routing. So a changed feature arrives with the reload.
- [`await`](../../../docs/glossary.md#await) continuations survive a
  reload. They finish in the routing they started in, because a position
  in the old code means nothing in the new one.

The test never edits these files. It copies the directory into its temp
directory, starts the proxy from the copy and edits that.

**Edge cases checked** (`tests/scenarios/s11_live_reload.py`). All of
them run while a background UA sends a
[MESSAGE](../../../docs/glossary.md#message) every 20 ms.
- One reload changes three things:
  - a new routing: a header renamed, a statement added before the
    `await`, a different 486 reason;
  - `fr_timer` 1s → 2s;
  - `release` r1 → r2.

  It is reported as applied, and nothing needs a restart. New requests get
  v2 and r2. A silent upstream times out after 2s.
- An [INVITE](../../../docs/glossary.md#invite) that was waiting in
  `await` across the reload gets its 486 with v1's reason. It finishes in
  the routing it was [suspended](../../../docs/glossary.md#suspend-and-resume)
  in, even though v2 added a statement before the `await`: it isn't
  relayed again.
- A call established before the reload hangs up through its
  [Record-Route](../../../docs/glossary.md#record-route).
- `workers` changed: reported under `needs_restart`, and the proxy keeps
  serving.
- These are refused, with nothing changed. The routing, feature and timer
  are checked each time.
  - A `.fsr` syntax error. The error names the file.
  - An unknown function in the `.fsr` together with a valid `fr_timer`
    change. The timer isn't applied either.
  - A valid `.fsr` change together with `fr_timer = "soon"`. The routing
    isn't applied either.
- Five reloads in a row: the last routing runs.
- Every background MESSAGE (several hundred) is answered 200.

**Run it by hand**: `ferrosip --config ferrosip.toml`. It listens on port
5060, with upstream `sip:127.0.0.1:5080`. Set `SIP_PORT`, `UPSTREAM`,
`TRUSTED`. Edit, then run `ferroctl -s /tmp/ferrosip-s11.sock cfg.reload`.
