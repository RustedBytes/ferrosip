# l02-shared-location (large)

This scenario models two [registrars](../../../docs/glossary.md#registrar),
**reg-a** and **reg-b**, with the same routing and one SQLite `location`
table between them ([usrloc](../../../docs/glossary.md#usrloc)
`db_mode = "write-through"`). It shows exactly what a shared table gives
you and what it doesn't. It proves that each registrar keeps the other's
rows intact, and documents when a registrar sees the other's changes.

```
alice, carol ──REGISTER──▶ reg-a ──┐ write-through          ┌── reg-b ◀──INVITE── bob
                           (memory)│                        │(memory)
                                   ▼                        │
                            location.db (SQLite) ──load at startup only──┘
```

**Shows**:
- `[modules.location] db_mode` and `db_url` from the environment
  (`LOCATION_DB`, a file in the test's temp directory);
- `auth.check` / `auth.challenge` with one `users` file for both
  (`../users`);
- a header added from a [`[feature]`](../../../docs/glossary.md#feature-switch)
  value (`X-Served-By`), so the callee can tell which registrar relayed
  the call.

**What a shared table gives you, and what it doesn't.** usrloc keeps its
contacts in memory, and the table is a copy:
- Every change is written at once (write-through).
- The table is read **once, at startup**. Lookups never read it.
  `db_mode = "db-only"` behaves the same in ferrosip (crates/mod-location
  README: "the in-memory table stays the cache").
  [Kamailio's](../../../docs/glossary.md#kamailio) db-only mode reads the
  database on every lookup. So in Kamailio, that mode is the one to use
  for a live shared table.

So a registration on A is seen by B only after B (re)starts. An
unregister on B leaves A with a stale contact until it expires or A
restarts. The test checks both, as the expected behaviour.

**Edge cases checked** (`tests/scenarios/l02_shared_location.py`):
- alice registers on A. Her row is in the table at once.
- B started after that loads it. bob calls alice via B (200, relayed by
  B), and the [BYE](../../../docs/glossary.md#bye) follows B's
  [Record-Route](../../../docs/glossary.md#record-route).
- carol registers on A while B runs. Her row is in the table, but B
  answers 404, because it doesn't re-read.
- B restarts (stop, start) and finds alice and carol.
- One [AoR](../../../docs/glossary.md#aor) with a device on each
  registrar: bob's desk phone on A, his mobile on B. The table keeps both
  rows. Each registrar rewrites only the contacts it wrote or loaded, as
  Kamailio's write-through does: B's write never erases the desk phone A
  wrote.
- alice unregisters via B. Her row is gone and B answers 404. But A still
  finds her (stale memory) and relays to her.
- A restarts: alice is gone (404), and carol is still found.

**Run it by hand**: create the `location` table. The SQL is in the test,
from `etc/schema/postgres.sql`. Then start `reg-a` (`SIP_PORT` 5060) and
`reg-b` (`SIP_PORT` 5070), each from its own directory, with the same
`LOCATION_DB=sqlite:///path/location.db`.
