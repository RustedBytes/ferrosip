# l09-postgres-cluster (large)

This scenario models two [registrars](../../../docs/glossary.md#registrar),
**reg-a** and **reg-b**, with the same routing and one PostgreSQL
database. Credentials come from `subscriber` (auth_db). Contacts are in
`location`. Number routes are in a `numbers` table the operator fills. It
proves that each registrar sees the other's registrations and run-time
data at once, that SQL values are escaped safely, and how the pair
behaves while the database is down.

```
alice ──REGISTER──▶ reg-a ──┐                          ┌── reg-b ◀──INVITE alice── bob
                            │ auth_db: subscriber      │
                            │ location.save() ─────────┤ write-through
                            ▼                          ▼
                      ┌──────────── PostgreSQL (DB_URL) ────────────┐
                      │ subscriber   location   numbers (num→target)│
                      └─────────────────────────────────────────────┘
                            ▲ sql.query_value: the newest unexpired contact,
                            │ or the target of a number, read on every call
```

**Shows**:
- the auth_db parameters in `[modules.auth]`: `db_url`, and
  `calculate_ha1 = true` for plain passwords (see
  [HA1](../../../docs/glossary.md#ha1));
- `[modules.location]` with `db_mode = "write-through"`;
- `[modules.sql] sqlcon`;
- all three on one `DB_URL` from the environment;
- `sql.query_value` into a `let`. It tells a database error (false) from
  no row (true, with the variable unchanged);
- `auth.check` / `auth.challenge` with the default table `subscriber`;
- a `fn … -> Action` called with `return` from the main route.

**Which db_mode, and why the lookup reads the table.**
[usrloc](../../../docs/glossary.md#usrloc) keeps its contacts in memory.
It reads the table only at startup, in every `db_mode`
(crates/mod-location README: `"db-only"` behaves like write-through, "the
in-memory table stays the cache"). So `location.lookup()` on B never sees
a registration made on A after B started. l02-shared-location shows this.

Here both registrars save with `location.save()`. With write-through, the
row is there at once. They look users up in the table with
`sql.query_value`: the newest unexpired contact of the
[R-URI](../../../docs/glossary.md#r-uri) user, whichever registrar wrote
it. The price:
- one contact per [AoR](../../../docs/glossary.md#aor), so no
  [forking](../../../docs/glossary.md#forking);
- no [`received`](../../../docs/glossary.md#received)/[Path](../../../docs/glossary.md#path)
  handling. That is fine for phones that aren't behind
  [NAT](../../../docs/glossary.md#nat), as here.

An unregister must reach the registrar that saved the contact. Each
registrar deletes only the rows it wrote or loaded, as
[Kamailio's](../../../docs/glossary.md#kamailio) db_mode 1 does. So an
`Expires: 0` sent to the other one is answered 200 and changes nothing.
Put a load balancer that hashes on the AoR in front, so a phone always
reaches the same registrar.

**Database down.** sip-db keeps a pool and retries a statement once on a
fresh connection. So a restarted Postgres is picked up without
restarting ferrosip. While it is down:
- A call gets **503 Database unavailable**. The `sql.query_value` lookup
  fails (false), which is not the same as "no row" (404).
- A request that fails `auth.check` gets 503 too, not another 401.
  `refuse()` runs `SELECT 1` when the check fails, and only
  [challenges](../../../docs/glossary.md#challenge) when the database
  answers. Otherwise a phone would ask its user for the password during
  an outage.

**Values in SQL are quoted with `sql.quote(…)`** (Kamailio's
`{sql.val.str}`). `{sql.quote(msg.ruri.user)}` puts the user into the
query as a quoted, escaped literal. A quote is legal in a SIP user part
(`o'brien`). Without it, a callee like `x'or'1'='1` would turn the lookup
into "any contact". Two of the checks below cover it.

**Edge cases checked** (`tests/scenarios/l09_postgres_cluster.py`):
- alice registers on A (401, then 200). The row is in `location` at once.
  bob registers on B. A wrong password and a user not in `subscriber` get
  401.
- bob → alice via B and alice → bob via A: each registrar finds the
  other's registrations. Each call gets 200, relayed by the proxy the call
  came in on. Meanwhile B's usrloc memory (`ul.lookup`) doesn't have
  alice. An unknown user gets 404.
- 100 is routed to the IVR from `numbers`. 999 gets 404 until it is
  inserted, then 200.
- dave is inserted into `subscriber` while both run. He registers on B
  and is reached via A. After his password is changed in the table, the
  old one gets 401 and the new one 200.
- alice's unregister via B leaves her row. Via A it removes it, and B
  answers 404.
- o'brien registers (auth_db and usrloc bind their values) and is called
  via B: 200, because the quote is escaped.
- A callee `x'or'1'='1`: 404, and no registered user gets the
  [INVITE](../../../docs/glossary.md#invite). `subscriber` and `location`
  are intact.
- Postgres stopped:
  - a call via B and a call to a number via A get 503 within 5 s;
  - a [REGISTER](../../../docs/glossary.md#register) with credentials
    gets 503 (not 401);
  - both registrars keep running.
- Postgres started again:
  - alice registers, bob reaches her via B, and 100 via A;
  - a user inserted after the restart gets 401 before and 200 after.

**Run it by hand** (with a ferrosip built with the PostgreSQL driver:
`cargo build --release --features ferrosip/db-all`):
1. Load `etc/schema/postgres.sql` into a database.
2. Create `numbers (num VARCHAR(32) PRIMARY KEY, target VARCHAR(255))`.
3. Add users to `subscriber` (plain passwords).
4. Start `reg-a` (`SIP_PORT` 5060) and `reg-b` (`SIP_PORT` 5070), each
   from its own directory, with the same
   `DB_URL=postgres://user@host:5432/ferrosip`.

Postgres must be up when they start. A `sqlcon` that can't connect stops
ferrosip at startup.
