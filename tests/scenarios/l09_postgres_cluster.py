"""l09-postgres-cluster: two registrars on one PostgreSQL. auth_db from
`subscriber`, location write-through plus lookups in the shared table with
`sql`, number routes from a `numbers` table; users and numbers added at
run time, quotes in SQL values, Postgres restarted mid-test."""
import time

import sipkit


def q(v):
    """A SQL string literal (quotes doubled)."""
    return "'" + v.replace("'", "''") + "'"


def code(r):
    return r.code if r is not None else None


def served_by(ua, cid):
    inv = next((m for m in ua.received if m.method == "INVITE" and m.get("call-id") == cid), None)
    return inv and inv.get("x-served-by")


def call(ua, ruri, timeout=8):
    """INVITE; (final reply, Call-ID of the reply, seconds); BYE when answered."""
    t0 = time.time()
    r, d = ua.call(ruri, timeout=timeout)
    took = time.time() - t0
    if d:
        d.bye()
    return r, (r.get("call-id") if r is not None else None), took


def run(sc):
    if not sipkit.built_with("db-postgres"):
        sc.skip("ferrosip built without db-postgres (cargo build --features ferrosip/db-all)")
    if not sipkit.Postgres.available():
        sc.skip("postgresql not installed")
    pg = sipkit.Postgres(sc.port(), sc.tmp).start()
    sc.closers.append(pg.stop)
    for user, pw in (("alice", "secret-a"), ("bob", "secret-b"), ("o'brien", "secret-o")):
        pg.sql(f"INSERT INTO subscriber (username, domain, password) VALUES ({q(user)}, 'example.com', {q(pw)})")
    ivr = sc.ua("ivr", sc.port()).auto_answer()
    pg.sql("CREATE TABLE numbers (num VARCHAR(32) PRIMARY KEY, target VARCHAR(255) NOT NULL)")
    pg.sql(f"INSERT INTO numbers VALUES ('100', 'sip:ivr@127.0.0.1:{ivr.port}')")

    def rows(user):
        return [r[0] for r in pg.sql(f"SELECT contact FROM location WHERE username = {q(user)}")]

    pa, pb = sc.port(), sc.port()
    a = sc.proxy("reg-a", sc.env(SIP_PORT=pa, DB_URL=pg.url), name="reg-a")
    b = sc.proxy("reg-b", sc.env(SIP_PORT=pb, DB_URL=pg.url), name="reg-b")

    # --- auth_db from subscriber, location write-through.
    alice = sc.ua("alice", pa, password="secret-a").auto_answer()
    r = alice.register()
    sc.check("alice registers on A (401, then 200 with credentials from subscriber)", code(r) == 200, r)
    sc.check("…her contact is in the location table at once (write-through)", rows("alice") == [alice.contact], rows("alice"))
    bob = sc.ua("bob", pb, password="secret-b").auto_answer()
    r = bob.register()
    sc.check("bob registers on B: 200", code(r) == 200, r)
    r = sc.ua("alice", pa, password="wrong").register()
    sc.check("alice with a wrong password: challenged again (401)", code(r) == 401, r)
    r = sc.ua("mallory", pb, password="x").register()
    sc.check("a user not in subscriber: 401", code(r) == 401, r)

    # --- Each registrar finds the other's registrations (in the table).
    r, cid, _ = call(bob, "sip:alice@example.com")
    sc.check("bob calls alice via B (registered on A): 200, relayed by B",
             code(r) == 200 and served_by(alice, cid) == "reg-b", (r, served_by(alice, cid)))
    look = b.rpc("ul.lookup", "location", "alice")
    sc.check("…while B's own usrloc memory doesn't have alice (why the lookup reads the table)",
             "alice@127.0.0.1" not in str(look), look)
    r, cid, _ = call(alice, "sip:bob@example.com")
    sc.check("alice calls bob via A (registered on B): 200, relayed by A",
             code(r) == 200 and served_by(bob, cid) == "reg-a", (r, served_by(bob, cid)))
    r, _, _ = call(alice, "sip:carol@example.com")
    sc.check("a user with no registration: 404", code(r) == 404, r)

    # --- Number routes from the numbers table (sql namespace).
    r, cid, _ = call(alice, "sip:100@example.com")
    sc.check("alice calls 100: routed to the IVR from the numbers table, 200",
             code(r) == 200 and served_by(ivr, cid) == "reg-a", r)
    r, _, _ = call(bob, "sip:999@example.com")
    sc.check("a number not in the table: 404", code(r) == 404, r)
    pg.sql(f"INSERT INTO numbers VALUES ('999', 'sip:ivr@127.0.0.1:{ivr.port}')")
    r, cid, _ = call(bob, "sip:999@example.com")
    sc.check("…999 added to the table at run time: routed at once via B, 200",
             code(r) == 200 and served_by(ivr, cid) == "reg-b", r)

    # --- A user added to subscriber at run time.
    pg.sql("INSERT INTO subscriber (username, domain, password) VALUES ('dave', 'example.com', 'secret-d')")
    dave = sc.ua("dave", pb, password="secret-d").auto_answer()
    r = dave.register()
    sc.check("dave, added to subscriber while both run, registers on B: 200", code(r) == 200, r)
    r, cid, _ = call(alice, "sip:dave@example.com")
    sc.check("…and alice reaches him via A: 200", code(r) == 200 and served_by(dave, cid) == "reg-a", r)
    pg.sql("UPDATE subscriber SET password = 'new-d' WHERE username = 'dave'")
    r = dave.register()
    sc.check("dave's password changed in the table: the old one is refused (401)", code(r) == 401, r)
    dave.password = "new-d"
    r = dave.register()
    sc.check("…the new one works (200)", code(r) == 200, r)

    # --- An unregister sent to the other registrar (write-through: each
    # registrar deletes only the rows it wrote or loaded, as Kamailio's
    # db_mode 1 does).
    alice_b = sc.ua("alice", pb, password="secret-a")
    r = alice_b.register(expires=0, contact=alice.contact)
    sc.check("alice unregisters via B (Expires 0, her contact): 200", code(r) == 200, r)
    sc.check("…but the row A wrote stays (B never had it in memory)", rows("alice") == [alice.contact], rows("alice"))
    r = alice.register(expires=0)
    sc.check("alice unregisters via A, where she registered: 200", code(r) == 200, r)
    sc.check("…now her row is gone", rows("alice") == [], rows("alice"))
    r, _, _ = call(bob, "sip:alice@example.com")
    sc.check("…and B answers 404 for her", code(r) == 404, r)
    r = alice.register()
    sc.check("alice registers on A again: 200", code(r) == 200, r)

    # --- Quotes in SQL values.
    obrien = sc.ua("o'brien", pa, password="secret-o").auto_answer()
    r = obrien.register()
    sc.check("o'brien (a quote in the user name: legal in a SIP URI) registers on A: 200", code(r) == 200, r)
    sc.check("…his row is in the location table", rows("o'brien") == [obrien.contact], rows("o'brien"))
    r, cid, _ = call(bob, "sip:o'brien@example.com")
    sc.check("bob calls o'brien via B: 200 (the quote must be escaped in the lookup's SQL)",
             code(r) == 200 and served_by(obrien, cid) == "reg-b", r)
    n_before = {u.user: sum(m.method == "INVITE" for m in u.received) for u in (alice, bob, dave, obrien)}
    r, _, _ = call(bob, "sip:x'or'1'='1@example.com")
    got = {u.user: sum(m.method == "INVITE" for m in u.received) - n_before[u.user] for u in (alice, bob, dave, obrien)}
    sc.check("a callee x'or'1'='1 (SQL injection in the R-URI user): 404, not some other user's contact",
             code(r) == 404, r)
    sc.check("…and no registered user got the INVITE", not any(got.values()), got)
    sc.check("…the subscriber and location tables are intact",
             len(pg.sql("SELECT 1 FROM subscriber")) == 4 and rows("alice") == [alice.contact],
             (pg.sql("SELECT username FROM subscriber"), rows("alice")))

    # --- Postgres restarted mid-test.
    pg.stop()
    r, _, took = call(bob, "sip:alice@example.com", timeout=12)
    sc.check("Postgres down: bob's call via B gets 503 (not a hang, not a 404)", code(r) == 503, r)
    sc.check(f"…quickly (took {took:.1f}s, < 5s)", took < 5, took)
    t0 = time.time()
    r = alice.register()
    sc.check("Postgres down: alice's REGISTER on A gets 503, not a new challenge", code(r) == 503, r)
    sc.check("…quickly (< 5s)", time.time() - t0 < 5, time.time() - t0)
    r, _, _ = call(alice, "sip:100@example.com", timeout=12)
    sc.check("Postgres down: a call to a number via A gets 503", code(r) == 503, r)
    sc.check("…both registrars are still running", a.p.poll() is None and b.p.poll() is None)

    pg.start(first=False)
    r = alice.register()
    sc.check("Postgres back: alice re-registers on A, 200 (auth_db and location reconnect)", code(r) == 200, r)
    r, cid, _ = call(bob, "sip:alice@example.com")
    sc.check("…bob reaches alice via B, 200 (B's sql connection reconnected)", code(r) == 200 and served_by(alice, cid) == "reg-b", r)
    r, cid, _ = call(alice, "sip:100@example.com")
    sc.check("…and 100 via A, 200", code(r) == 200 and served_by(ivr, cid) == "reg-a", r)
    r = sc.ua("erin", pa, password="secret-e").register()
    pg.sql("INSERT INTO subscriber (username, domain, password) VALUES ('erin', 'example.com', 'secret-e')")
    r2 = sc.ua("erin", pa, password="secret-e").register()
    sc.check("…a user added after the restart: refused before (401), registers after (200)",
             code(r) == 401 and code(r2) == 200, (r, r2))
