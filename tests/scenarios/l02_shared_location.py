"""l02-shared-location: two registrars on one SQLite location table
(usrloc db_mode write-through). What each one sees of the other's writes,
and when."""
import os, sqlite3

# The location table (etc/schema/postgres.sql, in SQLite types).
SCHEMA = """CREATE TABLE location (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL, domain TEXT, contact TEXT NOT NULL, received TEXT, path TEXT,
    expires INTEGER NOT NULL, q REAL, callid TEXT NOT NULL, cseq INTEGER NOT NULL,
    cflags INTEGER NOT NULL, user_agent TEXT NOT NULL, instance TEXT, reg_id INTEGER,
    last_modified INTEGER NOT NULL)"""


def rows(db, user):
    """The contacts of `user` in the table (a local helper: reads SQLite directly)."""
    c = sqlite3.connect(db)
    try:
        return [r[0] for r in c.execute("SELECT contact FROM location WHERE username = ?", (user,))]
    finally:
        c.close()


def served_by(callee, cid):
    """X-Served-By of the INVITE of this call that reached `callee`."""
    inv = next((m for m in callee.received if m.method == "INVITE" and m.get("call-id") == cid), None)
    return inv and inv.get("x-served-by")


def run(sc):
    db = os.path.join(sc.tmp, "location.db")
    c = sqlite3.connect(db)
    c.execute(SCHEMA)
    c.commit()
    c.close()
    url = f"sqlite://{db}"
    pa, pb = sc.port(), sc.port()
    a = sc.proxy("reg-a", sc.env(SIP_PORT=pa, LOCATION_DB=url), name="reg-a")

    # alice registers on A before B is running.
    alice = sc.ua("alice", pa, password="secret-a")
    alice.auto_answer()
    r = alice.register()
    sc.check("alice registers on A (401, then 200)", r is not None and r.code == 200, r)
    sc.check("A wrote alice's contact to the shared table at once (write-through)",
             rows(db, "alice") == [alice.contact], rows(db, "alice"))

    # B starts now: it loads the table, so it knows alice.
    b = sc.proxy("reg-b", sc.env(SIP_PORT=pb, LOCATION_DB=url), name="reg-b")
    bob = sc.ua("bob", pb, password="secret-b")
    r, d = bob.call("sip:alice@example.com", timeout=6)
    sc.check("bob calls alice via B (B loaded her contact at startup): 200", r is not None and r.code == 200 and d, r)
    sc.check("…and the INVITE alice got was relayed by B", d is not None and served_by(alice, d.call_id) == "reg-b",
             d and served_by(alice, d.call_id))
    if d:
        rep = d.bye()
        sc.check("bob's BYE to alice (through B's Record-Route) → 200", rep is not None and rep.code == 200, rep)

    # carol registers on A while B runs: B only reads the table at startup.
    carol = sc.ua("carol", pa, password="secret-c")
    carol.auto_answer()
    r = carol.register()
    sc.check("carol registers on A while B runs", r is not None and r.code == 200, r)
    sc.check("carol's row is in the shared table", rows(db, "carol") == [carol.contact], rows(db, "carol"))
    r, d = bob.call("sip:carol@example.com", timeout=6)
    sc.check("B doesn't see a registration A made after B started (write-through keeps memory as the cache): 404",
             r is not None and r.code == 404, r)

    # Restart B: it reloads the table and finds both.
    b.stop()
    b.start()
    for who, ua in (("alice", alice), ("carol", carol)):
        r, d = bob.call(f"sip:{who}@example.com", timeout=6)
        sc.check(f"after B restarts it finds {who} (reloaded from the table): 200",
                 r is not None and r.code == 200 and d is not None and served_by(ua, d.call_id) == "reg-b", r)
        if d:
            d.bye()

    # One AoR, two devices, one on each registrar: B doesn't know the desk
    # phone A saved after B started. Kamailio's write-through inserts and
    # deletes single contacts, so both rows stay in the table.
    desk = sc.ua("bob", pa, password="secret-b")
    mobile = sc.ua("bob", pb, password="secret-b")
    r1, r2 = desk.register(), mobile.register()
    sc.check("bob registers a desk phone on A and a mobile on B", r1 is not None and r1.code == 200 and r2 is not None and r2.code == 200, (r1, r2))
    sc.check("the table keeps both of bob's contacts (B's write doesn't erase the row A wrote)",
             sorted(rows(db, "bob")) == sorted([desk.contact, mobile.contact]), rows(db, "bob"))

    # alice unregisters on B: B deletes her row, A keeps its cached copy.
    alice_b = sc.ua("alice", pb, password="secret-a")
    r = alice_b.register(expires=0, contact=alice.contact)
    sc.check("alice unregisters via B (Expires 0, her contact): 200", r is not None and r.code == 200, r)
    sc.check("…B removed her row from the shared table", rows(db, "alice") == [], rows(db, "alice"))
    r, _ = bob.call("sip:alice@example.com", timeout=6)
    sc.check("…B no longer finds alice: 404", r is not None and r.code == 404, r)
    caller_a = sc.ua("bob", pa, password="secret-b")
    r, d = caller_a.call("sip:alice@example.com", timeout=6)
    sc.check("A still finds alice after the unregister on B (no re-read: the stale contact lives in A's memory until it expires)",
             r is not None and r.code == 200 and d is not None and served_by(alice, d.call_id) == "reg-a", r)
    if d:
        d.bye()

    # A restart makes A agree with the table again.
    a.stop()
    a.start()
    r, _ = caller_a.call("sip:alice@example.com", timeout=6)
    sc.check("after A restarts it no longer finds alice: 404", r is not None and r.code == 404, r)
    r, d = caller_a.call("sip:carol@example.com", timeout=6)
    sc.check("…while carol (still in the table) is found by A: 200", r is not None and r.code == 200, r)
    if d:
        d.bye()
