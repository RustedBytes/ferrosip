"""l06-multi-tenant: two tenants on one proxy, told apart by the request
domain; per-tenant users (a subscriber table with domains), limits and
routes from imported .fsr files."""
import os, sqlite3

A, B = "a.example.com", "b.example.com"
USERS = [("alice", A, "pa-alice"), ("bob", A, "pa-bob"), ("alice", B, "pb-alice"), ("carol", B, "pb-carol")]


def invites(ua, cid):
    """INVITEs of this call at `ua` (one per branch)."""
    return list({m.all("via")[0] for m in ua.received if m.method == "INVITE" and m.get("call-id") == cid})


def run(sc):
    db = os.path.join(sc.tmp, "tenants.db")
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE subscriber (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, domain TEXT, password TEXT, ha1 TEXT)")
    c.executemany("INSERT INTO subscriber (username, domain, password) VALUES (?, ?, ?)", USERS)
    c.commit()
    c.close()
    sip = sc.port()
    gw = sc.ua("gw-a", sip).auto_answer()
    sc.proxy("proxy", sc.env(SIP_PORT=sip, SUBSCRIBER_DB=f"sqlite://{db}", GW_A=f"sip:127.0.0.1:{gw.port}"), name="proxy")
    u = {(n, d): sc.ua(n, sip, domain=d, password=p).auto_answer() for n, d, p in USERS}
    a_alice, a_bob, b_alice, b_carol = (u[k] for k in [("alice", A), ("bob", A), ("alice", B), ("carol", B)])

    for (n, d), ua in u.items():
        r = ua.register()
        sc.check(f"{n}@{d} registers with her tenant's password", r is not None and r.code == 200, r)
    # alice@b using alice@a's password.
    wrong = sc.ua("alice", sip, domain=B, password="pa-alice")
    r = wrong.register()
    sc.check("alice@b with alice@a's password is refused (users are per tenant)", r is not None and r.code in (401, 403), r)

    # Same user name, two tenants: each call reaches the right alice.
    r, d = a_bob.call(f"sip:alice@{A}", timeout=6)
    sc.check("bob@a calls alice@a: 200", r is not None and r.code == 200 and d is not None, r)
    if d:
        sc.check("…and it rang alice@a, not alice@b", len(invites(a_alice, d.call_id)) == 1 and invites(b_alice, d.call_id) == [])
        d.bye()
    r, d = b_carol.call(f"sip:alice@{B}", timeout=6)
    sc.check("carol@b calls alice@b: 200", r is not None and r.code == 200 and d is not None, r)
    if d:
        sc.check("…and it rang alice@b, not alice@a", len(invites(b_alice, d.call_id)) == 1 and invites(a_alice, d.call_id) == [])
        d.bye()

    # Crossing tenants.
    r, _ = a_bob.call(f"sip:carol@{B}", timeout=6)
    sc.check("bob@a calls carol@b → 403 Wrong tenant (B's routes refuse A's users)",
             r is not None and r.code == 403 and r.reason == "Wrong tenant", r)
    sc.check("…and carol never sees it", not any(m.method == "INVITE" for m in b_carol.received if "bob" in (m.get("from") or "")))
    spoof = sc.ua("bob", sip, domain=B, password="pa-bob")  # bob@a pretending to be in B
    r, _ = spoof.call(f"sip:carol@{B}", timeout=6)
    sc.check("bob with a From in B (but only an account in A) can't authenticate in B", r is not None and r.code in (403, 407), r)
    r, _ = a_bob.call("sip:alice@c.example.com", timeout=6)
    sc.check("a domain that is no tenant → 404 Unknown domain", r is not None and r.code == 404 and r.reason == "Unknown domain", r)
    r, _ = a_bob.call(f"sip:dave@{A}", timeout=6)
    sc.check("an unregistered user of A → 404 Not registered", r is not None and r.code == 404 and r.reason == "Not registered", r)

    # Per-tenant routes: PSTN for A only.
    r, d = a_bob.call(f"sip:+4930123456@{A}", timeout=6)
    sc.check("A's number goes to A's gateway: 200", r is not None and r.code == 200 and d is not None and len(invites(gw, d.call_id)) == 1, r)
    if d:
        d.bye()
    r, _ = b_carol.call(f"sip:+4930123456@{B}", timeout=6)
    sc.check("B has no PSTN: 403 No PSTN for this tenant", r is not None and r.code == 403 and r.reason == "No PSTN for this tenant", r)

    # A failed call must not keep the tenant's slot (the profile is set
    # before the lookup fails).
    for i in range(2):
        r, _ = b_carol.call(f"sip:dave@{B}", timeout=6)
        sc.check(f"B calls an unregistered user ({i + 1}): 404, not the call limit", r is not None and r.code == 404, r)
    r = a_alice.register(registrar=f"sip:{B}")
    sc.check("alice@a registering at B's domain → 403 Wrong tenant", r is not None and r.code == 403, r)

    # Per-tenant limits: B one call at a time, A two.
    r, held_b = b_carol.call(f"sip:alice@{B}", timeout=6)
    sc.check("B's first call is up", held_b is not None, r)
    r, _ = b_alice.call(f"sip:carol@{B}", timeout=6)
    sc.check("B's second call at the same time → 486 Tenant B call limit", r is not None and r.code == 486 and r.reason == "Tenant B call limit", r)
    r, held_a1 = a_bob.call(f"sip:alice@{A}", timeout=6)
    r2, held_a2 = a_alice.call(f"sip:bob@{A}", timeout=6)
    sc.check("…while A still has two calls up at once (its own limit)", held_a1 is not None and held_a2 is not None, (r, r2))
    r, _ = a_bob.call(f"sip:+49301111@{A}", timeout=6)
    sc.check("A's third call → 486 Tenant A call limit", r is not None and r.code == 486 and r.reason == "Tenant A call limit", r)
    for d in (held_b, held_a1, held_a2):
        if d:
            d.bye()
    r, d = b_alice.call(f"sip:carol@{B}", timeout=6)
    sc.check("after the hangups B can call again", r is not None and r.code == 200, r)
    if d:
        d.bye()
