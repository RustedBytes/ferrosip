"""m17-credential-store: digest auth against HA1s in Redis (pv_auth_check
with $au naming the subscriber), cached in a shared table; a password
change, an unknown user, credentials of another user, Redis down for a
cached and an uncached user; one phone per user (save flag 0x04) and
GET /phone (reg_fetch_contacts, $ulc)."""
import hashlib

import sipkit
from sipkit import challenges, credentials, http_get

REALM = "voip.example.com"


def ha1(user, password):
    return hashlib.md5(f"{user}:{REALM}:{password}".encode()).hexdigest()


def code(r):
    return r.code if r is not None else None


def phone(api, user):
    st, body = http_get(f"{api}/phone?{user}")
    return st, dict(l.split("=", 1) for l in body.splitlines() if "=" in l) if st == 200 else body


def run(sc):
    if not sipkit.Redis.available():
        sc.skip("redis-server not installed")
    sip, hport, rport = sc.port(), sc.port(), sc.port()
    redis = sipkit.Redis(rport, sc.tmp).start()
    sc.closers.append(redis.stop)

    def provision(user, password):
        return redis.cmd("HSET", f"subscriber:{user}", "ha1", ha1(user, password))

    for u, p in (("alice", "a-secret"), ("bob", "b-secret"), ("dave", "d-secret")):
        provision(u, p)
    sc.proxy(env=sc.env(SIP_PORT=sip, HTTP_PORT=hport, REDIS_PORT=rport))
    api = f"http://127.0.0.1:{hport}"
    ua = lambda user, password, **kw: sc.ua(user, sip, domain=REALM, password=password, **kw)  # noqa: E731
    alice, bob = ua("alice", "a-secret").auto_answer(), ua("bob", "b-secret").auto_answer()

    # --- Registration against Redis.
    r = alice.register(auth=False)
    ch = challenges(r) if r is not None else []
    sc.check("REGISTER without credentials → 401 for realm voip.example.com", code(r) == 401 and ch and ch[0][1].get("realm") == REALM, r)
    r = alice.register(headers={"User-Agent": "desk-phone/1"})
    sc.check("alice registers with the password whose HA1 is in Redis: 200", code(r) == 200, r)
    r = bob.register()
    sc.check("bob registers: 200", code(r) == 200, r)
    st, ph = phone(api, "alice")
    sc.check("GET /phone?alice: her phone ($ulc count, addr, received, user_agent)",
             st == 200 and ph.get("count") == "1" and ph.get("contact") == alice.contact
             and ph.get("received", "").startswith(f"sip:127.0.0.1:{alice.port}") and ph.get("user_agent") == "desk-phone/1", (st, ph))
    r = ua("carol", "c-secret").register()
    sc.check("carol (no subscriber:carol in Redis) is challenged again: 401", code(r) == 401, r)
    r = ua("alice", "wrong").register()
    sc.check("alice with a wrong password → 401", code(r) == 401, r)
    r = ua("Bad User", "x").register()
    sc.check("a user name that can't be a Redis key → 403 Bad user name", code(r) == 403 and r.reason == "Bad user name", r)

    # --- A call: 407, then relayed with the authenticated identity.
    r, d = alice.call(f"sip:bob@{REALM}", timeout=6)
    inv = next((m for m in bob.received if m.method == "INVITE" and d and m.get("call-id") == d.call_id), None)
    sc.check("alice calls bob: 407, then 200", code(r) == 200 and d is not None, r)
    sc.check("…bob's INVITE has X-Authenticated-User: alice@voip.example.com ($au@$ar) and no credentials",
             inv is not None and inv.get("x-authenticated-user") == f"alice@{REALM}" and inv.get("proxy-authorization") is None,
             inv and inv.raw)
    if d:
        rep = d.bye()
        sc.check("…BYE → 200", code(rep) == 200, rep)

    # bob's credentials on a request From alice.
    s = bob.request("INVITE", f"sip:alice@{REALM}", body=sipkit.sdp(bob.port + 1000), from_uri=f"sip:alice@{REALM}")
    r = bob.final(call_id=s["call_id"], method="INVITE")
    if r is not None and r.code == 407:
        bob._ack_neg(s, r)
        alg, p, hdr = challenges(r)[0]
        name, value = credentials("bob", "b-secret", p, "INVITE", s["ruri"], hdr, alg)
        s = bob.request("INVITE", s["ruri"], call_id=s["call_id"], from_tag=s["from_tag"], cseq=2, headers={name: value},
                        body=s["body"], from_uri=f"sip:alice@{REALM}")
        r = bob.final(call_id=s["call_id"], method="INVITE", cseq=2)
    sc.check("bob's valid credentials on an INVITE From alice → 403 Credentials of another user",
             code(r) == 403 and r.reason == "Credentials of another user", r)

    # --- The password changes in Redis: a cached HA1 that fails is re-read.
    provision("alice", "a-new-secret")
    renewed = ua("alice", "a-new-secret")
    r = renewed.register()
    sc.check("alice's password changed in Redis: the new one works at once (200)", code(r) == 200, r)
    r = ua("alice", "a-secret").register()
    sc.check("…and the old one no longer does (401)", code(r) == 401, r)

    # --- One phone per user (save flag 0x04), shown by GET /phone.
    st, ph = phone(api, "alice")
    sc.check("…GET /phone?alice shows the phone that registered with the new password (it replaced the first one)",
             st == 200 and ph.get("count") == "1" and ph.get("contact") == renewed.contact, (st, ph))
    desk2 = ua("alice", "a-new-secret").auto_answer()
    r = desk2.register(headers={"User-Agent": "desk-phone/2"})
    sc.check("alice registers a second phone: 200 listing only the new contact (save flag 0x04)",
             code(r) == 200 and len(r.all("contact")) == 1 and desk2.contact in r.all("contact")[0], r and r.all("contact"))
    st, ph = phone(api, "alice")
    sc.check("…GET /phone?alice: count 1, the new phone and its User-Agent",
             st == 200 and ph.get("count") == "1" and ph.get("contact") == desk2.contact and ph.get("user_agent") == "desk-phone/2", (st, ph))
    r, d = bob.call(f"sip:alice@{REALM}", timeout=6)
    sc.check("bob calls alice: only the new phone rings",
             code(r) == 200 and d is not None and any(m.method == "INVITE" and m.get("call-id") == d.call_id for m in desk2.received)
             and not any(m.method == "INVITE" and m.get("call-id") == d.call_id for m in alice.received + renewed.received), r)
    if d:
        d.bye()
    st, _ = phone(api, "carol")
    sc.check("GET /phone?carol (not registered) → 404", st == 404, st)
    st, _ = phone(api, "a%20b")
    sc.check("GET /phone?a%20b → 400", st == 400, st)

    # --- Redis down: cached users still authenticate, others get 503.
    redis.stop()
    r = desk2.register()
    sc.check("Redis down: alice (HA1 cached) still re-registers: 200", code(r) == 200, r)
    r = ua("dave", "d-secret").register()
    sc.check("…dave (in Redis, never seen: not cached) → 503 Credential store unavailable",
             code(r) == 503 and r.reason == "Credential store unavailable", r)
    redis.start()
    provision("dave", "d-secret")  # a fresh Redis (no persistence): provisioned again
    r = ua("dave", "d-secret").register()
    sc.check("Redis back: dave registers: 200", code(r) == 200, r)
