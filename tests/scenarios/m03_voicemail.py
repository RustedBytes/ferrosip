"""m03-voicemail: busy / no answer / not registered → voicemail, through
`await txn.relay` on the same transaction; 2xx and 3xx forwarded; CANCEL
in both legs."""
import time


def scripted(sc, sip, name, mode, **kw):
    """A UA whose answer to the next INVITE is `mode[name]`: a code, "ring"
    (180 until CANCEL), "ring-then-200", or "302"."""
    u = sc.ua(name, sip, **kw)

    def h(m):
        if m.method == "INVITE":
            what = mode.get(name, "200")
            if what == "ring":
                u.respond(m, 180, "Ringing")
                return None
            if what == "302":
                return (302, "Moved Temporarily", {"Contact": "<sip:bob@mobile.example.net>"})
            code = int(what)
            u.respond(m, 180, "Ringing")
            from sipkit import sdp
            u.respond(m, code, {200: "OK", 486: "Busy Here", 600: "Busy Everywhere", 603: "Decline"}.get(code, "X"),
                      body=sdp(u.port + 1000) if code == 200 else "")
            return None
        if m.method == "CANCEL":
            u.respond(m, 200)
            inv = next(x for x in reversed(u.received) if x.method == "INVITE" and x.get("call-id") == m.get("call-id"))
            u.respond(inv, 487, "Request Terminated")
            return None
        if m.method == "ACK":
            return None
        return (200, "OK")
    u.handler = h
    return u


def invites(u, cid, method="INVITE"):
    return [m for m in {m.all("via")[0]: m for m in u.received if m.method == method and m.get("call-id") == cid}.values()]


def run(sc):
    sip = sc.port()
    mode = {}
    vm = scripted(sc, sip, "vm", mode)
    sc.proxy(env=sc.env(SIP_PORT=sip, VOICEMAIL=f"sip:127.0.0.1:{vm.port}"))
    bob = scripted(sc, sip, "bob", mode, password="secret-b")
    alice = sc.ua("alice", sip)
    alice.auto_answer()

    r = bob.register()
    sc.check("bob registers (401, then 200)", r is not None and r.code == 200, r)

    def call(**modes):
        mode.clear()
        mode.update(modes)
        r, d = alice.call("sip:bob@example.com", timeout=15)
        cid = d.call_id if d else (r.get("call-id") if r else None)
        return r, d, cid

    # Answered: forwarded, voicemail never tried.
    r, d, cid = call(bob="200")
    sc.check("bob answers: 200 to the caller", r is not None and r.code == 200 and f":{bob.port}" in (r.get("contact") or ""), r)
    sc.check("…and voicemail is not called", not invites(vm, cid))
    if d:
        rep = d.bye()
        sc.check("…the BYE reaches bob through the Record-Route: 200", rep is not None and rep.code == 200 and any(m.method == "BYE" and m.get("call-id") == cid for m in bob.received), rep)

    # Busy: voicemail.
    r, d, cid = call(bob="486", vm="200")
    sc.check("bob busy (486) → voicemail answers: 200 from voicemail", r is not None and r.code == 200 and f":{vm.port}" in (r.get("contact") or ""), r)
    v = invites(vm, cid)
    sc.check("voicemail gets one INVITE for bob's mailbox (R-URI sip:bob@voicemail.example.com)",
             len(v) == 1 and v[0].ruri == "sip:bob@voicemail.example.com", [m.ruri for m in v])
    sc.check("…with Diversion: <sip:bob@example.com>;reason=user-busy",
             v and v[0].all("diversion") == ["<sip:bob@example.com>;reason=user-busy"], v and v[0].raw)
    sc.check("…and still carries the proxy's Record-Route (added before the await)",
             v and len(v[0].all("record-route")) == 1 and f":{sip}" in v[0].all("record-route")[0], v and v[0].raw)
    sc.check("…and Max-Forwards decremented once (70 → 69), as on bob's leg",
             v and v[0].get("max-forwards") == "69" and all(m.get("max-forwards") == "69" for m in invites(bob, cid)),
             (v and v[0].get("max-forwards"), [m.get("max-forwards") for m in invites(bob, cid)]))
    sc.check("…and the voicemail leg carries the caller's SDP", v and f"m=audio {alice.port + 1000}" in v[0].body, v and v[0].body)
    if d:
        rep = d.bye()
        sc.check("…BYE to voicemail: 200", rep is not None and rep.code == 200 and any(m.method == "BYE" and m.get("call-id") == cid for m in vm.received), rep)

    r, d, cid = call(bob="600", vm="200")
    sc.check("600 Busy Everywhere is global (RFC 3261 §16.7): forwarded, no voicemail", r is not None and r.code == 600 and not invites(vm, cid), r)

    # Declined: the caller gets the 603, no voicemail.
    r, d, cid = call(bob="603", vm="200")
    sc.check("603 Decline is forwarded to the caller, not voicemail", r is not None and r.code == 603 and not invites(vm, cid), r)

    # No answer: bob rings past the await timeout (5s).
    t0 = time.time()
    r, d, cid = call(bob="ring", vm="200")
    took = time.time() - t0
    sc.check("no answer (bob rings) → voicemail answers: 200", r is not None and r.code == 200 and f":{vm.port}" in (r.get("contact") or ""), r)
    v = invites(vm, cid)
    sc.check("…with Diversion reason=no-answer", v and v[0].all("diversion") == ["<sip:bob@example.com>;reason=no-answer"], v and v[0].raw)
    sc.check("…bob's ringing branch is CANCELed", len(invites(bob, cid, "CANCEL")) == 1, [m.first for m in bob.received if m.get("call-id") == cid])
    sc.check("…after the await timeout (5s), not fr_inv_timer (60s)", 4 <= took < 15, took)
    if d:
        d.bye()

    # Not registered: straight to voicemail.
    mode.clear()
    mode["vm"] = "200"
    r, d = alice.call("sip:carol@example.com", timeout=6)
    cid = d.call_id if d else (r.get("call-id") if r else None)
    v = invites(vm, cid)
    sc.check("a user with no registration → voicemail at once (200), reason=unavailable",
             r is not None and r.code == 200 and v and v[0].ruri == "sip:carol@voicemail.example.com"
             and v[0].all("diversion") == ["<sip:carol@example.com>;reason=unavailable"], (r, v and v[0].raw))
    if d:
        d.bye()

    # A redirect from the callee: forwarded to the caller (no recursion).
    r, d, cid = call(bob="302", vm="200")
    sc.check("bob's 302 is forwarded to the caller with its Contact (not followed, not voicemail)",
             r is not None and r.code == 302 and "mobile.example.net" in (r.get("contact") or "") and not invites(vm, cid), r)

    # CANCEL while bob rings: 487, no voicemail.
    mode.clear()
    mode.update(bob="ring", vm="200")
    sent = alice.invite("sip:bob@example.com")
    ring = alice.recv(4, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == sent["call_id"])
    sc.check("bob rings: 180 reaches the caller", ring is not None)
    alice.cancel(sent)
    r = alice.final(method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"], timeout=6)
    sc.check("caller CANCEL while bob rings → 487 to the caller", r is not None and r.code == 487, r)
    if r is not None:
        alice._ack_neg(sent, r)
    time.sleep(1.0)
    sc.check("…bob got the CANCEL", len(invites(bob, sent["call_id"], "CANCEL")) == 1)
    sc.check("…and voicemail is not called after a CANCEL", not invites(vm, sent["call_id"]))

    # CANCEL during the voicemail leg: bob busy, voicemail rings.
    mode.clear()
    mode.update(bob="486", vm="ring")
    sent = alice.invite("sip:bob@example.com")
    ok = False
    end = time.time() + 5
    while time.time() < end and not ok:
        ok = bool(invites(vm, sent["call_id"]))
        time.sleep(0.1)
    sc.check("bob busy → voicemail rings", ok)
    time.sleep(0.3)
    alice.cancel(sent)
    r = alice.final(method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"], timeout=6)
    sc.check("caller CANCEL during the voicemail leg → 487", r is not None and r.code == 487, r)
    if r is not None:
        alice._ack_neg(sent, r)
    time.sleep(0.5)
    vi = invites(vm, sent["call_id"])
    vc = invites(vm, sent["call_id"], "CANCEL")
    sc.check("…voicemail got a CANCEL on its INVITE's branch", len(vc) == 1 and vi and vc[0].all("via")[0] == vi[0].all("via")[0],
             [m.first for m in vm.received if m.get("call-id") == sent["call_id"]])
    sc.check("…and bob got no CANCEL (its branch had already ended with 486)", not invites(bob, sent["call_id"], "CANCEL"))
