"""m01-registrar-proxy: auth + location, 404 vs 480, parallel forking to two
contacts of one AoR (first 200 wins, the other branch is CANCELed), and a
CANCEL from the caller while both ring."""
import time

import sipkit


def invite_auth(ua, ruri):
    """INVITE `ruri` and answer the 407 without waiting for the final reply
    (for ringing and CANCEL tests); the sent request with credentials."""
    sent = ua.invite(ruri)
    r = ua.final(method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"])
    if r is None or r.code != 407:
        return None, r
    ua._ack_neg(sent, r)
    _, p, hdr = sipkit.challenges(r)[0]
    name, value = sipkit.credentials(ua.user, ua.password, p, "INVITE", ruri, hdr)
    sent2 = ua.request("INVITE", ruri, to=sent["to"], call_id=sent["call_id"], from_tag=sent["from_tag"],
                       cseq=sent["cseq"] + 1, headers={name: value}, body=sent["body"])
    return sent2, r


def branches(ua, cid, method="INVITE"):
    """Distinct requests of this call at `ua` (by top Via: retransmissions share it)."""
    return list({m.all("via")[0] for m in ua.received if m.method == method and m.get("call-id") == cid})


def run(sc):
    sip = sc.port()
    sc.proxy(env=sc.env(SIP_PORT=sip))
    alice = sc.ua("alice", sip, password="secret-a")
    bob1 = sc.ua("bob", sip, password="secret-b")   # bob's desk phone
    bob2 = sc.ua("bob", sip, password="secret-b")   # bob's softphone
    alice.auto_answer()

    # --- registration
    r = alice.register()
    sc.check("alice registers (401 challenge, then 200)", r is not None and r.code == 200, r)
    r1 = bob1.register()
    r2 = bob2.register()
    sc.check("bob registers two contacts: both 200", r1 is not None and r1.code == 200 and r2 is not None and r2.code == 200, (r1, r2))
    sc.check("the second 200 lists both of bob's contacts",
             r2 is not None and len(r2.all("contact")) == 2 and f":{bob1.port}" in " ".join(r2.all("contact")) and f":{bob2.port}" in " ".join(r2.all("contact")),
             r2 and r2.all("contact"))
    wrong = sc.ua("carol", sip, password="not-carols")
    r = wrong.register()
    sc.check("a REGISTER with a wrong password is refused (401/403, never 200)", r is not None and r.code in (401, 403), r)
    sent = alice.request("REGISTER", "sip:example.com", to=f"<{alice.aor}>", headers={"Contact": f"<{alice.contact}>", "Expires": "60"})
    r = alice.final(method="REGISTER", call_id=sent["call_id"])
    sc.check("a REGISTER without credentials is challenged with 401 (WWW-Authenticate)",
             r is not None and r.code == 401 and r.get("www-authenticate") is not None, r)

    carol = sc.ua("carol", sip, password="secret-c")
    r = carol.register(expires=7200)
    sc.check("a REGISTER asking 7200s is clamped to max_expires (1h): expires=3600 in the 200",
             r is not None and r.code == 200 and "expires=3600" in (r.get("contact") or ""), r and r.get("contact"))
    r = carol.register(expires=0)
    sc.check("…and carol unregisters again (Expires 0 → 200 without contacts)", r is not None and r.code == 200 and not r.all("contact"), r and r.raw)

    # --- 404 vs 480
    r, _ = alice.call("sip:zed@example.com")
    sc.check("a call to an unknown user → 404", r is not None and r.code == 404, r)
    r, _ = alice.call("sip:carol@example.com")
    sc.check("a call to a known user with no registration → 480", r is not None and r.code == 480, r)
    r, _ = alice.call("sip:caroline@example.com")
    sc.check("the users list matches whole names: 'caroline' is unknown → 404 (not carol's 480)", r is not None and r.code == 404, r)
    anon = sc.ua("alice", sip)  # no password
    r, _ = anon.call("sip:bob@example.com", auth=False)
    sc.check("an INVITE without credentials → 407 (Proxy-Authenticate)",
             r is not None and r.code == 407 and r.get("proxy-authenticate") is not None, r)
    sc.check("…and is never relayed to bob", not any(m.get("call-id") == (r and r.get("call-id")) for m in bob1.received + bob2.received))

    # Credentials of one user with the From of another: auth.check's flag 1
    # (the From user must be the authenticated user).
    sent = alice.request("INVITE", "sip:bob@example.com", body=sipkit.sdp(alice.port + 1000), from_uri="sip:carol@example.com")
    r = alice.final(method="INVITE", call_id=sent["call_id"])
    if r is not None and r.code == 407:
        alice._ack_neg(sent, r)
        _, p, hdr = sipkit.challenges(r)[0]
        name, value = sipkit.credentials("alice", "secret-a", p, "INVITE", "sip:bob@example.com", hdr)
        s2 = alice.request("INVITE", "sip:bob@example.com", to=sent["to"], call_id=sent["call_id"], from_tag=sent["from_tag"],
                           cseq=2, headers={name: value}, body=sent["body"], from_uri="sip:carol@example.com")
        r = alice.final(method="INVITE", call_id=sent["call_id"], cseq=2)
        if r is not None:
            alice._ack_neg(s2, r)
    sc.check("alice's credentials with From: carol are refused (4xx, not relayed)",
             r is not None and 400 <= r.code < 500 and not branches(bob1, sent["call_id"]) and not branches(bob2, sent["call_id"]), r)

    # --- parallel forking: bob1 answers after ringing, bob2 only rings.
    bob1.auto_answer(ring=True, delay=0.7)
    bob2.auto_answer(code=None, ring=True)
    r, d = alice.call("sip:bob@example.com", timeout=8)
    sc.check("alice → bob (two contacts): 200", r is not None and r.code == 200 and d is not None, r)
    cid = d.call_id if d else (r.get("call-id") if r else None)
    sc.check("both of bob's contacts got the INVITE (parallel fork), once each",
             len(branches(bob1, cid)) == 1 and len(branches(bob2, cid)) == 1, (branches(bob1, cid), branches(bob2, cid)))
    sc.check("the 200 comes from bob1 (the one that answered)", r is not None and f":{bob1.port}" in (r.get("contact") or ""), r and r.get("contact"))
    time.sleep(1.0)
    c2 = [m for m in bob2.received if m.method == "CANCEL" and m.get("call-id") == cid]
    sc.check("the ringing branch (bob2) is CANCELed after bob1's 200", len(c2) >= 1, [m.first for m in bob2.received])
    sc.check("…with a CANCEL on the same branch as its INVITE",
             c2 and c2[0].all("via")[0] == branches(bob2, cid)[0] if branches(bob2, cid) else False,
             (c2 and c2[0].all("via"), branches(bob2, cid)))
    sc.check("…and bob1 (the winner) gets no CANCEL", not any(m.method == "CANCEL" and m.get("call-id") == cid for m in bob1.received))
    sc.check("the caller sees exactly one 200 dialog: Record-Route of the proxy",
             r is not None and len(r.all("record-route")) == 1 and f":{sip}" in r.all("record-route")[0], r and r.all("record-route"))
    time.sleep(0.3)
    sc.check("bob1 got the ACK of the 200 (through the proxy's Record-Route)",
             any(m.method == "ACK" and m.get("call-id") == cid for m in bob1.received))
    b2 = branches(bob2, cid)
    sc.check("bob2's 487 is ACKed by the proxy, on bob2's INVITE branch (hop by hop)",
             b2 and any(m.method == "ACK" and m.get("call-id") == cid and m.all("via")[0] == b2[0] for m in bob2.received),
             [(m.first, m.all("via")[:1]) for m in bob2.received if m.get("call-id") == cid])
    if d:
        rep = d.bye()
        sc.check("alice's BYE → bob1 answers 200", rep is not None and rep.code == 200, rep)
        sc.check("…the BYE reached bob1, not bob2",
                 any(m.method == "BYE" and m.get("call-id") == cid for m in bob1.received)
                 and not any(m.method == "BYE" and m.get("call-id") == cid for m in bob2.received))

    # --- CANCEL from the caller while both contacts ring.
    bob1.auto_answer(code=None, ring=True)
    bob2.auto_answer(code=None, ring=True)
    sent, r = invite_auth(alice, "sip:bob@example.com")
    sc.check("a second call to bob is challenged, then sent with credentials", sent is not None, r)
    if sent:
        ringing = alice.recv(4, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == sent["call_id"])
        sc.check("bob's 180 Ringing reaches alice", ringing is not None)
        time.sleep(0.3)
        cid = sent["call_id"]
        sc.check("both contacts ring (one INVITE branch each)", len(branches(bob1, cid)) == 1 and len(branches(bob2, cid)) == 1,
                 (branches(bob1, cid), branches(bob2, cid)))
        alice.cancel(sent)
        c = alice.recv(4, lambda m: m.is_reply and m.cseq_method == "CANCEL" and m.get("call-id") == cid)
        sc.check("alice's CANCEL → 200 (hop by hop, from the proxy)", c is not None and c.code == 200, c)
        r = alice.final(method="INVITE", call_id=cid, cseq=sent["cseq"], timeout=6)
        sc.check("…and the INVITE ends with 487 Request Terminated", r is not None and r.code == 487, r)
        if r is not None:
            alice._ack_neg(sent, r)
        time.sleep(0.5)
        sc.check("both of bob's contacts got the CANCEL",
                 len(branches(bob1, cid, "CANCEL")) == 1 and len(branches(bob2, cid, "CANCEL")) == 1,
                 (branches(bob1, cid, "CANCEL"), branches(bob2, cid, "CANCEL")))
        extra = alice.recv(1.0, lambda m: m.is_reply and m.get("call-id") == cid and m.cseq_method == "INVITE" and m.code >= 200 and m.code != 487)
        sc.check("alice gets no other final after the 487 (the second 487 is not forwarded)", extra is None, extra)

    # --- unregistering one contact: calls go only to the other.
    rr = bob2.register(expires=0)
    sc.check("bob2 unregisters (Expires 0) → 200 listing only bob1",
             rr is not None and rr.code == 200 and f":{bob2.port}" not in " ".join(rr.all("contact")) and f":{bob1.port}" in " ".join(rr.all("contact")),
             rr and rr.all("contact"))
    bob1.auto_answer()
    r, d = alice.call("sip:bob@example.com", timeout=6)
    cid = d.call_id if d else (r.get("call-id") if r else None)
    sc.check("after bob2 unregistered: 200 from bob1, bob2 not tried",
             r is not None and r.code == 200 and len(branches(bob1, cid)) == 1 and not branches(bob2, cid), r)
    if d:
        d.bye()
    bob1.register(expires=0)
    r, _ = alice.call("sip:bob@example.com")
    sc.check("bob with no contact left → 480", r is not None and r.code == 480, r)
