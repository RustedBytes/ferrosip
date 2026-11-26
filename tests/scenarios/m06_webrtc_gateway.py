"""m06-webrtc-gateway: a browser over WebSocket (with an .invalid Contact
and Via, like JsSIP / SIP.js) and a UDP phone register, call each other
both ways; double Record-Route across the transports; BYE from either
side; a closed WebSocket unregisters the browser."""
import socket
import time

import sipkit


class Browser(sipkit.UA):
    """A WebRTC client: its Contact and Via name a random .invalid host, as
    browsers do (RFC 7118 §5.2); only the WebSocket connection reaches it.
    (Kit helper: sipkit's UA always advertises 127.0.0.1:port.)"""

    def __init__(self, *a, **kw):
        self.host = sipkit.rnd(10) + ".invalid"
        super().__init__(*a, transport="ws", **kw)

    @property
    def contact(self):
        return f"sip:{self.user}@{self.host};transport=ws"

    def via(self, branch):
        return f"SIP/2.0/WSS {self.host};branch=z9hG4bK{branch}"


def browser(sc, user, ws, **kw):
    b = Browser(user, sc.port(), ("127.0.0.1", ws), **kw)
    sc.closers.append(b.close)
    return b


def got(u, cid, method):
    return list({m.all("via")[0]: m for m in u.received if m.method == method and m.get("call-id") == cid}.values())


def callee_bye(ua, inv, from_uri):
    """BYE from the callee of `inv` (route set = Record-Route as received)."""
    cid = inv.get("call-id")
    ua.request("BYE", sipkit.uri_of(inv.get("contact")), to=inv.get("from"), call_id=cid,
                   from_tag=ua.tags.get((cid, inv.tag("from"))), cseq=1, headers={"Route": ", ".join(inv.all("record-route"))},
                   from_uri=from_uri)
    return ua.final(call_id=cid, method="BYE")


def run(sc):
    sip, ws = sc.port(), sc.port()
    sc.proxy(env=sc.env(SIP_PORT=sip, WS_PORT=ws))
    alice = browser(sc, "alice", ws, password="secret-a").auto_answer()
    bob = sc.ua("bob", sip, password="secret-b").auto_answer()

    r = alice.register()
    sc.check("alice registers over WebSocket (401, then 200)", r is not None and r.code == 200, r)
    sc.check("…the 200 lists her .invalid Contact", r is not None and alice.host in (r.get("contact") or ""), r and r.get("contact"))
    r = bob.register()
    sc.check("bob registers over UDP", r is not None and r.code == 200, r)

    # --- browser → phone
    r, d = alice.call("sip:bob@example.com", timeout=6)
    cid = d.call_id if d else (r.get("call-id") if r else None)
    inv = got(bob, cid, "INVITE")
    sc.check("alice (WS) → bob (UDP): 200 over the WebSocket", r is not None and r.code == 200, r)
    rr = inv[0].all("record-route") if inv else []
    sc.check("…bob's INVITE has two Record-Routes of the proxy (WS side and UDP side)",
             len(rr) == 2 and all(f":{p}" in x for x, p in zip(rr, (sip, ws))) and "transport=ws" in rr[1].lower(), rr)
    sc.check("…and the 200 to alice carries the same two", r is not None and r.all("record-route") == rr, r and r.all("record-route"))
    sc.check("…bob sees alice's Contact with an ;alias of her connection",
             inv and alice.host in (inv[0].get("contact") or "") and "alias=" in (inv[0].get("contact") or ""), inv and inv[0].get("contact"))
    sc.check("…and alice's Via (.invalid, WSS) kept below the proxy's",
             inv and len(inv[0].all("via")) == 2 and alice.host in inv[0].all("via")[1], inv and inv[0].all("via"))
    time.sleep(0.3)
    sc.check("…alice's ACK reaches bob", any(m.method == "ACK" and m.get("call-id") == cid for m in bob.received))
    if d:
        rep = d.bye()
        sc.check("…alice's BYE (WS) reaches bob (UDP): 200",
                 rep is not None and rep.code == 200 and got(bob, cid, "BYE"), rep)

    # --- browser → phone, the phone hangs up
    r, d = alice.call("sip:bob@example.com", timeout=6)
    cid = d.call_id if d else (r.get("call-id") if r else None)
    inv = got(bob, cid, "INVITE")
    if inv:
        rep = callee_bye(bob, inv[0], "sip:bob@example.com")
        sc.check("bob's BYE (UDP) to alice's .invalid Contact reaches her WebSocket: 200",
                 rep is not None and rep.code == 200 and got(alice, cid, "BYE"), (rep, [m.first for m in alice.received if m.get("call-id") == cid]))
    else:
        sc.check("second call alice → bob established", False, r)

    # --- phone → browser
    r, d = bob.call("sip:alice@example.com", timeout=6)
    cid = d.call_id if d else (r.get("call-id") if r else None)
    inv = got(alice, cid, "INVITE")
    sc.check("bob (UDP) → alice: the INVITE arrives over her WebSocket, 200 back", r is not None and r.code == 200 and len(inv) == 1, r)
    sc.check("…its R-URI is alice's registered Contact", inv and inv[0].ruri == alice.contact, inv and inv[0].ruri)
    rr = r.all("record-route") if r is not None else []
    sc.check("…two Record-Routes in bob's 200 as well", len(rr) == 2, rr)
    sc.check("…alice's Contact in the 200 carries an ;alias for bob's in-dialog requests",
             r is not None and "alias=" in (r.get("contact") or ""), r and r.get("contact"))
    time.sleep(0.3)
    sc.check("…bob's ACK reaches alice over WS", any(m.method == "ACK" and m.get("call-id") == cid for m in alice.received))
    if d:
        rep = d.bye()
        sc.check("…bob's BYE reaches alice over WS: 200", rep is not None and rep.code == 200 and got(alice, cid, "BYE"), rep)

    # --- phone → browser, the browser hangs up
    r, d = bob.call("sip:alice@example.com", timeout=6)
    cid = d.call_id if d else (r.get("call-id") if r else None)
    inv = got(alice, cid, "INVITE")
    if inv:
        rep = callee_bye(alice, inv[0], "sip:alice@example.com")
        sc.check("alice's BYE (WS) reaches bob (UDP): 200", rep is not None and rep.code == 200 and got(bob, cid, "BYE"), rep)
    else:
        sc.check("second call bob → alice established", False, r)

    # --- a CANCEL across the transports
    alice.auto_answer(code=None, ring=True)
    sent = bob.invite("sip:alice@example.com")
    sent_auth = None
    r = bob.final(method="INVITE", call_id=sent["call_id"])
    if r is not None and r.code == 407:
        bob._ack_neg(sent, r)
        _, p, hdr = sipkit.challenges(r)[0]
        name, value = sipkit.credentials("bob", "secret-b", p, "INVITE", sent["ruri"], hdr)
        sent_auth = bob.request("INVITE", sent["ruri"], to=sent["to"], call_id=sent["call_id"], from_tag=sent["from_tag"],
                                cseq=2, headers={name: value}, body=sent["body"])
    ring = sent_auth and bob.recv(4, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == sent["call_id"])
    sc.check("bob → alice rings (180 from the browser)", ring is not None and ring is not False, ring)
    if sent_auth:
        bob.cancel(sent_auth)
        r = bob.final(method="INVITE", call_id=sent["call_id"], cseq=2, timeout=5)
        sc.check("bob's CANCEL → 487, and alice got the CANCEL over WS",
                 r is not None and r.code == 487 and got(alice, sent["call_id"], "CANCEL"), r)
        if r is not None:
            bob._ack_neg(sent_auth, r)
    alice.auto_answer()

    # --- a closed tab: the binding goes with the connection
    carol = browser(sc, "carol", ws, password="secret-c")
    r = carol.register()
    sc.check("carol registers over WebSocket", r is not None and r.code == 200, r)
    # Close the tab: shutdown() sends the FIN at once (a bare close() of a
    # socket another thread is reading from doesn't).
    try:
        carol.t.s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    carol.close()
    time.sleep(1.0)
    dump = sc.proxies[0].rpc("ul.dump")
    sc.check("after carol's WebSocket closed her binding is gone from ul.dump (handle_lost_tcp)", "carol" not in str(dump), str(dump)[:600])
    t0 = time.time()
    r, _ = bob.call("sip:carol@example.com", timeout=6)
    if r is None:
        r = bob.final(40, method="INVITE")
    sc.check("…so a call to her → 404 at once, not a timeout on the dead connection",
             r is not None and r.code == 404 and time.time() - t0 < 3, (r, time.time() - t0))
