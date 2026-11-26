"""m05-nat-edge: phones that advertise a private address (Contact and Via
10.0.0.x) while their packets come from 127.0.0.1:port. Registration,
the NAT flag on the binding, rport/received, and calls both ways that must
reach the real source."""
import time

import sipkit


class NatUA(sipkit.UA):
    """A phone behind NAT: it believes it is `private` (Contact, Via), the
    proxy sees 127.0.0.1:port. With `rport=False` its Via has no ;rport.
    (Kit helper: sipkit's UA always advertises 127.0.0.1:port.)"""

    def __init__(self, private, rport, *a, **kw):
        self.private, self.rport = private, rport
        super().__init__(*a, **kw)

    @property
    def contact(self):
        return f"sip:{self.user}@{self.private}"

    def via(self, branch):
        return f"SIP/2.0/UDP {self.private};branch=z9hG4bK{branch}" + (";rport" if self.rport else "")


def nat_ua(sc, user, sip, private, rport=True, **kw):
    u = NatUA(private, rport, user, sc.port(), ("127.0.0.1", sip), **kw)
    sc.closers.append(u.close)
    return u


def invites(u, cid, method="INVITE"):
    return list({m.all("via")[0]: m for m in u.received if m.method == method and m.get("call-id") == cid}.values())


def run(sc):
    sip = sc.port()
    proxy = sc.proxy(env=sc.env(SIP_PORT=sip))
    carol = nat_ua(sc, "carol", sip, "10.0.0.5:5060", password="secret-c").auto_answer()
    dave = nat_ua(sc, "dave", sip, "192.168.1.20:5060", rport=False, password="secret-d").auto_answer()
    bob = sc.ua("bob", sip, password="secret-b").auto_answer()   # not behind NAT

    # --- registration from behind NAT
    r = carol.register()
    sc.check("carol (Via/Contact 10.0.0.5, really 127.0.0.1) registers: the 401 and the 200 reach her real address (rport)",
             r is not None and r.code == 200, r)
    sc.check("…the 200 lists the Contact as carol sent it (10.0.0.5:5060)",
             r is not None and "sip:carol@10.0.0.5:5060" in (r.get("contact") or ""), r and r.get("contact"))
    sc.check("…and the 200's Via has received=127.0.0.1 and rport=<real port>",
             r is not None and "received=127.0.0.1" in r.all("via")[0] and f"rport={carol.port}" in r.all("via")[0], r and r.all("via"))
    r = dave.register()
    sc.check("dave (private Via without ;rport) registers: the replies still reach his real port", r is not None and r.code == 200, r)
    r = bob.register()
    sc.check("bob (public) registers", r is not None and r.code == 200, r)

    dump = proxy.rpc("ul.dump")
    text = str(dump)

    def binding(user):
        def walk(x):
            if isinstance(x, dict):
                if any(user in str(v) for k, v in x.items() if k in ("contact", "aor")) and "cflags" in x:
                    yield x
                for v in x.values():
                    yield from walk(v)
            elif isinstance(x, list):
                for v in x:
                    yield from walk(v)
        return next(walk(dump), None)

    cb, bb = binding("carol"), binding("bob")
    sc.check("ul.dump: carol's binding is received from 127.0.0.1:<her port>",
             cb is not None and f"127.0.0.1:{carol.port}" in str(cb.get("received")), cb or text[:600])
    sc.check("ul.dump: carol's binding carries the NAT branch flag (bit 6: cflags & 64)",
             cb is not None and int(cb.get("cflags") or 0) & 64, cb or text[:600])
    sc.check("ul.dump: bob's binding has no NAT flag", bb is not None and not int(bb.get("cflags") or 0) & 64, bb or text[:600])

    # --- bob → carol: the INVITE must reach her real address
    r, d = bob.call("sip:carol@example.com", timeout=6)
    cid = d.call_id if d else (r.get("call-id") if r else None)
    inv = invites(carol, cid)
    sc.check("bob → carol (NATed): 200", r is not None and r.code == 200, r)
    sc.check("…the INVITE reached carol's real socket, R-URI still her registered Contact",
             len(inv) == 1 and inv[0].ruri == "sip:carol@10.0.0.5:5060", [m.ruri for m in inv])
    sc.check("…carol's private Contact in the 200 is rewritten to her real address for bob",
             r is not None and f"127.0.0.1:{carol.port}" in (r.get("contact") or "") and "10.0.0.5" not in (r.get("contact") or ""),
             r and r.get("contact"))
    time.sleep(0.3)
    sc.check("…bob's ACK reaches carol", any(m.method == "ACK" and m.get("call-id") == cid for m in carol.received))
    if d:
        rep = d.bye()
        sc.check("…bob's BYE reaches carol (through the proxy, to her real address): 200",
                 rep is not None and rep.code == 200 and any(m.method == "BYE" and m.get("call-id") == cid for m in carol.received), rep)

    # --- carol → bob: bob must be able to reach carol back
    r, d = carol.call("sip:bob@example.com", timeout=6)
    cid = d.call_id if d else (r.get("call-id") if r else None)
    inv = invites(bob, cid)
    sc.check("carol (NATed) → bob: 200 reaches carol", r is not None and r.code == 200, r)
    sc.check("…bob sees carol's Contact rewritten to 127.0.0.1:<her port>",
             len(inv) == 1 and f"127.0.0.1:{carol.port}" in (inv[0].get("contact") or ""), inv and inv[0].get("contact"))
    sc.check("…and her Via stamped received=127.0.0.1;rport=<her port> (RFC 3581)",
             len(inv) == 1 and len(inv[0].all("via")) == 2 and "received=127.0.0.1" in inv[0].all("via")[1]
             and f"rport={carol.port}" in inv[0].all("via")[1], inv and inv[0].all("via"))
    if d and inv:
        # bob hangs up: BYE to carol's (fixed) Contact through the Record-Route.
        rr = inv[0].all("record-route")
        b = bob.request("BYE", sipkit.uri_of(inv[0].get("contact")), to=inv[0].get("from"), call_id=cid,
                        from_tag=bob.tags.get((cid, inv[0].tag("from"))), cseq=1, headers={"Route": ", ".join(rr)},
                        from_uri="sip:bob@example.com")
        rep = bob.final(call_id=b["call_id"], method="BYE")
        sc.check("…bob's BYE reaches carol at her real address: 200",
                 rep is not None and rep.code == 200 and any(m.method == "BYE" and m.get("call-id") == cid for m in carol.received), rep)

    # --- dave (no rport) → carol: NAT to NAT
    r, d = dave.call("sip:carol@example.com", timeout=6)
    cid = d.call_id if d else (r.get("call-id") if r else None)
    inv = invites(carol, cid)
    sc.check("dave (NATed, Via without rport) → carol (NATed): 200 reaches dave's real port", r is not None and r.code == 200, r)
    sc.check("…carol sees dave's Contact as 127.0.0.1:<his port>",
             len(inv) == 1 and f"127.0.0.1:{dave.port}" in (inv[0].get("contact") or ""), inv and inv[0].get("contact"))
    sc.check("…dave's Via gets received=127.0.0.1 (its sent-by is private)",
             len(inv) == 1 and "received=127.0.0.1" in inv[0].all("via")[1], inv and inv[0].all("via"))
    sc.check("…dave sees carol's Contact as 127.0.0.1:<her port>",
             r is not None and f"127.0.0.1:{carol.port}" in (r.get("contact") or ""), r and r.get("contact"))
    if d:
        rep = d.bye()
        sc.check("…dave's BYE reaches carol: 200",
                 rep is not None and rep.code == 200 and any(m.method == "BYE" and m.get("call-id") == cid for m in carol.received), rep)

    # --- a public caller's Contact is left alone
    r, d = bob.call("sip:dave@example.com", timeout=6)
    cid = d.call_id if d else (r.get("call-id") if r else None)
    inv = invites(dave, cid)
    sc.check("bob → dave: the INVITE reaches dave's real socket", r is not None and r.code == 200 and len(inv) == 1, r)
    sc.check("…bob's public Contact is passed unchanged", len(inv) == 1 and inv[0].get("contact") == f"<{bob.contact}>",
             inv and inv[0].get("contact"))
    if d:
        d.bye()

    # --- the NAT binding expires with the registration
    r = carol.register(expires=0)
    sc.check("carol unregisters", r is not None and r.code == 200, r)
    r, _ = bob.call("sip:carol@example.com")
    sc.check("a call to carol after unregistering → 404 Not registered", r is not None and r.code == 404, r)
