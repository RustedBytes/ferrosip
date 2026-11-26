"""m12-topology-hiding: topoh at a border proxy. The carrier sees no
internal Via, Record-Route or Contact; in-dialog requests route both ways;
replies get their Vias back."""
import time

import sipkit

MASK = "198.51.100.10"
INTERNAL_IP = "10.0.0.7"     # an internal proxy's address, in a Via below alice's


def host_of(uri):
    u = sipkit.uri_of(uri or "").split(":", 1)[-1]      # drop the scheme
    hp = u.split("@")[-1].split(";")[0]
    return hp.split(":")[0]


def run(sc):
    sip = sc.port()
    bob = sc.ua("bob", sip)          # the carrier side
    alice = sc.ua("alice", sip)      # inside; also plays the internal proxy in front of her
    sc.proxy(env=sc.env(SIP_PORT=sip, CARRIER=f"sip:127.0.0.1:{bob.port}", MASK_IP=MASK))
    me = f"127.0.0.1:{alice.port}"
    internal_rr = f"<sip:{me};lr>"

    def leaks(m, skip_rr=False):
        """Internal addresses visible in a message the outside gets (outside Record-Route with skip_rr)."""
        raw = m.raw if m is not None else ""
        if skip_rr:
            raw = "\r\n".join(l for l in raw.split("\r\n") if not l.lower().startswith("record-route:"))
        return [x for x in (me, INTERNAL_IP, "alice@127.0.0.1") if x in raw]

    # ---------------------------------------------------------- INVITE out
    bob.handler = None
    sent = alice.request("INVITE", "sip:+15551234@carrier.example", body=sipkit.sdp(alice.port + 1000),
                         headers={"Via": f"SIP/2.0/UDP {INTERNAL_IP}:5060;branch=z9hG4bKinternal1",
                                  "Record-Route": internal_rr})
    inv = bob.request_in("INVITE", timeout=4)
    sc.check("the INVITE reaches the carrier", inv is not None)
    if inv is None:
        return
    sc.check("carrier sees one Via (the proxy's), carrying the hidden ones in ;th=",
             len(inv.all("via")) == 1 and ";th=" in inv.all("via")[0], inv.all("via"))
    sc.check("…no internal address in the INVITE's Vias or Contact", not leaks(inv, skip_rr=True), (leaks(inv, skip_rr=True), inv.raw))
    sc.check(f"…the Contact is masked: sip:{MASK}:<port>;line=…",
             host_of(inv.get("contact")) == MASK and ";line=" in (inv.get("contact") or ""), inv.get("contact"))
    sc.check("…the internal proxy's Record-Route is not shown (Kamailio topoh masks Record-Route)",
             not any(me in r for r in inv.all("record-route")), inv.all("record-route"))
    sc.check("…the border proxy's own Record-Route is there", any(f":{sip}" in r for r in inv.all("record-route")), inv.all("record-route"))

    bob.respond(inv, 180, "Ringing")
    bob.respond(inv, 200, "OK", body=sipkit.sdp(bob.port + 1000))
    ok = alice.final(method="INVITE", call_id=sent["call_id"], timeout=4)
    sc.check("200 back to the caller", ok is not None and ok.code == 200, ok)
    if ok is None:
        return
    vias = ok.all("via")
    sc.check("…with both of the caller's Vias restored, in order",
             len(vias) == 2 and f"127.0.0.1:{alice.port}" in vias[0] and INTERNAL_IP in vias[1] and ";th=" not in ok.raw, vias)
    sc.check("…the carrier's Contact masked too", host_of(ok.get("contact")) == MASK and ";line=" in (ok.get("contact") or ""),
             ok.get("contact"))
    sc.check("…its Record-Route list has the internal one back", internal_rr.strip("<>") in " ".join(ok.all("record-route")),
             ok.all("record-route"))

    # The caller's in-dialog requests: R-URI = the masked Contact, Route =
    # the border proxy's Record-Route (the internal proxy popped its own).
    proxy_routes = [r for r in reversed(ok.all("record-route")) if me not in r]
    to = ok.get("to")
    target = sipkit.uri_of(ok.get("contact"))

    def from_alice(method, cseq, body=""):
        return alice.request(method, target, to=to, call_id=sent["call_id"], from_tag=sent["from_tag"], cseq=cseq,
                             headers={"Route": ", ".join(proxy_routes)}, body=body)

    from_alice("ACK", 1)
    ack = bob.request_in("ACK", timeout=4)
    sc.check("caller's ACK reaches the carrier at its real Contact", ack is not None and ack.ruri == f"sip:bob@127.0.0.1:{bob.port}",
             ack and ack.first)
    sc.check("…with no internal address", ack is not None and not leaks(ack), ack and leaks(ack))

    # ---------------------------------------------------------- re-INVITE in
    # The carrier's route set is the INVITE's Record-Route; its R-URI the
    # masked Contact it saw.
    b_routes = inv.all("record-route")
    b_target = sipkit.uri_of(inv.get("contact"))
    b_from_tag = bob.tags.get((inv.get("call-id"), inv.tag("from")))

    def from_bob(method, cseq, body=""):
        return bob.request(method, b_target, to=inv.get("from"), call_id=inv.get("call-id"), from_tag=b_from_tag, cseq=cseq,
                           headers={"Route": ", ".join(b_routes)}, body=body, from_uri="sip:+15551234@carrier.example")

    alice.handler = None
    from_bob("INVITE", 10, body=sipkit.sdp(bob.port + 1002))
    got = alice.request_in("INVITE", timeout=4)
    sc.check("carrier's re-INVITE reaches the caller at her real Contact",
             got is not None and got.ruri == f"sip:alice@127.0.0.1:{alice.port}", got and got.first)
    if got is not None:
        sc.check("…with one Via: topoh hides the carrier's Via as well", len(got.all("via")) == 1 and ";th=" in got.all("via")[0],
                 got.all("via"))
        alice.respond(got, 200, "OK", body=sipkit.sdp(alice.port + 1002))
    r = bob.final(method="INVITE", call_id=inv.get("call-id"), cseq=10, timeout=4)
    sc.check("…its 200 reaches the carrier with only the carrier's own Via", r is not None and r.code == 200 and len(r.all("via")) == 1
             and f"127.0.0.1:{bob.port}" in r.all("via")[0], r and r.all("via"))
    sc.check("…with the caller's Contact masked and no internal address", r is not None and host_of(r.get("contact")) == MASK
             and not leaks(r), r and (r.get("contact"), leaks(r)))
    if r is not None:
        from_bob("ACK", 10)
        ack = alice.request_in("ACK", timeout=4)
        sc.check("…the carrier's ACK reaches the caller", ack is not None, ack)

    # ---------------------------------------------------------- BYE out
    from_alice("BYE", 2)
    bye = bob.request_in("BYE", timeout=4)
    sc.check("caller's BYE reaches the carrier at its real Contact, nothing internal in it",
             bye is not None and bye.ruri == f"sip:bob@127.0.0.1:{bob.port}" and not leaks(bye), bye and (bye.first, leaks(bye)))
    if bye is not None:
        bob.respond(bye, 200, "OK")
    r = alice.final(method="BYE", call_id=sent["call_id"], timeout=4)
    sc.check("…and its 200 comes back to the caller", r is not None and r.code == 200, r)

    # A forged token: not routed anywhere inside.
    n = len(alice.received)
    bob.request("BYE", f"sip:{MASK}:{sip};line=AAAAforgedAAAA", to=inv.get("from"), call_id="forged-" + sipkit.rnd(),
                from_tag="x1", cseq=1, from_uri="sip:+15551234@carrier.example")
    time.sleep(1.0)
    sc.check("a request with a forged ;line= token is not routed to anyone inside", len(alice.received) == n,
             [m.first for m in alice.received[n:]])
