"""m02-gateway-failover: `await txn.relay` in a loop over three gateways."""
import time


def gateway(sc, sip, name, mode):
    """A gateway whose behaviour for the next INVITE is `mode[name]`."""
    g = sc.ua(name, sip)

    def h(m):
        if m.method == "INVITE":
            what = mode.get(name, "200")
            if what == "silent":
                return None                          # not even 100 Trying
            if what == "ring":
                g.respond(m, 180, "Ringing")         # rings until CANCEL
                return None
            code = int(what)
            return (code, {200: "OK", 486: "Busy Here", 503: "Service Unavailable", 603: "Decline", 404: "Not Found"}.get(code, "X"))
        if m.method == "CANCEL":
            g.respond(m, 200)
            inv = next(x for x in reversed(g.received) if x.method == "INVITE" and x.get("call-id") == m.get("call-id"))
            g.respond(inv, 487, "Request Terminated")
            return None
        if m.method in ("ACK",):
            return None
        return (200, "OK")
    g.handler = h
    return g


def invites(g, cid):
    """INVITEs of this call at a gateway (one per branch: UDP retransmissions share it)."""
    return list({m.all("via")[0] for m in g.received if m.method == "INVITE" and m.get("call-id") == cid})


def run(sc):
    sip = sc.port()
    mode = {}
    gws = [gateway(sc, sip, f"gw{i}", mode) for i in (1, 2, 3)]
    sc.proxy(env=sc.env(SIP_PORT=sip, **{f"GW{i}": f"sip:127.0.0.1:{g.port}" for i, g in enumerate(gws, 1)}))
    ua = sc.ua("alice", sip)

    def call(case, **modes):
        mode.clear()
        mode.update(modes)
        r, d = ua.call("sip:+4930123456@example.com", timeout=8)
        cid = d.call_id if d else None
        if cid is None and r is not None:
            cid = r.get("call-id")
        tried = [len(invites(g, cid)) for g in gws]
        if d:
            d.bye()
        return r, tried

    r, tried = call("first answers", gw1="200")
    sc.check("gw1 answers: 200, gw2/gw3 untouched", r and r.code == 200 and tried == [1, 0, 0], (r, tried))

    r, tried = call("5xx then answer", gw1="503", gw2="200")
    sc.check("gw1 503 → gw2 answers: 200", r and r.code == 200 and tried == [1, 1, 0], (r, tried))

    r, tried = call("busy stops", gw1="486")
    sc.check("gw1 486 Busy: forwarded, no failover", r and r.code == 486 and tried == [1, 0, 0], (r, tried))

    r, tried = call("6xx stops", gw1="603")
    sc.check("gw1 603 Decline (global): forwarded, no failover", r and r.code == 603 and tried == [1, 0, 0], (r, tried))

    t0 = time.time()
    r, tried = call("silent gateway", gw1="silent", gw2="200")
    sc.check("gw1 silent → timeout → gw2 answers", r and r.code == 200 and tried == [1, 1, 0], (r, tried))
    sc.check("…after about fr_timer (1s), not fr_inv_timer", time.time() - t0 < 6, time.time() - t0)

    r, tried = call("all fail", gw1="503", gw2="503", gw3="503")
    sc.check("all gateways 503 → 503 All gateways failed", r and r.code == 503 and r.reason == "All gateways failed" and tried == [1, 1, 1], (r, tried))

    # CANCEL while gw1 rings: the caller gets 487 and no other gateway is tried.
    mode.clear()
    mode["gw1"] = "ring"
    sent = ua.invite("sip:+4930999@example.com")
    ringing = ua.recv(3, lambda m: m.is_reply and m.code == 180)
    sc.check("ringing at gw1 reaches the caller", ringing is not None)
    ua.cancel(sent)
    r = ua.final(method="INVITE", call_id=sent["call_id"], timeout=5)
    sc.check("CANCEL during ringing → 487 to the caller", r is not None and r.code == 487, r)
    if r is not None:
        ua._ack_neg(sent, r)
    time.sleep(0.5)
    sc.check("…and no failover after the CANCEL", [len(invites(g, sent["call_id"])) for g in gws] == [1, 0, 0],
             [len(invites(g, sent["call_id"])) for g in gws])
