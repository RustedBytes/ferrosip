"""l03-carrier-interconnect: an SBC between customers and two carriers:
digest auth, a per-customer rate limit, number normalisation, failover
with `await`, topology hiding and CDRs posted to a collector."""
import time

from sipkit import challenges, credentials, uri_of


def carrier(sc, sip, name, mode):
    """A carrier whose answer to the next INVITE is `mode[name]` (a code,
    "ring" or "silent"). A local helper (like m02's gateway)."""
    g = sc.ua(name, sip)

    def h(m):
        if m.method == "INVITE":
            what = mode.get(name, "200")
            if what == "silent":
                return None
            if what == "ring":
                g.respond(m, 180, "Ringing")
                return None
            code = int(what)
            body = "" if code >= 300 else "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n"
            g.respond(m, code, {200: "OK", 486: "Busy Here", 503: "Service Unavailable"}.get(code, "X"), body=body)
            return None
        if m.method == "CANCEL":
            g.respond(m, 200)
            inv = next(x for x in reversed(g.received) if x.method == "INVITE" and x.get("call-id") == m.get("call-id"))
            g.respond(inv, 487, "Request Terminated")
            return None
        if m.method == "ACK":
            return None
        return (200, "OK")
    g.handler = h
    return g


def invites(g, cid):
    """INVITEs of this call at a carrier (one per branch: retransmissions share it)."""
    return list({m.all("via")[0]: m for m in g.received if m.method == "INVITE" and m.get("call-id") == cid}.values())


def cdrs(svc, cid, event):
    """CDRs of this event posted for this call, as dicts. The body is not
    URL-encoded: split by hand, so a '+' stays a '+'."""
    out = []
    for _, path, _, body, _ in list(svc.log):
        if path == "/cdr":
            d = dict(kv.split("=", 1) for kv in body.split("&") if "=" in kv)
            if d.get("call_id") == cid and d.get("event") == event:
                out.append(d)
    return out


def wait_for(cond, timeout=4.0):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(0.05)
    return cond()


def invite_with_auth(ua, number, domain):
    """An INVITE that answers the 407 challenge but doesn't wait for the
    final (for CANCEL tests); the sent request, or None."""
    sent = ua.invite(f"sip:{number}@{domain}")
    r = ua.final(method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"])
    if r is None or r.code != 407:
        return None
    ua._ack_neg(sent, r)
    alg, p, hdr = challenges(r)[0]
    name, value = credentials(ua.user, ua.password, p, "INVITE", sent["ruri"], hdr, alg)
    return ua.request("INVITE", sent["ruri"], to=sent["to"], call_id=sent["call_id"], from_tag=sent["from_tag"],
                      cseq=sent["cseq"] + 1, headers={name: value}, body=sent["body"])


def run(sc):
    sip = sc.port()
    mode = {}
    c1, c2 = carrier(sc, sip, "carrier1", mode), carrier(sc, sip, "carrier2", mode)
    gw1, gw2 = f"sip:127.0.0.1:{c1.port}", f"sip:127.0.0.1:{c2.port}"
    collector = sc.service({"/cdr": (200, "ok")})
    sc.proxy("sbc", sc.env(SIP_PORT=sip, CARRIER1=gw1, CARRIER2=gw2, CDR_URL=f"http://127.0.0.1:{collector.srv.server_address[1]}/cdr"), name="sbc")
    dom = "sbc.example.com"
    cust = {n: sc.ua(f"cust-{n}", sip, password=f"secret-{n}", domain=dom).auto_answer() for n in "abcde"}

    def call(ua, number, **modes):
        mode.clear()
        mode.update(modes)
        r, d = ua.call(f"sip:{number}@{dom}", timeout=8)
        cid = d.call_id if d else (r.get("call-id") if r is not None else None)
        return r, d, cid, [len(invites(g, cid)) for g in (c1, c2)]

    # --- Normalisation (cust-a): national, international with 00, E.164.
    for dialled, want in (("030123456", "+4930123456"), ("00442071234567", "+442071234567"), ("+4930999", "+4930999")):
        r, d, cid, tried = call(cust["a"], dialled, carrier1="200")
        inv = invites(c1, cid)
        sc.check(f"{dialled} reaches carrier 1 as {want}", r is not None and r.code == 200 and len(inv) == 1
                 and inv[0].ruri.startswith(f"sip:{want}@"), (r, inv and inv[0].ruri))
        if d:
            d.bye()
    r, d, cid, tried = call(cust["a"], "123", carrier1="200")
    sc.check("a short number that isn't E.164 after normalising → 484, no carrier tried",
             r is not None and r.code == 484 and tried == [0, 0], (r, tried))

    # --- Topology hiding and the CDR of one answered call (cust-b).
    b = cust["b"]
    r, d, cid, tried = call(b, "0301111", carrier1="200")
    sc.check("cust-b's call is answered by carrier 1 only", r is not None and r.code == 200 and tried == [1, 0], (r, tried))
    inv = (invites(c1, cid) or [None])[0]
    if inv is not None:
        sc.check("carrier 1 sees one Via (the SBC's), not the customer's",
                 len(inv.all("via")) == 1 and f"127.0.0.1:{sip}" in inv.all("via")[0], inv.all("via"))
        sc.check("carrier 1 sees the customer's address nowhere in the INVITE", f"127.0.0.1:{b.port}" not in inv.raw, inv.raw)
        sc.check("…its Contact is the SBC's masked one", f"127.0.0.1:{sip}" in (inv.get("contact") or ""), inv.get("contact"))
        sc.check("…and it carries no customer credentials", inv.get("proxy-authorization") is None, inv.raw)
    if d and inv is not None:
        # The carrier hangs up: its BYE goes to the masked Contact, i.e. the SBC.
        tag = c1.tags.get((cid, inv.tag("from")))
        c1.request("BYE", uri_of(inv.get("contact")), to=inv.get("from"), call_id=cid, from_tag=tag, cseq=1,
                   from_uri=uri_of(inv.get("to")))
        rep = c1.final(call_id=cid, method="BYE")
        sc.check("carrier 1's BYE (to the masked Contact) reaches cust-b; 200 back", rep is not None and rep.code == 200, rep)
        got = next((m for m in b.received if m.method == "BYE" and m.get("call-id") == cid), None)
        sc.check("…cust-b got the BYE", got is not None)
        cdr = wait_for(lambda: cdrs(collector, cid, "end"))
        sc.check("a CDR for the answered call reached the collector", len(cdr) == 1, [x[3] for x in collector.log])
        if cdr:
            x = cdr[0]
            sc.check("…with the customer, the normalised number and the carrier",
                     (x.get("customer"), x.get("number"), x.get("carrier")) == ("cust-b", "+49301111", gw1), x)
            sc.check("…and the end reason callee_bye (the carrier hung up)", x.get("reason") == "callee_bye", x)

    # --- Failover (cust-c).
    c = cust["c"]
    r, d, cid, tried = call(c, "0302222", carrier1="503", carrier2="200")
    sc.check("carrier 1 503 → carrier 2 answers: 200", r is not None and r.code == 200 and tried == [1, 1], (r, tried))
    if d:
        d.bye()
        cdr = wait_for(lambda: cdrs(collector, cid, "end"))
        sc.check("…its CDR names carrier 2 and the end reason caller_bye",
                 len(cdr) == 1 and cdr[0].get("carrier") == gw2 and cdr[0].get("reason") == "caller_bye", cdr)
    t0 = time.time()
    r, d, cid, tried = call(c, "0303333", carrier1="silent", carrier2="200")
    sc.check("carrier 1 silent → carrier 2 answers: 200", r is not None and r.code == 200 and tried == [1, 1], (r, tried))
    sc.check("…after about fr_timer (1s), not the 30s ringing time", time.time() - t0 < 8, time.time() - t0)
    if d:
        d.bye()
    r, d, cid, tried = call(c, "0304444", carrier1="486")
    sc.check("carrier 1 486 Busy: forwarded, no failover", r is not None and r.code == 486 and tried == [1, 0], (r, tried))
    r, d, cid, tried = call(c, "0305555", carrier1="503", carrier2="503")
    sc.check("both carriers 503 → 503 No carrier available", r is not None and r.code == 503 and r.reason == "No carrier available"
             and tried == [1, 1], (r, tried))
    cdr = wait_for(lambda: cdrs(collector, cid, "failed"))
    sc.check("a failed-call CDR (dialog.failed) is posted for it, with code 503", len(cdr) == 1 and cdr[0].get("code") == "503", cdr)
    sc.check("…and no end CDR for a call that never connected", cdrs(collector, cid, "end") == [])

    # --- CANCEL while carrier 1 rings: 487, no failover (cust-d).
    mode.clear()
    mode["carrier1"] = "ring"
    dd = cust["d"]
    sent = invite_with_auth(dd, "0306666", dom)
    sc.check("cust-d's INVITE is challenged, then sent with credentials", sent is not None)
    if sent:
        ringing = dd.recv(4, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == sent["call_id"])
        sc.check("carrier 1's ringing reaches the customer", ringing is not None)
        dd.cancel(sent)
        r = dd.final(method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"], timeout=5)
        sc.check("CANCEL while carrier 1 rings → 487", r is not None and r.code == 487, r)
        if r is not None:
            dd._ack_neg(sent, r)
        time.sleep(0.5)
        n = [len(invites(g, sent["call_id"])) for g in (c1, c2)]
        sc.check("…and no failover to carrier 2 after the CANCEL", n == [1, 0], n)

    # --- Per-customer rate limit (cust-e): 5 calls per 5s window.
    codes = []
    for i in range(12):
        r, _, _, _ = call(cust["e"], f"03077{i:02d}", carrier1="486")
        codes.append((r.code, r.get("retry-after")) if r is not None else None)
    ok = sum(1 for x in codes if x and x[0] == 486)
    limited = [x for x in codes if x and x[0] == 503]
    sc.check("a burst of 12 calls from one customer: at least the limit (5) go through", ok >= 5, codes)
    sc.check("…at most two windows' worth (10), and the rest get 503", ok <= 10 and len(limited) == 12 - ok, codes)
    sc.check("…the 503s carry Retry-After: 5", limited and all(x[1] == "5" for x in limited), limited)
    r, _, _, _ = call(cust["a"], "0307799", carrier1="486")
    sc.check("…while another customer is still served", r is not None and r.code == 486, r)
