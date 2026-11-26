"""s01-options-responder: keepalive answers, Max-Forwards and malformed
requests, a trusted-source relay to one upstream."""


def run(sc):
    sip = sc.port()
    up = sc.ua("upstream", sip)  # the upstream's own socket (answers what it gets)
    up.auto_answer()
    sc.proxy(env=sc.env(SIP_PORT=sip, UPSTREAM=f"sip:127.0.0.1:{up.port}"))
    ua = sc.ua("alice", sip)

    # OPTIONS to the proxy itself: answered here, never relayed.
    r = ua.request("OPTIONS", f"sip:127.0.0.1:{sip}")
    rep = ua.final(call_id=r["call_id"])
    sc.check("OPTIONS to the proxy → 200", rep is not None and rep.code == 200, rep)
    sc.check("the keepalive is not relayed", not any(m.method == "OPTIONS" for m in up.received))

    # Max-Forwards 0: 483, nothing relayed.
    r = ua.request("MESSAGE", "sip:bob@example.com", max_forwards=0, body="hi", content_type="text/plain")
    rep = ua.final(call_id=r["call_id"])
    sc.check("Max-Forwards 0 → 483", rep is not None and rep.code == 483, rep)

    # Malformed: a CSeq method that doesn't match the request line.
    raw = r["raw"].replace("CSeq: 1 MESSAGE", "CSeq: 1 INVITE").replace("Max-Forwards: 0", "Max-Forwards: 70")
    raw = raw.replace(r["call_id"], "malformed-1").replace(r["branch"], "malformed1")
    ua.send(raw)
    rep = ua.recv(1.0, lambda m: m.is_reply and m.get("call-id") == "malformed-1")
    sc.check("a malformed request is answered 400 by the sanity check", rep is not None and rep.code == 400, rep)
    sc.check("…and not relayed", not any(m.get("call-id") == "malformed-1" for m in up.received))

    # Anything else from a trusted source: relayed, Max-Forwards decremented,
    # the upstream's answer comes back through the proxy.
    r = ua.request("OPTIONS", "sip:bob@example.com")
    rep = ua.final(call_id=r["call_id"])
    got = [m for m in up.received if m.get("call-id") == r["call_id"]]
    sc.check("OPTIONS to a user is relayed to the upstream", len(got) == 1, up.received)
    sc.check("…with Max-Forwards 69 and the proxy's Via on top",
             got and got[0].get("max-forwards") == "69" and len(got[0].all("via")) == 2 and f":{sip}" in got[0].all("via")[0], got and got[0].raw)
    sc.check("…and the upstream's 200 comes back", rep is not None and rep.code == 200 and len(rep.all("via")) == 1, rep)

    # A MESSAGE: same path, the body arrives intact.
    r = ua.request("MESSAGE", "sip:bob@example.com", body="héllo ünïcode", content_type="text/plain; charset=utf-8")
    rep = ua.final(call_id=r["call_id"])
    got = [m for m in up.received if m.get("call-id") == r["call_id"]]
    sc.check("MESSAGE relayed with its UTF-8 body and Content-Length intact",
             got and got[0].body == "héllo ünïcode" and int(got[0].get("content-length")) == len("héllo ünïcode".encode()), got and got[0].raw)
