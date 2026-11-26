"""m08-http-routing: `await http.get(…)` against a fake routing service picks
the target; 404 / 500 / bad answer / too slow / down take the fallback."""
import time


def invites(u, cid):
    return [m for m in u.received if m.method == "INVITE" and m.get("call-id") == cid]


def run(sc):
    sip = sc.port()
    uas = sc.ua("uas", sip).auto_answer()
    plus = sc.ua("plus", sip).auto_answer()
    fallback = sc.ua("fallback", sip).auto_answer()

    def route(method, path, query, body):
        user = path.rsplit("/", 1)[-1]
        return {
            "100": (200, f"127.0.0.1:{uas.port}"),
            "+4930123": (200, f"127.0.0.1:{plus.port}"),
            "404": (404, "no such number"),
            "500": (500, "database down"),
            "garbage": (200, "<html>oops</html>"),
            "slow": (200, f"127.0.0.1:{uas.port}", 3.0),
            "slowcancel": (200, f"127.0.0.1:{uas.port}", 2.0),
        }.get(user, (404, "?"))
    svc = sc.service({"*": route})
    sc.proxy(env=sc.env(SIP_PORT=sip, ROUTING_URL=f"http://127.0.0.1:{svc.srv.server_address[1]}", FALLBACK=f"sip:127.0.0.1:{fallback.port}"))
    ua = sc.ua("alice", sip)

    def call(user, timeout=8):
        n = len(svc.log)
        t0 = time.time()
        r, d = ua.call(f"sip:{user}@example.com", timeout=timeout)
        took = time.time() - t0
        cid = d.call_id if d else (r.get("call-id") if r is not None else None)
        bye = d.bye() if d else None
        return r, cid, svc.log[n:], took, bye

    # The service routes the call.
    r, cid, reqs, _, bye = call("100")
    sc.check("service answers 127.0.0.1:<uas> → the call reaches that UAS: 200", r is not None and r.code == 200 and len(invites(uas, cid)) == 1, r)
    sc.check("…the fallback is not involved", not invites(fallback, cid))
    q = reqs[0] if reqs else None
    sc.check("…one GET to the service, URL templated from R-URI user and From user",
             len(reqs) == 1 and q[0] == "GET" and q[1] == "/route/100" and q[2] == "caller=alice", reqs)
    hd = {k.lower(): v for k, v in (q[4] if q else {}).items()}
    sc.check("…with the X-Call-ID header templated from the Call-ID", hd.get("x-call-id") == cid, hd)
    sc.check("…and X-Caller from the From URI", hd.get("x-caller") == "sip:alice@example.com", hd)
    inv = (invites(uas, cid) or [None])[0]
    sc.check("…the relayed INVITE carries the Record-Route added before the await",
             inv is not None and len(inv.all("record-route")) == 1, inv and inv.all("record-route"))
    sc.check("…so the BYE follows the route set: 200", bye is not None and bye.code == 200, bye)
    sc.check("…no X-Routing-Fallback header on a routed call", inv is not None and inv.get("x-routing-fallback") is None, inv and inv.raw)

    # An E.164 number: the + stays a literal + in the URL path.
    r, cid, reqs, _, _ = call("+4930123")
    sc.check("+4930123 → path /route/+4930123 (not encoded, not a space) → its UAS",
             r is not None and r.code == 200 and len(invites(plus, cid)) == 1 and reqs and reqs[0][1] == "/route/+4930123", (r, reqs))

    def fallback_case(user, what, expect_hdr):
        r, cid, reqs, took, _ = call(user)
        inv = (invites(fallback, cid) or [None])[0]
        hdr = inv.get("x-routing-fallback") if inv else None
        sc.check(f"{what} → the fallback answers: 200, the routed UAS not tried",
                 r is not None and r.code == 200 and inv is not None and not invites(uas, cid), (r, reqs))
        sc.check(f"…X-Routing-Fallback says why ({expect_hdr})", hdr is not None and hdr.startswith(expect_hdr), hdr)
        sc.check("…the fallback INVITE keeps the Record-Route", inv is not None and len(inv.all("record-route")) == 1,
                 inv and inv.all("record-route"))
        return took, reqs, hdr

    fallback_case("404", "service 404", "status 404")
    fallback_case("500", "service 500", "status 500")
    fallback_case("garbage", "service 200 with a body that is no ip:port", "status 200")
    took, reqs, hdr = fallback_case("slow", "service slower (3s) than the 1s timeout", "error")
    sc.check("…the call didn't wait for the slow service (well under its 3s)", took < 2.8, took)
    sc.check("…the service did get the query", len(reqs) == 1, reqs)

    # A user part with characters that would change the URL: refused
    # before any query.
    n = len(svc.log)
    for user, what in (("1&admin=1", "&"), ("..%2F..%2Fadmin", "%"), ("a;b", ";")):
        r, d = ua.call(f"sip:{user}@example.com", timeout=5)
        sc.check(f"user with {what!r} → 484 Bad number", r is not None and r.code == 484, r)
    sc.check("…and the routing service never saw those", len(svc.log) == n, svc.log[n:])

    # CANCEL while the query is in flight: 487, and the call is never
    # relayed when the answer comes in.
    n = len(svc.log)
    sent = ua.invite("sip:slowcancel@example.com")
    time.sleep(0.5)
    ua.cancel(sent)
    c = ua.final(method="CANCEL", call_id=sent["call_id"], timeout=4)
    sc.check("CANCEL during the HTTP query → 200 for the CANCEL", c is not None and c.code == 200, c)
    r = ua.final(method="INVITE", call_id=sent["call_id"], timeout=6)
    sc.check("…and 487 for the INVITE", r is not None and r.code == 487, r)
    if r is not None:
        ua._ack_neg(sent, r)
    time.sleep(2.5)  # the slow answer (2s) arrives
    sc.check("…the INVITE is not relayed when the late answer arrives",
             not invites(uas, sent["call_id"]) and not invites(fallback, sent["call_id"]),
             [m.first for m in invites(uas, sent["call_id"]) + invites(fallback, sent["call_id"])])
    sc.check("…the query had been sent", len(svc.log) == n + 1, svc.log[n:])

    # Service down (port closed): fallback at once.
    svc.close()
    time.sleep(0.3)
    took, reqs, hdr = fallback_case("100", "routing service down (connection refused)", "error")
    sc.check("…quickly (no waiting for the timeout)", took < 2.0, took)
    sc.check("…the error text is in the header", hdr is not None and len(hdr) > len("error "), hdr)

    o = ua.request("OPTIONS", "sip:100@example.com")
    r = ua.final(call_id=o["call_id"])
    sc.check("an OPTIONS (not a call) → 405", r is not None and r.code == 405, r)
