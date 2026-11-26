"""m11-rate-limits: pipelimit per source ip:port, ratelimit on INVITEs,
503 with Retry-After, recovery after the window, in-dialog exempt."""
import time

import sipkit


def burst(ua, n, method="MESSAGE", ruri="sip:echo@example.com"):
    """Send n requests back to back, then collect their finals: {call_id: reply}."""
    sent = [ua.request(method, ruri, body="x" if method == "MESSAGE" else sipkit.sdp(ua.port + 1000),
                       content_type="text/plain" if method == "MESSAGE" else "application/sdp") for _ in range(n)]
    want = {s["call_id"]: s for s in sent}
    got = {}
    end = time.time() + 6
    while len(got) < n and time.time() < end:
        m = ua.recv(max(0.05, end - time.time()), lambda m: m.is_reply and m.code >= 200 and m.get("call-id") in want)
        if m is None:
            break
        got.setdefault(m.get("call-id"), m)
    return want, got


def codes(got):
    out = {}
    for m in got.values():
        out[m.code] = out.get(m.code, 0) + 1
    return out


def at_upstream(up, cids, method):
    return len({m.get("call-id") for m in up.received if m.method == method and m.get("call-id") in cids})


def run(sc):
    sip = sc.port()
    up = sc.ua("upstream", sip).auto_answer()
    px = sc.proxy(env=sc.env(SIP_PORT=sip, UPSTREAM=f"sip:127.0.0.1:{up.port}"))
    a = sc.ua("alice", sip)
    b = sc.ua("bob", sip)

    # A burst from one source: 5 per 2s window pass (10 if the burst
    # straddles a window boundary), the rest get 503.
    time.sleep(0.2)
    sent, got = burst(a, 15)
    c = codes(got)
    ok, rej = c.get(200, 0), c.get(503, 0)
    sc.check("15 MESSAGEs from one source: all answered", len(got) == 15, c)
    sc.check("…5 to 10 relayed (5 per window), the rest 503", 5 <= ok <= 10 and ok + rej == 15, c)
    sc.check("…the upstream saw exactly the relayed ones", at_upstream(up, set(sent), "MESSAGE") == ok, (at_upstream(up, set(sent), "MESSAGE"), ok))
    r503 = [m for m in got.values() if m.code == 503]
    sc.check("…each 503 has Retry-After: 2 (pipe_limits.reject(2s)) and pipelimit's reason",
             r503 and all(m.get("retry-after") == "2" and m.reason == "Server Unavailable" for m in r503),
             r503 and r503[0].raw)

    # Another source (same IP, other port) is not affected.
    sent, got = burst(b, 3)
    sc.check("…meanwhile another port on the same IP: 3 of 3 relayed (its own pipe)", codes(got) == {200: 3}, codes(got))

    # Recovery: after the window the source is served again.
    time.sleep(4.5)
    sent, got = burst(a, 3)
    sc.check("after the window (4.5s later): the limited source gets 3 of 3 through", codes(got) == {200: 3}, codes(got))

    # The global cap on new calls: 9 INVITEs from 3 sources (3 each: every
    # source under its own limit), at most 4 per window pass.
    time.sleep(2.2)
    callers = [sc.ua(f"c{i}", sip) for i in range(3)]
    invs, finals = {}, {}
    for u in callers:
        for _ in range(3):
            s = u.invite("sip:conf@example.com")
            invs[s["call_id"]] = (u, s)
    end = time.time() + 6
    for u in callers:            # recv drops what it skips: collect each UA's finals in one pass
        mine = {cid for cid, (x, _) in invs.items() if x is u}
        while len(mine - set(finals)) and time.time() < end:
            m = u.recv(max(0.05, end - time.time()), lambda m, mine=mine: m.is_reply and m.code >= 200 and m.cseq_method == "INVITE"
                       and m.get("call-id") in mine)
            if m is None:
                break
            finals.setdefault(m.get("call-id"), m)
    c = codes(finals)
    sc.check("9 INVITEs from 3 sources: all answered", len(finals) == 9, c)
    sc.check("…4 to 8 calls set up (4 per window), the rest 503 Too many calls",
             4 <= c.get(200, 0) <= 8 and c.get(200, 0) + c.get(503, 0) == 9
             and all(m.reason == "Too many calls" for m in finals.values() if m.code == 503), c)
    r503 = [m for m in finals.values() if m.code == 503]
    sc.check("…with Retry-After: 2 (append_to_reply)", r503 and all(m.get("retry-after") == "2" for m in r503), r503 and r503[0].raw)
    sc.check("…the upstream saw only the accepted INVITEs", at_upstream(up, set(invs), "INVITE") == c.get(200, 0),
             (at_upstream(up, set(invs), "INVITE"), c))
    for cid, m in finals.items():
        u, s = invs[cid]
        if m.code == 200:
            sipkit.Dialog(u, s, m).ack()
            u.request("BYE", sipkit.uri_of(m.get("contact")), to=m.get("to"), call_id=cid, from_tag=s["from_tag"], cseq=2,
                      headers={"Route": ", ".join(reversed(m.all("record-route")))})
        else:
            u._ack_neg(s, m)
    rl = px.rpc("rl.stats")
    sc.check("rl.stats: the calls pipe counted drops", "calls" in str(rl) and "dropped" in str(rl), rl)

    # In a dialog nothing is limited: a source over its limit can still hang up.
    time.sleep(4.5)
    r, d = a.call("sip:conf@example.com", timeout=5)
    sc.check("alice sets up a call: 200", r is not None and r.code == 200 and d is not None, r)
    sent, got = burst(a, 12)
    sc.check("…then floods 12 MESSAGEs: some get 503", codes(got).get(503, 0) >= 2, codes(got))
    rep = d.bye() if d else None
    sc.check("…her BYE (in the dialog) still goes through: 200 from the upstream",
             rep is not None and rep.code == 200 and d is not None and at_upstream(up, {d.call_id}, "BYE") == 1, rep)
    pl = px.rpc("pl.stats")
    sc.check("pl.stats lists a pipe per source ip:port", f"src:127.0.0.1:{a.port}" in str(pl) and f"src:127.0.0.1:{b.port}" in str(pl), pl)

    # A CANCEL from a limited source still reaches the callee.
    up.auto_answer(ring=True, delay=3)
    time.sleep(4.5)
    s = a.invite("sip:conf@example.com")
    ring = a.recv(3, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == s["call_id"])
    sc.check("a ringing call from alice", ring is not None, ring)
    burst(a, 12)
    a.cancel(s)
    r = a.final(method="INVITE", call_id=s["call_id"], timeout=5)
    sc.check("…flooding, then CANCEL: the call ends with 487 (CANCEL is not limited)", r is not None and r.code == 487, r)
    if r is not None:
        a._ack_neg(s, r)
