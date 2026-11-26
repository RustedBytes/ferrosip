"""s07-flood-ban: per-source counters swept by a timer, bans with a ttl, and
an HTTP API (on http) to query and lift bans."""
import time

import sipkit


def burst(ua, n, target):
    """Send n OPTIONS at once (no waiting in between); how many got a final reply."""
    sent = [ua.request("OPTIONS", target)["call_id"] for _ in range(n)]
    got, end = set(), time.time() + 2.0
    while time.time() < end and len(got) < n:
        m = ua.recv(0.3, lambda m: m.is_reply and m.code >= 200 and m.get("call-id") in sent)
        if m is None:
            break
        got.add(m.get("call-id"))
    return len(got)


def ping(ua, target, timeout=1.0):
    r = ua.request("OPTIONS", target)
    return ua.final(timeout, call_id=r["call_id"])


def run(sc):
    sip, http_port = sc.port(), sc.port()
    up = sc.ua("upstream", sip).auto_answer()
    sc.proxy(env=sc.env(SIP_PORT=sip, HTTP_PORT=http_port, UPSTREAM=f"sip:127.0.0.1:{up.port}"))
    api = f"http://127.0.0.1:{http_port}"
    keepalive = f"sip:127.0.0.1:{sip}"

    def http(path, method="GET"):
        for _ in range(20):  # the HTTP listener may come up just after the SIP ones
            st, body = sipkit.http_get(api + path, method=method)
            if st is not None:
                return st, body
            time.sleep(0.1)
        return st, body

    st, body = http("/bans")
    sc.check("GET /bans with no bans → 200 \"0\"", st == 200 and body.strip() == "0", (st, body))
    st, body = http("/stats")
    s0 = dict(kv.split("=") for kv in body.split()) if st == 200 else {}
    time.sleep(2.2)
    st, body = http("/stats")
    s1 = dict(kv.split("=") for kv in body.split()) if st == 200 else {}
    sc.check("on timer(every: 1s) runs: sweeps go up by about 2 in 2.2s",
             s0 and s1 and 1 <= int(s1["sweeps"] or 0) - int(s0["sweeps"] or 0) <= 3, (s0, s1))

    # A steady 6-7 requests per second for 3s (20 in all, more than flood_limit 10):
    # the sweep resets the window, so the source is never banned.
    steady = sc.ua("steady", sip)
    answered = 0
    for _ in range(20):
        t = time.time()
        if ping(steady, keepalive) is not None:
            answered += 1
        time.sleep(max(0.0, 0.15 - (time.time() - t)))
    sc.check("20 requests at ~6/s (under 10/s, more than 10 in all) are all answered: the timer resets the window",
             answered == 20, answered)

    # A burst of 30 from one source: about 10 answered, then banned and dropped.
    flooder = sc.ua("flooder", sip)
    who = f"127.0.0.1:{flooder.port}"
    n = burst(flooder, 30, keepalive)
    sc.check("a burst of 30 at once: 10..20 answered (flood_limit 10 per window), the rest dropped", 10 <= n <= 20, n)
    t_ban = time.time()
    sc.check("…the banned source gets nothing", ping(flooder, keepalive, 0.5) is None)
    sc.check("…its non-OPTIONS requests are dropped too (no relay, no reply)",
             ping(flooder, "sip:bob@example.com", 0.5) is None and not any(m.get("from", "") and "flooder" in m.get("from") for m in up.received))
    sc.check("…another source (other port, same IP) is still served", ping(steady, keepalive) is not None)
    r = steady.request("MESSAGE", "sip:bob@example.com", body="hi", content_type="text/plain")
    rep = steady.final(call_id=r["call_id"])
    sc.check("…and still relayed upstream", rep is not None and rep.code == 200, rep)

    st, body = http(f"/bans?{who}")
    sc.check("GET /bans?<ip:port> of the flooder → 200 banned", st == 200 and body.strip() == "banned", (st, body))
    st, body = http(f"/bans?127.0.0.1:{steady.port}")
    sc.check("GET /bans?<ip:port> of a good source → 404 not banned", st == 404, (st, body))
    st, body = http("/bans")
    sc.check("GET /bans → 1", st == 200 and body.strip() == "1", (st, body))
    st, body = http("/stats")
    sc.check("/stats counts the ban", st == 200 and "bans=1 " in body, (st, body))

    # The ban expires 5s after it was set, even though the source kept sending
    # meanwhile. Shared tables expire in whole seconds (as Kamailio's htable):
    # a 5s item set at T lives until floor(T) + 6, i.e. 5 to 6 s. The ban was
    # set during the burst, before t_ban, so it is gone by t_ban + 6; the
    # requests at t_ban + 2 would keep it until at least t_ban + 7 if they
    # extended it.
    time.sleep(max(0.0, 2.0 - (time.time() - t_ban)))
    for _ in range(3):
        ping(flooder, keepalive, 0.3)
    time.sleep(max(0.0, 6.3 - (time.time() - t_ban)))
    sc.check("the ban expires after its 5s ttl (requests while banned don't extend it)", ping(flooder, keepalive) is not None)
    st, body = http("/bans")
    sc.check("…GET /bans → 0 again (an expired item isn't counted)", st == 200 and body.strip() == "0", (st, body))

    # DELETE /bans?<ip:port>: one ban lifted at once.
    time.sleep(1.1)  # a fresh window
    n = burst(flooder, 30, keepalive)
    sc.check("flooding again bans again", ping(flooder, keepalive, 0.5) is None, n)
    st, _ = http(f"/bans?{who}", method="DELETE")
    sc.check("DELETE /bans?<ip:port> → 204", st == 204, st)
    time.sleep(1.1)  # the counter of the flood's window is swept
    sc.check("…the source is served again once its window is swept (else its count re-bans it)", ping(flooder, keepalive) is not None)

    # DELETE /bans: every ban lifted.
    f2 = sc.ua("flooder2", sip)
    time.sleep(1.1)
    burst(flooder, 30, keepalive)
    burst(f2, 30, keepalive)
    st, body = http("/bans")
    sc.check("two flooders → GET /bans → 2", st == 200 and body.strip() == "2", (st, body))
    st, _ = http("/bans", method="POST")
    st2, body = http("/bans")
    sc.check("POST /bans → 404 (no handler matches) and lifts nothing", st == 404 and body.strip() == "2", (st, body))
    st, _ = http("/bans", method="DELETE")
    sc.check("DELETE /bans → 204", st == 204, st)
    time.sleep(1.1)
    sc.check("…both flooders are served again", ping(flooder, keepalive) is not None and ping(f2, keepalive) is not None)
    st, body = http("/bans")
    sc.check("…GET /bans → 0", st == 200 and body.strip() == "0", (st, body))
    st, body = http("/nothing-here")
    sc.check("an unknown path → 404 from the catch-all handler", st == 404 and "no such resource" in body, (st, body))
