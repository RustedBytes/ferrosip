"""m07-load-balancer: dispatcher round robin over three servers, probing,
on balancer.down/up into a shared table served by `on http`, and failover
with `await txn.relay` + `balancer.next()`."""
import os, re, time

import sipkit


def server(sc, sip, name, mode):
    """An application server. mode[name] is a dict:
    - "options": answer OPTIONS probes (False: silent, looks dead);
    - "invite": "200", "503", or "silent" (no answer at all)."""
    s = sc.ua(name, sip)
    mode[name] = {"options": True, "invite": "200"}

    def h(m):
        st = mode[name]
        if m.method == "OPTIONS":
            return (200, "OK") if st["options"] else None
        if m.method == "INVITE":
            if mode.get("fail_next"):            # shared: the first server to get it refuses
                mode["fail_next"] = False
                return (503, "Service Unavailable")
            what = st["invite"]
            if what == "silent":
                return None
            code = int(what)
            if code == 200:
                s.respond(m, 200, "OK", body=sipkit.sdp(s.port + 1000))
                return None
            return (code, "Service Unavailable" if code == 503 else "X")
        if m.method in ("BYE", "CANCEL"):
            return (200, "OK")
        return None
    s.handler = h
    return s


def invites(s, cid):
    """INVITEs of this call at a server: one per branch (retransmissions share the Via)."""
    return len({m.all("via")[0] for m in s.received if m.method == "INVITE" and m.get("call-id") == cid})


def wait_for(pred, timeout):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.2)
    return pred()


def run(sc):
    sip, http = sc.port(), sc.port()
    mode = {}
    srv = [server(sc, sip, f"as{i}", mode) for i in (1, 2, 3)]
    uri = [f"sip:127.0.0.1:{s.port}" for s in srv]
    # as3 is dead from the start: no answer to probes or calls.
    mode["as3"] = {"options": False, "invite": "silent"}
    lst = os.path.join(sc.tmp, "dispatcher.list")
    with open(lst, "w") as f:
        f.write("# set 1: the application servers\n" + "".join(f"1 {u}\n" for u in uri))
    px = sc.proxy(env=sc.env(SIP_PORT=sip, HTTP_PORT=http, DS_LIST=lst))
    ua = sc.ua("alice", sip)

    def state(u):
        st, body = sipkit.http_get(f"http://127.0.0.1:{http}/balancer?{u}")
        return body if st == 200 else f"HTTP {st}: {body}"

    def flags(u):
        lst = px.rpc("dispatcher.list")
        try:
            return next(t["FLAGS"] for s in lst["RECORDS"] for t in s["TARGETS"] if t["URI"] == u)
        except (TypeError, KeyError, StopIteration):
            return None

    # Probing finds the dead server; on balancer.down records it.
    got = wait_for(lambda: state(uri[2]).startswith("down"), 10)
    sc.check("probes find the dead server: on balancer.down → shared table (GET /balancer)", got, state(uri[2]))
    sc.check("…its state is inactive in dispatcher.list", (flags(uri[2]) or "").startswith("I"), px.rpc("dispatcher.list"))
    sc.check("…a Counter that was never incremented reads 0 in a string (docs/fsr.md: t.get gives 0 when missing)",
             "down=0 up=0" in state(uri[0]), state(uri[0]))
    sc.check("…the live servers raised no down event", all(re.search(r"down=0?( |$)", state(u)) for u in uri[:2]),
             (state(uri[0]), state(uri[1])))
    sc.check("…and the live servers are active", (flags(uri[0]) or "").startswith("A") and (flags(uri[1]) or "").startswith("A"),
             (flags(uri[0]), flags(uri[1])))
    st, body = sipkit.http_get(f"http://127.0.0.1:{http}/other")
    sc.check("an HTTP path no handler matches → 404", st == 404, (st, body))

    def call(ruri="sip:app@example.com", timeout=8):
        r, d = ua.call(ruri, timeout=timeout)
        cid = d.call_id if d else (r.get("call-id") if r is not None else None)
        if d:
            rep = d.bye()
            if rep is None or rep.code != 200:
                sc.check(f"BYE of call {cid} follows its route set: 200", False, rep)
        return r, cid

    # Round robin over the two live servers, the dead one skipped.
    counts = [0, 0, 0]
    codes = []
    for _i in range(6):
        r, cid = call()
        codes.append(r.code if r is not None else None)
        for k in range(3):
            counts[k] += invites(srv[k], cid)
    sc.check("6 calls answered 200", codes == [200] * 6, codes)
    # Kamailio's round robin gives the dead server's turn to the next active
    # one, so the split need not be even: 4/2 is as right as 3/3.
    sc.check("round robin: both live servers get calls, the dead one none", counts[2] == 0 and min(counts[:2]) >= 2, counts)

    # Failover on a 5xx: whichever server gets the call first refuses it,
    # the other one answers.
    mode["fail_next"] = True
    r, cid = call()
    tried = [invites(s, cid) for s in srv]
    sc.check("a 503 from the chosen server → failover to the other one: 200", r is not None and r.code == 200, r)
    sc.check("…one INVITE each on the live servers, none on the dead one", tried == [1, 1, 0], tried)
    second = [m for s in srv[:2] for m in s.received if m.method == "INVITE" and m.get("call-id") == cid]
    sc.check("…both INVITEs (the failover branch too) carry the Record-Route added before the await",
             len(second) == 2 and all(m.all("record-route") for m in second), [m.all("record-route") for m in second])
    sc.check("…and a 503 does not mark the server down", (flags(uri[0]) or "").startswith("A") and (flags(uri[1]) or "").startswith("A"),
             (flags(uri[0]), flags(uri[1])))

    # Both live servers refuse: the dead one is not tried, the caller gets 503.
    mode["as1"]["invite"] = mode["as2"]["invite"] = "503"
    r, cid = call()
    tried = [invites(s, cid) for s in srv]
    sc.check("both live servers 503 → 503 All servers failed", r is not None and r.code == 503 and r.reason == "All servers failed", r)
    sc.check("…each live server tried once, the dead one never", tried == [1, 1, 0], tried)
    mode["as1"]["invite"] = mode["as2"]["invite"] = "200"

    # A server that answers probes but not calls: the call times out there
    # (fr_timer 1s), it is marked inactive (on balancer.down) and the call
    # goes on to the other server; the probes then bring it back (up).
    mode["as2"]["invite"] = "silent"
    t0 = time.time()
    r, cid = None, None
    for _ in range(4):        # the round-robin pointer may first pick as1 (twice)
        r, cid = call()
        if invites(srv[1], cid):
            break
    took = time.time() - t0
    mode["as2"]["invite"] = "200"
    tried = [invites(s, cid) for s in srv]
    sc.check("a server that never answers the INVITE → timeout → the other server: 200",
             r is not None and r.code == 200 and tried == [1, 1, 0], (r, tried))
    sc.check("…after about fr_timer, well before fr_inv_timer", took < 10, took)
    got = wait_for(lambda: "down=1" in state(uri[1]), 5)
    sc.check("…balancer.mark(\"ip\") fires on balancer.down for it", got, state(uri[1]))
    got = wait_for(lambda: state(uri[1]).startswith("up") and "up=1" in state(uri[1]), 8)
    sc.check("…and probing brings it back: on balancer.up", got, state(uri[1]))

    # The dead server comes back: probes see it, on balancer.up fires, and
    # it gets calls again.
    mode["as3"] = {"options": True, "invite": "200"}
    got = wait_for(lambda: state(uri[2]).startswith("up"), 10)
    sc.check("a revived server: on balancer.up recorded", got, state(uri[2]))
    sc.check("…active again in dispatcher.list", (flags(uri[2]) or "").startswith("A"), flags(uri[2]))
    sc.check("…one down and one up event in all for it", "down=1" in state(uri[2]) and "up=1" in state(uri[2]), state(uri[2]))
    counts = [0, 0, 0]
    for _i in range(6):
        r, cid = call()
        for k in range(3):
            counts[k] += invites(srv[k], cid)
    sc.check("round robin over all three again: 2 calls each", counts == [2, 2, 2], counts)

    # Every server down: no destination at all.
    for k in ("as1", "as2", "as3"):
        mode[k] = {"options": False, "invite": "silent"}
    got = wait_for(lambda: all(state(u).startswith("down") for u in uri), 10)
    sc.check("all servers stop answering probes: all reported down", got, [state(u) for u in uri])
    r, cid = call()
    sc.check("…a call then gets 503 No server available at once", r is not None and r.code == 503 and r.reason == "No server available", r)
    sc.check("…and no server saw it", [invites(s, cid) for s in srv] == [0, 0, 0], [invites(s, cid) for s in srv])

    # Requests other than INVITE are refused (the pool only takes calls).
    o = ua.request("MESSAGE", "sip:app@example.com", body="hi", content_type="text/plain")
    r = ua.final(call_id=o["call_id"])
    sc.check("a MESSAGE → 405", r is not None and r.code == 405, r)
