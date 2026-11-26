"""l05-lb-cluster: a ferrosip load balancer (balancer, probing) in front of
three ferrosip application proxies relaying to a UAS. One app proxy is
killed mid-test and later restarted."""
import os, socket, time

import sipkit


def wait_for(cond, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(0.1)
    return cond()


def release(ua):
    """Close a UA's UDP socket for good: its reader thread sits in recvfrom,
    which keeps the port bound until a datagram wakes it."""
    port = ua.port
    ua.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"\r\n", ("127.0.0.1", port))
    s.close()
    time.sleep(0.2)


def states(lb):
    """{uri: FLAGS} from the balancer's dispatcher.list RPC (local helper;
    the shape is searched loosely: any dict with URI and FLAGS)."""
    out = {}

    def walk(x):
        if isinstance(x, dict):
            u = x.get("URI") or x.get("uri")
            f = x.get("FLAGS") or x.get("flags")
            if u and f is not None:
                out[u] = f
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(lb.rpc("dispatcher.list"))
    return out


def run(sc):
    lb_port = sc.port()
    app_ports = [sc.port() for _ in range(3)]
    uas = sc.ua("uas", lb_port).auto_answer()
    uris = [f"sip:127.0.0.1:{p}" for p in app_ports]
    lst = os.path.join(sc.tmp, "dispatcher.list")
    with open(lst, "w") as f:
        f.write("".join(f"1 {u}\n" for u in uris))
    apps = [sc.proxy("app", sc.env(APP_PORT=p, APP_NAME=f"app{i}", UAS=f"sip:127.0.0.1:{uas.port}"), name=f"app{i}")
            for i, p in enumerate(app_ports, 1)]
    lb = sc.proxy("lb", sc.env(LB_PORT=lb_port, DISPATCHER_LIST=lst), name="lb")
    ua = sc.ua("alice", lb_port)

    ok = wait_for(lambda: all(states(lb).get(u, "").startswith("A") for u in uris))
    sc.check("the balancer lists the three app proxies as active", ok, states(lb))

    def calls(n, hangup=True):
        """n calls; [(code, app that relayed it, call-id, dialog)]."""
        out = []
        for _ in range(n):
            r, d = ua.call("sip:service@example.com", timeout=8)
            cid = d.call_id if d else (r.get("call-id") if r is not None else None)
            inv = next((m for m in uas.received if m.method == "INVITE" and m.get("call-id") == cid), None)
            out.append((r.code if r is not None else None, inv and inv.get("x-app"), cid, d))
            if d and hangup:
                d.bye()
        return out

    res = calls(6)
    sc.check("6 calls through the balancer: all 200", all(c == 200 for c, *_ in res), res)
    sc.check("…spread round robin: each app proxy took 2", sorted(a for _, a, *_ in res) == ["app1", "app1", "app2", "app2", "app3", "app3"],
             [a for _, a, *_ in res])

    # Keep a call up through app2, then kill app2.
    held = None
    for _ in range(3):
        (code, app, cid, d), = calls(1, hangup=False)
        if app == "app2":
            held = d
            break
        if d:
            d.bye()
    sc.check("a call is held through app2", held is not None)
    apps[1].kill()
    # Something sits on app2's address now but never answers: it shows what
    # the balancer still sends there (a local stand-in, not a kit feature).
    hole = sipkit.UA("hole", app_ports[1], ("127.0.0.1", lb_port))
    sc.closers.append(hole.close)

    def invites_to_hole(cid=None):
        """INVITEs sent to app2's address, one per branch (UDP retransmissions share it)."""
        return list({m.all("via")[0] for m in hole.received if m.method == "INVITE" and (cid is None or m.get("call-id") == cid)})

    # Until probing notices, a call may go to app2: it must fail over.
    res = calls(3)
    sc.check("right after the kill, 3 calls all get 200 (a call sent to app2 fails over after fr_timer)",
             all(c == 200 for c, *_ in res) and all(a in ("app1", "app3") for _, a, *_ in res), res)
    tried = sum(len(invites_to_hole(cid)) for _, _, cid, _ in res)
    sc.check("…at most one of them was tried on app2 first (round robin)", tried <= 1, tried)

    # The held call's BYE follows the route set to the dead app2: no failover.
    if held:
        rep = held.bye(timeout=6)
        sc.check("the call held through app2 can't be hung up through it: the BYE fails (408), it isn't rerouted",
                 rep is not None and rep.code == 408, rep)
        sc.check("…the BYE was sent to app2's address", any(m.method == "BYE" for m in hole.received))

    ok = wait_for(lambda: states(lb).get(uris[1], "").startswith("I"))
    sc.check("probing marks app2 inactive", ok, states(lb))
    sc.check("…and on balancer.down logs it", wait_for(lambda: any(f"app server {uris[1]} is down" in l for l in lb.lines), 3), "")
    before = len(invites_to_hole())
    res = calls(4)
    # (Round robin skips an inactive destination to the next active one, as
    # Kamailio's does: app3 may get two in a row.)
    sc.check("with app2 down, 4 calls go to app1 and app3 only", all(c == 200 for c, *_ in res)
             and {a for _, a, *_ in res} == {"app1", "app3"}, [(c, a) for c, a, *_ in res])
    sc.check("…and none is sent to app2", len(invites_to_hole()) == before, len(invites_to_hole()) - before)

    # Restart app2: probing brings it back.
    release(hole)
    apps[1].start()
    ok = wait_for(lambda: states(lb).get(uris[1], "").startswith("A"))
    sc.check("after app2 restarts, probing marks it active again", ok, states(lb))
    sc.check("…and on balancer.up logs it", wait_for(lambda: any(f"app server {uris[1]} is up" in l for l in lb.lines), 3), "")
    res = calls(6)
    sc.check("6 more calls: all 200, and app2 takes its share again", all(c == 200 for c, *_ in res)
             and sum(1 for _, a, *_ in res if a == "app2") == 2, [a for _, a, *_ in res])

    # Every app down: 503 from the balancer.
    for a in apps:
        a.kill()
    ok = wait_for(lambda: all(states(lb).get(u, "").startswith("I") for u in uris))
    sc.check("all app proxies killed: probing marks all three inactive", ok, states(lb))
    r, _ = ua.call("sip:service@example.com", timeout=8)
    sc.check("…and a call gets 503 No app server at once", r is not None and r.code == 503 and r.reason == "No app server", r)
