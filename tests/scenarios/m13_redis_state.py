"""m13-redis-state: two proxies share a block list and a call counter in
Redis (ndb_redis). Writes on one are enforced by the other; keys expire;
Redis stopped (reads fail open, writes fail closed) and restarted."""
import signal, time

import sipkit


def wait_for(pred, timeout):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.1)
    return pred()


def message(ua, ruri, headers, timeout=6):
    """Send a MESSAGE; its final reply (matched by Call-ID and CSeq) and the
    time it took (a local helper: sipkit has no one-shot request)."""
    t0 = time.time()
    s = ua.request("MESSAGE", ruri, headers=headers, body="", content_type="text/plain")
    r = ua.final(timeout, method="MESSAGE", call_id=s["call_id"], cseq=s["cseq"])
    return r, time.time() - t0


def call(ua, who, timeout=6):
    """INVITE sip:who@example.com; the final reply, and BYE when answered."""
    r, d = ua.call(f"sip:{who}@example.com", timeout=timeout)
    if d:
        d.bye()
    return r


def code(r):
    return r.code if r is not None else None


def invites_to(pbx, cid):
    return [m for m in pbx.received if m.method == "INVITE" and m.get("call-id") == cid]


def run(sc):
    if not sipkit.Redis.available():
        sc.skip("redis-server not installed")
    rport = sc.port()
    redis = sipkit.Redis(rport, sc.tmp).start()
    sc.closers.append(redis.stop)
    sc.check("redis-server started", redis.cmd("PING") == "PONG", redis.cmd("PING"))

    pbx = sc.ua("pbx", sc.port()).auto_answer()
    pa, pb = sc.port(), sc.port()
    env = dict(CALLEE=f"sip:127.0.0.1:{pbx.port}", REDIS_PORT=rport)
    a = sc.proxy("proxy-a", sc.env(SIP_PORT=pa, **env), name="proxy-a")
    sc.proxy("proxy-b", sc.env(SIP_PORT=pb, **env), name="proxy-b")
    alice_a = sc.ua("alice", pa)
    alice_b = sc.ua("alice", pb)
    carol_a, carol_b = sc.ua("carol", pa), sc.ua("carol", pb)

    # --- A block written through A, enforced by B, with an expiry.
    r, _ = message(alice_a, "sip:block@example.com", {"X-Block-User": "carol", "Expires": "3"})
    sc.check("alice blocks carol via A for 3s: 200 Blocked", code(r) == 200, r)
    ttl = redis.cmd("TTL", "block:alice:carol")
    sc.check("…the key block:alice:carol is in Redis with an expiry of 1..3s", ttl.isdigit() and 1 <= int(ttl) <= 3, ttl)
    r = call(carol_b, "alice")
    sc.check("carol calls alice via B: 603 (B enforces the block A wrote)", code(r) == 603, r)
    sc.check("…and the PBX never got that INVITE", r is not None and not invites_to(pbx, r.get("call-id")), r)
    r = call(carol_a, "alice")
    sc.check("carol calls alice via A: 603 as well", code(r) == 603, r)
    r = call(carol_b, "bob")
    sc.check("carol calls bob via B: 200 (the block is alice's only)", code(r) == 200, r)
    r = call(alice_b, "carol")
    sc.check("alice calls carol via B: 200 (a block is one way)", code(r) == 200, r)
    gone = wait_for(lambda: redis.cmd("EXISTS", "block:alice:carol") == "0", 8)
    sc.check("…Redis expires the block after 3s", gone, redis.cmd("TTL", "block:alice:carol"))
    r = call(carol_b, "alice")
    sc.check("after the block expired carol reaches alice via B: 200", code(r) == 200, r)

    # --- Bad input is refused before anything reaches Redis.
    for hs, what in (({"X-Block-User": "carol", "Expires": "0"}, "Expires 0"),
                     ({"X-Block-User": "carol", "Expires": "soon"}, "Expires not a number"),
                     ({"X-Block-User": "carol x"}, "a space in X-Block-User (would split the Redis command)"),
                     ({"Expires": "5"}, "no X-Block-User")):
        r, _ = message(alice_a, "sip:block@example.com", hs)
        sc.check(f"block with {what}: 400", code(r) == 400, r)
    sc.check("…none of them wrote a key", redis.cmd("KEYS", "block:*") == "", redis.cmd("KEYS", "block:*"))

    # --- The default expiry, and an unblock through the other proxy.
    r, _ = message(alice_a, "sip:block@example.com", {"X-Block-User": "dave"})
    sc.check("alice blocks dave via A without Expires: 200", code(r) == 200, r)
    ttl = redis.cmd("TTL", "block:alice:dave")
    sc.check("…with the default expiry (block_ttl 600s)", ttl.isdigit() and 590 <= int(ttl) <= 600, ttl)
    dave_a = sc.ua("dave", pa)
    sc.check("dave calls alice via A: 603", code(call(dave_a, "alice")) == 603)
    r, _ = message(alice_b, "sip:unblock@example.com", {"X-Block-User": "dave"})
    sc.check("alice unblocks dave via B: 200 Unblocked", code(r) == 200, r)
    sc.check("…the key is gone", redis.cmd("EXISTS", "block:alice:dave") == "0", redis.cmd("TTL", "block:alice:dave"))
    r = call(dave_a, "alice")
    sc.check("dave calls alice via A after the unblock on B: 200", code(r) == 200, r)

    # --- A call counter shared by both proxies (limit 3 per 30s window).
    eve_a, eve_b = sc.ua("eve", pa), sc.ua("eve", pb)
    codes = [code(call(u, f"x{i}")) for i, u in enumerate((eve_a, eve_b, eve_a))]
    sc.check("eve's calls 1..3, alternating A, B, A: all 200", codes == [200, 200, 200], codes)
    r = call(eve_b, "x4")
    sc.check("eve's 4th call (via B): 403 Call limit reached", code(r) == 403, r)
    sc.check("…not relayed to the PBX", r is not None and not invites_to(pbx, r.get("call-id")), r)
    sc.check("…the counter calls:eve is 4", redis.cmd("GET", "calls:eve") == "4", redis.cmd("GET", "calls:eve"))
    ttl = redis.cmd("TTL", "calls:eve")
    sc.check("…and expires with the window (0 < TTL ≤ 30)", ttl.lstrip("-").isdigit() and 0 < int(ttl) <= 30, ttl)

    # --- Redis stopped: reads fail open, writes fail closed, nothing hangs.
    r, _ = message(alice_a, "sip:block@example.com", {"X-Block-User": "frank", "Expires": "60"})
    sc.check("alice blocks frank (Redis up): 200", code(r) == 200, r)
    redis.stop()
    t0 = time.time()
    r, took = message(alice_a, "sip:block@example.com", {"X-Block-User": "carol"})
    sc.check("Redis down: a block request gets 503 (writes fail closed)", code(r) == 503, r)
    sc.check("…quickly (< 4s: no hang on a refused connection)", took < 4, took)
    frank_b = sc.ua("frank", pb)
    t0 = time.time()
    r = call(frank_b, "alice", timeout=8)
    sc.check("Redis down: frank's call to alice via B goes through, 200 (reads fail open, the block isn't seen)",
             code(r) == 200, r)
    sc.check("…within 5s", time.time() - t0 < 5, time.time() - t0)
    r = call(eve_b, "x5", timeout=8)
    sc.check("Redis down: eve, over her limit, is let through as well (200)", code(r) == 200, r)
    r = call(carol_a, "bob", timeout=8)
    sc.check("…and proxy A answers too (200)", code(r) == 200, r)
    sc.check("…the proxy logs that the block list wasn't checked",
             wait_for(lambda: any("redis down" in l for l in list(a.lines)), 3), "".join(a.lines[-5:]))

    # --- Redis restarted (empty: no persistence): both proxies reconnect.
    redis.start()
    sc.check("redis-server restarted", redis.cmd("PING") == "PONG")
    r, _ = message(alice_a, "sip:block@example.com", {"X-Block-User": "carol", "Expires": "60"})
    sc.check("after the restart alice blocks carol via A again: 200 (A reconnected)", code(r) == 200, r)
    r = call(carol_b, "alice")
    sc.check("…and B enforces it: 603 (B reconnected)", code(r) == 603, r)
    r = call(frank_b, "alice")
    sc.check("frank's block was lost with Redis' data (no persistence): 200", code(r) == 200, r)
    r = call(eve_a, "x6")
    sc.check("eve's counter starts again from 0: 200", code(r) == 200 and redis.cmd("GET", "calls:eve") == "1",
             (r, redis.cmd("GET", "calls:eve")))

    # --- Redis frozen (SIGSTOP: connections are accepted, nothing answers).
    # Each command waits for the 3s read timeout, is retried once on a new
    # connection (whose SELECT times out too), and the call fails open.
    redis.proc.send_signal(signal.SIGSTOP)
    gina_b = sc.ua("gina", pb)
    t0 = time.time()
    try:
        r = call(gina_b, "alice", timeout=25)
        took = time.time() - t0
    finally:
        redis.proc.send_signal(signal.SIGCONT)
    sc.check("Redis frozen: gina's call is still answered, 200 (fail open after the read timeouts)", code(r) == 200, r)
    sc.check(f"…within 5s (took {took:.1f}s: cmd_timeout 1s per command, no retry of a timed-out one)", took < 5, took)
    r, _ = message(alice_a, "sip:block@example.com", {"X-Block-User": "gina", "Expires": "60"})
    sc.check("Redis resumed: alice blocks gina via A: 200", code(r) == 200, r)
    sc.check("…gina → alice via B: 603 (replies not out of step after the timeouts)", code(call(gina_b, "alice")) == 603)
    sc.check("…gina → bob via B: 200", code(call(gina_b, "bob")) == 200)
