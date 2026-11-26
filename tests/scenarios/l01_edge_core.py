"""l01-edge-core: phones → edge (flood ban, Path, Record-Route) → core
(auth, registrar) and back through the edge."""


def run(sc):
    edge_port, core_port = sc.port(), sc.port()
    sc.proxy("core", sc.env(CORE_PORT=core_port), name="core")
    sc.proxy("edge", sc.env(EDGE_PORT=edge_port, CORE=f"sip:127.0.0.1:{core_port}"), name="edge")
    alice = sc.ua("alice", edge_port, password="secret-a")
    bob = sc.ua("bob", edge_port, password="secret-b")
    bob.auto_answer(ring=True)

    # Registration: challenged by the core, through the edge (with Path).
    r = alice.register()
    sc.check("alice registers through the edge (401, then 200)", r is not None and r.code == 200, r)
    r = bob.register()
    sc.check("bob registers", r is not None and r.code == 200, r)
    sc.check("the 200 lists bob's contact", r is not None and "bob@127.0.0.1" in (r.get("contact") or ""), r and r.raw)
    nobody = sc.ua("mallory", edge_port, password="wrong")
    r = nobody.register()
    sc.check("an unknown user is refused after the challenge", r is not None and r.code in (401, 403), r)

    # A call alice → bob: edge → core → edge → bob, both proxies in the route set.
    r, d = alice.call("sip:bob@example.com", timeout=6)
    sc.check("alice calls bob: 200 (auth answered on the way)", r is not None and r.code == 200 and d is not None, r)
    inv = next((m for m in bob.received if m.method == "INVITE"), None)
    sc.check("bob's INVITE came through the edge (twice) and the core: 3 Record-Routes",
             inv is not None and len(inv.all("record-route")) == 3, inv and inv.all("record-route"))
    sc.check("bob's INVITE carries no credentials (consumed by the core)",
             inv is not None and inv.get("proxy-authorization") is None, inv and inv.raw)
    if d:
        # BYE from bob back to alice: the reverse of the route set.
        alice.auto_answer()
        rr = list(inv.all("record-route"))
        b = bob.request("BYE", f"sip:alice@127.0.0.1:{alice.port}", to=inv.get("from"), call_id=inv.get("call-id"),
                        from_tag=bob.tags.get((inv.get("call-id"), inv.tag("from"))), cseq=1,
                        headers={"Route": ", ".join(rr)}, from_uri="sip:bob@example.com")
        rep = bob.final(call_id=b["call_id"], method="BYE")
        sc.check("bob's BYE reaches alice through edge, core, edge; 200 back", rep is not None and rep.code == 200, rep)
        sc.check("alice saw the BYE", any(m.method == "BYE" for m in alice.received))

    # Unknown callee: the core's 404.
    r, _ = alice.call("sip:carol@example.com")
    sc.check("a call to an unregistered user → 404 Not registered", r is not None and r.code == 404, r)

    # Without credentials the core challenges (407 for an INVITE).
    anon = sc.ua("alice", edge_port)  # no password: doesn't answer the challenge
    r, _ = anon.call("sip:bob@example.com", auth=False)
    sc.check("an INVITE without credentials → 407 from the core", r is not None and r.code == 407, r)

    # Keepalives answered at the edge.
    o = alice.request("OPTIONS", f"sip:127.0.0.1:{edge_port}")
    r = alice.final(call_id=o["call_id"])
    sc.check("OPTIONS to the edge → 200 at the edge", r is not None and r.code == 200, r)

    # Flood: one source sending 40 requests in a burst is banned; others aren't.
    flooder = sc.ua("flood", edge_port)
    answered = 0
    for _i in range(40):
        o = flooder.request("OPTIONS", f"sip:127.0.0.1:{edge_port}")
        if flooder.final(0.3, call_id=o["call_id"]) is not None:
            answered += 1
    sc.check("a burst of 40 from one source: answered until the limit (20), then dropped",
             15 <= answered <= 22, answered)
    o = flooder.request("OPTIONS", f"sip:127.0.0.1:{edge_port}")
    sc.check("…and the source stays banned", flooder.final(0.5, call_id=o["call_id"]) is None)
    o = alice.request("OPTIONS", f"sip:127.0.0.1:{edge_port}")
    sc.check("…while other sources are still served", alice.final(call_id=o["call_id"]) is not None)
