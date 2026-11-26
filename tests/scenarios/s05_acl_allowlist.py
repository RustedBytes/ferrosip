"""s05-acl-allowlist: only trunk addresses may send (a [feature] IP list and
the acl address table by ip:port); the rest gets 403."""
import os
import time

HEADER = "grp(int) ip_addr(string) mask(int) port(int) tag(string,null)\n"


def start(sc, name, **env):
    """Start a proxy; a startup failure is a failed check (and the proxy is
    dropped from sc.proxies: the runner can't stop one that never started)."""
    p = sc.proxy(env=sc.env(**env), name=name, start=False)
    try:
        return p.start()
    except RuntimeError as e:
        sc.proxies.remove(p)
        sc.check(f"{name}: starts", False, e)
        return None


def got(up, cid, method=None):
    return [m for m in up.received if m.get("call-id") == cid and (method is None or m.method == method)]


def run(sc):
    sip, sip_b = sc.port(), sc.port()
    pbx = sc.ua("pbx", sip).auto_answer()
    trunk = sc.ua("trunk-a", sip)
    stranger = sc.ua("stranger", sip)
    monitor = sc.ua("monitor", sip)
    # The address table, written into the scenario's temp dir: every UA is
    # 127.0.0.1, so the rules tell them apart by port.
    db = os.path.join(sc.tmp, "db")
    os.makedirs(db)
    table = os.path.join(db, "address")
    with open(os.path.join(db, "trusted"), "w") as f:  # unused, but the acl module loads it with the address table
        f.write("src_ip(string) proto(string) from_pattern(string,null) ruri_pattern(string,null) tag(string,null) priority(int)\n")
    with open(table, "w") as f:
        f.write(HEADER + f"1:127.0.0.1:32:{trunk.port}:trunk-a\n2:127.0.0.1:32:{monitor.port}:monitoring\n")
    px = start(sc, "acl", SIP_PORT=sip, PBX=f"sip:127.0.0.1:{pbx.port}", TRUNK_A="127.0.0.1", ACL_DB=db)
    if px is None:
        return

    dump = px.rpc("permissions.addressDump")
    sc.check("permissions.addressDump shows the 2 rows of the table", isinstance(dump, list) and len(dump) == 2, dump)

    # The trunk (group 1, its exact port): calls go to the PBX.
    r, d = trunk.call("sip:+4930123@pbx.example.com")
    sc.check("trunk (127.0.0.1, its port in group 1) calls → 200 from the PBX", r is not None and r.code == 200 and d is not None, r)
    if d:
        sc.check("…the INVITE reached the PBX once", len({m.all("via")[0] for m in got(pbx, d.call_id, "INVITE")}) == 1)
        rep = d.bye()
        sc.check("…and its BYE goes through too", rep is not None and rep.code == 200, rep)

    # Same IP, a port the table doesn't list: 403 from the acl layer.
    r = stranger.request("OPTIONS", "sip:+4930123@pbx.example.com")
    rep = stranger.final(call_id=r["call_id"])
    sc.check("same IP, a port not in the table → 403 Not a trunk", rep is not None and rep.code == 403 and rep.reason == "Not a trunk", rep)
    sc.check("…and nothing reaches the PBX", not got(pbx, r["call_id"]))
    sent = stranger.invite("sip:+4930123@pbx.example.com")
    rep = stranger.final(method="INVITE", call_id=sent["call_id"])
    sc.check("an INVITE from it → 403 too", rep is not None and rep.code == 403, rep)
    if rep is not None:
        stranger._ack_neg(sent, rep)

    # Group 2 is in the table, but only group 1 may send.
    r = monitor.request("OPTIONS", "sip:+4930123@pbx.example.com")
    rep = monitor.final(call_id=r["call_id"])
    sc.check("an address in group 2 (not 1) → 403 Not a trunk", rep is not None and rep.code == 403, rep)

    # An ACK from a stranger: refused, but an ACK is never answered (RFC 3261 §17).
    a = stranger.request("ACK", "sip:+4930123@pbx.example.com", to="<sip:+4930123@pbx.example.com>;tag=x1")
    rep = stranger.recv(1.0, lambda m: m.is_reply and m.get("call-id") == a["call_id"])
    sc.check("an ACK from a non-trunk is dropped without a reply", rep is None, rep)
    sc.check("…and not relayed", not got(pbx, a["call_id"]))

    # The table changes at run time: add the stranger's port, reload.
    with open(table, "a") as f:
        f.write(f"1:127.0.0.1:32:{stranger.port}:trunk-b\n")
    n = px.rpc("permissions.addressReload")
    sc.check("permissions.addressReload after adding a row → 3", n == 3, n)
    r = stranger.request("OPTIONS", "sip:+4930123@pbx.example.com")
    rep = stranger.final(call_id=r["call_id"])
    sc.check("…the newly added trunk is now relayed (200 from the PBX)", rep is not None and rep.code == 200 and len(got(pbx, r["call_id"])) >= 1, rep)

    # A broken table on reload: the running rules must stay (not go empty and allow or refuse everything).
    with open(table, "w") as f:
        f.write("this is not a db_text table\n")
    n = px.rpc("permissions.addressReload")
    r = trunk.request("OPTIONS", "sip:+4930123@pbx.example.com")
    rep = trunk.final(call_id=r["call_id"])
    sc.check("a reload of a broken table fails and keeps the old rules: the trunk is still relayed",
             rep is not None and rep.code == 200, (n, rep))
    r = monitor.request("OPTIONS", "sip:+4930123@pbx.example.com")
    rep = monitor.final(call_id=r["call_id"])
    sc.check("…and group 2 is still refused", rep is not None and rep.code == 403, (n, rep))

    # Second run: 127.0.0.1 isn't one of the trunk IPs. Even the trunk's port is refused, by the first layer.
    with open(table, "w") as f:
        f.write(HEADER + f"1:127.0.0.1:32:{trunk.port}:trunk-a\n")
    px2 = start(sc, "acl-other-ip", SIP_PORT=sip_b, PBX=f"sip:127.0.0.1:{pbx.port}", TRUNK_A="198.51.100.7", ACL_DB=db)
    if px2 is None:
        return
    t2 = sc.ua("trunk-a", sip_b)
    with open(table, "w") as f:  # t2 has its own port: list it, so only the IP layer can refuse it
        f.write(HEADER + f"1:127.0.0.1:32:{t2.port}:trunk-a\n")
    px2.rpc("permissions.addressReload")
    r = t2.request("OPTIONS", "sip:+4930123@pbx.example.com")
    rep = t2.final(call_id=r["call_id"])
    sc.check("127.0.0.1 not among the trunk IPs → 403 Not a trunk IP (even with its port in the table)",
             rep is not None and rep.code == 403 and rep.reason == "Not a trunk IP", rep)
    time.sleep(0.2)
    sc.check("…and nothing reaches the PBX", not got(pbx, r["call_id"]))
