"""m04-pstn-trunk: number normalisation to E.164, prefix routing to two
trunks, emergency calls, 484 for invalid numbers, a source ACL for the
trunks, and P-Asserted-Identity / Privacy (RFC 3325)."""
import socket
import threading
import time

import sipkit


def ua_at(sc, ip, user, proxy_port, **kw):
    """A UDP UA bound to another loopback address (127.0.0.2 …), so the
    proxy can tell trunks from phones by source IP. (Kit helper: sipkit's
    UA always binds 127.0.0.1.)"""
    u = sc.ua(user, proxy_port, **kw)
    old = u.t.s
    try:
        old.shutdown(socket.SHUT_RDWR)   # ends the 127.0.0.1 reader thread
    except OSError:
        pass
    time.sleep(0.05)
    old.close()
    time.sleep(0.05)
    u.received.clear()                   # the empty read that ended it
    while not u.q.empty():
        u.q.get_nowait()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, u.port))
    u.t.s = s
    threading.Thread(target=u._reader, daemon=True).start()
    u.__class__ = type("UAAt", (sipkit.UA,), {
        "contact": property(lambda self: f"sip:{self.user}@{ip}:{self.port}"),
        "via": lambda self, b: f"SIP/2.0/UDP {ip}:{self.port};branch=z9hG4bK{b};rport",
    })
    return u


def run(sc):
    sip = sc.port()
    de = ua_at(sc, "127.0.0.2", "trunk-de", sip).auto_answer()
    intl = ua_at(sc, "127.0.0.3", "trunk-intl", sip).auto_answer()
    sos = sc.ua("sos", sip).auto_answer()
    pbx = sc.ua("pbx", sip).auto_answer()
    sc.proxy(env=sc.env(SIP_PORT=sip, TRUNK_DE=f"sip:127.0.0.2:{de.port}", TRUNK_INTL=f"sip:127.0.0.3:{intl.port}",
                        EMERGENCY=f"sip:127.0.0.1:{sos.port}", PBX=f"sip:127.0.0.1:{pbx.port}"))
    alice = sc.ua("alice", sip, password="secret-a")
    peers = {"de": de, "intl": intl, "sos": sos, "pbx": pbx}

    def got(cid):
        """{peer: [INVITEs of this call]} (one per branch)."""
        out = {}
        for n, u in peers.items():
            ms = {m.all("via")[0]: m for m in u.received if m.method == "INVITE" and m.get("call-id") == cid}
            if ms:
                out[n] = list(ms.values())
        return out

    def dial(number, ua=alice, headers=None, auth=True):
        r, d = ua.call(f"sip:{number}@example.com", headers=headers, auth=auth)
        cid = d.call_id if d else (r.get("call-id") if r else None)
        g = got(cid)
        if d:
            d.bye()
        return r, g

    def routed(number, where, user, **kw):
        r, g = dial(number, **kw)
        inv = g.get(where, [None])[0]
        ok = r is not None and r.code == 200 and list(g) == [where] and len(g[where]) == 1 and inv.ruri == f"sip:{user}@example.com"
        sc.check(f"dialled {number!r} → {where} as {user}", ok, (r, {k: [m.ruri for m in v] for k, v in g.items()}))
        return inv

    # --- normalisation and prefix routing
    routed("+4930123456", "de", "+4930123456")
    routed("030123456", "de", "+4930123456")                 # national
    routed("0049301234567", "de", "+49301234567")            # international form of a domestic number
    routed("00442071234567", "intl", "+442071234567")        # international
    routed("+12125551234", "intl", "+12125551234")
    routed("030-1234-567", "de", "+49301234567")             # visual separators
    routed("116117", "de", "116117")                         # harmonised EU short code, kept as dialled
    routed("118", "de", "118")

    # --- emergency
    routed("112", "sos", "112")
    routed("110", "sos", "110")
    anon = sc.ua("stranger", sip)  # no credentials at all
    r, g = dial("112", ua=anon, auth=False, headers={"P-Asserted-Identity": "<sip:+4930999@example.com>"})
    sc.check("112 without credentials still reaches the emergency gateway (no 407)", r is not None and r.code == 200 and list(g) == ["sos"], (r, list(g)))
    inv = g.get("sos", [None])[0]
    sc.check("…with the caller's own unverified P-Asserted-Identity removed", inv is not None and inv.get("p-asserted-identity") is None, inv and inv.raw)
    r, g = dial("+4930123456", ua=anon, auth=False)
    sc.check("a non-emergency call without credentials → 407, not relayed", r is not None and r.code == 407 and not g, (r, list(g)))

    # --- invalid numbers: 484, nothing relayed
    for bad in ["0", "00", "+49", "+4930abc12", "abc", "999", "4930123456", "0049", "+1234567890123456"]:
        r, g = dial(bad)
        sc.check(f"invalid number {bad!r} → 484, not relayed", r is not None and r.code == 484 and not g, (r, list(g)))

    # --- P-Asserted-Identity and Privacy
    inv = routed("+4930123456", "de", "+4930123456", headers={"P-Asserted-Identity": "<sip:+4930999@example.com>"})
    sc.check("to the trusted trunk: exactly one P-Asserted-Identity, alice's (the caller's own replaced)",
             inv is not None and inv.all("p-asserted-identity") == ["<sip:alice@example.com>"], inv and inv.all("p-asserted-identity"))
    sc.check("…and the credentials are not passed to the carrier", inv is not None and inv.get("proxy-authorization") is None)
    inv = routed("+12125551234", "intl", "+12125551234")
    sc.check("to the untrusted trunk without Privacy: PAI is added", inv is not None and inv.all("p-asserted-identity") == ["<sip:alice@example.com>"],
             inv and inv.all("p-asserted-identity"))
    inv = routed("+4930123456", "de", "+4930123456", headers={"Privacy": "id"})
    sc.check("Privacy: id to the trusted trunk: PAI kept, Privacy passed on (the trunk withholds it)",
             inv is not None and inv.all("p-asserted-identity") == ["<sip:alice@example.com>"] and inv.get("privacy") == "id", inv and inv.raw)
    inv = routed("+12125551234", "intl", "+12125551234", headers={"Privacy": "id", "P-Asserted-Identity": "<sip:alice@example.com>"})
    sc.check("Privacy: id to the untrusted trunk: no P-Asserted-Identity at all",
             inv is not None and not inv.all("p-asserted-identity"), inv and inv.raw)
    inv = routed("00442071234567", "intl", "+442071234567", headers={"Privacy": "header;id"})
    sc.check("Privacy: header;id counts as id: no PAI to the untrusted trunk", inv is not None and not inv.all("p-asserted-identity"), inv and inv.raw)
    inv = routed("+12125551234", "intl", "+12125551234", headers={"Privacy": "none"})
    sc.check("Privacy: none: PAI to the untrusted trunk", inv is not None and inv.all("p-asserted-identity") == ["<sip:alice@example.com>"],
             inv and inv.raw)
    inv = routed("+12125551234", "intl", "+12125551234", headers={"Privacy": "user"})
    sc.check("Privacy: user (not id): PAI to the untrusted trunk", inv is not None and inv.all("p-asserted-identity") == ["<sip:alice@example.com>"],
             inv and inv.raw)
    inv = routed("+12125551234", "intl", "+12125551234", headers={"P-Preferred-Identity": "<sip:+4930999@example.com>"})
    sc.check("P-Preferred-Identity is consumed, not passed on", inv is not None and inv.get("p-preferred-identity") is None, inv and inv.raw)

    # --- calls from the trunks: ACL by source address
    r, d = de.call("sip:+4930555001@example.com", headers={"P-Asserted-Identity": "<sip:+4989123456@carrier.de>"})
    cid = d.call_id if d else (r.get("call-id") if r else None)
    g = got(cid)
    sc.check("from the domestic trunk (trunk IP): to the PBX without a challenge",
             r is not None and r.code == 200 and list(g) == ["pbx"], (r, list(g)))
    inv = g.get("pbx", [None])[0]
    sc.check("…its P-Asserted-Identity kept (trusted trunk)", inv is not None and inv.all("p-asserted-identity") == ["<sip:+4989123456@carrier.de>"],
             inv and inv.raw)
    if d:
        rep = d.bye()
        sc.check("…BYE from the PSTN side through the proxy: 200", rep is not None and rep.code == 200 and any(m.method == "BYE" and m.get("call-id") == cid for m in pbx.received), rep)
    r, d = intl.call("sip:+4930555001@example.com", headers={"P-Asserted-Identity": "<sip:+12125550000@carrier.example>"})
    cid = d.call_id if d else (r.get("call-id") if r else None)
    inv = got(cid).get("pbx", [None])[0]
    sc.check("from the international trunk: to the PBX, its PAI removed (not trusted)",
             r is not None and r.code == 200 and inv is not None and not inv.all("p-asserted-identity"), (r, inv and inv.raw))
    if d:
        d.bye()
    fake = ua_at(sc, "127.0.0.5", "fake-trunk", sip).auto_answer()
    r, d = fake.call("sip:+4930555001@example.com")
    sc.check("the same call from a non-trunk address → 407, not relayed to the PBX",
             r is not None and r.code == 407 and not got(r.get("call-id")), r)
    o = fake.request("OPTIONS", f"sip:127.0.0.1:{sip}")
    rep = fake.final(call_id=o["call_id"])
    sc.check("OPTIONS to the proxy is answered 200 (trunk keepalives)", rep is not None and rep.code == 200, rep)
    m = alice.request("MESSAGE", "sip:+4930123456@example.com", body="hi", content_type="text/plain")
    rep = alice.final(call_id=m["call_id"])
    sc.check("a MESSAGE to a number → 405 (the trunks carry calls only)", rep is not None and rep.code == 405, rep)
