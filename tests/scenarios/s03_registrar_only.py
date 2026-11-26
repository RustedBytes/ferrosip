"""s03-registrar-only: expiry limits, 423, max_contacts, `*`, Expires: 0,
refresh, several contacts and Path."""
import re
import subprocess

import sipkit


def rpc_full(px, *args):
    """ferroctl's (exit code, stdout + stderr): Proxy.rpc() keeps only stdout."""
    r = subprocess.run([sipkit.CTL, "-s", px.env["RPC_SOCK"], *map(str, args)], capture_output=True, text=True, timeout=5)
    return r.returncode, r.stdout + r.stderr


def reg(ua, contacts=None, expires=None, call_id=None, cseq=1, headers=None):
    """REGISTER with these Contact values (None: a query, no Contact); the final reply."""
    hs = dict(headers or {})
    if contacts:
        hs["Contact"] = ", ".join(contacts)
    if expires is not None:
        hs["Expires"] = str(expires)
    r = ua.request("REGISTER", "sip:example.com", to=f"<{ua.aor}>", call_id=call_id, cseq=cseq, headers=hs, contact=bool(contacts))
    return ua.final(call_id=r["call_id"], cseq=cseq), r


def bindings(rep):
    """{contact URI: expires} of a REGISTER's 200."""
    out = {}
    for c in (rep.all("contact") if rep is not None else []):
        m = re.search(r";\s*expires=(\d+)", c)
        out[sipkit.uri_of(c)] = int(m.group(1)) if m else None
    return out


def run(sc):
    sip = sc.port()
    px = sc.proxy(env=sc.env(SIP_PORT=sip))
    alice = sc.ua("alice", sip)
    c = lambda n: f"sip:alice@127.0.0.1:{40000 + n}"  # noqa: E731  (contact URIs: never contacted)

    # Expiry: capped by max_expires, default_expires when none is asked.
    rep, _ = reg(alice, [f"<{c(1)}>"], expires=7200)
    b = bindings(rep)
    sc.check("REGISTER Expires 7200 → 200", rep is not None and rep.code == 200, rep)
    sc.check("…the binding is capped at max_expires (3600)", b.get(c(1)) is not None and 3590 <= b[c(1)] <= 3600, b)
    rep, _ = reg(alice, [f"<{c(2)}>"])
    b = bindings(rep)
    sc.check("REGISTER without any expiry → default_expires (600)", b.get(c(2)) is not None and 590 <= b[c(2)] <= 600, b)
    sc.check("…and the 200 lists both bindings of the AoR", set(b) == {c(1), c(2)}, b)
    rep, _ = reg(alice, [f"<{c(1)}>;expires=120"], expires=3000)
    b = bindings(rep)
    sc.check("a Contact ;expires parameter wins over the Expires header", b.get(c(1)) is not None and 110 <= b[c(1)] <= 120, b)

    # 423: shorter than min_expires (header or Contact parameter), with Min-Expires.
    rep, _ = reg(alice, [f"<{c(3)}>"], expires=10)
    sc.check("Expires 10 (< min_expires 30) → 423 Interval Too Brief", rep is not None and rep.code == 423, rep)
    sc.check("…with Min-Expires: 30", rep is not None and (rep.get("min-expires") or "").strip() == "30", rep and rep.raw)
    rep, _ = reg(alice, [f"<{c(3)}>;expires=5"])
    sc.check("Contact ;expires=5 → 423 too", rep is not None and rep.code == 423, rep)
    rep, _ = reg(alice)
    sc.check("…and nothing was stored by the refused REGISTERs (query lists 2)", set(bindings(rep)) == {c(1), c(2)}, rep and rep.raw)

    # A query (no Contact): 200 with the bindings, changes nothing.
    sc.check("a query REGISTER → 200 with the current bindings", rep is not None and rep.code == 200, rep)

    # max_contacts = 3: a REGISTER that would make 4 is refused as a whole.
    rep, _ = reg(alice, [f"<{c(4)}>", f"<{c(5)}>"], expires=300)
    sc.check("2 bindings + a REGISTER with 2 more (max_contacts 3) → 503", rep is not None and rep.code == 503, rep)
    rep, _ = reg(alice)
    sc.check("…all or nothing: neither new contact is stored", set(bindings(rep)) == {c(1), c(2)}, rep and rep.raw)
    rep, _ = reg(alice, [f"<{c(4)}>"], expires=300)
    sc.check("a third binding is still accepted (exactly max_contacts)", rep is not None and rep.code == 200 and len(bindings(rep)) == 3, rep and rep.raw)
    rep, _ = reg(alice, [f"<{c(1)}>"], expires=300)
    sc.check("refreshing an existing binding at the limit is not refused", rep is not None and rep.code == 200 and len(bindings(rep)) == 3, rep and rep.raw)

    # Expires: 0 for one contact: only that binding goes.
    rep, _ = reg(alice, [f"<{c(4)}>"], expires=0)
    b = bindings(rep)
    sc.check("Expires: 0 for one contact → 200 without it, the others stay", rep is not None and rep.code == 200 and set(b) == {c(1), c(2)}, b)
    rep, _ = reg(alice, [f"<{c(2)}>;expires=0", f"<{c(5)}>;expires=300"])
    b = bindings(rep)
    sc.check("one REGISTER removing one contact (;expires=0) and adding another", rep is not None and rep.code == 200 and set(b) == {c(1), c(5)}, b)

    # Refresh on one Call-ID: CSeq goes up; a lower CSeq is out of order.
    bob = sc.ua("bob", sip)
    cid = f"refresh-{sipkit.rnd(6)}@127.0.0.1"
    rep, _ = reg(bob, [f"<{bob.contact}>"], expires=60, call_id=cid, cseq=10)
    sc.check("bob registers (Expires 60, CSeq 10)", rep is not None and rep.code == 200, rep)
    rep, _ = reg(bob, [f"<{bob.contact}>"], expires=900, call_id=cid, cseq=11)
    b = bindings(rep)
    sc.check("re-REGISTER on the same Call-ID, CSeq 11, Expires 900: one binding, refreshed to 900",
             rep is not None and rep.code == 200 and list(b.values()) and len(b) == 1 and 890 <= list(b.values())[0] <= 900, b)
    rep, _ = reg(bob, [f"<{bob.contact}>"], expires=60, call_id=cid, cseq=11)
    b = bindings(rep)
    sc.check("the same Call-ID and CSeq (11 again) within cseq_delay: a retransmission, 200, binding unchanged",
             rep is not None and rep.code == 200 and len(b) == 1 and 880 <= list(b.values())[0] <= 900, b)
    rep, _ = reg(bob, [f"<{bob.contact}>"], expires=60, call_id=cid, cseq=10)
    sc.check("the same Call-ID with a lower CSeq (10) → 400 Invalid CSeq number", rep is not None and rep.code == 400, rep)
    rep, _ = reg(bob)
    b = bindings(rep)
    sc.check("…and the binding keeps its 900s", len(b) == 1 and 880 <= list(b.values())[0] <= 900, b)

    # `*`: only with Expires: 0 and alone.
    rep, _ = reg(alice, ["*"], expires=3600)
    sc.check("Contact: * with Expires 3600 → 400", rep is not None and rep.code == 400, rep)
    rep, _ = reg(alice, ["*", f"<{c(6)}>"], expires=0)
    sc.check("Contact: * together with another contact → 400", rep is not None and rep.code == 400, rep)
    rep, _ = reg(alice, ["*"])
    sc.check("Contact: * without an Expires header → 400", rep is not None and rep.code == 400, rep)
    rep, _ = reg(alice)
    sc.check("…the refused `*` requests removed nothing", set(bindings(rep)) == {c(1), c(5)}, rep and rep.raw)
    rep, _ = reg(alice, ["*"], expires=0)
    sc.check("Contact: * with Expires: 0 → 200 and no bindings left", rep is not None and rep.code == 200 and not rep.all("contact"), rep and rep.raw)
    rep, _ = reg(alice)
    sc.check("…a query confirms the AoR is empty", rep is not None and rep.code == 200 and not bindings(rep), rep and rep.raw)
    rc, out = rpc_full(px, "ul.lookup", "location", "alice")
    sc.check("…and ul.lookup no longer finds alice (AoR not found)", "not found" in out.lower(), (rc, out))

    # Path (use_path, lazy): stored; echoed in the 200 when the UA supports it.
    carol = sc.ua("carol", sip)
    path = "<sip:edge.example.net;lr>"
    rep, _ = reg(carol, [f"<{carol.contact}>"], expires=300, headers={"Path": path, "Supported": "path"})
    sc.check("REGISTER with Path and Supported: path → 200 echoing the Path (RFC 3327 §5.3)",
             rep is not None and rep.code == 200 and "edge.example.net" in (rep.get("path") or ""), rep and rep.raw)
    dump = px.rpc("ul.lookup", "location", "carol")
    sc.check("…and the Path is stored with the binding (ul.lookup)", "edge.example.net" in str(dump), dump)
    dave = sc.ua("dave", sip)
    rep, _ = reg(dave, [f"<{dave.contact}>"], expires=300, headers={"Path": path})
    sc.check("REGISTER with Path but no Supported: path (lazy) → 200 without a Path header",
             rep is not None and rep.code == 200 and rep.get("path") is None, rep and rep.raw)

    # Anything but REGISTER: 405 with Allow.
    r = alice.request("OPTIONS", "sip:bob@example.com")
    rep = alice.final(call_id=r["call_id"])
    sc.check("OPTIONS → 405 with Allow: REGISTER", rep is not None and rep.code == 405 and "REGISTER" in (rep.get("allow") or ""), rep and rep.raw)
