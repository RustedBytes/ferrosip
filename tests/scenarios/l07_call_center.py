"""l07-call-center: a hunt group. Agents register to `sales` with q-values;
calls ring one q-group at a time (3s each; equal q rings in parallel),
then overflow to voicemail. Busy and silent agents, and a CANCEL from the
caller mid-hunt. In-dialog requests matched by the dialog cookie (did) in
the Record-Route; the supervisor API: a transfer (REFER to the customer)
and a callback (dialog.bridge through the hunt group)."""
import re, threading, time

from sipkit import challenges, credentials, http_get, sdp

DOM = "cc.example.com"
Q = {"a1": "1.0", "a2": "0.7", "a3": "0.3", "a4": "0.3"}


def invites(ua, cid):
    """INVITEs of this call at `ua` (one per branch)."""
    return list({m.all("via")[0] for m in ua.received if m.method == "INVITE" and m.get("call-id") == cid})


def got(ua, method, cid):
    return any(m.method == method and m.get("call-id") == cid for m in ua.received)


def wait_for(cond, timeout=4.0):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(0.05)
    return cond()


def agent(sc, sip, name, mode):
    """An agent's phone, registered as `sales`. mode[name]: "200" answers
    (after a 0.3s ring), "486" busy, "ring" rings until canceled."""
    u = sc.ua("sales", sip, domain=DOM, password="secret-sales")
    u.canceled = set()

    def h(m):
        what = mode.get(name, "ring")
        if m.method == "INVITE":
            if what == "486":
                return (486, "Busy Here")
            u.respond(m, 180, "Ringing")
            if what == "200":
                def answer():
                    if m.get("call-id") not in u.canceled:
                        u.respond(m, 200, "OK", body=sdp(u.port + 1000))
                threading.Timer(0.3, answer).start()
            return None
        if m.method == "CANCEL":
            u.canceled.add(m.get("call-id"))
            u.respond(m, 200)
            inv = next((x for x in reversed(u.received) if x.method == "INVITE" and x.get("call-id") == m.get("call-id")), None)
            if inv is not None:
                u.respond(inv, 487, "Request Terminated")
            return None
        if m.method == "ACK":
            return None
        if m.method == "REFER":
            return (202, "Accepted")
        return (200, "OK")
    u.handler = h
    return u


def invite_with_auth(ua, ruri):
    """An INVITE that answers the 407 but doesn't wait for the final; the sent request."""
    sent = ua.invite(ruri)
    r = ua.final(method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"])
    if r is None or r.code != 407:
        return None
    ua._ack_neg(sent, r)
    alg, p, hdr = challenges(r)[0]
    name, value = credentials(ua.user, ua.password, p, "INVITE", sent["ruri"], hdr, alg)
    return ua.request("INVITE", sent["ruri"], to=sent["to"], call_id=sent["call_id"], from_tag=sent["from_tag"],
                      cseq=sent["cseq"] + 1, headers={name: value}, body=sent["body"])


def in_dialog(d, method, route=None):
    """`method` inside the call of Dialog `d`, with `route` (default: its
    route set) as Route; the final reply."""
    d.cseq += 1
    hs = {"Route": ", ".join(d.route if route is None else route)}
    s = d.ua.request(method, d.remote_target, to=d.to, call_id=d.call_id, from_tag=d.local_tag, cseq=d.cseq, headers=hs)
    return d.ua.final(4, method=method, call_id=d.call_id, cseq=s["cseq"])


def run(sc):
    sip, hport = sc.port(), sc.port()
    vm = sc.ua("vm", sip).auto_answer()
    sc.proxy("acd", sc.env(SIP_PORT=sip, HTTP_PORT=hport, VOICEMAIL=f"sip:127.0.0.1:{vm.port}"), name="acd")
    api = f"http://127.0.0.1:{hport}"
    mode = {}
    agents = {n: agent(sc, sip, n, mode) for n in Q}
    for n, u in agents.items():
        r = u.register(headers={"Contact": f"<{u.contact}>;q={Q[n]}"})
        sc.check(f"agent {n} logs in (registers to sales, q={Q[n]})", r is not None and r.code == 200, r)
    caller = sc.ua("customer", sip, domain=DOM, password="secret-customer")

    def hunt(**modes):
        mode.clear()
        mode.update(modes)
        r, d = caller.call(f"sip:sales@{DOM}", timeout=20)
        cid = d.call_id if d else (r.get("call-id") if r is not None else None)
        return r, d, cid, {n: len(invites(u, cid)) for n, u in agents.items()}

    def done(d):
        if d:
            d.bye()

    r, d, cid, n = hunt(a1="200")
    sc.check("a1 (highest q) answers: 200, nobody else rung", r is not None and r.code == 200 and n == {"a1": 1, "a2": 0, "a3": 0, "a4": 0}, (r, n))
    # The dialog cookie: the ACD's Record-Route carries ;did=, and with
    # dlg_match_mode 0 in-dialog requests are matched by it alone.
    rr = d.route if d else []
    sc.check("…the ACD's Record-Route carries the dialog cookie (;did=<h_entry>.<h_id>)",
             len(rr) == 1 and re.search(r";did=[0-9a-f]+\.[0-9a-f]+", rr[0]) is not None, rr)
    if d and rr:
        forged = [re.sub(r";did=[0-9a-f]+\.[0-9a-f]+", ";did=fff.fff", rr[0])]
        stripped = [re.sub(r";did=[^;>]+", "", rr[0])]
        rep = in_dialog(d, "INFO", forged)
        sc.check("an INFO with a forged did → 481 from the ACD, never reaches a1",
                 rep is not None and rep.code == 481 and rep.reason == "Call Does Not Exist" and not got(agents["a1"], "INFO", cid), rep)
        rep = in_dialog(d, "INFO", stripped)
        sc.check("…without the cookie → 481 too (matched by the cookie only)", rep is not None and rep.code == 481 and not got(agents["a1"], "INFO", cid), rep)
        rep = in_dialog(d, "INFO")
        sc.check("…with the ACD's cookie → relayed to a1: 200", rep is not None and rep.code == 200 and got(agents["a1"], "INFO", cid), rep)
        rep = in_dialog(d, "BYE")
        sc.check("…BYE → 200", rep is not None and rep.code == 200, rep)
        rep = in_dialog(d, "BYE")
        sc.check("…a BYE once the call has ended → 481 (no dialog for the cookie)", rep is not None and rep.code == 481, rep)

    r, d, cid, n = hunt(a1="486", a2="200")
    sc.check("a1 busy → a2 answers; a3/a4 not rung", r is not None and r.code == 200 and n == {"a1": 1, "a2": 1, "a3": 0, "a4": 0}, (r, n))
    done(d)

    t0 = time.time()
    r, d, cid, n = hunt(a1="ring", a2="200")
    sc.check("a1 doesn't answer → after its 3s a2 answers", r is not None and r.code == 200 and n == {"a1": 1, "a2": 1, "a3": 0, "a4": 0}, (r, n))
    sc.check("…a1's ringing branch was canceled", wait_for(lambda: got(agents["a1"], "CANCEL", cid)))
    sc.check("…after a1's ring time (about 3s, well under the default timers)", 2 < time.time() - t0 < 10, time.time() - t0)
    done(d)

    r, d, cid, n = hunt(a1="486", a2="486", a3="ring", a4="200")
    sc.check("a1, a2 busy → a3 and a4 (same q) ring in parallel; a4 answers", r is not None and r.code == 200
             and n == {"a1": 1, "a2": 1, "a3": 1, "a4": 1}, (r, n))
    sc.check("…and a3 is canceled when a4 answers", wait_for(lambda: got(agents["a3"], "CANCEL", cid)))
    done(d)

    r, d, cid, n = hunt(a1="486", a2="ring", a3="486", a4="486")
    sc.check("everybody busy or not answering → overflow to voicemail: 200", r is not None and r.code == 200
             and len(invites(vm, cid)) == 1 and n == {"a1": 1, "a2": 1, "a3": 1, "a4": 1}, (r, n))
    vinv = next((m for m in vm.received if m.method == "INVITE" and m.get("call-id") == cid), None)
    sc.check("…voicemail gets the call for sip:sales@cc.example.com", vinv is not None and vinv.ruri == f"sip:sales@{DOM}", vinv)
    done(d)

    # The caller hangs up while a2 rings (a1 was busy).
    mode.clear()
    mode.update(a1="486", a2="ring", a3="200", a4="200")
    sent = invite_with_auth(caller, f"sip:sales@{DOM}")
    sc.check("the customer's INVITE is challenged, then sent with credentials", sent is not None)
    if sent:
        cid = sent["call_id"]
        sc.check("…a2 rings (a1 was busy)", wait_for(lambda: len(invites(agents["a2"], cid)) == 1))
        caller.cancel(sent)
        r = caller.final(method="INVITE", call_id=cid, cseq=sent["cseq"], timeout=6)
        sc.check("CANCEL mid-hunt → 487 to the customer (the code after await sees txn.is_canceled() and answers 487, not an earlier agent's 486)", r is not None and r.code == 487, r)
        if r is not None:
            caller._ack_neg(sent, r)
        sc.check("…a2's branch is canceled", wait_for(lambda: got(agents["a2"], "CANCEL", cid)))
        time.sleep(4)  # longer than a q-group's ring time: the hunt must not go on
        n = {k: len(invites(u, cid)) for k, u in agents.items()}
        sc.check("…the hunt stops: a3/a4 never rung", n == {"a1": 1, "a2": 1, "a3": 0, "a4": 0}, n)
        sc.check("…and voicemail is not called", invites(vm, cid) == [])

    # The supervisor transfers a customer: REFER inside the answered call.
    mode.clear()
    mode.update(a1="200")
    r, d = caller.call(f"sip:sales@{DOM}", timeout=20)
    cid = d.call_id if d else None
    sc.check("a customer call answered by a1, for the transfer", d is not None, r)
    st, body = http_get(f"{api}/transfer?nobody@nowhere", method="POST", body="supervisor")
    sc.check("POST /transfer for an unknown call → 404", st == 404, (st, body))
    st, body = http_get(f"{api}/transfer?{cid}", method="POST", body="sip:x@evil.example.com")
    sc.check("POST /transfer with a target that isn't a user name → 400", st == 400, (st, body))
    if d:
        st, body = http_get(f"{api}/transfer?{cid}", method="POST", body="supervisor")
        sc.check("POST /transfer?<call-id> supervisor → 202", st == 202, (st, body))
        ref = caller.request_in("REFER", timeout=4)
        sc.check("…the customer gets a REFER inside the call (Call-ID, From = a1's tag, To = the customer's, to its Contact)",
                 ref is not None and ref.get("call-id") == cid and ref.tag("from") == d.remote_tag and ref.tag("to") == d.local_tag
                 and ref.ruri == caller.contact, ref and ref.raw)
        sc.check("…Refer-To <sip:supervisor@cc.example.com>, Referred-By the ACD (bridge_controller)",
                 ref is not None and ref.get("refer-to") == f"<sip:supervisor@{DOM}>" and ref.get("referred-by") == f"<sip:acd@{DOM}>",
                 ref and (ref.get("refer-to"), ref.get("referred-by")))
        if ref is not None:
            caller.respond(ref, 202, "Accepted")
        rep = d.bye()
        sc.check("…the customer leaves the call with BYE → 200, a1 gets it", rep is not None and rep.code == 200 and got(agents["a1"], "BYE", cid), rep)
        st, body = http_get(f"{api}/transfer?{cid}", method="POST", body="supervisor")
        sc.check("…a transfer of the ended call → 404", st == 404, (st, body))

    # Callback: the ACD rings the hunt group and REFERs the agent who
    # answers to the customer (dialog.bridge through the ACD itself).
    mode.clear()
    mode.update(a1="486", a2="200")
    st, body = http_get(f"{api}/callback", method="POST", body="customer")
    sc.check("POST /callback customer → 202", st == 202, (st, body))
    cb = wait_for(lambda: next((m for m in agents["a2"].received if m.method == "INVITE" and f"sip:acd@{DOM}" in (m.get("from") or "")), None), 8)
    cid = cb.get("call-id") if cb else None
    sc.check("…the callback hunts: a1 busy, a2 rings with an INVITE from sip:acd@cc.example.com, record-routed with the cookie",
             cb is not None and len(invites(agents["a1"], cid)) == 1 and any(";did=" in x for x in cb.all("record-route")), cb and cb.raw)
    sc.check("…a2's answer is ACKed", wait_for(lambda: any(m.method == "ACK" and m.get("call-id") == cid for m in agents["a2"].q.queue), 4))
    ref = wait_for(lambda: next((m for m in agents["a2"].received if m.method == "REFER" and m.get("call-id") == cid), None), 4)
    sc.check("…then a2 gets a REFER to the customer (Refer-To <sip:customer@cc.example.com>) in that call",
             ref is not None and ref.get("refer-to") == f"<sip:customer@{DOM}>", ref and ref.raw)
    sc.check("…and the ACD hangs up its leg (BYE to a2)", wait_for(lambda: got(agents["a2"], "BYE", cid), 4))
    st, body = http_get(f"{api}/callback", method="POST", body="a b")
    sc.check("POST /callback with a bad customer → 400", st == 400, (st, body))

    # All agents log out: straight to voicemail.
    r = agents["a1"].register(expires=0, headers={"Contact": "*"})
    sc.check("all agents log out (Contact: *, Expires: 0)", r is not None and r.code == 200, r)
    r, d, cid, n = hunt()
    sc.check("nobody logged in → voicemail at once", r is not None and r.code == 200 and len(invites(vm, cid)) == 1
             and sum(n.values()) == 0, (r, n))
    done(d)
