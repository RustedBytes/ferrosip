"""l04-small-business-pbx: registrar and auth, voicemail on busy / no
answer / offline, per-user call forwarding set over HTTP (a shared table),
BLF (dialog-info) for one extension, CDRs in the log."""
import threading, time

from sipkit import challenges, credentials, http_get, sdp

DOM = "pbx.example.com"


def invites(ua, cid):
    """INVITEs of this call at `ua` (one per branch)."""
    return list({m.all("via")[0]: m for m in ua.received if m.method == "INVITE" and m.get("call-id") == cid}.values())


def wait_for(cond, timeout=4.0):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(0.05)
    return cond()


def authed(ua, method, ruri, headers=None):
    """A request that answers one digest challenge; (final reply, sent)."""
    sent = ua.request(method, ruri, headers=headers)
    r = ua.final(method=method, call_id=sent["call_id"], cseq=sent["cseq"])
    if r is not None and r.code in (401, 407):
        r, sent = ua.with_auth(sent, r)
    return r, sent


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


def ext(sc, sip, n, mode):
    """Extension n: answers per mode[n] ("200": rings and answers at once,
    "slow": rings 1s, then answers, "486", "ring": rings until canceled);
    other requests are answered 200."""
    u = sc.ua(str(n), sip, password=f"secret-{n}", domain=DOM)
    u.auto_answer(ring=True)
    base = u.handler

    def h(m):
        what = mode.get(n, "200")
        if m.method == "INVITE" and what == "486":
            return (486, "Busy Here")
        if m.method == "INVITE" and what == "ring":
            u.respond(m, 180, "Ringing")
            return None
        if m.method == "INVITE" and what == "slow":
            u.respond(m, 180, "Ringing")
            threading.Timer(1.0, lambda: u.respond(m, 200, "OK", body=sdp(u.port + 1000))).start()
            return None
        return base(m)
    u.handler = h
    return u


def cdr(proxy, cid):
    """The CDR line the PBX logged for this call, as a dict."""
    for line in list(proxy.lines):
        if "CDR " in line and f"call_id={cid} " in line:
            return dict(kv.split("=", 1) for kv in line.split("CDR ", 1)[1].split() if "=" in kv)
    return None


def run(sc):
    sip, hport = sc.port(), sc.port()
    vm = sc.ua("vm", sip).auto_answer()
    pbx = sc.proxy("pbx", sc.env(SIP_PORT=sip, HTTP_PORT=hport, VOICEMAIL=f"sip:127.0.0.1:{vm.port}"), name="pbx")
    api = f"http://127.0.0.1:{hport}/forward"
    mode = {}
    e = {n: ext(sc, sip, n, mode) for n in (100, 101, 102, 103)}
    for n, u in e.items():
        r = u.register()
        sc.check(f"extension {n} registers (401, then 200)", r is not None and r.code == 200, r)
    caller = e[100]

    # --- BLF: the receptionist (102) watches 101's line.
    r, sub = authed(e[102], "SUBSCRIBE", f"sip:101@{DOM}",
                    {"Event": "dialog", "Accept": "application/dialog-info+xml", "Expires": "300"})
    sc.check("102 subscribes to 101's dialog state (BLF): 200", r is not None and r.code in (200, 202), r)

    def notifies(state):
        return [m for m in e[102].received if m.method == "NOTIFY" and m.get("call-id") == sub["call_id"]
                and f"<state>{state}</state>" in m.body]
    sc.check("…and gets an initial NOTIFY", wait_for(lambda: any(m.method == "NOTIFY" and m.get("call-id") == sub["call_id"]
                                                                   for m in e[102].received)))

    def confirmed(cid):
        return [m for m in notifies("confirmed") if f'call-id="{cid}"' in m.body]

    # --- A normal call 100 → 101: rings 1s, answered; BLF follows it, CDR at the end.
    mode[101] = "slow"
    r, d = caller.call(f"sip:101@{DOM}", timeout=6)
    sc.check("100 calls 101 (rings 1s): 200", r is not None and r.code == 200 and d is not None, r)
    sc.check("BLF: 102 is told 101's line is confirmed", d is not None and wait_for(lambda: confirmed(d.call_id)),
             [m.body for m in e[102].received if m.method == "NOTIFY"][-1:])
    if d:
        rep = d.bye()
        sc.check("100 hangs up: BYE → 200", rep is not None and rep.code == 200, rep)
        sc.check("BLF: 102 is told the call terminated", wait_for(lambda: notifies("terminated")))
        x = wait_for(lambda: cdr(pbx, d.call_id))
        sc.check("a CDR is logged: caller 100, callee 101, caller_bye",
                 x is not None and (x.get("caller"), x.get("callee"), x.get("reason")) == ("100", "101", "caller_bye"), x)
    # The same, answered right after the 180: the "confirmed" PUBLISH is
    # made while the "early" one is still in flight.
    mode[101] = "200"
    r, d = caller.call(f"sip:101@{DOM}", timeout=6)
    sc.check("BLF: a call 101 answers at once is shown confirmed too", d is not None and wait_for(lambda: confirmed(d.call_id)),
             [m.body for m in e[102].received if m.method == "NOTIFY"][-1:])
    if d:
        d.bye()

    # --- Busy → voicemail.
    mode[103] = "486"
    r, d = caller.call(f"sip:103@{DOM}", timeout=8)
    cid = d.call_id if d else None
    sc.check("103 busy (486) → voicemail answers: 200", r is not None and r.code == 200 and d is not None, r)
    vinv = invites(vm, cid)
    sc.check("…voicemail gets one INVITE for 103's box (R-URI sip:103@pbx)", len(vinv) == 1 and vinv[0].ruri == f"sip:103@{DOM}",
             [m.ruri for m in vinv])
    sc.check("…and 103 got exactly one INVITE", len(invites(e[103], cid)) == 1, len(invites(e[103], cid)))
    if d:
        d.bye()
        x = wait_for(lambda: cdr(pbx, cid))
        sc.check("…the voicemail call's CDR has callee 103", x is not None and x.get("callee") == "103", x)

    # --- No answer → voicemail after the ring time (4s); 103 is canceled.
    mode[103] = "ring"
    r, d = caller.call(f"sip:103@{DOM}", timeout=12)
    cid = d.call_id if d else (r.get("call-id") if r is not None else None)
    sc.check("103 rings without answering → voicemail answers after the ring time: 200",
             r is not None and r.code == 200 and len(invites(vm, cid)) == 1, r)
    sc.check("…and 103's ringing branch is canceled",
             wait_for(lambda: any(m.method == "CANCEL" and m.get("call-id") == cid for m in e[103].received)))
    if d:
        d.bye()

    # --- Offline extension → voicemail at once; unknown number → 404.
    r, d = caller.call(f"sip:104@{DOM}", timeout=6)
    sc.check("104 (not registered) → straight to voicemail: 200", r is not None and r.code == 200 and d is not None
             and len(invites(vm, d.call_id)) == 1, r)
    if d:
        d.bye()
    r, _ = caller.call(f"sip:555@{DOM}", timeout=6)
    sc.check("555 (not an extension) → 404 No such extension", r is not None and r.code == 404 and r.reason == "No such extension", r)

    # --- CANCEL while 101 rings: 487, voicemail is not tried.
    mode[101] = "ring"
    sent = invite_with_auth(caller, f"sip:101@{DOM}")
    sc.check("100's INVITE to 101 is challenged, then sent with credentials", sent is not None)
    if sent:
        sc.check("…101 rings", caller.recv(4, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == sent["call_id"]) is not None)
        sc.check("BLF: 102 is told 101's line is early (ringing)", wait_for(lambda: notifies("early")))
        caller.cancel(sent)
        r = caller.final(method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"], timeout=5)
        sc.check("100 cancels: 487", r is not None and r.code == 487, r)
        if r is not None:
            caller._ack_neg(sent, r)
        time.sleep(0.5)
        sc.check("…and the canceled call is not sent to voicemail", invites(vm, sent["call_id"]) == [], invites(vm, sent["call_id"]))
    mode[101] = "200"

    # --- Call forwarding over HTTP.
    st, body = http_get(f"{api}?101", method="POST", body="102")
    sc.check("POST /forward?101 with 102 → 200", st == 200, (st, body))
    st, body = http_get(f"{api}?101")
    sc.check("GET /forward?101 → 102", st == 200 and body.strip() == "102", (st, body))
    st, body = http_get(f"{api}?101", method="POST", body="sip:evil@example.com")
    sc.check("a target that isn't an extension → 400", st == 400, (st, body))
    st, body = http_get(f"{api}?101")
    sc.check("…and the forwarding is unchanged", st == 200 and body.strip() == "102", (st, body))
    r, d = caller.call(f"sip:101@{DOM}", timeout=6)
    cid = d.call_id if d else None
    inv = invites(e[102], cid)
    sc.check("a call to 101 rings 102 instead: 200", r is not None and r.code == 200 and len(inv) == 1, r)
    sc.check("…with Diversion: <sip:101@pbx.example.com>", inv and "sip:101@pbx.example.com" in (inv[0].get("diversion") or ""),
             inv and inv[0].get("diversion"))
    sc.check("…and 101 never sees it", invites(e[101], cid) == [])
    if d:
        d.bye()
    # A forward to an extension that forwards too is followed once only.
    http_get(f"{api}?101", method="POST", body="103")
    http_get(f"{api}?103", method="POST", body="102")
    mode[103] = "486"
    r, d = caller.call(f"sip:101@{DOM}", timeout=8)
    cid = d.call_id if d else None
    sc.check("101 → 103 → 102: only the first hop is followed (103 busy → 103's voicemail)",
             r is not None and r.code == 200 and len(invites(e[103], cid)) == 1 and invites(e[102], cid) == []
             and [m.ruri for m in invites(vm, cid)] == [f"sip:103@{DOM}"], r)
    if d:
        d.bye()
    for n in (101, 103):
        st, _ = http_get(f"{api}?{n}", method="DELETE")
        sc.check(f"DELETE /forward?{n} → 204", st == 204, st)
    st, _ = http_get(f"{api}?101")
    sc.check("GET after DELETE → 404", st == 404, st)
    r, d = caller.call(f"sip:101@{DOM}", timeout=6)
    sc.check("without forwarding 101 answers itself again", r is not None and r.code == 200 and d is not None
             and len(invites(e[101], d.call_id)) == 1, r)
    if d:
        d.bye()
    st, _ = http_get(f"http://127.0.0.1:{hport}/forward?abc")
    sc.check("GET /forward?abc (not an extension) → 400", st == 400, st)
