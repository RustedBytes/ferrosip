"""m10-cdr: dialog.manage(), CDRs POSTed from `on dialog.ended` /
`on dialog.failed` with http_client.post; caller_bye, callee_bye, timeout,
admin; durations. The BYEs the proxy sends itself carry a Reason header
(event_route[tm:local-request]); relayed ones don't."""
import json, time


def wait_for(pred, timeout):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.1)
    return pred()


def run(sc):
    sip = sc.port()
    pbx = sc.ua("pbx", sip).auto_answer()
    svc = sc.service({"/cdr": (200, "stored")})
    px = sc.proxy(env=sc.env(SIP_PORT=sip, CALLEE=f"sip:127.0.0.1:{pbx.port}", COLLECTOR=f"http://127.0.0.1:{svc.srv.server_address[1]}"))
    alice = sc.ua("alice", sip).auto_answer()
    prepaid = sc.ua("pp100", sip).auto_answer()

    def cdrs(cid):
        out = []
        for m, path, _q, body, h in list(svc.log):
            try:
                j = json.loads(body)
            except ValueError:
                j = {"_raw": body}
            if j.get("call_id") == cid or (cid in body):
                out.append((m, path, j, h))
        return out

    def cdr(cid, timeout=5):
        got = wait_for(lambda: cdrs(cid), timeout)
        return got[0] if got else None

    # caller hangs up.
    t0 = time.time()
    r, d = alice.call("sip:200@example.com", timeout=6)
    sc.check("alice → PBX: 200", r is not None and r.code == 200 and d is not None, r)
    time.sleep(1.5)
    bye = d.bye() if d else None
    held = time.time() - t0
    sc.check("caller BYE → 200", bye is not None and bye.code == 200, bye)
    rb = next((m for m in pbx.received if m.method == "BYE" and d and m.get("call-id") == d.call_id), None)
    sc.check("…the relayed BYE reaches the PBX without a Reason (tm:local-request is for the proxy's own requests)",
             rb is not None and rb.get("reason") is None, rb and rb.raw)
    c = cdr(d.call_id) if d else None
    sc.check("caller_bye: one CDR POSTed to /cdr as valid JSON", c is not None and c[0] == "POST" and c[1] == "/cdr" and "_raw" not in c[2],
             svc.log[-3:])
    j = c[2] if c else {}
    sc.check("…end_reason caller_bye, caller and plan from the dialog vars",
             j.get("end_reason") == "caller_bye" and j.get("caller") == "alice" and j.get("plan") == "postpaid", j)
    sc.check("…from/to URIs of the dialog", j.get("from") == "sip:alice@example.com" and j.get("to") == "sip:200@example.com", j)
    sc.check(f"…duration plausible (held ~{held:.1f}s): 1 ≤ duration ≤ held+1", isinstance(j.get("duration"), int)
             and 1 <= j["duration"] <= held + 1, j.get("duration"))
    sc.check("…start is the Unix time of the answer", isinstance(j.get("start"), int) and abs(j["start"] - t0) <= 3, (j.get("start"), t0))
    hd = {k.lower(): v for k, v in (c[3] if c else {}).items()}
    sc.check("…sent as Content-Type: application/json", hd.get("content-type") == "application/json", hd)
    sc.check("…exactly one CDR for the call", d is not None and len(cdrs(d.call_id)) == 1, d and cdrs(d.call_id))

    # callee hangs up (BYE from the PBX back through the proxy).
    r, d = alice.call("sip:201@example.com", timeout=6)
    inv = next((m for m in pbx.received if m.method == "INVITE" and d and m.get("call-id") == d.call_id), None)
    time.sleep(1.0)
    if inv is not None:
        b = pbx.request("BYE", f"sip:alice@127.0.0.1:{alice.port}", to=inv.get("from"), call_id=inv.get("call-id"),
                        from_tag=pbx.tags.get((inv.get("call-id"), inv.tag("from"))), cseq=1,
                        headers={"Route": ", ".join(inv.all("record-route"))}, from_uri="sip:201@example.com")
        rep = pbx.final(call_id=b["call_id"], method="BYE")
        sc.check("callee BYE through the proxy → 200 from alice", rep is not None and rep.code == 200, rep)
    c = cdr(d.call_id) if d else None
    j = c[2] if c else {}
    sc.check("callee_bye: CDR with end_reason callee_bye", j.get("end_reason") == "callee_bye", j)
    sc.check("…duration about 1s (0 ≤ d ≤ 3)", isinstance(j.get("duration"), int) and 0 <= j["duration"] <= 3, j.get("duration"))

    # A prepaid caller: cut after 3s, BYE to both sides.
    t0 = time.time()
    r, d = prepaid.call("sip:202@example.com", timeout=6)
    sc.check("prepaid pp100 → PBX: 200", r is not None and r.code == 200 and d is not None, r)
    got = wait_for(lambda: d and any(m.method == "BYE" and m.get("call-id") == d.call_id for m in prepaid.received), 10)
    took = time.time() - t0
    sc.check("…the proxy sends BYE to the caller after the 3s limit", got, [m.first for m in prepaid.received])
    sc.check("…not before 3s, and not much after", 2.5 <= took <= 8, took)
    sc.check("…and to the callee", wait_for(lambda: any(m.method == "BYE" and m.get("call-id") == d.call_id for m in pbx.received), 3),
             [m.first for m in pbx.received[-4:]])
    why = [{m.get("reason") for m in ua.received if m.method == "BYE" and d and m.get("call-id") == d.call_id} for ua in (prepaid, pbx)]
    sc.check("…both BYEs carry Reason: SIP;cause=200;text=\"Call ended by the proxy\" (added in tm:local-request)",
             why == [{'SIP;cause=200;text="Call ended by the proxy"'}] * 2, why)
    c = cdr(d.call_id) if d else None
    j = c[2] if c else {}
    sc.check("…CDR with end_reason timeout, plan prepaid", j.get("end_reason") == "timeout" and j.get("plan") == "prepaid", j)
    sc.check("…duration about the limit (3 ≤ d ≤ 5)", isinstance(j.get("duration"), int) and 3 <= j["duration"] <= 5, j.get("duration"))
    if d:
        d.bye()           # late: the proxy already ended the dialog
    time.sleep(0.3)
    sc.check("…a late BYE from the caller makes no second CDR", d is not None and len(cdrs(d.call_id)) == 1, d and cdrs(d.call_id))

    # Ended by the admin (dlg.end_dlg).
    r, d = alice.call("sip:203@example.com", timeout=6)
    lst = px.rpc("dlg.list")
    me = next((x for x in (lst if isinstance(lst, list) else []) if d and x.get("call-id") == d.call_id), None)
    sc.check("dlg.list shows the call with the dialog vars", me is not None and "alice" in json.dumps(me.get("variables", {})), lst)
    if me:
        px.rpc("dlg.end_dlg", me["h_entry"], me["h_id"])
    got = wait_for(lambda: d and any(m.method == "BYE" and m.get("call-id") == d.call_id for m in alice.received), 5)
    sc.check("dlg.end_dlg → BYE to the caller", got)
    why = {m.get("reason") for m in alice.received if m.method == "BYE" and d and m.get("call-id") == d.call_id}
    sc.check("…with the Reason header too", why == {'SIP;cause=200;text="Call ended by the proxy"'}, why)
    c = cdr(d.call_id) if d else None
    j = c[2] if c else {}
    sc.check("…CDR with end_reason admin", j.get("end_reason") == "admin", j)

    # A rejected call: a failed CDR with the code, and no ended CDR.
    pbx.auto_answer(code=486, reason="Busy Here")
    r, d = alice.call("sip:204@example.com", timeout=6)
    cid = r.get("call-id") if r is not None else None
    sc.check("a busy callee → 486 to the caller", r is not None and r.code == 486, r)
    c = cdr(cid) if cid else None
    j = c[2] if c else {}
    sc.check("…on dialog.failed POSTs a CDR with code 486", j.get("end_reason") == "failed" and j.get("code") == 486, j)
    time.sleep(0.5)
    sc.check("…and on dialog.ended does not run for it", cid is not None and len(cdrs(cid)) == 1, cid and cdrs(cid))
    pbx.auto_answer()

    # The collector is down: the call and its BYE are unaffected.
    svc.close()
    r, d = alice.call("sip:205@example.com", timeout=6)
    t0 = time.time()
    bye = d.bye(timeout=5) if d else None
    sc.check("collector down: the BYE still gets 200", bye is not None and bye.code == 200, bye)
    sc.check("…within connection_timeout (1s) and some margin", time.time() - t0 < 3.5, time.time() - t0)
    r, d = alice.call("sip:206@example.com", timeout=6)
    sc.check("…and the next call still works", r is not None and r.code == 200, r)
    if d:
        d.bye()
