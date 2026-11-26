"""m16-json-webhooks: a JSON event per call (`json_doc.set` + `await
http.post`) to a fake webhook whose JSON answer routes the call
(`json_doc.get`): routing, rejection, and every way the answer can be
unusable (malformed, missing fields, wrong types, control characters),
escaping of display names in the event, UTF-8, large bodies."""
import json
import time

import sipkit


def send_invite(ua, ruri, display=None, headers=None, body=None):
    """An INVITE with a From display name (UA.request can't write one);
    the sent-request dict, as UA.request returns it (for Dialog/_ack_neg)."""
    branch, cid, ftag = sipkit.rnd(12), f"{sipkit.rnd(10)}@127.0.0.1", sipkit.rnd(8)
    to = f"<{ruri}>"
    frm = (f"{display} " if display else "") + f"<{ua.aor}>;tag={ftag}"
    body = sipkit.sdp(ua.port + 1000) if body is None else body
    hs = [f"Via: {ua.via(branch)}", f"From: {frm}", f"To: {to}", f"Call-ID: {cid}", "CSeq: 7 INVITE",
          "Max-Forwards: 70", f"Contact: <{ua.contact}>"]
    hs += [f"{k}: {v}" for k, v in (headers or {}).items()]
    if body:
        hs.append("Content-Type: application/sdp")
    hs.append(f"Content-Length: {len(body.encode())}")
    raw = f"INVITE {ruri} SIP/2.0\r\n" + "\r\n".join(hs) + "\r\n\r\n" + body
    ua.send(raw)
    return {"method": "INVITE", "ruri": ruri, "branch": branch, "call_id": cid, "from_tag": ftag, "cseq": 7,
            "to": to, "raw": raw, "headers": headers or {}, "body": body}


def invites(u, cid):
    return [m for m in u.received if m.method == "INVITE" and m.get("call-id") == cid]


def run(sc):
    sip = sc.port()
    uas = sc.ua("uas", sip).auto_answer()
    fallback = sc.ua("fallback", sip).auto_answer()
    target = f"sip:127.0.0.1:{uas.port}"
    pad = "x" * 300_000

    answers = {
        "100": (200, json.dumps({"action": "route", "route": {"uri": target, "account": 'Zoë é "quoted" back\\slash'}})),
        "plain": (200, json.dumps({"action": "route", "route": {"uri": target}})),
        "busy": (200, json.dumps({"action": "reject", "code": 486, "reason": "Besetzt – später"})),
        "decline": (200, json.dumps({"action": "reject", "code": 603})),
        "malformed": (200, '{"action": "route", "route": {"uri": '),
        "html": (200, "<html>oops</html>"),
        "empty": (200, ""),
        "noaction": (200, json.dumps({"route": {"uri": target}})),
        "teleport": (200, json.dumps({"action": "teleport"})),
        "nouri": (200, json.dumps({"action": "route"})),
        "uriint": (200, json.dumps({"action": "route", "route": {"uri": 42}})),
        "urilist": (200, json.dumps({"action": "route", "route": {"uri": [target]}})),
        "uriobj": (200, json.dumps({"action": "route", "route": "sip:x"})),
        "nocode": (200, json.dumps({"action": "reject"})),
        "codestr": (200, json.dumps({"action": "reject", "code": "abc"})),
        "codebool": (200, json.dumps({"action": "reject", "code": True})),
        "code200": (200, json.dumps({"action": "reject", "code": 200})),
        "actionint": (200, json.dumps({"action": 1})),
        "inject": (200, json.dumps({"action": "route", "route": {"uri": target, "account": "a\r\nX-Injected: 1"}})),
        "injectreason": (200, json.dumps({"action": "reject", "code": 486, "reason": "Busy\r\nX-Injected: 1"})),
        "status500": (500, json.dumps({"action": "route", "route": {"uri": target}})),
        "slow": (200, json.dumps({"action": "route", "route": {"uri": target}}), 3.0),
        "big": (200, json.dumps({"padding": pad, "list": list(range(2000)), "action": "route", "route": {"uri": target, "account": "big"}})),
    }

    def hook(method, path, query, body):
        try:
            ev = json.loads(body)
        except ValueError:
            return (400, "bad event")
        return answers.get(ev.get("to"), (404, "?"))
    svc = sc.service({"*": hook})
    sc.proxy(env=sc.env(SIP_PORT=sip, WEBHOOK_URL=f"http://127.0.0.1:{svc.port}/call", FALLBACK=f"sip:127.0.0.1:{fallback.port}"))
    ua = sc.ua("alice", sip)

    def call(user, display=None, headers=None, body=None, timeout=8):
        """(final, call-id, POSTs the webhook got for it, seconds)."""
        n = len(svc.log)
        t0 = time.time()
        sent = send_invite(ua, f"sip:{user}@example.com", display, headers, body)
        r = ua.final(timeout, method="INVITE", call_id=sent["call_id"], cseq=7)
        took = time.time() - t0
        if r is not None and r.code >= 300:
            ua._ack_neg(sent, r)
        elif r is not None:
            d = sipkit.Dialog(ua, sent, r)
            d.ack()
            b = d.bye()
            sc.check(f"[{user}] BYE → 200", b is not None and b.code == 200, b)
        return r, sent["call_id"], svc.log[n:], took

    def event(posts):
        """The event the webhook got, parsed by Python's strict json.loads."""
        try:
            return json.loads(posts[0][3]) if posts else None
        except ValueError as e:
            return f"invalid JSON: {e}: {posts[0][3][:300]!r}"

    # --- Routed by the webhook; what the webhook received.
    r, cid, posts, _ = call("100", headers={"Subject": "Rückruf ✆"})
    inv = (invites(uas, cid) or [None])[0]
    sc.check("webhook answers action route → the call reaches route.uri: 200, not the fallback",
             r is not None and r.code == 200 and inv is not None and not invites(fallback, cid), r)
    sc.check("…one POST per call, with Content-Type application/json",
             len(posts) == 1 and posts[0][0] == "POST" and posts[0][1] == "/call"
             and {k.lower(): v for k, v in posts[0][4].items()}.get("content-type", "").startswith("application/json"), posts)
    ev = event(posts)
    sc.check("…the event is valid JSON with event, call_id, from.user, to",
             isinstance(ev, dict) and ev.get("event") == "call.new" and ev.get("call_id") == cid
             and ev.get("from", {}).get("user") == "alice" and ev.get("to") == "100", ev)
    sc.check("…cseq is a JSON integer (json_doc.set integer)", isinstance(ev, dict) and ev.get("cseq") == 7 and type(ev.get("cseq")) is int, ev)
    sc.check("…the UTF-8 Subject is in the event as is", isinstance(ev, dict) and ev.get("subject") == "Rückruf ✆", ev)
    sc.check("…the SDP body is in the event, byte for byte",
             isinstance(ev, dict) and ev.get("sdp") == (inv.body if inv else None), ev)
    acc = inv.get("x-account") if inv else None
    sc.check("…route.account (JSON escapes \\\" \\\\ and UTF-8) decoded into X-Account",
             acc == 'Zoë é "quoted" back\\slash', acc)
    sc.check("…no X-Webhook-Fallback on a routed call", inv is not None and inv.get("x-webhook-fallback") is None)
    sc.check("…the INVITE carries the Record-Route added before the await", inv is not None and len(inv.all("record-route")) == 1,
             inv and inv.all("record-route"))
    sc.check("…the BYE did not POST another event", len(svc.log) == 1, svc.log)

    r, cid, posts, _ = call("plain")
    ev = event(posts)
    sc.check("no Subject header → no subject key in the event (not \"\" or \"<null>\")",
             isinstance(ev, dict) and "subject" not in ev, ev)
    sc.check("no display name → from.display is an empty string", isinstance(ev, dict) and ev.get("from", {}).get("display") == "", ev)

    # --- Display names that need JSON escaping. msg.from.display is $fn:
    # Kamailio gives the quoted-string as written (quotes and escapes);
    # the display text itself (unescaped) would do too. Either way the
    # event must stay valid JSON.
    names = [
        ('"Jo \\"The Boss\\" O\\\\Brien"', ('Jo "The Boss" O\\Brien', '"Jo \\"The Boss\\" O\\\\Brien"')),
        ('"Bob \\"B\\""', ('Bob "B"', '"Bob \\"B\\""')),
        ('"Zoë 日本 ☎"', ("Zoë 日本 ☎", '"Zoë 日本 ☎"')),
        ('"tab\there"', ("tab\there", '"tab\there"')),
        ("Bob   Smith", ("Bob Smith", "Bob   Smith")),
    ]
    for raw, ok_values in names:
        r, cid, posts, _ = call("plain", display=raw)
        ev = event(posts)
        sc.check(f"From display {raw!r} → the event is valid JSON (strict json.loads)", isinstance(ev, dict), ev)
        disp = ev.get("from", {}).get("display") if isinstance(ev, dict) else None
        sc.check(f"…from.display carries the name ({raw!r})", disp in ok_values, disp)
        sc.check(f"…and the call is routed: 200 ({raw!r})", r is not None and r.code == 200 and invites(uas, cid), r)

    # --- Rejections.
    r, cid, _, _ = call("busy")
    sc.check("action reject, code 486 → 486 to the caller with the UTF-8 reason",
             r is not None and r.code == 486 and r.reason == "Besetzt – später" and not invites(uas, cid) and not invites(fallback, cid), r)
    r, cid, _, _ = call("decline")
    sc.check("action reject, code 603 without reason → 603 Rejected", r is not None and r.code == 603 and r.reason == "Rejected", r)

    # --- Every unusable answer: the fallback, with the reason.
    def fb(user, what, why):
        r, cid, posts, took = call(user)
        inv = (invites(fallback, cid) or [None])[0]
        hdr = inv.get("x-webhook-fallback") if inv else None
        sc.check(f"{what} → the fallback answers: 200, route.uri not used",
                 r is not None and r.code == 200 and inv is not None and not invites(uas, cid), (r, posts and posts[0][3][:200]))
        sc.check(f"…X-Webhook-Fallback: {why}", hdr is not None and hdr.startswith(why), hdr)
        return inv, took

    fb("malformed", "malformed JSON (cut off)", "no action")
    fb("html", "an HTML body", "no action")
    fb("empty", "an empty body", "no action")
    fb("noaction", "JSON without action", "no action")
    fb("teleport", "an unknown action", "unknown action")
    fb("actionint", "action is a number (1), not a string", "unknown action")
    fb("nouri", "action route without route.uri", "no route.uri")
    fb("uriint", "route.uri is a number (42)", "bad route.uri")
    fb("urilist", "route.uri is a list", "bad route.uri")
    fb("uriobj", "route is a string, not an object", "no route.uri")
    fb("nocode", "action reject without code", "no code")
    fb("codestr", 'code is "abc"', "bad code")
    fb("codebool", "code is true", "bad code")
    fb("code200", "code 200 (not a rejection)", "bad code")
    inv, _ = fb("inject", "route.account with CR LF (header injection)", "bad route.account")
    sc.check("…no X-Injected header and no X-Account reached anyone",
             inv is not None and inv.get("x-injected") is None and inv.get("x-account") is None, inv and inv.raw)
    inv, _ = fb("injectreason", "a reject reason with CR LF", "bad reason")
    fb("status500", "webhook status 500 (even with a usable body)", "status 500")
    _, took = fb("slow", "webhook slower (3s) than the 2s timeout", "error")
    sc.check("…the call didn't wait for the slow webhook", took < 2.9, took)

    # --- Large: a 300 KB answer, and a 20 KB INVITE body in the event.
    r, cid, posts, _ = call("big")
    inv = (invites(uas, cid) or [None])[0]
    sc.check("a 300 KB JSON answer (action after the padding) → routed: 200, X-Account: big",
             r is not None and r.code == 200 and inv is not None and inv.get("x-account") == "big", r)
    big_sdp = sipkit.sdp(ua.port + 1000) + "".join(f"a=x-pad{i}:{'p' * 90} \"q\" \\ ü\r\n" for i in range(200))
    r, cid, posts, _ = call("plain", body=big_sdp)
    ev = event(posts)
    sc.check(f"a {len(big_sdp.encode()) // 1024} KB SDP with quotes, backslashes and UTF-8 → the event is valid JSON",
             isinstance(ev, dict), ev if not isinstance(ev, dict) else "")
    sc.check("…its sdp value equals the INVITE body byte for byte", isinstance(ev, dict) and ev.get("sdp") == big_sdp,
             isinstance(ev, dict) and len(ev.get("sdp") or ""))
    sc.check("…and the call is routed: 200", r is not None and r.code == 200 and invites(uas, cid), r)

    # --- The webhook down: the fallback at once.
    svc.close()
    time.sleep(0.3)
    _, took = fb("plain", "webhook down (connection refused)", "error")
    sc.check("…quickly (no waiting for the timeout)", took < 1.9, took)

    o = ua.request("OPTIONS", "sip:100@example.com")
    r = ua.final(call_id=o["call_id"])
    sc.check("an OPTIONS (not a call) → 405, no event", r is not None and r.code == 405, r)
