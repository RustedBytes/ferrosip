"""s06-message-edits: text module header/body edits, R-URI user rewrites,
Content-Length after every edit, 8 KB headers."""
import sipkit


def cl_ok(m):
    """Exactly one Content-Length (long or compact form), equal to the body's bytes."""
    if m is None:
        return False
    cls = m.all("content-length")
    return len(cls) == 1 and cls[0].strip().isdigit() and int(cls[0]) == len(m.body.encode())


def cl_info(m):
    return None if m is None else (m.all("content-length"), len(m.body.encode()), m.raw[-400:])


def run(sc):
    sip = sc.port()
    up = sc.ua("upstream", sip)

    def h(m):
        if m.method == "ACK":
            return None
        body = sipkit.sdp(up.port + 1000) if m.method == "INVITE" else ""
        return (200, "OK", {"X-Internal": "pbx-node-7"}, body)
    up.handler = h
    sc.proxy(env=sc.env(SIP_PORT=sip, UPSTREAM=f"sip:127.0.0.1:{up.port}"))
    ua = sc.ua("alice", sip)

    def at_up(cid, method=None):
        ms = [m for m in up.received if m.get("call-id") == cid and (method is None or m.method == method)]
        return ms[0] if ms else None

    # --- headers, R-URI user and body in one MESSAGE.
    body = "pay with 1234-5678-9012-3456 please"
    r = ua.request("MESSAGE", "sip:0301234567@example.com", body=body, content_type="text/plain",
                   headers={"X-Secret": ["token-1", "token-2"], "X-Tenant": "evil"})
    rep = ua.final(call_id=r["call_id"])
    m = at_up(r["call_id"])
    sc.check("MESSAGE relayed", m is not None, up.received)
    m = m or sipkit.Msg("X / SIP/2.0\r\n\r\n")
    sc.check("both X-Secret headers are removed", not m.all("x-secret"), m.raw)
    sc.check("X-Proxy: s06 is added once", m.all("x-proxy") == ["s06"], m.all("x-proxy"))
    sc.check("X-Tenant is replaced (one header, value acme), not appended", m.all("x-tenant") == ["acme"], m.all("x-tenant"))
    sc.check("R-URI user 0301234567 → +49301234567 (subst_user)", m.ruri == "sip:+49301234567@example.com", m.ruri)
    sc.check("the card number in the body is masked", m.body == "pay with XXXX-XXXX-XXXX-XXXX please", m.body)
    sc.check("Content-Length matches the edited body", cl_ok(m), cl_info(m))
    sc.check("the reply comes back without X-Internal (on reply edit)", rep is not None and rep.code == 200 and rep.get("x-internal") is None,
             rep and rep.raw)
    sc.check("…with X-Replied-Via added and a correct Content-Length", rep is not None and rep.get("x-replied-via") == "s06" and cl_ok(rep),
             rep and rep.raw)

    # --- header names are case-insensitive: x-SECRET is removed too, X-TENANT replaced.
    r = ua.request("OPTIONS", "sip:bob@example.com", headers={"x-SECRET": "t", "X-TENANT": "evil"})
    ua.final(call_id=r["call_id"])
    m = at_up(r["call_id"])
    sc.check("remove_header(\"X-Secret\") also removes x-SECRET", m is not None and not m.all("x-secret"), m and m.raw)
    sc.check("msg.headers[\"X-Tenant\"] = … also replaces X-TENANT", m is not None and m.all("x-tenant") == ["acme"], m and m.all("x-tenant"))

    # --- an alias R-URI user; no body.
    r = ua.request("OPTIONS", "sip:support@example.com")
    ua.final(call_id=r["call_id"])
    m = at_up(r["call_id"])
    sc.check("R-URI user support → alice (msg.ruri.user =)", m is not None and m.ruri == "sip:alice@example.com", m and m.ruri)
    sc.check("…To is untouched (only the R-URI changes)", m is not None and "support@example.com" in (m.get("to") or ""), m and m.get("to"))
    sc.check("…Content-Length 0 kept", m is not None and cl_ok(m) and m.body == "", cl_info(m))

    # --- UTF-8 before the edit: Content-Length counts bytes.
    body = "größe: 1111-2222-3333-4444 ✓"
    r = ua.request("MESSAGE", "sip:bob@example.com", body=body, content_type="text/plain; charset=utf-8")
    ua.final(call_id=r["call_id"])
    m = at_up(r["call_id"])
    sc.check("UTF-8 body: masked, multibyte characters intact", m is not None and m.body == "größe: XXXX-XXXX-XXXX-XXXX ✓", m and m.body)
    sc.check("…Content-Length in bytes", cl_ok(m), cl_info(m))

    # --- compact header forms (l:, c:, i:): still one correct Content-Length after the edit.
    cid = f"compact-{sipkit.rnd(8)}"
    body = "card 9999-8888-7777-6666"
    raw = (f"MESSAGE sip:bob@example.com SIP/2.0\r\nv: {ua.via(sipkit.rnd(10))}\r\nf: <{ua.aor}>;tag={sipkit.rnd(6)}\r\n"
           f"t: <sip:bob@example.com>\r\ni: {cid}\r\nCSeq: 1 MESSAGE\r\nMax-Forwards: 70\r\nc: text/plain\r\n"
           f"l: {len(body)}\r\n\r\n{body}")
    ua.send(raw)
    ua.final(call_id=cid)
    m = at_up(cid)
    sc.check("compact headers: the body is masked", m is not None and m.body == "card XXXX-XXXX-XXXX-XXXX", m and m.raw)
    sc.check("…and exactly one Content-Length/l:, matching it", cl_ok(m), cl_info(m))

    # --- SDP: every c= line rewritten (session and media level), lengths change.
    sdp = ("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
           "m=audio 40000 RTP/AVP 0\r\nc=IN IP4 10.1.2.3\r\na=sendrecv\r\n")
    r, d = ua.call("sip:bob@example.com", body=sdp)
    m = None
    if d:
        m = at_up(d.call_id, "INVITE")
        d.bye()
    sc.check("INVITE with SDP → 200", r is not None and r.code == 200, r)
    sc.check("both c= lines carry the media address", m is not None and m.body.count("c=IN IP4 203.0.113.200") == 2
             and "10.1.2.3" not in m.body and "o=- 1 1 IN IP4 127.0.0.1" in m.body, m and m.body)
    sc.check("…Content-Length matches the longer SDP", cl_ok(m), cl_info(m))
    sc.check("the 200's SDP is not edited (requests only) and its Content-Length is right",
             r is not None and "203.0.113.200" not in r.body and cl_ok(r), r and r.raw)

    # --- set_body on a request without a body.
    r = ua.request("OPTIONS", "sip:bob@example.com", headers={"X-Set-Body": "1"})
    ua.final(call_id=r["call_id"])
    m = at_up(r["call_id"])
    sc.check("set_body on a bodiless OPTIONS: the new body arrives", m is not None and m.body == "replaced by the proxy\n", m and m.raw)
    sc.check("…with Content-Type text/plain and Content-Length 22",
             m is not None and m.all("content-type") == ["text/plain"] and cl_ok(m) and m.get("content-length") == "22", cl_info(m))

    # --- set_body over a body that was already edited (replace_body_all first): the last edit wins.
    r = ua.request("MESSAGE", "sip:bob@example.com", body="card 1234-5678-9012-3456", content_type="text/plain", headers={"X-Set-Body": "1"})
    ua.final(call_id=r["call_id"])
    m = at_up(r["call_id"])
    sc.check("replace_body_all then set_body: the body is set_body's, once", m is not None and m.body == "replaced by the proxy\n", m and m.raw)
    sc.check("…one Content-Type and a correct Content-Length", m is not None and len(m.all("content-type")) == 1 and cl_ok(m), cl_info(m))

    # --- remove_body.
    r = ua.request("MESSAGE", "sip:bob@example.com", body="to be dropped", content_type="text/plain", headers={"X-Drop-Body": "1"})
    ua.final(call_id=r["call_id"])
    m = at_up(r["call_id"])
    sc.check("remove_body: empty body, Content-Length 0", m is not None and m.body == "" and m.get("content-length") == "0", cl_info(m))

    # --- an 8 KB header: relayed intact, copied by the script into X-Echo, body edits still right.
    long = "".join(sipkit.rnd(64) for _ in range(128))  # 8192 chars
    r = ua.request("MESSAGE", "sip:bob@example.com", body="card 1234-5678-9012-3456", content_type="text/plain", headers={"X-Long": long})
    rep = ua.final(call_id=r["call_id"])
    m = at_up(r["call_id"])
    sc.check("a request with an 8 KB header is relayed (200 back)", m is not None and rep is not None and rep.code == 200, rep)
    sc.check("…the 8 KB header arrives intact", m is not None and m.get("x-long") == long, m and len(m.get("x-long") or ""))
    sc.check("…msg.headers[\"X-Echo\"] = msg.headers[\"X-Long\"] copies all 8 KB", m is not None and m.get("x-echo") == long,
             m and len(m.get("x-echo") or ""))
    sc.check("…the body edit and Content-Length are still right", m is not None and m.body == "card XXXX-XXXX-XXXX-XXXX" and cl_ok(m), cl_info(m))

    # --- an 8 KB header in the reply: the reply edit keeps it, and the Content-Length.
    up.handler = lambda m: None if m.method == "ACK" else (200, "OK", {"X-Internal": "x", "X-Big": long}, "")
    r = ua.request("OPTIONS", "sip:bob@example.com")
    rep = ua.final(call_id=r["call_id"])
    sc.check("a reply with an 8 KB header: edited (X-Internal gone) and the 8 KB header intact",
             rep is not None and rep.get("x-internal") is None and rep.get("x-big") == long and cl_ok(rep), rep and rep.first)
