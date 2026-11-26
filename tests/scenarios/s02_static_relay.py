"""s02-static-relay: everything to one upstream; Via/rport handling, a silent
upstream (408 after fr_timer / fr_inv_timer) and a closed upstream port."""
import time

import sipkit


def raw_request(ua, method, ruri, via, call_id=None, cseq=1, body="", extra=()):
    """Send a request with a hand-written top Via; returns its Call-ID."""
    call_id = call_id or f"{sipkit.rnd(10)}@127.0.0.1"
    hs = [f"Via: {via}", f"From: <{ua.aor}>;tag={sipkit.rnd(8)}", f"To: <{ruri}>", f"Call-ID: {call_id}",
          f"CSeq: {cseq} {method}", "Max-Forwards: 70", *extra]
    if body:
        hs.append("Content-Type: text/plain")
    hs.append(f"Content-Length: {len(body.encode())}")
    ua.send(f"{method} {ruri} SIP/2.0\r\n" + "\r\n".join(hs) + "\r\n\r\n" + body)
    return call_id


def upstream(sc, sip, mode):
    """The upstream: answers by `mode['next']` (200, silent, ring)."""
    up = sc.ua("upstream", sip)

    def h(m):
        what = mode.get("next", "200")
        if m.method == "ACK":
            return None
        if m.method == "CANCEL":
            up.respond(m, 200)
            inv = next((x for x in reversed(up.received) if x.method == "INVITE" and x.get("call-id") == m.get("call-id")), None)
            if inv is not None:
                up.respond(inv, 487, "Request Terminated")
            return None
        if what == "silent":
            return None
        if what == "ring" and m.method == "INVITE":
            up.respond(m, 180, "Ringing")
            return None
        return (200, "OK")
    up.handler = h
    return up


def got(up, cid, method=None):
    return [m for m in up.received if m.get("call-id") == cid and (method is None or m.method == method)]


def branches(msgs):
    return {m.all("via")[0] for m in msgs}


def run(sc):
    sip, sip_closed, sip_untrusted, closed = sc.port(), sc.port(), sc.port(), sc.port()
    mode = {}
    up = upstream(sc, sip, mode)
    sc.proxy(env=sc.env(SIP_PORT=sip, UPSTREAM=f"sip:127.0.0.1:{up.port}"), name="relay")
    ua = sc.ua("alice", sip)
    witness = sc.ua("witness", sip)  # gets replies sent to a Via port that isn't the source port

    # --- the plain relay: Via on top, Max-Forwards decremented, Via stripped on the way back.
    mode["next"] = "200"
    r = ua.request("MESSAGE", "sip:bob@example.com", body="hello", content_type="text/plain")
    rep = ua.final(call_id=r["call_id"])
    fwd = got(up, r["call_id"])
    sc.check("MESSAGE is relayed to the upstream", len(fwd) >= 1, up.received)
    vias = fwd[0].all("via") if fwd else []
    sc.check("the relayed MESSAGE has two Vias, the proxy's on top", len(vias) == 2 and f"127.0.0.1:{sip}" in vias[0], vias)
    sc.check("the proxy's Via has a z9hG4bK branch", vias and ";branch=z9hG4bK" in vias[0], vias)
    sc.check("the UA's Via (with ;rport) gets rport=<source port> filled in (RFC 3581)",
             len(vias) == 2 and f"rport={ua.port}" in vias[1], vias)
    sc.check("…and received=127.0.0.1 (RFC 3581 §4: MUST, even when equal to sent-by)",
             len(vias) == 2 and "received=127.0.0.1" in vias[1], vias)
    sc.check("Max-Forwards 70 → 69", fwd and fwd[0].get("max-forwards") == "69", fwd and fwd[0].raw)
    sc.check("the upstream's 200 comes back with the proxy's Via removed",
             rep is not None and rep.code == 200 and len(rep.all("via")) == 1 and f":{ua.port}" in rep.all("via")[0], rep and rep.raw)

    # --- rport: sent-by names a port nobody listens on; with ;rport the reply goes to the source port.
    cid = raw_request(ua, "OPTIONS", "sip:bob@example.com", f"SIP/2.0/UDP ua.invalid:9;branch=z9hG4bK{sipkit.rnd(10)};rport")
    rep = ua.final(call_id=cid)
    sc.check("Via with ;rport and a bogus sent-by: the reply comes back to the source address", rep is not None and rep.code == 200, rep)
    fwd = got(up, cid)
    v = fwd[0].all("via")[1] if fwd and len(fwd[0].all("via")) == 2 else ""
    sc.check("…and the relayed Via carries received=127.0.0.1;rport=<source port>",
             "received=127.0.0.1" in v and f"rport={ua.port}" in v, v)

    # --- no rport: ferrosip still answers the source address (symmetric
    # response routing, as if force_rport() were always on; docs/sip.md).
    # RFC 3261 §18.2.2 and Kamailio would use the sent-by port here.
    cid = raw_request(ua, "OPTIONS", "sip:bob@example.com", f"SIP/2.0/UDP 127.0.0.1:{witness.port};branch=z9hG4bK{sipkit.rnd(10)}")
    rep = ua.final(call_id=cid)
    sc.check("Via without rport: the reply still goes to the source port (symmetric, as documented)", rep is not None and rep.code == 200, rep)
    sc.check("…and not to the sent-by port", witness.final(0.5, call_id=cid) is None)
    fwd = got(up, cid)
    v = fwd[0].all("via")[1] if fwd and len(fwd[0].all("via")) == 2 else ""
    sc.check("…the relayed Via is left alone (sent-by matches the source IP, no rport asked)",
             "received=" not in v and "rport" not in v, v)

    # --- a host name as sent-by (no rport): the proxy must add received= (RFC 3261 §18.2.1).
    cid = raw_request(ua, "OPTIONS", "sip:bob@example.com", f"SIP/2.0/UDP ua.invalid:{ua.port};branch=z9hG4bK{sipkit.rnd(10)}")
    ua.final(1.5, call_id=cid)
    fwd = got(up, cid)
    v = fwd[0].all("via")[1] if fwd and len(fwd[0].all("via")) == 2 else ""
    sc.check("Via sent-by is a host name: the relayed Via gets received=127.0.0.1 (RFC 3261 §18.2.1)",
             "received=127.0.0.1" in v, v)

    # --- a silent upstream: a non-INVITE gets 408 after fr_timer (1s), retransmitted meanwhile.
    mode["next"] = "silent"
    t0 = time.time()
    r = ua.request("MESSAGE", "sip:bob@example.com", body="anyone?", content_type="text/plain")
    rep = ua.final(5, call_id=r["call_id"])
    dt = time.time() - t0
    sc.check("silent upstream: MESSAGE → 408", rep is not None and rep.code == 408, rep)
    sc.check("…after about fr_timer (0.8s..2.5s)", 0.8 <= dt <= 2.5, f"{dt:.2f}s")
    fwd = got(up, r["call_id"], "MESSAGE")
    sc.check("…the proxy retransmitted over UDP (≥2 copies, one branch)", len(fwd) >= 2 and len(branches(fwd)) == 1,
             [m.all("via")[0] for m in fwd])

    # INVITE, no provisional at all: 100 from the proxy, then 408 after fr_timer (not fr_inv_timer).
    t0 = time.time()
    sent = ua.invite("sip:bob@example.com")
    trying = ua.recv(2, lambda m: m.is_reply and m.code == 100 and m.get("call-id") == sent["call_id"])
    sc.check("silent upstream: the INVITE gets the proxy's own 100 Trying", trying is not None, trying)
    rep = ua.final(5, method="INVITE", call_id=sent["call_id"])
    dt = time.time() - t0
    sc.check("…then 408 after about fr_timer (0.8s..2.5s), not fr_inv_timer",
             rep is not None and rep.code == 408 and 0.8 <= dt <= 2.5, (rep, f"{dt:.2f}s"))
    if rep is not None:
        ua._ack_neg(sent, rep)
    time.sleep(0.5)
    sc.check("…the caller's ACK to the 408 is absorbed, not relayed upstream", not got(up, sent["call_id"], "ACK"),
             got(up, sent["call_id"], "ACK"))
    sc.check("…and no CANCEL goes upstream (nothing was provisional there)", not got(up, sent["call_id"], "CANCEL"))

    # INVITE that rings then goes silent: fr_inv_timer (3s) → 408 to the caller, CANCEL upstream (RFC 3261 §16.8 timer C).
    mode["next"] = "ring"
    t0 = time.time()
    sent = ua.invite("sip:bob@example.com")
    ring = ua.recv(2, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == sent["call_id"])
    sc.check("ringing upstream: 180 reaches the caller", ring is not None, ring)
    rep = ua.final(7, method="INVITE", call_id=sent["call_id"])
    dt = time.time() - t0
    sc.check("…no answer → 408 after about fr_inv_timer (2.5s..5s)", rep is not None and rep.code == 408 and 2.5 <= dt <= 5,
             (rep, f"{dt:.2f}s"))
    if rep is not None:
        ua._ack_neg(sent, rep)
    time.sleep(0.5)
    sc.check("…and the upstream gets a CANCEL for the ringing branch", len(got(up, sent["call_id"], "CANCEL")) >= 1,
             [m.first for m in got(up, sent["call_id"])])

    # CANCEL from the caller while the upstream rings: 487, CANCEL relayed.
    sent = ua.invite("sip:bob@example.com")
    ring = ua.recv(2, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == sent["call_id"])
    ua.cancel(sent)
    c200 = ua.recv(3, lambda m: m.is_reply and m.cseq_method == "CANCEL" and m.get("call-id") == sent["call_id"])
    rep = ua.final(4, method="INVITE", call_id=sent["call_id"])
    sc.check("caller CANCELs a ringing call: 200 for the CANCEL, 487 for the INVITE",
             c200 is not None and c200.code == 200 and rep is not None and rep.code == 487, (c200, rep))
    sc.check("…and the CANCEL reaches the upstream", len(got(up, sent["call_id"], "CANCEL")) >= 1)
    if rep is not None:
        ua._ack_neg(sent, rep)

    # --- the upstream's port is closed (ICMP port unreachable). UDP send
    # errors aren't reported back, so the branch times out after fr_timer
    # (1s here) with a 408, as in Kamailio; RFC 3261 §18.4 only says SHOULD.
    sc.proxy(env=sc.env(SIP_PORT=sip_closed, UPSTREAM=f"sip:127.0.0.1:{closed}"), name="relay-closed")
    ua2 = sc.ua("alice", sip_closed)
    t0 = time.time()
    r = ua2.request("MESSAGE", "sip:bob@example.com", body="x", content_type="text/plain")
    rep = ua2.final(5, call_id=r["call_id"])
    dt = time.time() - t0
    sc.check("closed upstream port (ICMP unreachable): MESSAGE gets 408 after fr_timer (1s), as in Kamailio",
             rep is not None and rep.code == 408 and 0.8 < dt < 3, (rep, f"{dt:.2f}s"))
    t0 = time.time()
    sent = ua2.invite("sip:bob@example.com")
    rep = ua2.final(5, method="INVITE", call_id=sent["call_id"])
    dt = time.time() - t0
    sc.check("closed upstream port (ICMP unreachable): INVITE gets 408 after fr_timer (no 1xx came)",
             rep is not None and rep.code == 408 and 0.8 < dt < 3, (rep, f"{dt:.2f}s"))
    if rep is not None:
        ua2._ack_neg(sent, rep)

    # --- an untrusted source: 403, nothing relayed.
    sc.proxy(env=sc.env(SIP_PORT=sip_untrusted, UPSTREAM=f"sip:127.0.0.1:{up.port}", TRUSTED="192.0.2.0/24"), name="relay-untrusted")
    ua3 = sc.ua("mallory", sip_untrusted)
    mode["next"] = "200"
    r = ua3.request("OPTIONS", "sip:bob@example.com")
    rep = ua3.final(call_id=r["call_id"])
    sc.check("a source outside TRUSTED → 403 Not trusted", rep is not None and rep.code == 403 and rep.reason == "Not trusted", rep)
    sc.check("…and nothing is relayed", not got(up, r["call_id"]))

    # --- [core] force_rport = false: as in Kamailio (RFC 3261 §18.2.2), a
    # UDP reply goes to the Via sent-by port unless the Via has ;rport.
    sip_strict = sc.port()
    sc.proxy(env=sc.env(SIP_PORT=sip_strict, UPSTREAM=f"sip:127.0.0.1:{up.port}"), extra=("--set", "core.force_rport=false"), name="relay-strict")
    ua4 = sc.ua("carol", sip_strict)
    mode["next"] = "200"
    cid = raw_request(ua4, "OPTIONS", "sip:bob@example.com", f"SIP/2.0/UDP 127.0.0.1:{witness.port};branch=z9hG4bK{sipkit.rnd(10)}")
    rep = witness.final(call_id=cid)
    sc.check("force_rport = false, Via without rport: the reply goes to the sent-by port (the witness)", rep is not None and rep.code == 200, rep)
    sc.check("…and not to the source port", ua4.final(0.5, call_id=cid) is None)
    cid = raw_request(ua4, "OPTIONS", "sip:bob@example.com", f"SIP/2.0/UDP 127.0.0.1:{witness.port};branch=z9hG4bK{sipkit.rnd(10)};rport")
    rep = ua4.final(call_id=cid)
    sc.check("force_rport = false, Via with ;rport: the reply goes to the source port", rep is not None and rep.code == 200, rep)
