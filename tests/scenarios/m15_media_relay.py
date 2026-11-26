"""m15-media-relay: calls through a real media relay (rtpflux, ng protocol):
offer and answer rewritten to the relay, RTP both ways, hold and resume
re-INVITEs, BYE / CANCEL / 486 deleting the session, an SDP without media
lines and one with ICE candidates.

rtpflux: $RTPFLUX, else ../rtpflux/target/release/rtpflux (as in
tests/e2e_rtpflux.py); skipped without it."""
import os
import re
import socket
import subprocess
import time

import sipkit

RTPFLUX = os.environ.get("RTPFLUX") or os.path.join(os.path.dirname(sipkit.ROOT), "rtpflux/target/release/rtpflux")


# --- ng (bencode over UDP): the test's own view of the relay -------------

def benc(v):
    if isinstance(v, int):
        return b"i%de" % v
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, bytes):
        return b"%d:%s" % (len(v), v)
    if isinstance(v, list):
        return b"l" + b"".join(benc(x) for x in v) + b"e"
    return b"d" + b"".join(benc(k) + benc(x) for k, x in sorted(v.items())) + b"e"


def bdec(b, i=0):
    c = b[i:i + 1]
    if c == b"i":
        j = b.index(b"e", i)
        return int(b[i + 1:j]), j + 1
    if c in (b"l", b"d"):
        out, i = ([] if c == b"l" else {}), i + 1
        while b[i:i + 1] != b"e":
            x, i = bdec(b, i)
            if c == b"d":
                y, i = bdec(b, i)
                out[x.decode()] = y
            else:
                out.append(x)
        return out, i + 1
    j = b.index(b":", i)
    n = int(b[i:j])
    return b[j + 1:j + 1 + n], j + 1 + n


def ng(port, cmd):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        cookie = b"m15_%d" % (time.time_ns() % 10**9)
        s.sendto(cookie + b" " + benc(cmd), ("127.0.0.1", port))
        data = s.recv(65535)
        return bdec(data.split(b" ", 1)[1])[0]
    finally:
        s.close()


def listed(port, cid):
    """Is the call in the relay's `list`?"""
    return cid.encode() in ng(port, {"command": "list"}).get("calls", [])


# --- RTP -------------------------------------------------------------------

class Rtp:
    def __init__(self, port):
        self.port = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.seq = 0

    def send(self, to, payload, ssrc):
        self.seq += 1
        hdr = bytes([0x80, 0x00]) + self.seq.to_bytes(2, "big") + (self.seq * 160).to_bytes(4, "big") + ssrc.to_bytes(4, "big")
        self.s.sendto(hdr + payload, ("127.0.0.1", to))

    def recv(self, timeout=1.0):
        self.s.settimeout(timeout)
        try:
            return self.s.recvfrom(2048)
        except OSError:
            return None, None

    def drain(self):
        while self.recv(0.05)[0] is not None:
            pass

    def close(self):
        self.s.close()


def flow(src, dst, to_port, n=5, tag=b"A"):
    """Send n packets src → relay port `to_port`; how many reach dst intact,
    and from which addresses."""
    dst.drain()
    got, froms = 0, set()
    for i in range(n):
        payload = tag * 20 + bytes([i])
        src.send(to_port, payload, 0x1000 + src.port)
        end = time.time() + 1.0
        while time.time() < end:
            d, a = dst.recv(max(0.05, end - time.time()))
            if d is None:
                break
            if d[12:] == payload:
                got += 1
                froms.add(a)
                break
    return got, froms


# --- SDP ---------------------------------------------------------------------

def offer_sdp(port, direction="sendrecv", ice=False, sess=1, ver=1):
    s = (f"v=0\r\no=- {sess} {ver} IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
         f"m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na={direction}\r\n")
    if ice:
        s += ("a=ice-ufrag:F7gI\r\na=ice-pwd:x9cml/YzichV2+XlhiMu8g\r\n"
              f"a=candidate:1 1 UDP 2130706431 127.0.0.1 {port} typ host\r\n"
              f"a=candidate:2 1 UDP 1694498815 198.51.100.7 {port + 2} typ srflx raddr 127.0.0.1 rport {port}\r\n")
    return s


NO_MEDIA = "v=0\r\no=- 7 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"


def direction(body):
    m = re.search(r"a=(sendrecv|sendonly|recvonly|inactive)", body or "")
    return m.group(1) if m else None


def run(sc):
    if not os.path.exists(RTPFLUX):
        sc.skip("rtpflux not found")
    sip, ngp = sc.port(), sc.port()
    # The relay's RTP ports, from this scenario's block: even start, 32 ports.
    p = sc.port()
    if p % 2:
        p = sc.port()
    rng = [p] + [sc.port() for _ in range(31)]
    pmin, pmax = rng[0], rng[-1]
    cfg = os.path.join(sc.tmp, "rtpflux.toml")
    open(cfg, "w").write(f"""[control]
listen = ["127.0.0.1:{ngp}"]

[[interface]]
name = "default"
address = "127.0.0.1"

[ports]
min = {pmin}
max = {pmax}

[sessions]
max = 8
timeout = 60

[runtime]
workers = 2
""")
    chk = subprocess.run([RTPFLUX, "--check", "-c", cfg], capture_output=True, text=True, timeout=30)
    sc.check("rtpflux --check accepts its config", chk.returncode == 0, chk.stdout + chk.stderr)
    relay = subprocess.Popen([RTPFLUX, "-c", cfg], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    sc.closers.append(relay.terminate)
    for _ in range(50):
        try:
            if ng(ngp, {"command": "ping"}).get("result") == b"pong":
                break
        except OSError:
            time.sleep(0.1)
    sc.check("rtpflux answers an ng ping", ng(ngp, {"command": "ping"}).get("result") == b"pong")

    rtp_a, rtp_b = Rtp(sc.port()), Rtp(sc.port())
    sc.closers += [rtp_a.close, rtp_b.close]
    in_range = lambda port: port is not None and pmin <= port <= pmax  # noqa: E731

    # bob answers with his RTP port, mirroring the offer's direction
    # (sendonly → recvonly), and SDP-less for an SDP-less offer.
    bob = sc.ua("bob", sip)

    def bob_h(m):
        if m.method == "INVITE":
            d = direction(m.body)
            ans = {"sendonly": "recvonly", "recvonly": "sendonly", "inactive": "inactive"}.get(d, "sendrecv")
            if "m=" in m.body:
                body = offer_sdp(rtp_b.port, ans, sess=2, ver=len([x for x in bob.received if x.get("call-id") == m.get("call-id")]))
            else:
                body = NO_MEDIA
            bob.respond(m, 200, "OK", body=body)
            return None
        if m.method in ("BYE", "OPTIONS"):
            return (200, "OK")
        return None
    bob.handler = bob_h
    busy = sc.ua("busy", sip).auto_answer(486, "Busy Here")
    ringer = sc.ua("ringer", sip).auto_answer(code=None, ring=True)
    sc.proxy(env=sc.env(SIP_PORT=sip, MEDIA_RELAY=f"udp:127.0.0.1:{ngp}"))
    alice = sc.ua("alice", sip)

    def last_invite(u, cid):
        return next((m for m in reversed(u.received) if m.method == "INVITE" and m.get("call-id") == cid), None)

    # --- A call: the offer and the answer go through the relay.
    r, d = alice.call(f"sip:bob@127.0.0.1:{bob.port}", body=offer_sdp(rtp_a.port), timeout=8)
    sc.check("alice → bob through the relay: 200", r is not None and r.code == 200 and d is not None, r)
    if d is None:
        return
    cid = d.call_id
    inv = last_invite(bob, cid)
    addr_b, port_b = inv.sdp_media() if inv else (None, None)
    sc.check("the offer bob gets points at the relay: 127.0.0.1 and a port from rtpflux's range",
             addr_b == "127.0.0.1" and in_range(port_b) and port_b != rtp_a.port, (addr_b, port_b))
    sc.check("…Content-Length of the INVITE matches the rewritten SDP",
             inv is not None and int(inv.get("content-length")) == len(inv.body.encode()), inv and inv.raw)
    addr_a, port_a = r.sdp_media()
    sc.check("the answer alice gets points at the relay too, on another relay port",
             addr_a == "127.0.0.1" and in_range(port_a) and port_a not in (port_b, rtp_b.port), (addr_a, port_a))
    sc.check("…Content-Length of the 200 matches the rewritten SDP", int(r.get("content-length")) == len(r.body.encode()), r.raw)
    sc.check("rtpflux lists the call while it is up", listed(ngp, cid))

    got, froms = flow(rtp_a, rtp_b, port_a, tag=b"A")
    sc.check(f"RTP alice → relay → bob: {got}/5 packets, payload intact, from the relay's port",
             got >= 4 and froms == {("127.0.0.1", port_b)}, (got, froms))
    got, froms = flow(rtp_b, rtp_a, port_b, tag=b"B")
    sc.check(f"RTP bob → relay → alice: {got}/5 packets, payload intact, from the relay's port",
             got >= 4 and froms == {("127.0.0.1", port_a)}, (got, froms))

    # --- Hold (a=sendonly) and resume, by re-INVITE from alice.
    def reinvite(dirn, ver):
        sent = d.request("INVITE", body=offer_sdp(rtp_a.port, dirn, ver=ver))
        rr = alice.final(8, method="INVITE", call_id=cid, cseq=sent["cseq"])
        if rr is not None and rr.code < 300:
            d.request("ACK", cseq=sent["cseq"])
        return rr, last_invite(bob, cid)

    rr, inv2 = reinvite("sendonly", 2)
    sc.check("hold: re-INVITE a=sendonly → 200", rr is not None and rr.code == 200, rr)
    sc.check("…bob gets a=sendonly, on the same relay port as before",
             inv2 is not None and inv2 is not inv and direction(inv2.body) == "sendonly" and inv2.sdp_media() == ("127.0.0.1", port_b),
             inv2 and inv2.body)
    sc.check("…alice gets bob's a=recvonly, on the same relay port as before",
             rr is not None and direction(rr.body) == "recvonly" and rr.sdp_media() == ("127.0.0.1", port_a), rr and rr.body)
    got, _ = flow(rtp_a, rtp_b, port_a, tag=b"H")
    sc.check(f"…on hold alice's RTP (sendonly) still reaches bob: {got}/5", got >= 4, got)

    rr, inv3 = reinvite("sendrecv", 3)
    sc.check("resume: re-INVITE a=sendrecv → 200, both sides back to sendrecv on the same relay ports",
             rr is not None and rr.code == 200 and direction(rr.body) == "sendrecv" and rr.sdp_media() == ("127.0.0.1", port_a)
             and inv3 is not None and direction(inv3.body) == "sendrecv" and inv3.sdp_media() == ("127.0.0.1", port_b),
             (rr and rr.body, inv3 and inv3.body))
    got1, _ = flow(rtp_a, rtp_b, port_a, tag=b"R")
    got2, _ = flow(rtp_b, rtp_a, port_b, tag=b"S")
    sc.check(f"…after resume RTP flows both ways again ({got1}/5, {got2}/5)", got1 >= 4 and got2 >= 4, (got1, got2))

    # --- BYE deletes the session.
    bye = d.bye(timeout=4)
    sc.check("BYE → 200", bye is not None and bye.code == 200, bye)
    time.sleep(0.3)
    sc.check("…the BYE deleted the session: rtpflux no longer lists the call", not listed(ngp, cid))
    got, _ = flow(rtp_a, rtp_b, port_a, n=2, tag=b"L")
    sc.check("…and no RTP is relayed any more", got == 0, got)

    # --- CANCEL while ringing: the offer is deleted.
    sent = alice.invite(f"sip:ringer@127.0.0.1:{ringer.port}", body=offer_sdp(rtp_a.port))
    ring = alice.recv(6, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == sent["call_id"])
    sc.check("a call to a phone that rings: 180", ring is not None, ring)
    sc.check("…the offer created a session in rtpflux", listed(ngp, sent["call_id"]))
    alice.cancel(sent)
    c = alice.final(4, method="CANCEL", call_id=sent["call_id"])
    r = alice.final(6, method="INVITE", call_id=sent["call_id"])
    sc.check("CANCEL → 200 for the CANCEL, 487 for the INVITE", c is not None and c.code == 200 and r is not None and r.code == 487, (c, r))
    if r is not None:
        alice._ack_neg(sent, r)
    time.sleep(0.3)
    sc.check("…the canceled call's session is deleted in rtpflux", not listed(ngp, sent["call_id"]),
             ng(ngp, {"command": "list"}))

    # --- 486 Busy: the offer is deleted.
    r, _ = alice.call(f"sip:busy@127.0.0.1:{busy.port}", body=offer_sdp(rtp_a.port), timeout=8)
    bcid = r.get("call-id") if r is not None else None
    sc.check("a call to a busy phone: 486 reaches alice", r is not None and r.code == 486, r)
    time.sleep(0.3)
    sc.check("…the failed call's session is deleted in rtpflux", bcid is not None and not listed(ngp, bcid), ng(ngp, {"command": "list"}))

    # --- An SDP without media lines (RFC 4566 allows zero m= lines).
    r, d2 = alice.call(f"sip:bob@127.0.0.1:{bob.port}", body=NO_MEDIA, timeout=8)
    inv = last_invite(bob, d2.call_id if d2 else (r.get("call-id") if r is not None else ""))
    sc.check("an SDP offer with no m= line → the call still goes through: 200", r is not None and r.code == 200, r)
    sc.check("…bob gets an SDP with no m= line either", inv is not None and inv.body.startswith("v=0") and "m=" not in inv.body,
             inv and inv.body)
    if d2:
        b2 = d2.bye(timeout=4)
        time.sleep(0.3)
        sc.check("…its BYE → 200 and the session is gone", b2 is not None and b2.code == 200 and not listed(ngp, d2.call_id), b2)

    # --- An offer with ICE candidates: ICE=remove takes them out.
    r, d3 = alice.call(f"sip:bob@127.0.0.1:{bob.port}", body=offer_sdp(rtp_a.port, ice=True), timeout=8)
    inv = last_invite(bob, d3.call_id) if d3 else None
    sc.check("an offer with ICE candidates → 200", r is not None and r.code == 200 and inv is not None, r)
    body = inv.body if inv else ""
    sc.check("…bob's SDP has no a=candidate, a=ice-ufrag or a=ice-pwd (ICE=remove)",
             inv is not None and not re.search(r"a=(candidate|ice-ufrag|ice-pwd)", body), body)
    sc.check("…and no trace of the caller's srflx address 198.51.100.7", inv is not None and "198.51.100.7" not in body, body)
    ia, ip_ = inv.sdp_media() if inv else (None, None)
    sc.check("…its media still points at the relay", ia == "127.0.0.1" and in_range(ip_), (ia, ip_))
    if d3:
        got, _ = flow(rtp_a, rtp_b, r.sdp_media()[1], tag=b"I")
        sc.check(f"…and RTP goes through ({got}/5)", got >= 4, got)
        d3.bye(timeout=4)
        time.sleep(0.3)
        sc.check("…its BYE deletes the session", not listed(ngp, d3.call_id))

    # --- The callee hangs up: the BYE comes from bob's side (his tag is
    # the From tag of the delete).
    r, d4 = alice.call(f"sip:bob@127.0.0.1:{bob.port}", body=offer_sdp(rtp_a.port), timeout=8)
    inv = last_invite(bob, d4.call_id) if d4 else None
    sc.check("another call alice → bob: 200, in rtpflux", r is not None and r.code == 200 and d4 is not None and listed(ngp, d4.call_id), r)
    if inv is not None:
        btag = bob.tags.get((inv.get("call-id"), inv.tag("from")))
        sent = bob.request("BYE", sipkit.uri_of(inv.get("contact")), to=inv.get("from"), call_id=d4.call_id, from_tag=btag, cseq=1,
                           headers={"Route": ", ".join(inv.all("record-route"))})
        got = alice.request_in("BYE", timeout=4)
        if got is not None:
            alice.respond(got, 200)
        b = bob.final(4, method="BYE", call_id=d4.call_id, cseq=sent["cseq"])
        sc.check("bob hangs up: the BYE reaches alice, 200 back to bob", got is not None and b is not None and b.code == 200, (got, b))
        time.sleep(0.3)
        sc.check("…the callee's BYE deleted the session too", not listed(ngp, d4.call_id), ng(ngp, {"command": "list"}))

    sc.check("no session left in rtpflux at the end", ng(ngp, {"command": "list"}).get("calls") == [], ng(ngp, {"command": "list"}))
    relay.terminate()
    try:
        err = relay.communicate(timeout=10)[1]
    except subprocess.TimeoutExpired:
        relay.kill()
        err = relay.communicate()[1]
    sc.check("rtpflux ran without errors or panics", " ERROR " not in err and "panicked" not in err, err[-1500:])

    # --- The relay is down: the offer fails, the call is refused, bob never
    # sees it (2 tries of 1s, rtpengine_retr = 2).
    n = len(bob.received)
    t0 = time.time()
    r, _ = alice.call(f"sip:bob@127.0.0.1:{bob.port}", body=offer_sdp(rtp_a.port), timeout=10)
    took = time.time() - t0
    sc.check("media relay down → 500 Media relay failed", r is not None and r.code == 500 and r.reason == "Media relay failed", r)
    sc.check("…bob never got the INVITE", not [m for m in bob.received[n:] if m.method == "INVITE"], bob.received[n:])
    sc.check("…within the ng retries (well under 8s)", took < 8, took)
