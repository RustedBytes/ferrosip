"""s09-transports: UDP, TCP, TLS and WS listeners; calls across transports
(double Record-Route), an outbound TCP connection for ;transport=tcp,
large messages and TCP framing."""
import os
import queue
import re
import socket
import subprocess
import threading
import time

import sipkit


class _TcpServer:
    """A listening TCP socket for a UA the proxy must connect to (the kit's
    UAs only connect out). Messages are framed by Content-Length; replies go
    back on the connection the last message came in on."""
    proto = "TCP"

    def __init__(self, port):
        self.ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", port))
        self.ls.listen(8)
        self.inq, self.conns, self.last = queue.Queue(), [], None
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, a = self.ls.accept()
            except OSError:
                return
            self.conns.append(c)
            threading.Thread(target=self._conn, args=(c, a), daemon=True).start()

    def _conn(self, c, a):
        buf = b""
        while True:
            i = buf.find(b"\r\n\r\n")
            if i >= 0:
                m = re.search(rb"(?im)^(?:content-length|l)\s*:\s*(\d+)", buf[:i])
                n = int(m.group(1)) if m else 0
                if len(buf) >= i + 4 + n:
                    msg, buf = buf[:i + 4 + n], buf[i + 4 + n:]
                    self.last = c
                    self.inq.put((msg.lstrip(b"\r\n"), a))
                    continue
            try:
                d = c.recv(65536)
            except OSError:
                return
            if not d:
                return
            buf += d

    def read(self):
        while True:
            item = self.inq.get()
            if item is None:
                return
            yield item

    def send(self, data, to=None):
        self.last.sendall(data)

    def close(self):
        self.inq.put(None)
        for s in [self.ls, *self.conns]:
            try:
                s.close()
            except OSError:
                pass


def tcp_listener_ua(sc, user, proxy_port):
    """A sipkit.UA whose transport is a TCP *server* (local kit helper)."""
    ua = sipkit.UA.__new__(sipkit.UA)
    ua.user, ua.port, ua.proxy, ua.domain, ua.password = user, sc.port(), ("127.0.0.1", proxy_port), "example.com", None
    ua.transport = "tcp"
    ua.t = _TcpServer(ua.port)
    ua.q, ua.handler, ua.received, ua.nc, ua.tags = queue.Queue(), None, [], {}, {}
    threading.Thread(target=ua._reader, daemon=True).start()
    sc.closers.append(ua.close)
    return ua


def tp_of(rr):
    """The transport a Record-Route names (no ;transport= is UDP)."""
    m = re.search(r";transport=(\w+)", rr, re.I)
    return m.group(1).lower() if m else "udp"


def rr_info(msg):
    return msg.all("record-route") if msg is not None else None


def first(ua, method, cid):
    return next((m for m in ua.received if m.method == method and m.get("call-id") == cid), None)


def cross_call(sc, caller, callee, label, want_tp):
    """caller calls callee (registered); check delivery, the Record-Routes, and both BYE directions."""
    r, d = caller.call(f"sip:{callee.user}@example.com", timeout=6)
    sc.check(f"{label}: 200", r is not None and r.code == 200 and d is not None, r)
    if not d:
        return
    inv = first(callee, "INVITE", d.call_id)
    rrs = rr_info(inv) or []
    sc.check(f"{label}: the callee gets the INVITE with the proxy's Via over {want_tp.upper()}",
             inv is not None and inv.all("via")[0].startswith(f"SIP/2.0/{want_tp.upper()} "), inv and inv.all("via"))
    if caller.transport == callee.transport:
        sc.check(f"{label}: same transport → one Record-Route", len(rrs) == 1 and "r2=on" not in rrs[0], rrs)
    else:
        sc.check(f"{label}: transport change → two Record-Routes, both r2=on (double RR)",
                 len(rrs) == 2 and all("r2=on" in x for x in rrs), rrs)
        sc.check(f"{label}: …the top one is the callee's side ({want_tp})", len(rrs) == 2 and tp_of(rrs[0]) == want_tp, rrs)
        sc.check(f"{label}: …the other one is the caller's side ({caller.transport})",
                 len(rrs) == 2 and tp_of(rrs[1]) == caller.transport, rrs)
    sc.check(f"{label}: the caller's 200 carries the same Record-Routes", r.all("record-route") == rrs, (r.all("record-route"), rrs))
    time.sleep(0.3)
    sc.check(f"{label}: the ACK reaches the callee", first(callee, "ACK", d.call_id) is not None)
    # The callee hangs up: its BYE goes back along the Record-Route, reversed.
    caller.auto_answer()
    to_tag = callee.tags.get((d.call_id, inv.tag("from")))
    # The R-URI is the caller's Contact (with its ;transport=).
    b = callee.request("BYE", sipkit.uri_of(inv.get("contact")), to=inv.get("from"), call_id=d.call_id, from_tag=to_tag,
                       cseq=1, headers={"Route": ", ".join(rrs)}, from_uri=f"sip:{callee.user}@example.com")
    rep = callee.final(call_id=b["call_id"], method="BYE")
    sc.check(f"{label}: the callee's BYE reaches the caller (over {caller.transport.upper()}) → 200",
             rep is not None and rep.code == 200 and first(caller, "BYE", d.call_id) is not None, rep)


def run(sc):
    if not os.path.exists(f"{sipkit.TLS_DIR}/server.pem"):
        subprocess.run([f"{sipkit.TLS_DIR}/gen-certs.sh"], check=True, capture_output=True)
    sip, tls, ws = sc.port(), sc.port(), sc.port()
    sc.proxy(env=sc.env(SIP_PORT=sip, TLS_PORT=tls, WS_PORT=ws))

    alice = sc.ua("alice", sip, "udp").auto_answer()
    carol = sc.ua("carol", sip, "udp").auto_answer()
    bob = sc.ua("bob", sip, "tcp").auto_answer()
    erin = sc.ua("erin", tls, "tls").auto_answer()
    dave = sc.ua("dave", ws, "ws").auto_answer()
    for u in (alice, carol, bob, erin, dave):
        r = u.register(expires=300)
        sc.check(f"{u.user} registers over {u.transport.upper()} → 200", r is not None and r.code == 200, r)

    cross_call(sc, alice, bob, "UDP → TCP (callee registered over TCP)", "tcp")
    cross_call(sc, erin, carol, "TLS → UDP", "udp")
    cross_call(sc, alice, dave, "UDP → WS", "ws")
    cross_call(sc, alice, carol, "UDP → UDP", "udp")

    # R-URI ;transport=tcp to a host nobody registered: the proxy opens the connection.
    peer = tcp_listener_ua(sc, "pstn", sip).auto_answer()
    r, d = alice.call(f"sip:+4930555@127.0.0.1:{peer.port};transport=tcp", timeout=6)
    sc.check("UDP → R-URI ;transport=tcp: the proxy connects out over TCP → 200", r is not None and r.code == 200 and d is not None, r)
    inv = first(peer, "INVITE", d.call_id) if d else None
    rrs = rr_info(inv) or []
    sc.check("…two Record-Routes, the top one transport=tcp", len(rrs) == 2 and "transport=tcp" in rrs[0].lower(), rrs)
    if d:
        rep = d.bye()
        sc.check("…the caller's BYE follows the route over the proxy's TCP connection → 200",
                 rep is not None and rep.code == 200 and first(peer, "BYE", d.call_id) is not None, rep)

    # Large messages: > 3 KB over TCP, both from a TCP client and towards a TCP-registered callee.
    big = "".join(f"line {i:04d} " + "x" * 60 + "\n" for i in range(60))  # ~4.3 KB
    for sender, target, label in ((bob, carol, "TCP → UDP"), (alice, bob, "UDP → TCP")):
        r = sender.request("MESSAGE", f"sip:{target.user}@example.com", body=big, content_type="text/plain")
        rep = sender.final(call_id=r["call_id"])
        got = first(target, "MESSAGE", r["call_id"])
        sc.check(f"a {len(big.encode())}-byte MESSAGE {label}: 200 back", rep is not None and rep.code == 200, rep)
        sc.check(f"…delivered intact with the right Content-Length ({label})",
                 got is not None and got.body == big and int(got.get("content-length")) == len(big.encode()), got and len(got.body))
    frank = sc.ua("frank", sip, "tcp").auto_answer()
    r = frank.request("MESSAGE", "sip:bob@example.com", body=big * 2, content_type="text/plain")
    rep = frank.final(call_id=r["call_id"])
    got = first(bob, "MESSAGE", r["call_id"])
    sc.check("an 8.6 KB MESSAGE TCP → TCP: delivered intact, 200 back",
             rep is not None and rep.code == 200 and got is not None and got.body == big * 2, (rep, got and len(got.body)))

    # TCP framing: two requests in one segment, and one request split over three writes.
    raws, cids = [], []
    for _ in range(2):
        cid = f"pipe-{sipkit.rnd(8)}"
        cids.append(cid)
        body = "pipelined"
        raws.append(f"MESSAGE sip:bob@example.com SIP/2.0\r\nVia: {frank.via(sipkit.rnd(10))}\r\nFrom: <{frank.aor}>;tag={sipkit.rnd(6)}\r\n"
                    f"To: <sip:bob@example.com>\r\nCall-ID: {cid}\r\nCSeq: 1 MESSAGE\r\nMax-Forwards: 70\r\nContent-Type: text/plain\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n{body}")
    frank.send("".join(raws))
    reps = [frank.final(call_id=c) for c in cids]
    sc.check("two requests in one TCP write: both relayed and answered", all(x is not None and x.code == 200 for x in reps), reps)
    cid = f"split-{sipkit.rnd(8)}"
    raw = (f"MESSAGE sip:bob@example.com SIP/2.0\r\nVia: {frank.via(sipkit.rnd(10))}\r\nFrom: <{frank.aor}>;tag={sipkit.rnd(6)}\r\n"
           f"To: <sip:bob@example.com>\r\nCall-ID: {cid}\r\nCSeq: 1 MESSAGE\r\nMax-Forwards: 70\r\nContent-Type: text/plain\r\n"
           f"Content-Length: {len(big)}\r\n\r\n{big}").encode()
    for part in (raw[:40], raw[40:len(raw) - 1000], raw[len(raw) - 1000:]):
        frank.send(part)
        time.sleep(0.2)
    rep = frank.final(call_id=cid)
    got = first(bob, "MESSAGE", cid)
    sc.check("one request split over three TCP writes (mid-header, mid-body): relayed whole",
             rep is not None and rep.code == 200 and got is not None and got.body == big, (rep, got and len(got.body)))

    # A missing TLS certificate: the proxy must refuse to start.
    p = sc.proxy(env=sc.env(SIP_PORT=sc.port(), TLS_PORT=sc.port(), WS_PORT=sc.port(), TLS_DIR=os.path.join(sc.tmp, "no-tls")),
                 name="no-cert", start=False)
    try:
        p.start(timeout=5)
        started = True
    except RuntimeError as e:
        started, err = False, str(e)
    if not started:
        sc.proxies.remove(p)
    sc.check("a missing TLS certificate stops the proxy at startup, naming the file",
             not started and "no-tls" in err, "started" if started else err[-400:])
