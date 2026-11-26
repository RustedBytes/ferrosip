#!/usr/bin/env python3
"""End-to-end checks for ferrosip's TCP/TLS transport.

Starts its own proxy (target/release/ferrosip) with short TCP limits and plays
both client and downstream UAS with raw sockets, so every byte on the wire is
visible. Run from the repo root after `cargo build --release` and
`etc/tls/gen-certs.sh`.
"""
import json, os, socket, ssl, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TLS = os.path.join(ROOT, "etc/tls")
PROXY_TCP, PROXY_TLS, UAS_TCP, UAS_TLS, UAS_SLOW = 5160, 5161, 5171, 5172, 5173
UAS_WRONG_NAME, STALL, REFUSED, ALIAS = 5174, 5176, 5998, 5997
PROXY_TLS2, UAS_PROF = 5162, 5175
PROFILE = os.path.join(ROOT, "target/e2e_tls_profile.cfg")
CFG = f"""loadmodule "maxfwd"
loadmodule "tm"
request_route {{
    if !mf_process(70) {{ reply(483, "Too Many Hops"); exit; }}
    if method == "OPTIONS" {{ reply(200, "OK"); exit; }}
    if ruri_user_prefix("tls") {{ t_relay("tls:127.0.0.1:{UAS_TLS}"); exit; }}
    if ruri_user_prefix("slow") {{ t_relay("tcp:127.0.0.1:{UAS_SLOW}"); exit; }}
    if ruri_user_prefix("refused") {{ if !t_relay("tcp:127.0.0.1:{REFUSED}") {{ sl_reply_error(); }} exit; }}
    if ruri_user_prefix("stalled") {{ if !t_relay("tls:127.0.0.1:{STALL}") {{ sl_reply_error(); }} exit; }}
    if ruri_user_prefix("byname") {{ t_relay("tls:localhost:{UAS_TLS}"); exit; }}
    if ruri_user_prefix("wrongname") {{ if !t_relay("tls:localhost:{UAS_WRONG_NAME}") {{ sl_reply_error(); }} exit; }}
    if ruri_user_prefix("aliased") {{ t_relay("tcp:127.0.0.1:{ALIAS}"); exit; }}
    if ruri_user_prefix("victim") {{ if (!t_relay("tcp:192.0.2.1:{ALIAS}")) {{ sl_reply_error(); }} exit; }}
    if ruri_user_prefix("prof") {{ t_relay("tls:127.0.0.1:{UAS_PROF}"); exit; }}
    t_relay("tcp:127.0.0.1:{UAS_TCP}");
}}
"""

failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def req(method, user, branch, proto="TCP", body="", via="127.0.0.1:9"):
    return (f"{method} sip:{user}@127.0.0.1 SIP/2.0\r\n"
            f"Via: SIP/2.0/{proto} {via};branch=z9hG4bK{branch}\r\n"
            "Max-Forwards: 70\r\nFrom: <sip:a@x>;tag=1\r\n"
            f"To: <sip:{user}@x>\r\nCall-ID: {branch}\r\nCSeq: 1 {method}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}").encode()


SOCK = os.path.join(ROOT, "target/e2e_stream.sock")


def active_conns():
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, "stats.get_statistics", "tcp:active_connections"],
                         capture_output=True, text=True, timeout=5).stdout
    try:
        return json.loads(out)["tcp:active_connections"]
    except (ValueError, KeyError):
        return -1


def wait_conns(at_most, timeout=10.0):
    """Wait until the proxy holds at most `at_most` connections (inbound and
    outbound count against --tcp-max-conns), instead of guessing a sleep."""
    end = time.time() + timeout
    while time.time() < end:
        if 0 <= active_conns() <= at_most:
            return True
        time.sleep(0.1)
    return False


def closed_after(s, limit):
    """Seconds until the proxy closes `s` (None if still open after `limit`)."""
    t0 = time.time()
    s.settimeout(0.1)
    while time.time() - t0 < limit:
        try:
            if s.recv(65536) == b"":
                return time.time() - t0
        except socket.timeout:
            continue
        except OSError:
            return time.time() - t0
    return None


_leftover = {}


def read_msg(s, timeout=3.0):
    """Read exactly one SIP message (framed by Content-Length) or b'' on close.
    Bytes beyond the message are kept for the next call on the same socket."""
    s.settimeout(timeout)
    buf = _leftover.pop(id(s), b"").lstrip(b"\r\n")
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            return buf
        buf = (buf + d).lstrip(b"\r\n")
    head, _, rest = buf.partition(b"\r\n\r\n")
    clen = 0
    for line in head.split(b"\r\n"):
        k, _, v = line.partition(b":")
        if k.strip().lower() in (b"content-length", b"l"):
            clen = int(v)
    while len(rest) < clen:
        rest += s.recv(65536)
    _leftover[id(s)] = rest[clen:]
    return head + b"\r\n\r\n" + rest[:clen]


def reply_to(raw, code="200 OK"):
    lines = raw.decode().split("\r\n")
    keep = [l for l in lines if l.split(":")[0] in ("Via", "From", "To", "Call-ID", "CSeq")]
    return (f"SIP/2.0 {code}\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n").encode()


class Uas(threading.Thread):
    """Downstream: records requests and answers 200 on the same connection."""

    def __init__(self, port, tls=False, cert="server", require_client_cert=False):
        super().__init__(daemon=True)
        self.got, self.conns = [], 0
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", port))
        self.ls.listen()
        self.ctx = None
        if tls:
            self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ctx.load_cert_chain(f"{TLS}/{cert}.pem", f"{TLS}/{cert}.key.pem")
            if require_client_cert:  # the proxy must present its certificate
                self.ctx.verify_mode = ssl.CERT_REQUIRED
                self.ctx.load_verify_locations(f"{TLS}/ca.pem")
            self.peer_certs = []
        self.start()

    def run(self):
        while True:
            c, _ = self.ls.accept()
            self.conns += 1
            if self.ctx:
                try:
                    c = self.ctx.wrap_socket(c, server_side=True)
                except (ssl.SSLError, OSError):
                    continue
                self.peer_certs.append(c.getpeercert())
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        try:
            while True:
                m = read_msg(c, timeout=30)
                if not m:
                    return
                self.got.append(m)
                c.sendall(reply_to(m))
        except OSError:
            pass


def tls_client(port, cafile=f"{TLS}/ca.pem", client_cert="server", sni=None):
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.check_hostname = sni is not None  # without SNI: cert is for IP 127.0.0.1, chain still verified
    if client_cert:
        ctx.load_cert_chain(f"{TLS}/{client_cert}.pem", f"{TLS}/{client_cert}.key.pem")
    return ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname=sni)


def keepalive_armed(local_port):
    """Is a TCP keep-alive timer pending on a socket bound to local_port? (/proc/net/tcp: tr == 2)"""
    for line in open("/proc/net/tcp").read().splitlines()[1:]:
        f = line.split()
        if int(f[1].split(":")[1], 16) == local_port and f[3] == "01" and f[5].split(":")[0] == "02":
            return True
    return False


def main():
    cfg = os.path.join(ROOT, "target/e2e.cfg")
    open(cfg, "w").write(CFG)
    uas_tcp, uas_tls = Uas(UAS_TCP), Uas(UAS_TLS, tls=True, require_client_cert=True)
    _uas_wrong = Uas(UAS_WRONG_NAME, tls=True, cert="other.test")  # serves for the whole run
    uas_prof = Uas(UAS_PROF, tls=True, cert="other.test", require_client_cert=True)
    open(PROFILE, "w").write(f"""# per-peer: present b.test, verify the peer as other.test
[client:127.0.0.1:{UAS_PROF}]
certificate = {TLS}/b.test.pem
private_key = {TLS}/b.test.key.pem
ca_list = {TLS}/ca.pem
verify_certificate = yes
server_name = other.test

# a second listener: other certificate, no client certificates
[server:127.0.0.1:{PROXY_TLS2}]
certificate = {TLS}/other.test.pem
private_key = {TLS}/other.test.key.pem
verify_certificate = no
""")
    stall = socket.socket()  # accepts TCP, never speaks TLS → handshake never completes
    stall.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    stall.bind(("127.0.0.1", STALL))
    stall.listen()
    proxy = subprocess.Popen(
        [f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"tcp:127.0.0.1:{PROXY_TCP}",
         "-l", f"tls:127.0.0.1:{PROXY_TLS}", "-l", f"tls:127.0.0.1:{PROXY_TLS2}", "--tls-profile", PROFILE, "--tls-tickets",
         "--tcp-readers", "2", "--tcp-lifetime", "2",
         "--tcp-max-conns", "6", "--tls-cert", f"{TLS}/server.pem", "--tls-key",
         f"{TLS}/server.key.pem", "--tls-ca", f"{TLS}/ca.pem", "--tls-verify-client",
         "--tls-sni", f"b.test={TLS}/b.test.pem,{TLS}/b.test.key.pem", "--tcp-connect-timeout", "1",
         "--tcp-keepalive", "30", "--tcp-accept-aliases", "--rpc-socket", SOCK, "--shutdown-timeout", "1"],
        stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    try:
        # 1. TCP relay: our Via says TCP, reply returns on the same connection.
        c = socket.create_connection(("127.0.0.1", PROXY_TCP))
        c.sendall(req("MESSAGE", "bob", "t1"))
        r = read_msg(c)
        down = uas_tcp.got[-1].decode() if uas_tcp.got else ""
        check("tcp→tcp relay, reply on same connection", r.startswith(b"SIP/2.0 200"), r[:60])
        check("proxy Via uses transport TCP", f"Via: SIP/2.0/TCP 127.0.0.1:{PROXY_TCP};branch=" in down, down[:200])
        check("proxy Via stripped from reply", r.count(b"Via:") == 1, r)

        # 2. Message delivered one byte at a time (framing across reads).
        m = req("MESSAGE", "bob", "t2", body="hello")
        for b in m:
            c.send(bytes([b]))
        r = read_msg(c)
        check("byte-by-byte message with body is framed", r.startswith(b"SIP/2.0 200") and uas_tcp.got[-1].endswith(b"hello"))

        # 3. Pipelining: three requests in one segment.
        c.sendall(req("OPTIONS", "x", "p1") + req("OPTIONS", "x", "p2") + req("OPTIONS", "x", "p3"))
        rs = [read_msg(c) for _ in range(3)]
        check("3 pipelined requests → 3 replies", all(x.startswith(b"SIP/2.0 200") for x in rs))

        # 4. RFC 5626 keep-alive: CRLFCRLF ping → CRLF pong.
        c.sendall(b"\r\n\r\n")
        c.settimeout(2)
        check("CRLF ping answered with CRLF pong", c.recv(16) == b"\r\n")
        c.close()

        # 5. Missing Content-Length on a stream → connection closed.
        c = socket.create_connection(("127.0.0.1", PROXY_TCP))
        c.sendall(b"OPTIONS sip:x@y SIP/2.0\r\nVia: SIP/2.0/TCP a;branch=z9hG4bKcl\r\n\r\n")
        check("missing Content-Length closes connection", read_msg(c) == b"")
        c.close()

        # 6. TLS in, TLS out (verified against our CA both ways).
        c = tls_client(PROXY_TLS)
        c.sendall(req("MESSAGE", "tlsbob", "s1", proto="TLS"))
        r = read_msg(c)
        down = uas_tls.got[-1].decode() if uas_tls.got else ""
        check("tls→tls relay", r.startswith(b"SIP/2.0 200"), r[:80])
        check("proxy Via uses transport TLS", "Via: SIP/2.0/TLS" in down, down[:200])
        check("proxy presented its client certificate downstream (mTLS)",
              bool(uas_tls.peer_certs) and ("commonName", "localhost") in uas_tls.peer_certs[-1]["subject"][0])
        c.close()

        # 6b. Mutual TLS on our listener: no client certificate → rejected.
        try:
            c = tls_client(PROXY_TLS, client_cert=None)
            c.sendall(req("OPTIONS", "x", "nocert", proto="TLS"))
            rejected = read_msg(c) == b""
        except (ssl.SSLError, OSError):
            rejected = True
        check("TLS client without certificate rejected (--tls-verify-client)", rejected)

        # 6c. SNI picks the certificate (hostname-verified by the client).
        c = tls_client(PROXY_TLS, sni="b.test")
        check("SNI b.test → b.test certificate", ("commonName", "b.test") in c.getpeercert()["subject"][0])
        c.close()
        c = tls_client(PROXY_TLS)
        c.sendall(req("OPTIONS", "x", "nosni", proto="TLS"))
        check("no SNI → default certificate still works", read_msg(c).startswith(b"SIP/2.0 200"))
        c.close()

        # 7. Client with the wrong CA must fail the handshake (cert is verified).
        try:
            tls_client(PROXY_TLS, cafile="/etc/ssl/certs/ca-certificates.crt")
            check("TLS handshake fails with wrong CA", False, "handshake succeeded")
        except ssl.SSLError:
            check("TLS handshake fails with wrong CA", True)

        # 8. Downstream connection is reused across requests.
        before = uas_tcp.conns
        c = socket.create_connection(("127.0.0.1", PROXY_TCP))
        for i in range(5):
            c.sendall(req("MESSAGE", "bob", f"r{i}"))
            read_msg(c)
        c.close()
        check("downstream TCP connection reused", uas_tcp.conns == before, f"{before} → {uas_tcp.conns}")

        # 9. Idle connections are closed after tcp_connection_lifetime (2s).
        c = socket.create_connection(("127.0.0.1", PROXY_TCP))
        t0 = time.time()
        closed = read_msg(c, timeout=6) == b""
        check("idle connection closed after lifetime", closed and 1.5 < time.time() - t0 < 4.5, f"{time.time() - t0:.1f}s")
        c.close()
        time.sleep(1.5)  # proxy's downstream conns have also idled out by now

        # 10. ...and the proxy reconnects downstream when needed.
        before = uas_tcp.conns
        c = socket.create_connection(("127.0.0.1", PROXY_TCP))
        c.sendall(req("MESSAGE", "bob", "rc1"))
        r = read_msg(c)
        check("reconnects downstream after idle close", r.startswith(b"SIP/2.0 200") and uas_tcp.conns == before + 1,
              f"{r[:30]} conns {before}→{uas_tcp.conns}")
        c.close()

        # 11. tcp_max_connections: with 6 allowed, the 7th+ accepted socket is closed.
        time.sleep(3)
        socks = [socket.create_connection(("127.0.0.1", PROXY_TCP)) for _ in range(8)]
        time.sleep(0.3)
        alive = 0
        for s in socks:
            s.sendall(req("OPTIONS", "x", f"mc{id(s)}"))
            try:
                alive += read_msg(s, timeout=1).startswith(b"SIP/2.0 200")
            except OSError:
                pass
            s.close()
        check("tcp_max_connections enforced", alive == 6, f"{alive} of 8 served")

        # 12. A downstream that stops reading must not block any worker, and
        #     the connection is dropped once tcp_conn_wq_max is exceeded.
        time.sleep(3)  # let the max-conns sockets of test 11 be released
        slow_ls = socket.socket()
        slow_ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        slow_ls.bind(("127.0.0.1", UAS_SLOW))
        slow_ls.listen()
        c = socket.create_connection(("127.0.0.1", PROXY_TCP))
        body = "x" * 20000
        sent = 0
        def flood():
            nonlocal sent
            for i in range(300):  # 6 MB, more than the socket buffers + 256 KiB queue
                c.sendall(req("MESSAGE", "slow", f"slow{i}", body=body))
                sent += 1
        threading.Thread(target=flood, daemon=True).start()
        slow, _ = slow_ls.accept()  # never reads while the flood runs
        time.sleep(1.5)
        o = socket.create_connection(("127.0.0.1", PROXY_TCP))
        t0 = time.time()
        o.sendall(req("OPTIONS", "x", "alive"))
        r = read_msg(o, timeout=2)
        check("other traffic still served while downstream is stuck",
              r.startswith(b"SIP/2.0 200") and time.time() - t0 < 0.5, f"{time.time() - t0:.2f}s")
        o.close()
        got, slow_s = 0, slow
        slow_s.settimeout(3)
        try:
            while True:
                d = slow_s.recv(1 << 20)
                if not d:
                    break
                got += len(d)
        except OSError:
            pass
        check("stuck downstream dropped at tcp_conn_wq_max (EOF, not all data)",
              0 < got < sent * len(body), f"read {got} bytes of {sent * len(body)}")
        c.close()
        # The proxy may still be relaying the rest of the flood: with the
        # listener gone those reconnects are refused instead of filling the
        # tcp_max_connections slots (outbound connections count too).
        slow_s.close()
        slow_ls.close()

        # 13. Outbound connect refused → 477 immediately (not 408 after 32s):
        #     on loopback the refusal is synchronous, so t_relay() fails and
        #     the script answers with sl_reply_error() — Kamailio's idiom.
        # Tests 13-14 need free slots under --tcp-max-conns 6: the flood's
        # connections are released once idle (--tcp-lifetime 2).
        check("connection slots released after the flood", wait_conns(2), active_conns())
        c = socket.create_connection(("127.0.0.1", PROXY_TCP))
        t0 = time.time()
        c.sendall(req("MESSAGE", "refused", "rf1"))
        r = read_msg(c)
        check("connect refused → 477 at once", r.startswith(b"SIP/2.0 477") and time.time() - t0 < 1, (r[:40], time.time() - t0))
        try:
            extra = read_msg(c, timeout=1.5)
        except OSError:
            extra = b""
        check("…exactly one reply to the refused request", not extra, extra[:200])

        # 14. TLS handshake never completes → tcp_connect_timeout (1s) → tm
        #     fails the waiting transaction with 477 asynchronously.
        t0 = time.time()
        c.sendall(req("MESSAGE", "stalled", "st1"))
        r = read_msg(c, timeout=6)
        check("stalled TLS handshake → 477 after connect timeout", r.startswith(b"SIP/2.0 477") and 0.9 < time.time() - t0 < 1.8,
              (r[:40], round(time.time() - t0, 1), [l for l in r.split(b"\r\n") if l.startswith((b"Call-ID", b"CSeq"))]))

        # 15. Outbound TLS verified by host name.
        c.sendall(req("MESSAGE", "byname", "bn1"))
        r = read_msg(c)
        check("tls:localhost → cert with DNS:localhost accepted", r.startswith(b"SIP/2.0 200"), r[:40])
        c.sendall(req("MESSAGE", "wrongname", "wn1"))
        r = read_msg(c)
        check("tls:localhost → cert for other.test rejected → 477", r.startswith(b"SIP/2.0 477"), r[:40])

        # 16. TCP keep-alive armed on our sockets (--tcp-keepalive).
        # Right after a send /proc shows the retransmit timer (tr=1) until the
        # peer's delayed ACK arrives; then the keep-alive timer (tr=2).
        armed = any(keepalive_armed(PROXY_TCP) or time.sleep(0.1) for _ in range(10))
        check("TCP keep-alive timer armed on proxy socket", armed)
        c.close()

        # 17. RFC 5923 alias: A offers its connection for 127.0.0.1:ALIAS; a
        #     request routed there from B arrives on A's connection.
        a = socket.create_connection(("127.0.0.1", PROXY_TCP))
        a.sendall(req("OPTIONS", "x", "al1", via=f"127.0.0.1:{ALIAS};alias"))
        read_msg(a)
        b = socket.create_connection(("127.0.0.1", PROXY_TCP))
        b.sendall(req("MESSAGE", "aliased", "al2"))
        m = read_msg(a)
        check("Via ;alias → request delivered over the aliased connection", m.startswith(b"MESSAGE sip:aliased@"), m[:40])
        a.sendall(reply_to(m))
        r = read_msg(b)
        check("…and its reply routed back to the caller", r.startswith(b"SIP/2.0 200"), r[:40])
        a.close()
        b.close()

        # 17b. A client can't alias someone else's address: the Via host is
        #      ignored and the alias is the connection's own IP (as Kamailio).
        h = socket.create_connection(("127.0.0.1", PROXY_TCP))
        h.sendall(req("OPTIONS", "x", "hj1", via=f"192.0.2.1:{ALIAS};alias"))
        read_msg(h)
        b = socket.create_connection(("127.0.0.1", PROXY_TCP))
        b.sendall(req("MESSAGE", "victim", "hj2"))
        try:
            stolen = read_msg(h, timeout=1.5)
        except OSError:  # timed out: nothing arrived, as it should be
            stolen = b""
        check("Via ;alias with a foreign IP doesn't capture that IP's requests", not stolen.startswith(b"MESSAGE"), stolen[:40])
        h.close()
        b.close()

        # 17c. Slow clients (--tcp-connect-timeout 1, --tcp-lifetime 2).
        wait_conns(2)
        # A TLS client that connects and never sends a ClientHello is closed
        # at the handshake deadline, not after the idle lifetime.
        silent = socket.create_connection(("127.0.0.1", PROXY_TLS))
        t = closed_after(silent, 4)
        check("TLS client that never handshakes closed at the connect timeout", t is not None and t < 1.8, t)
        silent.close()
        # A client trickling one never-ending message: partial bytes don't
        # count as activity, so the idle lifetime still applies.
        trickle = socket.create_connection(("127.0.0.1", PROXY_TCP))
        trickle.sendall(b"OPTIONS sip:x@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:9;branch=z9hG4bKtr\r\n")
        t0, gone = time.time(), None
        while time.time() - t0 < 6 and gone is None:
            try:
                trickle.sendall(b"X")
            except OSError:
                gone = time.time() - t0
                break
            gone = closed_after(trickle, 0.4)
            gone = None if gone is None else time.time() - t0
        check("client trickling a partial message closed after the idle lifetime", gone is not None and gone < 4.5, gone)
        trickle.close()
        # 1 MB without a header end: closed, and other connections still served.
        flood = socket.create_connection(("127.0.0.1", PROXY_TCP))
        try:
            flood.sendall(b"OPTIONS sip:x SIP/2.0\r\nX: " + b"A" * (1 << 20))
        except OSError:
            pass
        t = closed_after(flood, 3)
        flood.close()
        o = socket.create_connection(("127.0.0.1", PROXY_TCP))
        o.sendall(req("OPTIONS", "x", "afterflood"))
        r = read_msg(o)
        o.close()
        check("1 MB without a header end: connection closed, others still served", t is not None and r.startswith(b"SIP/2.0 200"), (t, r[:30]))

        # 18. TLS profiles: per-peer client settings, per-listener server settings.
        time.sleep(2.5)  # let idle connections expire (--tcp-max-conns 6)
        c = socket.create_connection(("127.0.0.1", PROXY_TCP))
        c.sendall(req("MESSAGE", "prof", "pf1"))
        r = read_msg(c)
        cn = dict(x[0] for x in uas_prof.peer_certs[-1]["subject"]).get("commonName") if uas_prof.peer_certs else None
        check("[client:IP:PORT] profile: our b.test certificate, peer verified as server_name other.test",
              r.startswith(b"SIP/2.0 200") and cn == "b.test", (r[:40], cn))
        c.close()
        ctx = ssl.create_default_context(cafile=f"{TLS}/ca.pem")
        ctx.check_hostname = False
        t = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PROXY_TLS2)))
        scn = dict(x[0] for x in t.getpeercert()["subject"]).get("commonName")
        t.sendall(req("OPTIONS", "x", "pf2", proto="TLS"))
        r = read_msg(t)
        check("[server:IP:PORT] profile: that listener's certificate, no client certificate needed",
              scn == "other.test" and r.startswith(b"SIP/2.0 200"), (scn, r[:30]))
        sess = t.session
        t.close()
        t2 = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PROXY_TLS2)), session=sess)
        t2.sendall(req("OPTIONS", "x", "pf3", proto="TLS"))
        r = read_msg(t2)
        check("TLS session resumption (--tls-tickets)", t2.session_reused and r.startswith(b"SIP/2.0 200"), (t2.session_reused, r[:30]))
        t2.close()
    finally:
        proxy.terminate()
        err = proxy.communicate(timeout=5)[1]
        check("no panics in proxy log", "panic" not in err, err)
        if failures:
            print("--- proxy stderr (tail) ---\n" + err[-3000:])
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
