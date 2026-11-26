#!/usr/bin/env python3
"""End-to-end checks for SIP over WebSocket (RFC 7118 / RFC 6455).

Starts its own proxy with ws: and wss: listeners and speaks raw WebSocket
frames, so masking, fragmentation and control frames are all explicit.
Run from the repo root after `cargo build --release` and `etc/tls/gen-certs.sh`.
"""
import base64, hashlib, os, socket, ssl, subprocess, sys, threading, time, zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TLS = os.path.join(ROOT, "etc/tls")
WS, WSS, UAS_UDP = 8180, 8543, 5270
OUT_WS, OUT_WSS = 8190, 8590
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CFG = f"""loadmodule "tm"
request_route {{
    if method == "OPTIONS" {{ reply(200, "OK"); exit; }}
    if ruri_user_prefix("towss") {{ t_relay("wss:127.0.0.1:{OUT_WSS}"); exit; }}
    if ruri_user_prefix("tows") {{ t_relay("ws:127.0.0.1:{OUT_WS}"); exit; }}
    if ruri_user_prefix("wsout") {{
        if !t_relay("ws:127.0.0.1:9") {{ t_reply(503, "No WebSocket Connection"); }}
        exit;
    }}
    t_relay("udp:127.0.0.1:{UAS_UDP}");
}}
event_route[websocket:handshake] {{
    if ($hdr(User-Agent) =~ "BadBot") {{ drop; }}
    if ($hdr(X-WS-Path) == "/private") {{ drop; }}
}}
"""
OPCODES = {0: "CONT", 1: "TEXT", 2: "BINARY", 8: "CLOSE", 9: "PING", 10: "PONG"}
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def sip(method, user, branch, body=""):
    return (f"{method} sip:{user}@127.0.0.1 SIP/2.0\r\n"
            f"Via: SIP/2.0/WS df7jal23ls0d.invalid;branch=z9hG4bK{branch}\r\n"
            "Max-Forwards: 70\r\nFrom: <sip:a@x>;tag=1\r\n"
            f"To: <sip:{user}@x>\r\nCall-ID: {branch}\r\nCSeq: 1 {method}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}").encode()


def frame(op, payload=b"", fin=True, mask=True, rsv1=False):
    n = len(payload)
    b1 = n if n < 126 else 126 if n < 65536 else 127
    ext = b"" if n < 126 else n.to_bytes(2 if n < 65536 else 8, "big")
    hdr = bytes([(0x80 if fin else 0) | (0x40 if rsv1 else 0) | op, (0x80 if mask else 0) | b1]) + ext
    if not mask:
        return hdr + payload
    key = os.urandom(4)
    return hdr + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


class WsClient:
    def __init__(self, port, tls=False, protocol="sip", version="13", headers="", path="/ws"):
        s = socket.create_connection(("127.0.0.1", port))
        if tls:
            ctx = ssl.create_default_context(cafile=f"{TLS}/ca.pem")
            ctx.check_hostname = False
            s = ctx.wrap_socket(s)
        self.s, self.buf = s, b""
        self.key = base64.b64encode(os.urandom(16)).decode()
        proto = f"Sec-WebSocket-Protocol: {protocol}\r\n" if protocol else ""
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
                   f"Connection: Upgrade\r\nSec-WebSocket-Key: {self.key}\r\n"
                   f"Sec-WebSocket-Version: {version}\r\n{proto}{headers}\r\n").encode())
        s.settimeout(3)
        while b"\r\n\r\n" not in self.buf:
            d = s.recv(4096)
            if not d:
                break
            self.buf += d
        self.head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        self.head = self.head.decode()

    def expected_accept(self):
        return base64.b64encode(hashlib.sha1((self.key + GUID).encode()).digest()).decode()

    def send(self, data):
        self.s.sendall(data)

    def recv_frame(self, timeout=3.0):
        """(opcode name, fin, payload) — or None on EOF/timeout."""
        self.s.settimeout(timeout)
        try:
            while True:
                b = self.buf
                if len(b) >= 2:
                    n, off = b[1] & 0x7F, 2
                    if b[1] & 0x80:
                        return ("MASKED-FROM-SERVER", True, b"")
                    if n == 126 and len(b) >= 4:
                        n, off = int.from_bytes(b[2:4], "big"), 4
                    elif n == 127 and len(b) >= 10:
                        n, off = int.from_bytes(b[2:10], "big"), 10
                    if n < 126 or off > 2:
                        if len(b) >= off + n:
                            self.buf = b[off + n:]
                            self.rsv1 = bool(b[0] & 0x40)
                            return (OPCODES.get(b[0] & 0x0F, "?"), bool(b[0] & 0x80), b[off:off + n])
                d = self.s.recv(65536)
                if not d:
                    return None
                self.buf += d
        except (socket.timeout, OSError):
            return None

    def recv_data(self, timeout=3.0):
        """Next data frame, answering any keep-alive PINGs on the way."""
        while True:
            f = self.recv_frame(timeout)
            if f and f[0] == "PING":
                self.send(frame(10, f[2]))
                continue
            return f

    def closed(self, timeout=3.0):
        """True if the server closes the TCP connection (after any frames)."""
        end = time.time() + timeout
        while time.time() < end:
            if self.recv_frame(timeout=max(0.05, end - time.time())) is None:
                return True
        return False


class UdpUas(threading.Thread):
    def __init__(self, port):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.got = []
        self.start()

    def run(self):
        while True:
            d, a = self.s.recvfrom(65535)
            self.got.append(d)
            head = d.split(b"\r\n\r\n")[0].decode("latin-1")  # bodies may be binary
            keep = [l for l in head.split("\r\n") if l.split(":")[0] in ("Via", "From", "To", "Call-ID", "CSeq")]
            self.s.sendto(("SIP/2.0 200 OK\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n").encode("latin-1"), a)


class WsServer(threading.Thread):
    """A SIP-over-WebSocket server (we test ferrosip as the *client*):
    answers the upgrade, unmasks frames, answers SIP requests with 200."""

    def __init__(self, port, tls=False):
        super().__init__(daemon=True)
        self.l = socket.socket()
        self.l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l.bind(("127.0.0.1", port))
        self.l.listen(4)
        self.tls = tls
        self.upgrades, self.frames = [], []
        self.start()

    def run(self):
        while True:
            c, _ = self.l.accept()
            if self.tls:
                ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ctx.load_cert_chain(f"{TLS}/server.pem", f"{TLS}/server.key.pem")
                try:
                    c = ctx.wrap_socket(c, server_side=True)
                except ssl.SSLError:
                    continue
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = c.recv(4096)
            if not d:
                return
            buf += d
        head, _, buf = buf.partition(b"\r\n\r\n")
        head = head.decode()
        self.upgrades.append(head)
        key = next((l.split(":", 1)[1].strip() for l in head.split("\r\n") if l.lower().startswith("sec-websocket-key:")), "")
        acc = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        c.sendall(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {acc}\r\n"
                  "Sec-WebSocket-Protocol: sip\r\n\r\n".encode())
        while True:
            while len(buf) < 2 or len(buf) < 2 + (4 if buf[1] & 0x80 else 0) + (buf[1] & 0x7F if buf[1] & 0x7F < 126 else 0) + (2 if buf[1] & 0x7F == 126 else 0):
                d = c.recv(65536)
                if not d:
                    return
                buf += d
            masked, n, off = bool(buf[1] & 0x80), buf[1] & 0x7F, 2
            if n == 126:
                n, off = int.from_bytes(buf[2:4], "big"), 4
            need = off + (4 if masked else 0) + n
            while len(buf) < need:
                buf += c.recv(65536)
            key = buf[off:off + 4] if masked else b"\0\0\0\0"
            body = bytes(b ^ key[i % 4] for i, b in enumerate(buf[off + (4 if masked else 0):need]))
            self.frames.append((buf[0] & 0x0F, masked, body))
            buf = buf[need:]
            if body.startswith(b"SIP/2.0"):
                continue
            head = body.split(b"\r\n\r\n")[0].decode()
            keep = [l for l in head.split("\r\n") if l.split(":")[0] in ("Via", "From", "To", "Call-ID", "CSeq")]
            c.sendall(frame(1, ("SIP/2.0 200 OK\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n").encode(), mask=False))


def main():
    cfg = os.path.join(ROOT, "target/e2e_ws.cfg")
    open(cfg, "w").write(CFG)
    uas = UdpUas(UAS_UDP)
    out_ws, out_wss = WsServer(OUT_WS), WsServer(OUT_WSS, tls=True)
    proxy = subprocess.Popen(
        [f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", "udp:127.0.0.1:5260", "-l", f"ws:127.0.0.1:{WS}",
         "-l", f"wss:127.0.0.1:{WSS}", "-n", "1", "--tcp-readers", "2", "--tcp-lifetime", "4", "--tcp-connect-timeout", "2",
         "--ws-origin", "https://app.example", "--ws-deflate",
         "--tls-cert", f"{TLS}/server.pem", "--tls-key", f"{TLS}/server.key.pem", "--tls-ca", f"{TLS}/ca.pem"],
        stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    try:
        # 1. Opening handshake.
        c = WsClient(WS)
        check("101 Switching Protocols", c.head.startswith("HTTP/1.1 101"), c.head[:40])
        check("Sec-WebSocket-Accept is correct", f"Sec-WebSocket-Accept: {c.expected_accept()}" in c.head, c.head)
        check("subprotocol sip selected", "Sec-WebSocket-Protocol: sip" in c.head)

        # 2. SIP over WS → UDP downstream; reply comes back as an unmasked text frame.
        c.send(frame(1, sip("MESSAGE", "bob", "w1")))
        f = c.recv_frame()
        down = uas.got[-1].decode() if uas.got else ""
        check("relayed MESSAGE answered in a TEXT frame", f and f[0] == "TEXT" and f[2].startswith(b"SIP/2.0 200"), f)
        check("downstream sees proxy's UDP Via above the client's WS Via", "Via: SIP/2.0/UDP 127.0.0.1:5260" in down
              and "SIP/2.0/WS df7jal23ls0d.invalid" in down, down[:300])
        check("reply carries only the client's Via", f and f[2].count(b"Via:") == 1)

        # 3. Fragmented message with a ping between the fragments (allowed by RFC 6455).
        m = sip("MESSAGE", "bob", "w2", body="fragmented body")
        c.send(frame(1, m[:20], fin=False) + frame(9, b"hi") + frame(0, m[20:60], fin=False) + frame(0, m[60:]))
        f1, f2 = c.recv_frame(), c.recv_frame()
        check("ping between fragments answered with PONG", f1 == ("PONG", True, b"hi"), f1)
        check("fragmented message reassembled and relayed", f2 and f2[2].startswith(b"SIP/2.0 200")
              and uas.got[-1].endswith(b"fragmented body"), f2)

        # 4. Two messages in one TCP segment.
        c.send(frame(1, sip("OPTIONS", "x", "o1")) + frame(1, sip("OPTIONS", "x", "o2")))
        fs = [c.recv_frame(), c.recv_frame()]
        check("two frames in one segment → two replies", all(x and x[2].startswith(b"SIP/2.0 200") for x in fs))

        # 5. Large message (16-bit extended length).
        big = sip("MESSAGE", "bob", "w3", body="x" * 3000)
        c.send(frame(1, big))
        f = c.recv_frame()
        check("3 KB message (extended length)", f and f[2].startswith(b"SIP/2.0 200") and uas.got[-1].endswith(b"x" * 3000))

        # 6. Close handshake: server echoes the status code and closes.
        c.send(frame(8, (1000).to_bytes(2, "big")))
        f = c.recv_frame()
        check("CLOSE echoed with code 1000", f == ("CLOSE", True, (1000).to_bytes(2, "big")), f)
        check("TCP closed after CLOSE", c.closed())

        # 7. Unmasked client frame → close 1002.
        c = WsClient(WS)
        c.send(frame(1, sip("OPTIONS", "x", "um"), mask=False))
        f = c.recv_frame()
        check("unmasked client frame → CLOSE 1002", f == ("CLOSE", True, (1002).to_bytes(2, "big")), f)
        check("…and connection closed", c.closed())

        # 8. Handshake rejections.
        c = WsClient(WS, protocol=None)
        check("no 'sip' subprotocol → 400 (RFC 7118 §4)", c.head.startswith("HTTP/1.1 400") and c.closed(), c.head[:40])
        c = WsClient(WS, version="8")
        check("unsupported version → 426", c.head.startswith("HTTP/1.1 426") and "Sec-WebSocket-Version: 13" in c.head)

        # 8b. Origin allow-list (browsers only; no Origin = non-browser = allowed).
        c = WsClient(WS, headers="Origin: https://evil.example\r\n")
        check("foreign Origin → 403", c.head.startswith("HTTP/1.1 403") and c.closed(), c.head[:40])
        c = WsClient(WS, headers="Origin: https://app.example\r\n")
        check("allowed Origin → 101", c.head.startswith("HTTP/1.1 101"), c.head[:40])

        # 8c. Strict UTF-8 for TEXT messages (BINARY may carry anything).
        c.send(frame(2, sip("MESSAGE", "bob", "bin", body="\u00e9").replace("\u00e9".encode(), b"\xff")))
        f = c.recv_data()
        check("BINARY message with non-UTF-8 body is relayed", f and f[2].startswith(b"SIP/2.0 200"), f)
        c.send(frame(1, sip("MESSAGE", "bob", "utf", body="x").replace(b"\r\n\r\nx", b"\r\n\r\n\xff")))
        f = c.recv_frame()
        check("TEXT message with invalid UTF-8 → CLOSE 1007", f == ("CLOSE", True, (1007).to_bytes(2, "big")), f)
        check("…and connection closed", c.closed())

        # 8d. permessage-deflate (RFC 7692), checked with Python's zlib.
        c = WsClient(WS, headers="Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n")
        check("permessage-deflate negotiated (server_no_context_takeover)",
              "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover" in c.head, c.head)
        comp = zlib.compressobj(wbits=-15)  # keeps its window across messages: client context takeover
        def recv_sip():
            f = c.recv_data()
            if not f:
                return b""
            # server_no_context_takeover: a fresh decompressor per message works
            return zlib.decompressobj(wbits=-15).decompress(f[2] + b"\x00\x00\xff\xff") if c.rsv1 else f[2]
        oks = []
        for i in range(3):
            body = "compressible " * 40
            z = comp.compress(sip("MESSAGE", "bob", f"z{i}", body=body)) + comp.flush(zlib.Z_SYNC_FLUSH)
            c.send(frame(1, z[:-4], rsv1=True))
            reply = recv_sip()
            oks.append(reply.startswith(b"SIP/2.0 200") and uas.got[-1].endswith(body.encode()))
        check("3 compressed requests (client context takeover) relayed", all(oks), oks)
        check("replies come back compressed (RSV1)", c.rsv1)
        c.send(frame(1, sip("OPTIONS", "x", "small")))
        r = recv_sip()
        check("uncompressed message still accepted after negotiation", r.startswith(b"SIP/2.0 200"), r[:40])
        c.send(frame(1, b"\xff\xfe garbage", rsv1=True))
        f = c.recv_frame()
        check("corrupt deflate data → CLOSE 1007", f == ("CLOSE", True, (1007).to_bytes(2, "big")), f)
        c = WsClient(WS)
        c.send(frame(1, b"abc", rsv1=True))
        f = c.recv_frame()
        check("RSV1 without negotiation → CLOSE 1002", f == ("CLOSE", True, (1002).to_bytes(2, "big")), f)

        # 9. WSS (WebSocket over TLS).
        c = WsClient(WSS, tls=True)
        c.send(frame(1, sip("MESSAGE", "bob", "s1")))
        f = c.recv_data()
        check("WSS handshake + relayed MESSAGE", c.head.startswith("HTTP/1.1 101") and f and f[2].startswith(b"SIP/2.0 200"), f)
        c.s.close()

        # 10. Outbound WS: nothing listening → connection refused → 503.
        c = WsClient(WS)
        c.send(frame(1, sip("MESSAGE", "wsoutx", "o3")))
        f = c.recv_frame()
        check("t_relay to a ws: peer that refuses the connection → script sends 503", f and f[2].startswith(b"SIP/2.0 503"), f)
        # t_reply replaces tm's delayed 477 (Kamailio: kill_transaction sends
        # nothing once a final went out through the transaction).
        extra = c.recv_frame(timeout=0.5)
        check("…and it is the only final reply", not extra or extra[0] == "PING", extra)

        # 10b. Outbound WS / WSS client connections (ferrosip dials).
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(("127.0.0.1", 5271))
        u.settimeout(3)
        for name, srv in (("tows", out_ws), ("towss", out_wss)):
            u.sendto(sip("MESSAGE", name, f"out{name}").replace(b"SIP/2.0/WS df7jal23ls0d.invalid", b"SIP/2.0/UDP 127.0.0.1:5271"), ("127.0.0.1", 5260))
            try:
                r = u.recv(65535)
            except socket.timeout:
                r = b""
            up = srv.upgrades[-1] if srv.upgrades else ""
            fr = srv.frames[-1] if srv.frames else (0, False, b"")
            check(f"outbound {name[2:].upper()}: upgrade with Sec-WebSocket-Protocol: sip, masked TEXT frame, reply relayed back",
                  "Sec-WebSocket-Protocol: sip" in up and up.startswith("GET / HTTP/1.1") and fr[0] == 1 and fr[1] and fr[2].startswith(b"MESSAGE ")
                  and r.startswith(b"SIP/2.0 200"), (up[:80], fr[:2], r[:30]))
        n_before = len(out_ws.upgrades)
        u.sendto(sip("MESSAGE", "tows", "outws2").replace(b"SIP/2.0/WS df7jal23ls0d.invalid", b"SIP/2.0/UDP 127.0.0.1:5271"), ("127.0.0.1", 5260))
        r = u.recv(65535)
        check("…the connection is reused for the next request", r.startswith(b"SIP/2.0 200") and len(out_ws.upgrades) == n_before)

        # 10c. event_route[websocket:handshake] vets upgrades.
        bad = WsClient(WS, headers="User-Agent: BadBot/1.0\r\n")
        good = WsClient(WS, headers="User-Agent: Phone/2.0\r\n")
        check("event_route[websocket:handshake]: drop → 403, otherwise 101", bad.head.startswith("HTTP/1.1 403") and good.head.startswith("HTTP/1.1 101"),
              (bad.head[:30], good.head[:30]))
        priv = WsClient(WS, path="/private")
        check("…$hdr(X-WS-Path) is the request path (/private refused)", priv.head.startswith("HTTP/1.1 403"), priv.head[:30])

        # 11. Keep-alive: idle client is pinged at lifetime/2; answering keeps it open.
        t0 = time.time()
        f = c.recv_frame(timeout=5)
        check("server pings idle WS client", f and f[0] == "PING" and 1.5 < time.time() - t0 < 4, (f, time.time() - t0))
        c.send(frame(10, f[2] if f else b""))
        time.sleep(2.5)  # now > lifetime since our last *request*, but the pong was activity
        c.send(frame(1, sip("OPTIONS", "x", "ka")))
        f = c.recv_data()
        check("pong keeps the connection alive past the lifetime", f and f[2].startswith(b"SIP/2.0 200"), f)
        # Ignore the next ping: the connection is closed after the lifetime.
        check("unanswered ping → closed after lifetime", c.closed(timeout=7))

        # A client that opens TCP and never completes the upgrade is closed at
        # the handshake deadline (--tcp-connect-timeout 2), not after the
        # idle lifetime (4 s).
        h = socket.create_connection(("127.0.0.1", WS))
        h.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")
        t0 = time.time()
        h.settimeout(6)
        try:
            gone = h.recv(1024) == b""
        except OSError:
            gone = True
        dt = time.time() - t0
        h.close()
        check("WebSocket upgrade never completed → closed at the connect timeout", gone and dt < 3.5, round(dt, 2))
    finally:
        proxy.terminate()
        err = proxy.communicate(timeout=5)[1]
        check("no panics in proxy log", "panic" not in err, err)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
