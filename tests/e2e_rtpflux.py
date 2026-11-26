#!/usr/bin/env python3
"""ferrosip with rtpflux (https://github.com/RustedBytes/rtpflux) as its
media relay, in place of rtpengine: the rtpengine module speaks the ng
protocol to a real relay, and real RTP goes through it.

The same call is placed twice, through a Kamailio-style .cfg
(rtpengine_manage) and through .fsr (media.offer / media.answer /
media.delete):
- the INVITE's SDP reaches the callee rewritten to the relay (address and
  a port from rtpflux's range), and the 200's SDP reaches the caller
  rewritten too, with another relay port;
- rtpflux lists the call while it is up;
- RTP from the caller reaches the callee from the relay's port, and the
  callee's RTP comes back the same way (latching on both sides), payloads
  intact;
- `query` on rtpflux counts the packets;
- the BYE deletes the call: rtpflux no longer lists it.

rtpflux: $RTPFLUX (the binary), else ../rtpflux/target/release/rtpflux;
without one the test is skipped (CI builds it when the RTPFLUX_TOKEN
secret is set: rtpflux is a private repository).
Run from the repo root after `cargo build --release`.
"""
import os, re, socket, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = f"{ROOT}/target/release/ferrosip"
RTPFLUX = os.environ.get("RTPFLUX") or os.path.join(os.path.dirname(ROOT), "rtpflux/target/release/rtpflux")
PROXY, NG, UAC, UAS, UAC_RTP, UAS_RTP = 7720, 7722, 7730, 7731, 7740, 7742
PORT_MIN, PORT_MAX = 41000, 41199
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


# ------------------------------------------------------------- bencode (ng) ---

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
    if c == b"l":
        out, i = [], i + 1
        while b[i:i + 1] != b"e":
            x, i = bdec(b, i)
            out.append(x)
        return out, i + 1
    if c == b"d":
        out, i = {}, i + 1
        while b[i:i + 1] != b"e":
            k, i = bdec(b, i)
            v, i = bdec(b, i)
            out[k.decode()] = v
        return out, i + 1
    j = b.index(b":", i)
    n = int(b[i:j])
    return b[j + 1:j + 1 + n], j + 1 + n


def ng(cmd):
    """One ng command straight to rtpflux (the test's own view of it)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    cookie = b"t%d" % (time.time_ns() % 10**9)
    s.sendto(cookie + b" " + benc(cmd), ("127.0.0.1", NG))
    data = s.recv(65535)
    s.close()
    return bdec(data.split(b" ", 1)[1])[0]


# ---------------------------------------------------------------------- SIP ---

class Sock:
    def __init__(self, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.port = port

    def send(self, msg, to=PROXY):
        self.s.sendto(msg.encode() if isinstance(msg, str) else msg, ("127.0.0.1", to))

    def recv_raw(self, timeout=1.0):
        self.s.settimeout(timeout)
        try:
            return self.s.recvfrom(65535)
        except socket.timeout:
            return None, None

    def recv(self, timeout=3.0, want=None):
        """The next datagram (str for SIP); `want` skips 1xx replies."""
        end = time.time() + timeout
        while time.time() < end:
            self.s.settimeout(max(0.05, end - time.time()))
            try:
                data, addr = self.s.recvfrom(65535)
            except socket.timeout:
                return None, None
            m = data.decode(errors="replace")
            if want == "final" and m.startswith("SIP/2.0 1"):
                continue
            return m, addr
        return None, None


def sdp(port, sess="1"):
    return (f"v=0\r\no=- {sess} 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
            f"m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n")


def body_of(m):
    return m.split("\r\n\r\n", 1)[1] if m and "\r\n\r\n" in m else ""


def media_of(m):
    """(address, port) of the SDP's c= and m=audio lines."""
    b = body_of(m)
    c = re.search(r"c=IN IP4 (\S+)", b)
    p = re.search(r"m=audio (\d+)", b)
    return (c.group(1) if c else None, int(p.group(1)) if p else None)


def header(m, name):
    for line in m.split("\r\n"):
        if line.lower().startswith(name.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return None


def rtp(seq, ssrc, payload):
    return bytes([0x80, 0x00]) + seq.to_bytes(2, "big") + (seq * 160).to_bytes(4, "big") + ssrc.to_bytes(4, "big") + payload


def call(label):
    """One call through ferrosip + rtpflux; checks prefixed with `label`."""
    uac, uas = Sock(UAC), Sock(UAS)
    ra, rb = Sock(UAC_RTP), Sock(UAS_RTP)
    cid = f"rtpflux-{label}-{time.time_ns()}"
    try:
        offer = sdp(UAC_RTP)
        inv = (f"INVITE sip:bob@127.0.0.1:{UAS} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UAC};branch=z9hG4bK{cid}a;rport\r\n"
               f"From: <sip:alice@127.0.0.1>;tag=alice\r\nTo: <sip:bob@127.0.0.1>\r\nCall-ID: {cid}\r\nCSeq: 1 INVITE\r\n"
               f"Contact: <sip:alice@127.0.0.1:{UAC}>\r\nMax-Forwards: 70\r\nContent-Type: application/sdp\r\n"
               f"Content-Length: {len(offer)}\r\n\r\n{offer}")
        uac.send(inv)
        got, _ = uas.recv()
        check(f"{label}: the INVITE reaches the callee", got and got.startswith("INVITE "), got or uac.recv(0.5)[0])
        if not got:
            return
        addr, port_b = media_of(got)
        check(f"{label}: the offer is rewritten to rtpflux (address and a port from its range)",
              addr == "127.0.0.1" and port_b is not None and PORT_MIN <= port_b <= PORT_MAX and port_b != UAC_RTP, (addr, port_b))
        check(f"{label}: Content-Length matches the rewritten SDP", int(header(got, "Content-Length")) == len(body_of(got).encode()))
        listed = ng({"command": "list"})
        check(f"{label}: rtpflux lists the call after the offer", cid.encode() in listed.get("calls", []), listed)

        # The callee answers 200 with its SDP.
        ans = sdp(UAS_RTP, "2")
        keep = [l for l in got.split("\r\n") if l.split(":", 1)[0].lower() in ("via", "from", "call-id", "cseq", "record-route")]
        ok = ("SIP/2.0 200 OK\r\n" + "\r\n".join(keep) + f"\r\nTo: <sip:bob@127.0.0.1>;tag=bob\r\n"
              f"Contact: <sip:bob@127.0.0.1:{UAS}>\r\nContent-Type: application/sdp\r\nContent-Length: {len(ans)}\r\n\r\n{ans}")
        uas.send(ok)
        r, _ = uac.recv(want="final")
        check(f"{label}: the 200 reaches the caller", r and r.startswith("SIP/2.0 200"), r)
        if not r:
            return
        addr, port_a = media_of(r)
        check(f"{label}: the answer is rewritten to rtpflux, on another port",
              addr == "127.0.0.1" and port_a is not None and PORT_MIN <= port_a <= PORT_MAX and port_a not in (UAS_RTP, port_b), (addr, port_a))
        rr = header(r, "Record-Route")
        route = f"Route: {rr}\r\n" if rr else ""
        uac.send(f"ACK sip:bob@127.0.0.1:{UAS} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UAC};branch=z9hG4bK{cid}k;rport\r\n"
                 f"{route}From: <sip:alice@127.0.0.1>;tag=alice\r\nTo: <sip:bob@127.0.0.1>;tag=bob\r\nCall-ID: {cid}\r\n"
                 f"CSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
        a, _ = uas.recv()
        check(f"{label}: the ACK reaches the callee", a and a.startswith("ACK "), a)

        # Media, both ways, through the relay.
        n, okb, oka, src_b, src_a = 20, 0, 0, set(), set()
        for i in range(n):
            pa = b"A" * 160
            ra.send(rtp(i + 1, 0x1111, pa), to=port_a)
            d, src = rb.recv_raw()
            if d is not None and d[12:] == pa:
                okb += 1
                src_b.add(src)
            pb = b"B" * 160
            rb.send(rtp(i + 1, 0x2222, pb), to=port_b)
            d, src = ra.recv_raw()
            if d is not None and d[12:] == pb:
                oka += 1
                src_a.add(src)
        check(f"{label}: caller → callee RTP relayed ({okb}/{n}), from the relay's port", okb >= n - 1 and src_b == {("127.0.0.1", port_b)}, (okb, src_b))
        check(f"{label}: callee → caller RTP relayed ({oka}/{n}), from the relay's port", oka >= n - 1 and src_a == {("127.0.0.1", port_a)}, (oka, src_a))
        q = ng({"command": "query", "call-id": cid})
        rtp_tot = q.get("totals", {}).get("RTP", {})
        check(f"{label}: rtpflux query counts the packets", q.get("result") == b"ok" and rtp_tot.get("packets", 0) >= 2 * (n - 1), (q.get("result"), rtp_tot))

        # BYE from the caller: the proxy deletes the session.
        uac.send(f"BYE sip:bob@127.0.0.1:{UAS} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UAC};branch=z9hG4bK{cid}b;rport\r\n"
                 f"{route}From: <sip:alice@127.0.0.1>;tag=alice\r\nTo: <sip:bob@127.0.0.1>;tag=bob\r\nCall-ID: {cid}\r\n"
                 f"CSeq: 2 BYE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
        bye, _ = uas.recv()
        check(f"{label}: the BYE reaches the callee", bye and bye.startswith("BYE "), bye)
        if bye:
            keep = [l for l in bye.split("\r\n") if l.split(":", 1)[0].lower() in ("via", "from", "to", "call-id", "cseq")]
            uas.send("SIP/2.0 200 OK\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n")
            r, _ = uac.recv(want="final")
            check(f"{label}: the BYE's 200 comes back", r and r.startswith("SIP/2.0 200"), r)
        time.sleep(0.2)
        listed = ng({"command": "list"})
        check(f"{label}: the BYE deleted the call in rtpflux", cid.encode() not in listed.get("calls", []), listed)
        ra.send(rtp(99, 0x1111, b"late"), to=port_a)
        d, _ = rb.recv_raw(0.3)
        check(f"{label}: no media relayed after the delete", d is None, d)
    finally:
        for s in (uac, uas, ra, rb):
            s.s.close()


CFG = f'''loadmodule "sl"
loadmodule "siputils"
loadmodule "tm"
loadmodule "rr"
loadmodule "textops"
loadmodule "rtpengine"
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:{NG}")

request_route {{
    if (has_totag()) {{
        if (loose_route()) {{
            if (is_method("BYE")) {{ rtpengine_delete(); }}
            t_relay();
            exit;
        }}
        sl_send_reply("404", "Not here");
        exit;
    }}
    if (is_method("INVITE")) {{
        record_route();
        if (!rtpengine_manage("trust-address replace-origin")) {{ sl_send_reply("500", "rtp failed"); exit; }}
        t_on_reply("MEDIA");
    }}
    t_relay();
}}

onreply_route[MEDIA] {{
    if (has_body("application/sdp")) {{ rtpengine_manage("trust-address replace-origin"); }}
}}
'''

FSR = '''import route_set, media

route main(msg: Request) {
    if msg.has_to_tag {
        guard route_set.follow() else reply(404, "Not here")
        if msg.method == BYE {
            media.delete()
        }
        relay(msg)
    }
    if msg.method == INVITE {
        route_set.record()
        guard media.offer("trust-address replace-origin") else reply(500, "rtp failed")
    }
    relay(msg)
}

on reply(r: Reply) {
    if r.has_sdp {
        media.answer("trust-address replace-origin")
    }
}
'''

TOML = f'''[[listen]]
proto = "udp"
addr = "127.0.0.1:{PROXY}"

[modules.media]
rtpengine_sock = "udp:127.0.0.1:{NG}"

[routing]
entry = "main.fsr"
'''

RTPFLUX_CFG = f'''[control]
listen = ["127.0.0.1:{NG}"]

[[interface]]
name = "default"
address = "127.0.0.1"

[ports]
min = {PORT_MIN}
max = {PORT_MAX}

[sessions]
max = 20
timeout = 30

[runtime]
workers = 2
'''


def stop(p):
    p.terminate()
    try:
        return p.communicate(timeout=10)[1]
    except subprocess.TimeoutExpired:
        p.kill()
        return p.communicate()[1]


def main():
    if not os.path.exists(RTPFLUX):
        print(f"SKIP no rtpflux binary at {RTPFLUX} (set RTPFLUX, or build ../rtpflux)")
        return 0
    d = tempfile.mkdtemp(prefix="ferrosip-e2e-rtpflux-")
    for name, text in [("rtpflux.toml", RTPFLUX_CFG), ("main.cfg", CFG), ("main.fsr", FSR), ("ferrosip.toml", TOML)]:
        open(os.path.join(d, name), "w").write(text)
    chk = subprocess.run([RTPFLUX, "--check", "-c", f"{d}/rtpflux.toml"], capture_output=True, text=True, timeout=30)
    check("rtpflux --check accepts the config", chk.returncode == 0, chk.stdout + chk.stderr)
    relay = subprocess.Popen([RTPFLUX, "-c", f"{d}/rtpflux.toml"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(50):
            try:
                if ng({"command": "ping"}).get("result") == b"pong":
                    break
            except OSError:
                time.sleep(0.1)
        check("rtpflux answers ng ping", ng({"command": "ping"}).get("result") == b"pong")
        for label, args in [(".cfg", ["-f", f"{d}/main.cfg", "-l", f"udp:127.0.0.1:{PROXY}"]), (".fsr", ["--config", f"{d}/ferrosip.toml"])]:
            ok = subprocess.run([BIN, "check", *args], capture_output=True, text=True, timeout=30)
            check(f"{label}: ferrosip check accepts the routing", "config OK" in ok.stderr, ok.stderr[-400:])
            p = subprocess.Popen([BIN, *args], stderr=subprocess.PIPE, text=True)
            wait_listening(p)
            try:
                call(label)
            finally:
                err = p.early_log + stop(p)
            check(f"{label}: ferrosip ran without panics or rtpengine errors", "panicked" not in err and "rtpengine" not in err.lower().replace("loadmodule", ""), err[-800:])
    finally:
        rerr = stop(relay)
    check("rtpflux ran without errors", " ERROR " not in rerr and "panicked" not in rerr, rerr[-800:])
    print("\nall passed" if failures == 0 else f"\n{failures} FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
