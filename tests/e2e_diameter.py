#!/usr/bin/env python3
"""End-to-end checks for the Diameter transports and routing of `cdp`
(sip-diameter): TLS to and from peers (RFC 6733 §13, client certificates
verified both ways), SCTP (skipped when the kernel has no SCTP), realm
routing tables (`<Realm><Route metric/></Realm>`, then `<DefaultRoute>`),
and `ims_diameter_server` (`event_route[diameter:request]` answering
incoming requests from `$diameter_response`, `diameter_request()` sending
them).

Scripted Python peers play the other Diameter nodes. Run from the repo
root after `cargo build --release`.
"""
import json, os, socket, ssl, struct, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TLS_DIR = f"{ROOT}/etc/tls"
SIP = 7260
P_TLS, A_TLS, A_SCTP = 7268, 7269, 7270
P_HSS1, P_HSS2, P_HSS0 = 7271, 7272, 7273  # hss0 is never up
SIP_F, A_F = 7360, 7368  # the .fsr instance
SOCK_F = os.path.join(ROOT, "target/e2e_diameter_fsr.sock")
SOCK = os.path.join(ROOT, "target/e2e_diameter.sock")

failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def sctp_supported():
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132).close()
        return True
    except OSError:
        return False


# ------------------------------------------------------------- Diameter --
def avp(code, data, vendor=None, mandatory=True):
    if isinstance(data, int):
        data = struct.pack("!I", data)
    elif isinstance(data, str):
        data = data.encode()
    elif isinstance(data, list):
        data = b"".join(data)
    flags = (0x40 if mandatory else 0) | (0x80 if vendor else 0)
    hl = 12 if vendor else 8
    ln = hl + len(data)
    out = struct.pack("!I", code) + bytes([flags]) + ln.to_bytes(3, "big") + (struct.pack("!I", vendor) if vendor else b"") + data
    return out + b"\x00" * ((4 - ln % 4) % 4)


def parse_avps(b):
    out, i = [], 0
    while i + 8 <= len(b):
        code, = struct.unpack("!I", b[i:i + 4])
        flags = b[i + 4]
        ln = int.from_bytes(b[i + 5:i + 8], "big")
        hl = 12 if flags & 0x80 else 8
        vendor = struct.unpack("!I", b[i + 8:i + 12])[0] if flags & 0x80 else None
        out.append((code, vendor, b[i + hl:i + ln]))
        i += (ln + 3) & ~3
    return out


def get(avps, code, vendor=None):
    for c, v, d in avps:
        if c == code and v == vendor:
            return d
    return None


def u32(d):
    return struct.unpack("!I", d)[0] if d is not None and len(d) == 4 else None


HBH = [0x1000]


def encode(flags, cmd, app, avps, hbh=None, e2e=None):
    if hbh is None:
        HBH[0] += 1
        hbh = e2e = HBH[0]
    body = b"".join(avps)
    return bytes([1]) + (20 + len(body)).to_bytes(3, "big") + bytes([flags]) + cmd.to_bytes(3, "big") + struct.pack("!III", app, hbh, e2e) + body


def read_msg(f):
    h = f.read(20)
    if len(h) < 20:
        return None
    ln = int.from_bytes(h[1:4], "big")
    body = f.read(ln - 20)
    app, hbh, e2e = struct.unpack("!III", h[8:20])
    return {"flags": h[4], "cmd": int.from_bytes(h[5:8], "big"), "app": app, "hbh": hbh, "e2e": e2e, "avps": parse_avps(body)}


class Node(threading.Thread):
    """A Diameter node accepting connections (plain, TLS or SCTP): answers
    CER, DWR and the commands in `handlers` ({cmd: fn(msg) -> [avps]})."""

    def __init__(self, name, port, tls=None, sctp=False, handlers=None):
        super().__init__(daemon=True)
        self.name, self.tls, self.handlers = name, tls, handlers or {}
        self.l = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132 if sctp else 0)
        self.l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l.bind(("127.0.0.1", port))
        self.l.listen(8)
        self.log, self.peer_certs, self.conns = [], [], []
        self.start()

    def run(self):
        while True:
            try:
                c, _ = self.l.accept()
            except OSError:
                return
            self.conns.append(c)
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def close(self):
        """Go down: the listener and every connection."""
        self.l.close()
        for c in self.conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            c.close()

    def serve(self, c):
        if self.tls:
            try:
                c = self.tls.wrap_socket(c, server_side=True)
            except (ssl.SSLError, OSError) as e:
                self.log.append(("tls-error", str(e)))
                return
            cert = c.getpeercert()
            self.peer_certs.append(dict(x[0] for x in cert["subject"]) if cert else None)
        f = c.makefile("rb")
        while True:
            try:
                m = read_msg(f)
            except (OSError, ValueError):
                return
            if m is None:
                return
            if not m["flags"] & 0x80:
                continue
            self.log.append((m["cmd"], m["app"], m["avps"]))
            ident = [avp(264, self.name), avp(296, "diam.test")]
            sid = get(m["avps"], 263)
            if m["cmd"] == 257:
                body = [avp(268, 2001)] + ident + [avp(266, 10415), avp(269, "pypeer", mandatory=False), SH_APP]
            elif m["cmd"] == 280:
                body = [avp(268, 2001)] + ident
            elif m["cmd"] in self.handlers:
                body = ([avp(263, sid)] if sid else []) + ident + self.handlers[m["cmd"]](m)
            else:
                body = ([avp(263, sid)] if sid else []) + ident + [avp(268, 3001)]
            try:
                c.sendall(encode(m["flags"] & 0x40, m["cmd"], m["app"], body, m["hbh"], m["e2e"]))
            except OSError:
                return


# What the fake peers support (Vendor-Specific-Application-Id: 3GPP Sh), as
# the proxy's <Auth id="16777217" vendor="10415"/>: a CER/CEA without an
# application in common is refused with 5010.
SH_APP = avp(260, [avp(266, 10415), avp(258, 16777217)])


class Client:
    """A Diameter client connected to the proxy's acceptor."""

    def __init__(self, port, name, tls=None, sctp=False):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132 if sctp else 0)
        s.settimeout(5)
        s.connect(("127.0.0.1", port))
        if tls:
            s = tls.wrap_socket(s, server_hostname="localhost")
        self.s, self.f, self.name = s, s.makefile("rb"), name

    def ask(self, cmd, app, avps, ident=True):
        self.s.sendall(encode(0x80, cmd, app, ([avp(264, self.name), avp(296, "diam.test")] if ident else []) + avps))
        while True:
            m = read_msg(self.f)
            if m is None or not m["flags"] & 0x80:
                return m
            # A request from the proxy (DWR): answer it.
            self.s.sendall(encode(0, m["cmd"], m["app"], [avp(268, 2001), avp(264, self.name), avp(296, "diam.test")], m["hbh"], m["e2e"]))

    def cer(self):
        return self.ask(257, 0, [avp(257, b"\x00\x01\x7f\x00\x00\x01"), avp(266, 10415), avp(269, "pyclient", mandatory=False), SH_APP])


def ctl(*args, sock=SOCK):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", sock, *args], capture_output=True, text=True, timeout=5)
    try:
        return json.loads(out.stdout) if out.stdout.strip() else out.stderr.strip()
    except json.JSONDecodeError:
        return out.stdout


def sip(user, hdrs="", to=SIP):
    """A SIP MESSAGE to the proxy; its reply."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(8)
    port = s.getsockname()[1]
    tag = time.time_ns()
    m = (f"MESSAGE sip:{user}@diam.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bK{tag}\r\n"
         f"From: <sip:tester@diam.test>;tag={tag}\r\nTo: <sip:{user}@diam.test>\r\nCall-ID: {tag}@t\r\nCSeq: 1 MESSAGE\r\n"
         f"Max-Forwards: 70\r\n{hdrs}Content-Length: 0\r\n\r\n")
    s.sendto(m.encode(), ("127.0.0.1", to))
    try:
        r = s.recv(65535).decode(errors="replace")
    except socket.timeout:
        r = ""
    s.close()
    return r


def answer_of(reply):
    """The X-Answer header (diameter_request's $diameter_response) as JSON."""
    for line in reply.split("\r\n"):
        if line.lower().startswith("x-answer:"):
            try:
                return json.loads(line.split(":", 1)[1].strip())
            except json.JSONDecodeError:
                return line
    return None


def jget(avps, code):
    return next((a for a in avps or [] if isinstance(a, dict) and a.get("avpCode") == code), {})


def start(cfg_text, xml):
    xp = os.path.join(ROOT, "target/e2e_diameter_cdp.xml")
    open(xp, "w").write(xml)
    cfg = os.path.join(ROOT, "target/e2e_diameter.cfg")
    open(cfg, "w").write(cfg_text.replace("@XML@", xp))
    return subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{SIP}", "-n", "2", "--rpc-socket", SOCK],
                            stderr=subprocess.PIPE, text=True)


def stop(p):
    p.terminate()
    try:
        return p.communicate(timeout=3)[1]
    except subprocess.TimeoutExpired:
        p.kill()
        return p.communicate()[1]


def wait_open(fqdn, secs=5):
    end = time.time() + secs
    while time.time() < end:
        peers = ctl("cdp.list_peers")
        if isinstance(peers, list) and any(p["FQDN"] == fqdn and p["State"] == "I_Open" for p in peers):
            return peers
        time.sleep(0.1)
    return ctl("cdp.list_peers")


XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<DiameterPeer FQDN="proxy.diam.test" Realm="diam.test" Vendor_Id="10415" Product_Name="ferrosip" Tc="1" TransactionTimeout="2">
    <Peer FQDN="localhost" Realm="diam.test" port="{P_TLS}" host="127.0.0.1" proto="tls"/>
    <Acceptor port="{A_TLS}" bind="127.0.0.1" proto="tls"/>
    @SCTP@
    <Peer FQDN="hss1.diam.test" Realm="diam.test" port="{P_HSS1}" host="127.0.0.1"/>
    <Peer FQDN="hss2.diam.test" Realm="diam.test" port="{P_HSS2}" host="127.0.0.1"/>
    <Peer FQDN="hss0.diam.test" Realm="diam.test" port="{P_HSS0}" host="127.0.0.1"/>
    <Realm name="sh.test">
        <Route FQDN="hss1.diam.test" metric="20"/>
        <Route FQDN="hss0.diam.test" metric="1"/>
        <Route FQDN="hss2.diam.test" metric="10"/>
    </Realm>
    <DefaultRoute FQDN="hss2.diam.test" metric="9"/>
    <DefaultRoute FQDN="hss1.diam.test" metric="5"/>
    <TLS certificate="{TLS_DIR}/server.pem" private_key="{TLS_DIR}/server.key.pem" ca_list="{TLS_DIR}/ca.pem" require_certificate="1"/>
    <Auth id="16777217" vendor="10415"/>
</DiameterPeer>
"""

CFG = r"""
loadmodule "sl"
loadmodule "textops"
loadmodule "xlog"
loadmodule "cdp"
loadmodule "cdp_avp"
loadmodule "ims_diameter_server"
modparam("cdp", "config_file", "@XML@")

request_route {
    # diameter_request(peer, appid, commandcode, message): the answer's AVPs
    # (JSON) in $diameter_response, sent back in X-Answer.
    if ($rU == "realm") {
        $var(m) = "[{\"avpCode\":283,\"vendorId\":0,\"Flags\":64,\"string\":\"" + $hdr(X-Realm) + "\"},{\"avpCode\":700,\"vendorId\":10415,\"Flags\":192,\"list\":[{\"avpCode\":601,\"vendorId\":10415,\"Flags\":192,\"string\":\"sip:alice@diam.test\"}]},{\"avpCode\":703,\"vendorId\":10415,\"Flags\":192,\"int32\":0}]";
        if (diameter_request("$hdr(X-Peer)", "16777217", "306", "$var(m)")) {
            append_to_reply("X-Answer: $diameter_response\r\n");
            sl_send_reply(200, "OK");
        } else {
            sl_send_reply(500, "No Answer");
        }
        exit;
    }
    # Kamailio's 3-argument form: no peer, routed by Destination-Realm.
    if ($rU == "three") {
        $var(m) = "[{\"avpCode\":283,\"vendorId\":0,\"Flags\":64,\"string\":\"sh.test\"}]";
        if (diameter_request("16777217", "306", "$var(m)")) {
            append_to_reply("X-Answer: $diameter_response\r\n");
            sl_send_reply(200, "OK");
        } else {
            sl_send_reply(500, "No Answer");
        }
        exit;
    }
    # diameter_request_async: 0 (the route ends); the answer runs
    # event_route[diameter:response].
    if ($rU == "async") {
        sl_send_reply(202, "Accepted");
        diameter_request_async("hss1.diam.test", "16777217", "306", "[{\"avpCode\":601,\"vendorId\":10415,\"string\":\"sip:async@diam.test\"}]");
        xlog("L_ERR", "not reached: diameter_request_async ends the route\n");
        exit;
    }
    sl_send_reply(404, "Not Found");
}

# The answer to diameter_request_async: tell hss1 what came back.
event_route[diameter:response] {
    if ($diameter_response =~ "hss1.diam.test") {
        diameter_request("hss1.diam.test", "16777217", "309", "[{\"avpCode\":601,\"vendorId\":10415,\"Flags\":192,\"string\":\"async-answer-seen\"}]");
    }
}

# Incoming requests (Sh UDR, PUR, …) that no IMS module handles.
event_route[diameter:request] {
    if ($diameter_application == 16777217 && $diameter_command == 306) {
        if ($diameter_request =~ "sip:alice@diam.test") {
            $diameter_response = "[{\"avpCode\":702,\"vendorId\":10415,\"Flags\":192,\"string\":\"<Sh-Data>alice</Sh-Data>\"}]";
        } else {
            $diameter_response = "[{\"avpCode\":297,\"vendorId\":0,\"Flags\":64,\"list\":[{\"avpCode\":266,\"vendorId\":0,\"Flags\":64,\"int32\":10415},{\"avpCode\":298,\"vendorId\":0,\"Flags\":64,\"int32\":5001}]}]";
        }
    } else if ($diameter_command == 307) {
        $diameter_response = "[{\"avpCode\":268,\"vendorId\":0,\"Flags\":64,\"int32\":5012}]";
    }
}
"""


FSR_TOML = f"""
[[listen]]
proto = "udp"
addr = "127.0.0.1:{SIP_F}"

[modules.diameter]
identity = "fsr.diam.test"
realm = "diam.test"
peer = ["fqdn=hss1.diam.test;realm=diam.test;host=127.0.0.1;port={P_HSS1}"]
listen = ["127.0.0.1:{A_F}"]
realm_route = ["realm=sh.test;fqdn=hss1.diam.test;metric=1"]
auth_app = ["10415:16777217"]
tc = 1

[routing]
entry = "main.fsr"
"""

FSR = r"""import ims_diameter_server, text

route main(msg: Request) {
    let m = "[\{\"avpCode\":283,\"vendorId\":0,\"string\":\"sh.test\"\}]"
    guard ims_diameter_server.request("", 16777217, 306, m) else reply(500, "No Answer")
    text.append_to_reply("X-Answer: {pv("$diameter_response")}\r\n")
    reply(200, "OK")
}

// Typed Diameter handlers (event_route[diameter:request] / [diameter:response]).
on diameter.request(req: DiameterRequest) where req.command == 306 && req.application == 16777217 && req.avps =~ "sid-f" {
    req.answer("[\{\"avpCode\":702,\"vendorId\":10415,\"string\":\"fsr {req.application}\"\}]")
}

// 307: answered, then a request of our own whose answer runs `on diameter.response`.
on diameter.request(req: DiameterRequest) where req.command == 307 {
    req.answer("[\{\"avpCode\":268,\"vendorId\":0,\"int32\":2001\}]")
    ims_diameter_server.request_async("hss1.diam.test", 16777217, 306, "[\{\"avpCode\":601,\"vendorId\":10415,\"string\":\"sip:fsr-async@diam.test\"\}]")
}

// Not answered by the handlers above: no answer is sent.
on diameter.request(req: DiameterRequest) where req.answer_avps == "" {
    log.info("unanswered {req.command}\n")
}

on diameter.response(ans: DiameterAnswer) where ans.avps =~ "hss1.diam.test" {
    ims_diameter_server.request("hss1.diam.test", 16777217, 309, "[\{\"avpCode\":601,\"vendorId\":10415,\"string\":\"fsr-async-answer-seen\"\}]")
}
"""


def start_fsr():
    d = os.path.join(ROOT, "target/e2e_diameter_fsr")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "ferrosip.toml"), "w").write(FSR_TOML)
    open(os.path.join(d, "main.fsr"), "w").write(FSR)
    return subprocess.Popen([f"{ROOT}/target/release/ferrosip", "--config", os.path.join(d, "ferrosip.toml"), "--rpc-socket", SOCK_F],
                            stderr=subprocess.PIPE, text=True, cwd=d)


def fsr_part(hss1):
    p = start_fsr()
    err = ""
    try:
        end = time.time() + 6
        while time.time() < end and not (isinstance(ctl("cdp.list_peers", sock=SOCK_F), list)
                                         and any(x["State"] == "I_Open" for x in ctl("cdp.list_peers", sock=SOCK_F))):
            time.sleep(0.1)
        a = answer_of(sip("realm", to=SIP_F))
        check(".fsr: ims_diameter_server.request(…) routed by realm_route, answer via pv(\"$diameter_response\")",
              jget(a, 264).get("string") == "hss1.diam.test" and jget(a, 268).get("int32") == 2001, a)
        nc = Client(A_F, "rx-only.diam.test")
        cea = nc.ask(257, 0, [avp(257, b"\x00\x01\x7f\x00\x00\x01"), avp(266, 10415), avp(258, 16777236)])
        check("acceptor: a CER with no application in common gets CEA 5010, then the connection closes",
              cea and u32(get(cea["avps"], 268)) == 5010 and read_msg(nc.f) is None, cea)
        c = Client(A_F, "client.diam.test")
        c.cer()
        ans = c.ask(306, 16777217, [avp(263, "sid-f")])
        check(".fsr: on diameter.request(req: DiameterRequest): req.command/application/avps, req.answer(…)", ans
              and get(ans["avps"], 702, 10415) == b"fsr 16777217" and u32(get(ans["avps"], 268)) == 2001, ans)
        n309 = sum(1 for x in hss1.log if x[0] == 309)
        ans = c.ask(307, 16777217, [avp(263, "sid-f2")])
        end = time.time() + 3
        while time.time() < end and sum(1 for x in hss1.log if x[0] == 309) == n309:
            time.sleep(0.05)
        seen = [x for x in hss1.log if x[0] == 309][n309:]
        check(".fsr: on diameter.response(ans: DiameterAnswer) runs for request_async's answer (ans.avps)", ans and u32(get(ans["avps"], 268)) == 2001
              and seen and get(seen[0][2], 601, 10415) == b"fsr-async-answer-seen", (ans, seen))
    finally:
        err = stop(p)
        check(".fsr instance: no panics", "panicked" not in err, err[-2000:])
        if failures:
            print("--- .fsr proxy stderr ---\n" + err[-3000:])


def main():
    sctp = sctp_supported()
    srv_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=f"{TLS_DIR}/ca.pem")
    srv_ctx.load_cert_chain(f"{TLS_DIR}/server.pem", f"{TLS_DIR}/server.key.pem")
    srv_ctx.verify_mode = ssl.CERT_REQUIRED
    tls_hss = Node("localhost", P_TLS, tls=srv_ctx)
    udr = lambda name: (lambda m: [avp(268, 2001), avp(1, name)])
    hss1 = Node("hss1.diam.test", P_HSS1, handlers={306: udr("hss1")})
    hss2 = Node("hss2.diam.test", P_HSS2, handlers={306: udr("hss2")})
    xml = XML.replace("@SCTP@", f'<Acceptor port="{A_SCTP}" bind="127.0.0.1" proto="sctp"/>' if sctp else "")
    p = start(CFG, xml)
    err = ""
    try:
        time.sleep(0.6)
        # ------------------------------------------------- TLS, outgoing
        peers = wait_open("localhost")
        tp = next((x for x in peers if x["FQDN"] == "localhost"), {}) if isinstance(peers, list) else {}
        check("TLS peer: CER/CEA over TLS, peer open", tp.get("State") == "I_Open" and tp.get("Proto") == "tls" and tp.get("Origin-Host") == "localhost", peers)
        check("…the proxy presented its client certificate (verified by the peer)", tls_hss.peer_certs and tls_hss.peer_certs[0].get("commonName") == "localhost",
              (tls_hss.peer_certs, tls_hss.log))
        check("…and the CER came inside TLS", any(x[0] == 257 and get(x[2], 264) == b"proxy.diam.test" for x in tls_hss.log), tls_hss.log)

        # ------------------------------------------------- TLS, incoming
        cli_ctx = ssl.create_default_context(cafile=f"{TLS_DIR}/ca.pem")
        cli_ctx.load_cert_chain(f"{TLS_DIR}/b.test.pem", f"{TLS_DIR}/b.test.key.pem")
        try:
            c = Client(A_TLS, "b.test", tls=cli_ctx)
            cea = c.cer()
            check("TLS acceptor: CER → CEA 2001 with our identity", cea and u32(get(cea["avps"], 268)) == 2001 and get(cea["avps"], 264) == b"proxy.diam.test", cea)
            dwa = c.ask(280, 0, [])
            check("…DWR → DWA", dwa and dwa["cmd"] == 280 and u32(get(dwa["avps"], 268)) == 2001, dwa)
            # ------------------------------------------------- event_route[diameter:request] (over this TLS connection)
            alice = [avp(700, [avp(601, "sip:alice@diam.test", 10415)], 10415), avp(703, 0, 10415)]
            ans = c.ask(306, 16777217, [avp(263, "sid-1"), avp(283, "diam.test")] + alice)
            check("diameter:request: Sh UDR answered from $diameter_response (Session-Id first, 2001 added)",
                  ans and ans["cmd"] == 306 and not ans["flags"] & 0x80 and ans["avps"][0][0] == 263 and get(ans["avps"], 263) == b"sid-1"
                  and u32(get(ans["avps"], 268)) == 2001 and get(ans["avps"], 702, 10415) == b"<Sh-Data>alice</Sh-Data>"
                  and get(ans["avps"], 264) == b"proxy.diam.test" and get(ans["avps"], 296) == b"diam.test", ans)
            bob = [avp(700, [avp(601, "sip:bob@diam.test", 10415)], 10415)]
            ans = c.ask(306, 16777217, [avp(263, "sid-2")] + bob)
            exp = parse_avps(get(ans["avps"] if ans else [], 297) or b"")
            check("…$diameter_request (JSON) read by the script: unknown user → Experimental-Result 5001, no Result-Code",
                  ans and u32(get(exp, 298)) == 5001 and get(ans["avps"], 268) is None, ans)
            ans = c.ask(307, 16777217, [avp(263, "sid-3")])
            check("…a Result-Code set by the script is kept", ans and u32(get(ans["avps"], 268)) == 5012, ans)
            # A request the script sets no $diameter_response for is not
            # answered (Kamailio's callback_cdp_request()): the next answer
            # on the connection is the following request's.
            c.s.sendall(encode(0x80, 308, 16777217, [avp(264, c.name), avp(296, "diam.test"), avp(263, "sid-4")]))
            ans = c.ask(307, 16777217, [avp(263, "sid-5")])
            check("…a request the script leaves alone gets no answer", ans and ans["cmd"] == 307 and get(ans["avps"], 263) == b"sid-5", ans)
            peers = ctl("cdp.list_peers")
            check("…listed as R_Open over TLS", isinstance(peers, list) and any(x["FQDN"] == "b.test" and x["State"] == "R_Open" and x["Proto"] == "tls" for x in peers), peers)
            c.s.close()
        except (OSError, ssl.SSLError) as e:
            check("TLS acceptor: handshake with a client certificate", False, e)
        anon_ctx = ssl.create_default_context(cafile=f"{TLS_DIR}/ca.pem")
        try:
            c = Client(A_TLS, "anon.test", tls=anon_ctx)
            refused = c.cer() is None
        except (OSError, ssl.SSLError):
            refused = True
        check("…a client without a certificate is refused (require_certificate)", refused)

        # ------------------------------------------------- realm routes, diameter_request
        for f in ("hss1.diam.test", "hss2.diam.test"):
            wait_open(f)
        r = sip("realm", "X-Realm: sh.test\r\nX-Peer: \r\n")
        a = answer_of(r)
        check("diameter_request: answer in $diameter_response (JSON)", r.startswith("SIP/2.0 200") and isinstance(a, list)
              and jget(a, 268).get("int32") == 2001 and jget(a, 263).get("string", "").startswith("proxy.diam.test;"), r)
        check("realm route: sh.test → hss2 (metric 10; hss0 with metric 1 is down, hss1 has 20)", jget(a, 264).get("string") == "hss2.diam.test", a)
        req = next((x for x in reversed(hss2.log) if x[0] == 306), None)
        check("…the request carried the script's AVPs (grouped User-Identity, Data-Reference) after a Session-Id",
              req and req[2][0][0] == 263 and get(parse_avps(get(req[2], 700, 10415) or b""), 601, 10415) == b"sip:alice@diam.test"
              and u32(get(req[2], 703, 10415)) == 0 and get(req[2], 283) == b"sh.test" and get(req[2], 293) is None, req)
        a = answer_of(sip("realm", "X-Realm: sh.test\r\nX-Peer: hss1.diam.test\r\n"))
        check("diameter_request to a named peer: Destination-Host wins over the realm table", jget(a, 264).get("string") == "hss1.diam.test", a)
        a = answer_of(sip("three"))
        check("diameter_request(appid, cmd, message): routed by Destination-Realm (sh.test → hss2)", jget(a, 264).get("string") == "hss2.diam.test"
              and jget(a, 268) == {"avpCode": 268, "vendorId": 0, "DataType": 3, "Flags": 64, "int32": 2001}, a)
        check("…a base AVP cdp types (User-Name) is a string, DataType 1", jget(a, 1).get("string") == "hss2"
              and jget(a, 1).get("DataType") == 1, a)
        r = sip("async")
        end = time.time() + 3
        while time.time() < end and not any(x[0] == 309 for x in hss1.log):
            time.sleep(0.05)
        seen = next((x for x in hss1.log if x[0] == 309), None)
        check("diameter_request_async: event_route[diameter:response] runs with the answer in $diameter_response",
              r.startswith("SIP/2.0 202") and seen and get(seen[2], 601, 10415) == b"async-answer-seen", (r, seen))
        a = answer_of(sip("realm", "X-Realm: nowhere.test\r\nX-Peer: \r\n"))
        check("a realm without a table and no peer: default routes, lowest metric first (hss1, 5)", jget(a, 264).get("string") == "hss1.diam.test", a)
        hss2.close()
        end = time.time() + 5
        while time.time() < end and any(x["FQDN"] == "hss2.diam.test" and x["State"] == "I_Open" for x in ctl("cdp.list_peers")):
            time.sleep(0.1)
        a = answer_of(sip("realm", "X-Realm: sh.test\r\nX-Peer: \r\n"))
        check("…hss2 down: the next route (hss1, metric 20)", jget(a, 264).get("string") == "hss1.diam.test", a)
        r = sip("realm", "X-Realm: sh.test\r\nX-Peer: hss0.diam.test\r\n")
        check("…to a named peer that is down: realm routing still finds one", jget(answer_of(r), 264).get("string") == "hss1.diam.test", r)

        fsr_part(hss1)

        # ------------------------------------------------- SCTP
        if sctp:
            c = Client(A_SCTP, "sctp.test", sctp=True)
            cea = c.cer()
            check("SCTP acceptor: CER → CEA 2001", cea and u32(get(cea["avps"], 268)) == 2001, cea)
        elif os.environ.get("REQUIRE_SCTP"):
            check("SCTP required (REQUIRE_SCTP) but this kernel has none", False, "load the sctp module")
        else:
            print("SKIP SCTP: this kernel has no SCTP (socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP) fails: Protocol not supported)")
    finally:
        err += stop(p)
        check("no panics in proxy logs", "panicked" not in err, err[-2000:])
        check("diameter_request_async returned 0: the rest of the route did not run", "not reached" not in err, err[-2000:])
        if failures:
            print("--- proxy stderr ---\n" + err[-5000:])
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
