#!/usr/bin/env python3
"""End-to-end checks for the IMS modules (Phase 7): cdp, ims_auth (SIP
Digest and Digest-AKAv1-MD5 over Cx MAR), ims_registrar_scscf (SAR, Service-
Route, P-Associated-URI, Path), ims_usrloc_scscf, ims_isc (iFC → AS and
back), ims_charging (Ro CCR-I/U/T, call ended when credit runs out),
ims_usrloc_pcscf / ims_registrar_pcscf (registration via the P-CSCF,
service routes, asserted identity) and ims_qos (Rx AAR/STR). Then the
same I-CSCF and S-CSCF written in `.fsr` (`await ims_icscf.authorize()`,
`ims_auth.www_challenge()`, `ims_registrar_scscf.save()`…) with
ferrosip.toml, against the same Diameter peer.

A scripted Diameter peer plays HSS, PCRF and OCS; a tiny stateless SIP
proxy plays the application server. Run from the repo root after
`cargo build --release`.
"""
import hashlib, json, os, re, socket, struct, subprocess, sys, threading, time, base64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_routing import Peer, make_reply, hdr, hdrs, first  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCSCF, PCSCF, AS, DIAM, ICSCF = 6760, 6860, 6799, 6868, 6960
ALICE, BOB = 6701, 6702
SOCK_S = os.path.join(ROOT, "target/e2e_ims_s.sock")
SOCK_P = os.path.join(ROOT, "target/e2e_ims_p.sock")
SOCK_I = os.path.join(ROOT, "target/e2e_ims_i.sock")
SCSCF_F, ICSCF_F = 7060, 7160  # the .fsr S-CSCF and I-CSCF
SOCK_SF = os.path.join(ROOT, "target/e2e_ims_sf.sock")
SOCK_IF = os.path.join(ROOT, "target/e2e_ims_if.sock")
DBDIR = os.path.join(ROOT, "target/e2e_ims_db")  # ims_usrloc_scscf's db_text tables
V = 10415

SCSCF_CFG = r"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "siputils"
loadmodule "rr"
loadmodule "dialog"
loadmodule "cdp"
loadmodule "cdp_avp"
loadmodule "ims_usrloc_scscf"
loadmodule "ims_registrar_scscf"
loadmodule "ims_auth"
loadmodule "ims_isc"
loadmodule "ims_charging"
modparam("tm", "fr_timer", 2000)
modparam("cdp", "identity", "scscf.ims.test")
modparam("cdp", "realm", "ims.test")
modparam("cdp", "peer", "fqdn=hss.ims.test;realm=ims.test;host=127.0.0.1;port=6868")
modparam("cdp", "tc", 1)
modparam("ims_auth", "name", "sip:scscf.ims.test:6760")
modparam("ims_auth", "registration_default_algorithm", "MD5")
modparam("ims_registrar_scscf", "scscf_name", "sip:scscf.ims.test:6760")
modparam("ims_charging", "interim_update_credits", 10)
modparam("ims_usrloc_scscf", "db_mode", 1)
modparam("ims_usrloc_scscf", "db_url", "text://@DBDIR@")

request_route {
    if (is_method("SUBSCRIBE")) {
        if (!can_subscribe_to_reg("location")) { sl_send_reply(403, "Forbidden"); exit; }
        subscribe_to_reg("location");
        exit;
    }
    if (is_method("REGISTER")) {
        if (!ims_www_authenticate("ims.test")) {
            ims_www_challenge("REG_MAR_REPLY", "ims.test");
            exit;
        }
        save("REG_SAR_REPLY", "location");
        exit;
    }
    if (has_totag()) { loose_route(); t_relay(); exit; }
    loose_route();
    if (impu_registered("location")) {
        if (isc_match_filter("orig", "location")) { t_relay(); exit; }
        if (!Ro_CCR("CCR_REPLY", "orig", "2", "", "")) { sl_send_reply(402, "Payment Required"); exit; }
        dlg_manage();
    }
    if (lookup("location")) { t_relay(); exit; }
    sl_send_reply(404, "Not Found");
}
"""

PCSCF_CFG = r"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "siputils"
loadmodule "rr"
loadmodule "path"
loadmodule "dialog"
loadmodule "cdp"
loadmodule "ims_usrloc_pcscf"
loadmodule "ims_registrar_pcscf"
loadmodule "ims_qos"
loadmodule "ims_ipsec_pcscf"
modparam("ims_ipsec_pcscf", "ipsec_kernel", 1)
modparam("tm", "fr_timer", 2000)
modparam("cdp", "identity", "pcscf.ims.test")
modparam("cdp", "realm", "ims.test")
modparam("cdp", "peer", "fqdn=pcrf.ims.test;realm=ims.test;host=127.0.0.1;port=6868")
modparam("cdp", "tc", 1)

request_route {
    if (is_method("REGISTER")) {
        pcscf_save_pending("location");
        add_path();
        t_on_reply("REG");
        t_relay("udp:127.0.0.1:6760");
        exit;
    }
    if (has_totag()) { loose_route(); t_relay(); exit; }
    if (loose_route()) {
        if (is_method("MESSAGE")) { ipsec_forward("location"); }
        t_relay();
        exit;
    }
    if (!pcscf_is_registered("location")) { sl_send_reply(403, "Not registered"); exit; }
    if (!pcscf_assert_identity("location", "$fu")) { sl_send_reply(403, "Bad identity"); exit; }
    append_hf("P-Asserted-Identity: <$fu>");
    dlg_manage();
    # Kamailio style: the AAR suspends the transaction and the AAA is
    # handled in route[RX_REPLY].
    Rx_AAR("RX_REPLY", "orig");
    exit;
}

route[RX_REPLY] {
    if ($avp(aar_return_code) != 1) { sl_send_reply(503, "QoS refused"); exit; }
    record_route();
    pcscf_force_service_routes("location");
    t_relay();
}

onreply_route[REG] {
    if ($rs == 401) { ipsec_create("location"); }
    if ($rs == 200) { save("location"); }
}
"""

ICSCF_CFG = r"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "siputils"
loadmodule "rr"
loadmodule "cdp"
loadmodule "ims_icscf"
modparam("tm", "fr_timer", 2000)
modparam("cdp", "identity", "icscf.ims.test")
modparam("cdp", "realm", "ims.test")
modparam("cdp", "peer", "fqdn=hss.ims.test;realm=ims.test;host=127.0.0.1;port=6868")
modparam("cdp", "tc", 1)
modparam("ims_icscf", "scscf_entry", "sip:127.0.0.1:6999;caps=2")
modparam("ims_icscf", "scscf_entry", "sip:127.0.0.1:6760;caps=1,2")

request_route {
    if (has_totag()) { loose_route(); t_relay(); exit; }
    if (is_method("REGISTER")) {
        I_perform_user_authorization_request("REG_UAR_REPLY", "0");
        if ($avp(uaa_return_code) == 1) { I_scscf_select("0"); t_relay(); exit; }
        sl_send_reply(403, "UAR $avp(uaa_return_code)");
        exit;
    }
    # Kamailio style: the LIA is handled in the reply route named in the
    # call (REGISTER above has no REG_UAR_REPLY route: it goes on after it).
    I_perform_location_information_request("LIR_REPLY", "0");
    exit;
}

route[LIR_REPLY] {
    if ($avp(lia_return_code) == 1) { I_scscf_select("0"); t_relay(); exit; }
    sl_send_reply(404, "LIR $avp(lia_return_code)");
}
"""

# The .fsr versions of the S-CSCF and I-CSCF (ferrosip.toml + routing). The
# HSS sends UAR/LIR from Origin-Host icscf-fsr.ims.test to the .fsr S-CSCF.
SCSCF_FSR_TOML = f"""
[[listen]]
proto = "udp"
addr = "127.0.0.1:{SCSCF_F}"

[modules.txn]
fr_timer = "2s"

[modules.diameter]
identity = "scscf-fsr.ims.test"
realm = "ims.test"
peer = ["fqdn=hss.ims.test;realm=ims.test;host=127.0.0.1;port={DIAM}"]
tc = 1

[modules.ims_auth]
name = "sip:scscf-fsr.ims.test:{SCSCF_F}"
registration_default_algorithm = "MD5"

[modules.ims_registrar_scscf]
name = "sip:scscf-fsr.ims.test:{SCSCF_F}"

[routing]
entry = "scscf.fsr"
"""

SCSCF_FSR = """import ims_auth, ims_registrar_scscf, ims_charging

route main(msg: Request) {
    if msg.method == REGISTER {
        guard ims_auth.www_authenticate("ims.test") else ims_auth.www_challenge("ims.test")
        ims_registrar_scscf.save()
    }
    if msg.method == MESSAGE && ims_registrar_scscf.orig_registered() {
        let credit = await ims_charging.reserve("orig", 2)
        guard credit.code == 1 else reply(402, "Payment Required")
    }
    guard ims_registrar_scscf.lookup() else reply(404, "Not Found")
    relay(msg)
}
"""

ICSCF_FSR_TOML = f"""
[[listen]]
proto = "udp"
addr = "127.0.0.1:{ICSCF_F}"

[modules.txn]
fr_timer = "2s"

[modules.diameter]
identity = "icscf-fsr.ims.test"
realm = "ims.test"
peer = ["fqdn=hss.ims.test;realm=ims.test;host=127.0.0.1;port={DIAM}"]
tc = 1

[modules.ims_icscf]
scscf_entry = ["sip:127.0.0.1:6999;caps=2", "sip:127.0.0.1:{SCSCF_F};caps=1,2"]

[routing]
entry = "icscf.fsr"
"""

ICSCF_FSR = """import ims_icscf

route main(msg: Request) {
    if msg.has_to_tag {
        relay(msg)
    }
    if msg.method == REGISTER {
        let uar = await ims_icscf.authorize()
        guard uar.code == 1 else reply(403, "UAR {uar.code}")
        guard ims_icscf.select_scscf() else reply(500, "No S-CSCF")
        relay(msg)
    }
    let lir = await ims_icscf.locate()
    guard lir.code == 1 else reply(404, "LIR {lir.code}")
    guard ims_icscf.select_scscf() else reply(500, "No S-CSCF")
    relay(msg)
}
"""

USER_DATA = {
    "alice": """<?xml version="1.0"?><IMSSubscription><PrivateID>alice@ims.test</PrivateID><ServiceProfile>
<PublicIdentity><Identity>sip:alice@ims.test</Identity></PublicIdentity><PublicIdentity><Identity>tel:+4930111</Identity></PublicIdentity>
<InitialFilterCriteria><Priority>0</Priority><TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF>
<SPT><ConditionNegated>0</ConditionNegated><Group>0</Group><Method>INVITE</Method></SPT>
<SPT><ConditionNegated>0</ConditionNegated><Group>1</Group><SessionCase>0</SessionCase></SPT></TriggerPoint>
<ApplicationServer><ServerName>sip:127.0.0.1:6799</ServerName><DefaultHandling>0</DefaultHandling></ApplicationServer></InitialFilterCriteria>
</ServiceProfile></IMSSubscription>""",
    "bob": """<?xml version="1.0"?><IMSSubscription><PrivateID>bob@ims.test</PrivateID><ServiceProfile>
<PublicIdentity><Identity>sip:bob@ims.test</Identity></PublicIdentity></ServiceProfile></IMSSubscription>""",
}
RAND, AUTN, XRES, CK, IK = bytes(range(16)), bytes(range(16, 32)), b"\x11\x22\x33\x44\x55\x66\x77\x88", b"\xaa" * 16, b"\xbb" * 16
md5 = lambda b: hashlib.md5(b if isinstance(b, bytes) else b.encode()).hexdigest()

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


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


def scscf_for(avps):
    """The S-CSCF the HSS names: the .fsr one for the .fsr I-CSCF."""
    return SCSCF_F if get(avps, 264) == b"icscf-fsr.ims.test" else SCSCF


class Diameter(threading.Thread):
    """HSS + PCRF + OCS."""

    def __init__(self):
        super().__init__(daemon=True)
        self.l = socket.socket()
        self.l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l.bind(("127.0.0.1", DIAM))
        self.l.listen(8)
        self.log = []
        self.start()

    def run(self):
        while True:
            c, _ = self.l.accept()
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def answer(self, c, req, avps):
        flags, cmd, app, hbh, e2e = req[0], req[1], req[2], req[3], req[4]
        body = b"".join(avps)
        hdr_ = bytes([1]) + (20 + len(body)).to_bytes(3, "big") + bytes([flags & 0x40]) + cmd.to_bytes(3, "big") + struct.pack("!III", app, hbh, e2e)
        c.sendall(hdr_ + body)

    def serve(self, c):
        f = c.makefile("rb")
        while True:
            h = f.read(20)
            if len(h) < 20:
                return
            ln = int.from_bytes(h[1:4], "big")
            body = f.read(ln - 20)
            flags, cmd = h[4], int.from_bytes(h[5:8], "big")
            app, hbh, e2e = struct.unpack("!III", h[8:20])
            avps = parse_avps(body)
            req = (flags, cmd, app, hbh, e2e)
            if not flags & 0x80:
                continue
            sid = get(avps, 263)
            base = ([avp(263, sid)] if sid else []) + [avp(264, "hss.ims.test"), avp(296, "ims.test")]
            ok = avp(268, 2001)
            if cmd == 257:  # CER
                # Cx (HSS), Rx (PCRF) and Ro credit control (OCS) in one.
                apps = [avp(260, [avp(266, V), avp(258, 16777216)]), avp(260, [avp(266, V), avp(258, 16777236)]), avp(258, 4)]
                self.answer(c, req, [ok, avp(264, "hss.ims.test"), avp(296, "ims.test"), avp(266, V), avp(269, "fake", mandatory=False)] + apps)
            elif cmd == 280:  # DWR
                self.answer(c, req, [ok, avp(264, "hss.ims.test"), avp(296, "ims.test")])
            elif cmd == 303:  # MAR
                user = get(avps, 1).decode()
                scheme = parse_avps(get(avps, 612, V))
                self.log.append(("MAR", user, get(scheme, 608, V).decode()))
                if user.startswith("bob"):
                    item = [avp(608, "Digest-AKAv1-MD5", V), avp(609, RAND + AUTN, V), avp(610, XRES, V), avp(625, CK, V), avp(626, IK, V)]
                else:
                    ha1 = md5("alice@ims.test:ims.test:alicepw")
                    item = [avp(608, "SIP Digest", V), avp(635, [avp(104, "ims.test"), avp(121, ha1)], V)]
                self.answer(c, req, base + [ok, avp(601, get(avps, 601, V), V), avp(607, 1, V), avp(612, item, V)])
            elif cmd == 301:  # SAR
                user = get(avps, 1).decode().split("@")[0]
                sat = struct.unpack("!I", get(avps, 614, V))[0]
                self.log.append(("SAR", user, sat))
                extra = [avp(606, USER_DATA.get(user, USER_DATA["bob"]), V)] if sat in (1, 2) else []
                # sar_refuse: DIAMETER_UNABLE_TO_COMPLY (5012) instead of success.
                self.answer(c, req, base + ([avp(268, 5012)] if getattr(self, "sar_refuse", False) else [ok] + extra))
            elif cmd == 300:  # UAR
                user = get(avps, 1).decode()
                uat = struct.unpack("!I", get(avps, 623, V))[0]
                self.log.append(("UAR", user.split("@")[0], uat))
                if user.startswith("carol"):
                    self.answer(c, req, base + [avp(297, [avp(266, V), avp(298, 5001)])])
                elif user.startswith("dave"):
                    self.answer(c, req, base + [ok, avp(603, [avp(604, 1, V), avp(605, 2, V)], V)])
                else:
                    self.answer(c, req, base + [ok, avp(602, f"sip:127.0.0.1:{scscf_for(avps)}", V)])
            elif cmd == 302:  # LIR
                impu = get(avps, 601, V).decode()
                self.log.append(("LIR", impu))
                if "nobody" in impu:
                    self.answer(c, req, base + [avp(297, [avp(266, V), avp(298, 5001)])])
                else:
                    self.answer(c, req, base + [ok, avp(602, f"sip:127.0.0.1:{scscf_for(avps)}", V)])
            elif cmd == 265:  # Rx AAR
                mcds = [parse_avps(d) for code, v, d in avps if code == 517 and v == V]
                flows = [get(parse_avps(get(m, 519, V)), 507, V).decode() for m in mcds]
                self.log.append(("AAR", flows))
                self.answer(c, req, base + [ok, avp(258, 16777236)])
            elif cmd == 275:  # STR
                self.log.append(("STR",))
                self.answer(c, req, base + [ok])
            elif cmd == 272:  # CCR
                kind = struct.unpack("!I", get(avps, 416))[0]
                self.log.append(("CCR", kind))
                cc = lambda t: avp(456, [avp(431, [avp(420, t)])])
                if kind == 1:
                    self.answer(c, req, base + [ok, avp(416, kind), avp(415, 0), cc(2)])
                elif kind == 2:
                    self.answer(c, req, base + [avp(268, 4012), avp(416, kind)])
                else:
                    self.answer(c, req, base + [ok, avp(416, kind)])
            else:
                self.answer(c, req, base + [avp(268, 3001)])


class AppServer(threading.Thread):
    """A stateless SIP proxy at 6799: pops its Route, forwards; replies back by Via."""

    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", AS))
        self.seen = []
        self.start()

    def run(self):
        while True:
            d, a = self.s.recvfrom(65535)
            head, _, body = d.partition(b"\r\n\r\n")
            lines = head.decode().split("\r\n")
            if lines[0].startswith("SIP/2.0"):
                vias = [i for i, l in enumerate(lines) if l.lower().startswith("via:")]
                lines.pop(vias[0])
                nxt = re.search(r"SIP/2.0/UDP ([\d.]+):(\d+)", lines[vias[0]])
                self.s.sendto(("\r\n".join(lines) + "\r\n\r\n").encode() + body, (nxt.group(1), int(nxt.group(2))))
                continue
            self.seen.append(d)
            routes = [l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("route:")]
            allr = [r.strip() for r in ",".join(routes).split(",") if r.strip()]
            lines = [l for l in lines if not l.lower().startswith("route:")]
            allr = allr[1:]  # ours
            if allr:
                lines.insert(1, "Route: " + ", ".join(allr))
                target = re.search(r"sip:(?:[^@>]*@)?([\d.]+):(\d+)", allr[0])
            else:
                target = re.search(r"sip:(?:[^@ ]*@)?([\d.]+):(\d+)", lines[0])
            lines.insert(1, f"Via: SIP/2.0/UDP 127.0.0.1:{AS};branch=z9hG4bKas{time.time_ns()}")
            self.s.sendto(("\r\n".join(lines) + "\r\n\r\n").encode() + body, (target.group(1), int(target.group(2))))


def msg(method, ruri, port, extra="", user="alice", callid=None, cseq=1, to=None, body="", ctype=None):
    seq[0] += 1
    ex = "".join(l + "\r\n" for l in extra.split("\n") if l) if extra else ""
    ct = f"Content-Type: {ctype}\r\n" if body else ""
    return (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKi{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: <sip:{user}@ims.test>;tag=t{port}\r\nTo: {to or f'<sip:{user}@ims.test>'}\r\nCall-ID: {callid or f'ims-{seq[0]}-{time.time_ns()}'}\r\n"
            f"CSeq: {cseq} {method}\r\nContact: <sip:{user}@127.0.0.1:{port}>\r\n{ex}{ct}Content-Length: {len(body)}\r\n\r\n{body}").encode()


def ctl(sock, *args):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", sock, *args], capture_output=True, text=True, timeout=5)
    try:
        return json.loads(out.stdout) if out.stdout.strip() else out.stderr.strip()
    except json.JSONDecodeError:
        return out.stdout


def start(cfg_text, name, port, sock):
    cfg = os.path.join(ROOT, f"target/e2e_ims_{name}.cfg")
    open(cfg, "w").write(cfg_text)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{port}", "-n", "2", "--rpc-socket", sock], stderr=subprocess.PIPE, text=True)
    return p


def start_fsr(toml, entry, routing, name, sock):
    d = os.path.join(ROOT, f"target/e2e_ims_fsr_{name}")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "ferrosip.toml"), "w").write(toml)
    open(os.path.join(d, entry), "w").write(routing)
    return subprocess.Popen([f"{ROOT}/target/release/ferrosip", "--config", os.path.join(d, "ferrosip.toml"), "--rpc-socket", sock],
                            stderr=subprocess.PIPE, text=True, cwd=d)


def stop(p):
    p.terminate()
    try:
        return p.communicate(timeout=3)[1]
    except subprocess.TimeoutExpired:
        p.kill()
        return p.communicate()[1]


def register(ue, port, proxy, user, secret, cseq0=1, expires=600, extra=""):
    """REGISTER → 401 → REGISTER with credentials. Returns (401, final)."""
    cid = f"reg-{user}-{time.time_ns()}"
    ex = f"\n{extra}" if extra else ""
    ue.s.sendto(msg("REGISTER", "sip:ims.test", port, f"Expires: {expires}{ex}", user=user, callid=cid, cseq=cseq0), ("127.0.0.1", proxy))
    ch = ue.final()
    wa = hdr(ch or b"", "WWW-Authenticate")
    nonce = re.search(r'nonce="([^"]+)"', wa)
    if not nonce:
        return ch, None
    impi = f"{user}@ims.test"
    ha1 = md5(f"{impi}:ims.test:".encode() + secret) if isinstance(secret, bytes) else md5(f"{impi}:ims.test:{secret}")
    resp = md5(f"{ha1}:{nonce.group(1)}:{md5('REGISTER:sip:ims.test')}")
    auth = f'Authorization: Digest username="{impi}", realm="ims.test", nonce="{nonce.group(1)}", uri="sip:ims.test", response="{resp}"'
    ue.s.sendto(msg("REGISTER", "sip:ims.test", port, f"Expires: {expires}\n{auth}{ex}", user=user, callid=cid, cseq=cseq0 + 1), ("127.0.0.1", proxy))
    return ch, ue.final()


def fsr_cscfs(diam, alice, bob, carol, dave):
    """The same I-CSCF / S-CSCF checks against the .fsr routings."""
    end = time.time() + 5
    while time.time() < end:
        a, b = ctl(SOCK_SF, "cdp.list_peers"), ctl(SOCK_IF, "cdp.list_peers")
        if isinstance(a, list) and isinstance(b, list) and a and b and a[0]["State"] == "I_Open" and b[0]["State"] == "I_Open":
            break
        time.sleep(0.1)
    check(".fsr: both CSCFs (ferrosip.toml) have an open Diameter connection", isinstance(a, list) and a and a[0]["State"] == "I_Open"
          and isinstance(b, list) and b and b[0]["State"] == "I_Open", (a, b))
    for ue in (alice, bob, carol, dave):
        ue.drain()

    # I-CSCF: `await ims_icscf.authorize()` → select_scscf → relay; S-CSCF:
    # www_authenticate / www_challenge, then save().
    n = len(diam.log)
    ch, r = register(alice, ALICE, ICSCF_F, "alice", "alicepw", cseq0=51)
    check(".fsr I-CSCF → .fsr S-CSCF: await ims_icscf.authorize() (UAR), then ims_auth.www_challenge → 401 (SIP Digest)",
          first(ch) == "SIP/2.0 401 Unauthorized - Challenging the UE" and "algorithm=MD5" in hdr(ch or b"", "WWW-Authenticate")
          and ("UAR", "alice", 0) in diam.log[n:] and ("MAR", "alice@ims.test", "SIP Digest") in diam.log[n:], (ch, diam.log[n:]))
    check("…authenticated → ims_registrar_scscf.save() → SAR and 200 with Service-Route and P-Associated-URI", first(r) == "SIP/2.0 200 OK"
          and hdr(r, "Service-Route") == f"<sip:orig@127.0.0.1:{SCSCF_F};lr>" and hdr(r, "P-Associated-URI") == "<sip:alice@ims.test>, <tel:+4930111>"
          and ("SAR", "alice", 1) in diam.log[n:], (r, diam.log[n:]))
    imp = ctl(SOCK_SF, "ulscscf.showimpu", "tel:+4930111")
    check("…the .fsr S-CSCF holds alice's registration", isinstance(imp, dict) and imp.get("impu") == "sip:alice@ims.test", imp)
    _, r = register(alice, ALICE, ICSCF_F, "alice", "wrongpw", cseq0=53)
    check("…a wrong password gets a new challenge", first(r) == "SIP/2.0 401 Unauthorized - Challenging the UE", r)
    _, r = register(alice, ALICE, ICSCF_F, "alice", "alicepw", cseq0=55)
    check("…re-registration → SAR RE_REGISTRATION", first(r) == "SIP/2.0 200 OK" and ("SAR", "alice", 2) in diam.log[n:], (r, diam.log[n:]))

    carol.s.sendto(msg("REGISTER", "sip:ims.test", 6704, "Expires: 600", user="carol"), ("127.0.0.1", ICSCF_F))
    check(".fsr: UAR user unknown → uar.code -2 → 403", first(carol.final()) == "SIP/2.0 403 UAR -2")
    dave.s.sendto(msg("REGISTER", "sip:ims.test", 6706, "Expires: 600", user="dave"), ("127.0.0.1", ICSCF_F))
    r = dave.final()
    check(".fsr: UAR with capabilities only → the scscf_entry with the mandatory capability (the .fsr S-CSCF) → 401", first(r) == "SIP/2.0 401 Unauthorized - Challenging the UE"
          and hdr(r or b"", "WWW-Authenticate") != "", r)

    # AKA straight at the .fsr S-CSCF, then LIR through the .fsr I-CSCF.
    ch, r = register(bob, BOB, SCSCF_F, "bob", XRES, cseq0=71)
    check(".fsr S-CSCF: AKA challenge and registration", "algorithm=AKAv1-MD5" in hdr(ch or b"", "WWW-Authenticate") and first(r) == "SIP/2.0 200 OK", (ch, r))
    n = len(diam.log)
    carol.s.sendto(msg("MESSAGE", "sip:bob@ims.test", 6704, user="carol", to="<sip:bob@ims.test>"), ("127.0.0.1", ICSCF_F))
    m = bob.answer("MESSAGE")
    check(".fsr I-CSCF: await ims_icscf.locate() (LIR) → .fsr S-CSCF → bob", m is not None and ("LIR", "sip:bob@ims.test") in diam.log[n:], (m, diam.log[n:]))
    check("…the 200 back to the sender", first(carol.final()) == "SIP/2.0 200 OK")
    carol.s.sendto(msg("MESSAGE", "sip:nobody@ims.test", 6704, user="carol", to="<sip:nobody@ims.test>"), ("127.0.0.1", ICSCF_F))
    check(".fsr: LIR user unknown → lir.code -2 → 404", first(carol.final()) == "SIP/2.0 404 LIR -2")

    # ims_charging.reserve: Ro CCR-Initial for a registered sender.
    n = len(diam.log)
    alice.s.sendto(msg("MESSAGE", "sip:bob@ims.test", ALICE, user="alice", to="<sip:bob@ims.test>"), ("127.0.0.1", SCSCF_F))
    m = bob.answer("MESSAGE")
    check(".fsr S-CSCF: ims_charging.reserve(\"orig\", 2) → CCR-Initial granted → relayed", m is not None and ("CCR", 1) in diam.log[n:], (m, diam.log[n:]))
    check("…the 200 back to alice", first(alice.final()) == "SIP/2.0 200 OK")


def make_db():
    os.makedirs(DBDIR, exist_ok=True)
    open(os.path.join(DBDIR, "impu"), "w").write("impu(string) impi(string) reg_state(int) ims_subscription_data(string,null)\n")
    open(os.path.join(DBDIR, "contact"), "w").write("impu(string) contact(string) received(string) path(string,null) expires(int) callid(string) cseq(int)\n")
    open(os.path.join(DBDIR, "subscriber_scscf"), "w").write(
        "watcher_uri(string) watcher_contact(string) presentity_uri(string) event(int) expires(int) version(int) local_cseq(int) "
        "call_id(string) from_tag(string) to_tag(string) record_route(string,null) sockinfo_str(string,null)\n")


def main():
    diam, appsrv = Diameter(), AppServer()
    make_db()
    SCSCF_CFG_DB = SCSCF_CFG.replace("@DBDIR@", DBDIR)
    s = start(SCSCF_CFG_DB, "s", SCSCF, SOCK_S)
    p = start(PCSCF_CFG, "p", PCSCF, SOCK_P)
    ic = start(ICSCF_CFG, "i", ICSCF, SOCK_I)
    sf = start_fsr(SCSCF_FSR_TOML, "scscf.fsr", SCSCF_FSR, "s", SOCK_SF)
    icf = start_fsr(ICSCF_FSR_TOML, "icscf.fsr", ICSCF_FSR, "i", SOCK_IF)
    alice, bob = Peer(ALICE), Peer(BOB)
    err = ""
    try:
        end = time.time() + 5
        while time.time() < end:
            ps, pp = ctl(SOCK_S, "cdp.list_peers"), ctl(SOCK_P, "cdp.list_peers")
            if isinstance(ps, list) and isinstance(pp, list) and ps and pp and ps[0]["State"] == "I_Open" and pp[0]["State"] == "I_Open":
                break
            time.sleep(0.1)
        check("cdp: both CSCFs have an open Diameter connection (CER/CEA)", ps[0]["State"] == "I_Open" and ps[0]["Origin-Host"] == "hss.ims.test"
              and pp[0]["State"] == "I_Open", (ps, pp))

        # ------------------------------------------------- alice via the P-CSCF, SIP Digest
        ch, r = register(alice, ALICE, PCSCF, "alice", "alicepw")
        check("REGISTER via P-CSCF → 401 from the S-CSCF (SIP Digest from MAR)", first(ch) == "SIP/2.0 401 Unauthorized - Challenging the UE"
              and "algorithm=MD5" in hdr(ch, "WWW-Authenticate"), ch)
        check("…authenticated → 200 with Service-Route and P-Associated-URI", first(r) == "SIP/2.0 200 OK"
              and hdr(r, "Service-Route") == f"<sip:orig@127.0.0.1:{SCSCF};lr>" and hdr(r, "P-Associated-URI") == "<sip:alice@ims.test>, <tel:+4930111>", r)
        check("…Path of the P-CSCF echoed", hdr(r or b"", "Path") == f"<sip:127.0.0.1:{PCSCF};lr>", hdr(r or b"", "Path"))
        check("HSS saw MAR (SIP Digest) and SAR REGISTRATION", ("MAR", "alice@ims.test", "SIP Digest") in diam.log and ("SAR", "alice", 1) in diam.log, diam.log)
        imp = ctl(SOCK_S, "ulscscf.showimpu", "tel:+4930111")
        check("ims_usrloc_scscf: implicit set resolves to alice, contact with Path", isinstance(imp, dict) and imp["impu"] == "sip:alice@ims.test"
              and imp["contacts"][0]["path"] == f"<sip:127.0.0.1:{PCSCF};lr>", imp)
        ue = ctl(SOCK_P, "ulpcscf.showcontacts")
        check("ims_registrar_pcscf: UE registered with service route and associated URIs", isinstance(ue, list) and ue[0]["state"] == "registered"
              and ue[0]["service_routes"] == [f"<sip:orig@127.0.0.1:{SCSCF};lr>"] and "tel:+4930111" in ue[0]["associated_uris"], ue)
        _, r = register(alice, ALICE, PCSCF, "alice", "alicepw", cseq0=3)
        check("re-registration → SAR RE_REGISTRATION", first(r) == "SIP/2.0 200 OK" and ("SAR", "alice", 2) in diam.log, diam.log)

        # ------------------------------------------------- bob directly, AKA
        ch, r = register(bob, BOB, SCSCF, "bob", XRES)
        wa = hdr(ch or b"", "WWW-Authenticate")
        check("AKA challenge: nonce = base64(RAND||AUTN), ck/ik", "algorithm=AKAv1-MD5" in wa and base64.b64encode(RAND + AUTN).decode() in wa
              and f'ck="{CK.hex()}"' in wa and f'ik="{IK.hex()}"' in wa, wa)
        check("AKAv1-MD5 response (password = XRES) accepted", first(r) == "SIP/2.0 200 OK", r)
        _, bad = register(bob, BOB, SCSCF, "bob", b"wrongres", cseq0=5)
        check("wrong AKA response rejected (new challenge)", first(bad) == "SIP/2.0 401 Unauthorized - Challenging the UE", first(bad))

        # ------------------------------------------------- call alice → bob: P-CSCF (Rx) → S-CSCF (iFC → AS, Ro) → bob
        sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n"
        cid = f"call-{time.time_ns()}"
        alice.s.sendto(msg("INVITE", "sip:bob@ims.test", ALICE, callid=cid, to="<sip:bob@ims.test>", body=sdp, ctype="application/sdp"), ("127.0.0.1", PCSCF))
        inv = bob.expect("INVITE", 4)
        aar = [x for x in diam.log if x[0] == "AAR"]
        check("P-CSCF: Rx AAR with the media flows", aar and "permit out 17 from any to 127.0.0.1 40000" in aar[0][1], aar)
        as_inv = appsrv.seen[-1] if appsrv.seen else b""
        check("S-CSCF: iFC (INVITE, originating) routed the call through the AS", as_inv.startswith(b"INVITE sip:bob@ims.test")
              and re.search(rf"<sip:127\.0\.0\.1:{SCSCF};lr;s=1;d=orig>", hdr(as_inv, "Route")) is not None, as_inv[:400])
        check("…and back from the AS to bob (Ro CCR-I granted)", inv is not None and first(inv).startswith(f"INVITE sip:bob@127.0.0.1:{BOB}")
              and hdr(inv, "P-Asserted-Identity") == "<sip:alice@ims.test>" and ("CCR", 1) in diam.log, (inv, diam.log))
        if inv:
            bob.s.sendto(make_reply(inv, 200, "OK", f"Contact: <sip:bob@127.0.0.1:{BOB}>\r\n"), bob.addr)
        r = alice.final()
        check("200 OK back to alice", first(r) == "SIP/2.0 200 OK", r)
        rr = hdrs(r or b"", "Record-Route")
        ack_route = f"Route: {rr[0]}\n" if rr else ""
        alice.s.sendto(msg("ACK", f"sip:bob@127.0.0.1:{BOB}", ALICE, ack_route.strip(), callid=cid, to="<sip:bob@ims.test>;tag=uas"), ("127.0.0.1", PCSCF))
        bye_b = bob.expect("BYE", 6)
        bye_a = alice.expect("BYE", 3)
        check("Ro: CCR-U refused (credit limit) → BYE to both parties", bye_b is not None and bye_a is not None and ("CCR", 2) in diam.log, (bye_a, bye_b, diam.log))
        for ue_, m in ((bob, bye_b), (alice, bye_a)):
            if m:
                ue_.s.sendto(make_reply(m, 200, "OK"), ue_.addr)
        time.sleep(0.5)
        check("Ro: CCR-T sent when the call ended", ("CCR", 3) in diam.log, diam.log)
        check("Rx: STR when the call ended at the P-CSCF", ("STR",) in diam.log, diam.log)

        # ------------------------------------------------- I-CSCF: UAR / LIR
        end = time.time() + 5
        while time.time() < end and not (isinstance(ctl(SOCK_I, "cdp.list_peers"), list) and ctl(SOCK_I, "cdp.list_peers")[0]["State"] == "I_Open"):
            time.sleep(0.1)
        _, r = register(alice, ALICE, ICSCF, "alice", "alicepw", cseq0=21)
        check("I-CSCF: UAR → Server-Name → REGISTER reaches the S-CSCF and succeeds", first(r) == "SIP/2.0 200 OK" and ("UAR", "alice", 0) in diam.log, (r, diam.log[-6:]))
        carol = Peer(6704)
        carol.s.sendto(msg("REGISTER", "sip:ims.test", 6704, "Expires: 600", user="carol"), ("127.0.0.1", ICSCF))
        check("…user unknown (Experimental-Result 5001) → $avp(uaa_return_code) -2", first(carol.final()) == "SIP/2.0 403 UAR -2")
        dave = Peer(6706)
        dave.s.sendto(msg("REGISTER", "sip:ims.test", 6706, "Expires: 600", user="dave"), ("127.0.0.1", ICSCF))
        r = dave.final()
        check("…capabilities only: the scscf_entry with the mandatory capability is chosen", first(r) == "SIP/2.0 401 Unauthorized - Challenging the UE", r)
        carol.s.sendto(msg("MESSAGE", "sip:bob@ims.test", 6704, user="carol", to="<sip:bob@ims.test>"), ("127.0.0.1", ICSCF))
        m = bob.answer("MESSAGE") if hasattr(bob, "answer") else bob.expect("MESSAGE")
        check("I-CSCF: LIR (async, continued in route[LIR_REPLY]) → S-CSCF → bob", m is not None and ("LIR", "sip:bob@ims.test") in diam.log, (m, diam.log[-4:]))
        if m and not hasattr(bob, "answer"):
            bob.s.sendto(make_reply(m, 200, "OK"), bob.addr)
        carol.final()
        carol.s.sendto(msg("MESSAGE", "sip:nobody@ims.test", 6704, user="carol", to="<sip:nobody@ims.test>"), ("127.0.0.1", ICSCF))
        check("…LIR user unknown → $avp(lia_return_code) -2, read in route[LIR_REPLY]", first(carol.final()) == "SIP/2.0 404 LIR -2")

        # ------------------------------------------------- reg event (RFC 3680)
        watcher = Peer(6705)
        watcher.s.sendto(msg("SUBSCRIBE", "sip:alice@ims.test", 6705, "Event: reg\nExpires: 600", user="alice"), ("127.0.0.1", SCSCF))
        r = watcher.final()
        n1 = watcher.expect("NOTIFY", 3)
        body = n1.split(b"\r\n\r\n", 1)[1].decode() if n1 else ""
        check("subscribe_to_reg: 200, then a full reginfo NOTIFY", first(r) == "SIP/2.0 200 OK" and hdr(n1 or b"", "Event") == "reg"
              and hdr(n1 or b"", "Content-Type") == "application/reginfo+xml" and 'aor="sip:alice@ims.test"' in body and 'aor="tel:+4930111"' in body
              and f"<uri>sip:alice@127.0.0.1:{ALICE}</uri>" in body and 'state="active"' in body, (r, n1))
        if n1:
            watcher.s.sendto(make_reply(n1, 200, "OK"), watcher.addr)
        register(alice, ALICE, PCSCF, "alice", "alicepw", cseq0=31)
        n2 = watcher.expect("NOTIFY", 3)
        b2 = n2.split(b"\r\n\r\n", 1)[1].decode() if n2 else ""
        check("…re-registration → a partial reginfo NOTIFY, version incremented, same dialog", n2 is not None and 'version="1"' in b2
              and 'state="partial"' in b2 and hdr(n2, "Call-ID") == hdr(n1 or b"", "Call-ID"), n2)
        cid_full = re.findall(r'<contact id="(c[0-9a-f]+)"', body)
        check("…with the refreshed contact, under the same contact id as in the full document",
              re.search(rf'<contact id="(c[0-9a-f]+)" state="active" event="refreshed" expires="\d+"><uri>sip:alice@127\.0\.0\.1:{ALICE}</uri>', b2) is not None
              and re.findall(r'<contact id="(c[0-9a-f]+)"', b2)[:1] == cid_full[:1], (body, b2))
        if n2:
            watcher.s.sendto(make_reply(n2, 200, "OK"), watcher.addr)
        watcher.s.sendto(msg("SUBSCRIBE", "sip:alice@ims.test", 6705, "Event: reg\nExpires: 600", user="alice", callid=hdr(n1 or b"", "Call-ID"), cseq=2,
                             to=f"<sip:alice@ims.test>;tag={re.search(r'tag=([^;>]+)', hdr(n1 or b'', 'From')).group(1) if n1 else ''}"), ("127.0.0.1", SCSCF))
        watcher.final()
        n3 = watcher.expect("NOTIFY", 3)
        b3 = n3.split(b"\r\n\r\n", 1)[1].decode() if n3 else ""
        check("…a refresh SUBSCRIBE → a full document, the version still counting up", 'version="2"' in b3 and 'state="full"' in b3
              and int(hdr(n3 or b"", "CSeq").split()[0] or 0) > int(hdr(n2 or b"", "CSeq").split()[0] or 0), (n3, n2))
        if n3:
            watcher.s.sendto(make_reply(n3, 200, "OK"), watcher.addr)
        mallory = Peer(6707)
        mallory.s.sendto(msg("SUBSCRIBE", "sip:alice@ims.test", 6707, "Event: reg", user="mallory"), ("127.0.0.1", SCSCF))
        check("can_subscribe_to_reg: outsiders get 403", first(mallory.final()) == "SIP/2.0 403 Forbidden")

        # ------------------------------------------------- unregistered UE at the P-CSCF; deregistration
        stranger = Peer(6703)
        stranger.s.sendto(msg("INVITE", "sip:bob@ims.test", 6703, user="mallory"), ("127.0.0.1", PCSCF))
        check("P-CSCF rejects requests from unregistered UEs", first(stranger.final()) == "SIP/2.0 403 Not registered")
        diam.sar_refuse = True
        _, r = register(bob, BOB, SCSCF, "bob", XRES, cseq0=61)
        diam.sar_refuse = False
        check("an SAA that isn't a success (UNABLE_TO_COMPLY) → 500 SAR failed, as Kamailio", first(r) == "SIP/2.0 500 SAR failed", r)
        _, r = register(bob, BOB, SCSCF, "bob", XRES, cseq0=7, expires=0)
        check("deregistration → SAR USER_DEREGISTRATION", first(r) == "SIP/2.0 200 OK" and ("SAR", "bob", 5) in diam.log
              and ctl(SOCK_S, "ulscscf.showimpu", "sip:bob@ims.test") != {} and "not found" in str(ctl(SOCK_S, "ulscscf.showimpu", "sip:bob@ims.test")), diam.log)
        # ------------------------------------------------- IPsec agreement at the P-CSCF (AKA keys)
        sc = "Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=1111;spi-s=2222;port-c=6711;port-s=6712"
        ch, r = register(bob, BOB, PCSCF, "bob", XRES, cseq0=41, extra=sc)
        ss = hdr(ch or b"", "Security-Server")
        wa = hdr(ch or b"", "WWW-Authenticate")
        check("ipsec_create: Security-Server in the 401 (our SPIs and ports)", ss.startswith("ipsec-3gpp;") and "port-c=5062" in ss and "port-s=5063" in ss
              and re.search(r"spi-c=\d+;spi-s=\d+", ss) is not None, ss)
        check("…ck/ik stripped from the challenge the UE sees", "nonce=" in wa and "ck=" not in wa and "ik=" not in wa, wa)
        check("…and the registration completes", first(r) == "SIP/2.0 200 OK", r)
        sas = ctl(SOCK_P, "ipsec.list")
        check("RPC ipsec.list: the UE's ports/SPIs, keys taken", isinstance(sas, list) and any(x["port_us"] == 6712 and x["spi_us"] == 2222 and x["keys"] for x in sas), sas)
        # Kernel SAs: only where `ip xfrm` works (CAP_NET_ADMIN + XFRM).
        probe = subprocess.run(["ip", "xfrm", "state", "add", "src", "127.0.0.1", "dst", "127.0.0.1", "proto", "esp", "spi", "0xfffffff1",
                                "mode", "transport", "auth", "hmac(sha1)", "0x" + "00" * 20, "enc", "ecb(cipher_null)", ""], capture_output=True)
        bob_sa = next((x for x in sas if x["port_us"] == 6712), {}) if isinstance(sas, list) else {}
        if probe.returncode == 0:
            subprocess.run(["ip", "xfrm", "state", "delete", "src", "127.0.0.1", "dst", "127.0.0.1", "proto", "esp", "spi", "0xfffffff1"])
            states = subprocess.run(["ip", "xfrm", "state"], capture_output=True, text=True).stdout
            check("ipsec_kernel: the four ESP SAs are installed", bob_sa.get("kernel") == "installed" and f"spi 0x{2222:08x}" in states, (bob_sa, states[:300]))
        else:
            print("SKIP kernel IPsec: `ip xfrm` not usable here (" + probe.stderr.decode().strip() + ")")
            check("ipsec_kernel without XFRM support: detected, negotiation only", bob_sa.get("kernel") == "unavailable", bob_sa)
        protected = Peer(6712)
        carol.s.sendto(msg("MESSAGE", "sip:bob@ims.test", 6704, user="carol", to="<sip:bob@ims.test>"), ("127.0.0.1", SCSCF))
        m = protected.expect("MESSAGE", 3)
        check("ipsec_forward: requests to the UE go to its protected server port", m is not None and first(m).startswith("MESSAGE sip:bob@127.0.0.1:6702"), m)
        if m:
            protected.s.sendto(make_reply(m, 200, "OK"), protected.addr)

        # ------------------------------------------------- a request to alice: S-CSCF → her P-CSCF (Path) → alice
        carol.s.sendto(msg("MESSAGE", "sip:alice@ims.test", 6704, user="carol", to="<sip:alice@ims.test>"), ("127.0.0.1", SCSCF))
        m = alice.expect("MESSAGE", 3)
        check("a MESSAGE to alice reaches her through the S-CSCF and her P-CSCF (Path)", m is not None and first(m).startswith(f"MESSAGE sip:alice@127.0.0.1:{ALICE}"), m)
        if m:
            alice.s.sendto(make_reply(m, 200, "OK"), alice.addr)
            r = carol.expect("SIP/2.0", 3)
            check("…and her 200 comes back to the sender", first(r or b"") == "SIP/2.0 200 OK", r)

        # ------------------------------------------------- ims_usrloc_scscf db_mode: registrations survive a restart
        rows = open(os.path.join(DBDIR, "impu")).read()
        check("ims_usrloc_scscf db_mode=1: IMPU rows written through (with the User-Data XML)",
              "sip\\:alice@ims.test:alice@ims.test:1:" in rows and "InitialFilterCriteria" in rows and "sip\\:bob@ims.test" in rows, rows[:600])
        subs = open(os.path.join(DBDIR, "subscriber_scscf")).read().splitlines()
        cid_w = hdr(n1 or b"", "Call-ID")
        check("…the reg-event subscription is in subscriber_scscf (event 1, version 2, its CSeq)", len(subs) == 2
              and ":sip\\:alice@ims.test:1:" in subs[1] and f":2:{hdr(n3 or b'', 'CSeq').split()[0]}:{cid_w.replace(':', chr(92) + ':')}:" in subs[1], subs)
        err += stop(s)
        s = start(SCSCF_CFG_DB, "s", SCSCF, SOCK_S)
        end = time.time() + 5
        while time.time() < end and not (isinstance(ctl(SOCK_S, "cdp.list_peers"), list) and ctl(SOCK_S, "cdp.list_peers")[0]["State"] == "I_Open"):
            time.sleep(0.1)
        imp = ctl(SOCK_S, "ulscscf.showimpu", "tel:+4930111")
        check("…after a restart: alice loaded (implicit set, iFCs, contact with Path)", isinstance(imp, dict) and imp["impu"] == "sip:alice@ims.test"
              and imp["state"] == "registered" and imp["ifcs"] == 1 and "tel:+4930111" in imp["public_identities"]
              and imp["contacts"] and imp["contacts"][0]["path"] == f"<sip:127.0.0.1:{PCSCF};lr>" and imp["contacts"][0]["expires"] > 0, imp)
        n_re = diam.log.count(("SAR", "alice", 2))
        _, r = register(alice, ALICE, PCSCF, "alice", "alicepw", cseq0=51)
        check("…a REGISTER after the restart is a re-registration (SAR RE_REGISTRATION)", first(r) == "SIP/2.0 200 OK"
              and diam.log.count(("SAR", "alice", 2)) == n_re + 1, (r, diam.log[-4:]))
        n4 = watcher.expect("NOTIFY", 3)
        b4 = n4.split(b"\r\n\r\n", 1)[1].decode() if n4 else ""
        check("…the reg-event subscription survived: a partial NOTIFY in the same dialog, version and CSeq continuing", n4 is not None
              and 'version="3"' in b4 and 'state="partial"' in b4 and hdr(n4, "Call-ID") == hdr(n3 or b"", "Call-ID") and hdr(n4, "From") == hdr(n3 or b"", "From")
              and hdr(n4, "To") == hdr(n3 or b"", "To") and int(hdr(n4, "CSeq").split()[0]) == int(hdr(n3 or b"", "CSeq").split()[0] or 0) + 1, (n3, n4))
        if n4:
            watcher.s.sendto(make_reply(n4, 200, "OK"), watcher.addr)
        carol.s.sendto(msg("MESSAGE", "sip:alice@ims.test", 6704, user="carol", to="<sip:alice@ims.test>"), ("127.0.0.1", SCSCF))
        m = alice.expect("MESSAGE", 3)
        check("…and requests to alice are delivered again (contact and Path loaded)", m is not None and first(m).startswith(f"MESSAGE sip:alice@127.0.0.1:{ALICE}"), m)
        if m:
            alice.s.sendto(make_reply(m, 200, "OK"), alice.addr)
            carol.expect("SIP/2.0", 3)

        fsr_cscfs(diam, alice, bob, carol, dave)
    finally:
        err += stop(s) + stop(p) + stop(ic) + stop(sf) + stop(icf)
        check("no panics in proxy logs", "panicked" not in err, err[-2000:])
        if failures:
            print("--- proxy stderr ---\n" + err[-5000:])
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
