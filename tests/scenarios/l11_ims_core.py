"""l11-ims-core: UEs → P-CSCF → I-CSCF (Cx UAR/LIR) → S-CSCF (Cx MAR/SAR),
three ferrosip processes and a fake HSS speaking Diameter over TLS. The
S-CSCF keeps its registrations and reg-event subscriptions in SQLite and
is restarted.

The fake HSS is a copy of the one in tests/e2e_ims.py (Cx only), with
scripted users:
- alice: SIP Digest (HA1 from the MAR), implicit set sip:alice + tel:+4930111;
- bob: Digest-AKAv1-MD5 (RAND/AUTN/XRES/CK/IK);
- carol: known (LIR names the S-CSCF) but never registers;
- unknown*/nobody*: DIAMETER_ERROR_USER_UNKNOWN (5001) to UAR, LIR and MAR;
- mute*: the UAR is never answered; mutemar*: UAR fine, the MAR never answered;
- probe: the UAR names a fake S-CSCF (a UA of the test) that shows the Vias.

The HSS answers over TLS with a certificate for hss.ims.test
(etc/tls/gen-certs.sh) and requires the CSCFs' client certificate.

Local helpers (not in sipkit): `Hss`, `ims_register` (a REGISTER answered with
username = the IMPI, which UA.register can't do: it uses the user part) and
`digest` (AKA needs a binary password).
"""
import base64, hashlib, os, re, socket, sqlite3, ssl, struct, subprocess, threading, time

import sipkit
from sipkit import challenges, rnd

V = 10415  # 3GPP vendor id
REALM = "ims.test"
RAND, AUTN = bytes(range(16)), bytes(range(16, 32))
XRES, CK, IK = b"\x11\x22\x33\x44\x55\x66\x77\x88", b"\xaa" * 16, b"\xbb" * 16
PASSWORDS = {"alice": "alice-pw", "carol": "carol-pw", "mutemar": "x"}
USER_DATA = """<?xml version="1.0"?><IMSSubscription><PrivateID>{user}@ims.test</PrivateID><ServiceProfile>
<PublicIdentity><Identity>sip:{user}@ims.test</Identity></PublicIdentity>{extra}</ServiceProfile></IMSSubscription>"""
ALICE_TEL = "<PublicIdentity><Identity>tel:+4930111</Identity></PublicIdentity>"
SAR_TYPES = {1: "REGISTRATION", 2: "RE_REGISTRATION", 5: "USER_DEREGISTRATION", 3: "TIMEOUT_DEREGISTRATION"}


def md5(b):
    return hashlib.md5(b if isinstance(b, bytes) else b.encode()).hexdigest()


# ------------------------------------------------------------ Diameter --
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


class Hss(threading.Thread):
    """A Cx HSS on 127.0.0.1:`port`. `log` holds (command, user, detail)
    with the time it arrived; `scscf` is the Server-Name it hands out."""

    def __init__(self, port, scscf, tls=None):
        super().__init__(daemon=True)
        self.scscf, self.log, self.conns, self.lock = scscf, [], [], threading.Lock()
        self.tls, self.peer_certs = tls, []  # an ssl.SSLContext; the CN of each client certificate
        self.probe = None  # Server-Name handed out for user "probe"
        self.l = socket.socket()
        self.l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l.bind(("127.0.0.1", port))
        self.l.listen(8)
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
        for s in [self.l] + self.conns:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()

    def seen(self, cmd, user=None, since=0):
        with self.lock:
            return [x for x in self.log[since:] if x[0] == cmd and (user is None or x[1] == user)]

    def mark(self):
        with self.lock:
            return len(self.log)

    def note(self, *x):
        with self.lock:
            self.log.append(x + (time.time(),))

    def answer(self, c, req, avps):
        flags, cmd, app, hbh, e2e = req
        body = b"".join(avps)
        h = bytes([1]) + (20 + len(body)).to_bytes(3, "big") + bytes([flags & 0x40]) + cmd.to_bytes(3, "big") + struct.pack("!III", app, hbh, e2e)
        try:
            c.sendall(h + body)
        except OSError:
            pass

    def serve(self, c):
        if self.tls:
            try:
                c = self.tls.wrap_socket(c, server_side=True)
            except (ssl.SSLError, OSError) as e:
                self.note("TLS-ERROR", None, str(e))
                return
            self.conns.append(c)
            cert = c.getpeercert()
            with self.lock:
                self.peer_certs.append(dict(x[0] for x in cert["subject"]).get("commonName") if cert else None)
        f = c.makefile("rb")
        while True:
            try:
                h = f.read(20)
            except OSError:
                return
            if not h or len(h) < 20:
                return
            ln = int.from_bytes(h[1:4], "big")
            body = f.read(ln - 20)
            flags, cmd = h[4], int.from_bytes(h[5:8], "big")
            app, hbh, e2e = struct.unpack("!III", h[8:20])
            if not flags & 0x80:
                continue
            avps = parse_avps(body)
            req = (flags, cmd, app, hbh, e2e)
            sid = get(avps, 263)
            base = ([avp(263, sid)] if sid else []) + [avp(264, "hss.ims.test"), avp(296, REALM)]
            ok = avp(268, 2001)
            unknown = avp(297, [avp(266, V), avp(298, 5001)])  # DIAMETER_ERROR_USER_UNKNOWN
            if cmd == 257:  # CER
                self.note("CER", (get(avps, 264) or b"").decode(), type(c).__name__)
                cx = avp(260, [avp(266, V), avp(258, 16777216)])  # Cx: a CEA without it is refused (5010)
                self.answer(c, req, [ok, avp(264, "hss.ims.test"), avp(296, REALM), avp(266, V), avp(269, "fake-hss", mandatory=False), cx])
            elif cmd == 280:  # DWR
                self.answer(c, req, [ok, avp(264, "hss.ims.test"), avp(296, REALM)])
            elif cmd == 300:  # UAR
                user = get(avps, 1).decode().split("@")[0]
                uat = struct.unpack("!I", get(avps, 623, V) or b"\0\0\0\0")[0]
                self.note("UAR", user, uat)
                if user.startswith("mute") and not user.startswith("mutemar"):
                    continue  # never answered
                if user.startswith(("unknown", "nobody")):
                    self.answer(c, req, base + [unknown])
                else:
                    name = self.probe if user == "probe" and self.probe else self.scscf
                    self.answer(c, req, base + [ok, avp(602, name, V)])
            elif cmd == 302:  # LIR
                impu = get(avps, 601, V).decode()
                user = impu.split(":", 1)[-1].split("@")[0]
                self.note("LIR", user, impu)
                if user.startswith(("unknown", "nobody")):
                    self.answer(c, req, base + [unknown])
                else:
                    self.answer(c, req, base + [ok, avp(602, self.scscf, V)])
            elif cmd == 303:  # MAR
                impi = get(avps, 1).decode()
                user = impi.split("@")[0]
                scheme = parse_avps(get(avps, 612, V) or b"")
                self.note("MAR", user, (get(scheme, 608, V) or b"").decode())
                if user.startswith("mutemar"):
                    continue
                if user.startswith(("unknown", "nobody")):
                    self.answer(c, req, base + [unknown])
                    continue
                if user == "bob":
                    item = [avp(608, "Digest-AKAv1-MD5", V), avp(609, RAND + AUTN, V), avp(610, XRES, V), avp(625, CK, V), avp(626, IK, V)]
                else:
                    ha1 = md5(f"{impi}:{REALM}:{PASSWORDS.get(user, 'x')}")
                    item = [avp(608, "SIP Digest", V), avp(635, [avp(104, REALM), avp(121, ha1)], V)]
                self.answer(c, req, base + [ok, avp(601, get(avps, 601, V), V), avp(607, 1, V), avp(612, item, V)])
            elif cmd == 301:  # SAR
                user = get(avps, 1).decode().split("@")[0]
                sat = struct.unpack("!I", get(avps, 614, V))[0]
                self.note("SAR", user, sat)
                ud = USER_DATA.format(user=user, extra=ALICE_TEL if user == "alice" else "")
                self.answer(c, req, base + [ok] + ([avp(606, ud, V)] if sat in (1, 2) else []))
            else:
                self.answer(c, req, base + [avp(268, 3001)])  # DIAMETER_COMMAND_UNSUPPORTED


# ------------------------------------------------------------ SIP helpers --
def digest(impi, secret, ch, method, uri):
    """Authorization for an IMS challenge `ch` (params dict); `secret` is
    the password (str) or, for AKA, the RES (bytes)."""
    ha1 = md5(f"{impi}:{ch['realm']}:".encode() + (secret if isinstance(secret, bytes) else secret.encode()))
    ha2 = md5(f"{method}:{uri}")
    alg = ch.get("algorithm", "MD5")
    if "auth" in (ch.get("qop") or ""):
        cn = rnd(8)
        resp = md5(f"{ha1}:{ch['nonce']}:00000001:{cn}:auth:{ha2}")
        extra = f', qop=auth, nc=00000001, cnonce="{cn}"'
    else:
        resp, extra = md5(f"{ha1}:{ch['nonce']}:{ha2}"), ""
    return (f'Digest username="{impi}", realm="{ch["realm"]}", nonce="{ch["nonce"]}", uri="{uri}", '
            f'response="{resp}", algorithm={alg}{extra}')


def ims_register(ua, secret, expires=600, timeout=8.0):
    """REGISTER sip:ims.test, then once more with credentials for the 401.
    Returns (first reply, final reply); username is the IMPI user@ims.test."""
    impi = f"{ua.user}@{REALM}"
    hs = {"Contact": f"<{ua.contact}>", "Expires": str(expires)}
    call_id, tag = f"reg-{rnd(10)}", rnd(8)
    sent = ua.request("REGISTER", f"sip:{REALM}", to=f"<{ua.aor}>", headers=hs, call_id=call_id, from_tag=tag, cseq=1)
    first = ua.final(timeout, method="REGISTER", call_id=call_id, cseq=1)
    if first is None or first.code != 401 or secret is None:
        return first, first
    ch = [p for _, p, n in challenges(first) if n == "www-authenticate"]
    if not ch:
        return first, first
    hs2 = dict(hs, Authorization=digest(impi, secret, ch[0], "REGISTER", sent["ruri"]))
    ua.request("REGISTER", f"sip:{REALM}", to=f"<{ua.aor}>", headers=hs2, call_id=call_id, from_tag=tag, cseq=2)
    return first, ua.final(timeout, method="REGISTER", call_id=call_id, cseq=2)


def wait_open(proxy, secs=8.0):
    """Until the proxy's Diameter peer (the HSS) is I_Open."""
    end = time.time() + secs
    peers = None
    while time.time() < end:
        peers = proxy.rpc("cdp.list_peers")
        if isinstance(peers, list) and peers and peers[0].get("State") == "I_Open":
            return True, peers
        time.sleep(0.1)
    return False, peers


def contacts_of(pcscf, user):
    ues = pcscf.rpc("ulpcscf.showcontacts")
    if not isinstance(ues, list):
        return ues, []
    return ues, [u for u in ues if f"sip:{user}@" in str(u.get("aor", "")) or f"{user}@127.0.0.1" in str(u.get("contact", ""))]


def code(r):
    return r.code if r is not None else None


# The S-CSCF's tables (etc/schema/*.sql has them for PostgreSQL and MySQL).
USRLOC_SCHEMA = """
CREATE TABLE impu (id INTEGER PRIMARY KEY AUTOINCREMENT, impu TEXT NOT NULL, impi TEXT NOT NULL, reg_state INTEGER NOT NULL,
                   ims_subscription_data TEXT);
CREATE TABLE contact (id INTEGER PRIMARY KEY AUTOINCREMENT, impu TEXT NOT NULL, contact TEXT NOT NULL, received TEXT, path TEXT,
                      expires INTEGER NOT NULL, callid TEXT, cseq INTEGER);
CREATE TABLE subscriber_scscf (id INTEGER PRIMARY KEY AUTOINCREMENT, watcher_uri TEXT NOT NULL, watcher_contact TEXT NOT NULL,
                               presentity_uri TEXT NOT NULL, event INTEGER NOT NULL, expires INTEGER NOT NULL, version INTEGER NOT NULL,
                               local_cseq INTEGER NOT NULL, call_id TEXT NOT NULL, from_tag TEXT NOT NULL, to_tag TEXT NOT NULL,
                               record_route TEXT, sockinfo_str TEXT);
"""


def tls_dir(sc):
    """etc/tls when gen-certs.sh made the HSS's certificate there; else a
    private PKI in the scenario's temp directory (an older etc/tls is
    left alone: other scenarios may be using it)."""
    if os.path.exists(f"{sipkit.TLS_DIR}/hss.ims.test.pem"):
        return sipkit.TLS_DIR
    d = os.path.join(sc.tmp, "tls")
    os.makedirs(d, exist_ok=True)
    subprocess.run([f"{sipkit.TLS_DIR}/gen-certs.sh", d], check=True, capture_output=True)
    return d


def rows(db, q):
    c = sqlite3.connect(db)
    try:
        return c.execute(q).fetchall()
    finally:
        c.close()


def reginfo_version(m):
    """The version attribute of a NOTIFY's <reginfo> element."""
    x = re.search(r'<reginfo[^>]*\sversion="([^"]*)"', m.body) if m is not None else None
    return x.group(1) if x else None


# ------------------------------------------------------------------ run --
def run(sc):
    p_port, i_port, s_port, hss_port = sc.port(), sc.port(), sc.port(), sc.port()
    tls = tls_dir(sc)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=f"{tls}/ca.pem")
    ctx.load_cert_chain(f"{tls}/hss.ims.test.pem", f"{tls}/hss.ims.test.key.pem")
    ctx.verify_mode = ssl.CERT_REQUIRED  # the CSCFs must present a certificate of our CA
    hss = Hss(hss_port, f"sip:127.0.0.1:{s_port}", tls=ctx)
    sc.closers.append(hss.close)
    db = os.path.join(sc.tmp, "scscf.db")
    c = sqlite3.connect(db)
    c.executescript(USRLOC_SCHEMA)
    c.close()
    icscf_uri, scscf_uri = f"sip:127.0.0.1:{i_port}", f"sip:127.0.0.1:{s_port}"
    diam = {"HSS_HOST": "127.0.0.1", "HSS_PORT": hss_port, "TLS_DIR": tls}
    scscf = sc.proxy("scscf", sc.env(SCSCF_PORT=s_port, ICSCF=icscf_uri, **diam), name="scscf")
    icscf = sc.proxy("icscf", sc.env(ICSCF_PORT=i_port, SCSCF=scscf_uri, **diam), name="icscf")
    pcscf = sc.proxy("pcscf", sc.env(PCSCF_PORT=p_port, ICSCF=icscf_uri, SCSCF_ADDR=f"127.0.0.1:{s_port}"), name="pcscf")
    ok_s, ps = wait_open(scscf)
    ok_i, pi = wait_open(icscf)
    sc.check("S-CSCF and I-CSCF have an open Diameter connection to the HSS (CER/CEA), over TLS",
             ok_s and ok_i and ps[0].get("Proto") == "tls" and pi[0].get("Proto") == "tls", (ps, pi))
    sc.check("…the HSS got both CERs inside TLS (scscf.ims.test, icscf.ims.test)",
             sorted(x[1] for x in hss.seen("CER")) == ["icscf.ims.test", "scscf.ims.test"] and all(x[2] == "SSLSocket" for x in hss.seen("CER")),
             hss.log)
    sc.check("…and verified each CSCF's client certificate (signed by the CA, CN localhost)", hss.peer_certs == ["localhost", "localhost"], hss.peer_certs)

    ua = lambda user, **kw: sc.ua(user, p_port, domain=REALM, **kw)  # noqa: E731

    # First traffic: a REGISTER whose S-CSCF (per the HSS) is a probe, to see
    # the branch the P-CSCF puts in its Via; then the same after a P-CSCF
    # restart. RFC 3261 §8.1.1.7 / §16.6 step 8: branches are unique across
    # space and time. (A collision between two proxies' branches makes the
    # S-CSCF, which gets requests from both, take a new request for a
    # retransmission of another one: see the README.)
    probe_srv = sc.ua("probe-scscf", p_port, domain=REALM)
    hss.probe = f"sip:127.0.0.1:{probe_srv.port}"
    probe = ua("probe")

    def probe_register():
        """(branches the probe S-CSCF saw, the final reply the UE got for its REGISTER)."""
        s = probe.request("REGISTER", f"sip:{REALM}", to=f"<{probe.aor}>", headers={"Contact": f"<{probe.contact}>", "Expires": "600"})
        seen = probe_srv.request_in("REGISTER", timeout=4)
        if seen is not None:
            probe_srv.respond(seen, 403, "Probe")
        r = probe.final(4, call_id=s["call_id"])
        return [re.search(r"branch=([^;,\s]+)", v).group(1) for v in (seen.all("via") if seen else []) if "branch=" in v], r

    before, r1 = probe_register()
    sc.check("a REGISTER reaches the S-CSCF the HSS named (Vias of I-CSCF, P-CSCF, UE); its reply gets back",
             len(before) == 3 and code(r1) == 403, (before, r1))
    sc.check("pcscf (before its restart): no panics", "panicked" not in pcscf.stop(), pcscf.log[-800:])
    pcscf.start()
    after, r2 = probe_register()
    sc.check("after a P-CSCF restart, a new REGISTER reaches the S-CSCF too (the I-CSCF doesn't take it for a retransmission)",
             len(after) == 3 and code(r2) == 403, (after, r2))
    sc.check("…the restarted P-CSCF's Via branch is not the one it used before (unique across time, RFC 3261 §8.1.1.7)",
             len(before) == 3 and len(after) == 3 and before[1] != after[1], (before[:2], after[:2]))
    alice, bob = ua("alice"), ua("bob")
    bob.auto_answer()
    service_route = f"<sip:orig@127.0.0.1:{s_port};lr>"
    path = f"<sip:127.0.0.1:{p_port};lr>"

    # ---------------------------------------------------- registration
    m = hss.mark()
    ch, r = ims_register(alice, PASSWORDS["alice"])
    wa = (ch.get("www-authenticate") or "") if ch else ""
    sc.check("alice's REGISTER via P-CSCF and I-CSCF is challenged by the S-CSCF: 401 with SIP Digest (algorithm=MD5)",
             code(ch) == 401 and "algorithm=MD5" in wa and 'realm="ims.test"' in wa, ch and ch.raw)
    sc.check("…with credentials: 200", code(r) == 200, r and r.raw)
    sc.check("the HSS saw UAR (registration, type 0) for each REGISTER, one MAR (SIP Digest) and SAR REGISTRATION",
             [x[2] for x in hss.seen("UAR", "alice", m)] == [0, 0] and [x[2] for x in hss.seen("MAR", "alice", m)] == ["SIP Digest"]
             and [x[2] for x in hss.seen("SAR", "alice", m)] == [1], hss.log[m:])
    sc.check("the 200 has Service-Route <sip:orig@scscf;lr>", r is not None and r.all("service-route") == [service_route], r and r.all("service-route"))
    sc.check("the 200 echoes the P-CSCF's Path", r is not None and r.all("path") == [path], r and r.all("path"))
    sc.check("the 200 has P-Associated-URI with the implicit set (sip and tel)",
             r is not None and "<sip:alice@ims.test>" in (r.get("p-associated-uri") or "") and "<tel:+4930111>" in (r.get("p-associated-uri") or ""), r and r.get("p-associated-uri"))
    sc.check("the 200 lists alice's contact", r is not None and alice.contact in (r.get("contact") or ""), r and r.get("contact"))
    imp = scscf.rpc("ulscscf.showimpu", "tel:+4930111")
    sc.check("S-CSCF: the tel: IMPU of the implicit set resolves to alice's record, contact with the Path",
             isinstance(imp, dict) and imp.get("impu") == "sip:alice@ims.test" and any(c.get("path") == path for c in imp.get("contacts", [])), imp)
    ues, mine = contacts_of(pcscf, "alice")
    sc.check("P-CSCF keeps alice's registration: registered, with the Service-Route and associated URIs",
             len(mine) == 1 and mine[0].get("state") == "registered" and mine[0].get("service_routes") == [service_route]
             and "tel:+4930111" in str(mine[0].get("associated_uris")), ues)

    m = hss.mark()
    ch, r = ims_register(bob, XRES)
    wa = (ch.get("www-authenticate") or "") if ch else ""
    sc.check("bob gets an AKA challenge through the P-CSCF: algorithm=AKAv1-MD5, nonce = base64(RAND||AUTN)",
             code(ch) == 401 and "algorithm=AKAv1-MD5" in wa and base64.b64encode(RAND + AUTN).decode() in wa, wa)
    sc.check("…the AKA response (RES as the password) → 200, SAR REGISTRATION",
             code(r) == 200 and [x[2] for x in hss.seen("SAR", "bob", m)] == [1], (r and r.raw, hss.log[m:]))

    # ---------------------------------------------------- the core alone
    # What alice's P-CSCF would send: the request with the Service-Route.
    # S-CSCF (orig) → I-CSCF (LIR) → S-CSCF (term) → bob's P-CSCF (Path) → bob.
    m = hss.mark()
    core_ue = sc.ua("alice", s_port, domain=REALM)
    s = core_ue.request("MESSAGE", "sip:bob@ims.test", body="via the core", content_type="text/plain", headers={"Route": service_route})
    r = core_ue.final(8, call_id=s["call_id"])
    got = next((x for x in bob.received if x.method == "MESSAGE" and x.get("call-id") == s["call_id"]), None)
    sc.check("a MESSAGE on alice's Service-Route straight to the S-CSCF reaches bob through I-CSCF (LIR) and bob's P-CSCF: 200",
             code(r) == 200 and got is not None and any(x[2] == "sip:bob@ims.test" for x in hss.seen("LIR", "bob", m)), (r, hss.log[m:]))
    vias = got.all("via") if got else []
    sc.check("…bob's MESSAGE has the Vias of P-CSCF, S-CSCF, I-CSCF, S-CSCF and the sender",
             [v.split(";")[0].rsplit(":", 1)[-1] for v in vias] == [str(p_port), str(s_port), str(i_port), str(s_port), str(core_ue.port)], vias)

    # ---------------------------------------------------- a call
    m = hss.mark()
    route = {"Route": f"<sip:127.0.0.1:{p_port};lr>, {service_route}"}  # a UE preloads its P-CSCF and the Service-Route
    r, d = alice.call("sip:bob@ims.test", headers=route, timeout=8)
    sc.check("alice calls bob: P-CSCF → S-CSCF (orig) → I-CSCF (LIR) → S-CSCF (term) → P-CSCF → bob: 200",
             code(r) == 200 and d is not None, r and r.raw)
    inv = next((x for x in bob.received if x.method == "INVITE"), None)
    rr = inv.all("record-route") if inv else []
    sc.check("the HSS was asked where bob is (LIR for sip:bob@ims.test)", any(x[2] == "sip:bob@ims.test" for x in hss.seen("LIR", "bob", m)), hss.log[m:])
    sc.check("bob's INVITE went to his registered contact", inv is not None and inv.ruri.startswith(f"sip:bob@127.0.0.1:{bob.port}"), inv and inv.first)
    sc.check("bob's INVITE has 4 Record-Routes: P-CSCF, S-CSCF (term), S-CSCF (;orig), P-CSCF",
             len(rr) == 4 and f"127.0.0.1:{p_port}" in rr[0] and f"127.0.0.1:{s_port}" in rr[1] and "orig" not in rr[1]
             and f"127.0.0.1:{s_port}" in rr[2] and ";orig" in rr[2] and f"127.0.0.1:{p_port}" in rr[3], rr)
    sc.check("the S-CSCF's ;orig Record-Route: it got the call along the Service-Route (sip:orig@)",
             any(";orig" in x for x in rr), rr)
    sc.check("bob's INVITE has P-Asserted-Identity <sip:alice@ims.test> (added by alice's P-CSCF)",
             inv is not None and inv.all("p-asserted-identity") == ["<sip:alice@ims.test>"], inv and inv.all("p-asserted-identity"))
    sc.check("bob's INVITE carries no Route left over", inv is not None and not inv.all("route"), inv and inv.all("route"))
    if d:
        rep = d.bye(timeout=6)
        sc.check("alice's BYE goes back along the route set: 200", code(rep) == 200, rep and rep.raw)
        sc.check("…and bob saw it", any(x.method == "BYE" and x.get("call-id") == d.call_id for x in bob.received))

    # P-Asserted-Identity can't be forged; the identity must be one of the UE's.
    alice.auto_answer()
    fake = alice.request("MESSAGE", "sip:bob@ims.test", body="hi", content_type="text/plain",
                         headers={"P-Asserted-Identity": "<sip:bob@ims.test>", "P-Preferred-Identity": "<sip:bob@ims.test>"})
    r = alice.final(8, call_id=fake["call_id"])
    msg = next((x for x in bob.received if x.method == "MESSAGE" and x.get("call-id") == fake["call_id"]), None)
    sc.check("a MESSAGE with a forged P-Asserted-Identity: delivered (200) with the P-CSCF's PAI only (alice)",
             code(r) == 200 and msg is not None and msg.all("p-asserted-identity") == ["<sip:alice@ims.test>"]
             and msg.get("p-preferred-identity") is None, (r, msg and msg.raw))
    s = alice.request("MESSAGE", "sip:bob@ims.test", body="hi", content_type="text/plain", from_uri="sip:bob@ims.test")
    r = alice.final(6, call_id=s["call_id"])
    sc.check("alice sending as sip:bob (not one of her identities) → 403 Identity not registered at the P-CSCF",
             code(r) == 403 and r.reason == "Identity not registered", r)
    tel = alice.request("MESSAGE", "sip:bob@ims.test", body="hi", content_type="text/plain", from_uri="tel:+4930111")
    r = alice.final(8, call_id=tel["call_id"])
    sc.check("alice sending as tel:+4930111 (in her implicit set) → 200", code(r) == 200, r)

    mallory = ua("mallory")
    s = mallory.request("INVITE", "sip:bob@ims.test", body="v=0\r\n", headers={"Route": path})
    r = mallory.final(6, call_id=s["call_id"])
    sc.check("an unregistered UE (with a Route to the P-CSCF preloaded) → 403 Not registered", code(r) == 403, r)
    direct = sc.ua("carol", s_port, domain=REALM)
    s = direct.request("MESSAGE", "sip:bob@ims.test", body="hi", content_type="text/plain", headers={"Route": service_route})
    r = direct.final(6, call_id=s["call_id"])
    sc.check("S-CSCF: an originating request (sip:orig@ Route) from an unregistered user → 403", code(r) == 403, r)

    r, _ = alice.call("sip:carol@ims.test", headers=route, timeout=8)
    sc.check("a call to carol (known to the HSS, not registered): LIR ok, the S-CSCF answers 480", code(r) == 480, r)
    r, _ = alice.call("sip:nobody@ims.test", headers=route, timeout=8)
    sc.check("a call to an unknown user: LIR DIAMETER_ERROR_USER_UNKNOWN → 404 from the I-CSCF", code(r) == 404, r)

    # ---------------------------------------------------- failures
    m = hss.mark()
    _, r = ims_register(ua("unknown"), "x")
    sc.check("REGISTER of an unknown user: UAR DIAMETER_ERROR_USER_UNKNOWN → 403 from the I-CSCF, no MAR",
             code(r) == 403 and hss.seen("UAR", "unknown", m) and not hss.seen("MAR", since=m), (r, hss.log[m:]))

    m = hss.mark()
    t0 = time.time()
    # While the I-CSCF waits for the UAA, other traffic goes on: the UAR
    # suspends the transaction instead of holding a worker.
    other = {}

    def meanwhile():
        time.sleep(0.5)
        t1 = time.time()
        o = alice.request("MESSAGE", "sip:bob@ims.test", body="during a slow UAR", content_type="text/plain")
        other["r"], other["took"] = alice.final(6, call_id=o["call_id"]), time.time() - t1

    th = threading.Thread(target=meanwhile)
    th.start()
    _, r = ims_register(ua("mute"), "x", timeout=10)
    took = time.time() - t0
    th.join()
    sc.check("…a MESSAGE alice → bob sent meanwhile is answered at once (200 within 1.5s)",
             code(other.get("r")) == 200 and other.get("took", 99) < 1.5, (other.get("r"), other.get("took")))
    sc.check("REGISTER while the HSS doesn't answer the UAR → 500 from the I-CSCF after the 2s Diameter timeout",
             code(r) is not None and 500 <= code(r) < 600 and took < 5, (r, f"{took:.1f}s"))
    # The P-CSCF retransmits the REGISTER (T1 0.5s) while the I-CSCF waits;
    # let any repeated UAR run out before the next case.
    time.sleep(max(0.0, t0 + 6.5 - time.time()))
    uars = hss.seen("UAR", "mute", m)
    # The transaction is suspended while the HSS answers, so tm absorbs the
    # P-CSCF's retransmissions: they don't run the route again or send
    # another UAR.
    sc.check("…one UAR for that REGISTER: retransmissions during the wait are absorbed (as in Kamailio)",
             len(uars) == 1, [(x[0], x[1], round(x[3] - t0, 1)) for x in uars])

    t0 = time.time()
    _, r = ims_register(ua("mutemar"), "x", timeout=10)
    took = time.time() - t0
    sc.check("REGISTER while the HSS doesn't answer the MAR → the S-CSCF's 500 \"MAR failed\" (as Kamailio) in time",
             code(r) == 500 and took < 5, (r, f"{took:.1f}s"))
    o = alice.request("MESSAGE", "sip:bob@ims.test", body="still there?", content_type="text/plain")
    r = alice.final(6, call_id=o["call_id"])
    sc.check("…and the core still serves other users meanwhile (alice → bob MESSAGE: 200)", code(r) == 200, r)

    # ---------------------------------------------------- re-registration
    ues, reg_before = contacts_of(pcscf, "alice")
    m = hss.mark()
    _, r = ims_register(alice, PASSWORDS["alice"], expires=900)
    sc.check("alice re-registers: 200, SAR RE_REGISTRATION", code(r) == 200 and [x[2] for x in hss.seen("SAR", "alice", m)] == [2], (r, hss.log[m:]))
    sc.check("…same Service-Route", r is not None and r.all("service-route") == [service_route], r and r.all("service-route"))
    sc.check("…one contact for alice in the 200 (not a second binding)", r is not None and len(r.all("contact")) == 1, r and r.all("contact"))
    ues, reg_after = contacts_of(pcscf, "alice")
    sc.check("…the P-CSCF still has one entry for alice, registered, its expiry pushed out to about 900s",
             len(reg_after) == 1 and reg_after[0].get("state") == "registered" and 800 < int(reg_after[0].get("expires") or 0) <= 900, (reg_before, reg_after))

    # ---------------------------------------------------- reg event, the S-CSCF's database, a restart
    imp_rows = rows(db, "SELECT impu, impi, reg_state FROM impu")
    ct_rows = rows(db, "SELECT impu, contact, path FROM contact")
    sc.check("the S-CSCF wrote alice's and bob's records through to its database (impu, contact with the Path)",
             ("sip:alice@ims.test", "alice@ims.test", 1) in imp_rows and ("sip:bob@ims.test", "bob@ims.test", 1) in imp_rows
             and any(r[0] == "sip:alice@ims.test" and alice.contact in r[1] and r[2] == path for r in ct_rows), (imp_rows, ct_rows))

    def notifies(cid):
        return [x for x in alice.received if x.method == "NOTIFY" and x.get("call-id") == cid]

    def wait_notify(cid, n, secs=4.0):
        end = time.time() + secs
        while time.time() < end and len(notifies(cid)) < n:
            time.sleep(0.05)
        got = notifies(cid)
        return got[n - 1] if len(got) >= n else None

    # alice subscribes to her own registration state (TS 24.229 §5.1.1.3),
    # along her Service-Route through the P-CSCF.
    sub = alice.request("SUBSCRIBE", "sip:alice@ims.test", headers={"Event": "reg", "Accept": "application/reginfo+xml", "Expires": "600"})
    r = alice.final(8, call_id=sub["call_id"])
    sc.check("alice SUBSCRIBEs to her reg event (via P-CSCF, Service-Route): 200 from the S-CSCF", code(r) == 200, r and r.raw)
    n1 = wait_notify(sub["call_id"], 1)
    sc.check("…a NOTIFY with the full reginfo document: both IMPUs of her implicit set, her contact active",
             n1 is not None and n1.get("event") == "reg" and n1.get("content-type") == "application/reginfo+xml"
             and 'state="full"' in n1.body and 'aor="sip:alice@ims.test"' in n1.body and 'aor="tel:+4930111"' in n1.body
             and alice.contact in n1.body, n1 and n1.raw)
    sc.check("…reaching alice through her P-CSCF (the NOTIFY came along the SUBSCRIBE's Record-Route)",
             n1 is not None and n1.src == ("127.0.0.1", p_port), n1 and n1.src)
    s = bob.request("SUBSCRIBE", "sip:alice@ims.test", headers={"Event": "reg", "Expires": "600"})
    r = bob.final(8, call_id=s["call_id"])
    sc.check("bob subscribing to alice's registration → 403 (not in her implicit set)", code(r) == 403, r)
    s = alice.request("SUBSCRIBE", "sip:alice@ims.test", headers={"Event": "presence", "Expires": "600"})
    r = alice.final(8, call_id=s["call_id"])
    sc.check("a SUBSCRIBE for another event package → 489 Bad Event", code(r) == 489, r)
    _, r = ims_register(alice, PASSWORDS["alice"], expires=900)
    n2 = wait_notify(sub["call_id"], 2)
    sc.check("alice re-registers: a partial NOTIFY (contact refreshed), version 1, in the same dialog",
             code(r) == 200 and n2 is not None and 'state="partial"' in n2.body and reginfo_version(n2) == "1"
             and 'event="refreshed"' in n2.body and n2.tag("from") == n1.tag("from"), n2 and n2.raw)
    subs = rows(db, "SELECT presentity_uri, watcher_uri, version, local_cseq, call_id FROM subscriber_scscf")
    sc.check("…the subscription is in subscriber_scscf with its version and last CSeq",
             n2 is not None and ("sip:alice@ims.test", "sip:alice@ims.test", 1, int(n2.get("cseq").split()[0]), sub["call_id"]) in subs, subs)

    # The S-CSCF restarts: registrations and the subscription come back from the database.
    sc.check("scscf (before its restart): no panics", "panicked" not in scscf.stop(), scscf.log[-800:])
    scscf.start()
    ok_s, ps = wait_open(scscf)
    sc.check("the restarted S-CSCF reconnects to the HSS over TLS", ok_s and ps[0].get("Proto") == "tls", ps)
    sc.check("…and logs the records it loaded from the database", any("loaded 2 IMPU records" in l for l in scscf.lines), scscf.early[-600:])
    imp = scscf.rpc("ulscscf.showimpu", "tel:+4930111")
    sc.check("…alice is registered again without a REGISTER: implicit set and contact with the Path",
             isinstance(imp, dict) and imp.get("impu") == "sip:alice@ims.test" and imp.get("state") == "registered"
             and any(x.get("path") == path for x in imp.get("contacts", [])), imp)
    m = hss.mark()
    r, d = alice.call("sip:bob@ims.test", headers=route, timeout=8)
    sc.check("a call alice → bob right after the restart: 200 (both registrations loaded; no SAR needed)",
             code(r) == 200 and d is not None and not hss.seen("SAR", since=m), (r, hss.log[m:]))
    if d:
        rep = d.bye(timeout=6)
        sc.check("…BYE → 200", code(rep) == 200, rep)
    m = hss.mark()
    _, r = ims_register(alice, PASSWORDS["alice"], expires=900)
    sc.check("alice's next REGISTER is a re-registration (SAR RE_REGISTRATION)",
             code(r) == 200 and [x[2] for x in hss.seen("SAR", "alice", m)] == [2], (r, hss.log[m:]))
    n3 = wait_notify(sub["call_id"], 3)
    sc.check("…and the reg-event subscription survived: a partial NOTIFY in the same dialog, CSeq and version continuing",
             n2 is not None and n3 is not None and 'state="partial"' in n3.body and reginfo_version(n3) == "2"
             and n3.tag("from") == n2.tag("from") and n3.tag("to") == n2.tag("to")
             and int(n3.get("cseq").split()[0]) == int(n2.get("cseq").split()[0]) + 1, (n2 and n2.raw, n3 and n3.raw))

    # ---------------------------------------------------- de-registration
    m = hss.mark()
    _, r = ims_register(bob, XRES, expires=0)
    sc.check("bob de-registers (Expires 0): 200", code(r) == 200, r and r.raw)
    sc.check("…UAR de-registration (type 1) and SAR USER_DEREGISTRATION",
             1 in [x[2] for x in hss.seen("UAR", "bob", m)] and [x[2] for x in hss.seen("SAR", "bob", m)] == [5], hss.log[m:])
    imp = scscf.rpc("ulscscf.showimpu", "sip:bob@ims.test")
    sc.check("…the S-CSCF has no record for bob", not (isinstance(imp, dict) and imp.get("contacts")), imp)
    ues, b = contacts_of(pcscf, "bob")
    sc.check("…and the P-CSCF dropped bob's contact", not b, ues)
    r, _ = alice.call("sip:bob@ims.test", headers=route, timeout=8)
    sc.check("a call to bob now → 480 from the S-CSCF", code(r) == 480, r)
    s = bob.request("MESSAGE", "sip:alice@ims.test", body="hi", content_type="text/plain")
    r = bob.final(6, call_id=s["call_id"])
    sc.check("bob's own requests are refused by the P-CSCF (403)", code(r) == 403, r)

    # ---------------------------------------------------- HSS gone
    hss.close()
    time.sleep(0.5)
    t0 = time.time()
    _, r = ims_register(ua("dave"), "x", timeout=10)
    took = time.time() - t0
    sc.check("with the HSS down, a REGISTER gets a 5xx quickly (no hang)", code(r) is not None and 500 <= code(r) < 600 and took < 5, (r, f"{took:.1f}s"))
