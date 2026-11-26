#!/usr/bin/env python3
"""End-to-end checks for the Phase 4 modules: rtpengine (against a fake
ng server), dialplan, lcr (Sipwise patches), acc (+ CDRs), uac (From/To
replacement and restore, uac_auth, uac_req_send, remote registrations),
topoh and topos. Run from the repo root after `cargo build --release`.
"""
import hashlib, json, os, re, shutil, socket, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402
from e2e_routing import Peer, make_reply, hdr, hdrs, first  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PX, PX2 = 6160, 6260
CALLER, A, B = 6100, 6101, 6102
GW1, GW2, GW3 = 6111, 6112, 6113
NG, NG_DEAD, REGSRV = 6122, 6123, 6130
SOCK = os.path.join(ROOT, "target/e2e_carrier.sock")
SOCK2 = os.path.join(ROOT, "target/e2e_carrier2.sock")
DB = os.path.join(ROOT, "target/e2e_carrier_db")

CFG = r"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "siputils"
loadmodule "dialog"
loadmodule "rtpengine"
loadmodule "dialplan"
loadmodule "lcr"
loadmodule "acc"
loadmodule "uac"
modparam("tm", "fr_timer", 1500)
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:6122")
modparam("rtpengine", "rtpengine_sock", "1 == udp:127.0.0.1:6123")
modparam("rtpengine", "rtpengine_tout_ms", 200)
modparam("rtpengine", "rtpengine_retr", 1)
modparam("dialplan", "db_url", "text://DB")
modparam("dialplan", "attrs_pvar", "$avp(dpattrs)")
modparam("lcr", "db_url", "text://DB")
modparam("lcr", "lcr_stats", 1)
modparam("lcr", "gw_id_avp", "$avp(gwid)")
modparam("lcr", "tag_avp", "$avp(gwtag)")
modparam("acc", "log_flag", 1)
modparam("acc", "db_flag", 2)
modparam("acc", "db_missed_flag", 3)
modparam("acc", "db_url", "text://DB")
modparam("acc", "db_extra", "src_user=$fU;dst_user=$rU")
modparam("acc", "cdr_enable", 1)
modparam("uac", "restore_mode", "auto")
modparam("uac", "credential", "u1:gw:pw1")
modparam("uac", "reg_db_url", "text://DB")
modparam("uac", "reg_contact_addr", "127.0.0.1:6160")

request_route {
    if (has_totag()) {
        if ($rm == "BYE") { rtpengine_delete(); }
        t_relay();
        exit;
    }
    if ($rU =~ "^49") {
        if (!load_gws(1)) { sl_send_reply(500, "lcr error"); exit; }
        if (!next_gw()) { sl_send_reply(503, "no gateways"); exit; }
        append_hf("X-GW: $avp(gwid) $avp(gwtag)");
        t_on_failure("lcrnext");
        t_relay();
        exit;
    }
    switch ($rU) {
    case "rtp":
        if (!rtpengine_offer("replace-origin replace-session-connection ICE=remove RTP/AVP via-branch=1")) { sl_send_reply(500, "rtp failed"); exit; }
        t_on_reply("rtp");
        t_relay("udp:127.0.0.1:6101");
        exit;
    case "rtpq":
        rtpengine_query();
        sl_send_reply(200, "$rtpstat");
        exit;
    case "rtpdead":
        set_rtpengine_set(1);
        if (!rtpengine_offer()) { sl_send_reply(503, "no rtpengine"); exit; }
        sl_send_reply(200, "?");
        exit;
    case "dp":
        $var(in) = $hdr(X-Num);
        if (dp_translate("1", "$var(in)/$var(out)")) { sl_send_reply(200, "out=$var(out) attrs=$avp(dpattrs)"); }
        else { sl_send_reply(404, "no rule"); }
        exit;
    case "fromgw":
        $var(r) = "";
        if (from_gw("1")) { $var(r) = "src "; }
        if (!from_gw("1", "127.0.0.1", "1", "6100")) { $var(r) = $var(r) + "notport "; }
        if (from_gw("1", "127.0.0.1", "1", "6111")) { $var(r) = $var(r) + "gw tag=$avp(gwtag)"; }
        sl_send_reply(200, "$var(r)");
        exit;
    case "acc":
        setflag(1); setflag(2); setflag(3);
        t_relay("udp:127.0.0.1:6101");
        exit;
    case "accdlg":
        dlg_manage();
        t_relay("udp:127.0.0.1:6101");
        exit;
    case "accman":
        acc_db_request("200 Manual", "acc");
        sl_send_reply(200, "accounted");
        exit;
    case "uacfrom":
        uac_replace_from("Anon", "sip:anonymous@anonymous.invalid");
        t_relay("udp:127.0.0.1:6101");
        exit;
    case "uacauth":
        t_on_failure("auth");
        t_relay("udp:127.0.0.1:6101");
        exit;
    case "uacreq":
        $uac_req(method) = "MESSAGE";
        $uac_req(ruri) = "sip:x@127.0.0.1:6102";
        $uac_req(furi) = "sip:proxy@x";
        $uac_req(hdrs) = "X-Q: 1";
        $uac_req(body) = "hello";
        if (uac_req_send()) { sl_send_reply(200, "sent"); } else { sl_send_reply(500, "not sent"); }
        exit;
    case "acct1":
        if (uac_reg_lookup("$rU", "$var(d)")) { sl_send_reply(200, "$var(d)"); } else { sl_send_reply(404, "no reg"); }
        exit;
    }
    sl_send_reply(404, "Not Found");
}

onreply_route[rtp] {
    if (has_body("application/sdp")) { rtpengine_answer(); }
}

failure_route[lcrnext] {
    if (t_check_status("503")) {
        defunct_gw("60");
        if (next_gw()) { append_hf("X-GW: $avp(gwid) $avp(gwtag)"); t_relay(); }
    }
}

failure_route[auth] {
    if (t_check_status("401|407")) {
        if (uac_auth()) { t_relay(); }
    }
}
"""

CFG_TOPO = r"""
loadmodule "tm"
loadmodule "siputils"
loadmodule "TOPO"
request_route {
    if (has_totag()) { t_relay(); exit; }
    t_relay("udp:127.0.0.1:6101");
}
"""

TABLES = {
    "dialplan": "id(int,auto) dpid(int) pr(int) match_op(int) match_exp(string) match_len(int) subst_exp(string,null) repl_exp(string,null) attrs(string,null)\n"
                "1:1:1:1:^0([1-9][0-9]+)$:0:^0([1-9][0-9]+)$:+49\\\\1:national\n"
                "2:1:2:0:110:0::+49110:emergency\n"
                "3:1:3:2:00*:0:^00:+:intl\n"
                "4:1:0:1:(broken:0:::bad\n",
    "lcr_gw": "id(int,auto) lcr_id(int) gw_name(string) ip_addr(string,null) hostname(string,null) port(int,null) params(string,null) "
              "uri_scheme(int,null) transport(int,null) strip(int,null) prefix(string,null) tag(string,null) flags(int) defunct(int,null)\n"
              "1:1:gw1:127.0.0.1::6111::1:1:2:pre:gw1tag:3:\n"
              "2:1:gw2:127.0.0.1::6112::1::0::gw2tag:0:\n"
              "3:1:gw3:127.0.0.1::6113::1::0::gw3tag:0:\n",
    "lcr_rule": "id(int,auto) lcr_id(int) prefix(string,null) from_uri(string,null) request_uri(string,null) mt_tvalue(string,null) stopper(int) enabled(int)\n"
                "1:1:49::::0:1\n2:1:4930::::0:1\n3:1:4940::::1:1\n4:1:::::0:1\n",
    "lcr_rule_target": "id(int,auto) lcr_id(int) rule_id(int) gw_id(int) priority(int) weight(int)\n"
                       "1:1:2:1:1:1\n2:1:1:2:1:1\n3:1:3:3:1:1\n4:1:4:3:1:1\n",
    "acc": "id(int,auto) method(string) from_tag(string) to_tag(string) callid(string) sip_code(string) sip_reason(string) time(int) src_user(string,null) dst_user(string,null)\n",
    "missed_calls": "id(int,auto) method(string) from_tag(string) to_tag(string) callid(string) sip_code(string) sip_reason(string) time(int) src_user(string,null) dst_user(string,null)\n",
    "cdrs": "cdr_id(int,auto) sip_call_id(string) sip_from_tag(string) sip_to_tag(string) src_username(string) src_domain(string) dst_username(string) dst_domain(string) call_start_time(int) duration(int)\n",
    "uacreg": "id(int,auto) l_uuid(string) l_username(string) l_domain(string) r_username(string) r_domain(string) realm(string) auth_username(string) "
              "auth_password(string) auth_proxy(string,null) expires(int) flags(int)\n"
              "1:acct1:local1:x:remote1:127.0.0.1\\:6130:reg:remote1:rpw::60:0\n",
}

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def msg(method, ruri, extra="", frm="sip:caller@x", body="", callid=None, to=None, cseq=1, port=CALLER):
    seq[0] += 1
    ex = "".join(l + "\r\n" for l in extra.split("\n") if l) if extra else ""
    ct = "Content-Type: application/sdp\r\n" if body else ""
    return (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKc{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: <{frm}>;tag=c1\r\nTo: {to or '<' + ruri + '>'}\r\nCall-ID: {callid or f'ca-{seq[0]}-{time.time_ns()}'}\r\n"
            f"CSeq: {cseq} {method}\r\nContact: <sip:caller@127.0.0.1:{port}>\r\n{ex}{ct}Content-Length: {len(body)}\r\n\r\n{body}").encode()


# --------------------------------------------------------------- bencode --
def benc(x):
    if isinstance(x, int):
        return b"i%de" % x
    if isinstance(x, str):
        x = x.encode()
    if isinstance(x, bytes):
        return b"%d:%s" % (len(x), x)
    if isinstance(x, list):
        return b"l" + b"".join(benc(i) for i in x) + b"e"
    return b"d" + b"".join(benc(k) + benc(v) for k, v in sorted(x.items())) + b"e"


def bdec(s, i=0):
    c = s[i:i + 1]
    if c == b"i":
        e = s.index(b"e", i)
        return int(s[i + 1:e]), e + 1
    if c == b"l":
        i, out = i + 1, []
        while s[i:i + 1] != b"e":
            v, i = bdec(s, i)
            out.append(v)
        return out, i + 1
    if c == b"d":
        i, out = i + 1, {}
        while s[i:i + 1] != b"e":
            k, i = bdec(s, i)
            v, i = bdec(s, i)
            out[k.decode()] = v
        return out, i + 1
    colon = s.index(b":", i)
    n = int(s[i:colon])
    return s[colon + 1:colon + 1 + n], colon + 1 + n


class FakeRtpengine(threading.Thread):
    def __init__(self, port):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.cmds = []
        self.start()

    def run(self):
        while True:
            d, a = self.s.recvfrom(65535)
            cookie, _, body = d.partition(b" ")
            req, _ = bdec(body)
            self.cmds.append(req)
            cmd = req["command"].decode()
            if cmd in ("offer", "answer"):
                sdp = req["sdp"].decode()
                sdp = re.sub(r"c=IN IP4 \S+", "c=IN IP4 203.0.113.1", sdp)
                sdp = re.sub(r"m=audio \d+", "m=audio 30000" if cmd == "offer" else "m=audio 30002", sdp)
                resp = {"result": "ok", "sdp": sdp}
            elif cmd == "query":
                resp = {"result": "ok", "totals": {"RTP": {"bytes": 1000, "packets": 10, "errors": 0}, "RTCP": {"bytes": 50, "packets": 1, "errors": 0}}}
            elif cmd == "ping":
                resp = {"result": "pong"}
            else:
                resp = {"result": "ok"}
            self.s.sendto(cookie + b" " + benc(resp), a)


class FakeRegistrar(threading.Thread):
    def __init__(self, port):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.got, self.ok = [], False
        self.start()

    def run(self):
        while True:
            d, a = self.s.recvfrom(65535)
            if not d.startswith(b"REGISTER"):
                continue
            self.got.append(d)
            auth = hdr(d, "Authorization")
            if not auth:
                # RFC 8760: challenges in order of preference, SHA-256 first.
                self.s.sendto(make_reply(d, 401, "Unauthorized",
                                         'WWW-Authenticate: Digest realm="reg", nonce="rn1", algorithm=SHA-256, qop="auth"\r\n'
                                         'WWW-Authenticate: Digest realm="reg", nonce="rn1", algorithm=MD5\r\n'), a)
                continue
            p = dict(re.findall(r'(\w+)="?([^",]+)"?', auth))
            h = lambda x: hashlib.sha256(x.encode()).hexdigest()
            ha2 = h("REGISTER:" + p.get("uri", ""))
            want = h(f"{h('remote1:reg:rpw')}:rn1:{p.get('nc')}:{p.get('cnonce')}:auth:{ha2}")
            if p.get("algorithm") == "SHA-256" and p.get("qop") == "auth" and f'response="{want}"' in auth:
                self.ok = True
                self.s.sendto(make_reply(d, 200, "OK", "Expires: 60\r\n"), a)
            else:
                self.s.sendto(make_reply(d, 403, "Forbidden"), a)


def ctl(sock, *args):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", sock, *args], capture_output=True, text=True, timeout=5)
    try:
        return json.loads(out.stdout) if out.stdout.strip() else out.stderr.strip()
    except json.JSONDecodeError:
        return out.stdout


def start(cfg, port, sock):
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{port}", "-n", "2", "--rpc-socket", sock],
                         stderr=subprocess.PIPE, text=True)
    wait_listening(p)
    if p.poll() is not None:
        print(p.stderr.read())
        sys.exit(1)
    return p


def stop(p):
    p.terminate()
    try:
        return p.communicate(timeout=3)[1]
    except subprocess.TimeoutExpired:
        p.kill()
        return p.communicate()[1]


def rows(t):
    return open(os.path.join(DB, t)).read().splitlines()[1:]


def main():
    shutil.rmtree(DB, ignore_errors=True)
    os.makedirs(DB)
    for t, body in TABLES.items():
        open(os.path.join(DB, t), "w").write(body)
    cfg = os.path.join(ROOT, "target/e2e_carrier.cfg")
    open(cfg, "w").write(CFG.replace("text://DB", "text://" + DB))
    ng, regsrv = FakeRtpengine(NG), FakeRegistrar(REGSRV)
    proxy = start(cfg, PX, SOCK)
    caller, a, b, g1, g2, g3 = Peer(CALLER), Peer(A), Peer(B), Peer(GW1), Peer(GW2), Peer(GW3)
    err = ""

    def send(m, to=PX, sock=None):
        (sock or caller).s.sendto(m, ("127.0.0.1", to))

    def ask(m, to=PX):
        send(m, to)
        return caller.final()

    try:
        # ------------------------------------------------------------ rtpengine
        sdp = "v=0\r\no=- 1 1 IN IP4 10.0.0.5\r\ns=-\r\nc=IN IP4 10.0.0.5\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n"
        cid = f"rtp-{time.time_ns()}"
        send(msg("INVITE", "sip:rtp@127.0.0.1:6160", body=sdp, callid=cid))
        inv = a.expect("INVITE")
        body = inv.split(b"\r\n\r\n", 1)[1].decode() if inv else ""
        check("rtpengine_offer: SDP rewritten, Content-Length fixed", "c=IN IP4 203.0.113.1" in body and "m=audio 30000" in body
              and hdr(inv, "Content-Length") == str(len(body)), body)
        off = ng.cmds[-1] if ng.cmds else {}
        check("…ng offer dictionary (call-id, from-tag, flags, replace, ICE, transport, received-from, via-branch)",
              off.get("command") == b"offer" and off.get("call-id") == cid.encode() and off.get("from-tag") == b"c1"
              and off.get("replace") == [b"origin", b"session-connection"] and off.get("ICE") == b"remove"
              and off.get("transport-protocol") == b"RTP/AVP" and off.get("received-from") == [b"IP4", b"127.0.0.1"]
              and off.get("via-branch", b"").startswith(b"z9hG4bK"), off)
        ans_sdp = sdp.replace("10.0.0.5", "10.0.0.6")
        rep = make_reply(inv, 200, "OK", f"Contact: <sip:a@127.0.0.1:{A}>\r\nContent-Type: application/sdp\r\n").replace(
            b"Content-Length: 0\r\n\r\n", f"Content-Length: {len(ans_sdp)}\r\n\r\n{ans_sdp}".encode())
        a.s.sendto(rep, a.addr)
        r = caller.final()
        rbody = r.split(b"\r\n\r\n", 1)[1].decode() if r else ""
        check("rtpengine_answer in onreply_route rewrites the 200's SDP", "c=IN IP4 203.0.113.1" in rbody and "m=audio 30002" in rbody
              and hdr(r, "Content-Length") == str(len(rbody)) and ng.cmds[-1].get("to-tag") == b"uas", rbody)
        send(msg("BYE", f"sip:a@127.0.0.1:{A}", callid=cid, to="<sip:rtp@127.0.0.1:6160>;tag=uas", cseq=2))
        a.answer("BYE")
        caller.final()
        check("rtpengine_delete on BYE", ng.cmds[-1].get("command") == b"delete" and ng.cmds[-1].get("call-id") == cid.encode(), ng.cmds[-1])
        r = ask(msg("OPTIONS", "sip:rtpq@127.0.0.1:6160"))
        check("rtpengine_query → $rtpstat", first(r) == "SIP/2.0 200 RTP: 1000 bytes, 10 packets, 0 errors; RTCP: 50 bytes, 1 packets, 0 errors", first(r))
        r = ask(msg("INVITE", "sip:rtpdead@127.0.0.1:6160", body=sdp))
        shown = ctl(SOCK, "rtpengine.show", "udp:127.0.0.1:6123")
        check("dead rtpengine node: offer fails, node disabled", first(r) == "SIP/2.0 503 no rtpengine" and shown[0]["disabled"] is True, (first(r), shown))
        check("rtpengine.ping", ctl(SOCK, "rtpengine.ping", "udp:127.0.0.1:6122") == [{"url": "udp:127.0.0.1:6122", "status": "success"}])

        # ------------------------------------------------------------ dialplan
        dp = lambda n: first(ask(msg("OPTIONS", "sip:dp@127.0.0.1:6160", f"X-Num: {n}")))
        check("dialplan: regex subst with \\1 and attrs", dp("03012345") == "SIP/2.0 200 out=+493012345 attrs=national", dp("03012345"))
        check("dialplan: string equality rule", dp("110") == "SIP/2.0 200 out=+49110 attrs=emergency")
        check("dialplan: fnmatch rule", dp("0044123") == "SIP/2.0 200 out=+44123 attrs=intl")
        check("dialplan: no match", dp("abc") == "SIP/2.0 404 no rule")
        check("dialplan: broken rule skipped (Sipwise patch), others loaded", len(ctl(SOCK, "dialplan.dump", "1")) == 3)
        check("dialplan.translate", ctl(SOCK, "dialplan.translate", "1", "0301") == {"Output": "+49301", "Attributes": "national"})

        # ------------------------------------------------------------ lcr
        lg = lambda u: [g["gw_id"] for g in ctl(SOCK, "lcr.load_gws", "1", u)]
        check("lcr: longest prefix first, catch-all last", lg("49301234") == [1, 2, 3], lg("49301234"))
        check("lcr: stopper rule hides shorter prefixes", lg("49401234") == [3], lg("49401234"))
        send(msg("INVITE", "sip:49301234@127.0.0.1:6160"))
        m1 = g1.expect("INVITE")
        check("next_gw: strip 2 + prefix, gateway host/port, gw_id_avp/tag_avp", m1 is not None and first(m1).startswith("INVITE sip:pre301234@127.0.0.1:6111")
              and hdr(m1, "X-GW") == "1 gw1tag", m1)
        if m1:
            g1.s.sendto(make_reply(m1, 503, "Unavailable"), g1.addr)
        m2 = g2.expect("INVITE")
        check("failure_route: defunct_gw + next_gw → second gateway", m2 is not None and first(m2).startswith("INVITE sip:49301234@127.0.0.1:6112")
              and hdrs(m2, "X-GW")[-1] == "2 gw2tag", m2)
        if m2:
            g2.s.sendto(make_reply(m2, 200, "OK", f"Contact: <sip:gw@127.0.0.1:{GW2}>\r\n"), g2.addr)
        r = caller.final()
        check("…call answered by gw2", first(r) == "SIP/2.0 200 OK", r)
        gws = {g["gw_id"]: g for g in ctl(SOCK, "lcr.dump_gws")}
        check("defunct gateway reported", gws[1]["state"] == "defunct", gws[1])
        check("lcr_stats (Sipwise): replies per gateway", gws[1]["stats"]["rcv_gw_rpl_5xx"] == 1 and gws[2]["stats"]["rcv_gw_rpl_2xx"] == 1, gws)
        check("lcr: defunct gateway skipped", lg("49301234") == [2, 3], lg("49301234"))
        send(msg("OPTIONS", "sip:fromgw@127.0.0.1:6160", port=GW3), sock=g3)
        r = g3.final()
        check("from_gw: by source IP / by address + port", first(r) == "SIP/2.0 200 src notport gw tag=gw1tag", first(r))
        check("lcr.defunct_gw RPC (0 = reactivate)", ctl(SOCK, "lcr.defunct_gw", "1", "1", "0") == 0 and lg("49301234") == [1, 2, 3])

        # ------------------------------------------------------------ acc
        send(msg("INVITE", "sip:acc@127.0.0.1:6160"))
        a.answer("INVITE", 200, "OK", f"Contact: <sip:a@127.0.0.1:{A}>\r\n")
        caller.final()
        time.sleep(0.2)
        accrows = rows("acc")
        check("acc: answered INVITE in the acc table with db_extra", len(accrows) == 1 and ":INVITE:c1:uas:" in accrows[0]
              and accrows[0].split(":")[5] == "200" and accrows[0].endswith(":caller:acc"), accrows)
        send(msg("INVITE", "sip:acc@127.0.0.1:6160"))
        a.answer("INVITE", 486, "Busy Here")
        caller.final()
        time.sleep(0.2)
        miss = rows("missed_calls")
        check("acc: missed call (486) in missed_calls", len(miss) == 1 and miss[0].split(":")[5] == "486", miss)
        check("…and not in acc (no failed_transaction_flag)", len(rows("acc")) == 1)
        r = ask(msg("OPTIONS", "sip:accman@127.0.0.1:6160"))
        check("acc_db_request", first(r) == "SIP/2.0 200 accounted" and rows("acc")[-1].split(":")[5:7] == ["200", "Manual"], rows("acc"))
        cid = f"cdr-{time.time_ns()}"
        send(msg("INVITE", "sip:accdlg@127.0.0.1:6160", callid=cid))
        a.answer("INVITE", 200, "OK", f"Contact: <sip:a@127.0.0.1:{A}>\r\n")
        caller.final()
        send(msg("ACK", f"sip:a@127.0.0.1:{A}", callid=cid, to="<sip:accdlg@127.0.0.1:6160>;tag=uas"))
        a.expect("ACK")
        time.sleep(1.1)
        send(msg("BYE", f"sip:a@127.0.0.1:{A}", callid=cid, to="<sip:accdlg@127.0.0.1:6160>;tag=uas", cseq=2))
        a.answer("BYE")
        caller.final()
        time.sleep(0.2)
        cdr = rows("cdrs")
        check("acc CDR from dialog (cdr_enable)", len(cdr) == 1 and cdr[0].startswith(f"1:{cid}:c1:uas:caller:x:accdlg:127.0.0.1")
              and int(cdr[0].split(":")[-1]) >= 1, cdr)

        # ------------------------------------------------------------ uac
        cid = f"uac-{time.time_ns()}"
        send(msg("INVITE", "sip:uacfrom@127.0.0.1:6160", callid=cid))
        m = a.answer("INVITE", 200, "OK", f"Contact: <sip:a@127.0.0.1:{A}>\r\n")
        check("uac_replace_from: callee sees the new From", m is not None and hdr(m, "From") == '"Anon" <sip:anonymous@anonymous.invalid>;tag=c1', hdr(m or b"", "From"))
        r = caller.final()
        check("…reply restored for the caller", hdr(r or b"", "From") == "<sip:caller@x>;tag=c1", hdr(r or b"", "From"))
        send(msg("BYE", f"sip:a@127.0.0.1:{A}", callid=cid, to="<sip:uacfrom@127.0.0.1:6160>;tag=uas", cseq=2))
        m = a.answer("BYE")
        check("…in-dialog request from the caller replaced again", m is not None and hdr(m, "From") == '"Anon" <sip:anonymous@anonymous.invalid>;tag=c1', hdr(m or b"", "From"))
        caller.final()
        rev = (f"BYE sip:caller@127.0.0.1:{CALLER} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{A};branch=z9hG4bKrev{time.time_ns()}\r\nMax-Forwards: 70\r\n"
               f"From: <sip:uacfrom@127.0.0.1:6160>;tag=uas\r\nTo: \"Anon\" <sip:anonymous@anonymous.invalid>;tag=c1\r\nCall-ID: {cid}\r\n"
               f"CSeq: 5 BYE\r\nContent-Length: 0\r\n\r\n").encode()
        a.s.sendto(rev, ("127.0.0.1", PX))
        m = caller.expect("BYE")
        check("…request from the callee gets the original To back", m is not None and hdr(m, "To") == "<sip:caller@x>;tag=c1", m)
        if m:
            caller.s.sendto(make_reply(m, 200, "OK"), caller.addr)
        a.final()

        send(msg("INVITE", "sip:uacauth@127.0.0.1:6160"))
        m = a.answer("INVITE", 407, "Proxy Authentication Required", 'Proxy-Authenticate: Digest realm="gw", nonce="n1"\r\n')
        m2 = a.expect("INVITE")
        pa = hdr(m2 or b"", "Proxy-Authorization")
        h = lambda x: hashlib.md5(x.encode()).hexdigest()
        want = h(f"{h('u1:gw:pw1')}:n1:{h('INVITE:sip:uacauth@127.0.0.1:6160')}")
        check("uac_auth answers the 407 with the configured credential", f'response="{want}"' in pa and 'username="u1"' in pa, pa)
        if m2:
            a.s.sendto(make_reply(m2, 200, "OK", f"Contact: <sip:a@127.0.0.1:{A}>\r\n"), a.addr)
        check("…call goes through", first(caller.final()) == "SIP/2.0 200 OK")

        r = ask(msg("OPTIONS", "sip:uacreq@127.0.0.1:6160"))
        m = b.answer("MESSAGE")
        check("uac_req_send with $uac_req", first(r) == "SIP/2.0 200 sent" and m is not None and m.endswith(b"hello") and hdr(m, "X-Q") == "1"
              and "sip:proxy@x" in hdr(m, "From"), m)

        time.sleep(1.5)
        dump = ctl(SOCK, "uac.reg_dump")
        check("uac remote registration: 401 → SHA-256 digest (the server's first choice) → registered", regsrv.ok and isinstance(dump, list) and dump[0]["state"] == "Registered"
              and len(regsrv.got) == 2 and "<sip:acct1@127.0.0.1:6160>" in hdr(regsrv.got[0], "Contact"), (dump, len(regsrv.got)))
        r = ask(msg("INVITE", "sip:acct1@127.0.0.1:6160"))
        check("uac_reg_lookup", first(r) == "SIP/2.0 200 sip:local1@x", first(r))

        # ------------------------------------------------------------ topoh / topos
        err += stop(proxy)
        proxy = None
        for mod in ("topoh", "topos"):
            cfg2 = os.path.join(ROOT, f"target/e2e_carrier_{mod}.cfg")
            open(cfg2, "w").write(CFG_TOPO.replace("TOPO", mod))
            p2 = start(cfg2, PX2, SOCK2)
            try:
                cid = f"{mod}-{time.time_ns()}"
                inv = msg("INVITE", f"sip:x@127.0.0.1:{PX2}", callid=cid).replace(b"Max-Forwards", b"Via: SIP/2.0/UDP 10.9.9.9;branch=z9hG4bKupstream\r\nMax-Forwards")
                send(inv, PX2)
                m = a.expect("INVITE")
                vias = hdrs(m or b"", "Via")
                check(f"{mod}: callee sees one Via and a masked Contact", m is not None and len(vias) == 1 and b"10.9.9.9" not in m
                      and b":6100" not in m and hdr(m, "Contact").startswith(f"<sip:127.0.0.1:{PX2};line="), m)
                if mod == "topos":
                    check("topos: only a short id on the wire", re.search(r"line=[0-9a-f]{16}>", hdr(m or b"", "Contact")) is not None, hdr(m or b"", "Contact"))
                if m:
                    a.s.sendto(make_reply(m, 200, "OK", f"Contact: <sip:a@127.0.0.1:{A}>\r\n"), a.addr)
                r = caller.final()
                rv = hdrs(r or b"", "Via")
                check(f"{mod}: caller gets its Vias back, callee Contact masked", len(rv) == 2 and "10.9.9.9" in rv[1] and b"6101" not in (r or b"")
                      and hdr(r, "Contact").startswith(f"<sip:127.0.0.1:{PX2};line="), r)
                masked = hdr(r or b"", "Contact").strip("<>")
                send(msg("BYE", masked, callid=cid, to=f"<sip:x@127.0.0.1:{PX2}>;tag=uas", cseq=2), PX2)
                m = a.answer("BYE")
                check(f"{mod}: in-dialog request to the masked Contact reaches the real one", m is not None and first(m) == f"BYE sip:a@127.0.0.1:{A} SIP/2.0", m)
                caller.final()
            finally:
                err += stop(p2)
    finally:
        if proxy:
            err += stop(proxy)
        check("no panics in proxy log", "panicked" not in err, err[-2000:])
        if failures:
            print("--- proxy stderr ---\n" + err[-4000:])
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
