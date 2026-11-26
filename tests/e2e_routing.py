#!/usr/bin/env python3
"""End-to-end checks for the Phase 2 modules: rr, path, nathelper,
dispatcher, permissions, domain, alias_db, group (with db_text tables).
Run from the repo root after `cargo build --release`.
"""
import json, os, re, shutil, socket, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PX = 5960
CALLER, A, B, C, TCPP, N = 5900, 5901, 5902, 5903, 5904, 5905
D1, D2 = 5911, 5912
D5, D6, D7, D8 = 5915, 5916, 5917, 5918
PERM = os.path.join(ROOT, "target/e2e_perm")
SOCK = os.path.join(ROOT, "target/e2e_routing.sock")
DB = os.path.join(ROOT, "target/e2e_routing_db")
DSLIST = os.path.join(ROOT, "target/e2e_routing_ds.list")

CFG = r"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "rr"
loadmodule "path"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "nathelper"
loadmodule "dialog"
loadmodule "dispatcher"
loadmodule "permissions"
loadmodule "domain"
loadmodule "alias_db"
loadmodule "group"
modparam("tm", "fr_timer", 1000)
modparam("registrar", "use_path", 1)
modparam("nathelper", "natping_interval", 1)
modparam("nathelper", "ping_nated_only", 1)
modparam("nathelper", "nat_bflag", 6)
modparam("nathelper", "sipping_bflag", 7)
modparam("nathelper", "sipping_from", "sip:pinger@test")
modparam("dispatcher", "list_file", "DSLIST")
modparam("dispatcher", "ds_ping_interval", 1)
modparam("dispatcher", "ds_probing_mode", 1)
modparam("dispatcher", "setid_pvname", "$var(dsgrp)")
modparam("dispatcher", "ds_ping_latency_stats", 1)
modparam("dialog", "default_timeout", 3)
modparam("permissions", "db_url", "text://DB")
modparam("permissions", "peer_tag_avp", "$avp(tag)")
modparam("domain", "db_url", "text://DB")
modparam("domain", "register_myself", 1)
modparam("alias_db", "db_url", "text://DB")
modparam("group", "db_url", "text://DB")

request_route {
    if (loose_route()) {
        if (is_direction("downstream")) { append_hf("X-Dir: down"); } else { append_hf("X-Dir: up"); }
        if (check_route_param("foo=bar")) { append_hf("X-Param: yes"); }
        append_hf("X-Route-Uri: $route_uri");
        t_relay();
        exit;
    }
    if ($rU =~ "^(okuser|blocked|other)$") {
        if (allow_routing("PERMBASE")) { sl_send_reply(200, "allowed"); } else { sl_send_reply(403, "denied"); }
        exit;
    }
    if ($rU == "regperm") {
        if (allow_register("PERMBASE_reg")) { sl_send_reply(200, "allowed"); } else { sl_send_reply(403, "denied"); }
        exit;
    }
    switch ($rU) {
    case "dsload":
        dlg_manage();
        if (!ds_select_dst(5, 10)) { sl_send_reply(503, "no dst"); exit; }
        t_relay();
        exit;
    case "dsdone":
        if (ds_load_unset()) { sl_send_reply(200, "unset"); } else { sl_send_reply(404, "none"); }
        exit;
    case "dslat":
        if (!ds_select_dst(6, 13)) { sl_send_reply(503, "no dst"); exit; }
        t_relay();
        exit;
    case "rr":
        record_route();
        t_relay("udp:127.0.0.1:5901");
        exit;
    case "rrtcp":
        record_route();
        t_relay("tcp:127.0.0.1:5904");
        exit;
    case "preset":
        add_rr_param("foo=bar");
        record_route_preset("1.2.3.4:5080");
        t_relay("udp:127.0.0.1:5901");
        exit;
    case "edge":
        add_path_received();
        t_relay("udp:127.0.0.1:5902");
        exit;
    case "nattest":
        $var(r) = "";
        if (nat_uac_test(1)) { $var(r) = $var(r) + "1 "; }
        if (nat_uac_test(2)) { $var(r) = $var(r) + "2 "; }
        if (nat_uac_test(8)) { $var(r) = $var(r) + "8 "; }
        if (nat_uac_test(16)) { $var(r) = $var(r) + "16 "; }
        if (nat_uac_test(64)) { $var(r) = $var(r) + "64 "; }
        if (nat_uac_test(128)) { $var(r) = $var(r) + "128 "; }
        if (is_rfc1918("10.0.0.1") && !is_rfc1918("8.8.8.8")) { $var(r) = $var(r) + "rfc1918"; }
        sl_send_reply(200, "$var(r)");
        exit;
    case "natfix":
        fix_nated_contact();
        fix_nated_sdp(3);
        t_relay("udp:127.0.0.1:5901");
        exit;
    case "natalias":
        set_contact_alias();
        t_relay("udp:127.0.0.1:5901");
        exit;
    case "al":
        handle_ruri_alias();
        t_relay();
        exit;
    case "perm":
        $var(r) = "";
        if (allow_source_address()) { $var(r) = $var(r) + "src:$avp(tag) "; }
        if (!allow_source_address("2")) { $var(r) = $var(r) + "notgrp2 "; }
        if (allow_address("2", "10.1.1.1", "5060")) { $var(r) = $var(r) + "addr "; }
        $var(g) = allow_source_address_group();
        $var(r) = $var(r) + "grp=" + $var(g) + " ";
        if (allow_trusted()) { $var(r) = $var(r) + "trusted:$avp(tag)"; }
        sl_send_reply(200, "$var(r)");
        exit;
    case "dom":
        $var(r) = "";
        if (is_domain_local("Example.COM")) { $var(r) = $var(r) + "local "; }
        if (!is_from_local()) { $var(r) = $var(r) + "fromremote "; }
        if (is_uri_host_local()) { $var(r) = $var(r) + "urilocal "; }
        if (uri == myself) { $var(r) = $var(r) + "myself"; }
        sl_send_reply(200, "$var(r)");
        exit;
    case "sales":
        if (alias_db_lookup("dbaliases")) { sl_send_reply(200, "$ru"); } else { sl_send_reply(404, "no alias"); }
        exit;
    case "alice":
        if (alias_db_lookup("dbaliases", "r")) { sl_send_reply(200, "$ru"); } else { sl_send_reply(404, "no alias"); }
        exit;
    case "grp":
        $var(r) = "";
        if (is_user_in("From", "admins")) { $var(r) = $var(r) + "from "; }
        if (!is_user_in("Request-URI", "admins")) { $var(r) = $var(r) + "notruri "; }
        $var(u) = "sip:caller@x";
        if (is_user_in("$var(u)", "admins")) { $var(r) = $var(r) + "pv"; }
        sl_send_reply(200, "$var(r)");
        exit;
    case "ds":
        if (!ds_select_dst(1, 4)) { sl_send_reply(503, "no dst"); exit; }
        append_hf("X-Attrs: $xavp(_dsdst_=>attrs)");
        t_relay();
        exit;
    case "dsfo":
        t_on_failure("dsfo");
        if (!ds_select_dst(1, 8)) { sl_send_reply(503, "no dst"); exit; }
        t_relay();
        exit;
    case "dspar":
        ds_select_dst(1, 12);
        t_relay();
        exit;
    case "dsfrom":
        $var(r) = "";
        if (!ds_is_from_list()) { $var(r) = "caller-not "; }
        if (ds_is_from_list(-1, 0, "sip:127.0.0.1:5912")) { $var(r) = $var(r) + "d2=" + $var(dsgrp); }
        sl_send_reply(200, "$var(r)");
        exit;
    case "events":
        sl_send_reply(200, "down=$shv(down) up=$shv(up)");
        exit;
    }
    if (is_method("REGISTER")) {
        if (nat_uac_test(1)) { setbflag(6); setbflag(7); }
        save("location");
        exit;
    }
    if (lookup("location")) { t_relay(); exit; }
    sl_send_reply(404, "Not Found");
}

failure_route[dsfo] {
    if (t_check_status("503")) {
        ds_mark_dst("ip");
        if (ds_next_dst()) { t_relay(); }
    }
}

event_route[dispatcher:dst-down] {
    $shv(down) = $shv(down) + $ru + ";";
}

event_route[dispatcher:dst-up] {
    $shv(up) = $shv(up) + $ru + ";";
}
"""

TABLES = {
    "address": "grp(int) ip_addr(string) mask(int) port(int) tag(string,null)\n"
               "1:127.0.0.1:32:5900:caller-tag\n2:10.0.0.0:8:0:\n",
    "trusted": "src_ip(string) proto(string) from_pattern(string,null) ruri_pattern(string,null) tag(string,null) priority(int)\n"
               "127.0.0.1:udp:^sip\\:caller@::trusted-caller:0\n",
    "domain": "domain(string)\nexample.com\nlocal.test\n",
    "dbaliases": "alias_username(string) alias_domain(string) username(string) domain(string)\n"
                 "sales:example.com:alice:127.0.0.1\n",
    "grp": "username(string) domain(string) grp(string)\ncaller:x:admins\n",
}
DS = """# setid uri flags priority attrs
1 sip:127.0.0.1:5911 0 10 duid=d1;weight=50
1 sip:127.0.0.1:5912 0 5 duid=d2;weight=50
3 sip:127.0.0.1:5999 0 0 duid=dead
5 sip:127.0.0.1:5915 0 0 maxload=1
5 sip:127.0.0.1:5916 0 0 maxload=4
6 sip:127.0.0.1:5917 0 0 duid=slow
6 sip:127.0.0.1:5918 0 0 duid=fast
"""

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def first(m):
    return m.split(b"\r\n", 1)[0].decode() if m else "timeout"


def hdrs(m, name):
    out = []
    for l in m.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]:
        if l.lower().startswith(name.lower().encode() + b":"):
            out.append(l.split(b":", 1)[1].strip().decode())
    return out


def hdr(m, name):
    h = hdrs(m, name)
    return h[0] if h else ""


def make_reply(req, code, reason, extra=""):
    keep = []
    for l in req.decode().split("\r\n\r\n", 1)[0].split("\r\n")[1:]:
        name = l.split(":")[0]
        if name == "To" and code > 100 and ";tag=" not in l:
            l += ";tag=uas"
        if name in ("Via", "From", "To", "Call-ID", "CSeq", "Record-Route"):
            keep.append(l)
    return (f"SIP/2.0 {code} {reason}\r\n" + "\r\n".join(keep) + "\r\n" + extra + "Content-Length: 0\r\n\r\n").encode()


def msg(method, ruri, extra="", body="", frm="sip:caller@x", port=CALLER, to=None):
    seq[0] += 1
    ex = "".join(l + "\r\n" for l in extra.split("\n") if l) if extra else ""
    ct = "Content-Type: application/sdp\r\n" if body else ""
    return (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKr{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: <{frm}>;tag=c1\r\nTo: <{to or ruri}>\r\nCall-ID: rt-{seq[0]}\r\n"
            f"CSeq: 1 {method}\r\n{ex}{ct}Content-Length: {len(body)}\r\n\r\n{body}").encode()


class Peer:
    def __init__(self, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))

    def recv(self, timeout=2.0):
        self.s.settimeout(timeout)
        try:
            d, self.addr = self.s.recvfrom(65535)
            return d
        except socket.timeout:
            return None

    def expect(self, prefix, timeout=2.0):
        end = time.time() + timeout
        while time.time() < end:
            m = self.recv(max(0.05, end - time.time()))
            if m is None:
                return None
            if m.startswith(prefix.encode()):
                return m
        return None

    def final(self, timeout=3.0):
        """Next final reply (skips provisionals and requests)."""
        end = time.time() + timeout
        while time.time() < end:
            m = self.recv(max(0.05, end - time.time()))
            if m is None:
                return None
            if m.startswith(b"SIP/2.0 ") and not m.startswith(b"SIP/2.0 1"):
                return m
        return None

    def answer(self, prefix, code=200, reason="OK", extra=""):
        m = self.expect(prefix)
        if m:
            self.s.sendto(make_reply(m, code, reason, extra), self.addr)
        return m

    def drain(self):
        while self.recv(0.05) is not None:
            pass


class DsPeer(threading.Thread):
    """A dispatcher destination: answers OPTIONS (while alive) and INVITEs
    with `code`, recording what it got."""

    def __init__(self, port, delay=0.0):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.alive, self.code, self.got, self.pings, self.delay = True, 200, [], 0, delay
        self.start()

    def run(self):
        while True:
            try:
                d, a = self.s.recvfrom(65535)
            except OSError:
                return
            if d.startswith(b"OPTIONS"):
                self.pings += 1
                if self.alive:
                    if self.delay:
                        threading.Timer(self.delay, self.s.sendto, (make_reply(d, 200, "OK"), a)).start()
                    else:
                        self.s.sendto(make_reply(d, 200, "OK"), a)
            elif d.startswith(b"INVITE"):
                self.got.append(d)
                self.s.sendto(make_reply(d, self.code, "OK" if self.code == 200 else "Unavailable"), a)


def ctl(*args):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, *args], capture_output=True, text=True, timeout=5)
    try:
        return json.loads(out.stdout) if out.stdout.strip() else out.stderr.strip()
    except json.JSONDecodeError:
        return out.stdout


def ds_flags(lst, uri):
    for s in lst["RECORDS"]:
        for t in s["TARGETS"]:
            if t["URI"] == uri:
                return t["FLAGS"]
    return None


def main():
    shutil.rmtree(DB, ignore_errors=True)
    os.makedirs(DB)
    for t, body in TABLES.items():
        open(os.path.join(DB, t), "w").write(body)
    open(DSLIST, "w").write(DS)
    open(PERM + ".allow", "w").write('# routing\n"^sip:caller@.*" : "^sip:okuser@.*"\n')
    open(PERM + ".deny", "w").write('ALL : "^sip:okuser@.*", "^sip:blocked@.*"\n')
    open(PERM + "_reg.allow", "w").write('"^sip:regperm@.*" : "^sip:good@.*"\n')
    open(PERM + "_reg.deny", "w").write("ALL : ALL\n")
    cfg = os.path.join(ROOT, "target/e2e_routing.cfg")
    open(cfg, "w").write(CFG.replace("DSLIST", DSLIST).replace("text://DB", "text://" + DB).replace("PERMBASE", PERM))
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}", "-l", f"tcp:127.0.0.1:{PX}",
                              "-n", "2", "--rpc-socket", SOCK], stderr=subprocess.PIPE, text=True)
    caller, a, b, c, n = Peer(CALLER), Peer(A), Peer(B), Peer(C), Peer(N)
    d1, d2 = DsPeer(D1), DsPeer(D2)
    d5, d6, d7, d8 = DsPeer(D5), DsPeer(D6), DsPeer(D7, delay=0.15), DsPeer(D8)
    tcp = socket.socket()
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", TCPP))
    tcp.listen(4)
    wait_listening(proxy)
    if proxy.poll() is not None:
        print(proxy.stderr.read())
        sys.exit(1)

    def send(m, sock=caller):
        sock.s.sendto(m, ("127.0.0.1", PX))

    def ask(m):
        send(m)
        return caller.final()

    try:
        # ---------------------------------------------------------- rr
        send(msg("INVITE", "sip:rr@127.0.0.1:5960"))
        m = a.answer("INVITE")
        rr = hdrs(m or b"", "Record-Route")
        check("record_route: one entry with ;lr and ftag", rr == ["<sip:127.0.0.1:5960;lr;ftag=c1>"], rr)
        r = caller.final()
        check("…reply carries the Record-Route back", hdrs(r or b"", "Record-Route") == rr, r)

        send(msg("INVITE", "sip:rrtcp@127.0.0.1:5960"))
        tcp.settimeout(3)
        try:
            conn, _ = tcp.accept()
            conn.settimeout(3)
            data = b""
            while b"\r\n\r\n" not in data:
                data += conn.recv(65535)
            conn.sendall(make_reply(data, 200, "OK"))
        except socket.timeout:
            data = b""
        rr = hdrs(data, "Record-Route")
        check("double Record-Route when UDP → TCP (r2=on, outbound first)",
              rr == ["<sip:127.0.0.1:5960;transport=tcp;r2=on;lr;ftag=c1>", "<sip:127.0.0.1:5960;r2=on;lr;ftag=c1>"], rr)
        r = caller.final()
        check("…200 back to the UDP caller", first(r) == "SIP/2.0 200 OK", first(r))

        send(msg("INVITE", "sip:preset@127.0.0.1:5960"))
        m = a.answer("INVITE")
        rr = hdrs(m or b"", "Record-Route")
        check("record_route_preset + add_rr_param", rr == ["<sip:1.2.3.4:5080;lr;ftag=c1;foo=bar>"], rr)
        caller.final()

        # loose_route: in-dialog BYE through our own Route
        send(msg("BYE", "sip:a@127.0.0.1:5901", "Route: <sip:127.0.0.1:5960;lr;ftag=c1;foo=bar>"))
        m = a.answer("BYE")
        check("loose_route removes our Route and relays to the R-URI", m is not None and not hdrs(m, "Route"), m)
        check("…is_direction(downstream), check_route_param, $route_uri",
              m and hdr(m, "X-Dir") == "down" and hdr(m, "X-Param") == "yes" and hdr(m, "X-Route-Uri") == "sip:127.0.0.1:5960;lr;ftag=c1;foo=bar", m)
        caller.final()
        # upstream: From tag differs from ftag
        m = msg("BYE", "sip:a@127.0.0.1:5901", "Route: <sip:127.0.0.1:5960;lr;ftag=other>")
        send(m)
        m = a.answer("BYE")
        check("is_direction(upstream) when From tag != ftag", m and hdr(m, "X-Dir") == "up", m)
        caller.final()

        # double route: both of ours consumed, next hop is the next Route
        send(msg("BYE", "sip:a@127.0.0.1:5901",
                 "Route: <sip:127.0.0.1:5960;r2=on;lr>,<sip:127.0.0.1:5960;transport=tcp;r2=on;lr>\nRoute: <sip:127.0.0.1:5902;lr>"))
        m = b.answer("BYE")
        check("loose_route: r2 pair consumed, next Route is the next hop", m is not None and hdrs(m, "Route") == ["<sip:127.0.0.1:5902;lr>"]
              and first(m).startswith("BYE sip:a@127.0.0.1:5901"), m)
        caller.final()

        # pre-loaded Route to someone else
        send(msg("MESSAGE", "sip:x@198.51.100.1", "Route: <sip:127.0.0.1:5903;lr>"))
        m = c.answer("MESSAGE")
        check("loose_route: foreign top Route → sent there, Route kept", m is not None and hdrs(m, "Route") == ["<sip:127.0.0.1:5903;lr>"], m)
        caller.final()

        # ---------------------------------------------------------- path
        send(msg("REGISTER", "sip:edge@127.0.0.1:5960", "Contact: <sip:edge@198.51.100.7:5060>", port=N, frm="sip:edge@x", to="sip:edge@x"), n)
        m = b.answer("REGISTER")
        path = hdr(m or b"", "Path")
        check("add_path_received(): Path with escaped received", path == "<sip:127.0.0.1:5960;lr;received=sip:127.0.0.1:5905>", path)
        n.final()
        send(msg("INVITE", "sip:edge@198.51.100.7:5060", f"Route: {path}"))
        m = n.expect("INVITE")
        check("loose_route on a Path with ;received → sent to the NATed client", m is not None and first(m).startswith("INVITE sip:edge@198.51.100.7"), m)
        if m:
            n.s.sendto(make_reply(m, 200, "OK"), n.addr)
        caller.final()

        r = ask(msg("REGISTER", "sip:127.0.0.1:5960", "Contact: <sip:pathuser@203.0.113.9:5070>\nPath: <sip:127.0.0.1:5903;lr>\nSupported: path",
                    frm="sip:pathuser@x", to="sip:pathuser@x"))
        check("registrar use_path: 200 echoes Path", first(r) == "SIP/2.0 200 OK" and hdr(r, "Path") == "<sip:127.0.0.1:5903;lr>", r)
        send(msg("INVITE", "sip:pathuser@127.0.0.1:5960"))
        m = c.answer("INVITE")
        check("lookup with Path: sent to the edge with Route set, R-URI = contact",
              m is not None and first(m).startswith("INVITE sip:pathuser@203.0.113.9:5070") and hdrs(m, "Route") == ["<sip:127.0.0.1:5903;lr>"], m)
        caller.final()

        # ---------------------------------------------------------- nathelper
        sdp = "v=0\r\no=- 1 1 IN IP4 192.168.1.50\r\ns=-\r\nc=IN IP4 192.168.1.50\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n"
        r = ask(msg("OPTIONS", "sip:nattest@127.0.0.1:5960", "Contact: <sip:x@192.168.1.50:5062>", body=sdp))
        check("nat_uac_test 1/2/8/16/64/128 + is_rfc1918", first(r) == "SIP/2.0 200 1 8 128 rfc1918", first(r))
        send(msg("INVITE", "sip:natfix@127.0.0.1:5960", "Contact: \"X\" <sip:x@192.168.1.50:5062;transport=udp>", body=sdp))
        m = a.answer("INVITE")
        body = m.split(b"\r\n\r\n", 1)[1].decode() if m else ""
        check("fix_nated_contact → source address", hdr(m or b"", "Contact") == "\"X\" <sip:x@127.0.0.1:5900;transport=udp>", hdr(m or b"", "Contact"))
        check("fix_nated_sdp(3): c= rewritten + a=direction:active", "c=IN IP4 127.0.0.1\r\na=direction:active\r\n" in body
              and hdr(m, "Content-Length") == str(len(body)), body)
        caller.final()
        send(msg("INVITE", "sip:natalias@127.0.0.1:5960", "Contact: <sip:x@192.168.1.50:5062>"))
        m = a.answer("INVITE")
        check("set_contact_alias", hdr(m or b"", "Contact") == "<sip:x@192.168.1.50:5062;alias=127.0.0.1~5900~1>", hdr(m or b"", "Contact"))
        caller.final()
        send(msg("MESSAGE", "sip:al@192.168.1.50:5062;alias=127.0.0.1~5901~1"))
        m = a.answer("MESSAGE")
        check("handle_ruri_alias → $du from alias, alias removed", m is not None and first(m) == "MESSAGE sip:al@192.168.1.50:5062 SIP/2.0", first(m or b""))
        caller.final()

        # NAT keep-alive: a NATed REGISTER gets nat+sipping bflags → OPTIONS pings
        send(msg("REGISTER", "sip:127.0.0.1:5960", "Contact: <sip:natuser@192.168.1.50:5062>", frm="sip:natuser@x", to="sip:natuser@x", port=N), n)
        n.final()
        ul = ctl("ul.lookup", "location", "natuser")
        check("registrar stores branch flags (cflags=192)", isinstance(ul, list) and ul[0].get("cflags") == 192, ul)
        p = n.expect("OPTIONS", timeout=3)
        check("nathelper pings the NATed contact (SIP OPTIONS from sipping_from)", p is not None and "sip:pinger@test" in hdr(p, "From"), p)
        if p:
            n.s.sendto(make_reply(p, 200, "OK"), n.addr)
        n.drain()

        # ---------------------------------------------------------- permissions/domain/alias/group
        r = ask(msg("OPTIONS", "sip:perm@127.0.0.1:5960"))
        check("permissions: address + groups + trusted with peer tag", first(r) == "SIP/2.0 200 src:caller-tag notgrp2 addr grp=1 trusted:trusted-caller", first(r))
        dump = ctl("permissions.addressDump")
        check("permissions.addressDump", isinstance(dump, list) and len(dump) == 2, dump)
        open(os.path.join(DB, "address"), "a").write("3:192.0.2.0:24:0:new\n")
        check("permissions.addressReload picks up new rows", ctl("permissions.addressReload") == 3)

        r = ask(msg("OPTIONS", "sip:dom@local.test"))
        check("domain: is_domain_local / is_from_local / is_uri_host_local / myself", first(r) == "SIP/2.0 200 local fromremote urilocal myself", first(r))
        check("domain.dump", ctl("domain.dump") == ["example.com", "local.test"])
        r = ask(msg("OPTIONS", "sip:sales@example.com"))
        check("alias_db_lookup", first(r) == "SIP/2.0 200 sip:alice@127.0.0.1", first(r))
        r = ask(msg("OPTIONS", "sip:alice@127.0.0.1"))
        check("alias_db_lookup reverse (r)", first(r) == "SIP/2.0 200 sip:sales@example.com", first(r))
        r = ask(msg("OPTIONS", "sip:grp@127.0.0.1:5960"))
        check("group: is_user_in From / R-URI / variable", first(r) == "SIP/2.0 200 from notruri pv", first(r))

        # ---------------------------------------------------------- dispatcher
        got = []
        for _i in range(4):
            r = ask(msg("INVITE", "sip:ds@127.0.0.1:5960"))
            got.append(first(r))
        check("ds_select_dst round-robin answered", got == ["SIP/2.0 200 OK"] * 4, got)
        check("…spread over both destinations", len(d1.got) == 2 and len(d2.got) == 2, (len(d1.got), len(d2.got)))
        check("…$xavp(_dsdst_=>attrs)", hdr(d1.got[0], "X-Attrs").startswith("duid=d"), hdr(d1.got[0], "X-Attrs"))

        d1.code = 503
        before = (len(d1.got), len(d2.got))
        r = ask(msg("INVITE", "sip:dsfo@127.0.0.1:5960"))
        check("failover: 503 from first → ds_next_dst in failure_route → 200", first(r) == "SIP/2.0 200 OK"
              and (len(d1.got), len(d2.got)) == (before[0] + 1, before[1] + 1), (first(r), len(d1.got), len(d2.got)))
        lst = ctl("dispatcher.list")
        check("ds_mark_dst(\"ip\") → destination inactive+probing", ds_flags(lst, "sip:127.0.0.1:5911") == "IP", lst)
        d1.code = 200
        time.sleep(2.5)
        lst = ctl("dispatcher.list")
        check("probing brings it back (OPTIONS 200)", ds_flags(lst, "sip:127.0.0.1:5911") == "AP", lst)
        check("…and the dead one goes down", ds_flags(lst, "sip:127.0.0.1:5999") == "IP", lst)
        r = ask(msg("OPTIONS", "sip:events@127.0.0.1:5960"))
        r = first(r)
        check("event_route[dispatcher:dst-down/up] with $ru", "sip:127.0.0.1:5999;" in r and "down=" in r
              and r.endswith("up=sip:127.0.0.1:5911;") and "sip:127.0.0.1:5911;" in r.split("up=")[0], r)

        check("dispatcher.set_state", ctl("dispatcher.set_state", "i", "1", "sip:127.0.0.1:5912") == 1)
        d1.got.clear(), d2.got.clear()
        for _i in range(2):
            ask(msg("INVITE", "sip:ds@127.0.0.1:5960"))
        check("…inactive destination skipped", (len(d1.got), len(d2.got)) == (2, 0), (len(d1.got), len(d2.got)))
        ctl("dispatcher.set_state", "a", "1", "sip:127.0.0.1:5912")

        d1.got.clear(), d2.got.clear()
        send(msg("INVITE", "sip:dspar@127.0.0.1:5960"))
        caller.final()
        time.sleep(0.3)
        check("alg 12: parallel forking to the whole set", (len(d1.got), len(d2.got)) == (1, 1), (len(d1.got), len(d2.got)))
        caller.drain()

        r = ask(msg("OPTIONS", "sip:dsfrom@127.0.0.1:5960"))
        check("ds_is_from_list (+ setid_pvname)", first(r) == "SIP/2.0 200 caller-not d2=1", first(r))
        # alg 10: least load relative to maxload; the dialog ends the load.
        cids = []
        for _i in range(4):
            m = msg("INVITE", "sip:dsload@127.0.0.1:5960")
            cids.append(re.search(rb"Call-ID: (\S+)", m).group(1).decode())
            r = ask(m)
        loads = {d["URI"]: d["LOAD"] for s in ctl("dispatcher.list")["RECORDS"] if s["ID"] == 5 for d in s["TARGETS"]}
        check("alg 10: calls go to the least loaded (load/maxload), counted per destination",
              (len(d5.got), len(d6.got)) == (1, 3) and loads == {"sip:127.0.0.1:5915": 1, "sip:127.0.0.1:5916": 3}, ((len(d5.got), len(d6.got)), loads))
        m = re.sub(rb"Call-ID: \S+", f"Call-ID: {cids[1]}".encode(), msg("OPTIONS", "sip:dsdone@127.0.0.1:5960"))
        r = ask(m)
        total = lambda: sum(d["LOAD"] for s in ctl("dispatcher.list")["RECORDS"] if s["ID"] == 5 for d in s["TARGETS"])
        check("ds_load_unset() releases the call's load", first(r) == "SIP/2.0 200 unset" and total() == 3, (first(r), total()))
        end = time.time() + 6
        while time.time() < end and total() != 0:
            time.sleep(0.2)
        check("…and the dialog ending (timeout) releases the rest", total() == 0, total())
        caller.drain()

        # alg 13: lowest probe latency.
        lat = {d["URI"]: d.get("LATENCY", {}) for s in ctl("dispatcher.list")["RECORDS"] if s["ID"] == 6 for d in s["TARGETS"]}
        send(msg("INVITE", "sip:dslat@127.0.0.1:5960"))
        caller.final()
        check("alg 13: the destination with the lowest estimated latency", len(d8.got) == 1 and len(d7.got) == 0
              and lat["sip:127.0.0.1:5917"].get("EST", 0) > 100 > lat["sip:127.0.0.1:5918"].get("EST", 999), (len(d7.got), len(d8.got), lat))

        # permissions allow/deny files.
        res = [first(ask(msg("OPTIONS", f"sip:{u}@127.0.0.1:5960"))) for u in ("okuser", "blocked", "other")]
        check("allow_routing: allow file, then deny file, else allowed", res == ["SIP/2.0 200 allowed", "SIP/2.0 403 denied", "SIP/2.0 200 allowed"], res)
        good = first(ask(msg("OPTIONS", "sip:regperm@127.0.0.1:5960", "Contact: <sip:good@10.0.0.1>", to="sip:regperm@x")))
        bad = first(ask(msg("OPTIONS", "sip:regperm@127.0.0.1:5960", "Contact: <sip:good@10.0.0.1>, <sip:evil@10.0.0.2>", to="sip:regperm@x")))
        check("allow_register: every Contact must be allowed for the To user", (good, bad) == ("SIP/2.0 200 allowed", "SIP/2.0 403 denied"), (good, bad))
        open(PERM + ".allow", "a").write('ALL : "^sip:blocked@.*"\n')
        n_files = ctl("permissions.reload")
        r = first(ask(msg("OPTIONS", "sip:blocked@127.0.0.1:5960")))
        check("RPC permissions.reload re-reads the files", n_files == 2 and r == "SIP/2.0 200 allowed", (n_files, r))

        open(DSLIST, "a").write("4 sip:127.0.0.1:5913 0 0\n")
        check("dispatcher.reload", ctl("dispatcher.reload") == 8)
        check("…keeps states of known destinations", ds_flags(ctl("dispatcher.list"), "sip:127.0.0.1:5999") == "IP")
    finally:
        proxy.terminate()
        try:
            _, err = proxy.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, err = proxy.communicate()
        check("no panics in proxy log", "panicked" not in err, err[-2000:])
        if failures:
            print("--- proxy stderr ---\n" + err[-4000:])
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
