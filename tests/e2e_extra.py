#!/usr/bin/env python3
"""End-to-end checks for the Phase 6 modules: siptrace (fake HEP
collector), cnxcc, tmx, uac_redirect, avpops, sqlops, mtree, prefix_route,
speeddial, enum (fake DNS), outbound + GRUU, auth_ephemeral, tsilo, rtimer,
xhttp + xhttp_prom, ndb_redis (fake Redis), app_lua.
Run from the repo root after `cargo build --release`.
"""
import base64, hashlib, hmac, json, os, re, shutil, socket, sqlite3, struct, subprocess, sys, threading, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402
from e2e_routing import Peer, make_reply, hdr, hdrs, first  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PX = 6460
CALLER, A, B, U, C = 6400, 6401, 6402, 6403, 6404
HEP, DNS, REDIS, HTTP = 6490, 6453, 6479, 6481
SOCK = os.path.join(ROOT, "target/e2e_extra.sock")
DB = os.path.join(ROOT, "target/e2e_extra_db")

CFG = r"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "siputils"
loadmodule "rr"
loadmodule "path"
loadmodule "outbound"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "dialog"
loadmodule "auth"
loadmodule "auth_ephemeral"
loadmodule "siptrace"
loadmodule "cnxcc"
loadmodule "tmx"
loadmodule "uac_redirect"
loadmodule "avpops"
loadmodule "sqlops"
loadmodule "mtree"
loadmodule "prefix_route"
loadmodule "speeddial"
loadmodule "enum"
loadmodule "tsilo"
loadmodule "rtimer"
loadmodule "xhttp"
loadmodule "xhttp_prom"
loadmodule "ndb_redis"
loadmodule "app_lua"
modparam("tm", "fr_timer", 1500)
modparam("registrar", "outbound_mode", 1)
modparam("outbound", "flow_token_secret", "flow-secret")
modparam("auth_ephemeral", "secret", "s3cret")
modparam("siptrace", "duplicate_uri", "sip:127.0.0.1:6490")
modparam("siptrace", "hep_capture_id", 7)
modparam("avpops", "db_url", "text://DB")
modparam("sqlops", "sqlcon", "db=>sqlite://DB/data.sqlite")
modparam("mtree", "db_url", "text://DB")
modparam("mtree", "mtree", "name=gw;dbtable=mtree")
modparam("prefix_route", "db_url", "text://DB")
modparam("speeddial", "db_url", "text://DB")
modparam("enum", "nameserver", "127.0.0.1:6453")
modparam("rtimer", "timer", "name=t1;interval=1")
modparam("rtimer", "exec", "timer=t1;route=TICK")
modparam("xhttp", "listen", "127.0.0.1:6481")
modparam("ndb_redis", "server", "name=r1;addr=127.0.0.1;port=6479")
modparam("app_lua", "load", "DB/script.lua")

request_route {
    if (is_method("REGISTER")) {
        if ($tU == "eph") {
            if (!autheph_check("x")) { auth_challenge("x", "0"); exit; }
            sl_send_reply(200, "eph ok");
            exit;
        }
        if ($tU == "edge") { add_path(); t_relay("udp:127.0.0.1:6402"); exit; }
        save("location");
        ts_append("location", "sip:$tU@$td");
        exit;
    }
    if (has_totag()) { loose_route(); t_relay(); exit; }
    if (loose_route()) { t_relay(); exit; }
    if ($rU =~ "^1[0-9]$") {
        if (sd_lookup("speed_dial")) { sl_send_reply(200, "$ru"); } else { sl_send_reply(404, "no speed dial"); }
        exit;
    }
    if ($rU =~ "^\+") {
        if (enum_query()) { sl_send_reply(200, "$ru"); } else { sl_send_reply(404, "no enum"); }
        exit;
    }
    switch ($rU) {
    case "trace":
        sip_trace("", "", "t");
        t_relay("udp:127.0.0.1:6401");
        exit;
    case "cnx":
        dlg_manage();
        if (!cnxcc_set_max_time("cust1", "2")) { sl_send_reply(402, "No credit"); exit; }
        t_relay("udp:127.0.0.1:6401");
        exit;
    case "redir":
        t_on_failure("redir");
        t_relay("udp:127.0.0.1:6401");
        exit;
    case "tmx":
        t_on_failure("tmx");
        t_relay("udp:127.0.0.1:6401");
        exit;
    case "avp":
        avp_db_load("$fu", "*");
        $avp(color) = "blue";
        avp_db_store("$fu", "$avp(color)");
        if (avp_check("$avp(limit)", "gt/3")) { $var(c) = "limit>3"; }
        sl_send_reply(200, "$avp(lang) $avp(limit) $var(c)");
        exit;
    case "sql":
        sql_query("db", "select name from numbers where num='$hdr(X-Num)'", "r");
        sql_pvquery("db", "select num, name from numbers where num='$hdr(X-Num)'", "$var(n),$var(m)");
        sl_send_reply(200, "$dbr(r=>rows) $dbr(r=>[0,0]) $var(n)/$var(m)");
        exit;
    case "mt":
        if (mt_match("gw", "$hdr(X-Num)", "0")) { sl_send_reply(200, "$avp(tvalue)"); } else { sl_send_reply(404, "no prefix"); }
        exit;
    case "pr":
        prefix_route("$hdr(X-Num)");
        sl_send_reply(404, "no prefix route");
        exit;
    case "redis":
        redis_cmd("r1", "SET k %s", "$hdr(X-V)", "a");
        redis_cmd("r1", "GET k", "b");
        sl_send_reply(200, "$redis(a=>value) $redis(b=>value) $redis(b=>type)");
        exit;
    case "lua":
        lua_run("route_lua", "$fU");
        sl_send_reply(500, "lua did not exit");
        exit;
    case "luapv":
        lua_runstring("KSR.pv.sets('\$var(x)', 'from-lua')");
        sl_send_reply(200, "$var(x)");
        exit;
    case "ticks":
        sl_send_reply(200, "ticks=$shv(ticks)");
        exit;
    case "late":
        t_relay("udp:127.0.0.1:6401");
        ts_store();
        exit;
    }
    if (lookup("location")) { t_relay(); exit; }
    sl_send_reply(404, "Not Found");
}

route[TICK] {
    $shv(ticks) = $shv(ticks) + 1;
}
route[PR_DE] {
    sl_send_reply(200, "pr de");
    exit;
}
route[PR_US] {
    sl_send_reply(200, "pr us");
    exit;
}

failure_route[redir] {
    if (get_redirects("3")) { t_relay(); }
}

failure_route[tmx] {
    if (t_is_failure_route() && !t_is_branch_route()) {
        t_reply(500, "$T_rpl($rs)-$T_rpl($hdr(X-Why))");
    }
}

event_route[xhttp:request] {
    xhttp_reply("200", "OK", "text/plain", "url=$hu method=$hm x=$hdr(X-Test) body=$rb");
}
"""

LUA = r"""
function route_lua(user)
  if KSR.pv.get("$rm") == "OPTIONS" then
    KSR.sl.sl_send_reply(200, "lua " .. user .. " " .. KSR.pv.get("$rU"))
    KSR.x.exit()
  end
  return 1
end
"""

TABLES = {
    "usr_preferences": "uuid(string) username(string) domain(string) attribute(string) type(int) value(string)\n:caller:x:lang:0:de\n:caller:x:limit:1:5\n",
    "mtree": "tprefix(string) tvalue(string)\n49:gw-de\n4930:gw-berlin\n1:gw-us\n",
    "prefix_route": "prefix(string) route(string) comment(string,null)\n49:PR_DE:\n1:PR_US:\n",
    "speed_dial": "id(int,auto) username(string) domain(string) sd_username(string) sd_domain(string) new_uri(string)\n1:caller:x:11:x:sip\\:bob@example.com\n",
    "location": "",
}

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def msg(method, ruri, port=CALLER, extra="", frm="sip:caller@x", to=None, callid=None, cseq=1, contact=None, body=""):
    seq[0] += 1
    ex = "".join(l + "\r\n" for l in extra.split("\n") if l) if extra else ""
    ct = contact or f"<sip:u{port}@127.0.0.1:{port}>"
    return (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKe{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: <{frm}>;tag=f{port}\r\nTo: {to or '<' + ruri + '>'}\r\nCall-ID: {callid or f'ex-{seq[0]}-{time.time_ns()}'}\r\n"
            f"CSeq: {cseq} {method}\r\nContact: {ct}\r\n{ex}Content-Length: {len(body)}\r\n\r\n{body}").encode()


class Hep(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", HEP))
        self.pkts = []
        self.start()

    def run(self):
        while True:
            d, _ = self.s.recvfrom(65535)
            if d[:4] != b"HEP3":
                continue
            chunks, i = {}, 6
            while i + 6 <= len(d):
                _, t, ln = struct.unpack("!HHH", d[i:i + 6])
                chunks[t] = d[i + 6:i + ln]
                i += ln
            self.pkts.append(chunks)


class FakeDns(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", DNS))
        self.start()

    def run(self):
        while True:
            q, a = self.s.recvfrom(512)
            qid = q[:2]
            i, labels = 12, []
            while q[i]:
                labels.append(q[i + 1:i + 1 + q[i]].decode())
                i += 1 + q[i]
            question = q[12:i + 5]
            name = ".".join(labels)
            if name == "3.2.1.0.3.9.4.e164.arpa":
                cs = lambda s: bytes([len(s)]) + s
                rd = struct.pack("!HH", 10, 100) + cs(b"u") + cs(b"E2U+sip") + cs(b"!^\\+49(.*)$!sip:\\1@enum.example!") + b"\x00"
                ans = b"\xc0\x0c" + struct.pack("!HHIH", 35, 1, 60, len(rd)) + rd
                self.s.sendto(qid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + ans, a)
            else:
                self.s.sendto(qid + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + question, a)


class FakeRedis(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.l = socket.socket()
        self.l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l.bind(("127.0.0.1", REDIS))
        self.l.listen(4)
        self.kv = {}
        self.start()

    def run(self):
        while True:
            c, _ = self.l.accept()
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        f = c.makefile("rb")
        while True:
            line = f.readline()
            if not line:
                return
            n = int(line[1:])
            args = []
            for _ in range(n):
                ln = int(f.readline()[1:])
                args.append(f.read(ln + 2)[:-2])
            cmd = args[0].upper()
            if cmd == b"SET":
                self.kv[args[1]] = args[2]
                c.sendall(b"+OK\r\n")
            elif cmd == b"GET":
                v = self.kv.get(args[1])
                c.sendall(b"$-1\r\n" if v is None else b"$%d\r\n%s\r\n" % (len(v), v))
            else:
                c.sendall(b"-ERR unknown\r\n")


def ctl(*args):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, *args], capture_output=True, text=True, timeout=5)
    try:
        return json.loads(out.stdout) if out.stdout.strip() else out.stderr.strip()
    except json.JSONDecodeError:
        return out.stdout


def http(path, data=None, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{HTTP}{path}", data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=3) as r:
        return r.status, r.read().decode()


def main():
    shutil.rmtree(DB, ignore_errors=True)
    os.makedirs(DB)
    for t, body in TABLES.items():
        open(os.path.join(DB, t), "w").write(body)
    open(os.path.join(DB, "location"), "w").write(
        "username(string) domain(string,null) contact(string) received(string) path(string,null) expires(int) q(double,null) "
        "callid(string) cseq(int) cflags(int) user_agent(string) instance(string,null) reg_id(int,null) last_modified(int)\n")
    open(os.path.join(DB, "script.lua"), "w").write(LUA)
    con = sqlite3.connect(os.path.join(DB, "data.sqlite"))
    con.execute("create table numbers(num text, name text)")
    con.execute("insert into numbers values ('100', 'alice')")
    con.commit()
    con.close()
    cfg = os.path.join(ROOT, "target/e2e_extra.cfg")
    open(cfg, "w").write(CFG.replace("text://DB", "text://" + DB).replace("sqlite://DB", "sqlite://" + DB).replace('"DB/', '"' + DB + "/"))
    hep, _dns, _redis = Hep(), FakeDns(), FakeRedis()
    env = dict(os.environ, NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
    os.environ.update(NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}", "-n", "2", "--rpc-socket", SOCK],
                             stderr=subprocess.PIPE, text=True, env=env)
    wait_listening(proxy)
    if proxy.poll() is not None:
        print(proxy.stderr.read())
        sys.exit(1)
    caller, a, b, u, c = Peer(CALLER), Peer(A), Peer(B), Peer(U), Peer(C)

    def send(m, p=None):
        (p or caller).s.sendto(m, ("127.0.0.1", PX))

    def ask(m, p=None):
        send(m, p)
        return first((p or caller).final())

    try:
        # ------------------------------------------------------------ rtimer
        time.sleep(1.6)
        r = ask(msg("OPTIONS", f"sip:ticks@127.0.0.1:{PX}"))
        n = int(r.split("=")[-1]) if "=" in r else 0
        check("rtimer runs route[TICK] every second", n >= 1, r)

        # ------------------------------------------------------------ siptrace
        cid = f"trace-{time.time_ns()}"
        send(msg("INVITE", f"sip:trace@127.0.0.1:{PX}", callid=cid))
        a.answer("INVITE", 200, "OK", f"Contact: <sip:a@127.0.0.1:{A}>\r\n")
        caller.final()
        time.sleep(0.3)
        mine = [p for p in hep.pkts if p.get(17) == cid.encode()]
        firsts = [p.get(15, b"").split(b"\r\n", 1)[0] for p in mine]
        check("siptrace (t): HEP3 copies of the INVITE in and out and of the 200 in and out",
              len(mine) >= 4 and sum(f.startswith(b"INVITE") for f in firsts) >= 2 and sum(f.startswith(b"SIP/2.0 200") for f in firsts) >= 2
              and all(struct.unpack("!I", p[12])[0] == 7 and p[11] == b"\x01" for p in mine), firsts)

        # ------------------------------------------------------------ cnxcc
        cid = f"cnx-{time.time_ns()}"
        send(msg("INVITE", f"sip:cnx@127.0.0.1:{PX}", callid=cid))
        a.answer("INVITE", 200, "OK", f"Contact: <sip:a@127.0.0.1:{A}>\r\n")
        r = caller.final()
        info = ctl("cnxcc.check_client", "cust1")
        check("cnxcc: call admitted and tracked", first(r) == "SIP/2.0 200 OK" and isinstance(info, dict) and info["type"] == "time", info)
        bye_a = a.expect("BYE", 4)
        bye_c = caller.expect("BYE", 1)
        check("cnxcc: max time reached → BYE to both sides", bye_a is not None and bye_c is not None and hdr(bye_a, "Call-ID") == cid, (bye_a, bye_c))
        for p, m in ((a, bye_a), (caller, bye_c)):
            if m:
                p.s.sendto(make_reply(m, 200, "OK"), p.addr)

        # ------------------------------------------------------------ uac_redirect
        send(msg("INVITE", f"sip:redir@127.0.0.1:{PX}"))
        a.answer("INVITE", 302, "Moved", f"Contact: <sip:b@127.0.0.1:{B}>;q=0.5, <sip:u@127.0.0.1:{U}>;q=0.9\r\n")
        mu, mb = u.expect("INVITE"), b.expect("INVITE")
        check("get_redirects: the 302's contacts become branches", mu is not None and mb is not None and first(mu).startswith(f"INVITE sip:u@127.0.0.1:{U}"), (mu, mb))
        if mu:
            u.s.sendto(make_reply(mu, 486, "Busy"), u.addr)
        if mb:
            b.s.sendto(make_reply(mb, 200, "OK", f"Contact: <sip:b@127.0.0.1:{B}>\r\n"), b.addr)
        check("…call answered by a redirect target", first(caller.final()) == "SIP/2.0 200 OK")

        # ------------------------------------------------------------ tmx
        send(msg("INVITE", f"sip:tmx@127.0.0.1:{PX}"))
        a.answer("INVITE", 503, "Unavailable", "X-Why: busy\r\n")
        r = first(caller.final())
        check("tmx: t_is_failure_route + $T_rpl($rs) / $T_rpl($hdr(X-Why))", r == "SIP/2.0 500 503-busy", r)

        # ------------------------------------------------------------ avpops / sqlops / mtree / prefix_route / speeddial / enum
        r = ask(msg("OPTIONS", f"sip:avp@127.0.0.1:{PX}"))
        check("avpops: avp_db_load + avp_check", r == "SIP/2.0 200 de 5 limit>3", r)
        check("avpops: avp_db_store wrote the row", ":caller:x:color:0:blue" in open(os.path.join(DB, "usr_preferences")).read())
        r = ask(msg("OPTIONS", f"sip:sql@127.0.0.1:{PX}", extra="X-Num: 100"))
        check("sqlops: sql_query + $dbr + sql_pvquery (SQLite)", r == "SIP/2.0 200 1 alice 100/alice", r)
        r = ask(msg("OPTIONS", f"sip:mt@127.0.0.1:{PX}", extra="X-Num: 4930123"))
        check("mtree: longest prefix", r == "SIP/2.0 200 gw-berlin", r)
        r = ask(msg("OPTIONS", f"sip:pr@127.0.0.1:{PX}", extra="X-Num: 4930123"))
        r2 = ask(msg("OPTIONS", f"sip:pr@127.0.0.1:{PX}", extra="X-Num: 1555"))
        check("prefix_route runs the route of the longest prefix", r == "SIP/2.0 200 pr de" and r2 == "SIP/2.0 200 pr us", (r, r2))
        r = ask(msg("OPTIONS", f"sip:11@127.0.0.1:{PX}"))
        check("speeddial: sd_lookup", r == "SIP/2.0 200 sip:bob@example.com", r)
        r = ask(msg("OPTIONS", f"sip:+4930123@127.0.0.1:{PX};user=phone"))
        check("enum: NAPTR lookup and regexp rewrite", r == "SIP/2.0 200 sip:30123@enum.example", r)
        r = ask(msg("OPTIONS", f"sip:+4400@127.0.0.1:{PX}"))
        check("enum: no record → -1", r == "SIP/2.0 404 no enum", r)

        # ------------------------------------------------------------ ndb_redis / app_lua
        r = ask(msg("OPTIONS", f"sip:redis@127.0.0.1:{PX}", extra="X-V: hello world"))
        check("ndb_redis: SET with %s (spaces kept) and GET", r == "SIP/2.0 200 OK hello world 1", r)
        r = ask(msg("OPTIONS", f"sip:lua@127.0.0.1:{PX}"))
        check("app_lua: lua_run + KSR.pv.get + KSR.sl.sl_send_reply + KSR.x.exit", r == "SIP/2.0 200 lua caller lua", r)
        r = ask(msg("OPTIONS", f"sip:luapv@127.0.0.1:{PX}"))
        check("app_lua: lua_runstring + KSR.pv.sets", r == "SIP/2.0 200 from-lua", r)

        # ------------------------------------------------------------ xhttp / prom / RPC over HTTP
        st, body = http("/hello?a=1", data=b"payload", headers={"X-Test": "yes"})
        check("xhttp: event_route[xhttp:request] with $hu/$hm/$hdr/$rb", st == 200 and body == "url=/hello?a=1 method=POST x=yes body=payload", body)
        st, body = http("/metrics")
        check("xhttp_prom: Prometheus metrics", st == 200 and re.search(r"^kamailio_core_rcv_requests \d+$", body, re.M) is not None
              and "kamailio_tm_" in body, body[:300])
        check("xhttp_prom: counters typed counter, computed values gauge",
              "# TYPE kamailio_core_rcv_requests counter" in body and "# TYPE kamailio_tm_current gauge" in body, body[:300])
        st, body = http("/RPC", data=json.dumps({"jsonrpc": "2.0", "method": "core.version", "id": 1}).encode())
        check("JSON-RPC over HTTP (/RPC)", st == 200 and json.loads(body).get("result", "").startswith("ferrosip"), body)

        # ------------------------------------------------------------ auth_ephemeral
        def eph_register(username, secret="s3cret"):
            send(msg("REGISTER", f"sip:127.0.0.1:{PX}", frm="sip:eph@x", to="<sip:eph@x>", callid="eph-1"))
            r = caller.final()
            nonce = re.search(r'nonce="([^"]+)"', hdr(r or b"", "WWW-Authenticate"))
            if not nonce:
                return "no challenge"
            pw = base64.b64encode(hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()).decode()
            h = lambda x: hashlib.md5(x.encode()).hexdigest()
            uri = f"sip:127.0.0.1:{PX}"
            resp = h(f"{h(f'{username}:x:{pw}')}:{nonce.group(1)}:{h('REGISTER:' + uri)}")
            auth = f'Authorization: Digest username="{username}", realm="x", nonce="{nonce.group(1)}", uri="{uri}", response="{resp}"'
            return ask(msg("REGISTER", uri, frm="sip:eph@x", to="<sip:eph@x>", callid="eph-1", cseq=2, extra=auth))
        r = eph_register(f"{int(time.time()) + 600}:alice")
        check("auth_ephemeral: HMAC-SHA1 time-limited credentials accepted", r == "SIP/2.0 200 eph ok", r)
        r = eph_register(f"{int(time.time()) - 10}:alice")
        check("auth_ephemeral: expired username rejected", r == "SIP/2.0 401 Unauthorized", r)
        r = eph_register(f"{int(time.time()) + 600}:alice", secret="wrong")
        check("auth_ephemeral: wrong secret rejected", r == "SIP/2.0 401 Unauthorized", r)

        # ------------------------------------------------------------ outbound flow tokens + registrar outbound/GRUU
        send(msg("REGISTER", f"sip:127.0.0.1:{PX}", C, frm="sip:edge@x", to="<sip:edge@x>", contact=f"<sip:c@127.0.0.1:{C};ob>",
                 extra="Supported: outbound, path"), c)
        m = b.answer("REGISTER")
        path = hdr(m or b"", "Path")
        tok = re.match(r"<sip:([0-9a-v]+)@127\.0\.0\.1:6460;lr;ob>", path)
        check("outbound: edge Path carries a flow token and ;ob", tok is not None, path)
        c.final()
        send(msg("INVITE", "sip:c@10.10.10.10:5060", B, extra=f"Route: {path}"), b)
        m = c.expect("INVITE")
        check("loose_route on the flow token → request sent over the client's flow", m is not None and first(m).startswith("INVITE sip:c@10.10.10.10"), m)
        if m:
            c.s.sendto(make_reply(m, 200, "OK"), c.addr)
        b.final()

        reg = msg("REGISTER", f"sip:127.0.0.1:{PX}", U, frm="sip:g@127.0.0.1", to="<sip:g@127.0.0.1>", callid="gruu-1",
                  contact=f'<sip:g1@127.0.0.1:{U}>;+sip.instance="<urn:uuid:1111>";reg-id=1, <sip:g2@127.0.0.1:{C}>;+sip.instance="<urn:uuid:2222>";reg-id=1',
                  extra="Supported: gruu, outbound")
        send(reg, u)
        r = u.final()
        cts = ",".join(hdrs(r or b"", "Contact"))
        check("registrar: Require: outbound for reg-id flows", hdr(r or b"", "Require") == "outbound", r)
        pub = re.search(r'pub-gruu="([^"]+uuid:2222)"', cts)
        tmp = re.search(r'temp-gruu="([^"]+)"', cts.split("2222")[-1] if "2222" in cts else "")
        check("registrar: pub-gruu and temp-gruu per instance", pub is not None and pub.group(1) == "sip:g@127.0.0.1;gr=urn:uuid:2222" and tmp is not None, cts)
        if pub:
            send(msg("INVITE", pub.group(1)))
            m = u.expect("INVITE")
            check("lookup of a pub-gruu reaches only that instance", m is not None and first(m).startswith(f"INVITE sip:g2@127.0.0.1:{C}") and u.expect("INVITE", 0.4) is None, m)
            if m:
                u.s.sendto(make_reply(m, 200, "OK"), u.addr)
            caller.final()
        if tmp:
            send(msg("INVITE", tmp.group(1)))
            m = u.expect("INVITE")
            check("lookup of a temp-gruu", m is not None and first(m).startswith(f"INVITE sip:g2@127.0.0.1:{C}"), (tmp.group(1), m))
            if m:
                u.s.sendto(make_reply(m, 200, "OK"), u.addr)
            caller.final()

        # ------------------------------------------------------------ tsilo
        cid = f"late-{time.time_ns()}"
        send(msg("INVITE", f"sip:late@127.0.0.1:{PX}", callid=cid))
        ma = a.expect("INVITE")
        if ma:
            a.s.sendto(make_reply(ma, 180, "Ringing"), a.addr)
        r = ask(msg("REGISTER", f"sip:127.0.0.1:{PX}", U, frm="sip:late@127.0.0.1", to="<sip:late@127.0.0.1>", contact=f"<sip:late@127.0.0.1:{U}>"), u)
        mu = u.expect("INVITE")
        check("tsilo: REGISTER during the call adds a branch to the stored transaction", r == "SIP/2.0 200 OK" and mu is not None
              and first(mu).startswith(f"INVITE sip:late@127.0.0.1:{U}") and hdr(mu, "Call-ID") == cid, (r, mu))
        if mu:
            u.s.sendto(make_reply(mu, 200, "OK", f"Contact: <sip:late@127.0.0.1:{U}>\r\n"), u.addr)
        fin = caller.final()
        cancel = a.expect("CANCEL", 2)
        check("…the new branch answers, the old one is canceled", first(fin) == "SIP/2.0 200 OK" and cancel is not None, (first(fin), cancel))
        if cancel:
            a.s.sendto(make_reply(cancel, 200, "OK"), a.addr)
            a.s.sendto(make_reply(ma, 487, "Request Terminated"), a.addr)
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
