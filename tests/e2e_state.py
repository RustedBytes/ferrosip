#!/usr/bin/env python3
"""End-to-end checks for the Phase 3 modules: htable, pike, ratelimit,
pipelimit, secfilter, userblocklist, dialog, usrloc db_mode, auth_db
(db_text tables; the proxy is restarted to check persistence).
Run from the repo root after `cargo build --release`.
"""
import hashlib, json, os, re, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402
from e2e_routing import Peer, make_reply, hdr, first  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PX = 6060
CALLER, A = 6000, 6001
SOCK = os.path.join(ROOT, "target/e2e_state.sock")
DB = os.path.join(ROOT, "target/e2e_state_db")

CFG = r"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "siputils"
loadmodule "htable"
loadmodule "pike"
loadmodule "ratelimit"
loadmodule "pipelimit"
loadmodule "secfilter"
loadmodule "userblocklist"
loadmodule "dialog"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "auth"
loadmodule "auth_db"
modparam("tm", "fr_timer", 1000)
modparam("htable", "htable", "t=>size=4;autoexpire=0;")
modparam("htable", "htable", "exp=>autoexpire=2;")
modparam("htable", "htable", "db=>dbtable=htable;dbmode=1;")
modparam("htable", "db_url", "text://DB")
modparam("htable", "timer_interval", 1)
modparam("pike", "sampling_time_unit", 30)
modparam("pike", "reqs_density_per_unit", 5)
modparam("ratelimit", "pipe", "0:TAILDROP:3")
modparam("ratelimit", "queue", "0:MESSAGE")
modparam("ratelimit", "timer_interval", 60)
modparam("pipelimit", "timer_interval", 60)
modparam("secfilter", "db_url", "text://DB")
modparam("userblocklist", "db_url", "text://DB")
modparam("dialog", "profiles_with_value", "caller")
modparam("dialog", "profiles_no_value", "calls")
modparam("dialog", "db_url", "text://DB")
modparam("dialog", "db_mode", 1)
modparam("usrloc", "db_url", "text://DB")
modparam("usrloc", "db_mode", 1)
modparam("auth_db", "db_url", "text://DB")
modparam("auth_db", "calculate_ha1", 1)
modparam("auth_db", "load_credentials", "rpid")

event_route[htable:mod-init] {
    $sht(t=>init) = "yes";
}
event_route[htable:expired:exp] {
    $sht(t=>expired) = $shtrecord(key) + "=" + $shtrecord(value);
}
event_route[pike:blocked] {
    $sht(t=>pike) = $si;
}
event_route[dialog:start] {
    $sht(t=>dstart) = $dlg(callid);
}
event_route[dialog:end] {
    $sht(t=>dend) = $dlg(callid);
}
event_route[dialog:failed] {
    $sht(t=>dfail) = $dlg(callid);
}

request_route {
    if (has_totag()) {
        if (is_known_dlg()) { append_hf("X-Dlg: $dlg_var(x) $dlg(state)"); }
        t_relay();
        exit;
    }
    if (is_method("REGISTER")) {
        if (!www_authorize("x", "subscriber")) { www_challenge("x", "0"); exit; }
        append_to_reply("X-RPID: $avp(rpid)");
        save("location");
        exit;
    }
    if ($rU =~ "^900") {
        $var(r) = check_blocklist();
        sl_send_reply(200, "global $var(r)");
        exit;
    }
    switch ($rU) {
    case "ht":
        $sht(t=>k1) = "x";
        $sht(t=>$fU) = 5;
        $var(n) = $shtinc(t=>ctr);
        $var(n) = $shtinc(t=>ctr);
        sl_send_reply(200, "k1=$sht(t=>k1) user=$sht(t=>caller) ctr=$var(n) cn=$shtcn(t=>%~k) init=$sht(t=>init) db=$sht(db=>pre)");
        exit;
    case "htexp":
        $sht(exp=>x) = "e";
        sl_send_reply(200, "ex=$shtex(exp=>x)");
        exit;
    case "htrm":
        sht_rm("t", "k1");
        sht_setxs("t", "sx", "val", "0");
        $var(r) = "";
        if ($sht(t=>k1) == $null) { $var(r) = "rm "; }
        sl_send_reply(200, "$var(r)sx=$sht(t=>sx)");
        exit;
    case "htget":
        sl_send_reply(200, "expired=$sht(t=>expired) pike=$sht(t=>pike) dstart=$sht(t=>dstart) dend=$sht(t=>dend) dfail=$sht(t=>dfail)");
        exit;
    case "pike":
        if (!pike_check_req()) { sl_send_reply(403, "pike blocked"); exit; }
        sl_send_reply(200, "ok");
        exit;
    case "rl":
        if (!rl_check()) { sl_send_reply(503, "rate limited"); exit; }
        sl_send_reply(200, "ok");
        exit;
    case "pl":
        if (!pl_check("p1", "TAILDROP", "2")) { pl_drop("5"); exit; }
        sl_send_reply(200, "ok");
        exit;
    case "sec":
        $var(a) = secf_check_ua();
        $var(b) = secf_check_from_hdr();
        $var(c) = secf_check_dst("900123");
        $var(d) = secf_check_sqli_all();
        sl_send_reply(200, "$var(a) $var(b) $var(c) $var(d)");
        exit;
    case "ubl":
        $var(a) = check_user_blocklist("$fU", "$fd", "4940");
        $var(b) = check_user_blocklist("$fU", "$fd", "49301");
        $var(c) = check_user_allowlist("$fU", "$fd", "49301");
        sl_send_reply(200, "$var(a) $var(b) $var(c)");
        exit;
    case "dlg":
        dlg_manage();
        set_dlg_profile("calls");
        set_dlg_profile("caller", "$fU");
        $dlg_var(x) = "vx";
        if ($hdr(X-Timeout) != $null) {
            dlg_set_timeout("$hdr(X-Timeout)");
            dlg_set_property("timeout-bye");
        }
        t_relay("udp:127.0.0.1:6001");
        exit;
    case "dlgsl":
        dlg_manage();
        sl_send_reply(404, "Not Found");
        exit;
    case "dlgsize":
        get_profile_size("calls", "$var(n)");
        get_profile_size("caller", "caller", "$var(m)");
        sl_send_reply(200, "calls=$var(n) caller=$var(m)");
        exit;
    }
    sl_send_reply(404, "Not Found");
}
"""

TABLES = {
    "htable": "key_name(string) key_type(int) value_type(int) key_value(string) expires(int)\npre:0:0:loaded:0\n",
    "secfilter": "id(int,auto) action(int) type(int) data(string)\n1:0:0:friendly-scanner\n2:0:4:baduser\n3:1:4:caller\n4:2:0:900\n",
    "userblocklist": "id(int,auto) username(string) domain(string) prefix(string) allowlist(int)\n1:caller:x:49:0\n2:caller:x:4930:1\n",
    "globalblocklist": "id(int,auto) prefix(string) allowlist(int) description(string,null)\n1:900:0:premium\n2:9001:1:ok\n",
    "subscriber": "id(int,auto) username(string) domain(string) password(string) rpid(string,null)\n1:alice:x:secret:+4930111\n",
    "location": "username(string) domain(string,null) contact(string) received(string) path(string,null) expires(int) q(double,null) "
                "callid(string) cseq(int) cflags(int) user_agent(string) instance(string,null) reg_id(int,null) last_modified(int)\n",
    "dialog": "hash_entry(int) hash_id(int) callid(string) from_uri(string) from_tag(string) to_uri(string) to_tag(string) "
              "caller_cseq(int) callee_cseq(int) caller_route_set(string,null) callee_route_set(string,null) caller_contact(string) "
              "callee_contact(string) caller_sock(string) callee_sock(string) state(int) start_time(int) timeout(int) xdata(string,null)\n",
}

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def msg(method, ruri, extra="", frm="sip:caller@x", fdisp="", ua=None, cseq=1, callid=None, to=None, ftag="c1", contact=True):
    seq[0] += 1
    ex = "".join(l + "\r\n" for l in extra.split("\n") if l) if extra else ""
    if ua:
        ex += f"User-Agent: {ua}\r\n"
    cid = callid or f"st-{seq[0]}-{time.time_ns()}"
    # (A backslash inside a nested f-string needs Python 3.12; keep 3.10.)
    contact_line = f"Contact: <sip:caller@127.0.0.1:{CALLER}>\r\n" if contact else ""
    return (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch=z9hG4bKs{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: {fdisp}<{frm}>;tag={ftag}\r\nTo: {to or '<' + ruri + '>'}\r\nCall-ID: {cid}\r\n"
            f"CSeq: {cseq} {method}\r\n{contact_line}{ex}Content-Length: 0\r\n\r\n").encode()


def ctl(*args):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, *args], capture_output=True, text=True, timeout=5)
    try:
        return json.loads(out.stdout) if out.stdout.strip() else out.stderr.strip()
    except json.JSONDecodeError:
        return out.stdout


def start(cfg):
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}", "-n", "2", "--rpc-socket", SOCK],
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


def main():
    shutil.rmtree(DB, ignore_errors=True)
    os.makedirs(DB)
    for t, body in TABLES.items():
        open(os.path.join(DB, t), "w").write(body)
    cfg = os.path.join(ROOT, "target/e2e_state.cfg")
    open(cfg, "w").write(CFG.replace("text://DB", "text://" + DB))
    proxy = start(cfg)
    caller, a = Peer(CALLER), Peer(A)
    err = ""

    def send(m):
        caller.s.sendto(m, ("127.0.0.1", PX))

    def ask(m):
        send(m)
        return first(caller.final())

    def call(extra="", code=200):
        """INVITE dlg → A answers → returns (invite seen by A, final at caller)."""
        send(msg("INVITE", "sip:dlg@127.0.0.1:6060", extra))
        inv = a.expect("INVITE")
        if inv is None:
            return None, None
        if code == 200:
            a.s.sendto(make_reply(inv, 180, "Ringing"), a.addr)
        a.s.sendto(make_reply(inv, code, "OK" if code == 200 else "Busy Here", "Contact: <sip:a@127.0.0.1:6001>\r\n" if code == 200 else ""), a.addr)
        return inv, caller.final()

    def indlg(method, inv, cseq, from_callee=False):
        cid = hdr(inv, "Call-ID")
        if from_callee:
            return (f"{method} sip:caller@127.0.0.1:{CALLER} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{A};branch=z9hG4bKcl{time.time_ns()}\r\n"
                    f"Max-Forwards: 70\r\nFrom: <sip:dlg@127.0.0.1:6060>;tag=uas\r\nTo: <sip:caller@x>;tag=c1\r\nCall-ID: {cid}\r\n"
                    f"CSeq: {cseq} {method}\r\nContent-Length: 0\r\n\r\n").encode()
        return msg(method, "sip:a@127.0.0.1:6001", callid=cid, cseq=cseq, to="<sip:dlg@127.0.0.1:6060>;tag=uas")

    try:
        # ------------------------------------------------------------ htable
        r = ask(msg("OPTIONS", "sip:ht@127.0.0.1:6060"))
        check("htable: $sht with variable keys, $shtinc, $shtcn, mod-init event, db preload",
              r == "SIP/2.0 200 k1=x user=5 ctr=2 cn=1 init=yes db=loaded", r)
        r = ask(msg("OPTIONS", "sip:htexp@127.0.0.1:6060"))
        check("htable autoexpire → $shtex", r == "SIP/2.0 200 ex=2", r)
        r = ask(msg("OPTIONS", "sip:htrm@127.0.0.1:6060"))
        check("sht_rm / sht_setxs", r == "SIP/2.0 200 rm sx=val", r)
        dump = ctl("htable.dump", "t")
        check("htable.dump", isinstance(dump, list) and {d["name"] for d in dump} >= {"caller", "ctr", "sx", "init"}, dump)
        check("htable.sets + htable.get", ctl("htable.sets", "t", "r", "rpcval") == 0 and ctl("htable.get", "t", "r") == "rpcval")
        ctl("htable.sets", "db", "newkey", "newval")

        # ---------------------------------------------------------- pike
        got = [ask(msg("OPTIONS", "sip:pike@127.0.0.1:6060")) for _ in range(7)]
        check("pike: allowed up to the density, then blocked", got[:5] == ["SIP/2.0 200 ok"] * 5 and got[5:] == ["SIP/2.0 403 pike blocked"] * 2, got)
        check("pike.top lists the address", any(e["ip"] == "127.0.0.1" and e["blocked"] for e in ctl("pike.top")))

        # ---------------------------------------------------------- ratelimit / pipelimit
        got = [ask(msg("MESSAGE", "sip:rl@127.0.0.1:6060")) for _ in range(5)]
        check("ratelimit: MESSAGE queue → TAILDROP pipe of 3", got == ["SIP/2.0 200 ok"] * 3 + ["SIP/2.0 503 rate limited"] * 2, got)
        check("…other methods not limited", ask(msg("OPTIONS", "sip:rl@127.0.0.1:6060")) == "SIP/2.0 200 ok")
        st = ctl("rl.stats")
        check("rl.stats", isinstance(st, list) and st[0]["counter"] == 5 and st[0]["dropped"] == 2, st)
        send(msg("OPTIONS", "sip:pl@127.0.0.1:6060"))
        caller.final()
        send(msg("OPTIONS", "sip:pl@127.0.0.1:6060"))
        caller.final()
        send(msg("OPTIONS", "sip:pl@127.0.0.1:6060"))
        r = caller.final()
        check("pipelimit: dynamic pipe, pl_drop → 503 + Retry-After", first(r) == "SIP/2.0 503 Server Unavailable" and hdr(r, "Retry-After") == "5", r)
        check("pl.set_pipe raises the limit", ctl("pl.set_pipe", "p1", "TAILDROP", "100") == 0 and ask(msg("OPTIONS", "sip:pl@127.0.0.1:6060")) == "SIP/2.0 200 ok")

        # ---------------------------------------------------------- secfilter / userblocklist
        r = ask(msg("OPTIONS", "sip:sec@127.0.0.1:6060", ua="friendly-scanner 1.0"))
        check("secfilter: UA blocklisted, From user allowlisted, dst blocked, no SQLi", r == "SIP/2.0 200 -2 2 -2 1", r)
        r = ask(msg("OPTIONS", "sip:sec@127.0.0.1:6060", ua="Good", frm="sip:baduser@x", fdisp="\"x' or 1=1\" "))
        check("secfilter: user blocklisted, SQL injection found", r == "SIP/2.0 200 1 -2 -2 -1", r)
        check("secfilter.add_bl at runtime", ctl("secfilter.add_bl", "ua", "Good") == 0
              and ask(msg("OPTIONS", "sip:sec@127.0.0.1:6060", ua="Good")).startswith("SIP/2.0 200 -2"))
        r = ask(msg("OPTIONS", "sip:ubl@127.0.0.1:6060"))
        check("userblocklist: per-user longest prefix (block 49, allow 4930)", r == "SIP/2.0 200 -1 1 1", r)
        check("userblocklist: global blocklist", ask(msg("OPTIONS", "sip:9005@127.0.0.1:6060")) == "SIP/2.0 200 global -1"
              and ask(msg("OPTIONS", "sip:90011@127.0.0.1:6060")) == "SIP/2.0 200 global 1")

        # ---------------------------------------------------------- auth_db + usrloc db_mode
        reg = lambda auth="", cseq=1: msg("REGISTER", "sip:127.0.0.1:6060", "Contact: <sip:alice@127.0.0.1:6000>" + auth, frm="sip:alice@x",
                                          to="<sip:alice@x>", callid="reg-alice", cseq=cseq, contact=False)
        send(reg())
        r = caller.final()
        nonce = re.search(r'nonce="([^"]+)"', hdr(r or b"", "WWW-Authenticate"))
        check("auth_db: challenge for a db subscriber", first(r) == "SIP/2.0 401 Unauthorized" and nonce, r)
        h = lambda s: hashlib.md5(s.encode()).hexdigest()
        resp = h(f"{h('alice:x:secret')}:{nonce.group(1)}:{h('REGISTER:sip:127.0.0.1:6060')}") if nonce else ""
        auth = f'\nAuthorization: Digest username="alice", realm="x", nonce="{nonce.group(1) if nonce else ""}", uri="sip:127.0.0.1:6060", response="{resp}"'
        send(reg(auth, 2))
        r = caller.final()
        check("auth_db: password from the subscriber table (calculate_ha1)", first(r) == "SIP/2.0 200 OK", r)
        check("auth_db: load_credentials → $avp(rpid)", hdr(r or b"", "X-RPID") == "+4930111", hdr(r or b"", "X-RPID"))
        rows = open(os.path.join(DB, "location")).read().splitlines()
        check("usrloc db_mode=1: contact written to the location table", len(rows) == 2 and rows[1].startswith("alice::sip\\:alice@127.0.0.1\\:6000"), rows)

        # ---------------------------------------------------------- dialog
        inv, r = call()
        check("dialog: call set up", first(r) == "SIP/2.0 200 OK", r)
        lst = ctl("dlg.list")
        check("dlg.list: confirmed (3) with variables and profiles", isinstance(lst, list) and len(lst) == 1 and lst[0]["state"] == 3
              and lst[0]["variables"] == {"x": "vx"}, lst)
        send(indlg("ACK", inv, 1))
        ack = a.expect("ACK")
        check("in-dialog ACK matched: $dlg_var and state 4", hdr(ack or b"", "X-Dlg") == "vx 4", ack)
        check("profiles: get_profile_size", ask(msg("OPTIONS", "sip:dlgsize@127.0.0.1:6060")) == "SIP/2.0 200 calls=1 caller=1")
        check("dlg.profile_get_size", ctl("dlg.profile_get_size", "caller", "caller") == 1)
        send(indlg("BYE", inv, 2))
        bye = a.answer("BYE")
        caller.final()
        check("BYE ends the dialog", bye is not None and hdr(bye, "X-Dlg") == "vx 5" and ctl("dlg.list") == [], ctl("dlg.list"))
        check("…profiles emptied", ask(msg("OPTIONS", "sip:dlgsize@127.0.0.1:6060")) == "SIP/2.0 200 calls=0 caller=0")
        cid1 = hdr(inv, "Call-ID")

        inv2, r = call(code=486)
        check("rejected call: 486 forwarded", first(r) == "SIP/2.0 486 Busy Here", r)
        check("…dialog failed and removed", ctl("dlg.list") == [])

        # timeout with BYE to both sides
        inv3, r = call("X-Timeout: 2")
        send(indlg("ACK", inv3, 1))
        a.expect("ACK")
        b_callee = a.expect("BYE", timeout=4)
        b_caller = caller.expect("BYE", timeout=2)
        check("dlg_set_timeout + timeout-bye: BYE to the callee", b_callee is not None and first(b_callee).startswith("BYE sip:a@127.0.0.1:6001")
              and "tag=c1" in hdr(b_callee, "From") and "tag=uas" in hdr(b_callee, "To") and hdr(b_callee, "CSeq") == "2 BYE", b_callee)
        check("…and to the caller (reversed tags)", b_caller is not None and first(b_caller).startswith("BYE sip:caller@127.0.0.1:6000")
              and "tag=uas" in hdr(b_caller, "From") and "tag=c1" in hdr(b_caller, "To"), b_caller)
        for p, m in ((a, b_callee), (caller, b_caller)):
            if m:
                p.s.sendto(make_reply(m, 200, "OK"), p.addr)
        time.sleep(0.2)
        check("…dialog gone", ctl("dlg.list") == [])

        # dlg.end_dlg via RPC
        inv4, r = call()
        lst = ctl("dlg.list")
        if lst:
            ctl("dlg.end_dlg", str(lst[0]["h_entry"]), str(lst[0]["h_id"]))
        b1, b2 = a.expect("BYE"), caller.expect("BYE")
        check("dlg.end_dlg sends BYE both ways", b1 is not None and b2 is not None)
        for p, m in ((a, b1), (caller, b2)):
            if m:
                p.s.sendto(make_reply(m, 200, "OK"), p.addr)

        # exp's item (autoexpire 2s) is gone 2..3s after it was set (whole
        # seconds, as in Kamailio), then the sweep raises the event.
        for _ in range(25):
            r = ask(msg("OPTIONS", "sip:htget@127.0.0.1:6060"))
            if "expired=x=e" in (r or ""):
                break
            time.sleep(0.2)
        check("events: htable:expired, pike:blocked, dialog:start/end/failed",
              r == f"SIP/2.0 200 expired=x=e pike=127.0.0.1 dstart={hdr(inv4, 'Call-ID')} dend={hdr(inv4, 'Call-ID')} dfail={hdr(inv2, 'Call-ID')}"
              and cid1 != "", r)
        st = ctl("stats.get_statistics", "dialog:")
        check("dialog statistics", isinstance(st, dict) and st.get("dialog:processed_dialogs") == 4 and st.get("dialog:failed_dialogs") == 1
              and st.get("dialog:expired_dialogs") == 1, st)

        # dlg_manage() then a stateless rejection: no transaction reports the
        # final reply, the dialog must end anyway (not linger as early).
        r = ask(msg("INVITE", "sip:dlgsl@127.0.0.1:6060", callid="dlgsl-1"))
        st = ctl("stats.get_statistics", "dialog:")
        check("dlg_manage + sl_send_reply(404): no dialog left", r == "SIP/2.0 404 Not Found" and ctl("dlg.list") == []
              and st.get("dialog:early_dialogs") == 0 and st.get("dialog:failed_dialogs") == 2, (r, ctl("dlg.list"), st))

        # a call that stays up across a restart
        inv5, r = call()
        time.sleep(1.2)  # htable dbmode=1 write-back
        hrows = open(os.path.join(DB, "htable")).read()
        check("htable dbmode=1 writes the table back", "newkey:0:0:newval" in hrows, hrows)
        err += stop(proxy)
        proxy = start(cfg)
        lst = ctl("dlg.list")
        check("dialog db_mode=1: dialog reloaded after restart", isinstance(lst, list) and len(lst) == 1 and lst[0]["call-id"] == hdr(inv5, "Call-ID")
              and lst[0]["variables"] == {"x": "vx"}, lst)
        ul = ctl("ul.lookup", "location", "alice")
        check("usrloc db_mode=1: contact reloaded after restart", isinstance(ul, list) and ul[0]["contact"] == "sip:alice@127.0.0.1:6000", ul)
        check("htable: db table reloaded", ctl("htable.get", "db", "newkey") == "newval")
        send(indlg("BYE", inv5, 2))
        a.answer("BYE")
        caller.final()
        time.sleep(0.2)
        check("BYE after restart ends the reloaded dialog", ctl("dlg.list") == [] and open(os.path.join(DB, "dialog")).read().count("\n") == 1)
    finally:
        err += stop(proxy)
        check("no panics in proxy log", "panicked" not in err, err[-2000:])
        if failures:
            print("--- proxy stderr ---\n" + err[-4000:])
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
