#!/usr/bin/env python3
"""End-to-end checks for the Phase 1 utility modules: sl, textops,
textopsx, siputils, sanity, xlog, cfgutils, corex, kex, statistics, pv,
ipops. Run from the repo root after `cargo build --release`.
"""
import json, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402
from e2e_fork import Peer, first, hdr  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PX = 5860
SOCK = os.path.join(ROOT, "target/e2e_utils.sock")
TMPF = os.path.join(ROOT, "target/e2e_utils.txt")
CFG = r"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "textopsx"
loadmodule "siputils"
loadmodule "sanity"
loadmodule "xlog"
loadmodule "cfgutils"
loadmodule "corex"
loadmodule "kex"
loadmodule "statistics"
loadmodule "pv"
loadmodule "ipops"
modparam("cfgutils", "initial_probability", 100)
modparam("statistics", "variable", "script:hits")

request_route {
    if (!sanity_check(3047, 7)) { exit; }
    update_stat("script:hits", 1);
    xinfo("req $rm from $si to $rU");
    if ($rm == "OPTIONS" && $rU == $null) { options_reply(); exit; }
    switch ($rU) {
    case "sl":
        sl_send_reply(299, "sl ok $rm");
        exit;
    case "hf":
        if (is_present_hf("X-Foo") && !is_present_hf("X-Nope") && is_present_hf_re("^X-F")) { append_to_reply("X-Result: present"); }
        if (search("X-Foo: bar[0-9]+")) { append_to_reply("X-Search: yes"); }
        if (search_hf("X-Foo", "bar1", "f") && !search_hf("X-Foo", "bar1", "l")) { append_to_reply("X-SearchHf: yes"); }
        if (is_method("OPTIONS|INFO")) { append_to_reply("X-Method: ok"); }
        append_time();
        sl_send_reply(200, "hf");
        exit;
    case "edit":
        append_hf("X-Appended: $fU");
        insert_hf("X-First: 1");
        append_hf("X-After-CallID: y", "Call-ID");
        remove_hf("X-Remove");
        remove_hf_re("^X-Gone-");
        subst("/X-Subst: old/X-Subst: new/");
        replace("Subject: [a-z]+", "Subject: replaced");
        subst_user("/^edit$/edited/");
        t_relay("udp:127.0.0.1:5801");
        exit;
    case "body":
        if (has_body("text/plain") && search_body("hello")) {
            replace_body("hello", "bye");
            subst_body("/w(or)ld/W\1LD/");
        }
        t_relay("udp:127.0.0.1:5801");
        exit;
    case "setbody":
        set_body("new body for $rU", "application/x-test");
        t_relay("udp:127.0.0.1:5801");
        exit;
    case "rmbody":
        remove_body();
        t_relay("udp:127.0.0.1:5801");
        exit;
    case "keep":
        keep_hf("^X-Keep");
        t_relay("udp:127.0.0.1:5801");
        exit;
    case "su":
        $var(r) = "";
        if (!has_totag()) { $var(r) = $var(r) + "nototag "; }
        if (is_user("su")) { $var(r) = $var(r) + "user "; }
        if (is_e164("+4930123456") && !is_e164("123")) { $var(r) = $var(r) + "e164 "; }
        if (uri_param("transport", "tcp")) { $var(r) = $var(r) + "param "; }
        if (cmp_uri("sip:a@B.com;transport=TCP", "sip:a@b.com;transport=tcp")) { $var(r) = $var(r) + "cmpuri "; }
        if (cmp_aor("sip:a@b.com:5060", "sip:a@B.com")) { $var(r) = $var(r) + "cmpaor "; }
        if (is_supported("timer")) { $var(r) = $var(r) + "timer "; }
        tel2sip("tel:+1-555-0100;phone-context=x", "sip:gw.example", "$var(t)");
        sl_send_reply(200, "$var(r)| $var(t)");
        exit;
    case "ip":
        $var(r) = "";
        if (is_ip("10.0.0.1") && is_ipv4("10.0.0.1") && is_ipv6("::1") && !is_ip("x")) { $var(r) = $var(r) + "ip "; }
        if (is_ip_rfc1918("192.168.1.1") && !is_ip_rfc1918("8.8.8.8")) { $var(r) = $var(r) + "rfc1918 "; }
        if (ip_is_in_subnet("10.1.2.3", "192.168.0.0/16,10.0.0.0/8")) { $var(r) = $var(r) + "subnet "; }
        if (compare_ips("::1", "[::1]")) { $var(r) = $var(r) + "cmp "; }
        if (dns_query("localhost", "d")) { $var(r) = $var(r) + "dns=" + $dns(d=>addr[0]) + " "; }
        if (ip_type("[::1]") == 3) { $var(r) = $var(r) + "type3 "; }
        sl_send_reply(200, "$var(r)");
        exit;
    case "cfg":
        $var(r) = "";
        if (rand_event()) { $var(r) = "rand "; }
        set_gflag(5);
        if (is_gflag(5)) { $var(r) = $var(r) + "gflag "; }
        lock("k");
        if (!trylock("k")) { $var(r) = $var(r) + "locked "; }
        unlock("k");
        if (trylock("k")) { $var(r) = $var(r) + "relock "; unlock("k"); }
        sl_send_reply(200, "$var(r)");
        exit;
    case "corex":
        $var(r) = "";
        setxflag(2);
        if (isxflagset(2) && !isxflagset(3)) { $var(r) = "xflag "; }
        if (!is_faked_msg()) { $var(r) = $var(r) + "real "; }
        file_write("TMPF", "data-$rU");
        file_read("TMPF", "$var(f)");
        send_data("sip:127.0.0.1:5802", "RAW $rU");
        sl_send_reply(200, "$var(r)$var(f)");
        exit;
    case "kex":
        $var(r) = "";
        setsflag(1);
        if (issflagset(1)) { $var(r) = "sflag "; }
        setdsturi("sip:127.0.0.1:5802");
        if (isdsturiset()) { $var(r) = $var(r) + "dst=" + $du + " "; }
        resetdsturi();
        if (!isdsturiset()) { $var(r) = $var(r) + "reset "; }
        pv_printf("$var(p)", "pp-$rU");
        sl_send_reply(200, "$var(r)$var(p)");
        exit;
    case "pvm":
        $var(r) = "";
        $var(x) = 5;
        if (pv_isset("$var(x)") && is_int("$var(x)") && typeof("$var(x)", "int")) { $var(r) = "int "; }
        pv_unset("$var(x)");
        if (!pv_isset("$var(x)")) { $var(r) = $var(r) + "unset "; }
        $var(s) = "abc";
        if (typeof("$var(s)", "str") && not_empty("$var(s)")) { $var(r) = $var(r) + "str "; }
        xavp_params_explode("a=1;b=two", "xp");
        sl_send_reply(200, "$var(r)$xavp(xp=>b)");
        exit;
    }
    sl_send_reply(404, "nf");
}
""".replace("TMPF", TMPF)
failures = 0
n = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def msg(method, user, extra="", body="", ctype="text/plain", cseq_method=None, drop=()):
    n[0] += 1
    ruri = f"sip:{user}@127.0.0.1:{PX}" if user else f"sip:127.0.0.1:{PX}"
    h = [f"{method} {ruri} SIP/2.0", f"Via: SIP/2.0/UDP 127.0.0.1:5800;branch=z9hG4bKu{n[0]}x{time.time_ns()}",
         "Max-Forwards: 70", "From: <sip:caller@x>;tag=c1", f"To: <sip:{user or 'x'}@x>", f"Call-ID: u{n[0]}@x",
         f"CSeq: 1 {cseq_method or method}"]
    h = [l for l in h if l.split(":")[0] not in drop]
    if extra:
        h.append(extra.rstrip("\r\n"))
    if body:
        h.append(f"Content-Type: {ctype}")
    return ("\r\n".join(h) + f"\r\nContent-Length: {len(body)}\r\n\r\n{body}").encode()


def main():
    cfg = os.path.join(ROOT, "target/e2e_utils.cfg")
    open(cfg, "w").write(CFG)
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}", "-n", "2", "--rpc-socket", SOCK],
                             stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    caller, a, b = Peer(5800), Peer(5801), Peer(5802)

    def ask(m):
        caller.s.sendto(m, ("127.0.0.1", PX))
        return caller.recv()

    def relayed(m):
        caller.s.sendto(m, ("127.0.0.1", PX))
        got = a.expect(m.split(b" ")[0].decode())
        if got:
            a.reply(got, 200, "OK")
            caller.recv()
        return got or b""

    try:
        r = ask(msg("OPTIONS", "sl"))
        check("sl_send_reply with variables", first(r) == "SIP/2.0 299 sl ok OPTIONS", first(r))
        r = ask(msg("OPTIONS", None))
        check("options_reply → 200 with Allow", first(r) == "SIP/2.0 200 OK" and "INVITE" in hdr(r, "Allow"), r[:200])

        # textops: presence/search + append_to_reply + append_time
        r = ask(msg("OPTIONS", "hf", "X-Foo: bar1\r\nX-Foo: bar2"))
        check("is_present_hf/_re, search, search_hf, is_method → reply headers",
              [hdr(r, h) for h in ("X-Result", "X-Search", "X-SearchHf", "X-Method")] == ["present", "yes", "yes", "ok"], r)
        check("append_time adds a Date header", hdr(r, "Date").endswith("GMT"), hdr(r, "Date"))

        # header edits on a relayed request
        m = relayed(msg("MESSAGE", "edit", "X-Remove: 1\r\nX-Gone-A: 1\r\nX-Gone-B: 2\r\nX-Subst: old\r\nSubject: hello"))
        lines = m.decode().split("\r\n")
        check("append_hf with variable", hdr(m, "X-Appended") == "caller", m)
        check("insert_hf right after the request line", lines[1] == "X-First: 1", lines[:3])
        check("append_hf after Call-ID", lines.index("X-After-CallID: y") == next(i for i, l in enumerate(lines) if l.startswith("Call-ID")) + 1)
        check("remove_hf / remove_hf_re", b"X-Remove" not in m and b"X-Gone" not in m)
        check("subst / replace on headers", hdr(m, "X-Subst") == "new" and hdr(m, "Subject") == "replaced")
        check("subst_user rewrites the R-URI user", first(m).startswith("MESSAGE sip:edited@"), first(m))

        # body operations (Content-Length must follow)
        m = relayed(msg("MESSAGE", "body", body="hello world"))
        body = m.split(b"\r\n\r\n", 1)[1]
        check("replace_body + subst_body with \\1", body == b"bye WorLD", body)
        check("…Content-Length fixed", hdr(m, "Content-Length") == str(len(body)), hdr(m, "Content-Length"))
        m = relayed(msg("MESSAGE", "setbody", body="old"))
        body = m.split(b"\r\n\r\n", 1)[1]
        check("set_body with variables and new Content-Type", body == b"new body for setbody" and hdr(m, "Content-Type") == "application/x-test"
              and hdr(m, "Content-Length") == str(len(body)), m)
        m = relayed(msg("MESSAGE", "rmbody", body="gone"))
        check("remove_body", m.endswith(b"\r\n\r\n") and hdr(m, "Content-Length") == "0" and not hdr(m, "Content-Type"), m)
        m = relayed(msg("MESSAGE", "keep", "X-Keep-Me: 1\r\nX-Drop: 1\r\nSubject: s"))
        check("keep_hf keeps mandatory + matching headers", hdr(m, "X-Keep-Me") == "1" and not hdr(m, "X-Drop") and not hdr(m, "Subject")
              and hdr(m, "Call-ID"), m)

        # siputils
        m = msg("OPTIONS", "su", "Supported: path, timer")
        m = m.replace(b"@127.0.0.1:5860 SIP", b"@127.0.0.1:5860;transport=tcp SIP")
        r = first(ask(m))
        check("siputils: has_totag/is_user/is_e164/uri_param/cmp_uri/cmp_aor/is_supported/tel2sip",
              r == "SIP/2.0 200 nototag user e164 param cmpuri cmpaor timer | sip:+15550100;phone-context=x@gw.example;user=phone", r)
        r = first(ask(msg("OPTIONS", "ip")))
        # localhost may resolve to ::1 first (/etc/hosts order varies).
        check("ipops", r in ("SIP/2.0 200 ip rfc1918 subnet cmp dns=127.0.0.1 type3 ",
                             "SIP/2.0 200 ip rfc1918 subnet cmp dns=::1 type3 "), r)
        r = first(ask(msg("OPTIONS", "cfg")))
        check("cfgutils: rand_event, gflags, lock/trylock/unlock", r == "SIP/2.0 200 rand gflag locked relock ", r)
        r = first(ask(msg("OPTIONS", "corex")))
        raw = b.recv(1.0)
        check("corex: xflags, is_faked_msg, file_write/read", r == "SIP/2.0 200 xflag real data-corex", r)
        check("corex: send_data raw payload", raw == b"RAW corex", raw)
        r = first(ask(msg("OPTIONS", "kex")))
        check("kex: sflags, setdsturi/resetdsturi, pv_printf", r == "SIP/2.0 200 sflag dst=sip:127.0.0.1:5802 reset pp-kex", r)
        r = first(ask(msg("OPTIONS", "pvm")))
        check("pv: pv_isset/unset, is_int, typeof, not_empty, xavp_params_explode", r == "SIP/2.0 200 int unset str two", r)

        # sanity
        r = ask(msg("MESSAGE", "x", cseq_method="INVITE"))
        check("sanity: CSeq method mismatch → 400", first(r) == "SIP/2.0 400 CSeq method does not match request method", first(r))
        r = ask(msg("MESSAGE", "x", drop=("Call-ID",)))
        check("sanity: missing Call-ID → 400", first(r) == "SIP/2.0 400 Missing Required Header in Request", first(r))
        r = ask(msg("MESSAGE", "x", "Proxy-Require: foo"))
        check("sanity: Proxy-Require → 420 + Unsupported", first(r) == "SIP/2.0 420 Bad Extension" and hdr(r, "Unsupported") == "foo", r)
        bad = msg("MESSAGE", "x", body="12345").replace(b"Content-Length: 5", b"Content-Length: 9")
        check("sanity: Content-Length mismatch → 400", first(ask(bad)) == "SIP/2.0 400 Content-Length mis-match")
        r = ask(msg("MESSAGE", "x", "Expires: soon"))
        check("sanity: bad Expires → 400", first(r) == "SIP/2.0 400 Expires value is illegal", first(r))

        # statistics via RPC
        out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, "stats.get_statistics", "script:", "sl:", "sanity:"],
                             capture_output=True, text=True, timeout=5)
        st = json.loads(out.stdout or "{}")
        # 14 requests pass sanity (9 answered locally, 5 relayed); 5 fail it.
        check("update_stat + sl/sanity counters", st.get("script:hits") == 14 and st.get("sl:sent_replies") == 14
              and st.get("sl:2xx_replies") == 9 and st.get("sl:4xx_replies") == 5 and st.get("sanity:failed") == 5, st)
    finally:
        proxy.terminate()
        err = proxy.communicate(timeout=5)[1]
        check("xinfo logged with variables", "INFO: req OPTIONS from 127.0.0.1 to sl" in err, err[:300])
        check("no panics in proxy log", "panic" not in err, err)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
