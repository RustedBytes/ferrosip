#!/usr/bin/env python3
"""End-to-end checks for the Phase 0 foundations: script expressions and
pseudo-variables, route()/return, while/switch, $avp/flags carried into
failure_route, branch_route, t_uac_send, and the JSON-RPC control socket
(via tools/ferroctl). Run from the repo root after `cargo build --release`.
"""
import json, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402
from e2e_fork import Peer, first, hdr, request  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PX = 5760
SOCK = os.path.join(ROOT, "target/e2e_script.sock")
CFG = r"""loadmodule "tm"
loadmodule "usrloc"
loadmodule "registrar"
modparam("tm", "fr_timer", 1000)
modparam("tm", "wait_timer", 1000)

request_route {
    if ($rm == "REGISTER") { save("location"); exit; }
    if ($rU == "calc") {
        $var(a) = 6;
        $var(b) = $var(a) * 7 - 2;
        $var(s) = "n=" + $var(b);
        $var(i) = 0;
        $var(sum) = 0;
        while ($var(i) < 5) {
            $var(i) = $var(i) + 1;
            $var(sum) = $var(sum) + $var(i);
        }
        switch ($var(sum)) {
            case 15: $var(sw) = "fifteen"; break;
            default: $var(sw) = "other";
        }
        reply(200, "$var(s) sum=$var(sum) sw=$var(sw) flen=$(fU{s.len}) host=$(ru{uri.host}) up=$(fU{s.toupper})");
        exit;
    }
    if ($fU =~ "^blocked" || $si == "1.2.3.4") { reply(403, "Forbidden"); exit; }
    if ($rU == "sub") {
        route(SUB);
        reply(200, "rc=$rc x=$var(x)");
        exit;
    }
    if ($rU == "hdr") { reply(200, "ua=$hdr(User-Agent) vias=$hdrc(Via) cs=$cs tag=$ft"); exit; }
    if ($rU == "me") {
        if ($ru == myself) { reply(200, "mine"); } else { reply(200, "notmine"); }
        exit;
    }
    if ($rU == "notme") {
        if ($ru != myself) { reply(200, "notmine"); } else { reply(200, "mine"); }
        exit;
    }
    if ($rU == "avp") {
        $avp(target) = "sip:127.0.0.1:5702";
        setflag(3);
        t_on_failure("AVPFAIL");
        t_relay("udp:127.0.0.1:5701");
        exit;
    }
    if ($rU == "br") {
        t_on_branch("BR");
        append_branch("sip:b@127.0.0.1:5702");
        append_branch("sip:c@127.0.0.1:5703");
        t_relay("udp:127.0.0.1:5701");
        exit;
    }
    if ($rU == "rewrite") {
        $rU = "bob";
        $rd = "127.0.0.1";
        $rp = 5701;
        t_relay();
        exit;
    }
    if ($rU == "du") { $du = "sip:127.0.0.1:5702"; t_relay(); exit; }
    if ($rU == "uac") {
        t_uac_send("MESSAGE", "sip:x@127.0.0.1:5703", "", "", "X-Uac: 1\r\nContent-Type: text/plain\r\n", "hello $fU");
        reply(202, "sent");
        exit;
    }
    if ($rU == "shv") {
        $shv(n) = $shv(n) + 1;
        reply(200, "n=$shv(n)");
        exit;
    }
    reply(404, "Not here");
}

route[SUB] {
    $var(x) = "in-sub";
    return(7);
}

failure_route[AVPFAIL] {
    if (isflagset(3) && $T_reply_code == 486) {
        $du = $avp(target);
        t_relay();
    }
}

branch_route[BR] {
    if ($T_branch_idx == 1) { drop; }
    append_hdr("X-Branch: $T_branch_idx");
}
"""
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def ctl(*args):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, *args], capture_output=True, text=True, timeout=5)
    try:
        return out.returncode, json.loads(out.stdout) if out.stdout.strip() else None, out.stderr.strip()
    except json.JSONDecodeError:
        return out.returncode, out.stdout, out.stderr.strip()


def main():
    cfg = os.path.join(ROOT, "target/e2e_script.cfg")
    open(cfg, "w").write(CFG)
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}", "-n", "2", "--rpc-socket", SOCK],
                             stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    caller, a, b, c = Peer(5700), Peer(5701), Peer(5702), Peer(5703)

    def ask(user, method="OPTIONS", extra=b"", from_user="caller"):
        m, _ = request(method, user, PX)
        m = m.replace(b"From: <sip:caller@x>", f"From: <sip:{from_user}@x>".encode())
        if extra:
            m = m.replace(b"Content-Length", extra + b"Content-Length")
        caller.s.sendto(m, ("127.0.0.1", PX))
        return caller.recv()

    try:
        # 1. Expressions, loops, switch, transformations.
        r = first(ask("calc"))
        check("arithmetic, concat, while, switch, transformations",
              r == "SIP/2.0 200 n=40 sum=15 sw=fifteen flen=6 host=127.0.0.1 up=CALLER", r)
        check("regex match on $fU", first(ask("x", from_user="blocked-1")) == "SIP/2.0 403 Forbidden")
        check("route() + return(7) → $rc, $var shared", first(ask("sub")) == "SIP/2.0 200 rc=7 x=in-sub")
        r = first(ask("hdr", extra=b"User-Agent: test/1.0\r\n"))
        check("$hdr / $hdrc / $cs / $ft", r == "SIP/2.0 200 ua=test/1.0 vias=1 cs=1 tag=c1", r)
        check("$ru == myself", first(ask("me")) == "SIP/2.0 200 mine")
        m, _ = request("OPTIONS", "notme", PX)
        caller.s.sendto(m.replace(b"@127.0.0.1:5760 SIP", b"@10.9.9.9 SIP"), ("127.0.0.1", PX))
        check("$ru != myself for a foreign host", first(caller.recv()) == "SIP/2.0 200 notmine")
        r1, r2 = first(ask("shv")), first(ask("shv"))
        check("$shv shared across requests", (r1, r2) == ("SIP/2.0 200 n=1", "SIP/2.0 200 n=2"), (r1, r2))

        # 2. $avp + flag survive into failure_route; $du from the AVP.
        ask("avp", "INVITE")  # 100 Trying
        ia = a.expect("INVITE")
        a.reply(ia, 486, "Busy Here")
        ib = b.expect("INVITE")
        check("failure_route sees $avp/flag/$T_reply_code and re-routes via $du", ib is not None, first(ib))
        b.reply(ib, 200, "OK")
        msgs = []
        while (m := caller.recv(0.8)) is not None:
            msgs.append(first(m))
        check("…caller gets B's 200", "SIP/2.0 200 OK" in msgs, msgs)
        for p in (caller, a, b, c):
            p.drain()

        # 3. branch_route: per-branch header, drop branch 1.
        ask("br", "MESSAGE") if False else caller.s.sendto(request("MESSAGE", "br", PX)[0], ("127.0.0.1", PX))
        ma, mc = a.expect("MESSAGE"), c.expect("MESSAGE")
        check("branch_route adds a per-branch header", ma is not None and mc is not None
              and hdr(ma, "X-Branch") == "0" and hdr(mc, "X-Branch") == "2", (hdr(ma or b"", "X-Branch"), hdr(mc or b"", "X-Branch")))
        check("branch_route drop removes branch 1", b.recv(0.4) is None)
        a.reply(ma, 200, "OK")
        c.reply(mc, 200, "OK")
        caller.recv()
        for p in (caller, a, b, c):
            p.drain()

        # 4. $rU/$rd/$rp setters rebuild $ru; t_relay() routes by it.
        caller.s.sendto(request("MESSAGE", "rewrite", PX)[0], ("127.0.0.1", PX))
        m = a.expect("MESSAGE")
        check("$rU/$rd/$rp rewrite the R-URI and route by it", m is not None and first(m).startswith("MESSAGE sip:bob@127.0.0.1:5701 "), first(m))
        a.reply(m, 200, "OK")
        caller.recv()
        caller.s.sendto(request("MESSAGE", "du", PX)[0], ("127.0.0.1", PX))
        m = b.expect("MESSAGE")
        check("$du = … routes to the given hop, R-URI unchanged", m is not None and first(m).startswith("MESSAGE sip:du@127.0.0.1:5760 "), first(m))
        b.reply(m, 200, "OK")
        caller.recv()

        # 5. t_uac_send: a request of our own.
        r = first(ask("uac"))
        m = c.expect("MESSAGE")
        check("t_uac_send → new MESSAGE with headers and templated body", r == "SIP/2.0 202 sent" and m is not None
              and hdr(m, "X-Uac") == "1" and m.endswith(b"hello caller") and hdr(m, "Call-ID").startswith("fs-"), m)
        c.reply(m, 200, "OK")
        time.sleep(0.2)

        # 6. RPC via ferroctl.
        reg, _ = request("REGISTER", "alice", PX)
        reg = reg.replace(b"Content-Length", b"Contact: <sip:alice@127.0.0.1:5700>\r\nExpires: 60\r\nContent-Length")
        caller.s.sendto(reg, ("127.0.0.1", PX))
        caller.recv()
        rc, res, _ = ctl("system.listMethods")
        check("system.listMethods lists module commands", rc == 0 and {"ul.dump", "tm.stats", "stats.get_statistics", "core.uptime"} <= set(res), res)
        rc, res, _ = ctl("ul.dump")
        check("ul.dump shows the registration", rc == 0 and "alice" in res and res["alice"][0]["contact"] == "sip:alice@127.0.0.1:5700", res)
        rc, res, _ = ctl("stats.get_statistics", "core:", "tm:")
        check("stats: core and tm counters", rc == 0 and res.get("core:rcv_requests", 0) >= 10 and res.get("tm:total", 0) >= 4
              and res.get("tm:total_local") == 1 and res.get("tm:rpl_received", 0) >= 4, res)
        rc, res, _ = ctl("stats.get_statistics", "usrloc:registered_users")
        check("usrloc gauge", res == {"usrloc:registered_users": 1}, res)
        rc, res, _ = ctl("ul.rm", "location", "alice")
        rc2, _, err = ctl("ul.lookup", "location", "alice")
        check("ul.rm removes, ul.lookup then fails", res == 1 and rc2 != 0 and "not found" in err, (res, rc2, err))
        rc, _, err = ctl("no.such.method")
        check("unknown method → error exit", rc != 0 and "not found" in err.lower(), err)
    finally:
        proxy.terminate()
        err = proxy.communicate(timeout=5)[1]
        check("no panics in proxy log", "panic" not in err, err)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
