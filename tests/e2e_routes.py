#!/usr/bin/env python3
"""End-to-end checks for failure_route / onreply_route / reply_route.

One proxy, three scripted user agents (A, B, C = voicemail) and a caller,
all raw UDP. Run from the repo root after `cargo build --release`.
"""
import os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402
from e2e_fork import Peer, first, hdr, request  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PX = 5660
CFG = """loadmodule "tm"
modparam("tm", "fr_timer", 1000)
modparam("tm", "fr_inv_timer", 2000)
modparam("tm", "wait_timer", 1500)

# Every reply passes here first.
reply_route {
    if t_check_status("199") { drop; }
    append_hdr("X-Global-Reply: seen");
}

request_route {
    if ruri_user_prefix("vm") {          # busy / no answer → voicemail
        t_on_failure("TO_VOICEMAIL");
        t_relay("udp:127.0.0.1:5601");
        exit;
    }
    if ruri_user_prefix("chain") {       # A, then B, then C (re-armed routes)
        t_on_failure("NEXT_B");
        t_relay("udp:127.0.0.1:5601");
        exit;
    }
    if ruri_user_prefix("busyreply") {   # the failure route answers itself
        t_on_failure("REPLY");
        t_relay("udp:127.0.0.1:5601");
        exit;
    }
    if ruri_user_prefix("hdr") {         # per-transaction reply route
        t_on_reply("EDIT");
        t_relay("udp:127.0.0.1:5601");
        exit;
    }
    t_relay("udp:127.0.0.1:5601");
}

failure_route[TO_VOICEMAIL] {
    if t_check_status("486|408") {
        if t_branch_timeout() {
            append_hdr("X-Reason: no-answer");
        } else {
            append_hdr("X-Reason: busy");
        }
        rewriteuri("sip:vm@127.0.0.1:5603");
        t_relay("udp:127.0.0.1:5603");
    }
}

failure_route[NEXT_B] {
    t_on_failure("NEXT_C");
    rewriteuri("sip:b@127.0.0.1:5602");
    t_relay("udp:127.0.0.1:5602");
}

failure_route[NEXT_C] {
    rewriteuri("sip:c@127.0.0.1:5603");
    t_relay("udp:127.0.0.1:5603");
}

failure_route[REPLY] {
    if t_check_status("4[0-9][0-9]") {
        t_reply(480, "Temporarily Unavailable (failure_route)");
    }
}

onreply_route[EDIT] {
    if t_check_status("183") { drop; }
    append_hdr("X-Onreply: edited");
    remove_hdr("X-Secret");
}
"""
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def main():
    cfg = os.path.join(ROOT, "target/e2e_routes.cfg")
    open(cfg, "w").write(CFG)
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}", "-n", "2"],
                             stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    caller, a, b, c = Peer(5600), Peer(5601), Peer(5602), Peer(5603)

    def invite(user, method="INVITE"):
        m, _ = request(method, user, PX)
        caller.s.sendto(m, ("127.0.0.1", PX))
        return m

    def caller_msgs(timeout=1.0):
        out = []
        while (m := caller.recv(timeout)) is not None:
            out.append(m)
            timeout = 0.4
        return out

    def finals(msgs):
        return [first(m) for m in msgs if first(m) >= "SIP/2.0 2"]

    def reset():
        time.sleep(0.1)
        for p in (caller, a, b, c):
            p.drain()

    try:
        # 1. Busy → failure_route forwards to voicemail; caller never sees 486.
        invite("vmbob")
        caller.recv()
        ia = a.expect("INVITE")
        a.reply(ia, 486, "Busy Here")
        check("A's 486 ACKed", a.expect("ACK") is not None)
        iv = c.expect("INVITE")
        check("failure_route: 486 → INVITE to voicemail with rewritten R-URI",
              iv is not None and first(iv).startswith("INVITE sip:vm@127.0.0.1:5603 "), first(iv))
        check("…carrying the route's header (busy)", iv is not None and hdr(iv, "X-Reason") == "busy", iv)
        check("…same Call-ID, new Via branch", iv is not None and hdr(iv, "Call-ID") == hdr(ia, "Call-ID")
              and hdr(iv, "Via") != hdr(ia, "Via"))
        c.reply(iv, 200, "OK")
        check("caller gets voicemail's 200, not the 486", finals(caller_msgs()) == ["SIP/2.0 200 OK"])
        reset()

        # 2. No answer (fr_timer 1 s) → t_branch_timeout() → voicemail busy too.
        invite("vmcarol")
        caller.recv()
        a.expect("INVITE")
        t0 = time.time()
        iv = c.expect("INVITE", 3)
        check("timeout → failure_route after fr_timer", iv is not None and 0.9 < time.time() - t0 < 2.0, round(time.time() - t0, 2))
        check("…t_branch_timeout() true (X-Reason: no-answer)", iv is not None and hdr(iv, "X-Reason") == "no-answer")
        c.reply(iv, 486, "Busy Here")
        check("route not re-armed → best reply (486 beats our 408)", finals(caller_msgs()) == ["SIP/2.0 486 Busy Here"])
        reset()

        # 3. t_check_status doesn't match → nothing added → best reply (503 → 500).
        invite("vmdave")
        caller.recv()
        a.reply(a.expect("INVITE"), 503, "Service Unavailable")
        check("unmatched status → no voicemail branch", c.recv(0.5) is None)
        check("…best reply upstream (503 → 500 Service Unavailable)", finals(caller_msgs()) == ["SIP/2.0 500 Service Unavailable"])
        reset()

        # 4. Chain A → B → C via failure routes that re-arm the next one.
        invite("chainy")
        caller.recv()
        ia = a.expect("INVITE")
        check("chain: B not tried while A is pending", b.recv(0.3) is None)
        a.reply(ia, 480, "Temporarily Unavailable")
        ib = b.expect("INVITE")
        check("chain: A failed → B", ib is not None and first(ib).startswith("INVITE sip:b@127.0.0.1:5602 "))
        b.reply(ib, 486, "Busy Here")
        ic = c.expect("INVITE")
        check("chain: B failed → C (route re-armed with t_on_failure)", ic is not None and first(ic).startswith("INVITE sip:c@"))
        c.reply(ic, 404, "Not Found")
        f = finals(caller_msgs())
        check("chain exhausted → exactly one final (best 4xx)", len(f) == 1 and f[0].startswith("SIP/2.0 4"), f)
        reset()

        # 5. The failure route answers with t_reply().
        invite("busyreply")
        caller.recv()
        a.reply(a.expect("INVITE"), 486, "Busy Here")
        check("t_reply() from failure_route", finals(caller_msgs()) == ["SIP/2.0 480 Temporarily Unavailable (failure_route)"])
        reset()

        # 6. onreply_route[EDIT]: drop 183, edit 180 and 200; global route too.
        invite("hdrs")
        caller.recv()
        ia = a.expect("INVITE")
        a.reply(ia, 183, "Session Progress")
        a.reply(ia, 180, "Ringing", "X-Secret: s3cr3t\r\n")
        msgs = caller_msgs()
        lines = [first(m) for m in msgs]
        check("onreply_route drop → 183 not forwarded", "SIP/2.0 183 Session Progress" not in lines, lines)
        r180 = next((m for m in msgs if first(m) == "SIP/2.0 180 Ringing"), b"")
        check("180 forwarded with X-Onreply added", hdr(r180, "X-Onreply") == "edited", r180)
        check("…X-Secret removed by the route", b"X-Secret" not in r180, r180)
        check("…and the global reply_route ran first", hdr(r180, "X-Global-Reply") == "seen", r180)
        a.reply(ia, 200, "OK")
        r = caller.recv()
        check("final 200 also edited", first(r) == "SIP/2.0 200 OK" and hdr(r, "X-Onreply") == "edited", r)
        reset()

        # 7. Global reply_route alone (no t_on_reply): edits and drops.
        invite("plain")
        caller.recv()
        ia = a.expect("INVITE")
        a.reply(ia, 199, "Early Dialog Terminated")
        a.reply(ia, 200, "OK")
        msgs = caller_msgs()
        check("global reply_route drops 199", [first(m) for m in msgs] == ["SIP/2.0 200 OK"], [first(m) for m in msgs])
        check("…and edits the 200", msgs and hdr(msgs[0], "X-Global-Reply") == "seen" and not hdr(msgs[0], "X-Onreply"))
        reset()

        # 8. Caller CANCELs: the failure route does not run.
        m = invite("vmeve")
        caller.recv()
        ia = a.expect("INVITE")
        a.reply(ia, 180, "Ringing")
        caller_msgs(0.3)
        caller.s.sendto(m.replace(b"INVITE sip:", b"CANCEL sip:").replace(b"CSeq: 1 INVITE", b"CSeq: 1 CANCEL"), ("127.0.0.1", PX))
        a.expect("CANCEL")
        a.reply(ia, 487, "Request Terminated")
        msgs = caller_msgs()
        check("after CANCEL: no voicemail branch", c.recv(0.5) is None)
        check("…caller gets 487", "SIP/2.0 487 Request Terminated" in finals(msgs), [first(x) for x in msgs])
        reset()

        # 9. Startup errors name the problem.
        for bad, want in (
            ('loadmodule "tm"\nrequest_route { t_on_failure("NOPE"); t_relay("udp:127.0.0.1:1"); }\n', "no failure_route[NOPE]"),
            ('loadmodule "tm"\nrequest_route { t_on_reply("X"); }\n', "no onreply_route[X]"),
            ('loadmodule "tm"\nrequest_route { exit; }\nfailure_route { exit; }\n', "failure_route needs a name"),
            ('loadmodule "tm"\nrequest_route { exit; }\nfailure_route[A] { exit; }\nfailure_route[A] { exit; }\n', "defined twice"),
        ):
            p = os.path.join(ROOT, "target/e2e_routes_bad.cfg")
            open(p, "w").write(bad)
            out = subprocess.run([f"{ROOT}/target/release/ferrosip", "-f", p, "-l", "udp:127.0.0.1:5669"],
                                 capture_output=True, text=True, timeout=5)
            check(f"config error: {want}", out.returncode != 0 and want in out.stderr, out.stderr.strip())
    finally:
        proxy.terminate()
        err = proxy.communicate(timeout=5)[1]
        check("no panics in proxy log", "panic" not in err, err)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
