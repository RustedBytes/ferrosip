#!/usr/bin/env python3
"""End-to-end checks for the dialog module's Kamailio extras: dlg_flag
(dialog created by t_relay), the Record-Route `did` cookie with
dlg_match_mode 0, dialog flags, $dlg_ctx, dlg_get, dlg_refer, dlg_bridge,
timeout-noreset and timeout routes, the extra RPCs and db_mode delayed.
Run from the repo root after `cargo build --release`.
"""
import json, os, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402
from e2e_routing import Peer, make_reply, hdr, first  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PX = 6560
CALLER, A = 6561, 6562
SOCK = os.path.join(ROOT, "target/e2e_dialog.sock")
DB = os.path.join(ROOT, "target/e2e_dialog_db")

CFG = r"""
loadmodule "tm"
loadmodule "sl"
loadmodule "rr"
loadmodule "textops"
loadmodule "siputils"
loadmodule "htable"
loadmodule "dialog"
modparam("htable", "htable", "t=>size=4;autoexpire=0;")
modparam("dialog", "dlg_flag", 4)
modparam("dialog", "dlg_match_mode", 0)
modparam("dialog", "db_url", "text://DB")
modparam("dialog", "db_mode", 2)
modparam("dialog", "db_update_period", 1)
modparam("dialog", "bridge_controller", "sip:ctl@127.0.0.1")
modparam("dialog", "profiles_with_value", "caller")
modparam("dialog", "profiles_no_value", "calls")

route[DLGTO] {
    $sht(t=>to) = $dlg(callid);
}

request_route {
    if (has_totag()) {
        if (is_known_dlg()) {
            if (is_method("INFO") && $hdr(X-Flag) != $null) { dlg_setflag("$hdr(X-Flag)"); }
            append_hf("X-Dlg: $dlg(h_id) f=$dlg(sflags) dir=$dlg_ctx(dir) set=$dlg_ctx(set)\r\n");
            if (is_method("INFO") && $hdr(X-Set-Timeout) != $null) { dlg_set_timeout("$hdr(X-Set-Timeout)"); }
            if (is_method("INFO") && $hdr(X-Prof) != $null) { set_dlg_profile("calls"); set_dlg_profile("caller", "$hdr(X-Prof)"); }
            append_hf("X-Life: $dlg(lifetime) $dlg(timeout)\r\n");
        }
        loose_route();
        t_relay();
        exit;
    }
    switch ($rU) {
    case "flag":
        setflag(4);
        dlg_setflag(3);
        # No dialog yet: dlg_set_timeout() is -1 (Kamailio), the context
        # sets the lifetime of the one t_relay creates.
        if ($hdr(X-Timeout) != $null) {
            if (dlg_set_timeout("$hdr(X-Timeout)")) { append_hf("X-Early-Timeout: set\r\n"); }
            $dlg_ctx(timeout) = $hdr(X-Timeout);
        }
        if ($hdr(X-Noreset) != $null) { dlg_set_property("timeout-noreset"); }
        $dlg_ctx(timeout_route) = "DLGTO";
        if (dlg_isflagset(3) && !is_known_dlg()) { append_hf("X-Ctx: 3 $dlg_ctx(flags) $dlg_ctx(set)\r\n"); }
        record_route();
        t_relay("udp:127.0.0.1:6562");
        exit;
    case "noflag":
        record_route();
        t_relay("udp:127.0.0.1:6562");
        exit;
    case "get":
        if (dlg_get("$hdr(X-Cid)", "$hdr(X-F)", "$hdr(X-T)")) {
            sl_send_reply(200, "found $dlg(h_id) f=$dlg(sflags) set=$dlg_ctx(set)");
        } else {
            sl_send_reply(404, "none");
        }
        exit;
    case "refer":
        if (dlg_get("$hdr(X-Cid)", "$hdr(X-F)", "$hdr(X-T)") && dlg_refer("callee", "sip:bob@example.com")) {
            sl_send_reply(200, "referred");
        } else {
            sl_send_reply(500, "no refer");
        }
        exit;
    case "bridge":
        if (dlg_bridge("sip:alice@127.0.0.1:6562", "sip:bob@example.com", "")) {
            sl_send_reply(200, "bridging");
        } else {
            sl_send_reply(500, "no bridge");
        }
        exit;
    case "tbp1":
        if (dlg_set_timeout_by_profile("caller", "$hdr(X-V)", "200")) { sl_send_reply(200, "tbp1"); } else { sl_send_reply(500, "tbp1 failed"); }
        exit;
    case "tbp2":
        if (dlg_set_timeout_by_profile("calls", "300")) { sl_send_reply(200, "tbp2"); } else { sl_send_reply(500, "tbp2 failed"); }
        exit;
    case "htget":
        sl_send_reply(200, "to=$sht(t=>to)");
        exit;
    }
    sl_send_reply(404, "Not Found");
}
"""

DIALOG_TABLE = ("hash_entry(int) hash_id(int) callid(string) from_uri(string) from_tag(string) to_uri(string) to_tag(string) "
                "caller_cseq(int) callee_cseq(int) caller_route_set(string,null) callee_route_set(string,null) caller_contact(string) "
                "callee_contact(string) caller_sock(string) callee_sock(string) state(int) start_time(int) timeout(int) xdata(string,null)\n")

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def msg(method, ruri, extra="", cseq=1, callid=None, to=None, ftag="c1", route=None, port=CALLER, frm="sip:caller@x"):
    seq[0] += 1
    ex = "".join(l + "\r\n" for l in extra.split("\n") if l) if extra else ""
    if route:
        ex = f"Route: {route}\r\n" + ex
    cid = callid or f"dg-{seq[0]}-{time.time_ns()}"
    return (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKd{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: <{frm}>;tag={ftag}\r\nTo: {to or '<' + ruri + '>'}\r\nCall-ID: {cid}\r\n"
            f"CSeq: {cseq} {method}\r\nContact: <sip:caller@127.0.0.1:{port}>\r\n{ex}Content-Length: 0\r\n\r\n").encode()


def ctl(*args):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, *args], capture_output=True, text=True, timeout=5)
    try:
        return json.loads(out.stdout) if out.stdout.strip() else out.stderr.strip()
    except json.JSONDecodeError:
        return out.stdout


def rev_hex(n):
    return "0" if n == 0 else "".join("0123456789abcdef"[(n >> (4 * i)) & 15] for i in range((n.bit_length() + 3) // 4))


def main():
    shutil.rmtree(DB, ignore_errors=True)
    os.makedirs(DB)
    open(os.path.join(DB, "dialog"), "w").write(DIALOG_TABLE)
    cfg = os.path.join(ROOT, "target/e2e_dialog.cfg")
    open(cfg, "w").write(CFG.replace("text://DB", "text://" + DB))
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}", "-n", "2", "--rpc-socket", SOCK],
                             stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    if proxy.poll() is not None:
        print(proxy.stderr.read())
        sys.exit(1)
    caller, a = Peer(CALLER), Peer(A)

    def send(m):
        caller.s.sendto(m, ("127.0.0.1", PX))

    def ask(m):
        send(m)
        return first(caller.final())

    def call(user="flag", extra=""):
        """INVITE → A answers 200 → (INVITE at A, 200 at the caller)."""
        send(msg("INVITE", f"sip:{user}@127.0.0.1:{PX}", extra))
        inv = a.expect("INVITE")
        if inv is None:
            return None, None
        a.s.sendto(make_reply(inv, 200, "OK", "Contact: <sip:a@127.0.0.1:6562>\r\n"), a.addr)
        return inv, caller.final()

    def indlg(method, inv, ok, cseq, route=True, extra=""):
        """A request from the caller inside the call `inv` set up."""
        rr = hdr(ok, "Record-Route") if route else None
        return msg(method, "sip:a@127.0.0.1:6562", extra, cseq=cseq, callid=hdr(inv, "Call-ID"),
                   to="<sip:flag@127.0.0.1:6560>;tag=uas", route=rr)

    def ids(inv):
        return f"X-Cid: {hdr(inv, 'Call-ID')}\nX-F: c1\nX-T: uas"

    err = ""
    try:
        # ------------------------------------------------ dlg_flag + did cookie
        inv, ok = call()
        lst = ctl("dlg.list")
        check("dlg_flag: t_relay creates the dialog", first(ok) == "SIP/2.0 200 OK" and isinstance(lst, list) and len(lst) == 1, (ok, lst))
        d = lst[0] if isinstance(lst, list) and lst else {"h_entry": -1, "h_id": -1}
        did = f"did={rev_hex(d['h_entry'])}.{rev_hex(d['h_id'])}"
        rr = hdr(inv or b"", "Record-Route")
        check("Record-Route carries the did cookie (reverse hex h_entry.h_id)", did in rr, (did, rr))
        check("dlg_setflag before the dialog exists: dialog context flags", hdr(inv or b"", "X-Ctx") == "3 8 0", hdr(inv or b"", "X-Ctx"))
        lc = ctl("dlg.list_ctx")
        check("dlg.list_ctx: flags and timeout route from the context", isinstance(lc, list) and lc[0]["context"]["sflags"] == 8
              and lc[0]["context"]["timeout_route"] == "DLGTO", lc)

        send(indlg("ACK", inv, ok, 1))
        ack = a.expect("ACK")
        check("ACK matched by the did cookie: $dlg, $dlg_ctx(dir/set)", hdr(ack or b"", "X-Dlg") == f"{d['h_id']} f=8 dir=1 set=1", ack)
        check("…state 4", ctl("dlg.list")[0]["state"] == 4)
        send(indlg("INFO", inv, ok, 2, route=False))
        info = a.answer("INFO")
        caller.final()
        check("dlg_match_mode 0: no cookie, no match", info is not None and hdr(info, "X-Dlg") == "", info)
        send(indlg("INFO", inv, ok, 3, extra="X-Flag: 5"))
        info = a.answer("INFO")
        caller.final()
        check("in-dialog dlg_setflag", hdr(info or b"", "X-Dlg") == f"{d['h_id']} f=40 dir=1 set=1", info)
        # From the callee: Route from the INVITE's Record-Route.
        cb = (f"INFO sip:caller@127.0.0.1:{CALLER} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{A};branch=z9hG4bKcb{time.time_ns()}\r\n"
              f"Max-Forwards: 70\r\nRoute: {rr}\r\nFrom: <sip:flag@127.0.0.1:6560>;tag=uas\r\nTo: <sip:caller@x>;tag=c1\r\n"
              f"Call-ID: {hdr(inv or b'', 'Call-ID')}\r\nCSeq: 1 INFO\r\nContent-Length: 0\r\n\r\n").encode()
        a.s.sendto(cb, ("127.0.0.1", PX))
        info = caller.answer("INFO")
        a.final()
        check("…from the callee: dir=2", hdr(info or b"", "X-Dlg") == f"{d['h_id']} f=40 dir=2 set=1", info)

        r = ask(msg("OPTIONS", f"sip:get@127.0.0.1:{PX}", ids(inv)))
        check("dlg_get finds the dialog from another request", r == f"SIP/2.0 200 found {d['h_id']} f=40 set=1", r)
        r = ask(msg("OPTIONS", f"sip:get@127.0.0.1:{PX}", ids(inv).replace("X-T: uas", "X-T: nope")))
        check("…and nothing for wrong tags", r == "SIP/2.0 404 none", r)
        cid = hdr(inv, "Call-ID")
        check("dlg.dlg_list <callid>", [x["h_id"] for x in ctl("dlg.dlg_list", cid)] == [d["h_id"]] and ctl("dlg.dlg_list", cid, "zz") == [])
        check("dlg.dlg_list_ctx", ctl("dlg.dlg_list_ctx", cid)[0]["context"]["sflags"] == 40)
        check("dlg.is_alive", ctl("dlg.is_alive", str(d["h_entry"]), str(d["h_id"])) == 0)

        # dlg_refer: REFER to the callee, sent as the caller
        r = ask(msg("OPTIONS", f"sip:refer@127.0.0.1:{PX}", ids(inv)))
        ref = a.answer("REFER", 202, "Accepted")
        check("dlg_refer(callee): REFER inside the dialog", r == "SIP/2.0 200 referred" and ref is not None
              and first(ref) == "REFER sip:a@127.0.0.1:6562 SIP/2.0" and hdr(ref, "Refer-To") == "<sip:bob@example.com>"
              and hdr(ref, "Referred-By") == "<sip:ctl@127.0.0.1>" and "tag=c1" in hdr(ref, "From") and "tag=uas" in hdr(ref, "To")
              and hdr(ref, "CSeq") == "4 REFER" and hdr(ref, "Call-ID") == cid, ref)

        # db_mode delayed: the row appears within db_update_period
        time.sleep(1.5)
        rows = open(os.path.join(DB, "dialog")).read().splitlines()
        check("db_mode 2 (delayed): row written by the periodic flush, flags in xdata",
              len(rows) == 2 and '"sflags"\\:40' in rows[1] and rows[1].startswith(f"{d['h_entry']}:{d['h_id']}:"), rows)

        # terminate_dlg by ids
        check("dlg.terminate_dlg <callid> <ftag> <ttag>", ctl("dlg.terminate_dlg", cid, "c1", "uas") == 0)
        b1, b2 = a.expect("BYE"), caller.expect("BYE")
        check("…BYE both ways", b1 is not None and b2 is not None and hdr(b1, "CSeq") == "5 BYE", (b1, b2))
        for p, m in ((a, b1), (caller, b2)):
            if m:
                p.s.sendto(make_reply(m, 200, "OK"), p.addr)
        time.sleep(1.5)
        rows = open(os.path.join(DB, "dialog")).read().splitlines()
        check("…dialog gone, and its row after the next flush", ctl("dlg.list") == [] and len(rows) == 1, rows)

        # no flag: no dialog
        inv0, ok0 = call("noflag")
        check("without the flag t_relay creates no dialog", first(ok0) == "SIP/2.0 200 OK" and ctl("dlg.list") == []
              and "did=" not in hdr(inv0 or b"", "Record-Route"), hdr(inv0 or b"", "Record-Route"))

        # ------------------------------------------- timeout-noreset, timeout_route
        inv1, ok1 = call(extra="X-Timeout: 5")
        inv2, ok2 = call(extra="X-Timeout: 5\nX-Noreset: 1")
        check("dlg_set_timeout() without a dialog → -1", inv1 is not None and b"X-Early-Timeout" not in inv1, inv1)
        t0 = time.time()
        send(indlg("ACK", inv1, ok1, 1))
        send(indlg("ACK", inv2, ok2, 1))
        a.expect("ACK")
        a.expect("ACK")
        time.sleep(3.5)
        for iv, o in ((inv1, ok1), (inv2, ok2)):
            send(indlg("INFO", iv, o, 2))
            a.answer("INFO")
            caller.final()
        cids = {hdr(inv1, "Call-ID"): "reset", hdr(inv2, "Call-ID"): "noreset"}
        left = None
        while time.time() < t0 + 8:
            left = sorted(cids[x["call-id"]] for x in ctl("dlg.list"))
            if "noreset" not in left:
                break
            time.sleep(0.1)
        check("timeout-noreset: the in-dialog INFO didn't extend it; it did the other", left == ["reset"], left)
        r = ask(msg("OPTIONS", f"sip:htget@127.0.0.1:{PX}"))
        check("$dlg_ctx(timeout_route) ran on the timeout", r == f"SIP/2.0 200 to={hdr(inv2, 'Call-ID')}", r)
        lst = ctl("dlg.list")
        if lst:
            ctl("dlg.end_dlg", str(lst[0]["h_entry"]), str(lst[0]["h_id"]))
            for p in (a, caller):
                p.answer("BYE")
        a.drain()
        caller.drain()

        # dlg_set_timeout on a confirmed dialog: later in-dialog requests
        # restart the timeout with the new lifetime (Kamailio's
        # update_dlg_timeout() doesn't stop the resets).
        inv3, ok3 = call()
        send(indlg("ACK", inv3, ok3, 1))
        a.expect("ACK")
        send(indlg("INFO", inv3, ok3, 2, extra="X-Set-Timeout: 100"))
        a.answer("INFO")
        caller.final()
        time.sleep(1.2)
        t_before = int(time.time())
        send(indlg("INFO", inv3, ok3, 3))
        info = a.answer("INFO")
        caller.final()
        life = (hdr(info or b"", "X-Life") or "0 0").split()
        check("dlg_set_timeout(100) on a dialog: the next in-dialog request restarts it with 100 s",
              life[0] == "100" and int(life[1]) >= t_before + 100, (life, t_before))
        lst = [x for x in ctl("dlg.list") if x["call-id"] == hdr(inv3, "Call-ID")]
        if lst:
            ctl("dlg.end_dlg", str(lst[0]["h_entry"]), str(lst[0]["h_id"]))
            for p in (a, caller):
                p.answer("BYE")

        # --------------- dlg_set_timeout_by_profile, dlg.briefing, dlg.set_state
        calls = []
        for v in ("v1", "v2"):
            iv, o = call()
            send(indlg("ACK", iv, o, 1))
            a.expect("ACK")
            send(indlg("INFO", iv, o, 2, extra=f"X-Prof: {v}"))
            a.answer("INFO")
            caller.final()
            calls.append((iv, o))
        cid1, cid2 = (hdr(iv, "Call-ID") for iv, _ in calls)

        def life():
            return {x["call-id"]: x["context"]["lifetime"] for x in ctl("dlg.list_ctx")}

        before = life()
        t0 = int(time.time())
        r = ask(msg("OPTIONS", f"sip:tbp1@127.0.0.1:{PX}", "X-V: v1"))
        after = life()
        tmo = {x["call-id"]: x["timeout"] for x in ctl("dlg.list")}
        check("dlg_set_timeout_by_profile(profile, value, 200): only the dialog with that value",
              r == "SIP/2.0 200 tbp1" and after.get(cid1) == 200 and after.get(cid2) == before.get(cid2) != 200
              and t0 + 199 <= tmo.get(cid1, 0) <= t0 + 202, (r, before, after, tmo))
        r = ask(msg("OPTIONS", f"sip:tbp1@127.0.0.1:{PX}", "X-V: "))
        check("…an empty value → -1", r == "SIP/2.0 500 tbp1 failed", r)
        r = ask(msg("OPTIONS", f"sip:tbp2@127.0.0.1:{PX}"))
        after = life()
        check("dlg_set_timeout_by_profile(profile, 300): every dialog of the profile", r == "SIP/2.0 200 tbp2"
              and after.get(cid1) == 300 and after.get(cid2) == 300, (r, after))

        br = ctl("dlg.briefing")
        mine = [x for x in br if x.get("call-id") == cid1] if isinstance(br, list) else []
        check("dlg.briefing: h_entry, h_id, from_uri, to_uri, call-id, from_tag, to_tag", len(mine) == 1
              and set(mine[0]) == {"h_entry", "h_id", "from_uri", "to_uri", "call-id", "from_tag", "to_tag"}
              and mine[0]["from_tag"] == "c1" and mine[0]["to_tag"] == "uas" and mine[0]["from_uri"] == "sip:caller@x", br)
        br = ctl("dlg.briefing", "sIE")
        check("dlg.briefing sIE: state, init_ts, end_ts", isinstance(br, list) and len(br) == 2
              and all(set(x) == {"h_entry", "h_id", "state", "init_ts", "end_ts"} and x["state"] == 4 and x["end_ts"] == 0 for x in br), br)

        r = ctl("dlg.set_state", cid1, "c1", "uas", "7")
        check("dlg.set_state with a state outside 1..5 → error", isinstance(r, str) and "Invalid state value" in r, r)
        r = ctl("dlg.set_state", cid1, "c1", "nope", "5")
        check("dlg.set_state for an unknown dialog → error", isinstance(r, str) and "Dialog not found" in r, r)
        r = ctl("dlg.set_state", cid1, "c1", "uas")
        left = [x["call-id"] for x in ctl("dlg.list")]
        check("dlg.set_state <callid> <ftag> <ttag> (default 5): the dialog is dropped, no BYE", r == "Done" and cid1 not in left
              and cid2 in left and a.expect("BYE", timeout=0.5) is None, (r, left))
        r = ctl("dlg.set_state", cid2, "uas", "c1", "3")
        st = [x["state"] for x in ctl("dlg.list") if x["call-id"] == cid2]
        check("dlg.set_state 3 (tags in either order)", r == "Done" and st == [3], (r, st))
        lst = [x for x in ctl("dlg.list") if x["call-id"] == cid2]
        if lst:
            ctl("dlg.end_dlg", str(lst[0]["h_entry"]), str(lst[0]["h_id"]))
            for p in (a, caller):
                p.answer("BYE")
        a.drain()
        caller.drain()

        # ------------------------------------------------------- dlg_bridge
        r = ask(msg("OPTIONS", f"sip:bridge@127.0.0.1:{PX}"))
        binv = a.expect("INVITE")
        check("dlg_bridge: INVITE to `from` from the controller, on hold", r == "SIP/2.0 200 bridging" and binv is not None
              and first(binv) == "INVITE sip:alice@127.0.0.1:6562 SIP/2.0" and "<sip:ctl@127.0.0.1>;tag=" in hdr(binv, "From")
              and hdr(binv, "Content-Type") == "application/sdp" and b"c=IN IP4 0.0.0.0" in binv, binv)
        if binv:
            a.s.sendto(make_reply(binv, 180, "Ringing"), a.addr)
            a.s.sendto(make_reply(binv, 200, "OK", "Contact: <sip:alice@127.0.0.1:6562>\r\n"), a.addr)
        back = a.expect("ACK")
        check("…2xx ACKed", back is not None and first(back) == "ACK sip:alice@127.0.0.1:6562 SIP/2.0" and hdr(back, "CSeq") == "1 ACK"
              and "tag=uas" in hdr(back, "To"), back)
        bref = a.answer("REFER", 202, "Accepted")
        check("…then REFER to `to`", bref is not None and hdr(bref, "Refer-To") == "<sip:bob@example.com>" and hdr(bref, "CSeq") == "2 REFER"
              and hdr(bref, "Call-ID") == hdr(binv or b"", "Call-ID"), bref)
        bbye = a.answer("BYE")
        check("…then BYE", bbye is not None and hdr(bbye, "CSeq") == "3 BYE", bbye)

        # RPC form; a non-2xx is ACKed by tm, nothing more is sent
        check("dlg.bridge_dlg", ctl("dlg.bridge_dlg", "sip:alice@127.0.0.1:6562", "sip:carol@example.com") == 0)
        binv = a.expect("INVITE")
        if binv:
            a.s.sendto(make_reply(binv, 486, "Busy Here"), a.addr)
        back = a.expect("ACK")
        check("…486 to the bridge INVITE: ACKed, no REFER", binv is not None and back is not None and hdr(back, "CSeq") == "1 ACK"
              and a.expect("REFER", timeout=0.5) is None, back)
    finally:
        proxy.terminate()
        try:
            err = proxy.communicate(timeout=3)[1]
        except subprocess.TimeoutExpired:
            proxy.kill()
            err = proxy.communicate()[1]
        check("no panics in proxy log", "panicked" not in err, err[-2000:])
        if failures:
            print("--- proxy stderr ---\n" + err[-4000:])
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
