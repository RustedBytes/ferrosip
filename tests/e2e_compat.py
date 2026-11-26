#!/usr/bin/env python3
"""Kamailio config compatibility, end to end.

1. Kamailio's stock etc/kamailio.cfg (vendored in tests/compat/kamailio,
   unmodified) runs as is: OPTIONS to the server gets "200 Keepalive",
   REGISTER is saved, an INVITE to an unknown user gets 404, a MESSAGE to
   the registered user is relayed to its contact and the answer comes
   back, and a retransmitted MESSAGE is absorbed by t_check_trans().
2. A script using the compatibility features added for Kamailio configs:
   #!define / #!ifdef / --define, custom cfg vars with $sel(cfg_get.…) and
   cfg.set_now_string, @selects, strip/prefix/rewritehost, (int) casts,
   `mod`, binary `|`, `+` in arguments, $msg(len), re.subst, exec_dset,
   counters, dlgs and msg_apply_changes.
3. `ferrosip import`: both run again from their import (ferrosip.toml +
   routes/main.fsr, with the same defines) and must behave the same. With
   WITH_VOICEMAIL, WITH_BLOCK3XX and WITH_BLOCK401407, failure_route
   [MANAGE_FAILURE]'s t_check_status tests import as named `txn.code`
   comparisons, its `t_reply(…); exit;` as `reply(NotFound, "Not found")`,
   onreply_route[MANAGE_REPLY]'s `status =~ "[12][0-9][0-9]"` as
   `msg.code in 100..299`, setflag(FLT_ACC) as `msg.set(FLT_ACC)` with
   `flag FLT_ACC = 1`, xlog as `log.error` / `log.info`, and the import
   passes `lint --fix` then `lint -D warnings`.
Run from the repo root after `cargo build --release`.
"""
import json, os, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = f"{ROOT}/target/release/ferrosip"
CTL = f"{ROOT}/target/release/ferroctl"
KCFG = f"{ROOT}/tests/compat/kamailio/etc/kamailio.cfg"
PROXY, UA = 7600, 7601
SOCK = os.path.join(ROOT, "target/e2e_compat.sock")
failures = 0
LABEL = ""  # "imported: " for the runs from `ferrosip import`'s output


def check(name, cond, detail=""):
    global failures
    name = LABEL + name
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def start(args):
    p = subprocess.Popen([BIN] + args, stderr=subprocess.PIPE, text=True)
    wait_listening(p)
    return p


def stop(p):
    p.terminate()
    try:
        return p.early_log + p.communicate(timeout=10)[1]
    except subprocess.TimeoutExpired:
        p.kill()
        return p.early_log + p.communicate()[1]


def ctl(*args):
    out = subprocess.run([CTL, "-s", SOCK, *args], capture_output=True, text=True, timeout=5).stdout
    try:
        return json.loads(out)
    except ValueError:
        return out


class Ua:
    def __init__(self, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.port = port

    def send(self, msg):
        self.s.sendto(msg.encode(), ("127.0.0.1", PROXY))

    def recv(self, timeout=2.0):
        self.s.settimeout(timeout)
        try:
            return self.s.recv(65535).decode()
        except socket.timeout:
            return None

    def reply(self, timeout=2.0):
        """The first final reply received (requests are skipped)."""
        end = time.time() + timeout
        while time.time() < end:
            m = self.recv(max(0.05, end - time.time()))
            if m is None:
                return None
            if m.startswith("SIP/2.0 ") and not m.startswith("SIP/2.0 1"):
                return m
        return None

    def final(self, timeout=2.0):
        """The first non-1xx reply (or request) received."""
        end = time.time() + timeout
        while time.time() < end:
            m = self.recv(max(0.05, end - time.time()))
            if m is None:
                return None
            if not m.startswith("SIP/2.0 1"):
                return m
        return None


def req(method, ruri, branch, to="x", extra="", body=""):
    return (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UA};branch=z9hG4bK{branch};rport\r\n"
            f"From: <sip:alice@127.0.0.1>;tag=a{branch}\r\nTo: <sip:{to}@127.0.0.1>\r\nCall-ID: {branch}\r\n"
            f"CSeq: 1 {method}\r\nMax-Forwards: 70\r\n{extra}Content-Length: {len(body)}\r\n\r\n{body}")


def first_line(m):
    return m.split("\r\n", 1)[0] if m else None


def answer(m, code="200 OK"):
    """A reply to request `m` (copies Via/From/To/Call-ID/CSeq)."""
    keep = [h for h in m.split("\r\n")[1:] if h.split(":", 1)[0].lower() in ("via", "from", "to", "call-id", "cseq")]
    return f"SIP/2.0 {code}\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n"


def imported(cfg, defines, name):
    """`ferrosip import` the config; the ferrosip.toml to run, or None."""
    out = os.path.join(ROOT, "target", f"e2e_compat_import_{name}")
    args = [BIN, "import", cfg, "-o", out, "--force"]
    for d in defines:
        args += ["--define", d]
    r = subprocess.run(args, capture_output=True, text=True, timeout=60)
    ok = r.returncode == 0 and "config OK" in r.stderr
    check(f"import {name}: imports and passes ferrosip check", ok, r.stderr[-800:])
    return os.path.join(out, "ferrosip.toml") if ok else None


def stock_failure_codes():
    """The stock config's t_check_status tests (behind defines) as `txn.code`."""
    for defines in (["WITH_VOICEMAIL", "WITH_BLOCK3XX", "WITH_BLOCK401407"], ["ACTIVE", "WITH_VOICEMAIL", "WITH_BLOCK3XX", "WITH_BLOCK401407"]):
        name = "stock_" + "_".join(d.lower() for d in defines[:2])
        toml = imported(KCFG, defines, name)
        if not toml:
            continue
        text = open(os.path.join(os.path.dirname(toml), "routes", "main.fsr")).read()
        # failure_route[MANAGE_FAILURE] runs after `await txn.relay` in route(RELAY).
        fr = text[text.find("fn manage_failure(msg: Request) {"):]
        fr = fr[:fr.find("\n}\n")]
        check(f"import {name}: route(RELAY)'s t_on_failure + t_relay is `await txn.relay` + match, MANAGE_FAILURE a function",
              "    if msg.method == INVITE {\n        let res = await txn.relay(msg)\n        match res {\n"
              "            Final(r) if !r.sent => stateless.reply_error_and_continue()\n            Final(r) if r.code < 300 => {}\n"
              "            _ => manage_failure(msg)\n        }\n        exit\n    }\n" in text
              and "t_on_failure" not in text and '"failure_route"' not in text and "kamailio.failure_route" not in text
              and "// failure_route[MANAGE_FAILURE]: runs after `await txn.relay`" in text, text)
        check(f"import {name}: MANAGE_FAILURE tests txn.code by name",
              "if txn.code in 300..399 {" in fr and "if txn.code == Unauthorized || txn.code == ProxyAuthenticationRequired {" in fr
              and "if txn.code == BusyHere || txn.code == RequestTimeout {" in fr and "status_is" not in fr, fr)
        check(f"import {name}: MANAGE_FAILURE's t_reply + exit is a named reply() with its reason as written",
              fr.count('reply(NotFound, "Not found")') == 2 and "t_reply" not in fr, fr)
        mr = text[text.find('name: "MANAGE_REPLY"'):]
        mr = mr[:mr.find("\n}\n")]
        check(f"import {name}: MANAGE_REPLY's status =~ \"[12][0-9][0-9]\" is a msg.code range",
              "if msg.code in 100..299 {" in mr and "=~" not in mr, mr)
        check(f"import {name}: flags are declared at their #!define's bit and used by name",
              "flag FLT_ACC = 1\nflag FLT_ACCMISSED = 2\nflag FLT_ACCFAILED = 3\nflag FLT_NATS = 5\n" in text
              and "msg.set(FLT_ACC)\n" in text and "msg.set(FLT_ACCMISSED)" in text and "if msg.is(FLT_NATS) {" in text
              and '"setflag"' not in text and '"isflagset"' not in text, text)
        check(f"import {name}: xlog is log.*, $sp / $hdr(Event) are msg fields, numbers as text are Ints",
              '"xlog"' not in text and 'log.error("Malformed SIP request from {msg.src.ip}:{msg.src.port}\\n")' in text
              and "if !sip.process(10) {" in text and "if !sip.check(17895, 7) {" in text and "if !sip.check(17604, 6) {" in text
              and 'msg.headers["Event"] == "message-summary"' in text, text)
        check(f"import {name}: branch flags, force_rport / set_reply_no_connect and send_reply_error as a statement are typed",
              "branch flag FLB_NATB = 6\n" in text and "msg.set(FLB_NATB)\n" in text and '"setbflag"' not in text
              and "    sip.reply_no_connect()\n    sip.force_rport()\n" in text
              and text.count("stateless.reply_error_and_continue()\n") == 3 and '"send_reply_error"' not in text, text)
        fix = subprocess.run([BIN, "lint", "--fix", "--config", toml], capture_output=True, text=True, timeout=60)
        lint = subprocess.run([BIN, "lint", "--config", toml, "-D", "warnings"], capture_output=True, text=True, timeout=60)
        check(f"import {name}: lint --fix, then lint -D warnings passes", fix.returncode == 0 and lint.returncode == 0, fix.stderr[-500:] + lint.stderr[-800:])


def stock_kamailio_cfg(source=None):
    base = ["-f", KCFG, "--define", "ACTIVE"] if source is None else ["--config", source]
    p = start(base + ["-l", f"udp:127.0.0.1:{PROXY}"])
    ua = Ua(UA)
    try:
        ua.send(req("OPTIONS", f"sip:127.0.0.1:{PROXY}", "o1"))
        check("kamailio.cfg: OPTIONS to the server -> 200 Keepalive", first_line(ua.final()) == "SIP/2.0 200 Keepalive")
        ua.send(req("REGISTER", "sip:127.0.0.1", "r1", to="alice", extra=f"Contact: <sip:alice@127.0.0.1:{UA}>\r\nExpires: 60\r\n"))
        r = ua.final()
        check("kamailio.cfg: REGISTER saved (200 with the contact)", r and r.startswith("SIP/2.0 200") and f"127.0.0.1:{UA}" in r, r)
        ua.send(req("INVITE", "sip:bob@127.0.0.1", "i1", to="bob", extra=f"Contact: <sip:alice@127.0.0.1:{UA}>\r\n"))
        r = ua.final()
        check("kamailio.cfg: INVITE to an unknown user -> 404", first_line(r) == "SIP/2.0 404 Not Found", r)
        if r:
            to = next(h for h in r.split("\r\n") if h.lower().startswith("to:"))
            ua.send(f"ACK sip:bob@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UA};branch=z9hG4bKi1;rport\r\n"
                    f"From: <sip:alice@127.0.0.1>;tag=ai1\r\n{to}\r\nCall-ID: i1\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n")
            check("kamailio.cfg: the ACK is not answered", ua.recv(0.3) is None)
        msg = req("MESSAGE", "sip:alice@127.0.0.1", "m1", to="alice", extra="Content-Type: text/plain\r\n", body="hi")
        ua.send(msg)
        fwd = ua.final()
        check("kamailio.cfg: MESSAGE relayed to the registered contact", first_line(fwd) == f"MESSAGE sip:alice@127.0.0.1:{UA} SIP/2.0", fwd)
        if fwd:
            branch = lambda m: m.split("branch=", 1)[1].split(";", 1)[0].split("\r\n", 1)[0]
            ua.send(msg)  # retransmission while pending: absorbed, not relayed again
            again = ua.recv(0.3)
            # (tm's own retransmission of the relayed MESSAGE has the same branch)
            check("kamailio.cfg: retransmission absorbed (t_check_trans)", again is None or branch(again) == branch(fwd), first_line(again))
            ua.s.sendto(answer(fwd).encode(), ("127.0.0.1", PROXY))
            r = ua.reply()
            check("kamailio.cfg: the 200 comes back to the sender", r and r.startswith("SIP/2.0 200") and "branch=z9hG4bKm1" in r, r)
    finally:
        err = stop(p)
        ua.s.close()
    check("kamailio.cfg: no panics or script errors", "panicked" not in err and "ERROR" not in err, err[-600:])


SCRIPT = r'''#!define GW "127.0.0.1"
#!ifdef WITH_PREFIX
#!define PFX "+49"
#!else
#!define PFX "00"
#!endif
loadmodule "sl"
loadmodule "tm"
loadmodule "textops"
loadmodule "textopsx"
loadmodule "exec"
loadmodule "counters"
loadmodule "dlgs"
loadmodule "xlog"
modparam("counters", "script_counter", "calls")
modparam("tm", "auto_inv_100", 0)

gw.host = "gw.invalid" desc "Gateway host"

request_route {
    if (is_method("OPTIONS")) {
        cnt_inc("calls");
        $var(n) = (int)"41" + 1;
        $var(m) = 17 mod 5;
        $var(b) = 4 | 1;
        sl_send_reply("200", "n=" + $var(n) + " m=" + $var(m) + " b=" + $var(b) + " len=" + $msg(len));
        exit;
    }
    if ($rU == "cfg") {
        sl_send_reply("200", "gw=" + $sel(cfg_get.gw.host) + " tag=" + @from.tag);
        exit;
    }
    if ($rU =~ "^uri") {
        strip(2);
        prefix(PFX);
        rewritehost(GW);
        $var(u) = $(ru{re.subst,/;transport=[a-z]+//g});
        sl_send_reply("200", $var(u));
        exit;
    }
    if ($rU == "dset") {
        exec_dset("echo sip:exec@127.0.0.1;:");
        sl_send_reply("200", $ru);
        exit;
    }
    if ($rU == "apply") {
        append_hf("X-Added: yes\r\n");
        msg_apply_changes();
        if ($hdr(X-Added) == "yes") { sl_send_reply("200", "applied"); } else { sl_send_reply("500", "not applied"); }
        exit;
    }
    if (is_method("INVITE")) {
        dlgs_init("$fu", "$tu", "x");
        sl_send_reply("200", "dlgs=" + $var(x));
        exit;
    }
    sl_send_reply("404", "Not Found");
}
'''


def compat_script(source=None):
    cfg = os.path.join(ROOT, "target/e2e_compat.cfg")
    if source is None:
        open(cfg, "w").write(SCRIPT)
        chk = subprocess.run([BIN, "-c", "-f", cfg], capture_output=True, text=True, timeout=10)
        check("-c accepts the script", "config OK" in chk.stderr, chk.stderr[-400:])
        bad = os.path.join(ROOT, "target/e2e_compat_bad.cfg")
        open(bad, "w").write('loadmodule "sl"\nrequest_route {\n  sl_send_reply("200", $sel(cfg_get.nope.x));\n}\n')
        chk = subprocess.run([BIN, "-c", "-f", bad], capture_output=True, text=True, timeout=10)
        check("-c rejects an undeclared cfg var with the line", chk.returncode != 0 and "nope.x" in chk.stderr, chk.stderr[-300:])
    base = ["-f", cfg, "--define", "WITH_PREFIX"] if source is None else ["--config", source]
    p = start(base + ["-l", f"udp:127.0.0.1:{PROXY}", "--rpc-socket", SOCK])
    ua = Ua(UA)
    try:
        o = req("OPTIONS", "sip:x@127.0.0.1", "c1")
        ua.send(o)
        r = first_line(ua.final())
        check("(int) cast, mod, binary |, + in arguments, $msg(len)", r == f"SIP/2.0 200 n=42 m=2 b=5 len={len(o)}", r)
        ua.send(req("MESSAGE", "sip:cfg@127.0.0.1", "c2"))
        check("$sel(cfg_get.gw.host) and @from.tag", first_line(ua.final()) == "SIP/2.0 200 gw=gw.invalid tag=ac2")
        ctl("cfg.set_now_string", "gw", "host", "gw2.invalid")
        ua.send(req("MESSAGE", "sip:cfg@127.0.0.1", "c3"))
        check("cfg.set_now_string changes it at runtime", first_line(ua.final()) == "SIP/2.0 200 gw=gw2.invalid tag=ac3")
        ua.send(req("MESSAGE", "sip:uri0123@example.com;transport=udp", "c4"))
        r = first_line(ua.final())
        check("strip / prefix (#!ifdef via --define) / rewritehost / re.subst", r == "SIP/2.0 200 sip:+49i0123@127.0.0.1", r)
        ua.send(req("MESSAGE", "sip:dset@127.0.0.1", "c5"))
        r = first_line(ua.final())
        check("exec_dset: command output becomes the R-URI", r == "SIP/2.0 200 sip:exec@127.0.0.1", r)
        ua.send(req("MESSAGE", "sip:apply@127.0.0.1", "c6"))
        r = first_line(ua.final())
        check("msg_apply_changes: later reads see added headers", r == "SIP/2.0 200 applied", r)
        ua.send(req("INVITE", "sip:bob@127.0.0.1", "c7"))
        ua.final()
        st = ctl("dlgs.stats")
        check("dlgs_init tracks the INVITE", isinstance(st, dict) and st.get("all", st.get("active", 0)) >= 1, st)
        stats = ctl("stats.get_statistics", "script:calls")
        check("counters: cnt_inc counted the OPTIONS", isinstance(stats, dict) and stats.get("script:calls") == 1, stats)
    finally:
        err = stop(p)
        ua.s.close()
    check("script: no panics", "panicked" not in err, err[-600:])


def main():
    stock_kamailio_cfg()
    compat_script()
    # The same traffic through `ferrosip import`'s ferrosip.toml + .fsr.
    global LABEL
    LABEL = "imported: "
    toml = imported(KCFG, ["ACTIVE"], "stock")
    if toml:
        stock_kamailio_cfg(toml)
    toml = imported(os.path.join(ROOT, "target/e2e_compat.cfg"), ["WITH_PREFIX"], "script")
    if toml:
        compat_script(toml)
    stock_failure_codes()
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
