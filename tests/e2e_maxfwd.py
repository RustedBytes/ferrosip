#!/usr/bin/env python3
"""End-to-end checks for the maxfwd module:
- `mf_process_maxfwd_header(max)` decrements Max-Forwards, inserts it when
  missing with the argument; an existing value is capped by `max_limit`
  only (Kamailio's process_maxfwd_header());
- 0 gets 483, a malformed value is refused too (`if (!mf_process…)`),
  with Kamailio's return codes (-1, -2);
- `is_maxfwd_lt(n)` and its codes (-2 without the header), also as
  `mf_lowlimit(n)`.

Run from the repo root after `cargo build --release`.
"""
import os, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY, CALLER, UAS = 7581, 7582, 7583

CFG = f"""
loadmodule "tm"
loadmodule "sl"
loadmodule "maxfwd"
loadmodule "textops"
modparam("maxfwd", "max_limit", 30)
request_route {{
    if ruri_user_prefix("lt") {{
        is_maxfwd_lt(5);
        $var(rc) = $rc;
        sl_send_reply(200, "rc=$var(rc)");
        exit;
    }}
    if ruri_user_prefix("low") {{
        mf_lowlimit(5);
        $var(rc) = $rc;
        sl_send_reply(200, "rc=$var(rc)");
        exit;
    }}
    if ruri_user_prefix("small") {{
        process_maxfwd(5);
        $var(rc) = $rc;
        append_hdr("X-Rc: $var(rc)\r\n");
        t_relay("udp:127.0.0.1:{UAS}");
        exit;
    }}
    if (!mf_process_maxfwd_header(50)) {{
        $var(rc) = $rc;
        sl_send_reply(483, "Too Many Hops rc=$var(rc)");
        exit;
    }}
    $var(rc) = $rc;
    append_hdr("X-Rc: $var(rc)\\r\\n");
    t_relay("udp:127.0.0.1:{UAS}");
}}
"""

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def sock(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(2)
    return s


def req(user, mf):
    seq[0] += 1
    line = f"Max-Forwards: {mf}\r\n" if mf is not None else ""
    return (f"MESSAGE sip:{user}@127.0.0.1:{PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch=z9hG4bKmf{seq[0]}x{time.time_ns()}\r\n"
            f"{line}From: <sip:c@x>;tag=m{seq[0]}\r\nTo: <sip:{user}@x>\r\nCall-ID: mf{seq[0]}-{time.time_ns()}\r\nCSeq: 1 MESSAGE\r\n"
            "Content-Length: 0\r\n\r\n").encode()


def recv(s):
    try:
        return s.recvfrom(65535)
    except socket.timeout:
        return None, None


def hdr(m, name):
    for l in m.decode().split("\r\n"):
        if l.lower().startswith(name.lower() + ":"):
            return l.split(":", 1)[1].strip()
    return None


def reply_to(m, code):
    keep = [l for l in m.decode().split("\r\n\r\n")[0].split("\r\n")[1:] if l.split(":")[0] in ("Via", "From", "To", "Call-ID", "CSeq")]
    return (f"SIP/2.0 {code} OK\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n").encode()


def main():
    caller, uas = sock(CALLER), sock(UAS)
    cfg = os.path.join(ROOT, "target/e2e_maxfwd.cfg")
    open(cfg, "w").write(CFG)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY}", "-n", "1"],
                         stderr=subprocess.PIPE, text=True)
    try:
        wait_listening(p)

        def relayed(mf, user="r"):
            caller.sendto(req(user, mf), ("127.0.0.1", PROXY))
            d, a = recv(uas)
            if d:
                uas.sendto(reply_to(d, 200), a)
                recv(caller)
            return d

        d = relayed(10)
        check("Max-Forwards 10 → 9, rc 1", d is not None and hdr(d, "Max-Forwards") == "9" and hdr(d, "X-Rc") == "1", d)
        d = relayed(None)
        check("missing → inserted with the argument (as in Kamailio, max_limit doesn't apply), rc 2",
              d is not None and hdr(d, "Max-Forwards") == "50" and hdr(d, "X-Rc") == "2", d)
        d = relayed(200)
        check("max_limit 30: 200 → 30", d is not None and hdr(d, "Max-Forwards") == "30", d)
        d = relayed(20, "small")
        check("process_maxfwd(5): 20 → 19 (the argument is only for a missing header)", d is not None and hdr(d, "Max-Forwards") == "19", d)
        caller.sendto(req("low", 3), ("127.0.0.1", PROXY))
        r, _ = recv(caller)
        check("mf_lowlimit(5) (is_maxfwd_lt) with 3 → rc=1", r is not None and r.decode().startswith("SIP/2.0 200 rc=1"), r)
        for mf, want in (("0", "SIP/2.0 483 Too Many Hops rc=-1"), ("abc", "SIP/2.0 483 Too Many Hops rc=-2")):
            caller.sendto(req("r", mf), ("127.0.0.1", PROXY))
            r, _ = recv(caller)
            first = r.decode().split("\r\n")[0] if r else None
            check(f"Max-Forwards {mf!r} → refused ({want[8:]})", first == want, first)
        for mf, want in ((3, "rc=1"), (5, "rc=-1"), (None, "rc=-2"), ("x", "rc=-3")):
            caller.sendto(req("lt", mf), ("127.0.0.1", PROXY))
            r, _ = recv(caller)
            first = r.decode().split("\r\n")[0] if r else None
            check(f"is_maxfwd_lt(5) with {mf!r} → {want}", first == f"SIP/2.0 200 {want}", first)
    finally:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
        log = p.early_log + (p.stderr.read() if p.stderr else "")
        check("no panics in proxy log", "panicked" not in log, log[-2000:])
        if failures:
            print("--- proxy stderr ---\n" + log[-4000:])
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
