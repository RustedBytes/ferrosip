#!/usr/bin/env python3
"""End-to-end checks for `cfg.reload` (Phase 13): the routing script is
re-read and swapped while ferrosip runs. Checked:
- new requests use the new routes;
- a transaction armed with a failure_route before the reload runs that
  route's *new* body, by name, even though route order and count changed;
- changing loadmodule/modparam is refused with the difference;
- a script with an error is refused, and the old script keeps running.

Run from the repo root after `cargo build --release`.
"""
import json, os, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_routing import Peer, make_reply, first  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY, CALLER, UAS = 7500, 7599, 7501
SOCK = os.path.join(ROOT, "target/e2e_reload.sock")
CFG = os.path.join(ROOT, "target/e2e_reload.cfg")

HEAD = """
loadmodule "tm"
loadmodule "sl"
modparam("tm", "fr_timer", 3000)
"""

V1 = HEAD + f"""
request_route {{
    if ($rU == "slow") {{ t_on_failure("B"); t_relay("udp:127.0.0.1:{UAS}"); exit; }}
    sl_send_reply(200, "v1");
}}
failure_route[A] {{ t_reply(500, "A v1"); }}
failure_route[B] {{ t_reply(599, "B v1"); }}
"""

V2 = HEAD + f"""
request_route {{
    if ($rU == "slow") {{ t_on_failure("B"); t_relay("udp:127.0.0.1:{UAS}"); exit; }}
    route(NEW);
}}
route[NEW] {{ sl_send_reply(200, "v2"); }}
failure_route[C] {{ t_reply(500, "C v2"); }}
failure_route[B] {{ t_reply(599, "B v2"); }}
"""

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def msg(user):
    seq[0] += 1
    return (f"MESSAGE sip:{user}@127.0.0.1:{PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch=z9hG4bKr{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: <sip:c@x>;tag=c{seq[0]}\r\nTo: <sip:{user}@x>\r\nCall-ID: rl-{seq[0]}-{time.time_ns()}\r\n"
            f"CSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n").encode()


def ctl(*args):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, *args], capture_output=True, text=True, timeout=5)
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return (out.stdout + out.stderr).strip()


def main():
    open(CFG, "w").write(V1)
    caller, uas = Peer(CALLER), Peer(UAS)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", CFG, "-l", f"udp:127.0.0.1:{PROXY}", "-n", "2", "--rpc-socket", SOCK],
                         stderr=subprocess.PIPE, text=True)
    err = []
    threading.Thread(target=lambda: err.extend(p.stderr), daemon=True).start()
    try:
        end = time.time() + 5
        while time.time() < end and not any("listening on" in l for l in err):
            time.sleep(0.05)

        def ask(user):
            caller.s.sendto(msg(user), ("127.0.0.1", PROXY))
            return caller.final()

        check("v1 running", first(ask("x")) == "SIP/2.0 200 v1")
        # Arm failure_route[B] (index 1 in v1), then reload while it waits.
        caller.s.sendto(msg("slow"), ("127.0.0.1", PROXY))
        pending = uas.expect("MESSAGE")
        open(CFG, "w").write(V2)
        r = ctl("cfg.reload")
        check("cfg.reload: new script compiled and swapped", isinstance(r, dict) and r.get("failure_routes") == 3 and r.get("routes") == 1, r)
        check("…new requests run the new routes", first(ask("y")) == "SIP/2.0 200 v2")
        if pending:
            uas.s.sendto(make_reply(pending, 486, "Busy"), uas.addr)
        r = caller.final()
        check("…a transaction armed before the reload runs failure_route[B]'s new body", first(r) == "SIP/2.0 599 B v2", first(r))

        open(CFG, "w").write(V2.replace('"fr_timer", 3000', '"fr_timer", 1000'))
        r = ctl("cfg.reload")
        check("changed modparam → refused with the difference", isinstance(r, str) and "restart needed" in r and "fr_timer" in r, r)
        open(CFG, "w").write(V2.replace("route(NEW);", "no_such_function();"))
        r = ctl("cfg.reload")
        check("script error → refused", isinstance(r, str) and "no_such_function" in r, r)
        check("…and the running script is unchanged", first(ask("z")) == "SIP/2.0 200 v2")
    finally:
        p.terminate()
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
        time.sleep(0.1)
        log = "".join(err)
        check("no panics in proxy log", "panicked" not in log, log[-2000:])
        if failures:
            print("--- proxy stderr ---\n" + log[-3000:])
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
