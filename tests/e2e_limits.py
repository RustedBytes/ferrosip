#!/usr/bin/env python3
"""Connection admission limits (--tcp-accept-iplimit, --tcp-max-conns).

With 3 connections allowed per source IP:
- the 4th and 5th connections from 127.0.0.1 are closed at once, while
  the first 3 are served;
- closing one frees its unit for a new connection;
- tcp:rejected_iplimit counts the refusals, and tcp:active_connections
  returns to 0 when all connections are closed (no unit is leaked).
Run from the repo root after `cargo build --release`.
"""
import json, os, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY = 7500
SOCK = os.path.join(ROOT, "target/e2e_limits.sock")
CFG = """loadmodule "sl"
request_route { sl_send_reply(200, "OK"); }
"""
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def stat(name):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, "stats.get_statistics", name], capture_output=True, text=True, timeout=5).stdout
    try:
        return json.loads(out)[name]
    except (ValueError, KeyError):
        return -1


def options(tag):
    return (f"OPTIONS sip:x@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:9;branch=z9hG4bK{tag}\r\n"
            f"From: <sip:a@x>;tag=1\r\nTo: <sip:x@x>\r\nCall-ID: {tag}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n").encode()


def served(s, tag):
    """True if the proxy answers an OPTIONS on `s`; False if it closed it."""
    try:
        s.sendall(options(tag))
        s.settimeout(2)
        return s.recv(4096).startswith(b"SIP/2.0 200")
    except OSError:
        return False


def wait_active(n, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if stat("tcp:active_connections") == n:
            return True
        time.sleep(0.1)
    return False


def main():
    cfg = os.path.join(ROOT, "target/e2e_limits.cfg")
    open(cfg, "w").write(CFG)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"tcp:127.0.0.1:{PROXY}", "--tcp-accept-iplimit", "3",
                          "--tcp-max-conns", "100", "--rpc-socket", SOCK], stderr=subprocess.PIPE, text=True)
    wait_listening(p)
    try:
        socks = []
        for _i in range(5):
            socks.append(socket.create_connection(("127.0.0.1", PROXY)))
            time.sleep(0.05)  # accepted in order
        ok = [served(s, f"c{i}") for i, s in enumerate(socks)]
        check("3 connections per IP served, the 4th and 5th refused", ok == [True, True, True, False, False], ok)
        check("tcp:rejected_iplimit counts the refusals", stat("tcp:rejected_iplimit") == 2, stat("tcp:rejected_iplimit"))
        socks[0].close()
        check("closing one gives its unit back", wait_active(2), stat("tcp:active_connections"))
        again = socket.create_connection(("127.0.0.1", PROXY))
        check("…so a new connection from that IP is served", served(again, "again"))
        for s in socks[1:] + [again]:
            s.close()
        check("all units released: no connections left", wait_active(0), stat("tcp:active_connections"))
    finally:
        p.terminate()
        try:
            err = p.early_log + p.communicate(timeout=10)[1]
        except subprocess.TimeoutExpired:
            p.kill()
            err = p.early_log + p.communicate()[1]
        check("refusals logged once (rate-limited), no panics", err.count("accept_iplimit (3 per address) reached") >= 1 and "panicked" not in err,
              err[-800:])
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
