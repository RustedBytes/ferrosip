#!/usr/bin/env python3
"""Graceful shutdown (SIGTERM/SIGINT).

1. Drain: with an INVITE in flight, SIGTERM makes the proxy answer new
   INVITEs 503 + Retry-After, refuse new TCP connections, still forward the
   pending call's 200, then exit 0 promptly and remove its control socket.
2. Timeout: an INVITE that never gets answered doesn't hold the exit beyond
   --shutdown-timeout; the proxy reports it as unfinished.
3. A second signal exits at once.
Run from the repo root after `cargo build --release`.
"""
import os, signal, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY, UAS, CALLER = 7400, 7410, 7499
SOCK = os.path.join(ROOT, "target/e2e_shutdown.sock")
CFG = f"""loadmodule "tm"
modparam("tm", "fr_inv_timer", 30000)
request_route {{ t_relay("udp:127.0.0.1:{UAS}"); }}
"""
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def invite(call_id):
    return (f"INVITE sip:bob@127.0.0.1:{PROXY} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP 127.0.0.1:{CALLER};branch=z9hG4bK{call_id}\r\n"
            "Max-Forwards: 70\r\nFrom: <sip:alice@x>;tag=a1\r\nTo: <sip:bob@x>\r\n"
            f"Call-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n").encode()


def reply_to(req, code, reason):
    lines = req.decode().split("\r\n")
    keep = [l for l in lines if l.split(":", 1)[0].lower() in ("via", "from", "call-id", "cseq")]
    to = next(l for l in lines if l.lower().startswith("to:"))
    return (f"SIP/2.0 {code} {reason}\r\n" + "\r\n".join(keep) + f"\r\n{to};tag=u1\r\nContent-Length: 0\r\n\r\n").encode()


def recv(s, timeout=2.0, want=None):
    """Next datagram whose first line starts with `want` (skipping 100s)."""
    end = time.time() + timeout
    while time.time() < end:
        s.settimeout(max(0.05, end - time.time()))
        try:
            d = s.recvfrom(65535)[0]
        except socket.timeout:
            return None
        if want is None or d.startswith(want.encode()):
            return d
    return None


def invite_for(s, call_id, timeout=2.0):
    """The INVITE for `call_id` (skipping retransmissions of earlier calls)."""
    end = time.time() + timeout
    while time.time() < end:
        m = recv(s, max(0.05, end - time.time()), want="INVITE")
        if m is None or f"Call-ID: {call_id}".encode() in m:
            return m
    return None


def drain(*socks):
    for s in socks:
        while recv(s, 0.05) is not None:
            pass


def start(timeout_s):
    cfg = os.path.join(ROOT, "target/e2e_shutdown.cfg")
    open(cfg, "w").write(CFG)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY}", "-l", f"tcp:127.0.0.1:{PROXY}",
                          "-n", "2", "--rpc-socket", SOCK, "--shutdown-timeout", str(timeout_s)],
                         stderr=subprocess.PIPE, text=True)
    wait_listening(p)
    return p


def finish(p, timeout):
    t0 = time.time()
    try:
        rc = p.wait(timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        rc = p.wait()
    return rc, time.time() - t0, p.early_log + p.stderr.read()


def main():
    uas = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    uas.bind(("127.0.0.1", UAS))
    caller = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    caller.bind(("127.0.0.1", CALLER))

    # 1. Drain with a call in flight.
    p = start(4)
    caller.sendto(invite("call-a"), ("127.0.0.1", PROXY))
    ia = invite_for(uas, "call-a")
    check("INVITE A forwarded before the signal", ia is not None)
    p.send_signal(signal.SIGTERM)
    time.sleep(0.3)
    caller.sendto(invite("call-b"), ("127.0.0.1", PROXY))
    r = recv(caller, want="SIP/2.0 503")
    check("new INVITE while draining → 503 with Retry-After", r is not None and b"\r\nRetry-After: " in r, r)
    leaked = [m for m in iter(lambda: recv(uas, 0.3, want="INVITE"), None) if b"call-b" in m]
    check("…and it isn't forwarded (only A's retransmissions reach the UAS)", not leaked, leaked[:1])
    t = socket.create_connection(("127.0.0.1", PROXY), timeout=2)
    t.settimeout(2)
    try:
        refused = t.recv(1) == b""
    except OSError:
        refused = True
    t.close()
    check("new TCP connections refused while draining", refused)
    check("still running while A is unanswered", p.poll() is None)
    uas.sendto(reply_to(ia, 200, "OK"), ("127.0.0.1", PROXY))
    ok = recv(caller, want="SIP/2.0 200")
    check("pending call's 200 still forwarded during the drain", ok is not None and b"call-a" in ok, ok)
    rc, dt, log = finish(p, 6)
    check("exits 0 soon after the last transaction finished", rc == 0 and dt < 2, (rc, round(dt, 2), log[-300:]))
    check("control socket removed", not os.path.exists(SOCK))
    check("log says stopped", "ferrosip: stopped" in log and "unfinished" not in log, log[-300:])

    # 2. A transaction that never finishes doesn't hold the exit.
    drain(uas, caller)
    p = start(2)
    caller.sendto(invite("call-c"), ("127.0.0.1", PROXY))
    check("INVITE C forwarded", invite_for(uas, "call-c") is not None)
    t0 = time.time()
    p.send_signal(signal.SIGTERM)
    rc, _, log = finish(p, 6)
    dt = time.time() - t0
    check("unanswered transaction: exit 0 after --shutdown-timeout", rc == 0 and 1.8 < dt < 3.5, (rc, round(dt, 2)))
    check("…reported as unfinished", "1 transaction(s) unfinished" in log, log[-300:])

    # 3. A second signal exits at once.
    drain(uas, caller)
    p = start(10)
    caller.sendto(invite("call-d"), ("127.0.0.1", PROXY))
    check("INVITE D forwarded", invite_for(uas, "call-d") is not None)
    p.send_signal(signal.SIGTERM)
    time.sleep(0.3)
    t0 = time.time()
    p.send_signal(signal.SIGINT)
    rc, _, log = finish(p, 5)
    check("second signal exits immediately", rc == 1 and time.time() - t0 < 1.5, (rc, round(time.time() - t0, 2)))
    check("no panics", "panicked" not in log, log[-500:])

    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
