#!/usr/bin/env python3
"""End-to-end checks for the sip-ua engine through its example B2BUA
(crates/sip-ua/examples/b2bua), with independent SIP implementations on
both sides: the Python UAs of tests/sipkit.py, and SIPp's built-in uac/uas
scenarios when `sipp` is installed.

- a call is relayed as two independent dialogs (Call-ID, tags and Via
  branches differ between legs), ACKed end to end and torn down by BYE;
- a busy callee's 486 reaches the caller;
- a caller's CANCEL while ringing cancels the outbound leg: 200 to the
  CANCEL, 487 to the INVITE, and the callee sees the CANCEL;
- a caller over TCP reaches a callee over UDP (the BYE goes back over
  the caller's connection);
- SIPp: 20 calls uac → B2BUA → uas complete.

Run from the repo root after
`cargo build --release -p sip-ua --example b2bua`.
"""
import os, shutil, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sipkit import ROOT, UA, sdp  # noqa: E402

BIN = f"{ROOT}/target/release/examples/b2bua"
B2B, CALLEE, CALLER = 5470, 5480, 5471
FAILS = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'} {name}{': ' + detail if detail and not ok else ''}")
    if not ok:
        FAILS.append(name)


def start_b2bua(listen, target):
    p = subprocess.Popen([BIN, f"udp:127.0.0.1:{listen},tcp:127.0.0.1:{listen}", f"127.0.0.1:{target}"], stderr=subprocess.PIPE, text=True)
    lines = []
    ready = threading.Event()

    def drain():
        for line in p.stderr:
            lines.append(line)
            if "listening on" in line:
                ready.set()

    threading.Thread(target=drain, daemon=True).start()
    if not ready.wait(10):
        p.kill()
        raise RuntimeError("b2bua did not start:\n" + "".join(lines))
    p.lines = lines
    return p


def basic_call():
    callee = UA("bob", CALLEE, ("127.0.0.1", B2B)).auto_answer(ring=True)
    caller = UA("alice", CALLER, ("127.0.0.1", B2B))
    try:
        r, d = caller.call(f"sip:bob@127.0.0.1:{B2B}")
        check("call answered", r is not None and r.code == 200, repr(r))
        if d is None:
            return
        check("2xx carries the callee's SDP", "m=audio 6480" in r.body, r.body)
        time.sleep(0.3)
        inv = next((m for m in callee.received if m.method == "INVITE"), None)
        ack = next((m for m in callee.received if m.method == "ACK"), None)
        check("callee got the INVITE with the caller's SDP", inv is not None and "m=audio 6471" in inv.body)
        check("callee got the ACK", ack is not None)
        if inv is not None:
            check("independent Call-IDs", inv.get("call-id") != d.call_id)
            check("independent From tags", inv.tag("from") != d.local_tag)
            check("independent To tags", d.remote_tag not in (inv.tag("from"), ack.tag("to") if ack else None))
        b = d.bye()
        check("BYE answered 200", b is not None and b.code == 200, repr(b))
        time.sleep(0.3)
        check("callee got the BYE", any(m.method == "BYE" for m in callee.received))
    finally:
        caller.close()
        callee.close()


def tcp_caller():
    callee = UA("bob", CALLEE, ("127.0.0.1", B2B)).auto_answer(ring=True)
    caller = UA("alice", CALLER, ("127.0.0.1", B2B), transport="tcp")
    try:
        r, d = caller.call(f"sip:bob@127.0.0.1:{B2B};transport=tcp")
        check("TCP caller answered", r is not None and r.code == 200, repr(r))
        if d is None:
            return
        time.sleep(0.3)
        inv = next((m for m in callee.received if m.method == "INVITE"), None)
        ack = next((m for m in callee.received if m.method == "ACK"), None)
        check("callee leg is UDP", inv is not None and "SIP/2.0/UDP" in (inv.get("via") or ""))
        # The callee hangs up; the BYE must reach the caller over its TCP connection.
        if inv is not None and ack is not None:
            raw = (f"BYE {inv.get('contact').strip('<>')} SIP/2.0\r\nVia: {callee.via('byeb' + str(time.time_ns()))}\r\n"
                   f"From: {ack.get('to')}\r\nTo: {inv.get('from')}\r\nCall-ID: {inv.get('call-id')}\r\nCSeq: 2 BYE\r\n"
                   f"Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
            callee.send(raw)
            got = caller.request_in("BYE", timeout=4)
            check("BYE relayed to the TCP caller", got is not None)
            if got is not None:
                caller.respond(got, 200)
    finally:
        caller.close()
        callee.close()


def busy():
    callee = UA("bob", CALLEE, ("127.0.0.1", B2B)).auto_answer(code=486, reason="Busy Here")
    caller = UA("alice", CALLER, ("127.0.0.1", B2B))
    try:
        r, d = caller.call(f"sip:bob@127.0.0.1:{B2B}")
        check("busy callee: caller gets 486", r is not None and r.code == 486 and d is None, repr(r))
    finally:
        caller.close()
        callee.close()


def cancel():
    callee = UA("bob", CALLEE, ("127.0.0.1", B2B)).auto_answer(code=None, ring=True)
    caller = UA("alice", CALLER, ("127.0.0.1", B2B))
    try:
        sent = caller.invite(f"sip:bob@127.0.0.1:{B2B}", body=sdp(6471))
        ring = caller.recv(4, lambda m: m.is_reply and m.code == 180)
        check("ringing relayed", ring is not None)
        caller.cancel(sent)
        c = caller.recv(4, lambda m: m.is_reply and m.cseq_method == "CANCEL")
        f = caller.final(4, method="INVITE", call_id=sent["call_id"])
        check("CANCEL answered 200", c is not None and c.code == 200, repr(c))
        check("INVITE answered 487", f is not None and f.code == 487, repr(f))
        if f is not None:
            caller._ack_neg(sent, f)
        time.sleep(0.5)
        check("callee got the CANCEL", any(m.method == "CANCEL" for m in callee.received))
    finally:
        caller.close()
        callee.close()


def sipp():
    exe = shutil.which("sipp")
    if exe is None:
        print("SKIP SIPp interop (sipp not installed)")
        return
    uas = subprocess.Popen([exe, "-sn", "uas", "-i", "127.0.0.1", "-p", str(CALLEE), "-nostdin", "-bg"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    try:
        uac = subprocess.run(
            [exe, "-sn", "uac", f"127.0.0.1:{B2B}", "-i", "127.0.0.1", "-p", str(CALLER), "-m", "20", "-r", "10", "-d", "200",
             "-nostdin", "-timeout", "30s", "-timeout_error", "-trace_err"],
            capture_output=True, text=True, timeout=60)
        check("SIPp: 20 calls through the B2BUA", uac.returncode == 0, uac.stdout[-2000:] + uac.stderr[-2000:])
    finally:
        uas.kill()
        subprocess.run(["pkill", "-f", f"sipp -sn uas -i 127.0.0.1 -p {CALLEE}"], check=False)


def main():
    if not os.path.exists(BIN):
        print(f"FAIL {BIN} missing: cargo build --release -p sip-ua --example b2bua")
        return 1
    p = start_b2bua(B2B, CALLEE)
    try:
        basic_call()
        tcp_caller()
        busy()
        cancel()
        sipp()
    finally:
        p.terminate()
        p.wait(5)
    print(f"{'FAIL' if FAILS else 'OK'}: {len(FAILS)} failed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
