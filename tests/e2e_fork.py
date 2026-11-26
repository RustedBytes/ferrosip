#!/usr/bin/env python3
"""End-to-end checks for tm forking (RFC 3261 §16.6/§16.7).

Two proxies: one forks in parallel, one serially by q-value (fork_by_q).
Three scripted user agents (A, B, C) and a caller, all raw UDP sockets, so
every INVITE / provisional / CANCEL / ACK on the wire is checked.
Run from the repo root after `cargo build --release`.
"""
import os, socket, subprocess, sys, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAR, SER = 5560, 5561
A, B, C = 5601, 5602, 5603
CFG = """loadmodule "tm"
loadmodule "textops"
modparam("tm", "fr_timer", 1000)
modparam("tm", "fr_inv_timer", 3000)
modparam("tm", "wait_timer", 1500)
modparam("tm", "fork_by_q", FORK_BY_Q)
request_route {
    if ruri_user_prefix("slow") { t_set_fr(5000, 1500); }
    # A script header edit that every branch must carry (lumps regression).
    append_hf("X-Edited: yes\\r\\n");
    append_branch("sip:b@127.0.0.1:5602", "0.5");
    append_branch("sip:c@127.0.0.1:5603", "0.1");
    t_relay("udp:127.0.0.1:5601");
}
"""
failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def first(m):
    return m.split(b"\r\n", 1)[0].decode() if m else "timeout"


def hdr(m, name):
    for l in m.split(b"\r\n"):
        if l.lower().startswith(name.lower().encode() + b":"):
            return l.split(b":", 1)[1].strip().decode()
    return ""


class Peer:
    def __init__(self, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.addr = None

    def recv(self, timeout=2.0, skip_retrans=True):
        """Next message (skipping retransmitted INVITEs already seen)."""
        self.s.settimeout(timeout)
        try:
            while True:
                d, a = self.s.recvfrom(65535)
                if d.startswith(b"INVITE") or d.startswith(b"MESSAGE"):
                    self.addr = a
                    key = hdr(d, "Via")
                    if skip_retrans and key in getattr(self, "seen", set()):
                        continue
                    self.seen = getattr(self, "seen", set()) | {key}
                return d
        except socket.timeout:
            return None

    def expect(self, prefix, timeout=2.0):
        """Wait for a message starting with prefix (ignoring retransmissions/others)."""
        end = time.time() + timeout
        while time.time() < end:
            m = self.recv(max(0.05, end - time.time()))
            if m is None:
                return None
            if m.startswith(prefix.encode()):
                return m
        return None

    def reply(self, req, code, reason, extra="", tag=None):
        lines = req.decode().split("\r\n")
        keep = []
        for l in lines:
            name = l.split(":")[0]
            if name == "To" and code > 100:
                l += f";tag={tag or 'ua' + str(self.s.getsockname()[1])}"
            if name in ("Via", "From", "To", "Call-ID", "CSeq"):
                keep.append(l)
        msg = f"SIP/2.0 {code} {reason}\r\n" + "\r\n".join(keep) + "\r\n" + extra + "Content-Length: 0\r\n\r\n"
        self.s.sendto(msg.encode(), self.addr)

    def drain(self):
        self.s.settimeout(0.05)
        try:
            while True:
                self.s.recv(65535)
        except socket.timeout:
            pass
        self.seen = set()


def request(method, user, proxy, branch=None, cseq=1):
    seq[0] += 1
    b = branch or f"z9hG4bKc{seq[0]}x{time.time_ns()}"
    return (f"{method} sip:{user}@127.0.0.1:{proxy} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5600;branch={b}\r\n"
            f"Max-Forwards: 70\r\nFrom: <sip:caller@x>;tag=c1\r\nTo: <sip:{user}@x>\r\nCall-ID: fork-{seq[0]}\r\n"
            f"CSeq: {cseq} {method}\r\nContent-Length: 0\r\n\r\n").encode(), b


def main():
    procs, logs = [], []
    for port, fbq in ((PAR, 0), (SER, 1)):
        cfg = os.path.join(ROOT, f"target/e2e_fork_{fbq}.cfg")
        open(cfg, "w").write(CFG.replace("FORK_BY_Q", str(fbq)))
        p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{port}", "-n", "2", "--rpc-socket", "none"],
                             stderr=subprocess.PIPE, text=True)
        log = []
        # A thread per proxy drains stderr: no blocking readline, no full pipe.
        threading.Thread(target=lambda p=p, log=log: log.extend(p.stderr), daemon=True).start()
        procs.append(p)
        logs.append(log)
    # Wait until both proxies listen (a fixed sleep was flaky under load).
    end = time.time() + 10
    while time.time() < end and not all(any("listening on" in l for l in log) for log in logs):
        time.sleep(0.05)
    caller, a, b, c = Peer(5600), Peer(A), Peer(B), Peer(C)
    uas = (a, b, c)

    def invite(user="par", proxy=PAR, method="INVITE"):
        m, br = request(method, user, proxy)
        caller.s.sendto(m, ("127.0.0.1", proxy))
        return m, br

    def caller_msgs(timeout=1.0):
        out = []
        while True:
            m = caller.recv(timeout)
            if m is None:
                return out
            out.append(first(m))
            timeout = 0.4

    def reset():
        time.sleep(0.1)
        for p in (caller,) + uas:
            p.drain()

    try:
        # 1. Parallel fork; 200 from B cancels ringing A and (after its 180) C.
        invite()
        check("INVITE → 100 Trying from the proxy", first(caller.recv()) == "SIP/2.0 100 Trying")
        ia, ib, ic = a.expect("INVITE"), b.expect("INVITE"), c.expect("INVITE")
        check("parallel: all three branches get the INVITE", all((ia, ib, ic)), [first(x) for x in (ia, ib, ic)])
        check("each branch has its own R-URI and Via branch",
              ia and ib and ic and first(ib).startswith("INVITE sip:b@127.0.0.1:5602") and len({hdr(x, "Via") for x in (ia, ib, ic)}) == 3)
        check("every branch keeps the script's header edit and only its own R-URI",
              ia and ib and ic and all(hdr(x, "X-Edited") == "yes" for x in (ia, ib, ic))
              and first(ia).startswith("INVITE sip:par@") and first(ic).startswith("INVITE sip:c@127.0.0.1:5603 SIP/2.0"),
              [(first(x), hdr(x, "X-Edited")) for x in (ia, ib, ic) if x])
        a.reply(ia, 180, "Ringing")
        check("180 from A forwarded", first(caller.recv()) == "SIP/2.0 180 Ringing")
        b.reply(ib, 200, "OK")
        check("200 from B forwarded", first(caller.recv()) == "SIP/2.0 200 OK")
        ca = a.expect("CANCEL")
        check("A (ringing) gets CANCEL with A's branch", ca is not None and hdr(ca, "Via") == hdr(ia, "Via"), first(ca))
        check("C (no provisional yet) gets no CANCEL yet (§9.1)", c.expect("CANCEL", 0.4) is None)
        c.reply(ic, 180, "Ringing")
        check("…C gets its CANCEL right after its 180", c.expect("CANCEL") is not None)
        a.reply(ca, 200, "OK")
        a.reply(ia, 487, "Request Terminated")
        ack = a.expect("ACK")
        check("A's 487 is ACKed hop-by-hop", ack is not None and hdr(ack, "CSeq") == "1 ACK", first(ack))
        check("caller sees no 487 after the 200", "SIP/2.0 487 Request Terminated" not in caller_msgs(0.6))
        reset()

        # 2. Best response: 486 / 404 / 503 → 486 (4xx, first); each ACKed.
        invite()
        caller.recv()
        ia, ib, ic = a.expect("INVITE"), b.expect("INVITE"), c.expect("INVITE")
        a.reply(ia, 486, "Busy Here")
        b.reply(ib, 404, "Not Found")
        c.reply(ic, 503, "Service Unavailable")
        acks = [p.expect("ACK") is not None for p in uas]
        check("every non-2xx branch ACKed", all(acks), acks)
        check("best of 486/404/503 → 486 upstream", caller_msgs() == ["SIP/2.0 486 Busy Here"])
        reset()

        # 3. All 503 → 500 (§16.7 step 6).
        invite()
        caller.recv()
        for p in uas:
            p.reply(p.expect("INVITE"), 503, "Service Unavailable")
        check("all branches 503 → 500 Service Unavailable upstream (Kamailio's local 500)", caller_msgs() == ["SIP/2.0 500 Service Unavailable"])
        reset()

        # 4. 6xx cancels the others and wins.
        invite()
        caller.recv()
        ia, ib, ic = a.expect("INVITE"), b.expect("INVITE"), c.expect("INVITE")
        b.reply(ib, 180, "Ringing")
        c.reply(ic, 180, "Ringing")
        a.reply(ia, 603, "Decline")
        cb, cc = b.expect("CANCEL"), c.expect("CANCEL")
        check("6xx → CANCEL to the other branches", cb is not None and cc is not None)
        b.reply(ib, 487, "Request Terminated")
        c.reply(ic, 487, "Request Terminated")
        msgs = caller_msgs()
        check("6xx forwarded (not 487) once all branches ended", msgs[-1:] == ["SIP/2.0 603 Decline"], msgs)
        reset()

        # 5. 401/407 challenges of all branches are merged (§16.7 step 7).
        invite()
        caller.recv()
        ia, ib, ic = a.expect("INVITE"), b.expect("INVITE"), c.expect("INVITE")
        a.reply(ia, 407, "Proxy Authentication Required", 'Proxy-Authenticate: Digest realm="a.example", nonce="1"\r\n')
        b.reply(ib, 407, "Proxy Authentication Required", 'Proxy-Authenticate: Digest realm="b.example", nonce="2"\r\n')
        c.reply(ic, 404, "Not Found")
        r = caller.recv()
        check("407 chosen over 404, with both challenges merged", first(r) == "SIP/2.0 407 Proxy Authentication Required"
              and b'realm="a.example"' in r and b'realm="b.example"' in r, r)
        reset()

        # 6. Upstream CANCEL fans out; final 487.
        m, br = invite()
        caller.recv()
        ia, ib, ic = a.expect("INVITE"), b.expect("INVITE"), c.expect("INVITE")
        a.reply(ia, 180, "Ringing")
        b.reply(ib, 180, "Ringing")
        caller_msgs(0.3)
        cancel = m.replace(b"INVITE sip:", b"CANCEL sip:").replace(b"CSeq: 1 INVITE", b"CSeq: 1 CANCEL")
        caller.s.sendto(cancel, ("127.0.0.1", PAR))
        check("CANCEL answered 200 by the proxy", first(caller.recv()) == "SIP/2.0 200 OK")
        ca, cb = a.expect("CANCEL"), b.expect("CANCEL")
        check("upstream CANCEL sent to ringing branches", ca is not None and cb is not None)
        c.reply(ic, 100, "Trying")
        check("…and to the silent branch after its 100", c.expect("CANCEL") is not None)
        for p, i in ((a, ia), (b, ib), (c, ic)):
            p.reply(i, 487, "Request Terminated")
        check("caller gets 487", caller_msgs()[-1:] == ["SIP/2.0 487 Request Terminated"])
        reset()

        # 7. Nobody answers → fr_timer (1 s) per branch → 408.
        invite()
        caller.recv()
        t0 = time.time()
        msgs = caller_msgs(2.5)
        check("no answers → 408 after fr_timer", msgs == ["SIP/2.0 408 Request Timeout"] and 0.9 < time.time() - t0 < 2.5, msgs)
        reset()

        # 8. A rings forever (fr_inv_timer 3 s) while B/C are busy: A is
        #    CANCELed, and the real 486 beats A's local 408.
        invite()
        caller.recv()
        ia, ib, ic = a.expect("INVITE"), b.expect("INVITE"), c.expect("INVITE")
        a.reply(ia, 180, "Ringing")
        b.reply(ib, 486, "Busy Here")
        c.reply(ic, 486, "Busy Here")
        t0 = time.time()
        ca = a.expect("CANCEL", 4)
        check("ringing branch CANCELed at fr_inv_timer", ca is not None and 2.5 < time.time() - t0 < 3.6, round(time.time() - t0, 2))
        msgs = caller_msgs()
        check("received 486 preferred over local 408", msgs[-1:] == ["SIP/2.0 486 Busy Here"], msgs)
        reset()

        # 9. Forked INVITE answered by two UAs: both 2xx go upstream.
        invite()
        caller.recv()
        ia, ib, ic = a.expect("INVITE"), b.expect("INVITE"), c.expect("INVITE")
        a.reply(ia, 200, "OK", tag="A")
        b.reply(ib, 200, "OK", tag="B")
        msgs = caller_msgs()
        check("two 2xx (two dialogs) both forwarded", msgs.count("SIP/2.0 200 OK") == 2, msgs)
        check("third branch CANCELed after first 2xx", c.reply(ic, 180, "Ringing") or c.expect("CANCEL") is not None)
        reset()

        # 10. Non-INVITE fork: exactly one 200 upstream.
        invite(method="MESSAGE")
        ma, mb, mc = a.expect("MESSAGE"), b.expect("MESSAGE"), c.expect("MESSAGE")
        a.reply(ma, 200, "OK")
        b.reply(mb, 200, "OK")
        c.reply(mc, 404, "Not Found")
        check("forked MESSAGE: one 200, no 100 Trying", caller_msgs() == ["SIP/2.0 200 OK"])
        reset()

        # 11. Request retransmission is absorbed and answered with the last reply.
        m, _ = invite()
        caller.recv()
        a.expect("INVITE")
        caller.s.sendto(m, ("127.0.0.1", PAR))
        check("retransmitted INVITE → last reply (100) again", first(caller.recv()) == "SIP/2.0 100 Trying")
        check("…and not forwarded again", a.recv(0.3) is None)
        reset()
        time.sleep(1.2)  # let the parallel proxy's timers finish
        reset()

        # 12. Serial (fork_by_q): A (q=1) → B (q=0.5) → C (q=0.1).
        invite(proxy=SER)
        caller.recv()
        ia = a.expect("INVITE")
        check("serial: only the highest-q branch first", ia is not None and b.recv(0.3) is None and c.recv(0.1) is None)
        a.reply(ia, 486, "Busy Here")
        ib = b.expect("INVITE")
        check("…next q-group after A fails", ib is not None and c.recv(0.3) is None)
        b.reply(ib, 480, "Temporarily Unavailable")
        ic = c.expect("INVITE")
        check("…then the lowest q", ic is not None)
        check("serial branches keep the header edit and their own R-URI",
              ib and ic and hdr(ib, "X-Edited") == "yes" and hdr(ic, "X-Edited") == "yes"
              and first(ib).startswith("INVITE sip:b@127.0.0.1:5602 SIP/2.0") and first(ic).startswith("INVITE sip:c@127.0.0.1:5603 SIP/2.0"),
              [(first(x), hdr(x, "X-Edited")) for x in (ib, ic) if x])
        c.reply(ic, 200, "OK")
        msgs = caller_msgs()
        check("serial: caller gets C's 200", msgs == ["SIP/2.0 200 OK"], msgs)
        reset()

        # 13. Serial with per-transaction timers: t_set_fr(5000, 1500).
        invite("slowpoke", proxy=SER)
        caller.recv()
        a.expect("INVITE")
        t0 = time.time()
        ib = b.expect("INVITE", 3)
        check("t_set_fr: A times out after 1.5 s, B tried next", ib is not None and 1.3 < time.time() - t0 < 2.2, round(time.time() - t0, 2))
        b.reply(ib, 200, "OK")
        check("…B's 200 forwarded", caller_msgs()[-1:] == ["SIP/2.0 200 OK"])
        reset()

        # 14. Serial stops at a 6xx.
        invite(proxy=SER)
        caller.recv()
        a.reply(a.expect("INVITE"), 600, "Busy Everywhere")
        check("6xx ends serial forking (B never tried)", b.recv(0.5) is None)
        check("…and 600 goes upstream", caller_msgs()[-1:] == ["SIP/2.0 600 Busy Everywhere"])
    finally:
        for p, log in zip(procs, logs):
            p.terminate()
            p.wait(timeout=5)
            time.sleep(0.05)
            err = "".join(log)
            check("no panics in proxy log", "panic" not in err, err)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
