#!/usr/bin/env python3
"""sip-ua with real rtpflux media, through crashes: the media B2BUA of
interop/sip-ua-rtpflux (durable sip-ua + rtpflux-client-async, native API
over TCP) between two independent Python UAs that exchange real RTP via a
real rtpflux relay.

- established call: RTP flows caller -> relay -> callee; the B2BUA is
  SIGKILLed; RTP keeps flowing while it is down; after the restart there is
  no second INVITE to the callee, and the caller's BYE ends both legs and
  destroys the media (RTP stops);
- ringing call: the B2BUA is SIGKILLed while the callee rings; the restart
  does not call again; the callee's 200 is ACKed by the new process, which
  bridges the media and answers the caller; RTP flows.

Needs the relay binary (pinned rtpflux; RTPFLUX_BIN) and
`cargo build --release --manifest-path interop/sip-ua-rtpflux/Cargo.toml`.
A missing binary is a failure, not a skip.
"""
import os, shutil, signal, socket, struct, subprocess, sys, tempfile, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sipkit import ROOT, UA, Dialog, sdp  # noqa: E402

RELAY = os.environ.get("RTPFLUX_BIN", "")
B2B = f"{ROOT}/interop/sip-ua-rtpflux/target/release/sip-ua-rtpflux"
TOKEN = "ferrosip-interop-token"
NATIVE, NG = 22540, 22530
B2BP, CALLER, CALLEE = 5495, 5496, 5497
CALLER_RTP, CALLEE_RTP = 6496, 6497
FAILS = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'} {name}{': ' + str(detail) if detail and not ok else ''}")
    if not ok:
        FAILS.append(name)


class Lines:
    def __init__(self, args):
        self.lines = []
        self.p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            self.lines.append(line.strip())

    def wait_for(self, prefix, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            hit = next((l for l in list(self.lines) if l.startswith(prefix)), None)
            if hit:
                return hit
            time.sleep(0.02)
        return None

    def kill(self):
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGKILL)
        self.p.wait(5)


def b2b(d):
    p = Lines([B2B, "--listen", f"127.0.0.1:{B2BP}", "--dir", d, "--forward", f"sip:bob@127.0.0.1:{CALLEE}",
               "--media", f"127.0.0.1:{NATIVE}", "--token", TOKEN])
    check("b2b ready", p.wait_for("READY", 10) is not None, p.lines)
    return p


class Rtp:
    """Caller side sends a packet every 20 ms; callee side counts them."""

    def __init__(self):
        self.tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tx.bind(("127.0.0.1", CALLER_RTP))
        self.rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rx.bind(("127.0.0.1", CALLEE_RTP))
        self.rx.settimeout(0.1)
        self.dest, self.got, self.stop = None, 0, False
        threading.Thread(target=self._send, daemon=True).start()
        threading.Thread(target=self._recv, daemon=True).start()

    def _send(self):
        seq = 0
        while not self.stop:
            if self.dest:
                seq += 1
                hdr = struct.pack("!BBHII", 0x80, 0, seq & 0xFFFF, seq * 160, 0x1234ABCD)
                try:
                    self.tx.sendto(hdr + b"\xff" * 160, self.dest)
                except OSError:
                    pass
            time.sleep(0.02)

    def _recv(self):
        while not self.stop:
            try:
                self.rx.recvfrom(2048)
                self.got += 1
            except OSError:
                pass

    def flowing(self, secs=1.0):
        """Packets that reached the callee in the next `secs`."""
        before = self.got
        time.sleep(secs)
        return self.got - before

    def close(self):
        self.stop = True
        time.sleep(0.15)
        self.tx.close()
        self.rx.close()


def invites(callee):
    return {m.get("call-id") for m in callee.received if m.method == "INVITE"}


def established_call_survives_sigkill(d):
    p = b2b(d)
    rtp = Rtp()
    callee = UA("bob", CALLEE, ("127.0.0.1", B2BP))
    callee.auto_answer(sdp_port=CALLEE_RTP)
    caller = UA("alice", CALLER, ("127.0.0.1", B2BP))
    try:
        r, dlg = caller.call(f"sip:ua@127.0.0.1:{B2BP}", body=sdp(CALLER_RTP), timeout=8)
        check("established: caller answered by the b2b", r is not None and r.code == 200, (repr(r), p.lines))
        if dlg is None:
            return
        check("established: media bridged", p.wait_for("BRIDGED") is not None, p.lines)
        rtp.dest = r.sdp_media()
        n = rtp.flowing()
        check("established: RTP reaches the callee through rtpflux", n >= 25, n)
        p.kill()
        n = rtp.flowing(1.5)
        check("established: RTP keeps flowing while the b2b is down", n >= 40, n)
        p = b2b(d)
        check("established: both legs restored", sum(1 for l in p.lines if l.startswith("RESTORED Restored")) == 2, p.lines)
        check("established: no new leg B on restart", not any(l.startswith("BLEG") for l in p.lines), p.lines)
        check("established: the same rtpflux endpoints after the restart", not any(l.startswith("ENDPOINTS-CHANGED") for l in p.lines), p.lines)
        n = rtp.flowing()
        check("established: RTP flows after the restart", n >= 25, n)
        check("established: one INVITE Call-ID at the callee", len(invites(callee)) == 1, invites(callee))
        b = dlg.bye()
        check("established: caller's BYE answered 200 by the restarted b2b", b is not None and b.code == 200, repr(b))
        check("established: media destroyed", p.wait_for("DESTROYED") is not None, p.lines)
        time.sleep(0.5)
        check("established: the callee got the BYE", any(m.method == "BYE" for m in callee.received))
        n = rtp.flowing(0.5)
        check("established: RTP stops once the media is destroyed", n == 0, n)
    finally:
        rtp.close()
        caller.close()
        callee.close()
        p.kill()


def ringing_call_survives_sigkill(d):
    p = b2b(d)
    rtp = Rtp()
    callee = UA("bob", CALLEE, ("127.0.0.1", B2BP))
    callee.handler = lambda m: (180, "Ringing") if m.method == "INVITE" else ((200, "OK") if m.method == "BYE" else None)
    caller = UA("alice", CALLER, ("127.0.0.1", B2BP))
    try:
        sent = caller.invite(f"sip:ua@127.0.0.1:{B2BP}", body=sdp(CALLER_RTP))
        check("ringing: leg B originated", (p.wait_for("BLEG") or "").endswith("replayed=false"), p.lines)
        time.sleep(0.4)
        inv = next((m for m in callee.received if m.method == "INVITE"), None)
        check("ringing: the callee rings", inv is not None)
        if inv is None:
            return
        p.kill()
        p = b2b(d)
        check("ringing: no second INVITE after the restart", not any(l.startswith("BLEG") for l in p.lines) and len(invites(callee)) == 1,
              (p.lines, invites(callee)))
        check("ringing: the same rtpflux endpoints after the restart", not any(l.startswith("ENDPOINTS-CHANGED") for l in p.lines), p.lines)
        callee.respond(inv, 200, body=sdp(CALLEE_RTP))
        r = caller.final(6, method="INVITE", call_id=sent["call_id"])
        check("ringing: the restarted b2b answers the caller", r is not None and r.code == 200, (repr(r), p.lines))
        time.sleep(0.3)
        check("ringing: the restarted b2b ACKs the callee's 200", any(m.method == "ACK" for m in callee.received))
        if r is None or r.code != 200:
            return
        dlg = Dialog(caller, sent, r)
        dlg.ack()
        rtp.dest = r.sdp_media()
        n = rtp.flowing()
        check("ringing: RTP flows through the media bridged after the restart", n >= 25, n)
        b = dlg.bye()
        check("ringing: BYE answered", b is not None and b.code == 200, repr(b))
        check("ringing: media destroyed", p.wait_for("DESTROYED") is not None, p.lines)
    finally:
        rtp.close()
        caller.close()
        callee.close()
        p.kill()


def main():
    for path, what in ((RELAY, "the rtpflux relay (RTPFLUX_BIN)"), (B2B, "interop/sip-ua-rtpflux")):
        if not path or not os.path.exists(path):
            print(f"FAIL {what} missing: {path or 'RTPFLUX_BIN unset'}")
            return 1
    d = tempfile.mkdtemp(prefix="sipua-rtpflux-")
    with open(f"{d}/rtpflux.toml", "w") as f:
        f.write(f"""[control]
listen = ["127.0.0.1:{NG}"]
native_listen = ["127.0.0.1:{NATIVE}"]
native_tokens = {{ default = "{TOKEN}" }}
pcm_dir = "{d}"
[[interface]]
name = "lo"
address = "127.0.0.1"
[ports]
min = 41000
max = 41199
[sessions]
max = 40
[runtime]
workers = 1
""")
    relay = subprocess.Popen([RELAY, "-c", f"{d}/rtpflux.toml"], stdout=subprocess.DEVNULL, stderr=open(f"{d}/relay.log", "w"))
    try:
        end = time.time() + 10
        while time.time() < end:
            try:
                socket.create_connection(("127.0.0.1", NATIVE), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        for test in (established_call_survives_sigkill, ringing_call_survives_sigkill):
            sd = tempfile.mkdtemp(prefix="sipua-b2b-", dir=d)
            test(sd)
    finally:
        relay.send_signal(signal.SIGTERM)
        relay.wait(10)
        if FAILS:
            print(open(f"{d}/relay.log").read()[-3000:])
        shutil.rmtree(d, ignore_errors=True)
    print(f"{'FAIL' if FAILS else 'OK'}: {len(FAILS)} failed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
