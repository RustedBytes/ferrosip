#!/usr/bin/env python3
"""Crash recovery of the sip-ua engine with real processes and durable
storage: crates/sip-ua/examples/recoverable_ua (FileJournal, fsync per
transition) killed with SIGKILL or aborted at a commit boundary, then
restarted from its journal, with the independent Python UAs of
tests/sipkit.py on the other side.

- an established UDP call survives SIGKILL: after the restart the caller's
  re-INVITE and BYE are answered within the same dialog (not 481);
- abort after committing the 200 but before sending it: the restart sends
  it; abort before committing it: the restart reconciles and answers;
- an outbound call killed while ringing is not originated again on
  restart (same key), and the callee's later 200 is ACKed by the new
  process;
- with a checkpoint after every transition (journal truncation), the
  restored call still works;
- takeover with two live incarnations: the old owner (epoch 1) is paused
  (SIGSTOP) with a call up, a new owner (epoch 2) takes over the same
  directory and binds the same address (SO_REUSEPORT), the old one resumes:
  it sends nothing more, the call continues with the new owner, and a
  takeover with a stale epoch is refused;
- lease: an owner cut off from its lease authority halts by its own clock
  within the lease and answers nothing after.

Run from the repo root after
`cargo build --release -p sip-ua --features recovery --example recoverable_ua`.
"""
import os, shutil, signal, subprocess, sys, tempfile, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sipkit import ROOT, UA, sdp  # noqa: E402

BIN = f"{ROOT}/target/release/examples/recoverable_ua"
UAP, CALLER, CALLEE = 5490, 5491, 5492
FAILS = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'} {name}{': ' + str(detail) if detail and not ok else ''}")
    if not ok:
        FAILS.append(name)


class Proc:
    """The UA process; stdout lines collected by a thread."""

    def __init__(self, d, env=None, extra=(), ready=True):
        self.lines = []
        e = {**os.environ, **(env or {})}
        self.p = subprocess.Popen([BIN, "--listen", f"127.0.0.1:{UAP}", "--dir", d, *extra], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=e)
        threading.Thread(target=self._read, daemon=True).start()
        if ready:
            self.wait_for("READY", 10)

    def _read(self):
        for line in self.p.stdout:
            self.lines.append(line.strip())

    def wait_for(self, prefix, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            hit = next((l for l in list(self.lines) if l.startswith(prefix)), None)
            if hit:
                return hit
            if self.p.poll() is not None and not any(l.startswith(prefix) for l in self.lines):
                time.sleep(0.05)
                return next((l for l in list(self.lines) if l.startswith(prefix)), None)
            time.sleep(0.02)
        return None

    def kill(self):
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGKILL)
        self.p.wait(5)

    def died(self, timeout=5.0):
        try:
            self.p.wait(timeout)
            return True
        except subprocess.TimeoutExpired:
            return False


def reinvite_and_bye(caller, d, label):
    d.request("INVITE", body=sdp(6491))
    r = caller.final(4, method="INVITE", call_id=d.call_id, cseq=d.cseq)
    check(f"{label}: re-INVITE answered 200 in the restored dialog", r is not None and r.code == 200, repr(r))
    if r is not None and r.code == 200:
        d.request("ACK", cseq=d.cseq)
    b = d.bye()
    check(f"{label}: BYE answered 200 (not 481)", b is not None and b.code == 200, repr(b))


def sigkill_established(extra=(), label="SIGKILL"):
    d = tempfile.mkdtemp(prefix="sipua-rec-")
    p = Proc(d, extra=extra)
    caller = UA("alice", CALLER, ("127.0.0.1", UAP))
    try:
        r, dlg = caller.call(f"sip:ua@127.0.0.1:{UAP}", body=sdp(6491))
        check(f"{label}: call answered", r is not None and r.code == 200, repr(r))
        if dlg is None:
            return
        time.sleep(0.3)
        p.kill()
        p = Proc(d, extra=extra)
        check(f"{label}: the leg is restored", p.wait_for("RESTORED Restored") is not None, p.lines)
        reinvite_and_bye(caller, dlg, label)
    finally:
        caller.close()
        p.kill()
        shutil.rmtree(d, ignore_errors=True)


def abort_around_the_200(boundary):
    d = tempfile.mkdtemp(prefix="sipua-rec-")
    p = Proc(d, env={"RECOVERY_CRASH": f"{boundary}:SIP/2.0 200"})
    caller = UA("alice", CALLER, ("127.0.0.1", UAP))
    try:
        sent = caller.invite(f"sip:ua@127.0.0.1:{UAP}", body=sdp(6491))
        check(f"{boundary}: the process aborts at the failpoint", p.died(5))
        early = caller.recv(0.5, lambda m: m.is_reply and m.code == 200)
        check(f"{boundary}: no 200 before the restart", early is None or boundary == "post-send", repr(early))
        p = Proc(d)
        r = caller.final(6, method="INVITE", call_id=sent["call_id"])
        check(f"{boundary}: the caller gets the 200 after the restart", r is not None and r.code == 200, (repr(r), p.lines))
        if r is None or r.code != 200:
            return
        from sipkit import Dialog
        dlg = Dialog(caller, sent, r)
        dlg.ack()
        b = dlg.bye()
        check(f"{boundary}: BYE answered 200", b is not None and b.code == 200, repr(b))
    finally:
        caller.close()
        p.kill()
        shutil.rmtree(d, ignore_errors=True)


def outbound_killed_while_ringing():
    d = tempfile.mkdtemp(prefix="sipua-rec-")
    callee = UA("bob", CALLEE, ("127.0.0.1", UAP))
    callee.handler = lambda m: (180, "Ringing") if m.method == "INVITE" else ((200, "OK") if m.method in ("BYE",) else None)
    extra = ("--call", f"sip:bob@127.0.0.1:{CALLEE}", "--key", "call-1")
    p = Proc(d, extra=extra)
    try:
        check("UAC: originated under the key", (p.wait_for("KEYED") or "").endswith("replayed=false"), p.lines)
        time.sleep(0.5)
        invs = [m for m in callee.received if m.method == "INVITE"]
        check("UAC: the callee rings", len(invs) >= 1)
        p.kill()
        p = Proc(d, extra=extra)
        check("UAC: the restart finds the call instead of calling again", (p.wait_for("KEYED") or "").endswith("replayed=true"), p.lines)
        time.sleep(0.5)
        callids = {m.get("call-id") for m in callee.received if m.method == "INVITE"}
        check("UAC: one call on the wire", len(callids) == 1, callids)
        inv = invs[0]
        callee.respond(inv, 200, body=sdp(6492))
        time.sleep(0.5)
        acks = [m for m in callee.received if m.method == "ACK"]
        check("UAC: the restarted process ACKs the 200", len(acks) >= 1)
        check("UAC: the application is told", p.wait_for("EVENT", 1) is not None and any(" Accepted" in l for l in p.lines), p.lines)
    finally:
        callee.close()
        p.kill()
        shutil.rmtree(d, ignore_errors=True)


def takeover_with_two_live_incarnations():
    d = tempfile.mkdtemp(prefix="sipua-rec-")
    old = Proc(d, extra=("--epoch", "1"))
    new = None
    caller = UA("alice", CALLER, ("127.0.0.1", UAP))
    try:
        r, dlg = caller.call(f"sip:ua@127.0.0.1:{UAP}", body=sdp(6491))
        check("takeover: call answered by epoch 1", r is not None and r.code == 200 and any(l.startswith("SENT 1 SIP/2.0 200") for l in old.lines), (repr(r), old.lines))
        if dlg is None:
            return
        time.sleep(0.3)
        old.p.send_signal(signal.SIGSTOP)
        paused_at = len(old.lines)
        new = Proc(d, extra=("--epoch", "2", "--takeover"))
        check("takeover: the new owner restored the call", new.wait_for("RESTORED Restored") is not None, new.lines)
        stale = Proc(d, extra=("--epoch", "1", "--takeover"), ready=False)
        check("takeover: a stale epoch is refused", stale.wait_for("REFUSED", 5) is not None and stale.died(5), stale.lines)
        old.p.send_signal(signal.SIGCONT)
        # The caller's requests may reach either socket; the old owner must
        # answer none of them, and the new owner all.
        reinvite_and_bye(caller, dlg, "takeover")
        time.sleep(0.5)
        leaked = [l for l in old.lines[paused_at:] if l.startswith("SENT")]
        check("takeover: the old owner sent nothing after the takeover", not leaked, leaked)
        check("takeover: everything the new owner sent is epoch 2", all(l.startswith("SENT 2 ") for l in new.lines if l.startswith("SENT")), new.lines)
        halted = old.p.poll() is not None
        print(f"INFO takeover: old owner {'halted (' + next((l for l in old.lines if l.startswith('HALT')), '?') + ')' if halted else 'still running (got no traffic)'}")
    finally:
        caller.close()
        if old.p.poll() is None:
            old.p.send_signal(signal.SIGCONT)
        old.kill()
        if new:
            new.kill()
        shutil.rmtree(d, ignore_errors=True)


def lease_lapse_stops_a_cut_off_owner():
    d = tempfile.mkdtemp(prefix="sipua-rec-")
    lease = f"{d}/lease"
    open(lease, "w").close()
    p = Proc(d, extra=("--lease-ms", "800", "--lease-file", lease))
    caller = UA("alice", CALLER, ("127.0.0.1", UAP))
    try:
        r, dlg = caller.call(f"sip:ua@127.0.0.1:{UAP}", body=sdp(6491))
        check("lease: call answered while renewed", r is not None and r.code == 200, repr(r))
        time.sleep(1.5)
        check("lease: still running past the lease length (renewed)", p.p.poll() is None, p.lines)
        os.remove(lease)
        cut = time.time()
        halted = p.wait_for("HALT lease", 3) is not None and p.died(3)
        check("lease: halts by itself within the lease once renewals stop", halted and time.time() - cut < 2.0, p.lines)
        n = len(p.lines)
        if dlg is not None:
            dlg.request("BYE")
            b = caller.final(1.5, method="BYE")
            check("lease: nothing answers after the halt", b is None and not any(l.startswith("SENT") for l in p.lines[n:]), repr(b))
    finally:
        caller.close()
        p.kill()
        shutil.rmtree(d, ignore_errors=True)


def main():
    if not os.path.exists(BIN):
        print(f"FAIL {BIN} missing: cargo build --release -p sip-ua --features recovery --example recoverable_ua")
        return 1
    sigkill_established()
    sigkill_established(extra=("--checkpoint-every", "1"), label="SIGKILL with checkpoints")
    for b in ("pre-commit", "post-commit", "post-send"):
        abort_around_the_200(b)
    outbound_killed_while_ringing()
    takeover_with_two_live_incarnations()
    lease_lapse_stops_a_cut_off_owner()
    print(f"{'FAIL' if FAILS else 'OK'}: {len(FAILS)} failed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
