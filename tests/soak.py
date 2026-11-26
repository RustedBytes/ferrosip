#!/usr/bin/env python3
"""Soak test: sustained call load through ferrosip, watching for leaks.

SIPp's UAC places calls (INVITE/180/200/ACK/BYE) through a ferrosip proxy
running tm + dialog (dlg_manage, record_route) to a SIPp UAS, plus a REGISTER
loop and OPTIONS answered statelessly. While it runs the proxy's RSS (from
/proc), current transactions (tm.stats) and active dialogs (dlg.stats_active)
are sampled. Checks:

  * no failed calls;
  * RSS after warmup stays within a bound (default +10% and +8 MB; SOAK_RSS_PCT, SOAK_RSS_MB);
  * once the load stops, transactions and dialogs drain back to 0.

  tests/soak.py [SECONDS]        # default 120; env SOAK_RATE (calls/s, default 300)

Needs `sipp` and `cargo build --release`.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from harness import wait_listening

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PX, UAS = 7900, 7910
SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 120
RATE = int(os.environ.get("SOAK_RATE", "300"))
REG_RATE = int(os.environ.get("SOAK_REG_RATE", "20"))
RSS_PCT = float(os.environ.get("SOAK_RSS_PCT", "10"))
RSS_MB = float(os.environ.get("SOAK_RSS_MB", "8"))

CFG = f"""
loadmodule "tm"
loadmodule "sl"
loadmodule "maxfwd"
loadmodule "siputils"
loadmodule "textops"
loadmodule "rr"
loadmodule "dialog"
loadmodule "usrloc"
loadmodule "registrar"
modparam("tm", "wait_timer", 2000)
modparam("registrar", "min_expires", 1)
modparam("usrloc", "timer_interval", 1)
modparam("tm", "fr_inv_timer", 10000)

request_route {{
    if (!mf_process(10)) {{ sl_send_reply(483, "Too Many Hops"); exit; }}
    if (is_method("OPTIONS")) {{ sl_send_reply(200, "OK"); exit; }}
    if (is_method("REGISTER")) {{ save("location"); exit; }}
    if (has_totag() && loose_route()) {{ t_relay(); exit; }}
    if (is_method("CANCEL")) {{ t_relay(); exit; }}
    # SIPp's built-in UAC ignores Record-Route: its ACK/BYE come without Route.
    if (is_method("INVITE") && !has_totag()) {{ dlg_manage(); record_route(); }}
    t_relay("udp:127.0.0.1:{UAS}");
}}
"""

REGISTER = """<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="register">
  <send retrans="500"><![CDATA[
REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
From: <sip:u[call_number]@[remote_ip]>;tag=[pid]r[call_number]
To: <sip:u[call_number]@[remote_ip]>
Call-ID: [call_id]
CSeq: 1 REGISTER
Contact: <sip:u[call_number]@[local_ip]:[local_port]>
Expires: 5
Max-Forwards: 70
Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>
"""


def rss_kb(pid):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


def ctl(sock, method):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", sock, method], capture_output=True, text=True, timeout=5)
    if out.returncode != 0:
        raise RuntimeError(f"ferroctl {method}: {out.stderr.strip()}")
    return json.loads(out.stdout)


def sample(proxy, sock):
    tm = ctl(sock, "tm.stats")
    # The branch index and the transactions must drain together.
    return rss_kb(proxy.pid), max(tm["current"], tm["branch_index"]), ctl(sock, "dlg.stats_active")["all"]


def main():
    if not shutil.which("sipp"):
        print("SKIP: sipp not installed (apt-get install sip-tester)")
        sys.exit(0)
    work = tempfile.mkdtemp(prefix="ferrosip-soak-")
    sock = os.path.join(work, "rpc.sock")
    cfg = os.path.join(work, "soak.cfg")
    open(cfg, "w").write(CFG)
    open(os.path.join(work, "register.xml"), "w").write(REGISTER)
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}", "-n", "2", "--rpc-socket", sock],
                             stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    if proxy.poll() is not None:
        sys.exit("proxy failed to start:\n" + proxy.early_log)
    calls = RATE * SECS
    failures = []
    procs = []
    try:
        common = ["sipp", "-nostdin", "-i", "127.0.0.1", "-trace_err"]
        procs.append(subprocess.Popen(common + ["-sn", "uas", "-p", str(UAS)], cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(0.5)
        uac = subprocess.Popen(common + ["-sn", "uac", f"127.0.0.1:{PX}", "-s", "bob", "-m", str(calls), "-r", str(RATE),
                                         "-l", str(RATE * 2), "-d", "500", "-timeout_error", "-timeout", f"{SECS + 120}s"],
                               cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(uac)
        reg = None
        if REG_RATE:
            reg = subprocess.Popen(common + ["-sf", "register.xml", f"127.0.0.1:{PX}", "-m", str(REG_RATE * SECS), "-r", str(REG_RATE),
                                             "-p", "7920"], cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(reg)

        t0 = time.time()
        warm, samples = None, []
        print(f"soak: {calls} calls at {RATE}/s over {SECS}s, {REG_RATE} REGISTER/s (expiring after 5s)")
        print("   t(s)   RSS(MB)  txns  dialogs")
        while uac.poll() is None:
            time.sleep(min(5, max(1, SECS / 24)))
            t = time.time() - t0
            r, tx, dl = sample(proxy, sock)
            samples.append((t, r))
            if warm is None and t >= SECS * 0.25:
                warm = r
            print(f"  {t:6.0f}  {r / 1024:8.1f}  {tx:5}  {dl:7}")
        if reg:
            reg.wait(60)
        if uac.returncode != 0:
            failures.append(f"SIPp UAC exited {uac.returncode} (failed calls; see {work}/*_errors.log)")
        if reg and reg.returncode != 0:
            failures.append(f"REGISTER loop exited {reg.returncode}")

        # Drain: transactions leave after wait_timer, dialogs after BYE.
        deadline = time.time() + 20
        while True:
            r, tx, dl = sample(proxy, sock)
            if (tx == 0 and dl == 0) or time.time() > deadline:
                break
            time.sleep(0.5)
        print(f"  drained: RSS {r / 1024:.1f} MB, {tx} transactions, {dl} dialogs")
        if tx or dl:
            failures.append(f"leftover state after the load: {tx} transactions, {dl} dialogs")
        peak = max(s[1] for s in samples if s[0] >= SECS * 0.25) if warm else r
        warm = warm or samples[0][1]
        limit = warm * (1 + RSS_PCT / 100) + RSS_MB * 1024
        print(f"  RSS after warmup {warm / 1024:.1f} MB, peak after warmup {peak / 1024:.1f} MB, limit {limit / 1024:.1f} MB")
        if peak > limit:
            failures.append(f"RSS grew from {warm / 1024:.1f} MB to {peak / 1024:.1f} MB")
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
            p.wait()
        proxy.terminate()
        try:
            err = proxy.communicate(timeout=5)[1]
        except subprocess.TimeoutExpired:
            proxy.kill()
            err = proxy.communicate()[1]
        if "panicked" in err:
            failures.append("panic in proxy log:\n" + err[-1500:])
    for f in failures:
        print("FAIL " + f)
    if failures:
        print(f"work dir kept: {work}")
        sys.exit(1)
    shutil.rmtree(work, ignore_errors=True)
    print("soak passed")


if __name__ == "__main__":
    main()
