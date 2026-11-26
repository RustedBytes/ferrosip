#!/usr/bin/env python3
"""Interop with SIPp (an independent SIP implementation), through ferrosip:
- SIPp's built-in UAC → ferrosip → SIPp's built-in UAS, over UDP, TCP and TLS:
  INVITE / 100 / 180 / 200 / ACK / BYE. No failed calls allowed. (SIPp's
  built-in UAC ignores Record-Route, so its ACK/BYE reach ferrosip without a
  Route header; the script routes them like the INVITE.)
- REGISTER with digest authentication (tests/sipp/register_auth.xml, SIPp's
  [authentication]).
- A caller canceling a ringing call (uac_cancel.xml / uas_ring.xml): 200 to
  the CANCEL, 487 to the INVITE, ACK.

Needs `sipp` (Debian/Ubuntu: sip-tester). Run from the repo root after
`cargo build --release` and `etc/tls/gen-certs.sh`.
"""
import os, shutil, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TLS = os.path.join(ROOT, "etc/tls")
SC = os.path.join(ROOT, "tests/sipp")
PX, PX_TLS = 7800, 7801
UAS = {"udp": 7810, "tcp": 7811, "tls": 7812, "ring": 7814}
CALLS = int(os.environ.get("SIPP_CALLS", "200"))

CFG = f"""
loadmodule "tm"
loadmodule "sl"
loadmodule "maxfwd"
loadmodule "textops"
loadmodule "siputils"
loadmodule "rr"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "auth"
modparam("auth", "users_file", "USERS")
modparam("tm", "fr_inv_timer", 10000)

request_route {{
    if (!mf_process(10)) {{ sl_send_reply(483, "Too Many Hops"); exit; }}
    if (has_totag() && loose_route()) {{ t_relay(); exit; }}
    if (is_method("CANCEL")) {{ t_relay(); exit; }}
    if (is_method("REGISTER")) {{
        if (!www_authorize("example.com", "subscriber")) {{ www_challenge("example.com", 0); exit; }}
        consume_credentials();
        save("location");
        exit;
    }}
    # SIPp's built-in UAC ignores Record-Route: its ACK/BYE come without a
    # Route header and are routed like the INVITE.
    if (!has_totag()) {{ record_route(); }}
    if ($rU == "ring") {{ t_relay("udp:127.0.0.1:{UAS['ring']}"); exit; }}
    if ($pr == "udp") {{ t_relay("udp:127.0.0.1:{UAS['udp']}"); exit; }}
    if ($pr == "tcp") {{ t_relay("tcp:127.0.0.1:{UAS['tcp']}"); exit; }}
    if ($pr == "tls") {{ t_relay("tls:127.0.0.1:{UAS['tls']}"); exit; }}
    sl_send_reply(500, "?");
}}
"""

failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def sipp(args, cwd, timeout=120):
    cmd = ["sipp", "-nostdin", "-trace_err", "-timeout", "60s", "-timeout_error"] + args
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def summary(r, cwd):
    errs = "".join(open(os.path.join(cwd, f)).read()[-600:] for f in os.listdir(cwd) if f.endswith("_errors.log"))
    return f"rc={r.returncode} {r.stdout[-400:]} {r.stderr[-400:]} {errs}"


def sipp_tls_works(work):
    """SIPp's own TLS client against its own TLS server: in some sandboxes
    (gVisor) its non-blocking SSL_connect never completes, whatever the peer."""
    d = os.path.join(work, "tlsprobe")
    os.makedirs(d)
    for f in ("cacert.pem", "cakey.pem"):
        shutil.copy(os.path.join(work, f), d)
    uas = subprocess.Popen(["sipp", "-nostdin", "-sn", "uas", "-i", "127.0.0.1", "-p", "7813", "-t", "l1", "-tls_version", "1.2", "-m", "1"],
                           cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    try:
        r = subprocess.run(["sipp", "-nostdin", "-sn", "uac", "127.0.0.1:7813", "-i", "127.0.0.1", "-t", "l1", "-tls_version", "1.2",
                            "-m", "1", "-timeout", "10s", "-timeout_error"], cwd=d, capture_output=True, timeout=30)
        return r.returncode == 0
    finally:
        uas.kill()
        uas.wait()


def main():
    if not shutil.which("sipp"):
        print("SKIP: sipp not installed (apt-get install sip-tester)")
        sys.exit(0)
    work = tempfile.mkdtemp(prefix="ferrosip-sipp-")
    # SIPp's TLS endpoints read cacert.pem / cakey.pem from the working dir.
    shutil.copy(f"{TLS}/server.pem", f"{work}/cacert.pem")
    shutil.copy(f"{TLS}/server.key.pem", f"{work}/cakey.pem")
    users = os.path.join(work, "users")
    open(users, "w").write("alice secret\n")
    cfg = os.path.join(work, "ferrosip.cfg")
    open(cfg, "w").write(CFG.replace("USERS", users))
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}", "-l", f"tcp:127.0.0.1:{PX}",
                              "-l", f"tls:127.0.0.1:{PX_TLS}", "-n", "2", "--rpc-socket", "none",
                              "--tls-cert", f"{TLS}/server.pem", "--tls-key", f"{TLS}/server.key.pem", "--tls-ca", f"{TLS}/ca.pem"],
                             stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    try:
        # 1. Calls over each transport.
        legs = [("udp", "u1", PX), ("tcp", "t1", PX)]
        if sipp_tls_works(work):
            legs.append(("tls", "l1", PX_TLS))
        else:
            print("SKIP TLS leg: SIPp's TLS client cannot reach even a SIPp TLS server here (SSL_connect WANT_READ)")
        for proto, flag, px in legs:
            d = os.path.join(work, proto)
            os.makedirs(d)
            for f in ("cacert.pem", "cakey.pem"):
                shutil.copy(os.path.join(work, f), d)
            # SIPp's default TLS method gives up on a non-blocking handshake
            # (SSL_ERROR_WANT_READ); an explicit version works.
            tlsv = ["-tls_version", "1.2"] if proto == "tls" else []
            uas = subprocess.Popen(["sipp", "-nostdin", "-sn", "uas", "-i", "127.0.0.1", "-p", str(UAS[proto]), "-t", flag, "-m", str(CALLS)] + tlsv,
                                   cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            t0 = time.time()
            r = sipp(["-sn", "uac", f"127.0.0.1:{px}", "-i", "127.0.0.1", "-t", flag, "-s", "bob", "-m", str(CALLS), "-r", "50", "-l", "40",
                      "-d", "200"] + tlsv, d)
            dt = time.time() - t0
            uas.terminate()
            uas.wait(10)
            check(f"SIPp UAC → ferrosip → SIPp UAS over {proto.upper()}: {CALLS} calls (INVITE/180/200/ACK/BYE), none failed",
                  r.returncode == 0, summary(r, d))
            print(f"      ({CALLS} calls in {dt:.1f}s)")

        # 2. REGISTER with digest auth.
        d = os.path.join(work, "reg")
        os.makedirs(d)
        r = sipp(["-sf", f"{SC}/register_auth.xml", f"127.0.0.1:{PX}", "-i", "127.0.0.1", "-s", "alice", "-au", "alice", "-ap", "secret",
                  "-m", "20", "-r", "20"], d)
        check("SIPp REGISTER with digest auth (401 → credentials → 200), 20 registrations", r.returncode == 0, summary(r, d))
        r = sipp(["-sf", f"{SC}/register_auth.xml", f"127.0.0.1:{PX}", "-i", "127.0.0.1", "-s", "alice", "-au", "alice", "-ap", "wrong",
                  "-m", "1"], d)
        check("…wrong password is not accepted", r.returncode != 0, summary(r, d))

        # 3. CANCEL of a ringing call.
        d = os.path.join(work, "cancel")
        os.makedirs(d)
        uas = subprocess.Popen(["sipp", "-nostdin", "-sf", f"{SC}/uas_ring.xml", "-i", "127.0.0.1", "-p", str(UAS["ring"]), "-m", "20"],
                               cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        r = sipp(["-sf", f"{SC}/uac_cancel.xml", f"127.0.0.1:{PX}", "-i", "127.0.0.1", "-s", "ring", "-m", "20", "-r", "10"], d)
        uas.wait(30)
        check("SIPp caller cancels a ringing call: 200 (CANCEL) + 487 + ACK, 20 calls", r.returncode == 0 and uas.returncode == 0,
              summary(r, d) + f" uas rc={uas.returncode}")
    finally:
        proxy.terminate()
        try:
            err = proxy.communicate(timeout=5)[1]
        except subprocess.TimeoutExpired:
            proxy.kill()
            err = proxy.communicate()[1]
        check("no panics in proxy log", "panicked" not in err, err[-1500:])
        if failures:
            print("--- proxy stderr ---\n" + err[-3000:])
        if failures and os.environ.get("KEEP"):
            print(f"work dir kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
