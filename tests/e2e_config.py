#!/usr/bin/env python3
"""ferrosip.toml (phase 1 of the configuration redesign).

ferrosip runs from a ferrosip.toml, plus an overlay, --set values and the
environment; routing stays in a .cfg named by [routing] entry. Checked
with real traffic:
- listeners come from [[listen]], with the UDP port taken from the
  environment and an advertised address on the UDP listener (seen in the
  Via of a relayed INVITE);
- a TLS listener uses a named [tls.edge] section, and a client verifying
  the CA completes the handshake;
- module parameters reach the modules through the ferrosip names:
  - [modules.location] max_expires from the overlay caps a REGISTER;
  - max_contacts from --set refuses a second contact (503);
- a feature switch in the overlay turns the Prometheus module on;
- `check --explain` shows every value with its source and the
  conversions;
- every problem in a bad file is reported at once, with "did you mean";
  a parameter set in both the .toml and the .cfg is refused, as is an
  unset environment variable;
- modules the routing script needs load by themselves under --config (the
  .cfg has no loadmodule); the same file under plain -f still fails;
- cfg.reload re-reads the files: a reloadable parameter (max_expires)
  changes live, a listener change is reported as needing a restart, a
  broken file changes nothing;
- docs/modules-reference.md and bin/ferrosip/src/functions.txt are what
  `ferrosip schema --markdown` / `--functions` print.
Run from the repo root after `cargo build --release`.
"""
import os, re, socket, ssl, subprocess, sys, tempfile, threading, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = f"{ROOT}/target/release/ferrosip"
UDP, TCP, TLS, PROM, UAC = 7400, 7401, 7402, 7495, 7410
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


d = tempfile.mkdtemp(prefix="ferrosip-e2e-config-")
os.makedirs(f"{d}/routes")
os.makedirs(f"{d}/envs")
os.makedirs(f"{d}/tls")
ossl = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True)
ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=e2e CA", "-keyout", f"{d}/tls/ca.key", "-out", f"{d}/tls/ca.pem",
     "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
ossl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", f"{d}/tls/edge.key", "-out", f"{d}/tls/edge.csr")
open(f"{d}/tls/ext", "w").write("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
ossl("x509", "-req", "-in", f"{d}/tls/edge.csr", "-CA", f"{d}/tls/ca.pem", "-CAkey", f"{d}/tls/ca.key", "-CAcreateserial", "-days", "2", "-extfile", f"{d}/tls/ext", "-out", f"{d}/tls/edge.pem")

open(f"{d}/ferrosip.toml", "w").write(f"""
[core]
workers = 2
rpc_socket = "${{E2E_RPC}}"
shutdown_timeout = "1s"

[[listen]]
proto = "udp"
addr = "127.0.0.1:${{E2E_UDP_PORT}}"
advertise = "203.0.113.9:5999"

[[listen]]
proto = "tcp"
addr = "127.0.0.1:{TCP}"

[[listen]]
proto = "tls"
addr = "127.0.0.1:{TLS}"
tls = "edge"

[tls.edge]
cert = "tls/edge.pem"            # relative to this file
key = "tls/edge.key"

[feature]
metrics = false

[modules.txn]
fr_timer = "5s"

[modules.location]
min_expires = "10s"
default_expires = "30s"
max_expires = "60s"

[modules.prometheus]
enabled = "${{feature.metrics}}"
listen = "127.0.0.1:{PROM}"

[routing]
entry = "routes/main.cfg"
""")
open(f"{d}/envs/test.toml", "w").write("""
[feature]
metrics = true

[modules.location]
max_expires = "45s"
""")
RPC = f"{d}/rpc.sock"
# No loadmodule: sl, textops… load for the functions used (--config only).
open(f"{d}/routes/main.cfg", "w").write("""
request_route {
    if (is_method("REGISTER")) { save("location"); exit; }
    if (is_method("OPTIONS")) { sl_send_reply(200, "OK"); exit; }
    if (!lookup("location")) { sl_send_reply(404, "Not Found"); exit; }
    t_relay();
}
""")

uac = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
uac.bind(("127.0.0.1", UAC))
uac.settimeout(3)


def sip(method, user, cid, extra="", contact_port=UAC):
    uac.sendto((f"{method} sip:{user}@127.0.0.1:{UDP} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UAC};branch=z9hG4bK{cid};rport\r\n"
                f"From: <sip:{user}@127.0.0.1>;tag=f{cid}\r\nTo: <sip:{user}@127.0.0.1>\r\nCall-ID: {cid}\r\nCSeq: 1 {method}\r\n"
                f"Contact: <sip:{user}@127.0.0.1:{contact_port}>\r\nMax-Forwards: 70\r\n{extra}Content-Length: 0\r\n\r\n").encode(), ("127.0.0.1", UDP))
    while True:
        m = uac.recv(65535).decode(errors="replace")
        if not m.startswith("SIP/2.0 1"):
            return m


def run(*args, env=None):
    return subprocess.run([BIN, *args], capture_output=True, text=True, env={**os.environ, "E2E_UDP_PORT": str(UDP), "E2E_RPC": RPC, **(env or {})}, timeout=60)


def ctl(*a):
    r = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", RPC, *a], capture_output=True, text=True, timeout=10)
    return r.stdout + r.stderr


args = ["--config", f"{d}/ferrosip.toml", "--overlay", f"{d}/envs/test.toml", "--set", "modules.location.max_contacts=1"]
env = {**os.environ, "E2E_UDP_PORT": str(UDP), "E2E_RPC": RPC}
proxy = subprocess.Popen([BIN, *args], stderr=subprocess.PIPE, text=True, env=env)
# No -l flags to count: wait for the three [[listen]] lines.
early, end = "", time.time() + 10
while early.count("listening on") < 3 and time.time() < end and proxy.poll() is None:
    early += proxy.stderr.readline()
log = []
threading.Thread(target=lambda: [log.append(l) for l in proxy.stderr], daemon=True).start()
try:
    check("three listeners from [[listen]]", early.count("listening on") == 3 and f"udp:127.0.0.1:{UDP}" in early and f"tls:127.0.0.1:{TLS}" in early, early)
    r = sip("REGISTER", "alice", "reg1", "Expires: 3600\r\n")
    check("REGISTER capped by max_expires from the overlay (45s)", r.startswith("SIP/2.0 200") and re.search(r"expires=45\b", r) is not None, r)
    r = sip("REGISTER", "alice", "reg2", "Expires: 3600\r\n", contact_port=UAC + 1)
    check("second contact refused by max_contacts from --set", r.startswith("SIP/2.0 503"), r.split("\r\n")[0])

    # A relayed INVITE carries the advertised address in our Via.
    uac.sendto((f"INVITE sip:alice@127.0.0.1:{UDP} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UAC};branch=z9hG4bKinv1;rport\r\n"
                f"From: <sip:bob@127.0.0.1>;tag=b1\r\nTo: <sip:alice@127.0.0.1>\r\nCall-ID: inv1\r\nCSeq: 1 INVITE\r\n"
                f"Contact: <sip:bob@127.0.0.1:{UAC}>\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n").encode(), ("127.0.0.1", UDP))
    relayed = None
    end = time.time() + 3
    while time.time() < end and relayed is None:
        m = uac.recv(65535).decode(errors="replace")
        if m.startswith("INVITE "):
            relayed = m
    via = next((l for l in (relayed or "").split("\r\n") if l.lower().startswith("via:")), "")
    check("[[listen]] advertise: relayed INVITE's Via has 203.0.113.9:5999", "203.0.113.9:5999" in via, via)

    # TLS with the named section, verified against our CA.
    ctx = ssl.create_default_context(cafile=f"{d}/tls/ca.pem")
    try:
        with socket.create_connection(("127.0.0.1", TLS), timeout=3) as raw, ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall((f"OPTIONS sip:127.0.0.1:{TLS} SIP/2.0\r\nVia: SIP/2.0/TLS 127.0.0.1:1;branch=z9hG4bKtls1\r\nFrom: <sip:t@x>;tag=t\r\n"
                         f"To: <sip:x@x>\r\nCall-ID: tls1\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n").encode())
            got = tls.recv(4096).decode(errors="replace")
        check("TLS listener uses [tls.edge] (verified handshake, OPTIONS answered)", got.startswith("SIP/2.0 200"), got[:60])
    except Exception as e:  # noqa: BLE001
        check("TLS listener uses [tls.edge] (verified handshake, OPTIONS answered)", False, repr(e))

    try:
        body = urllib.request.urlopen(f"http://127.0.0.1:{PROM}/metrics", timeout=3).read().decode()
        check("feature switch from the overlay turns prometheus on", "ferrosip_build_info" in body)
    except Exception as e:  # noqa: BLE001
        check("feature switch from the overlay turns prometheus on", False, repr(e))

    # cfg.reload: max_expires 45s → 20s (reloadable), TCP port changed (restart).
    overlay = open(f"{d}/envs/test.toml").read()
    open(f"{d}/envs/test.toml", "w").write(overlay.replace('max_expires = "45s"', 'max_expires = "20s"'))
    base = open(f"{d}/ferrosip.toml").read()
    open(f"{d}/ferrosip.toml", "w").write(base.replace(f'addr = "127.0.0.1:{TCP}"', f'addr = "127.0.0.1:{TCP + 50}"'))
    out = ctl("cfg.reload")
    check("cfg.reload: max_expires applied live", "registrar.max_expires = 20" in out, out)
    check("cfg.reload: the listener change needs a restart", "needs_restart" in out and "listen" in out, out)
    r = sip("REGISTER", "carol", "reg3", "Expires: 3600\r\n")
    check("…a new REGISTER is capped at 20s", re.search(r"expires=20\b", r) is not None, r)
    with socket.create_connection(("127.0.0.1", TCP), timeout=3):
        check("…the old TCP listener still serves (not applied)", True)
    open(f"{d}/envs/test.toml", "w").write(overlay.replace('max_expires = "45s"', 'max_expires = "5s"\nmax_contactz = 3'))
    out = ctl("cfg.reload")
    check("cfg.reload with a broken file: refused", "max_contactz" in out and "did you mean" in out, out)
    r = sip("REGISTER", "dave", "reg4", "Expires: 3600\r\n")
    check("…and nothing changed (still 20s)", re.search(r"expires=20\b", r) is not None, r)
    open(f"{d}/envs/test.toml", "w").write(overlay)
    open(f"{d}/ferrosip.toml", "w").write(base)
finally:
    proxy.terminate()
    proxy.wait(5)
check("proxy: no panics", "panicked" not in "".join(log))

# check --explain
r = run("check", *args, "--explain")
out = r.stdout
check("check --explain: exit 0, config OK", r.returncode == 0 and "config OK" in r.stderr, r.stderr[-300:])
check("…values with their sources", re.search(r'modules\.location\.max_expires = "45s"\s+# .*envs/test\.toml', out) is not None
      and re.search(r"modules\.location\.max_contacts = 1\s+# --set", out) is not None, out[:1500])
check("…modules in load order with conversions and defaults",
      out.index("usrloc (location)") < out.index("registrar (location)") and 'max_expires = "45s" (→ 45)' in out and "use_received = true  # default" in out, out[-1500:])
check("…modules loaded for the script's functions", re.search(r"^sl .*# loaded for sl_send_reply\(\)", out, re.M) is not None
      and re.search(r"^textops .*# loaded for is_method\(\)", out, re.M) is not None, out[-800:])
check("…reloadable parameters marked", re.search(r"max_expires = .*reloadable", out) is not None)
r = run("check", "-f", f"{d}/routes/main.cfg")
check("plain -f: the same .cfg still needs loadmodule (unknown function)", r.returncode == 1 and "unknown function" in r.stderr, r.stderr[-200:])

# Errors, all at once.
open(f"{d}/bad.toml", "w").write('[core]\nworkerz = 2\n[modules.txn]\nfr_timer = "10 s"\nmax_branches = 100\n[modules.locaton]\n[modules.location]\ndb_mode = "write_back"\n[routing]\nentry = "routes/main.cfg"\n')
r = run("check", "--config", f"{d}/bad.toml")
e = r.stderr
check("bad file: exit 1 and every problem listed", r.returncode == 1 and "5 problems" in e, e)
for frag in ['core.workerz: unknown key (did you mean "workers"?)', 'modules.locaton: unknown module "locaton" (did you mean "location"?)',
             'db_mode: "write_back" is not one of', '(did you mean "write-back"?)', "max_branches: 100 is out of range", 'fr_timer: "10 s": unknown unit']:
    check(f"…reports: {frag}", frag in e, e)

open(f"{d}/routes/dup.cfg", "w").write('loadmodule "sl"\nmodparam("registrar", "max_expires", 10)\nrequest_route { sl_send_reply(200, "OK"); }\n')
open(f"{d}/dup.toml", "w").write('[modules.location]\nmax_expires = "1m"\n[routing]\nentry = "routes/dup.cfg"\n')
r = run("check", "--config", f"{d}/dup.toml")
check("a parameter in both .toml and .cfg is refused", r.returncode == 1 and "set twice" in r.stderr and "dup.cfg" in r.stderr, r.stderr)

open(f"{d}/env.toml", "w").write('[core]\nrpc_socket = "${E2E_NOT_SET}"\n[routing]\nentry = "routes/main.cfg"\n')
r = run("check", "--config", f"{d}/env.toml")
check("unset environment variable: refused with a hint", r.returncode == 1 and "E2E_NOT_SET is not set" in r.stderr and ":-default" in r.stderr, r.stderr)

open(f"{d}/routes/plain.cfg", "w").write('loadmodule "sl"\nrequest_route { sl_send_reply(200, "OK"); }\n')
r = run("check", "-f", f"{d}/routes/plain.cfg")
check("plain -f file.cfg still works (no ferrosip.toml)", r.returncode == 0 and "config OK" in r.stderr, r.stderr[-200:])

fx = run("schema", "--functions").stdout
check("bin/ferrosip/src/functions.txt is up to date (ferrosip schema --functions)", fx == open(f"{ROOT}/bin/ferrosip/src/functions.txt").read(),
      "regenerate: target/release/ferrosip schema --functions > bin/ferrosip/src/functions.txt")
ref = run("schema", "--markdown").stdout
check("docs/modules-reference.md is up to date (ferrosip schema --markdown)", ref == open(f"{ROOT}/docs/modules-reference.md").read(),
      "regenerate: target/release/ferrosip schema --markdown > docs/modules-reference.md")

print(f"\n{failures} FAILED" if failures else "\nall passed")
sys.exit(1 if failures else 0)
