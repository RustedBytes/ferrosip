#!/usr/bin/env python3
"""`.fsr` routing (phase 2 of the configuration redesign), with real traffic.

ferrosip runs from a ferrosip.toml whose [routing] entry is a .fsr file.
Raw UDP user agents check:
- `await txn.relay(…)`:
  - a 2xx goes upstream, and the code after `await` still runs (it logs
    the code and a local set before the wait);
  - a 486 sends the call on to voicemail (a second UAS) from the same
    transaction;
  - no answer within the `timeout:` → our reply, whose reason carries a
    local and a flag set before the wait;
  - two awaits in a row: a gateway answering 503 fails over to a second
    gateway;
- `on reply … where` sees the 180;
- a `kamailio.failure_route` tests `txn.code == BusyHere` on a 486;
- plain replies (`reply(200)`, `guard … else reply(483)`), and status
  codes by name (`reply(BusyHere)`, `r.code == BusyHere` after `await`);
- `[feature]` values are compile-time constants;
- `ferrosip check` reports type errors with file:line:col and a caret;
  `--lowered` prints a .cfg that `ferrosip -c` accepts; `ferrosip fmt` is
  idempotent; `cfg.reload` picks up a changed .fsr;
- `ferrosip test` runs `test` blocks against this routing in-process
  (failover, voicemail, a ban, a mock) and reports a failing assert with
  its position and the value it saw;
- docs/functions-reference.md is what `ferrosip schema --fsr` prints.
Run from the repo root after `cargo build --release`.
"""
import os, re, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = f"{ROOT}/target/release/ferrosip"
PROXY, UAC, A, VM, GW1, GW2, HTTP = 7600, 7610, 7611, 7612, 7613, 7614, 7690
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


MAIN = f"""import dialog
import {{ features }} from config

flag SEEN

shared table hits: Map<Str, Counter> ttl 30s
shared table bans: Map<Str, Bool>
shared table stats: Map<Str, Counter>
dialog var caller: Str

route main(msg: Request) {{
    guard msg.max_forwards > 0 else reply(483)
    if features.closed {{
        reply(503, "Closed")
    }}
    if bans.contains(msg.src.ip) {{
        drop
    }}
    match msg.method {{
        SUBSCRIBE => {{
            // flood: more than 3 from one address bans it
            if hits.incr(msg.src.ip) > 3 {{
                bans.set(msg.src.ip, true)
                drop
            }}
            reply(202)
        }}
        OPTIONS => reply(200)
        INVITE => invite(msg)
        MESSAGE => gateways(msg)
        INFO => reply(BusyHere)
        PUBLISH => {{
            // a Kamailio-style failure route, testing txn.code by name
            kamailio.call("t_on_failure", "BUSY")
            kamailio.call("t_relay")
            exit
        }}
        _ => reply(405)
    }}
}}

fn invite(msg: Request) -> Action {{
    msg.set(SEEN)
    dialog.manage()
    dialog.caller = msg.from.user
    let note = "kept"
    let res = await txn.relay(msg, timeout: 1500ms)
    match res {{
        Final(r) if r.code in 200..299 => {{
            log.info("answered {{r.code}} {{note}}\\n")
            forward(r)
        }}
        Final(r) if r.code == BusyHere => voicemail(msg)
        Timeout => {{
            if msg.is(SEEN) {{
                reply(480, "Nobody Home {{note}}")
            }}
            reply(500)
        }}
        Final(r) => forward(r)
    }}
}}

fn voicemail(msg: Request) -> Action {{
    msg.ruri = "sip:vm@127.0.0.1:{VM}"
    relay(msg)
}}

fn gateways(msg: Request) -> Action {{
    // await inside a loop: each failure tries the next gateway
    for gw in ["sip:127.0.0.1:{GW1}", "sip:127.0.0.1:{GW2}"] {{
        msg.dst_uri = gw
        let res = await txn.relay(msg, timeout: 2s)
        match res {{
            Final(r) if r.code < 500 => forward(r)
            _ => count("failover")
        }}
    }}
    reply(503, "All gateways failed")
}}

// A helper without the message: handlers can call it too.
fn count(what: Str) {{
    stats.incr(what)
}}

on kamailio.failure_route(msg: Request, name: "BUSY") {{
    if txn.code == BusyHere || txn.code == RequestTimeout {{
        reply(480, "Busy in failure route ({{txn.reason}})")
    }}
}}

on reply(r: Reply) where r.code == 180 {{
    log.info("ringing {{r.call_id}}\\n")
}}

on dialog.started(d: Dialog) {{
    log.info("started {{d.call_id}} {{d.caller}}\\n")
}}

on dialog.ended(d: Dialog) {{
    log.info("cdr {{d.call_id}} {{d.caller}} {{d.duration}} {{d.end_reason}}\\n")
}}

on timer(every: 1s) {{
    count("ticks")
}}

on http(req: HttpRequest) where req.path == "/api/ticks" {{
    req.reply(200, "{{stats.get("ticks")}}")
}}

on http(req: HttpRequest) where req.path == "/api/bans" {{
    if bans.contains(req.query) {{
        req.reply(200, "banned")
    }}
    req.reply(200, "free")
}}

on http(req: HttpRequest) where req.path == "/api/bans/clear" && req.method == "POST" {{
    bans.clear()
    hits.clear()
    req.reply(204)
}}
"""


def hdr(m, name):
    for l in m.split(b"\r\n"):
        if l.lower().startswith(name.lower().encode() + b":"):
            return l.split(b":", 1)[1].strip().decode()
    return ""


def first_line(m):
    return m.split(b"\r\n", 1)[0].decode() if m else "timeout"


class Peer:
    def __init__(self, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.addr, self.seen = None, set()

    def expect(self, prefix, timeout=2.0):
        """The next message starting with `prefix` (requests: not a retransmission)."""
        end = time.time() + timeout
        while time.time() < end:
            self.s.settimeout(max(0.05, end - time.time()))
            try:
                d, a = self.s.recvfrom(65535)
            except socket.timeout:
                return None
            if not d.startswith(b"SIP/2.0"):
                self.addr = a
                key = hdr(d, "Via")
                if key in self.seen:
                    continue
                self.seen.add(key)
            if d.startswith(prefix.encode()):
                return d
        return None

    def reply(self, req, code, reason):
        keep = []
        for l in req.decode().split("\r\n"):
            name = l.split(":")[0]
            if name == "To" and code > 100:
                l += f";tag=ua{self.s.getsockname()[1]}"
            if name in ("Via", "From", "To", "Call-ID", "CSeq"):
                keep.append(l)
        self.s.sendto((f"SIP/2.0 {code} {reason}\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n").encode(), self.addr)

    def drain(self):
        self.s.settimeout(0.05)
        try:
            while True:
                self.s.recv(65535)
        except socket.timeout:
            pass


n = [0]


def request(method, ruri, mf=70):
    n[0] += 1
    return (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UAC};branch=z9hG4bKfsr{n[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: {mf}\r\nFrom: <sip:caller@x>;tag=c{n[0]}\r\nTo: <sip:callee@x>\r\nCall-ID: fsr-{n[0]}\r\n"
            f"CSeq: 1 {method}\r\nContent-Length: 0\r\n\r\n").encode()


def final_at(uac, timeout=4.0):
    """The first final reply the caller gets."""
    end = time.time() + timeout
    while time.time() < end:
        m = uac.expect("SIP/2.0", max(0.05, end - time.time()))
        if m is None:
            return None
        if not first_line(m).startswith("SIP/2.0 1"):
            return m
    return None


d = tempfile.mkdtemp(prefix="ferrosip-e2e-fsr-")
os.makedirs(f"{d}/routes")
toml = f"""[core]
workers = 2
rpc_socket = "{d}/rpc.sock"

[[listen]]
proto = "udp"
addr = "127.0.0.1:{PROXY}"

[feature]
closed = false

[modules.http]
listen = "127.0.0.1:{HTTP}"

[modules.txn]
wait_timer = "1s"

[routing]
entry = "routes/main.fsr"
"""
open(f"{d}/ferrosip.toml", "w").write(toml)
open(f"{d}/routes/main.fsr", "w").write(MAIN)


def run(*args):
    return subprocess.run([BIN, *args], capture_output=True, text=True, cwd=d)


# --- tooling -----------------------------------------------------------
c = run("check", "--config", "ferrosip.toml")
check("ferrosip check accepts the .fsr routing", c.returncode == 0, c.stderr)
low = run("check", "--config", "ferrosip.toml", "--lowered")
check("--lowered prints the generated .cfg", "request_route {" in low.stdout and "t_relay_await(" in low.stdout and "route[voicemail]" in low.stdout, low.stdout[:400])
cfg = low.stdout.replace("# generated", "loadmodule \"tm\"\nloadmodule \"sl\"\nloadmodule \"maxfwd\"\nloadmodule \"xlog\"\n# generated", 1).replace(
    "loadmodule \"rtimer\"\n", f"loadmodule \"rtimer\"\nmodparam(\"xhttp\", \"listen\", \"127.0.0.1:{HTTP + 1}\")\n", 1)
open(f"{d}/lowered.cfg", "w").write(cfg)
c = run("-c", "-f", "lowered.cfg")
check("the lowered .cfg passes `ferrosip -c`", c.returncode == 0, c.stderr)

open(f"{d}/routes/bad.fsr", "w").write("""route main(msg: Request) {
    msg.ruri.usr = "bob"
    txn.relay(msg, timeout: "abc")
    let res = await txn.relay(msg)
    match res {
        Final(r) => forward(r)
    }
}
""")
open(f"{d}/bad.toml", "w").write(toml.replace("routes/main.fsr", "routes/bad.fsr"))
c = run("check", "--config", "bad.toml")
err = c.stderr
check("type errors: every one, with file:line:col and a caret",
      c.returncode != 0 and "routes/bad.fsr:2:5: msg has no field \"ruri.usr\" (did you mean \"ruri.user\"?)" in err
      and "routes/bad.fsr:3:20: txn.relay() has no argument \"timeout\"" in err
      and "this match doesn't handle every result: add Timeout" in err and "^^^" in err, err)

ugly = MAIN.replace("    guard", "  guard", 1).replace("flag SEEN\n", "flag SEEN\n\n\n")
open(f"{d}/routes/ugly.fsr", "w").write(ugly)
f1 = run("fmt", "routes/ugly.fsr")
once = open(f"{d}/routes/ugly.fsr").read()
f2 = run("fmt", "--check", "routes/ugly.fsr")
check("ferrosip fmt formats, and is idempotent", f1.returncode == 0 and "formatted" in f1.stdout and f2.returncode == 0 and once != ugly, f1.stdout + f1.stderr + f2.stdout + f2.stderr)
os.remove(f"{d}/routes/ugly.fsr")

# --- traffic -------------------------------------------------------------
p = subprocess.Popen([BIN, "--config", f"{d}/ferrosip.toml"], stderr=subprocess.PIPE, text=True, cwd=d)
wait_listening(p)
uac, a, vm, gw1, gw2 = (Peer(x) for x in (UAC, A, VM, GW1, GW2))
P = ("127.0.0.1", PROXY)
try:
    uac.s.sendto(request("OPTIONS", f"sip:x@127.0.0.1:{PROXY}"), P)
    check("reply(200) to OPTIONS", first_line(final_at(uac)) == "SIP/2.0 200 OK")
    uac.s.sendto(request("OPTIONS", f"sip:x@127.0.0.1:{PROXY}", mf=0), P)
    check("guard msg.max_forwards > 0 else reply(483)", first_line(final_at(uac)) == "SIP/2.0 483 Too Many Hops")
    uac.s.sendto(request("BYE", f"sip:x@127.0.0.1:{PROXY}"), P)
    check("match … _ => reply(405)", first_line(final_at(uac)) == "SIP/2.0 405 Method Not Allowed")
    uac.s.sendto(request("INFO", f"sip:x@127.0.0.1:{PROXY}"), P)
    check("a status code by name: reply(BusyHere) → 486 Busy Here", first_line(final_at(uac)) == "SIP/2.0 486 Busy Here")

    # 2xx: forwarded, and the code after await ran (log line with the local).
    uac.s.sendto(request("INVITE", f"sip:ok@127.0.0.1:{A}"), P)
    inv = a.expect("INVITE")
    a.reply(inv, 180, "Ringing")
    ring = uac.expect("SIP/2.0 180")
    a.reply(inv, 200, "OK")
    fin = final_at(uac)
    check("await: the 180 and the 200 reach the caller", ring is not None and first_line(fin) == "SIP/2.0 200 OK", first_line(fin))

    # 486 → voicemail, on the same transaction.
    a.drain()
    uac.s.sendto(request("INVITE", f"sip:busy@127.0.0.1:{A}"), P)
    inv = a.expect("INVITE")
    a.reply(inv, 486, "Busy Here")
    vinv = vm.expect("INVITE")
    check("486 → voicemail branch from the code after await (r.code == BusyHere)", vinv is not None and first_line(vinv).startswith("INVITE sip:vm@"), first_line(vinv))
    if vinv:
        vm.reply(vinv, 200, "OK")
    fin = final_at(uac)
    check("the caller gets voicemail's 200 (not the 486)", first_line(fin) == "SIP/2.0 200 OK", first_line(fin))

    # A failure route: txn.code == BusyHere on the upstream's 486.
    a.drain()
    uac.s.sendto(request("PUBLISH", f"sip:busy@127.0.0.1:{A}"), P)
    pub = a.expect("PUBLISH")
    if pub:
        a.reply(pub, 486, "Busy Here")
    fin = final_at(uac)
    check("failure route: txn.code == BusyHere → its reply, with txn.reason",
          first_line(fin) == "SIP/2.0 480 Busy in failure route (Busy Here)", first_line(fin))
    uac.s.sendto(request("PUBLISH", f"sip:gone@127.0.0.1:{A}"), P)
    pub = a.expect("PUBLISH")
    if pub:
        a.reply(pub, 404, "Not Found")
    fin = final_at(uac)
    check("failure route: another code (404) goes upstream as it is", first_line(fin) == "SIP/2.0 404 Not Found", first_line(fin))

    # No answer → our 480, with a local and a flag kept across the wait.
    a.drain()
    t0 = time.time()
    uac.s.sendto(request("INVITE", f"sip:slow@127.0.0.1:{A}"), P)
    inv = a.expect("INVITE")
    a.reply(inv, 100, "Trying")
    fin = final_at(uac, timeout=6)
    took = time.time() - t0
    check("timeout: 480 with a reason built from a local, after the 1.5s timeout:",
          first_line(fin) == "SIP/2.0 480 Nobody Home kept" and 1.2 < took < 4, f"{first_line(fin)} after {took:.1f}s")

    # Two awaits in a row: 503 from the first gateway, 200 from the second.
    uac.s.sendto(request("MESSAGE", f"sip:pstn@127.0.0.1:{PROXY}"), P)
    m1 = gw1.expect("MESSAGE")
    if m1:
        gw1.reply(m1, 503, "Service Unavailable")
    m2 = gw2.expect("MESSAGE")
    if m2:
        gw2.reply(m2, 200, "OK")
    fin = final_at(uac)
    check("failover loop: gateway 1 answers 503, gateway 2's 200 reaches the caller", m1 is not None and m2 is not None and first_line(fin) == "SIP/2.0 200 OK", first_line(fin))

    # Both gateways fail: the loop ends and the code after it answers.
    uac.s.sendto(request("MESSAGE", f"sip:pstn@127.0.0.1:{PROXY}"), P)
    for gw in (gw1, gw2):
        m = gw.expect("MESSAGE")
        if m:
            gw.reply(m, 503, "Service Unavailable")
    fin = final_at(uac)
    check("failover loop: every gateway failed → the reply after the loop", first_line(fin) == "SIP/2.0 503 All gateways failed", first_line(fin))

    # A dialog: started and ended handlers see the dialog var set in the route.
    a.drain()
    uac.drain()
    inv_msg = request("INVITE", f"sip:dlg@127.0.0.1:{A}")
    uac.s.sendto(inv_msg, P)
    inv = a.expect("INVITE")
    a.reply(inv, 200, "OK")
    ok = final_at(uac)
    call_id = hdr(inv_msg, "Call-ID")
    to = hdr(ok, "To") if ok else ""
    via = hdr(inv_msg, "Via").replace("branch=z9hG4bK", "branch=z9hG4bKack")
    ack = (f"ACK sip:dlg@127.0.0.1:{A} SIP/2.0\r\nVia: {via}\r\nMax-Forwards: 70\r\nFrom: {hdr(inv_msg, 'From')}\r\nTo: {to}\r\n"
           f"Call-ID: {call_id}\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n")
    uac.s.sendto(ack.encode(), P)
    time.sleep(1.2)
    bye = ack.replace("ACK sip", "BYE sip").replace("CSeq: 1 ACK", "CSeq: 2 BYE").replace("branch=z9hG4bKack", "branch=z9hG4bKbye")
    uac.s.sendto(bye.encode(), P)
    time.sleep(0.5)
    check("dialog: the INVITE was answered", ok is not None and first_line(ok) == "SIP/2.0 200 OK", first_line(ok))

    # Shared tables: the 4th SUBSCRIBE bans the address; the HTTP API sees
    # the ban and clears it.
    def http(method, path):
        try:
            with urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{HTTP}{path}", method=method), timeout=3) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
    uac.drain()  # the BYE's answer
    codes = []
    for _ in range(5):
        uac.s.sendto(request("SUBSCRIBE", f"sip:x@127.0.0.1:{PROXY}"), P)
        m = final_at(uac, timeout=0.6)
        codes.append(first_line(m)[8:11] if m else "drop")
    check("shared table: three SUBSCRIBEs answered, then the address is banned", codes == ["202", "202", "202", "drop", "drop"], str(codes))
    uac.s.sendto(request("OPTIONS", f"sip:x@127.0.0.1:{PROXY}"), P)
    check("a banned address gets nothing at all", final_at(uac, timeout=0.6) is None)
    check("on http: GET /api/bans?127.0.0.1 → banned", http("GET", "/api/bans?127.0.0.1") == (200, "banned"))
    check("on http: GET /api/bans?10.9.9.9 → free", http("GET", "/api/bans?10.9.9.9") == (200, "free"))
    check("on http: POST /api/bans/clear → 204", http("POST", "/api/bans/clear")[0] == 204)
    uac.s.sendto(request("OPTIONS", f"sip:x@127.0.0.1:{PROXY}"), P)
    check("after clearing, the address is answered again", first_line(final_at(uac)) == "SIP/2.0 200 OK")
    check("on http: an unmatched path is a 404", http("GET", "/nope")[0] == 404)
    st, ticks = http("GET", "/api/ticks")
    check("on timer(every: 1s) counted in a shared table (through a helper fn)", st == 200 and ticks.isdigit() and int(ticks) >= 2, f"{st} {ticks!r}")

    # cfg.reload of a changed .fsr: OPTIONS now answered 202.
    open(f"{d}/routes/main.fsr", "w").write(MAIN.replace("OPTIONS => reply(200)", "OPTIONS => reply(202)"))
    r = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", f"{d}/rpc.sock", "cfg.reload"], capture_output=True, text=True)
    uac.s.sendto(request("OPTIONS", f"sip:x@127.0.0.1:{PROXY}"), P)
    check("cfg.reload picks up the changed .fsr", first_line(final_at(uac)) == "SIP/2.0 202 Accepted", r.stdout + r.stderr)
finally:
    time.sleep(0.3)
    p.terminate()
    log = p.early_log + p.stderr.read()
    p.wait()

check("on reply … where r.code == 180 ran", "ringing fsr-" in log, log[-800:])
check("the code after await ran for the 2xx (and saw the local)", "answered 200 kept" in log, log[-800:])
check("on dialog.started saw the dialog var set by the route", f"started {call_id} caller" in log, log[-1200:])
cdr = re.search(rf"cdr {re.escape(call_id)} caller (\d+) (\w+)", log)
check("on dialog.ended: the CDR line has the var, a duration and the end reason", cdr is not None and int(cdr.group(1)) >= 1 and cdr.group(2) == "caller_bye", log[-1200:])

# ferrosip test: tests of this routing, run in-process (no sockets).
open(f"{d}/routes/main.fsr", "w").write(MAIN)  # undo the reload check's change
open(f"{d}/routes/main_test.fsr", "w").write(f"""
test "OPTIONS is answered" {{
    send("OPTIONS sip:x@127.0.0.1")
    assert(reply_code() == 200)
    assert(relays() == 0)
}}

test "failover loop: 503, then the second gateway" {{
    send("MESSAGE sip:pstn@127.0.0.1")
    assert(relay_dest() == "127.0.0.1:{GW1}")
    answer(503)
    assert(relay_dest(2) == "127.0.0.1:{GW2}")
    answer(200)
    assert(reply_code() == 200)
    assert(stats.get("failover") == 1)
}}

test "busy goes to voicemail" {{
    send(\"\"\"
        INVITE sip:busy@127.0.0.1:{A}
        Contact: <sip:caller@10.9.9.9>
    \"\"\")
    answer(486)
    assert(relay_uri(2) == "sip:vm@127.0.0.1:{VM}")
    answer(200)
    assert(reply_code() == 200)
}}

test "a SUBSCRIBE flood bans the source" {{
    for i in 1..4 {{
        send("SUBSCRIBE sip:x@127.0.0.1", from: "10.1.1.1:5060")
    }}
    assert(reply_code() == 0)
    assert(bans.contains("10.1.1.1"))
    send("OPTIONS sip:x@127.0.0.1", from: "10.1.1.2:5060")
    assert(reply_code() == 200)
}}

test "with dialog.manage mocked" {{
    dialog.manage = false
    send("INVITE sip:ok@127.0.0.1:{A}")
    assert(calls(dialog.manage) == 1)
    assert(relays() == 1)
}}
""")
t = run("test", "--config", "ferrosip.toml", "routes/main_test.fsr")
check("ferrosip test: every test passes", t.returncode == 0 and "5 passed, 0 failed" in t.stdout, t.stdout + t.stderr[-1500:])
open(f"{d}/routes/fail_test.fsr", "w").write("""test "expects the wrong code" {
    send("OPTIONS sip:x@127.0.0.1")
    assert(reply_code() == 404)
}
""")
t = run("test", "--config", "ferrosip.toml", "routes/fail_test.fsr")
check("ferrosip test: a failing assert fails the run, with where and what it saw",
      t.returncode != 0 and "routes/fail_test.fsr:3: assert(reply_code() == 404) failed: reply_code() is \"200\"" in t.stdout and "0 passed, 1 failed" in t.stdout, t.stdout + t.stderr[-800:])
t = run("test", "--config", "ferrosip.toml", "routes/main_test.fsr", "--filter", "voicemail")
check("ferrosip test --filter runs the matching tests only", t.returncode == 0 and "1 passed, 0 failed" in t.stdout, t.stdout)

# Regressions: an `await` on a request nothing edited (headers parsed
# lazily: the Via branch must still be found), and a failed action that
# already answered (save's 423) must not get a second reply.
d2 = f"{d}/plain"
os.makedirs(d2)
open(f"{d2}/ferrosip.toml", "w").write(f'''[[listen]]
proto = "udp"
addr = "127.0.0.1:{PROXY + 50}"
[modules.location]
min_expires = "60s"
[routing]
entry = "main.fsr"
''')
open(f"{d2}/main.fsr", "w").write('''import location

route main(msg: Request) {
    if msg.method == REGISTER {
        location.save(msg)
    }
    call(msg)
}

fn call(msg: Request) -> Action {
    let res = await txn.relay(msg, timeout: 30s)
    match res {
        Final(r) if r.code == 503 => reply(480)
        Final(r) => forward(r)
        Timeout => reply(408)
    }
}

test "a 503 to an unedited request resumes the code after await" {
    send("INVITE sip:123@10.0.0.5:5060")
    answer(503)
    assert(reply_code() == 480)
}

test "a 486 is forwarded" {
    send("INVITE sip:123@10.0.0.5:5060")
    answer(486)
    assert(reply_code() == 486)
}

test "a failed save answers once" {
    send(\"\"\"
        REGISTER sip:example.com
        To: <sip:alice@example.com>
        Contact: <sip:alice@10.0.0.9:5060>
        Expires: 10
    \"\"\")
    assert(reply_code() == 423)
}
''')
t = subprocess.run([BIN, "test", "--config", f"{d2}/ferrosip.toml"], capture_output=True, text=True, cwd=d2)
check("ferrosip test: await on an unedited request, and no second reply after a failed save", t.returncode == 0 and "3 passed, 0 failed" in t.stdout, t.stdout + t.stderr[-800:])

# The registrar's optional arguments and the new functions, typed:
# save_and_continue(flags, aor), fetch_contacts + $ulc, unregister,
# is_registered(uri), lookup(uri), lookup_branches().
d2b = f"{d}/registrar"
os.makedirs(d2b)
open(f"{d2b}/ferrosip.toml", "w").write(f'''[[listen]]
proto = "udp"
addr = "127.0.0.1:{PROXY + 55}"
[routing]
entry = "main.fsr"
''')
open(f"{d2b}/main.fsr", "w").write('''import location

route main(msg: Request) {
    if msg.method == REGISTER {
        if location.save_and_continue(2, "sip:shared@example.com") {
            reply(200, "Quiet")
        }
        reply(500, "Not saved")
    }
    if msg.headers["X-Op"] == "fetch" {
        if location.fetch_contacts("sip:shared@example.com", "p") {
            let n = pv("$ulc(p=>count)")
            let a = pv("$ulc(p=>addr)")
            location.free_contacts("p")
            reply(200, "{n} {a}")
        }
        reply(404, "none")
    }
    if msg.headers["X-Op"] == "unregister" {
        location.unregister("sip:shared@example.com")
        reply(200, "gone")
    }
    if msg.headers["X-Op"] == "registered" {
        if location.is_registered("sip:shared@example.com") {
            reply(200, "yes")
        }
        reply(404, "no")
    }
    if msg.headers["X-Op"] == "branches" {
        guard location.lookup_branches() else reply(404)
        relay(msg)
    }
    guard location.lookup("sip:shared@example.com") else reply(404)
    relay(msg)
}

test "save(2, aor): the route replies; the contact is under the aor" {
    send(\"\"\"
        REGISTER sip:example.com
        To: <sip:alice@example.com>
        Contact: <sip:alice@10.0.0.9:5060>
        Expires: 600
    \"\"\")
    assert(reply_code() == 200)
    assert(reply_reason() == "Quiet")
    send(\"\"\"
        OPTIONS sip:x@example.com
        X-Op: registered
    \"\"\")
    assert(reply_reason() == "yes")
    send(\"\"\"
        OPTIONS sip:x@example.com
        X-Op: fetch
    \"\"\")
    assert(reply_reason() == "1 sip:alice@10.0.0.9:5060")
    send("MESSAGE sip:nobody@example.com")
    wait(300ms)
    assert(relay_dest() == "127.0.0.1:5060")
    send(\"\"\"
        OPTIONS sip:x@example.com
        X-Op: unregister
    \"\"\")
    send(\"\"\"
        OPTIONS sip:x@example.com
        X-Op: registered
    \"\"\")
    assert(reply_reason() == "no")
}
''')
t = subprocess.run([BIN, "test", "--config", f"{d2b}/ferrosip.toml"], capture_output=True, text=True, cwd=d2b)
check("ferrosip test: save_and_continue(flags, aor), fetch_contacts + $ulc, unregister, is_registered(uri), lookup(uri)",
      t.returncode == 0 and "1 passed, 0 failed" in t.stdout, t.stdout + t.stderr[-1500:])

# await http.get(…): a routing service over HTTP; the call resumes with a
# typed result (r.ok, r.status, r.body) and relays to what it says.
import http.server, threading
class Routes(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        user = self.path.split("user=")[-1]
        body = {"alice": "10.0.0.7:5060"}.get(user)
        self.send_response(200 if body else 404)
        self.end_headers()
        self.wfile.write((body or "unknown").encode())
    def log_message(self, *a):
        pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Routes)
threading.Thread(target=srv.serve_forever, daemon=True).start()
hport = srv.server_address[1]
d3 = f"{d}/httpawait"
os.makedirs(d3)
open(f"{d3}/ferrosip.toml", "w").write(f'''[[listen]]
proto = "udp"
addr = "127.0.0.1:{PROXY + 60}"
[routing]
entry = "main.fsr"
''')
open(f"{d3}/main.fsr", "w").write(f'''import http

route main(msg: Request) {{
    let r = await http.get("http://127.0.0.1:{hport}/route?user={{msg.ruri.user}}", timeout: 2s)
    if r.ok && r.status == 200 {{
        msg.dst_uri = "sip:{{r.body}}"
        relay(msg)
    }}
    if !r.ok {{
        reply(503, "Routing service down")
    }}
    reply(404, "No route: {{r.status}}")
}}

test "the routing service answers: relay where it says" {{
    send("MESSAGE sip:alice@127.0.0.1")
    wait(500ms)
    assert(relay_dest() == "10.0.0.7:5060")
}}

test "unknown user: the service's 404" {{
    send("MESSAGE sip:bob@127.0.0.1")
    wait(500ms)
    assert(reply_code() == 404)
    assert(reply_reason() == "No route: 404")
}}
''')
open(f"{d3}/down_test.fsr", "w").write('''test "the service is down" {
    send("MESSAGE sip:alice@127.0.0.1")
    wait(500ms)
    assert(reply_code() == 503)
}
''')
t = subprocess.run([BIN, "test", "--config", f"{d3}/ferrosip.toml"], capture_output=True, text=True, cwd=d3)
check("await http.get: the script resumes with the response (relay to its body; its 404)", t.returncode == 0 and "2 passed, 0 failed" in t.stdout, t.stdout + t.stderr[-800:])
srv.shutdown()
srv.server_close()
t = subprocess.run([BIN, "test", "--config", f"{d3}/ferrosip.toml", "down_test.fsr", "--filter", "down"], capture_output=True, text=True, cwd=d3)
check("await http.get: a service that's down gives r.ok == false", t.returncode == 0 and "1 passed, 0 failed" in t.stdout, t.stdout + t.stderr[-800:])

# [feature] constants: closed = true answers everything with 503.
c = run("check", "--config", "ferrosip.toml", "--set", "feature.closed=true", "--lowered")
check("[feature] values are constants (closed = true → an unconditional 503)", 'send_reply(503, "Closed");' in c.stdout and "if (" not in c.stdout.split("request_route {")[1].split("send_reply(503")[0].split("mf_process")[1][20:], c.stdout[:500])

c = subprocess.run([BIN, "check", "--config", f"{ROOT}/examples/fsr/ferrosip.toml", "--overlay", f"{ROOT}/examples/fsr/envs/prod.toml"], capture_output=True, text=True)
f = subprocess.run([BIN, "fmt", "--check", f"{ROOT}/examples/fsr/routes"], capture_output=True, text=True)
check("examples/fsr checks, and is formatted", c.returncode == 0 and f.returncode == 0, c.stderr + f.stdout + f.stderr)
for ex in ("fsr", "toml"):
    l = subprocess.run([BIN, "lint", "--config", "ferrosip.toml", "-D", "warnings"], capture_output=True, text=True, cwd=f"{ROOT}/examples/{ex}")
    check(f"examples/{ex} passes ferrosip lint -D warnings", l.returncode == 0, l.stderr[-1500:])
# The container's config (Dockerfile, docker-compose.yml).
c = subprocess.run([BIN, "check", "--config", f"{ROOT}/etc/docker/ferrosip.toml"], capture_output=True, text=True)
f = subprocess.run([BIN, "fmt", "--check", f"{ROOT}/etc/docker/routes"], capture_output=True, text=True)
l = subprocess.run([BIN, "lint", "--config", "ferrosip.toml", "-D", "warnings"], capture_output=True, text=True, cwd=f"{ROOT}/etc/docker")
check("etc/docker (the container's config) checks, is formatted and passes lint -D warnings",
      c.returncode == 0 and f.returncode == 0 and l.returncode == 0, c.stderr + f.stdout + l.stderr[-1500:])
t = subprocess.run([BIN, "test", "--config", f"{ROOT}/examples/fsr/ferrosip.toml", f"{ROOT}/examples/fsr/routes/main_test.fsr"], capture_output=True, text=True)
check("examples/fsr's tests pass", t.returncode == 0 and " 0 failed" in t.stdout, t.stdout + t.stderr[-800:])
ref = subprocess.run([BIN, "schema", "--fsr"], capture_output=True, text=True).stdout
check("docs/functions-reference.md is up to date (ferrosip schema --fsr)", ref == open(f"{ROOT}/docs/functions-reference.md").read())

# A .fsr checked without ferrosip.toml: the modules it uses load with
# their dependencies (location.save → registrar after usrloc).
alone = tempfile.mkdtemp(prefix="ferrosip-e2e-fsr-alone-")
open(f"{alone}/main.fsr", "w").write("import location, dialog\n\nroute main(msg: Request) {\n    if msg.method == REGISTER {\n        location.save(msg)\n    }\n    dialog.manage()\n    relay(msg)\n}\n")
p = subprocess.run([BIN, "check", "-f", "main.fsr"], cwd=alone, capture_output=True, text=True)
check("check -f x.fsr without ferrosip.toml loads module dependencies (usrloc, tm)", p.returncode == 0 and "config OK" in p.stderr, p.stderr[-300:])

print("\nall passed" if failures == 0 else f"\n{failures} FAILED")
sys.exit(1 if failures else 0)
