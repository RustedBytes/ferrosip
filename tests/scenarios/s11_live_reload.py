"""s11-live-reload: cfg.reload under traffic. The routing and a reloadable
TOML value change in a copy of the scenario (in sc.tmp); broken edits are
refused and change nothing; a call suspended in `await` across the reload
finishes in the routing it was suspended in."""
import os
import shutil
import subprocess
import threading
import time

import sipkit


def reload(px):
    """cfg.reload: the parsed result (a dict) or, on refusal, ferroctl's text
    (stdout + stderr: Proxy.rpc() keeps only stdout)."""
    r = subprocess.run([sipkit.CTL, "-s", px.env["RPC_SOCK"], "cfg.reload"], capture_output=True, text=True, timeout=10)
    try:
        return __import__("json").loads(r.stdout)
    except ValueError:
        return f"rc={r.returncode} {r.stdout}{r.stderr}"


class Traffic:
    """A UA sending a MESSAGE every 20ms in the background; records each final."""

    def __init__(self, ua):
        self.ua, self.sent, self.stop_ = ua, [], threading.Event()
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        while not self.stop_.is_set():
            r = self.ua.request("MESSAGE", "sip:load@example.com", body="x", content_type="text/plain")
            self.sent.append(r["call_id"])
            time.sleep(0.02)

    def stop(self):
        self.stop_.set()
        self.t.join()
        time.sleep(1.0)
        finals = {}
        while True:
            m = self.ua.recv(0.2, lambda m: m.is_reply and m.code >= 200)
            if m is None:
                break
            finals.setdefault(m.get("call-id"), m.code)
        return finals


def sipdump_of(px, call_id):
    """Each message of `call_id` in the proxy's sip_dump output (stderr):
    its direction, start line and CSeq; then any warning or error."""
    out = []
    for chunk in "".join(px.lines).split("||||||||||||||||||||"):
        if call_id not in chunk:
            continue
        lines = chunk.strip().splitlines()
        tag = next((l for l in lines if l.startswith("tag:")), "")
        start = next((l for l in lines if l.startswith("SIP/2.0 ") or " sip:" in l.split("\t")[0][:30] and "SIP/2.0" in l), "")
        cseq = next((l for l in lines if l.lower().startswith("cseq:")), "")
        out.append(f"{tag} | {start.strip()} | {cseq.strip()}")
    out += [l.strip() for l in px.lines if "WARN" in l or "ERR" in l]
    return "\n".join(out)[-4000:]


def run(sc):
    live = os.path.join(sc.tmp, "live")
    shutil.copytree(sc.dir, live, ignore=shutil.ignore_patterns("README.md"))
    toml_p, fsr_p = os.path.join(live, "ferrosip.toml"), os.path.join(live, "routes", "main.fsr")
    toml0, fsr0 = open(toml_p).read(), open(fsr_p).read()

    def write(toml=None, fsr=None):
        if toml is not None:
            open(toml_p, "w").write(toml)
        if fsr is not None:
            open(fsr_p, "w").write(fsr)

    sip = sc.port()
    up = sc.ua("upstream", sip)
    pending = {}

    def h(m):
        if m.method == "ACK":
            return None
        if m.get("x-silent"):
            return None
        if m.method == "INVITE" and m.ruri.startswith("sip:slow@"):
            pending[m.get("call-id")] = m        # answered later by the test
            up.respond(m, 180, "Ringing")
            return None
        return (200, "OK")
    up.handler = h
    # Every SIP message on stderr (sip_dump mode 8): what the proxy saw of the
    # call suspended across the reload is printed if that check fails.
    px = sc.proxy(live, sc.env(SIP_PORT=sip, UPSTREAM=f"sip:127.0.0.1:{up.port}"), name="live",
                  extra=("--set", "modules.sip_dump.enable=true", "--set", "modules.sip_dump.mode=8"))
    ua = sc.ua("alice", sip)

    def probe(headers=None):
        r = ua.request("OPTIONS", "sip:bob@example.com", headers=headers)
        rep = ua.final(call_id=r["call_id"])
        m = next((x for x in up.received if x.get("call-id") == r["call_id"]), None)
        return rep, m

    def silent_408():
        t0 = time.time()
        r = ua.request("OPTIONS", "sip:bob@example.com", headers={"X-Silent": "1"})
        rep = ua.final(6, call_id=r["call_id"])
        return (rep.code if rep else None), time.time() - t0

    rep, m = probe()
    sc.check("v1: X-Routing v1 and X-Release r1", m is not None and m.get("x-routing") == "v1" and m.get("x-release") == "r1", m and m.raw)
    code, dt = silent_408()
    sc.check("v1: a silent upstream → 408 after fr_timer 1s", code == 408 and 0.8 <= dt < 1.8, (code, dt))

    # A call established under v1 (for an in-dialog BYE later), and one suspended in `await` (ringing).
    up.auto_answer()
    est_r, est = ua.call("sip:bob@example.com")
    up.handler = h
    sc.check("a call established under v1", est is not None, est_r)
    slow = ua.invite("sip:slow@example.com")
    t_slow = time.time()  # its await gives up after 60s (the routing's timeout)
    ring = ua.recv(3, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == slow["call_id"])
    sc.check("a second call rings under v1 (its transaction waits in await)", ring is not None and slow["call_id"] in pending, ring)

    traffic = Traffic(sc.ua("load", sip))
    time.sleep(0.3)

    # --- the reload: new routing (v2: a header renamed, a statement before the await, another 486 reason),
    # a reloadable timer and a [feature] value.
    fsr_v2 = (fsr0.replace("X-Routing: v1", "X-Routing: v2")
              .replace('reply(486, "Busy v1")', 'reply(486, "Busy v2")')
              .replace("    route_set.record()\n", '    text.append_header("X-Before-Await: v2\\r\\n")\n    route_set.record()\n'))
    toml_v2 = toml0.replace('fr_timer = "1s"', 'fr_timer = "2s"').replace('release = "r1"', 'release = "r2"')
    write(toml_v2, fsr_v2)
    res = reload(px)
    sc.check("cfg.reload with a new .fsr, fr_timer 2s and a new [feature] → a result, not an error", isinstance(res, dict), res)
    applied = str(res.get("applied")) if isinstance(res, dict) else ""
    sc.check("…fr_timer is reported as applied", "fr_timer" in applied, res)
    sc.check("…nothing needs a restart", isinstance(res, dict) and not res.get("needs_restart"), res)

    rep, m = probe()
    sc.check("after the reload: X-Routing v2", m is not None and m.get("x-routing") == "v2", m and m.raw)
    sc.check("after the reload: X-Release r2 (the [feature] change reaches the routing)", m is not None and m.get("x-release") == "r2",
             m and m.get("x-release"))
    code, dt = silent_408()
    sc.check("after the reload: 408 after fr_timer 2s (1.7..3s)", code == 408 and 1.7 <= dt < 3.0, (code, dt))

    # The call that waited in await across the reload gets its 486 now, from the routing it started in (v1).
    inv = pending.get(slow["call_id"])
    if inv is not None:
        up.respond(inv, 486, "Busy Here")
    rep = ua.final(4, method="INVITE", call_id=slow["call_id"])
    seen = [(m.get("via") or "").split("branch=")[-1][:40] for m in list(up.received) if m.method == "INVITE" and m.get("call-id") == slow["call_id"]]
    sc.check("the call suspended in await across the reload gets 486", rep is not None and rep.code == 486,
             (rep, f"{time.time() - t_slow:.1f}s after its INVITE", f"upstream held the INVITE: {inv is not None}",
              f"INVITE branches the upstream got for it: {seen}", f"tm.stats: {px.rpc('tm.stats')}", sipdump_of(px, slow["call_id"])))
    sc.check("…with v1's reason (a suspended request finishes in the script version it started in)", rep is not None and rep.reason == "Busy v1", rep)
    if rep is not None:
        ua._ack_neg(slow, rep)
    up.auto_answer()
    r, d = ua.call("sip:bob@example.com")
    invs = [x for x in up.received if x.method == "INVITE" and d and x.get("call-id") == d.call_id]
    sc.check("a new INVITE after the reload runs v2 before its await (X-Before-Await)", invs and invs[0].get("x-before-await") == "v2",
             invs and invs[0].raw)
    if d:
        d.bye()
    if est:
        rep = est.bye()
        sc.check("the call established under v1 hangs up after the reload (BYE follows its Record-Route)", rep is not None and rep.code == 200, rep)
    up.handler = h

    # --- a change that can't be applied live: reported, the running value kept, the rest still works.
    write(toml_v2.replace("workers = 2", "workers = 3"))
    res = reload(px)
    sc.check("workers 2 → 3: reported under needs_restart", isinstance(res, dict) and "workers" in str(res.get("needs_restart")), res)
    rep, m = probe()
    sc.check("…and the proxy keeps serving with v2", m is not None and m.get("x-routing") == "v2", m and m.raw)
    write(toml_v2)

    # --- broken edits are refused, and nothing changes.
    def unchanged(label):
        rep, m = probe()
        code, dt = silent_408()
        sc.check(f"{label}: still X-Routing v2, X-Release r2 and fr_timer 2s",
                 m is not None and m.get("x-routing") == "v2" and m.get("x-release") == "r2" and code == 408 and 1.7 <= dt < 3.0,
                 (m and (m.get("x-routing"), m.get("x-release")), code, dt))

    write(fsr=fsr_v2.replace("X-Routing: v2", "X-Routing: v3") + "\nfn broken(msg: Request {\n")
    res = reload(px)
    sc.check("a .fsr syntax error → cfg.reload refused, naming the file", not isinstance(res, dict) and "main.fsr" in str(res), res)
    unchanged("after the refused .fsr")

    write(toml_v2.replace('fr_timer = "2s"', 'fr_timer = "1s"'), fsr_v2.replace("X-Routing: v2", "X-Routing: v3").replace("text.append_header", "text.apend_header", 1))
    res = reload(px)
    sc.check("an unknown function in the .fsr plus a valid fr_timer change → refused", not isinstance(res, dict) and "apend_header" in str(res), res)
    unchanged("after the refused mixed edit (the valid TOML part isn't applied either)")

    write(toml_v2.replace('fr_timer = "2s"', 'fr_timer = "soon"'), fsr_v2.replace("X-Routing: v2", "X-Routing: v3"))
    res = reload(px)
    sc.check("a valid .fsr change plus a TOML value of the wrong type → refused", not isinstance(res, dict) and "fr_timer" in str(res), res)
    unchanged("after the refused TOML (the valid .fsr part isn't applied either)")

    # --- several reloads in a row under traffic, then a good one.
    for i in range(5):
        write(toml_v2, fsr_v2.replace("X-Routing: v2", f"X-Routing: v3.{i}"))
        reload(px)
    rep, m = probe()
    sc.check("five reloads in a row: the last routing runs", m is not None and m.get("x-routing") == "v3.4", m and m.get("x-routing"))

    finals = traffic.stop()
    lost = [c for c in traffic.sent if c not in finals]
    bad = {c: code for c, code in finals.items() if code != 200}
    sc.check(f"background traffic across all reloads ({len(traffic.sent)} MESSAGEs): every one answered 200",
             not lost and not bad, (len(lost), bad))
