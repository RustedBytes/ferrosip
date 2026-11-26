#!/usr/bin/env python3
"""The Prometheus exporter (loadmodule "prometheus").

A proxy with tm, usrloc, dialog and the exporter gets real traffic:
REGISTERs, OPTIONS answered statelessly, MESSAGEs and an INVITE relayed to
a UAS that rings for 100 ms before answering. Then /metrics:
- needs the Bearer token (401 without), /-/healthy doesn't;
- parses strictly: HELP/TYPE once per family before its samples, valid
  names and labels, counters end in _total, histogram buckets cumulative
  with +Inf == _count;
- carries the expected values: requests by method, tm replies by class,
  usrloc users, active dialogs, the routing and transaction histograms
  (with the ringing delay in the INVITE's buckets), process metrics,
  build info; the generic fallback for unmapped statistics;
- honours gzip; 405 for POST; the connection limit gives 503 and the
  server recovers.
Run from the repo root after `cargo build --release`.
"""
import gzip, http.client, os, re, socket, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY, UAS, UAC, PROM = 7500, 7501, 7502, 7595
TOKEN = "e2e-token"
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


CFG = f"""loadmodule "sl"
loadmodule "textops"
loadmodule "tm"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "dialog"
loadmodule "counters"
loadmodule "prometheus"
modparam("prometheus", "listen", "127.0.0.1:{PROM}")
modparam("prometheus", "bearer_token", "{TOKEN}")
modparam("prometheus", "max_connections", 4)

request_route {{
    if (is_method("REGISTER")) {{ save("location"); exit; }}
    if (is_method("OPTIONS")) {{ cnt_inc("app.pings"); sl_send_reply(200, "OK"); exit; }}
    if (is_method("INVITE")) {{ dlg_manage(); }}
    t_relay("udp:127.0.0.1:{UAS}");
}}
"""

RING_MS = 100


def uas():
    """Answers MESSAGE with 200, INVITE with 180 then 200 after RING_MS."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", UAS))
    while True:
        m, a = s.recvfrom(65535)
        t = m.decode(errors="replace")
        if t.startswith("SIP/") or t.startswith("ACK"):
            continue
        keep = [l for l in t.split("\r\n")[1:] if re.match(r"(?i)^(via|from|call-id|cseq):", l)]
        to = next(l for l in t.split("\r\n") if l.lower().startswith("to:")) + ";tag=uas"

        def reply(code, reason, keep=keep, to=to, a=a):
            s.sendto(("SIP/2.0 %d %s\r\n%s\r\n%s\r\nContact: <sip:uas@127.0.0.1:%d>\r\nContent-Length: 0\r\n\r\n" % (code, reason, "\r\n".join(keep), to, UAS)).encode(), a)

        if t.startswith("INVITE"):
            reply(180, "Ringing")
            time.sleep(RING_MS / 1000)
        reply(200, "OK")


uac = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
uac.bind(("127.0.0.1", UAC))
uac.settimeout(3)


def sip(method, user, cid, extra=""):
    uac.sendto((f"{method} sip:{user}@127.0.0.1:{PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UAC};branch=z9hG4bK{cid}{method};rport\r\n"
                f"From: <sip:{user}@127.0.0.1>;tag=f{cid}\r\nTo: <sip:{user}@127.0.0.1>\r\nCall-ID: {cid}\r\nCSeq: 1 {method}\r\n"
                f"Contact: <sip:{user}@127.0.0.1:{UAC}>\r\nMax-Forwards: 70\r\n{extra}Content-Length: 0\r\n\r\n").encode(), ("127.0.0.1", PROXY))
    while True:
        r = uac.recv(65535).decode(errors="replace")
        if not r.startswith("SIP/2.0 1"):
            return r


def get(path, token=TOKEN, headers=None, method="GET"):
    c = http.client.HTTPConnection("127.0.0.1", PROM, timeout=5)
    h = dict(headers or {})
    if token:
        h["Authorization"] = f"Bearer {token}"
    c.request(method, path, headers=h)
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})? (\S+)$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"(,|$)')


def parse(text):
    """Strict parse → ({family: (type, [(sample_name, labels, value)])}, [problems])."""
    fams, problems, cur = {}, [], None
    for ln in text.split("\n"):
        if not ln:
            continue
        if ln.startswith("# HELP "):
            name = ln.split(" ")[2]
            if name in fams:
                problems.append(f"HELP twice / out of order: {name}")
            fams[name] = [None, []]
            cur = name
            continue
        if ln.startswith("# TYPE "):
            _, _, name, ty = ln.split(" ")
            if name != cur or fams[name][0] is not None or ty not in ("counter", "gauge", "histogram"):
                problems.append(f"bad TYPE line: {ln}")
            fams[name][0] = ty
            continue
        m = SAMPLE.match(ln)
        if not m:
            problems.append(f"bad line: {ln}")
            continue
        sname, labels, value = m.group(1), m.group(3) or "", m.group(4)
        lab, pos = {}, 0
        while pos < len(labels):
            lm = LABEL.match(labels, pos)
            if not lm:
                problems.append(f"bad labels: {ln}")
                break
            lab[lm.group(1)] = lm.group(2)
            pos = lm.end()
        try:
            v = float(value)
        except ValueError:
            problems.append(f"bad value: {ln}")
            continue
        base = cur
        ok_name = sname == base or (fams.get(cur, [None])[0] == "histogram" and sname in (base + "_bucket", base + "_sum", base + "_count"))
        if not ok_name:
            problems.append(f"sample {sname} outside its family {cur}")
        if not NAME.match(sname):
            problems.append(f"bad name {sname}")
        fams[cur][1].append((sname, lab, v))
    for name, (ty, samples) in fams.items():
        if ty == "counter" and not name.endswith("_total"):
            problems.append(f"counter without _total: {name}")
        if ty == "histogram":
            series = {}
            for sname, lab, v in samples:
                key = tuple(sorted((k, x) for k, x in lab.items() if k != "le"))
                series.setdefault(key, {"b": [], "sum": None, "count": None})
                if sname.endswith("_bucket"):
                    series[key]["b"].append((lab["le"], v))
                elif sname.endswith("_sum"):
                    series[key]["sum"] = v
                else:
                    series[key]["count"] = v
            for key, s in series.items():
                les = [float("inf") if le == "+Inf" else float(le) for le, _ in s["b"]]
                vals = [v for _, v in s["b"]]
                if les != sorted(les) or les[-1] != float("inf"):
                    problems.append(f"{name}{key}: buckets out of order or no +Inf")
                if vals != sorted(vals):
                    problems.append(f"{name}{key}: buckets not cumulative {vals}")
                if vals[-1] != s["count"]:
                    problems.append(f"{name}{key}: +Inf {vals[-1]} != count {s['count']}")
    return fams, problems


def value(fams, name, **labels):
    for sname, lab, v in fams.get(name, (None, []))[1]:
        if sname == name and all(lab.get(k) == x for k, x in labels.items()):
            return v
    return None


def hist(fams, name, **labels):
    """(count, sum, {le: cumulative}) of one histogram series."""
    out = {"count": None, "sum": None, "b": {}}
    for sname, lab, v in fams.get(name, (None, []))[1]:
        if not all(lab.get(k) == x for k, x in labels.items()):
            continue
        if sname.endswith("_bucket"):
            out["b"][lab["le"]] = v
        elif sname.endswith("_sum"):
            out["sum"] = v
        elif sname.endswith("_count"):
            out["count"] = v
    return out


threading.Thread(target=uas, daemon=True).start()
cfg = f"{ROOT}/target/e2e_prometheus.cfg"
open(cfg, "w").write(CFG)
proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY}", "--rpc-socket", "none"], stderr=subprocess.PIPE, text=True)
wait_listening(proxy)
log = []
threading.Thread(target=lambda: [log.append(l) for l in proxy.stderr], daemon=True).start()

try:
    for i in range(5):
        check(f"REGISTER {i} answered", sip("REGISTER", f"user{i}", f"reg{i}", "Expires: 600\r\n").startswith("SIP/2.0 200"))
    for i in range(3):
        sip("OPTIONS", "ping", f"opt{i}")
    for i in range(4):
        sip("MESSAGE", "bob", f"msg{i}")
    r = sip("INVITE", "bob", "call1")
    check("INVITE answered after ringing", r.startswith("SIP/2.0 200"), r[:40])

    code, _, _ = get("/metrics", token=None)
    check("no token: 401", code == 401)
    code, _, _ = get("/metrics", token="wrong")
    check("wrong token: 401", code == 401)
    check("/-/healthy needs no token", get("/-/healthy", token=None)[0] == 200)
    check("POST: 405", get("/metrics", method="POST")[0] == 405)

    code, hdrs, body = get("/metrics")
    text = body.decode()
    check("with the token: 200, text format 0.0.4", code == 200 and "version=0.0.4" in hdrs.get("Content-Type", ""), (code, hdrs))
    fams, problems = parse(text)
    check("exposition parses strictly", not problems, problems[:5])

    P = "ferrosip_"
    check("requests by method", value(fams, P + "sip_requests_received_total", method="REGISTER") == 5 and value(fams, P + "sip_requests_received_total", method="OPTIONS") == 3
          and value(fams, P + "sip_requests_received_total", method="MESSAGE") == 4 and value(fams, P + "sip_requests_received_total", method="INVITE") == 1,
          [(l, v) for _, l, v in fams.get(P + "sip_requests_received_total", (0, []))[1]])
    check("messages received by kind", value(fams, P + "sip_messages_received_total", kind="request") >= 13)
    check("tm replies by class", value(fams, P + "tm_replies_total", **{"class": "2xx"}) == 5, value(fams, P + "tm_replies_total", **{"class": "2xx"}))
    check("sl replies by class (REGISTER, OPTIONS)", value(fams, P + "sl_replies_total", **{"class": "2xx"}) >= 8)
    check("usrloc users", value(fams, P + "usrloc_registered_users") == 5)
    check("active dialogs", value(fams, P + "dialogs", state="active") == 1, value(fams, P + "dialogs", state="active"))
    check("dialog families typed as gauges", fams[P + "dialogs"][0] == "gauge" and fams[P + "tm_replies_total"][0] == "counter")
    check("send errors exported (as a counter)", fams.get(P + "send_errors_total", (None,))[0] == "counter" and value(fams, P + "send_errors_total") is not None)

    rr = hist(fams, P + "request_route_seconds", method="REGISTER")
    check("routing time histogram counts every REGISTER", rr["count"] == 5 and rr["sum"] > 0, rr)
    inv = hist(fams, P + "tm_transaction_seconds", method="INVITE", **{"class": "2xx"})
    check("INVITE transaction time includes the ringing", inv["count"] == 1 and inv["sum"] >= RING_MS / 1000 and inv["b"].get("0.05") == 0 and inv["b"].get("0.25") == 1, inv)
    msg = hist(fams, P + "tm_transaction_seconds", method="other", **{"class": "2xx"})
    check("MESSAGE transactions timed as 'other'", msg["count"] == 4, msg)
    pdd = hist(fams, P + "tm_invite_first_reply_seconds")
    check("post-dial delay measured once, before the ringing ends", pdd["count"] == 1 and pdd["sum"] < RING_MS / 1000, pdd)

    check("process metrics", (value(fams, "process_resident_memory_bytes") or 0) > 1e6 and (value(fams, "process_threads") or 0) > 1
          and value(fams, "process_cpu_seconds_total") is not None and (value(fams, "process_open_fds") or 0) > 3)
    start = value(fams, "process_start_time_seconds") or 0
    check("process start time is recent", time.time() - 120 < start <= time.time() + 1, start)
    check("build info", any(l.get("version") for _, l, _ in fams.get(P + "build_info", (0, []))[1]))
    check("unmapped statistics exported generically (script counter app.pings)", fams.get(P + "app_pings_total", [None])[0] == "counter" and value(fams, P + "app_pings_total") == 3,
          [n for n in fams if "app" in n])
    check("no Kamailio-style names", "kamailio_" not in text)

    code, hdrs, z = get("/metrics", headers={"Accept-Encoding": "gzip"})
    check("gzip when asked", code == 200 and hdrs.get("Content-Encoding") == "gzip" and gzip.decompress(z).decode().startswith("# HELP"))

    # Connection limit (4): the 5th concurrent connection gets 503.
    held = []
    for _ in range(4):
        s = socket.create_connection(("127.0.0.1", PROM))
        held.append(s)
    time.sleep(0.2)
    extra = socket.create_connection(("127.0.0.1", PROM))
    extra.settimeout(3)
    resp = extra.recv(200).decode(errors="replace")
    check("connection limit: 503", resp.startswith("HTTP/1.1 503"), resp[:40])
    extra.close()
    for s in held:
        s.close()
    time.sleep(0.3)
    check("serves again after the limit", get("/metrics")[0] == 200)
finally:
    proxy.terminate()
    proxy.wait(5)

text = "".join(log)
check("proxy: no panics", "panicked" not in text, text[-400:])

# A metrics port already in use is a startup error, like a SIP port.
busy = socket.socket()
busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
busy.bind(("127.0.0.1", PROM))
busy.listen()
try:
    r = subprocess.run([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY + 10}", "--rpc-socket", "none"],
                       capture_output=True, text=True, timeout=15)
    check("metrics port in use: exits 1 with a clear message", r.returncode == 1 and f"cannot listen on 127.0.0.1:{PROM}" in r.stderr, (r.returncode, r.stderr[-300:]))
finally:
    busy.close()
print(f"\n{failures} FAILED" if failures else "\nall passed")
sys.exit(1 if failures else 0)
