#!/usr/bin/env python3
"""Smoke test of the monitoring example (docker compose up first).

1. SIP traffic through ferrosip for a while:
   - a phone registers as alice;
   - calls to her ring, are answered and hung up;
   - MESSAGEs to her, OPTIONS pings, and calls to an unknown user (404).
2. Checks:
   - ferrosip's /metrics exports every metric the dashboard uses (and
     only valid lines);
   - Prometheus scrapes ferrosip (target up);
   - Grafana has the provisioned dashboard and can query the
     datasource;
   - every panel query of the dashboard returns data in Prometheus. The
     AI panels may be empty: no AI calls are made.

    python3 smoke.py [--seconds 40] [--proxy 127.0.0.1:5060] [--metrics-only]
`--metrics-only` skips Prometheus and Grafana (a native ferrosip with
ferrosip.cfg is enough). Exit status 0 when everything passes.
"""
import argparse, base64, json, os, re, socket, threading, time, urllib.parse, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--proxy", default="127.0.0.1:5060")
ap.add_argument("--metrics", default="http://127.0.0.1:9095/metrics")
ap.add_argument("--prometheus", default="http://127.0.0.1:9090")
ap.add_argument("--grafana", default="http://127.0.0.1:3000")
ap.add_argument("--seconds", type=int, default=40, help="how long to send traffic")
ap.add_argument("--metrics-only", action="store_true")
args = ap.parse_args()
PH, PP = args.proxy.split(":")[0], int(args.proxy.split(":")[1])
HERE = os.path.dirname(os.path.abspath(__file__))
DASH = json.load(open(os.path.join(HERE, "grafana/dashboards/ferrosip.json")))
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -- {detail}"))
    failures += 0 if ok else 1


def http(url, data=None, auth=None, timeout=10):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


# ------------------------------------------------------------------ SIP ---
def sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(3)
    return s


phone, caller = sock(), sock()
PHONE, CALLER = phone.getsockname()[1], caller.getsockname()[1]
seq = iter(range(1, 10 ** 9))


def hdr(m, name):
    for l in m.split("\r\n"):
        if l.lower().startswith(name.lower() + ":"):
            return l.split(":", 1)[1].strip()
    return ""


def reply_to(s, m, addr, code, reason, extra=""):
    keep = [l for l in m.split("\r\n")[1:] if re.match(r"(?i)^(via|from|call-id|cseq|record-route):", l)]
    to = "To: " + hdr(m, "To") + ("" if "tag=" in hdr(m, "To") else ";tag=phone")
    s.sendto(("SIP/2.0 %d %s\r\n%s\r\n%s\r\n%sContent-Length: 0\r\n\r\n" % (code, reason, "\r\n".join(keep), to, extra)).encode(), addr)


def phone_loop():
    """alice: rings 80 ms then answers INVITE; 200 to BYE and MESSAGE."""
    while True:
        try:
            m, a = phone.recvfrom(65535)
        except (socket.timeout, OSError):
            continue
        m = m.decode(errors="replace")
        if m.startswith("SIP/") or m.startswith("ACK"):
            continue
        if m.startswith("INVITE"):
            reply_to(phone, m, a, 180, "Ringing")
            time.sleep(0.08)
            reply_to(phone, m, a, 200, "OK", f"Contact: <sip:alice@127.0.0.1:{PHONE}>\r\n")
        else:
            reply_to(phone, m, a, 200, "OK")


def request(s, port, method, ruri, cid, to_user, extra="", tag=""):
    n = next(seq)
    s.sendto((f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKsmoke{n};rport\r\n"
              f"From: <sip:bob@127.0.0.1>;tag=b{cid}\r\nTo: <sip:{to_user}@127.0.0.1>{tag}\r\nCall-ID: {cid}\r\nCSeq: {n} {method}\r\n"
              f"Contact: <sip:bob@127.0.0.1:{port}>\r\nMax-Forwards: 70\r\n{extra}Content-Length: 0\r\n\r\n").encode(), (PH, PP))


def final(s, cid):
    while True:
        m = s.recv(65535).decode(errors="replace")
        if m.startswith("SIP/2.0") and hdr(m, "Call-ID") == cid and int(m.split()[1]) >= 200:
            return m


def call(cid):
    request(caller, CALLER, "INVITE", f"sip:alice@{PH}:{PP}", cid, "alice")
    ok = final(caller, cid)
    if not ok.startswith("SIP/2.0 200"):
        return ok.split("\r\n")[0]
    tag = ";tag=" + hdr(ok, "To").split("tag=")[1]
    routes = [hdr(l, "Record-Route") for l in ok.split("\r\n") if l.lower().startswith("record-route:")]
    route = f"Route: {', '.join(routes)}\r\n" if routes else ""
    contact = hdr(ok, "Contact").strip("<>")
    request(caller, CALLER, "ACK", contact, cid, "alice", route, tag)
    time.sleep(0.2)
    request(caller, CALLER, "BYE", contact, cid, "alice", route, tag)
    return final(caller, cid).split("\r\n")[0]


threading.Thread(target=phone_loop, daemon=True).start()
reg = f"reg-{int(time.time())}"
phone.sendto((f"REGISTER sip:{PH}:{PP} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{PHONE};branch=z9hG4bKreg{reg};rport\r\n"
              f"From: <sip:alice@127.0.0.1>;tag=a1\r\nTo: <sip:alice@127.0.0.1>\r\nCall-ID: {reg}\r\nCSeq: 1 REGISTER\r\n"
              f"Contact: <sip:alice@127.0.0.1:{PHONE}>\r\nExpires: 3600\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n").encode(), (PH, PP))
time.sleep(0.5)

print(f"sending traffic for {args.seconds} s …")
end, n, results = time.time() + args.seconds, 0, {}
while time.time() < end:
    n += 1
    cid = f"smoke-{int(time.time())}-{n}"
    try:
        r = call(cid)
        results[r] = results.get(r, 0) + 1
        request(caller, CALLER, "MESSAGE", f"sip:alice@{PH}:{PP}", cid + "m", "alice")
        final(caller, cid + "m")
        request(caller, CALLER, "OPTIONS", f"sip:{PH}:{PP}", cid + "o", "")
        final(caller, cid + "o")
        request(caller, CALLER, "INVITE", f"sip:nobody@{PH}:{PP}", cid + "x", "nobody")
        final(caller, cid + "x")
    except socket.timeout:
        results["timeout"] = results.get("timeout", 0) + 1
    time.sleep(0.15)
check(f"calls completed ({n} sent: {results})", results.get("SIP/2.0 200 OK", 0) >= n * 0.9, results)

# --------------------------------------------------------- /metrics ---
code, body = http(args.metrics)
text = body.decode()
exported = set()
for ln in text.splitlines():
    if ln.startswith("#") or not ln:
        continue
    m = re.match(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})? (\S+)$', ln)
    if not m:
        check("valid exposition line", False, ln)
        continue
    exported.add(m.group(1))
used = set()
panels = [p for p in DASH["panels"] if p["type"] != "row"]
for p in panels:
    for t in p["targets"]:
        used |= set(re.findall(r"\b((?:ferrosip|process)_[a-zA-Z0-9_]+)\{", t["expr"]))
early = re.search(r'^ferrosip_dialogs\{state="early"\} (\S+)$', text, re.M)
check("no dialog left early after the traffic (404s included)", early is not None and float(early.group(1)) == 0, early and early.group(0))
missing = sorted(m for m in used if m not in exported)
check(f"/metrics exports every metric the dashboard uses ({len(used)})", not missing, missing)

if args.metrics_only:
    print(f"\n{failures} FAILED" if failures else "\nall passed (metrics only)")
    raise SystemExit(1 if failures else 0)

# ----------------------------------------------------------- Prometheus ---
def promql(expr):
    q = urllib.parse.urlencode({"query": expr})
    _, b = http(f"{args.prometheus}/api/v1/query?{q}")
    return json.loads(b)


up = None
for _ in range(30):
    t = json.loads(http(f"{args.prometheus}/api/v1/targets")[1])
    ups = [x for x in t["data"]["activeTargets"] if x["labels"].get("job") == "ferrosip"]
    up = ups[0]["health"] if ups else None
    if up == "up":
        break
    time.sleep(2)
check("Prometheus scrapes ferrosip", up == "up", up)
time.sleep(12)  # two more scrapes after the traffic, so rates have points

AI_OK_EMPTY = {"Provider connect time (p95)", "AI call length (median)"}
for p in panels:
    for t in p["targets"]:
        expr = t["expr"].replace("$instance", ".*").replace("$__rate_interval", "1m")
        try:
            r = promql(expr)
            series = r["data"]["result"] if r.get("status") == "success" else None
        except Exception as e:  # noqa: BLE001
            series, r = None, str(e)
        if series is None:
            check(f"panel '{p['title']}' [{t['refId']}]: query runs", False, r)
        elif p["title"] in AI_OK_EMPTY:
            check(f"panel '{p['title']}' [{t['refId']}]: query runs (no AI calls: may be empty)", True)
        else:
            check(f"panel '{p['title']}' [{t['refId']}]: has data", len(series) > 0, expr)

# -------------------------------------------------------------- Grafana ---
code, b = http(f"{args.grafana}/api/health")
check("Grafana is up", code == 200 and json.loads(b).get("database") == "ok", b)
code, b = http(f"{args.grafana}/api/dashboards/uid/ferrosip", auth="admin:admin")
d = json.loads(b)
check("the ferrosip dashboard is provisioned", d["dashboard"]["title"] == "ferrosip" and len(d["dashboard"]["panels"]) == len(DASH["panels"]),
      d.get("meta", {}).get("provisioned"))
now = int(time.time() * 1000)
code, b = http(f"{args.grafana}/api/ds/query", auth="admin:admin", data={
    "from": str(now - 10 * 60_000), "to": str(now),
    "queries": [{"refId": "A", "datasource": {"type": "prometheus", "uid": "prometheus"},
                 "expr": 'sum(rate(ferrosip_sip_requests_received_total[1m]))', "intervalMs": 5000, "maxDataPoints": 100}]})
frames = json.loads(b)["results"]["A"].get("frames", [])
check("Grafana queries the provisioned Prometheus datasource", code == 200 and frames and frames[0]["data"]["values"], b[:300])

print(f"\n{failures} FAILED" if failures else "\nall passed")
raise SystemExit(1 if failures else 0)
