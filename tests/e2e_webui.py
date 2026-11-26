#!/usr/bin/env python3
"""The read-only web UI (loadmodule "webui").

A proxy with usrloc, dialog, dispatcher and htable gets real data: three
registrations, an answered call that stays up, a dispatcher set and an
htable entry. Then, over HTTP:
- no credentials: 401 with a Basic challenge; wrong ones: 401, then 429
  for that address after repeated failures;
- /api/v1/meta lists the sections of the loaded modules;
- registrations (filter, sort, paging, contact detail), dialogs (state as a
  word), dispatcher, htable items, statistics, connections and the log
  tail return the expected rows;
- the embedded app is served gzip-encoded (or plain without gzip), with an
  ETag answered by 304, and every response carries the security headers;
- nothing writes: POST/PUT/DELETE → 405, unknown API paths → 404, path
  traversal → 400;
- connections are bounded: the 65th concurrent one gets 503, and the
  server serves again once they close.
Run from the repo root after `cargo build --release`.
"""
import base64, gzip, hashlib, http.client, json, os, socket, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY, UAS, UAC, WEB = 7800, 7801, 7802, 7880
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


SALT = "e2e"
HASH = "sha256:%s:%s" % (SALT, hashlib.sha256((SALT + "s3cret").encode()).hexdigest())
CFG = f"""loadmodule "sl"
loadmodule "textops"
loadmodule "tm"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "dialog"
loadmodule "dispatcher"
loadmodule "htable"
loadmodule "webui"
modparam("dispatcher", "list_file", "{ROOT}/target/e2e_webui.list")
modparam("htable", "htable", "t=>size=4;autoexpire=0;")
modparam("webui", "listen", "127.0.0.1:{WEB}")
modparam("webui", "user", "admin")
modparam("webui", "password_hash", "{HASH}")
modparam("webui", "max_connections", 64)

request_route {{
    if (is_method("REGISTER")) {{ save("location"); exit; }}
    if (is_method("MESSAGE")) {{ $sht(t=>greeting) = "hello"; sl_send_reply(200, "OK"); exit; }}
    if (is_method("INVITE")) {{ dlg_manage(); }}
    t_relay("udp:127.0.0.1:{UAS}");
}}
"""
AUTH = "Basic " + base64.b64encode(b"admin:s3cret").decode()


def get(path, auth=AUTH, method="GET", headers=None, source=None):
    c = http.client.HTTPConnection("127.0.0.1", WEB, timeout=5, source_address=(source, 0) if source else None)
    h = {"Authorization": auth} if auth else {}
    h.update(headers or {})
    c.request(method, path, headers=h)
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, dict((k.lower(), v) for k, v in r.getheaders()), body


def api(path):
    s, h, b = get("/api/v1/" + path)
    try:
        return s, json.loads(b)
    except ValueError:
        return s, b


class Uas(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", UAS))
        self.start()

    def run(self):
        while True:
            d, a = self.s.recvfrom(65535)
            m = d.decode()
            if m.startswith(("ACK", "SIP/")):
                continue
            keep = [h for h in m.split("\r\n")[1:] if h.split(":", 1)[0].lower() in ("via", "from", "to", "call-id", "cseq", "record-route")]
            keep = [h + ";tag=uas" if h.lower().startswith("to:") else h for h in keep]
            self.s.sendto(("SIP/2.0 200 OK\r\n" + "\r\n".join(keep) + f"\r\nContact: <sip:uas@127.0.0.1:{UAS}>\r\nContent-Length: 0\r\n\r\n").encode(), a)


def sip(sock, method, user, cid, extra=""):
    sock.sendto((f"{method} sip:{user}@127.0.0.1:{PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UAC};branch=z9hG4bK{cid}{method};rport\r\n"
                 f"From: <sip:{user}@127.0.0.1>;tag=f{cid}\r\nTo: <sip:{user}@127.0.0.1>\r\nCall-ID: {cid}\r\nCSeq: 1 {method}\r\n"
                 f"Contact: <sip:{user}@127.0.0.1:{UAC}>\r\nMax-Forwards: 70\r\n{extra}Content-Length: 0\r\n\r\n").encode(), ("127.0.0.1", PROXY))
    while True:
        r = sock.recv(65535).decode()
        if not r.startswith("SIP/2.0 1"):
            return r


def main():
    open(f"{ROOT}/target/e2e_webui.list", "w").write("1 sip:gw1.example.invalid:5060\n1 sip:gw2.example.invalid:5060\n")
    cfg = f"{ROOT}/target/e2e_webui.cfg"
    open(cfg, "w").write(CFG)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY}", "--rpc-socket", "none"],
                         stderr=subprocess.PIPE, text=True)
    wait_listening(p)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", WEB), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    Uas()
    uac = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    uac.bind(("127.0.0.1", UAC))
    uac.settimeout(3)
    try:
        for u in ("alice", "bob", "carol"):
            sip(uac, "REGISTER", u, f"reg-{u}", "Expires: 600\r\nUser-Agent: e2e-phone/1.0\r\n")
        sip(uac, "MESSAGE", "x", "msg-1")
        r = sip(uac, "INVITE", "dave", "call-1")
        check("setup: the call is answered", r.startswith("SIP/2.0 200"), r[:40])

        # ---- authentication
        s, h, _ = get("/api/v1/meta", auth=None)
        check("no credentials → 401 with a Basic challenge", s == 401 and h.get("www-authenticate", "").startswith("Basic realm="), (s, h))
        s, _, _ = get("/api/v1/meta", auth="Basic " + base64.b64encode(b"admin:nope").decode())
        check("wrong password → 401", s == 401, s)

        # ---- API
        s, m = api("meta")
        secs = m.get("sections", {}) if isinstance(m, dict) else {}
        check("meta: sections of the loaded modules",
              s == 200 and all(k in secs for k in ("overview", "registrations", "calls", "routing", "data", "logs", "statistics"))
              and "security" not in secs, secs)
        s, r = api("registrations?sort=aor&limit=2")
        check("registrations: sorted and paged (total 3, 2 rows)",
              s == 200 and r["total"] == 3 and [x["aor"] for x in r["rows"]] == ["alice", "bob"] and r["rows"][0]["user_agent"] == "e2e-phone/1.0", r)
        s, r = api("registrations?q=carol")
        check("registrations: search", s == 200 and r["total"] == 1 and r["rows"][0]["aor"] == "carol", r)
        s, r = api("registrations/contacts?aor=alice")
        check("registrations: contacts of one AoR", s == 200 and r["total"] == 1 and r["rows"][0]["contact"].startswith("sip:alice@"), r)
        s, r = api("registrations/contacts")
        check("registrations: missing ?aor → 400", s == 400, (s, r))
        s, r = api("dialogs")
        rows = r.get("rows", []) if isinstance(r, dict) else []
        check("dialogs: the call, its state as a word",
              s == 200 and any(d.get("call-id") == "call-1" and d.get("state_name") in ("confirmed", "established") for d in rows), rows)
        s, r = api("dispatcher")
        check("dispatcher: both destinations", s == 200 and r["total"] == 2 and {x["uri"] for x in r["rows"]} == {"sip:gw1.example.invalid:5060", "sip:gw2.example.invalid:5060"}, r)
        s, r = api("htable/items?table=t")
        check("htable: the item set by the script", s == 200 and any(x.get("name") == "greeting" for x in r.get("rows", [])), r)
        s, r = api("stats")
        names = {f'{x["group"]}:{x["name"]}': x for x in r.get("rows", [])} if isinstance(r, dict) else {}
        check("stats: counters and gauges with their kind",
              s == 200 and names.get("tm:total", {}).get("kind") == "counter" and names.get("usrloc:registered_users", {}).get("value") == 3, list(names)[:5])
        s, r = api("connections")
        check("connections: totals and the list", s == 200 and "max_connections" in r and "connections" in r, r)
        s, r = api("info")
        check("info: version, listeners, modules", s == 200 and "webui" in r.get("modules", []) and r.get("listeners"), r)
        s, r = api("logs?after=0")
        check("logs: the ring has the startup lines", s == 200 and any("webui: listening" in l["text"] for l in r.get("lines", [])), r)

        # ---- assets
        s, h, b = get("/", headers={"Accept-Encoding": "gzip"})
        check("app page served", s == 200 and h["content-type"].startswith("text/html") and b"/app.js" in b, (s, h))
        for k, v in {"content-security-policy": "default-src 'self'", "x-frame-options": "DENY", "x-content-type-options": "nosniff"}.items():
            check(f"security header {k}", v in h.get(k, ""), h.get(k))
        s, h, b = get("/app.js", headers={"Accept-Encoding": "gzip, deflate"})
        check("app.js gzip-encoded", s == 200 and h.get("content-encoding") == "gzip" and len(gzip.decompress(b)) > 0, h)
        s, h2, b2 = get("/app.js")
        check("app.js plain without Accept-Encoding: gzip", s == 200 and "content-encoding" not in h2 and b2 == gzip.decompress(b), h2)
        s, _, _ = get("/app.js", headers={"If-None-Match": h["etag"]})
        check("ETag → 304", s == 304, s)
        s, h, _ = get("/api/v1/stats")
        check("API answers are not cached", h.get("cache-control") == "no-store", h)

        # ---- read-only
        for method in ("POST", "PUT", "DELETE"):
            s, h, _ = get("/api/v1/meta", method=method)
            check(f"{method} → 405", s == 405 and h.get("allow") == "GET, HEAD", s)
        s, _, _ = get("/api/v1/dispatcher.reload")
        check("unknown API path (an RPC name) → 404", s == 404, s)
        s, _, _ = get("/../etc/passwd")
        check("path traversal → 400", s == 400, s)

        # ---- bounded connections
        idle = [socket.create_connection(("127.0.0.1", WEB)) for _ in range(64)]
        time.sleep(0.3)
        s = None
        try:
            s, _, _ = get("/api/v1/meta")
        except Exception as e:  # noqa: BLE001
            s = repr(e)
        check("65th concurrent connection → 503", s == 503, s)
        for c in idle:
            c.close()
        time.sleep(0.5)
        s, _, _ = get("/api/v1/meta")
        check("served again once they close", s == 200, s)

        # ---- throttling (from another address, so the checks above aren't affected)
        bad = "Basic " + base64.b64encode(b"admin:guess").decode()
        codes = [get("/api/v1/meta", auth=bad, source="127.0.0.2")[0] for _ in range(6)]
        s, _, _ = get("/api/v1/meta", source="127.0.0.2")
        check("repeated failures → 429 for that address (even with the right password)", codes[:5] == [401] * 5 and codes[5] == 429 and s == 429, (codes, s))
        s, _, _ = get("/api/v1/meta")
        check("…other addresses unaffected", s == 200, s)
    finally:
        p.terminate()
        try:
            err = p.early_log + p.communicate(timeout=10)[1]
        except subprocess.TimeoutExpired:
            p.kill()
            err = p.early_log + p.communicate()[1]
        check("no panics", "panicked" not in err, err[-600:])
    # A web UI port already in use is a startup error, like a SIP port.
    busy = socket.socket()
    busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    busy.bind(("127.0.0.1", WEB))
    busy.listen()
    try:
        r = subprocess.run([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY + 10}", "--rpc-socket", "none"],
                           capture_output=True, text=True, timeout=15)
        check("web UI port in use: exits 1 with a clear message", r.returncode == 1 and f"cannot listen on 127.0.0.1:{WEB}" in r.stderr, (r.returncode, r.stderr[-300:]))
    finally:
        busy.close()
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
