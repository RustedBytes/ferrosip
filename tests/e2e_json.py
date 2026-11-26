#!/usr/bin/env python3
"""End-to-end checks for JSON and REST (Phase 10): `http_client`
(`http_client_query`, `http_connect` with `httpcon`, `$curlerror`),
`jansson` (get, array_size, set, append, xdecode/xencode), `json`
(`json_get_field`), the `{json.parse,path}` transformation, and `jsonrpcs`
(`jsonrpc_exec`, FIFO transport). A Python REST server decides the route.
Run from the repo root after `cargo build --release`.
"""
import json, os, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_routing import Peer, first, hdr  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY, CALLER, UAS, HTTP = 7200, 7299, 7201, 7280
FIFO = os.path.join(ROOT, "target/e2e_json.fifo")

CFG = f"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "jansson"
loadmodule "json"
loadmodule "http_client"
loadmodule "jsonrpcs"
modparam("http_client", "httpcon", "api=>http://127.0.0.1:{HTTP}/api")
modparam("http_client", "query_result", 0)
modparam("http_client", "connection_timeout", 2)
modparam("jsonrpcs", "fifo_name", "{FIFO}")
modparam("jsonrpcs", "fifo_reply_dir", "{ROOT}/target/")

request_route {{
    if ruri_user_prefix("rest") {{
        http_client_query("http://127.0.0.1:{HTTP}/route?user=$rU", "$var(body)");
        $var(rc) = $rc;
        jansson_get("target.host", "$var(body)", "$var(host)");
        jansson_get("target.port", "$var(body)", "$var(port)");
        jansson_array_size("tags", "$var(body)", "$var(n)");
        append_hf("X-Rest: $var(rc) n=$var(n) first=$(var(body){{json.parse,tags[0]}}) vip=$(var(body){{json.parse,vip}})\\r\\n");
        $du = "sip:" + $var(host) + ":" + $var(port);
        t_relay();
        exit;
    }}
    if ruri_user_prefix("post") {{
        jansson_set("string", "caller", "$fU", "$var(doc)");
        jansson_set("integer", "n", "5", "$var(doc)");
        jansson_append("string", "list", "a", "$var(doc)");
        jansson_append("string", "list", "b", "$var(doc)");
        jansson_set("true", "flags.vip", "", "$var(doc)");
        http_connect("api", "/echo", "application/json", "$var(doc)", "$var(out)");
        json_get_field("$var(out)", "echo", "$var(e)");
        jansson_get("list[1]", "$var(e)", "$var(b)");
        append_to_reply("X-Doc: $var(doc)\\r\\nX-B: $var(b)\\r\\nX-CT: $(var(out){{json.parse,ctype}})\\r\\n");
        sl_send_reply(200, "Posted");
        exit;
    }}
    if ruri_user_prefix("qpost") {{
        http_client_query("http://127.0.0.1:{HTTP}/api/echo", "{{\\"q\\":1}}", "$var(o1)");
        http_client_query("http://127.0.0.1:{HTTP}/api/echo", "{{\\"q\\":2}}", "Content-Type: application/json", "$var(o2)");
        append_to_reply("X-CT1: $(var(o1){{json.parse,ctype}})\\r\\nX-CT2: $(var(o2){{json.parse,ctype}})\\r\\n");
        sl_send_reply(200, "QPost");
        exit;
    }}
    if ruri_user_prefix("xdec") {{
        jansson_xdecode("{{\\"a\\":\\"one\\",\\"b\\":2}}", "x");
        jansson_xencode("x", "$var(j)");
        append_to_reply("X-A: $xavp(x=>a)\\r\\nX-J: $var(j)\\r\\n");
        sl_send_reply(200, "Decoded");
        exit;
    }}
    if ruri_user_prefix("rpc") {{
        jsonrpc_exec("{{\\"jsonrpc\\":\\"2.0\\",\\"method\\":\\"core.version\\",\\"id\\":1}}");
        append_to_reply("X-Code: $jsonrpl(code)\\r\\nX-Body: $jsonrpl(body)\\r\\n");
        jsonrpc_exec("{{\\"jsonrpc\\":\\"2.0\\",\\"method\\":\\"no.such\\",\\"id\\":2}}");
        append_to_reply("X-Err: $jsonrpl(code) $jsonrpl(text)\\r\\n");
        sl_send_reply(200, "RPC");
        exit;
    }}
    if ruri_user_prefix("down") {{
        if (http_client_query("http://127.0.0.1:1/x", "$var(b)")) {{ sl_send_reply(200, "Unexpected"); exit; }}
        append_to_reply("X-Err: $curlerror(error)\\r\\n");
        sl_send_reply(503, "Backend down");
        exit;
    }}
    if ruri_user_prefix("status") {{
        http_client_query("http://127.0.0.1:{HTTP}/missing", "$var(b)");
        $var(rc) = $rc;
        append_to_reply("X-RC: $var(rc)\\r\\n");
        sl_send_reply(200, "Status");
        exit;
    }}
    sl_send_reply(404, "Unknown");
}}
"""

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


class Api(BaseHTTPRequestHandler):
    seen = []

    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        Api.seen.append(("GET", self.path, self.headers.get("User-Agent")))
        if self.path.startswith("/route"):
            self.reply(200, {"target": {"host": "127.0.0.1", "port": UAS}, "tags": ["gold", "eu"], "vip": True})
        else:
            self.reply(404, {"error": "no"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n).decode()
        Api.seen.append(("POST", self.path, data))
        self.reply(200, {"echo": json.loads(data), "ctype": self.headers.get("Content-Type")})

    def log_message(self, *a):
        pass


def msg(method, user):
    seq[0] += 1
    return (f"{method} sip:{user}@127.0.0.1:{PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch=z9hG4bKj{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: <sip:alice@x>;tag=c{seq[0]}\r\nTo: <sip:{user}@x>\r\nCall-ID: js-{seq[0]}-{time.time_ns()}\r\n"
            f"CSeq: 1 {method}\r\nContact: <sip:alice@127.0.0.1:{CALLER}>\r\nContent-Length: 0\r\n\r\n").encode()


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", HTTP), Api)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    caller, uas = Peer(CALLER), Peer(UAS)
    cfg = os.path.join(ROOT, "target/e2e_json.cfg")
    open(cfg, "w").write(CFG)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY}", "-n", "2", "--rpc-socket", "none"],
                         stderr=subprocess.PIPE, text=True)
    err = []
    threading.Thread(target=lambda: err.extend(p.stderr), daemon=True).start()
    try:
        end = time.time() + 5
        while time.time() < end and not any("listening on" in l for l in err):
            time.sleep(0.05)

        def ask(user, method="MESSAGE"):
            caller.s.sendto(msg(method, user), ("127.0.0.1", PROXY))
            return caller.final()

        # 1. REST decides the route; JSON parsed into variables.
        caller.s.sendto(msg("MESSAGE", "rest7"), ("127.0.0.1", PROXY))
        m = uas.answer("MESSAGE")
        r = caller.final()
        check("http_client_query → JSON → $du: request reaches the host/port from the REST answer", m is not None and first(r) == "SIP/2.0 200 OK", (m, r))
        check("…status, jansson_array_size, {json.parse,tags[0]} and a JSON boolean", m is not None and hdr(m, "X-Rest") == "200 n=2 first=gold vip=1", m and hdr(m, "X-Rest"))
        check("…the query carried the user and our User-Agent", any(s[0] == "GET" and s[1] == "/route?user=rest7" and "ferrosip" in (s[2] or "") for s in Api.seen), Api.seen)

        # 2. Build a document, POST it via a named connection.
        r = ask("post")
        doc = json.loads(hdr(r, "X-Doc") or "{}")
        check("jansson_set/append build a document", doc == {"caller": "alice", "n": 5, "list": ["a", "b"], "flags": {"vip": True}}, doc)
        post = [s for s in Api.seen if s[0] == "POST"]
        check("http_connect(api, /echo, ctype, data) POSTs it to the httpcon base URL", post and post[-1][1] == "/api/echo" and json.loads(post[-1][2]) == doc
              and hdr(r, "X-CT") == "application/json", (post, hdr(r, "X-CT")))
        check("json_get_field + jansson_get on the response", hdr(r, "X-B") == "b", hdr(r, "X-B"))

        # 2b. http_client_query POST: libcurl's default Content-Type, unless given.
        r = ask("qpost")
        check("http_client_query with a body and no headers POSTs as application/x-www-form-urlencoded (libcurl's default)",
              hdr(r, "X-CT1") == "application/x-www-form-urlencoded", hdr(r, "X-CT1"))
        check("…and with a Content-Type header, that one", hdr(r, "X-CT2") == "application/json", hdr(r, "X-CT2"))

        # 3. xavp round trip.
        r = ask("xdec")
        check("jansson_xdecode → $xavp, jansson_xencode → JSON", hdr(r, "X-A") == "one" and json.loads(hdr(r, "X-J") or "{}") == {"a": "one", "b": 2}, (hdr(r, "X-A"), hdr(r, "X-J")))

        # 4. jsonrpc_exec.
        r = ask("rpc")
        body = json.loads(hdr(r, "X-Body") or "{}")
        check("jsonrpc_exec(core.version) → $jsonrpl(code/body)", hdr(r, "X-Code") == "200" and "result" in body, (hdr(r, "X-Code"), body))
        check("…unknown method → $jsonrpl(code) -32601", hdr(r, "X-Err") == "-32601 Method not found", hdr(r, "X-Err"))

        # 5. Errors.
        r = ask("down")
        check("unreachable backend: query fails, $curlerror(error) set", first(r) == "SIP/2.0 503 Backend down" and len(hdr(r, "X-Err")) > 0, (first(r), hdr(r, "X-Err")))
        r = ask("status")
        check("HTTP 404 → return code 404", hdr(r, "X-RC") == "404", hdr(r, "X-RC"))

        # 6. FIFO transport (kamctl style).
        reply_fifo = os.path.join(ROOT, "target/e2e_json_reply")
        if os.path.exists(reply_fifo):
            os.remove(reply_fifo)
        os.mkfifo(reply_fifo)
        out = []
        rd = threading.Thread(target=lambda: out.append(open(reply_fifo).read()), daemon=True)
        rd.start()
        with open(FIFO, "w") as f:
            f.write(json.dumps({"jsonrpc": "2.0", "method": "core.version", "id": 7, "reply_name": "e2e_json_reply"}) + "\n")
        rd.join(3)
        resp = json.loads(out[0]) if out else {}
        check("jsonrpcs FIFO: request in, response in the reply FIFO", resp.get("id") == 7 and "result" in resp, out)
    finally:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
        time.sleep(0.1)
        log = "".join(err)
        check("no panics in proxy log", "panicked" not in log, log[-2000:])
        if failures:
            print("--- proxy stderr ---\n" + log[-4000:])
        srv.shutdown()
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
