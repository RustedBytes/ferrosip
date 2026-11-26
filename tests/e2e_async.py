#!/usr/bin/env python3
"""End-to-end checks for asynchronous processing (Phase 9): tm
`t_suspend()` / `t_continue()`, the `async` module (`async_ms_sleep`
continuing with the next action, `async_route`, `async_task_route`),
`http_async_client` (`http_async_query` + `$http_*`), retransmissions and
CANCEL while suspended, the suspend timeout, `sql_query_async`.
Run from the repo root after `cargo build --release`.
"""
import os, re, socket, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_routing import make_reply, first, hdr, hdrs  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY, CALLER, UAS, UAS2, HTTP = 7100, 7199, 7101, 7102, 7180
DB = os.path.join(ROOT, "target/e2e_async.sqlite")

CFG = f"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "htable"
loadmodule "sqlops"
loadmodule "async"
loadmodule "http_async_client"
modparam("tm", "fr_timer", 1000)
modparam("tm", "fr_inv_timer", 3000)
modparam("async", "workers", 4)
modparam("http_async_client", "workers", 2)
modparam("htable", "htable", "p=>size=4;")
modparam("sqlops", "sqlcon", "db=>sqlite://{DB}")

request_route {{
    if (is_method("CANCEL")) {{ t_relay(); exit; }}
    if (is_method("ACK")) {{ t_relay(); exit; }}
    if ruri_user_prefix("sleep") {{
        $avp(before) = "kept";
        append_hf("X-Before: 1\\r\\n");
        async_ms_sleep(200);
        append_hf("X-After: $avp(before)\\r\\n");
        t_relay("udp:127.0.0.1:{UAS}");
        exit;
    }}
    if ruri_user_prefix("nested") {{
        if (is_method("MESSAGE")) {{
            async_ms_sleep(100);
            append_hf("X-N: 1\\r\\n");
            async_ms_sleep(100);
            append_hf("X-N: 2\\r\\n");
            t_relay("udp:127.0.0.1:{UAS}");
        }}
        exit;
    }}
    if ruri_user_prefix("route") {{ async_route("LATER", 1); exit; }}
    if ruri_user_prefix("task") {{ async_task_route("LATER"); exit; }}
    if ruri_user_prefix("httpbad") {{ http_async_query("http://127.0.0.1:1/x", "HTTP_REPLY"); exit; }}
    if ruri_user_prefix("http") {{
        $http_req(hdr) = "X-Q: $rU";
        http_async_query("http://127.0.0.1:{HTTP}/target?u=$rU", "HTTP_REPLY");
        exit;
    }}
    if ruri_user_prefix("park") {{
        t_suspend();
        $sht(p=>i) = $T(id_index);
        $sht(p=>l) = $T(id_label);
        exit;
    }}
    if ruri_user_prefix("unpark") {{
        if (t_continue("$sht(p=>i)", "$sht(p=>l)", "LATER")) {{ sl_send_reply(200, "Unparked"); }}
        else {{ sl_send_reply(404, "No such"); }}
        exit;
    }}
    if ruri_user_prefix("stuck") {{ t_suspend(); exit; }}
    if ruri_user_prefix("slreply") {{ async_ms_sleep(50); sl_send_reply(404, "Not Here"); exit; }}
    if ruri_user_prefix("sqlasync") {{
        sql_query_async("db", "insert into cdr(callid) values('$ci')");
        sl_send_reply(200, "Queued");
        exit;
    }}
    sl_send_reply(404, "Unknown");
}}

route[LATER] {{
    append_hf("X-Later: yes\\r\\n");
    t_relay("udp:127.0.0.1:{UAS}");
}}

route[HTTP_REPLY] {{
    if ($http_ok && $http_rs == 200) {{
        append_hf("X-HTTP: $http_rs $http_hdr(X-Echo)\\r\\n");
        $du = "sip:" + $http_rb;
        t_relay();
        exit;
    }}
    t_reply(503, "HTTP failed");
}}
"""

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


class Http(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        Http.seen.append((self.path, self.headers.get("X-Q")))
        body = f"127.0.0.1:{UAS2}".encode()
        self.send_response(200)
        self.send_header("X-Echo", self.headers.get("X-Q", "-"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class Sock:
    def __init__(self, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.port = port

    def recv(self, timeout):
        self.s.settimeout(max(0.01, timeout))
        try:
            return self.s.recvfrom(65535)
        except socket.timeout:
            return None, None

    def collect(self, timeout, until=None):
        """All messages within `timeout` (or until `until(list)` is true)."""
        out, end = [], time.time() + timeout
        while time.time() < end:
            d, a = self.recv(end - time.time())
            if d is None:
                break
            out.append((d, a, time.time()))
            if until and until(out):
                break
        return out


def msg(method, user, callid=None, branch=None, cseq=1):
    seq[0] += 1
    branch = branch or f"z9hG4bKa{seq[0]}x{time.time_ns()}"
    return (f"{method} sip:{user}@127.0.0.1:{PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch={branch}\r\n"
            f"Max-Forwards: 70\r\nFrom: <sip:caller@x>;tag=c{seq[0]}\r\nTo: <sip:{user}@x>\r\nCall-ID: {callid or f'as-{seq[0]}-{time.time_ns()}'}\r\n"
            f"CSeq: {cseq} {method}\r\nContact: <sip:caller@127.0.0.1:{CALLER}>\r\nContent-Length: 0\r\n\r\n").encode()


def cancel_of(inv):
    lines = inv.decode().split("\r\n")
    keep = [l for l in lines[1:] if l.split(":")[0].lower() in ("via", "from", "to", "call-id", "max-forwards")]
    cseq = next(l for l in lines if l.lower().startswith("cseq:")).split()[1]
    return ("CANCEL " + lines[0].split()[1] + " SIP/2.0\r\n" + "\r\n".join(keep) + f"\r\nCSeq: {cseq} CANCEL\r\nContent-Length: 0\r\n\r\n").encode()


def main():
    if os.path.exists(DB):
        os.remove(DB)
    import sqlite3
    c = sqlite3.connect(DB)
    c.execute("create table cdr(callid text)")
    c.commit()
    c.close()
    srv = ThreadingHTTPServer(("127.0.0.1", HTTP), Http)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    caller, uas, uas2 = Sock(CALLER), Sock(UAS), Sock(UAS2)
    cfg = os.path.join(ROOT, "target/e2e_async.cfg")
    open(cfg, "w").write(CFG)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY}", "-n", "4", "--rpc-socket", "none"],
                         stderr=subprocess.PIPE, text=True)
    err = []
    threading.Thread(target=lambda: err.extend(p.stderr), daemon=True).start()
    try:
        end = time.time() + 5
        while time.time() < end and not any("listening on" in l for l in err):
            time.sleep(0.05)

        def send(m):
            caller.s.sendto(m, ("127.0.0.1", PROXY))

        # 1. 50 parallel INVITEs, each sleeping 200 ms in the script.
        t0 = time.time()
        for i in range(50):
            send(msg("INVITE", f"sleep{i}"))
        got = uas.collect(3, until=lambda l: len(l) >= 50)
        tryings = [d for d, _, _ in caller.collect(0.3) if d.startswith(b"SIP/2.0 100")]
        invs = [(d, a, t) for d, a, t in got if d.startswith(b"INVITE")]
        check("50 suspended INVITEs: 100 Trying each, at once", len(tryings) == 50, len(tryings))
        check("…all 50 relayed after the 200 ms sleep, not before", len(invs) == 50 and min(t for _, _, t in invs) - t0 >= 0.19, (len(invs), invs and min(t for _, _, t in invs) - t0))
        check("…script continued after async_ms_sleep: header edits + $avp kept", all(hdr(d, "X-Before") == "1" and hdr(d, "X-After") == "kept" for d, _, _ in invs), invs[:1])
        for d, a, _ in invs:
            uas.s.sendto(make_reply(d, 200, "OK", f"Contact: <sip:u@127.0.0.1:{UAS}>\r\n"), a)
        oks = [d for d, _, _ in caller.collect(2, until=lambda l: len(l) >= 50) if d.startswith(b"SIP/2.0 200")]
        check("…and all 50 answered 200 through the resumed transactions", len(oks) == 50, len(oks))

        # 2. Retransmission while suspended.
        m = msg("INVITE", "sleepre")
        send(m)
        time.sleep(0.05)
        send(m)
        rs = caller.collect(0.15)
        got = uas.collect(0.6)
        branches = {re.search(rb"branch=([^;\r]+)", d).group(1) for d, _, _ in got if d.startswith(b"INVITE")}
        check("retransmission while suspended: 100 again, forwarded once", sum(d.startswith(b"SIP/2.0 100") for d, _, _ in rs) == 2
              and len(branches) == 1, (rs, branches))
        for d, a, _ in got[:1]:
            uas.s.sendto(make_reply(d, 486, "Busy"), a)
        caller.collect(0.5)
        uas.collect(0.3)

        # 3. Two sleeps in a nested block.
        t0 = time.time()
        send(msg("MESSAGE", "nested"))
        d, a = uas.recv(2)
        check("async_ms_sleep twice inside an if-block: both continuations ran", d is not None and hdrs(d, "X-N") == ["1", "2"] and time.time() - t0 >= 0.19,
              d and hdrs(d, "X-N"))
        if d:
            uas.s.sendto(make_reply(d, 200, "OK"), a)
        caller.collect(0.3)

        # 4. async_route after 1 s, async_task_route now.
        t0 = time.time()
        send(msg("MESSAGE", "route"))
        d, a = uas.recv(3)
        dt = time.time() - t0
        check("async_route(LATER, 1): route runs ~1 s later on the same transaction", d is not None and hdr(d, "X-Later") == "yes" and 0.95 < dt < 1.8, dt)
        if d:
            uas.s.sendto(make_reply(d, 202, "Accepted"), a)
        r = [x for x, _, _ in caller.collect(0.5) if not x.startswith(b"SIP/2.0 1")]
        check("…its final reply reaches the caller", r and first(r[0]) == "SIP/2.0 202 Accepted", r)
        t0 = time.time()
        send(msg("MESSAGE", "task"))
        d, a = uas.recv(2)
        check("async_task_route: route runs on a worker right away", d is not None and hdr(d, "X-Later") == "yes" and time.time() - t0 < 0.5, d)
        if d:
            uas.s.sendto(make_reply(d, 200, "OK"), a)
        caller.collect(0.3)

        # 5. http_async_query: the HTTP answer picks the next hop.
        send(msg("INVITE", "http42"))
        d, a = uas2.recv(3)
        check("http_async_query: route continues with $http_rb as next hop", d is not None and d.startswith(b"INVITE sip:http42@"), d)
        check("…$http_rs and $http_hdr(X-Echo); $http_req(hdr) was sent", d is not None and hdr(d, "X-HTTP") == "200 http42"
              and ("/target?u=http42", "http42") in Http.seen, (d and hdr(d, "X-HTTP"), Http.seen))
        if d:
            uas2.s.sendto(make_reply(d, 486, "Busy Here"), a)
        r = [x for x, _, _ in caller.collect(1) if not x.startswith(b"SIP/2.0 1")]
        check("…final reply of the resumed transaction upstream", r and first(r[0]) == "SIP/2.0 486 Busy Here", r)
        send(msg("MESSAGE", "httpbad"))
        r = [x for x, _, _ in caller.collect(3, until=lambda l: any(not x.startswith(b"SIP/2.0 1") for x, _, _ in l)) if not x.startswith(b"SIP/2.0 1")]
        check("HTTP failure: $http_ok false → t_reply(503) on the resumed transaction", r and first(r[0]) == "SIP/2.0 503 HTTP failed", r)

        # 6. CANCEL while suspended.
        inv = msg("INVITE", "route")
        send(inv)
        time.sleep(0.2)
        send(cancel_of(inv))
        rs = caller.collect(0.5)
        codes = sorted(first(d) for d, _, _ in rs if not d.startswith(b"SIP/2.0 100"))
        check("CANCEL while suspended: 200 to the CANCEL, 487 to the INVITE", codes == ["SIP/2.0 200 OK", "SIP/2.0 487 Request Terminated"], codes)
        late = uas.collect(1.2)
        check("…and the resumed route does not forward it", not any(d.startswith(b"INVITE") for d, _, _ in late), late)

        # 7. Nobody resumes: 500 after fr_timer.
        t0 = time.time()
        send(msg("MESSAGE", "stuck"))
        r = [x for x, _, _ in caller.collect(2.5, until=lambda l: any(not x.startswith(b"SIP/2.0 1") for x, _, _ in l)) if not x.startswith(b"SIP/2.0 1")]
        check("t_suspend without t_continue → 500 after fr_timer", r and first(r[0]).startswith("SIP/2.0 500") and 0.9 < time.time() - t0 < 2.2, (r, time.time() - t0))

        # 8. t_suspend + t_continue from another request ($T(id_index/label) via htable).
        send(msg("INVITE", "park"))
        time.sleep(0.2)
        caller.collect(0.1)
        send(msg("MESSAGE", "unpark"))
        d, a = uas.recv(2)
        r = [x for x, _, _ in caller.collect(0.5) if x.startswith(b"SIP/2.0 200 Unparked")]
        check("t_continue(index, label, route) resumes the parked INVITE", d is not None and d.startswith(b"INVITE sip:park@") and hdr(d, "X-Later") == "yes" and r, (d, r))
        if d:
            uas.s.sendto(make_reply(d, 486, "Busy Here"), a)
        caller.collect(0.5)
        send(msg("MESSAGE", "unpark"))
        r = [x for x, _, _ in caller.collect(1) if not x.startswith(b"SIP/2.0 1")]
        check("…a second t_continue finds nothing", r and first(r[0]) == "SIP/2.0 404 No such", r)

        # 9. Stateless reply after resuming becomes the transaction's reply.
        m = msg("MESSAGE", "slreply")
        send(m)
        r1 = [x for x, _, _ in caller.collect(1, until=lambda l: len(l) >= 1)]
        # The reply goes out a moment before tm keeps it for retransmissions
        # (a retransmission in between is absorbed; a UAC would send another).
        time.sleep(0.2)
        send(m)
        r2 = [x for x, _, _ in caller.collect(0.5, until=lambda l: len(l) >= 1)]
        check("sl_send_reply after async_ms_sleep answers; a retransmission gets it again", r1 and first(r1[0]) == "SIP/2.0 404 Not Here" and r2
              and first(r2[0]) == "SIP/2.0 404 Not Here", (r1, r2))

        # 10. sql_query_async.
        cid = f"sql-{time.time_ns()}"
        send(msg("MESSAGE", "sqlasync", callid=cid))
        r = caller.collect(1, until=lambda l: len(l) >= 1)
        time.sleep(0.3)
        rows = sqlite3.connect(DB).execute("select callid from cdr").fetchall()
        check("sql_query_async: reply at once, row inserted in the background", r and first(r[0][0]) == "SIP/2.0 200 Queued" and (cid,) in rows, (r, rows))
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
