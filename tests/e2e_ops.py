#!/usr/bin/env python3
"""End-to-end checks for the operations modules (Phase 12): `keepalive`
(OPTIONS probes, is_alive, dst-up/dst-down events, RPC), `sipdump` (text
and pcap files, sipdump_send, RPC on/off) and `evapi` (netstring clients,
tags, unicast, evapi_async_relay + t_continue from the client's answer,
evapi_close, RPC). Run from the repo root after `cargo build --release`.
"""
import json, os, shutil, socket, struct, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_routing import Peer, make_reply, first, hdr  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY, CALLER, UAS, UP, DOWN, EV = 7400, 7499, 7401, 7410, 7411, 7448
SOCK = os.path.join(ROOT, "target/e2e_ops.sock")
DUMP = os.path.join(ROOT, "target/sipdump")

CFG = f"""
loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "keepalive"
loadmodule "sipdump"
loadmodule "evapi"
loadmodule "xlog"
modparam("tm", "fr_timer", 500)
modparam("keepalive", "destination", "127.0.0.1:{UP}")
modparam("keepalive", "destination", "sip:127.0.0.1:{DOWN}")
modparam("keepalive", "ping_interval", 1)
modparam("sipdump", "enable", 1)
modparam("sipdump", "mode", 7)
modparam("sipdump", "folder", "{DUMP}")
modparam("evapi", "bind_addr", "127.0.0.1:{EV}")

event_route[sipdump:msg] {{
    if ($sipdump(tag) == "rcv" && $sipdump(src_port) == {CALLER}) {{
        xlog("L_INFO", "SIPDUMP $sipdump(tag) $sipdump(proto) $sipdump(src_ip):$sipdump(src_port) $sipdump(len)\\n");
    }}
}}
event_route[keepalive:dst-up] {{ evapi_relay("up $ru"); }}
event_route[keepalive:dst-down] {{ evapi_relay("down $ru"); }}
event_route[evapi:connection-new] {{ evapi_set_tag("app"); }}
event_route[evapi:message-received] {{
    if ($(evapi(msg){{s.select,0,:}}) == "continue") {{
        t_continue("$(evapi(msg){{s.select,1,:}})", "$(evapi(msg){{s.select,2,:}})", "RESUME");
    }}
    if ($evapi(msg) == "bye") {{ evapi_close(); }}
}}

request_route {{
    if ruri_user_prefix("alive") {{
        is_alive("sip:127.0.0.1:{UP}");
        $var(u) = $rc;
        is_alive("127.0.0.1:{DOWN}");
        $var(d) = $rc;
        is_alive("sip:127.0.0.1:1");
        sl_send_reply(200, "up=$var(u) down=$var(d) unknown=$rc");
        exit;
    }}
    if ruri_user_prefix("ask") {{ evapi_async_relay("route:$T(id_index):$T(id_label):$rU"); exit; }}
    if ruri_user_prefix("tag") {{ evapi_unicast("hello $rU", "app"); sl_send_reply(200, "sent"); exit; }}
    if ruri_user_prefix("dump") {{ sipdump_send("mytag"); sl_send_reply(200, "dumped"); exit; }}
    sl_send_reply(200, "OK");
}}

route[RESUME] {{
    append_hf("X-Resumed: yes\\r\\n");
    t_relay("udp:127.0.0.1:{UAS}");
}}
"""

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


class Pinged(threading.Thread):
    """Answers OPTIONS with 200 while `on`."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.on, self.pings = True, 0
        self.start()

    def run(self):
        while True:
            d, a = self.s.recvfrom(65535)
            if d.startswith(b"OPTIONS"):
                self.pings += 1
                if self.on:
                    self.s.sendto(make_reply(d, 200, "OK"), a)


class EvClient:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", EV))
        self.buf = b""
        self.msgs = []
        self.closed = False
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            d = self.s.recv(4096)
            if not d:
                self.closed = True
                return
            self.buf += d
            while b":" in self.buf:
                n, rest = self.buf.split(b":", 1)
                n = int(n)
                if len(rest) < n + 1:
                    break
                self.msgs.append(rest[:n].decode())
                self.buf = rest[n + 1:]

    def send(self, m):
        self.s.sendall(f"{len(m)}:{m},".encode())

    def wait(self, pred, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            for m in self.msgs:
                if pred(m):
                    return m
            time.sleep(0.05)
        return None


def msg(method, user):
    seq[0] += 1
    return (f"{method} sip:{user}@127.0.0.1:{PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch=z9hG4bKo{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: <sip:caller@x>;tag=c{seq[0]}\r\nTo: <sip:{user}@x>\r\nCall-ID: ops-{seq[0]}-{time.time_ns()}\r\n"
            f"CSeq: 1 {method}\r\nContact: <sip:caller@127.0.0.1:{CALLER}>\r\nContent-Length: 0\r\n\r\n").encode()


def ctl(*args):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, *args], capture_output=True, text=True, timeout=5)
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return out.stdout + out.stderr


def main():
    shutil.rmtree(DUMP, ignore_errors=True)
    os.makedirs(DUMP)
    up = Pinged(UP)
    caller, uas = Peer(CALLER), Peer(UAS)
    cfg = os.path.join(ROOT, "target/e2e_ops.cfg")
    open(cfg, "w").write(CFG)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY}", "-n", "2", "--rpc-socket", SOCK],
                         stderr=subprocess.PIPE, text=True)
    err = []
    threading.Thread(target=lambda: err.extend(p.stderr), daemon=True).start()
    try:
        end = time.time() + 5
        while time.time() < end and not any("listening on" in l for l in err):
            time.sleep(0.05)
        ev = EvClient()

        def ask(user, method="OPTIONS"):
            caller.s.sendto(msg(method, user), ("127.0.0.1", PROXY))
            return caller.final()

        # ---------------------------------------------------- keepalive
        time.sleep(1.2)
        lst = {d["uri"]: d["state"] for d in ctl("keepalive.list")} if isinstance(ctl("keepalive.list"), list) else {}
        check("keepalive: OPTIONS probes mark the destinations up / down", lst == {f"sip:127.0.0.1:{UP}": "up", f"sip:127.0.0.1:{DOWN}": "down"} and up.pings >= 1, (lst, up.pings))
        r = ask("alive")
        check("is_alive(): 1 up, -1 down, -2 unknown", first(r) == "SIP/2.0 200 up=1 down=-1 unknown=-2", first(r))
        up.on = False
        m = ev.wait(lambda m: m == f"down sip:127.0.0.1:{UP}", 4)
        check("event_route[keepalive:dst-down] when it stops answering (relayed over evapi)", m is not None, ev.msgs)
        up.on = True
        m = ev.wait(lambda m: m == f"up sip:127.0.0.1:{UP}", 4)
        check("event_route[keepalive:dst-up] when it answers again", m is not None, ev.msgs)
        ctl("keepalive.add", "sip:127.0.0.1:7412")
        check("RPC keepalive.add / del", any(d["uri"] == "sip:127.0.0.1:7412" for d in ctl("keepalive.list")) and ctl("keepalive.del", "sip:127.0.0.1:7412") == "ok"
              and not any(d["uri"] == "sip:127.0.0.1:7412" for d in ctl("keepalive.list")))

        # ---------------------------------------------------- evapi
        cl = ctl("evapi.clients")
        check("evapi: client connected and tagged in connection-new", isinstance(cl, list) and len(cl) == 1 and cl[0]["tag"] == "app", cl)
        r = ask("tag42")
        check("evapi_unicast to the tagged client", first(r) == "SIP/2.0 200 sent" and ev.wait(lambda m: m == "hello tag42", 2) is not None, ev.msgs[-3:])
        caller.s.sendto(msg("INVITE", "ask7"), ("127.0.0.1", PROXY))
        m = ev.wait(lambda m: m.startswith("route:"), 3)
        check("evapi_async_relay: suspended, $T(id_index/id_label) sent to the app", m is not None and m.endswith(":ask7") and len(m.split(":")) == 4, m)
        if m:
            _, i, l, _ = m.split(":")
            ev.send(f"continue:{i}:{l}")
        inv = uas.expect("INVITE", 3)
        check("…the app's answer resumes it (t_continue in evapi:message-received)", inv is not None and hdr(inv, "X-Resumed") == "yes", inv)
        if inv:
            uas.s.sendto(make_reply(inv, 486, "Busy Here"), uas.addr)
        r = caller.final()
        check("…and the transaction completes", first(r) == "SIP/2.0 486 Busy Here", first(r))
        ev.send("bye")
        end = time.time() + 2
        while time.time() < end and not ev.closed:
            time.sleep(0.05)
        check("evapi_close() drops the client", ev.closed and ctl("evapi.clients") == [], ctl("evapi.clients"))

        # ---------------------------------------------------- sipdump
        ask("dump")
        time.sleep(0.3)
        files = sorted(os.listdir(DUMP))
        data = [f for f in files if f.endswith(".data")]
        pcap = [f for f in files if f.endswith(".pcap")]
        txt = open(os.path.join(DUMP, data[0])).read() if data else ""
        check("sipdump: text file with received and sent messages", data and "tag: rcv\n" in txt and "tag: snd\n" in txt and "OPTIONS sip:alive@" in txt
              and f"dstport: {CALLER}\n" in txt, files)
        check("sipdump_send(tag) records the message with that tag", "tag: mytag\n" in txt and "OPTIONS sip:dump@" in txt)
        lines = [l for l in "".join(err).splitlines() if "SIPDUMP " in l]
        check("mode 2: event_route[sipdump:msg] runs per record with $sipdump(...)", any(f"SIPDUMP rcv udp 127.0.0.1:{CALLER} " in l for l in lines), lines[-3:])
        raw = open(os.path.join(DUMP, pcap[0]), "rb").read() if pcap else b""
        ok = raw[:4] == b"\xd4\xc3\xb2\xa1" and struct.unpack("<I", raw[20:24])[0] == 101
        n, off, sip = 0, 24, 0
        while ok and off + 16 <= len(raw):
            ln = struct.unpack("<I", raw[off + 8:off + 12])[0]
            pkt = raw[off + 16:off + 16 + ln]
            n += 1
            if pkt[0] >> 4 == 4 and pkt[9] == 17 and (pkt[28:].startswith(b"SIP/2.0 ") or pkt[28:].split(b"\r\n", 1)[0].endswith(b" SIP/2.0")):
                sip += 1
            off += 16 + ln
        check("sipdump: pcap (raw IPv4/UDP) with the SIP messages", ok and n >= 4 and sip == n and off == len(raw), (n, sip, off, len(raw)))
        before = len(txt)
        check("RPC sipdump.enable 0 stops dumping", ctl("sipdump.enable", "0") == {"enable": 0})
        ask("quiet")
        time.sleep(0.3)
        check("…no new records", len(open(os.path.join(DUMP, data[0])).read()) == before if data else False)
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
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
