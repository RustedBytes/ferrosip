#!/usr/bin/env python3
"""End-to-end checks for request-URI routing (Phase 8): RFC 3263 DNS
(NAPTR → SRV → A, additional-section glue, SRV priorities and weighted load
balancing), DNS failover on 503 / timeout, `t_load_contacts()` /
`t_next_contacts()` serial forking by q-value (no q: below every q),
`max_branches`, and the `dns.lookup` / `dns.flush` RPCs. A scripted DNS server answers the queries.
Run from the repo root after `cargo build --release`.
"""
import json, os, socket, struct, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_routing import Peer, make_reply, first  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY, DNS, CALLER = 6900, 6953, 6999
GW1, GW2, GW3, DEAD, LBA, LBB = 6901, 6902, 6903, 6950, 6904, 6905
SA, SB, SC = 6911, 6912, 6913
SOCK = os.path.join(ROOT, "target/e2e_dns.sock")

CFG = f"""
loadmodule "tm"
loadmodule "sl"
loadmodule "blst"
modparam("tm", "fr_timer", 1000)
modparam("tm", "use_dst_blocklist", 1)
modparam("tm", "dst_blocklist_expire", 30)
modparam("tm", "fr_inv_timer", 3000)
modparam("tm", "dns_server", "127.0.0.1:{DNS}")
modparam("tm", "use_dns_failover", 1)
modparam("tm", "dns_try_naptr", 1)
modparam("tm", "dns_srv_lb", 1)
modparam("tm", "max_branches", 3)

request_route {{
    if ruri_user_prefix("bladd") {{ $du = "sip:127.0.0.1:6951"; blst_add(1); sl_send_reply(200, "added"); exit; }}
    if ruri_user_prefix("isbl") {{
        $du = "sip:127.0.0.1:6951";
        if (blst_is_blocklisted()) {{ sl_send_reply(200, "blocked"); }} else {{ sl_send_reply(200, "clear"); }}
        exit;
    }}
    if ruri_user_prefix("serial") {{
        append_branch("sip:b@127.0.0.1:{SB}", "0.5");
        append_branch("sip:c@127.0.0.1:{SC}", "0.5");
        t_load_contacts();
        t_next_contacts();
        t_on_failure("NEXT");
        t_relay();
        exit;
    }}
    if ruri_user_prefix("many") {{
        append_branch("sip:b@127.0.0.1:{SB}");
        append_branch("sip:c@127.0.0.1:{SC}");
        append_branch("sip:d@127.0.0.1:{GW3}");
        t_relay();
        exit;
    }}
    # No reply in the script: tm answers a failed relay itself.
    if (ruri_user_prefix("bare")) {{ t_relay(); exit; }}
    if (!t_relay()) {{ sl_reply_error(); }}
}}

failure_route[NEXT] {{
    if (!t_next_contacts()) {{ exit; }}
    t_on_failure("NEXT");
    t_relay();
}}
"""

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


# ------------------------------------------------------------------ DNS --
def name_bytes(n):
    return b"".join(bytes([len(l)]) + l.encode() for l in n.rstrip(".").split(".") if l) + b"\x00"


def rr(name, ty, rdata, ttl=300):
    return name_bytes(name) + struct.pack("!HHIH", ty, 1, ttl, len(rdata)) + rdata


def srv(prio, weight, port, target):
    return struct.pack("!HHH", prio, weight, port) + name_bytes(target)


def naptr(order, pref, flags, service, regexp, repl):
    cs = lambda s: bytes([len(s)]) + s.encode()
    return struct.pack("!HH", order, pref) + cs(flags) + cs(service) + cs(regexp) + name_bytes(repl)


A = lambda ip: socket.inet_aton(ip)
ZONE = {
    # NAPTR: only UDP is offered, under a non-default SRV name.
    ("naptr.test", 35): ([naptr(10, 10, "s", "SIP+D2U", "", "_sip._udp.alt.naptr.test")], []),
    ("_sip._udp.alt.naptr.test", 33): ([srv(10, 1, GW3, "gw3.naptr.test")], [("gw3.naptr.test", 1, A("127.0.0.1"))]),
    # Priority 10 then 20; gw2's address is not glued (needs an A query).
    ("_sip._udp.pool.test", 33): ([srv(10, 1, GW1, "gw1.pool.test"), srv(20, 1, GW2, "gw2.pool.test")], [("gw1.pool.test", 1, A("127.0.0.1"))]),
    ("gw2.pool.test", 1): ([A("127.0.0.1")], []),
    ("gw1.pool.test", 1): ([A("127.0.0.1")], []),
    # First target never answers → timeout → second.
    ("_sip._udp.dead.test", 33): ([srv(10, 1, DEAD, "dead.dead.test"), srv(20, 1, GW2, "gw2.pool.test")], [("dead.dead.test", 1, A("127.0.0.1"))]),
    # Two equal-priority targets for load balancing.
    # Too big for UDP (served with TC=1; the full answer comes over TCP).
    ("_sip._udp.big.test", 33): ([srv(10, 1, GW3, "gw3.big.test")], [("gw3.big.test", 1, A("127.0.0.1"))]),
    ("_sip._udp.lb.test", 33): ([srv(10, 50, LBA, "a.lb.test"), srv(10, 50, LBB, "b.lb.test")], [("a.lb.test", 1, A("127.0.0.1")), ("b.lb.test", 1, A("127.0.0.1"))]),
}


TRUNCATED = {"_sip._udp.big.test"}


def answer(d, tcp):
    qid, = struct.unpack("!H", d[:2])
    i, labels = 12, []
    while d[i]:
        labels.append(d[i + 1:i + 1 + d[i]].decode())
        i += 1 + d[i]
    qtype, = struct.unpack("!H", d[i + 1:i + 3])
    q = d[12:i + 5]
    name = ".".join(labels).lower()
    if name in TRUNCATED and not tcp:
        return name, qtype, struct.pack("!HHHHHH", qid, 0x8380, 1, 0, 0, 0) + q
    ans, add = ZONE.get((name, qtype), ([], []))
    ans_rr = b"".join(rr(name, qtype, x) for x in ans)
    add_rr = b"".join(rr(n, t, x) for n, t, x in add)
    rcode = 0 if ans or any(k[0] == name for k in ZONE) else 3
    hdr = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, len(ans), 0, len(add))
    return name, qtype, hdr + q + ans_rr + add_rr


class DnsServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", DNS))
        self.t = socket.socket()
        self.t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.t.bind(("127.0.0.1", DNS))
        self.t.listen(4)
        self.log, self.tcp_log = [], []
        threading.Thread(target=self.serve_tcp, daemon=True).start()
        self.start()

    def run(self):
        while True:
            d, a = self.s.recvfrom(4096)
            name, qtype, out = answer(d, False)
            self.log.append((name, qtype))
            self.s.sendto(out, a)

    def serve_tcp(self):
        while True:
            c, _ = self.t.accept()
            f = c.makefile("rb")
            n = struct.unpack("!H", f.read(2))[0]
            name, qtype, out = answer(f.read(n), True)
            self.tcp_log.append((name, qtype))
            c.sendall(struct.pack("!H", len(out)) + out)
            c.close()


# ------------------------------------------------------------------ SIP --
def msg(method, ruri, callid=None):
    seq[0] += 1
    return (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch=z9hG4bKd{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: <sip:caller@x>;tag=c{seq[0]}\r\nTo: <{ruri}>\r\nCall-ID: {callid or f'dns-{seq[0]}-{time.time_ns()}'}\r\n"
            f"CSeq: 1 {method}\r\nContact: <sip:caller@127.0.0.1:{CALLER}>\r\nContent-Length: 0\r\n\r\n").encode()


def ctl(*args):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, *args], capture_output=True, text=True, timeout=5)
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return out.stdout + out.stderr


def main():
    dns = DnsServer()
    caller = Peer(CALLER)
    gw = {p: Peer(p) for p in (GW1, GW2, GW3, LBA, LBB, SA, SB, SC)}
    cfg = os.path.join(ROOT, "target/e2e_dns.cfg")
    open(cfg, "w").write(CFG)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY}", "-n", "2", "--rpc-socket", SOCK],
                         stderr=subprocess.PIPE, text=True)
    err = ""
    try:
        end = time.time() + 5
        while time.time() < end and not os.path.exists(SOCK):
            time.sleep(0.05)
        time.sleep(0.2)

        def send(m):
            caller.s.sendto(m, ("127.0.0.1", PROXY))

        # 1. NAPTR → SRV (non-default name) → glue A.
        send(msg("MESSAGE", "sip:x@naptr.test"))
        m = gw[GW3].answer("MESSAGE")
        r = caller.final()
        check("NAPTR → SRV → A: MESSAGE reaches the NAPTR's SRV target", m is not None and first(r) == "SIP/2.0 200 OK", (first(r), dns.log))
        check("…NAPTR queried, its SRV name used, no A query (glue)", ("naptr.test", 35) in dns.log and ("_sip._udp.alt.naptr.test", 33) in dns.log
              and ("gw3.naptr.test", 1) not in dns.log, dns.log)

        # 2. SRV priority + 503 failover to the next priority.
        send(msg("INVITE", "sip:x@pool.test"))
        inv1 = gw[GW1].expect("INVITE")
        if inv1:
            gw[GW1].s.sendto(make_reply(inv1, 503, "Service Unavailable"), gw[GW1].addr)
        ack1 = gw[GW1].expect("ACK")
        inv2 = gw[GW2].expect("INVITE")
        b1 = inv1.split(b"branch=")[1].split(b"\r\n")[0] if inv1 else b""
        b2 = inv2.split(b"branch=")[1].split(b"\r\n")[0] if inv2 else b""
        check("SRV: priority 10 first; 503 → ACK, then priority 20 (new branch)", inv1 is not None and ack1 is not None and inv2 is not None and b1 != b2
              and b2.startswith(b1.split(b";")[0]), (inv1, inv2))
        check("…the second target's address came from an A query", ("gw2.pool.test", 1) in dns.log, dns.log)
        if inv2:
            gw[GW2].s.sendto(make_reply(inv2, 200, "OK", f"Contact: <sip:x@127.0.0.1:{GW2}>\r\n"), gw[GW2].addr)
        r = caller.final()
        check("…caller gets the 200 of the failover target, not the 503", first(r) == "SIP/2.0 200 OK", first(r))

        # 3. Timeout failover (fr_timer 1 s).
        t0 = time.time()
        send(msg("MESSAGE", "sip:x@dead.test"))
        m = gw[GW2].expect("MESSAGE", 3)
        if m:
            gw[GW2].s.sendto(make_reply(m, 200, "OK"), gw[GW2].addr)
        r = caller.final()
        check("timeout on the first SRV target → next target after fr_timer", m is not None and 0.9 < time.time() - t0 < 2.5 and first(r) == "SIP/2.0 200 OK",
              (time.time() - t0, first(r)))

        # 3b. The dead target is blocklisted now: straight to the next one.
        t0 = time.time()
        send(msg("MESSAGE", "sip:x@dead.test"))
        m = gw[GW2].expect("MESSAGE", 2)
        if m:
            gw[GW2].s.sendto(make_reply(m, 200, "OK"), gw[GW2].addr)
        caller.final()
        bl = ctl("dst_blocklist.list")
        check("dst_blocklist: the target that never answered is skipped (no fr_timer wait)", m is not None and time.time() - t0 < 0.5
              and any(e["addr"] == f"127.0.0.1:{DEAD}" for e in bl), (time.time() - t0, bl))

        # 4. Weighted load balancing among equal priorities.
        hits = {LBA: 0, LBB: 0}
        for _ in range(16):
            send(msg("MESSAGE", "sip:x@lb.test"))
            got = None
            end = time.time() + 2
            while got is None and time.time() < end:
                for port in (LBA, LBB):
                    gw[port].s.settimeout(0.02)
                    try:
                        d, a = gw[port].s.recvfrom(65535)
                        gw[port].s.sendto(make_reply(d, 200, "OK"), a)
                        got = port
                    except socket.timeout:
                        pass
            if got:
                hits[got] += 1
            caller.final(1)
        check("dns_srv_lb: equal-priority targets both used", hits[LBA] > 0 and hits[LBB] > 0 and hits[LBA] + hits[LBB] == 16, hits)

        # 5. t_load_contacts / t_next_contacts: B+C (q=0.5) → A (no q: Kamailio's
        #    Q_UNSPECIFIED, -1, below every q) → best reply.
        send(msg("INVITE", f"sip:serial@127.0.0.1:{SA}"))
        b, c = gw[SB].expect("INVITE"), gw[SC].expect("INVITE")
        early_a = gw[SA].recv(0.3)
        check("t_load_contacts/t_next_contacts: the q=0.5 group first, in parallel; the R-URI without q waits",
              b is not None and c is not None and early_a is None, (b, c, early_a))
        for peer, req, code, reason in ((gw[SB], b, 486, "Busy Here"), (gw[SC], c, 486, "Busy Here")):
            if req:
                peer.s.sendto(make_reply(req, code, reason), peer.addr)
        a = gw[SA].expect("INVITE")
        check("…after their failure, the R-URI (no q) alone", a is not None, a)
        if a:
            gw[SA].s.sendto(make_reply(a, 486, "Busy Here"), gw[SA].addr)
        r = caller.final()
        check("…no contacts left (t_next_contacts -2) → best reply upstream", first(r) == "SIP/2.0 486 Busy Here", first(r))

        # 6. max_branches = 3: the destination set holds 2, so the third
        #    append_branch() fails and its target is never tried.
        send(msg("MESSAGE", "sip:many@127.0.0.1:6911"))
        got = [gw[x].answer("MESSAGE", 404, "Not Found") is not None for x in (SA, SB, SC)]
        extra = gw[GW3].recv(0.4)
        caller.final()
        check("max_branches=3 limits the fork", all(got) and extra is None, (got, extra))

        # 7. RPC.
        lk = ctl("dns.lookup", "sip:pool.test")
        check("RPC dns.lookup lists the SRV targets in order", lk == [f"udp:127.0.0.1:{GW1}", f"udp:127.0.0.1:{GW2}"], lk)
        n = len(dns.log)
        check("RPC dns.flush clears the cache", ctl("dns.flush") == "ok" and (ctl("dns.lookup", "sip:pool.test") or True) and len(dns.log) > n, dns.log[n:])

        # 9. Truncated UDP answer → TCP.
        send(msg("MESSAGE", "sip:x@big.test"))
        m = gw[GW3].answer("MESSAGE")
        r = caller.final()
        check("DNS: a truncated (TC) answer is retried over TCP", m is not None and first(r) == "SIP/2.0 200 OK"
              and ("_sip._udp.big.test", 33) in dns.tcp_log, (dns.tcp_log, first(r)))

        # 10. blst module + RPCs.
        send(msg("OPTIONS", f"sip:bladd@127.0.0.1:{PROXY}"))
        a1 = first(caller.final())
        send(msg("OPTIONS", f"sip:isbl@127.0.0.1:{PROXY}"))
        a2 = first(caller.final())
        time.sleep(1.2)
        send(msg("OPTIONS", f"sip:isbl@127.0.0.1:{PROXY}"))
        a3 = first(caller.final())
        check("blst_add(1) / blst_is_blocklisted, entry expires", (a1, a2, a3) == ("SIP/2.0 200 added", "SIP/2.0 200 blocked", "SIP/2.0 200 clear"), (a1, a2, a3))
        ctl("dst_blocklist.add", f"sip:127.0.0.1:{SA}", "30")
        send(msg("MESSAGE", f"sip:plain@127.0.0.1:{SA}"))
        r = caller.final()
        check("only target blocklisted → t_relay fails, 477 (477/TM)", first(r) == "SIP/2.0 477 Unfortunately error on sending to next hop occurred (477/TM)", first(r))
        check("RPC dst_blocklist.del / flush", ctl("dst_blocklist.del", f"sip:127.0.0.1:{SA}") == "ok" and ctl("dst_blocklist.flush") == "ok"
              and ctl("dst_blocklist.list") == [], ctl("dst_blocklist.list"))

        # 8. Unknown name → 478 (Kamailio's E_BAD_ADDRESS reply).
        send(msg("MESSAGE", "sip:x@nowhere.invalid"))
        r = caller.final()
        check("unresolvable R-URI → 478 (478/TM)", first(r) == "SIP/2.0 478 Unresolvable destination (478/TM)", first(r))
        # Kamailio t_funcs.c:330-378: tm answers the failed relay when the
        # script ends (delayed_reply); sl_reply_error() sends nothing then.
        # An INVITE has its 100 Trying first. One final either way.
        e478 = "SIP/2.0 478 Unresolvable destination (478/TM)"
        for ruri, what in (("sip:x@nowhere.invalid", "if (!t_relay()) { sl_reply_error(); }"), ("sip:bare@nowhere.invalid", "a bare t_relay()")):
            send(msg("INVITE", ruri))
            got = []
            while (m := caller.recv(0.8)) is not None:
                got.append(first(m))
            check(f"unresolvable INVITE, {what} → 100 Trying, then tm's 478, nothing else", got == ["SIP/2.0 100 Trying", e478], got)
    finally:
        p.terminate()
        try:
            err = p.communicate(timeout=3)[1]
        except subprocess.TimeoutExpired:
            p.kill()
            err = p.communicate()[1]
        check("no panics in proxy log", "panicked" not in err, err[-2000:])
        if failures:
            print("--- proxy stderr ---\n" + err[-4000:])
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
