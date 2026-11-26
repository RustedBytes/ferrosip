#!/usr/bin/env python3
"""End-to-end checks for registrar + usrloc (RFC 3261 §10.3, RFC 5626 bits).

Starts its own proxy (UDP, TCP, WS listeners) and plays registering user
agents and callers with raw sockets. Run from the repo root after
`cargo build --release`.
"""
import os, re, shutil, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402
from e2e_ws import WsClient, frame  # noqa: E402  (raw WebSocket client)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PX, WS = 5360, 8280
PX2 = 5364
# The second proxy: save() flags and AoR argument, lookup(uri),
# lookup_branches(), registered() with match_option/match_action,
# unregister(), reg_fetch_contacts() and $ulc; usrloc writes a db_text table.
CFG2 = r"""loadmodule "tm"
loadmodule "sl"
loadmodule "textops"
loadmodule "usrloc"
loadmodule "registrar"
modparam("usrloc", "db_mode", 1)
modparam("usrloc", "db_url", "text://DB")
modparam("registrar", "min_expires", 2)
modparam("registrar", "xavp_cfg", "reg")
modparam("registrar", "xavp_rcd", "rcd")
request_route {
    if method == "REGISTER" {
        if $tU == "quiet" {
            if save("location", "0x12") {
                append_to_reply("X-Saved: yes\r\n");
                sl_send_reply(200, "Saved Quietly");
            } else {
                sl_reply_error();
            }
            exit;
        }
        if $tU == "varflags" {
            $var(f) = 18;
            if save("location", "$var(f)") { sl_send_reply(200, "Var Flags"); }
            exit;
        }
        if $tU == "rc" {
            # 0x02 alone: nothing for the script's reply; reg_send_reply()
            # sends what save() would have.
            save("location", "0x02");
            $var(rc) = $rc;
            append_to_reply("X-Rc: $var(rc)\r\n");
            reg_send_reply();
            exit;
        }
        if $tU == "bare" {
            save("location", "0x02");
            sl_send_reply(200, "Bare");
            exit;
        }
        if $tU == "single" { save("location", 4); exit; }
        if $tU == "mem" { save("location", "0x01"); exit; }
        if $tU == "alias" { save("location", "0", "sip:target@example.com"); exit; }
        save("location");
        exit;
    }
    if $hdr(X-Op) == "fetch" {
        if reg_fetch_contacts("location", "sip:$rU@example.com", "p") {
            append_to_reply("X-ULC: $ulc(p=>count) $ulc(p=>aor) $(ulc(p=>addr)[0]) $(ulc(p=>addr)[1]) $(ulc(p=>addr)[-1]) $ulc(p=>q) $ulc(p=>callid) $ulc(p=>user_agent) $ulc(p=>methods) $ulc(p=>domain) [$(ulc(p=>addr)[5])] [$ulc(p=>conid)] $ulc(p=>regid)\r\n");
            append_to_reply("X-Ruid: $ulc(p=>ruid)\r\n");
            append_to_reply("X-Rcv: $ulc(p=>received) $ulc(p=>socket) $ulc(p=>flags)\r\n");
            $var(ttl) = $ulc(p=>expires) - $Ts;
            append_to_reply("X-TTL: $var(ttl)\r\n");
            reg_free_contacts("p");
            append_to_reply("X-Freed: [$ulc(p=>count)]\r\n");
            sl_send_reply(200, "Fetched");
        } else {
            sl_send_reply(404, "No Contacts [$ulc(p=>count)]");
        }
        exit;
    }
    if $hdr(X-Op) == "unregister" {
        if is_present_hf("X-Ruid") {
            unregister("location", "sip:$rU@example.com", "$hdr(X-Ruid)");
            $var(rc) = $rc;
            if $var(rc) > 0 { sl_send_reply(200, "Unregistered One"); } else { sl_send_reply(404, "No Such Ruid $var(rc)"); }
        } else {
            if unregister("location", "$rU@example.com") { sl_send_reply(200, "Unregistered"); }
        }
        exit;
    }
    if $hdr(X-Op) == "registered" {
        $xavp(reg=>match_callid) = $hdr(X-Match);
        if registered("location", "sip:$rU@example.com", 1, 1) { sl_send_reply(200, "Match $xavp(rcd=>contact)"); } else { sl_send_reply(404, "No Match"); }
        exit;
    }
    if $hdr(X-Op) == "registered-rcv" {
        # match_option 2: the received address; match_action 2: no xavp_rcd.
        $xavp(reg=>match_received) = $hdr(X-Match);
        if registered("location", "sip:$rU@example.com", 2, 2) { sl_send_reply(200, "Match [$xavp(rcd=>contact)]"); } else { sl_send_reply(404, "No Match"); }
        exit;
    }
    if $hdr(X-Op) == "lookup-uri" {
        if !lookup("location", "$hdr(X-Target)") { sl_send_reply(404, "Not Found"); exit; }
        t_relay();
        exit;
    }
    if $hdr(X-Op) == "branches" {
        if $hdr(X-Other) == "single" { append_branch("sip:single@127.0.0.1"); } else { append_branch("sip:nobody2@127.0.0.1"); }
        if !lookup_branches("location") { sl_send_reply(404, "Not Found"); exit; }
        t_relay();
        exit;
    }
    if !lookup("location") { sl_send_reply(404, "Not Found"); exit; }
    t_relay();
}
"""
CFG = """loadmodule "tm"
loadmodule "usrloc"
loadmodule "registrar"
modparam("usrloc", "handle_lost_tcp", 1)
modparam("usrloc", "timer_interval", 1)
modparam("registrar", "min_expires", 2)
modparam("registrar", "max_expires", 7200)
modparam("registrar", "max_contacts", 3)
request_route {
    if method == "REGISTER" { save("location"); exit; }
    if method == "OPTIONS" {
        if registered("location") { reply(200, "Registered"); } else { reply(404, "Not Registered"); }
        exit;
    }
    if !lookup("location") { reply(404, "Not Found"); exit; }
    if !t_relay() { sl_reply_error(); }
}
"""
failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(2)
    return s


def msg(method, ruri, to, callid, cseq=1, contacts=(), expires=None, via="UDP 127.0.0.1:9", extra=""):
    seq[0] += 1
    h = [f"{method} {ruri} SIP/2.0", f"Via: SIP/2.0/{via};branch=z9hG4bKr{seq[0]}x{time.time_ns()}",
         "Max-Forwards: 70", "From: <sip:x@127.0.0.1>;tag=f1", f"To: <{to}>", f"Call-ID: {callid}",
         f"CSeq: {cseq} {method}"]
    h += [f"Contact: {c}" for c in contacts]
    if expires is not None:
        h.append(f"Expires: {expires}")
    if extra:
        h.append(extra)
    return ("\r\n".join(h) + "\r\nContent-Length: 0\r\n\r\n").encode()


def register(sock, user, contacts=(), expires=None, callid=None, cseq=None, extra="", px=PX):
    callid = callid or f"reg-{user}"
    sock.sendto(msg("REGISTER", "sip:127.0.0.1", f"sip:{user}@example.com", callid, cseq or seq[0] + 1,
                    contacts, expires, extra=extra), ("127.0.0.1", px))
    return sock.recv(65535).decode()


def ask(sock, user, extra, px=PX2, method="OPTIONS"):
    """Send a request with extra headers; returns the whole reply."""
    sock.sendto(msg(method, f"sip:{user}@127.0.0.1", f"sip:{user}@127.0.0.1", f"q-{time.time_ns()}", extra=extra), ("127.0.0.1", px))
    try:
        return sock.recv(65535).decode()
    except socket.timeout:
        return "timeout"


def hdr(reply, name):
    m = re.search(rf"^{name}: (.*?)\r?$", reply, re.M)
    return m.group(1) if m else None


def call(sock, user):
    """Caller sends MESSAGE to user; returns the status line (or 'timeout')."""
    sock.sendto(msg("MESSAGE", f"sip:{user}@127.0.0.1", f"sip:{user}@127.0.0.1", f"call-{time.time_ns()}"), ("127.0.0.1", PX))
    try:
        return sock.recv(65535).decode().split("\r\n")[0]
    except socket.timeout:
        return "timeout"


def answer(sock):
    """UA side: receive one request over UDP and answer 200; returns the request."""
    d, a = sock.recvfrom(65535)
    sock.sendto(ok_for(d), a)
    return d.decode()


def ok_for(raw):
    lines = raw.decode().split("\r\n")
    keep = [l for l in lines if l.split(":")[0] in ("Via", "From", "To", "Call-ID", "CSeq")]
    return ("SIP/2.0 200 OK\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n").encode()


def contacts_of(reply):
    return re.findall(r"^Contact: (.*?)\r?$", reply, re.M)


def drain(*socks):
    """Discard queued datagrams (e.g. tm retransmissions) between tests."""
    for s in socks:
        s.settimeout(0.05)
        try:
            while True:
                s.recv(65535)
        except (socket.timeout, BlockingIOError):
            pass
        s.settimeout(2)


def main():
    cfg = os.path.join(ROOT, "target/e2e_reg.cfg")
    open(cfg, "w").write(CFG)
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}",
                              "-l", f"tcp:127.0.0.1:{PX}", "-l", f"ws:127.0.0.1:{WS}", "-n", "2", "--tcp-readers", "2"],
                             stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    alice, caller, alice2 = udp(5301), udp(5302), udp(5303)
    try:
        # 1. Basic registration; Contact claims a private (NATed) address.
        r = register(alice, "alice", ["<sip:alice@10.9.9.9:5060>"], expires=120)
        check("REGISTER → 200 with binding and expires", r.startswith("SIP/2.0 200")
              and contacts_of(r) == ["<sip:alice@10.9.9.9:5060>;expires=120"], r)
        check("200 To has a tag", re.search(r"^To: .*;tag=", r, re.M) is not None)

        # 2. Query: REGISTER without Contact lists current bindings.
        r = register(alice, "alice")
        check("query REGISTER lists bindings", r.startswith("SIP/2.0 200") and len(contacts_of(r)) == 1, r)

        # 3. registered()
        caller.sendto(msg("OPTIONS", "sip:alice@127.0.0.1", "sip:alice@127.0.0.1", "o1"), ("127.0.0.1", PX))
        r1 = caller.recv(65535).decode().split("\r\n")[0]
        caller.sendto(msg("OPTIONS", "sip:nobody@127.0.0.1", "sip:nobody@127.0.0.1", "o2"), ("127.0.0.1", PX))
        r2 = caller.recv(65535).decode().split("\r\n")[0]
        check("registered() true/false", r1 == "SIP/2.0 200 Registered" and r2 == "SIP/2.0 404 Not Registered", (r1, r2))

        # 4. lookup → R-URI rewritten to the contact, delivered to where the
        #    REGISTER came from (not the private Contact address).
        caller.sendto(msg("MESSAGE", "sip:alice@127.0.0.1", "sip:alice@127.0.0.1", "m1"), ("127.0.0.1", PX))
        got = answer(alice)
        check("lookup: delivered to registration source, R-URI = contact",
              got.startswith("MESSAGE sip:alice@10.9.9.9:5060 SIP/2.0"), got[:60])
        r = caller.recv(65535).decode().split("\r\n")[0]
        check("…and the UA's 200 reaches the caller", r == "SIP/2.0 200 OK", r)
        check("unknown user → 404", call(caller, "bob") == "SIP/2.0 404 Not Found")

        # 5. Expiry limits.
        r = register(alice, "alice", ["<sip:alice@10.9.9.9:5060>"], expires=1)
        check("Expires below min_expires → 423 + Min-Expires", r.startswith("SIP/2.0 423") and "Min-Expires: 2" in r, r[:80])
        r = register(alice, "alice", ["<sip:alice@10.9.9.9:5060>"], expires=100000)
        check("Expires above max_expires → clamped", contacts_of(r) == ["<sip:alice@10.9.9.9:5060>;expires=7200"], contacts_of(r))

        # 6. Out-of-order CSeq for the same Call-ID is refused, binding kept.
        r = register(alice, "alice", ["<sip:alice@10.9.9.9:5060>;expires=0"], cseq=1)
        check("same Call-ID, lower CSeq → 400 Invalid CSeq number, binding kept", r.startswith("SIP/2.0 400 Invalid CSeq number")
              and len(contacts_of(register(alice, "alice"))) == 1, r[:60])

        # 7. Two bindings → lookup() appends both (append_branches=1, as in
        #    Kamailio) and tm forks in parallel; the caller gets one 200.
        register(alice, "alice", ["<sip:alice@10.9.9.9:5060>;q=0.5"])
        r = register(alice2, "alice", ["<sip:alice@10.9.9.9:5061>;q=0.9"], callid="reg-alice-2", cseq=1)
        check("second contact added (2 bindings)", len(contacts_of(r)) == 2, contacts_of(r))
        caller.sendto(msg("MESSAGE", "sip:alice@127.0.0.1", "sip:alice@127.0.0.1", "m2"), ("127.0.0.1", PX))
        got2, got1 = answer(alice2), answer(alice)
        check("both contacts receive the request (parallel fork)", got2.startswith("MESSAGE sip:alice@10.9.9.9:5061 ")
              and got1.startswith("MESSAGE sip:alice@10.9.9.9:5060 "), (got2[:50], got1[:50]))
        replies = []
        try:
            while True:
                replies.append(caller.recv(65535).decode().split("\r\n")[0])
                caller.settimeout(0.5)
        except socket.timeout:
            caller.settimeout(2)
        check("caller gets exactly one 200 for the forked MESSAGE", replies == ["SIP/2.0 200 OK"], replies)
        drain(alice, alice2, caller)

        # 8. max_contacts = 3.
        register(alice, "alice", ["<sip:alice@10.9.9.9:5062>"], callid="reg-alice-3", cseq=1)
        r = register(alice, "alice", ["<sip:alice@10.9.9.9:5063>"], callid="reg-alice-4", cseq=1)
        check("4th contact → 503 (max_contacts)", r.startswith("SIP/2.0 503"), r[:60])

        # 9. Remove one binding with expires=0.
        r = register(alice2, "alice", ["<sip:alice@10.9.9.9:5061>;expires=0"], callid="reg-alice-2", cseq=2)
        check("expires=0 removes that binding only", len(contacts_of(r)) == 2
              and not any("5061" in c for c in contacts_of(r)), contacts_of(r))

        # 10. Contact: * rules.
        r = register(alice, "alice", ["*"], expires=60)
        check("Contact * without Expires: 0 → 400", r.startswith("SIP/2.0 400"), r[:60])
        r = register(alice, "alice", ["*"], expires=0)
        check("Contact * + Expires: 0 removes all", r.startswith("SIP/2.0 200") and contacts_of(r) == [], r)
        check("…then lookup fails", call(caller, "alice") == "SIP/2.0 404 Not Found")

        # 11. Expiry.
        drain(alice, alice2, caller)
        register(alice, "alice", ["<sip:alice@10.9.9.9:5060>"], expires=2, callid="reg-exp")
        caller.sendto(msg("MESSAGE", "sip:alice@127.0.0.1", "sip:alice@127.0.0.1", "mexp"), ("127.0.0.1", PX))
        answer(alice)
        r = caller.recv(65535).decode().split("\r\n")[0]
        check("short binding usable before it expires", r == "SIP/2.0 200 OK", r)
        time.sleep(2.3)
        check("expired binding → 404", call(caller, "alice") == "SIP/2.0 404 Not Found")
        drain(alice, alice2, caller)

        # 12. use_domain=0: the AoR is the user part, whatever the domain.
        register(alice, "erin", ["<sip:erin@10.9.9.9>"], expires=60)
        caller.sendto(msg("MESSAGE", "sip:erin@other.example", "sip:erin@other.example", "m3"), ("127.0.0.1", PX))
        got = answer(alice)
        caller.recv(65535)
        check("use_domain=0: To@example.com found via R-URI @other.example", got.startswith("MESSAGE sip:erin@10.9.9.9 "), got[:60])

        # 13. RFC 5626: same +sip.instance/reg-id from a new flow replaces the binding.
        inst = '+sip.instance="<urn:uuid:00000000-0000-1000-8000-AABBCCDDEEFF>";reg-id=1'
        register(alice, "frank", [f"<sip:frank@10.0.0.1;ob>;{inst}"], expires=60, callid="f1", cseq=1)
        r = register(alice2, "frank", [f"<sip:frank@10.0.0.2;ob>;{inst}"], expires=60, callid="f2", cseq=1)
        check("same instance+reg-id → binding replaced, echoed in 200",
              len(contacts_of(r)) == 1 and "10.0.0.2" in r and 'reg-id=1' in r, contacts_of(r))
        caller.sendto(msg("MESSAGE", "sip:frank@127.0.0.1", "sip:frank@127.0.0.1", "m4"), ("127.0.0.1", PX))
        got = answer(alice2)
        caller.recv(65535)
        check("…and requests use the newest flow", got.startswith("MESSAGE sip:frank@10.0.0.2;ob "), got[:60])

        # 14. TCP: requests to a TCP-registered UA reuse its connection.
        t = socket.create_connection(("127.0.0.1", PX))
        t.settimeout(2)
        t.sendall(msg("REGISTER", "sip:127.0.0.1", "sip:carol@example.com", "c1", 1,
                      ["<sip:carol@192.168.1.5:5060;transport=tcp>"], 60, via="TCP 192.168.1.5:5060"))
        r = t.recv(65535).decode()
        check("REGISTER over TCP → 200", r.startswith("SIP/2.0 200"), r[:40])
        caller.sendto(msg("MESSAGE", "sip:carol@127.0.0.1", "sip:carol@127.0.0.1", "m5"), ("127.0.0.1", PX))
        got = t.recv(65535)
        check("UDP caller → TCP UA over its registration connection", got.startswith(b"MESSAGE sip:carol@192.168.1.5:5060;transport=tcp ")
              and b"Via: SIP/2.0/TCP" in got, got[:80])
        t.sendall(ok_for(got))
        r = caller.recv(65535).decode().split("\r\n")[0]
        check("…reply back to the UDP caller", r == "SIP/2.0 200 OK", r)

        # 15. WebSocket (browser): register over WS, get called over WS.
        w = WsClient(WS)
        contact = "<sip:4ifh2kd9@df7jal23ls0d.invalid;transport=ws>"
        w.send(frame(1, msg("REGISTER", "sip:127.0.0.1", "sip:dave@example.com", "d1", 1, [contact], 300,
                            via="WS df7jal23ls0d.invalid")))
        f = w.recv_frame()
        check("REGISTER over WebSocket → 200", f and f[2].startswith(b"SIP/2.0 200"), f)
        caller.sendto(msg("MESSAGE", "sip:dave@127.0.0.1", "sip:dave@127.0.0.1", "m6"), ("127.0.0.1", PX))
        f = w.recv_data()
        check("UDP caller → browser over its WebSocket", f and f[2].startswith(b"MESSAGE sip:4ifh2kd9@df7jal23ls0d.invalid;transport=ws ")
              and b"Via: SIP/2.0/WS " in f[2], f[2][:80] if f else f)
        if f:
            w.send(frame(1, ok_for(f[2])))
        r = caller.recv(65535).decode().split("\r\n")[0]
        check("…browser's 200 back to the caller", r == "SIP/2.0 200 OK", r)

        # 16. handle_lost_tcp: when the WebSocket closes, the binding goes.
        w.s.close()
        time.sleep(0.4)
        check("lost WS connection → binding removed → 404", call(caller, "dave") == "SIP/2.0 404 Not Found")
        t.close()
        time.sleep(0.4)
        check("lost TCP connection → binding removed → 404", call(caller, "carol") == "SIP/2.0 404 Not Found")
    finally:
        proxy.terminate()
        err = proxy.communicate(timeout=5)[1]
        check("no panics in proxy log", "panic" not in err, err)
    extended()
    sys.exit(1 if failures else 0)


def extended():
    db = os.path.join(ROOT, "target/e2e_reg_db")
    shutil.rmtree(db, ignore_errors=True)
    os.makedirs(db)
    open(os.path.join(db, "location"), "w").write(
        "username(string) domain(string,null) contact(string) received(string) path(string,null) expires(int) q(double,null) "
        "callid(string) cseq(int) cflags(int) user_agent(string) instance(string,null) reg_id(int,null) last_modified(int)\n")
    cfg = os.path.join(ROOT, "target/e2e_reg2.cfg")
    open(cfg, "w").write(CFG2.replace("text://DB", "text://" + db))
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX2}", "-n", "2"],
                             stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    ua, ua2, caller = udp(5311), udp(5312), udp(5313)
    reg = lambda *a, **k: register(*a, px=PX2, **k)  # noqa: E731
    try:
        # save() flag 0x02: no reply from save(); the script's 200 carries
        # the bindings, and an error goes out through sl_reply_error().
        r = reg(ua, "quiet", ["<sip:quiet@10.1.1.1>"], expires=60)
        check("save 0x12: the script replies, with the bindings (0x10: reg_prepare_reply)", r.startswith("SIP/2.0 200 Saved Quietly")
              and contacts_of(r) == ["<sip:quiet@10.1.1.1>;expires=60"] and hdr(r, "X-Saved") == "yes", r)
        r = reg(ua, "quiet", ["<sip:quiet@10.1.1.1>"], expires=1)
        check("save 0x12: 423 + Min-Expires through sl_reply_error()", r.startswith("SIP/2.0 423") and "Min-Expires: 2" in r, r[:80])
        r = reg(ua, "varflags", ["<sip:v@10.1.1.1>"], expires=60)
        check("save flags from a variable ($var(f) = 18)", r.startswith("SIP/2.0 200 Var Flags") and len(contacts_of(r)) == 1, r[:80])

        r = reg(ua, "bare", ["<sip:bare@10.1.1.9>"], expires=60)
        check("save 0x02 alone: the script's reply lists no bindings", r.startswith("SIP/2.0 200 Bare") and contacts_of(r) == [], r)
        # Return codes (registrar save.c): 1 inserted, 2 updated, 3 deleted,
        # 4 query; reg_send_reply() sends the reply save() skipped.
        r = reg(ua, "rc", ["<sip:rc@10.1.1.5>"], expires=60, callid="rc1", cseq=1)
        check("save: 1 for a new AoR; reg_send_reply() sends its 200 with the bindings", r.startswith("SIP/2.0 200 OK")
              and hdr(r, "X-Rc") == "1" and contacts_of(r) == ["<sip:rc@10.1.1.5>;expires=60"], r)
        r = reg(ua, "rc", ["<sip:rc@10.1.1.5>"], expires=60, callid="rc1", cseq=2)
        check("save: 2 for a refresh", hdr(r, "X-Rc") == "2", r)
        r = reg(ua, "rc", ["<sip:rc@10.1.1.6>"], expires=60, callid="rc1", cseq=3)
        check("save: 1 for a binding added", hdr(r, "X-Rc") == "1" and len(contacts_of(r)) == 2, r)
        r = reg(ua, "rc", ["<sip:rc@10.1.1.6>"], expires=0, callid="rc1", cseq=4)
        check("save: 3 for a binding removed", hdr(r, "X-Rc") == "3" and len(contacts_of(r)) == 1, r)
        r = reg(ua, "rc", [], callid="rc1", cseq=5)
        check("save: 4 for a query", hdr(r, "X-Rc") == "4" and len(contacts_of(r)) == 1, r)
        r = reg(ua, "rc", ["<sip:rc@10.1.1.5>"], expires=60, callid="rc1", cseq=1)
        check("same Call-ID, lower CSeq → 400 Invalid CSeq number, -1", r.startswith("SIP/2.0 400 Invalid CSeq number") and hdr(r, "X-Rc") == "-1", r)
        r = reg(ua, "rc", ["<sip:rc@10.1.1.5>"], expires=30, callid="rc1", cseq=2)
        check("same Call-ID and CSeq within cseq_delay: a retransmission, the binding is left as it was",
              r.startswith("SIP/2.0 200") and contacts_of(r) in (["<sip:rc@10.1.1.5>;expires=60"], ["<sip:rc@10.1.1.5>;expires=59"]), r)
        r = reg(ua, "rc", ["*"], expires=0, callid="rc1", cseq=9)
        check("save: 3 for Contact: *", hdr(r, "X-Rc") == "3" and contacts_of(r) == [], r)

        # 0x04: one contact per AoR.
        reg(ua, "single", ["<sip:single@10.1.1.1>"], expires=60, callid="s1", cseq=1)
        r = reg(ua2, "single", ["<sip:single@10.1.1.2>"], expires=60, callid="s2", cseq=1)
        check("save 0x04: the new contact replaces the old one", contacts_of(r) == ["<sip:single@10.1.1.2>;expires=60"], contacts_of(r))

        # uri argument: saved under another AoR.
        r = reg(ua, "alias", ["<sip:alias@10.1.1.3>"], expires=60)
        check("save(…, uri): 200", r.startswith("SIP/2.0 200") and len(contacts_of(r)) == 1, r[:60])
        r = ask(caller, "target", "X-Op: fetch")
        check("…the contact is under the uri's AoR", hdr(r, "X-ULC") is not None and hdr(r, "X-ULC").startswith("1 target sip:alias@10.1.1.3"), r)
        check("…and not under the To AoR", ask(caller, "alias", "X-Op: fetch").startswith("SIP/2.0 404 No Contacts"))

        # 0x01: memory only, not written to the database (db_mode 1).
        reg(ua, "mem", ["<sip:mem@10.1.1.4>"], expires=60)
        rows = open(os.path.join(db, "location")).read()
        check("save 0x01: contact not written to the database", "sip\\:mem@" not in rows and "sip\\:alias@" in rows, rows)
        r = ask(caller, "mem", "X-Op: fetch")
        check("…but it is registered (flags 1 in $ulc)", (hdr(r, "X-Rcv") or "").endswith(" 1"), r)

        # reg_fetch_contacts + $ulc, indexes, reg_free_contacts.
        reg(ua, "multi", ["<sip:multi@10.2.0.1>;q=0.5"], expires=60, callid="m1", cseq=1, extra="User-Agent: phone-a\r\nAllow: INVITE, MESSAGE")
        reg(ua2, "multi", ["<sip:multi@10.2.0.2>;q=0.9"], expires=60, callid="m2", cseq=1)
        r = ask(caller, "multi", "X-Op: fetch")
        check("$ulc: count, aor, addr[0], addr[1], addr[-1] (a negative index is 0, as in Kamailio), q, callid, user_agent, methods, domain,"
              " past the end, conid ($null for UDP), regid",
              hdr(r, "X-ULC") == "2 multi sip:multi@10.2.0.2 sip:multi@10.2.0.1 sip:multi@10.2.0.2 900 m2  4294967295 location [] [] 0", hdr(r, "X-ULC"))
        check("$ulc: received, socket", (hdr(r, "X-Rcv") or "").startswith("sip:127.0.0.1:5312 udp:127.0.0.1:"), hdr(r, "X-Rcv"))
        ttl = hdr(r, "X-TTL")
        check("$ulc(expires) is a Unix time", ttl is not None and 57 <= int(ttl) <= 60, ttl)
        check("reg_free_contacts drops the profile", hdr(r, "X-Freed") == "[]", hdr(r, "X-Freed"))
        ruid = hdr(r, "X-Ruid")
        check("$ulc(ruid) set", ruid and ruid.startswith("uloc-"), ruid)
        r2 = reg(ua2, "multi", ["<sip:multi@10.2.0.2>;q=0.9"], expires=60, callid="m2", cseq=2)
        check("a refreshed binding keeps its ruid", hdr(ask(caller, "multi", "X-Op: fetch"), "X-Ruid") == ruid, r2[:40])

        # registered(uri, match_option 1 (Call-ID), match_action 1 (xavp_rcd)).
        r = ask(caller, "multi", "X-Op: registered\r\nX-Match: m1")
        check("registered(…, 1, 1): Call-ID match, $xavp(rcd=>contact) set", r.startswith("SIP/2.0 200 Match sip:multi@10.2.0.1"), r[:60])
        r = ask(caller, "multi", "X-Op: registered\r\nX-Match: nope")
        check("registered(…, 1, 1): no contact with that Call-ID", r.startswith("SIP/2.0 404 No Match"), r[:60])
        r = ask(caller, "multi", "X-Op: registered-rcv\r\nX-Match: sip:127.0.0.1:5312")
        check("registered(…, 2, 2): received match (bit 2), no xavp_rcd (action bit 2)", r.startswith("SIP/2.0 200 Match [") and "sip:multi" not in r.split("\r\n")[0], r[:60])
        r = ask(caller, "multi", "X-Op: registered-rcv\r\nX-Match: sip:127.0.0.1:9")
        check("registered(…, 2, 2): no contact from that address", r.startswith("SIP/2.0 404 No Match"), r[:60])

        # lookup(table, uri).
        drain(ua, ua2, caller)
        caller.sendto(msg("MESSAGE", "sip:nobody@127.0.0.1", "sip:nobody@127.0.0.1", "lu1", extra="X-Op: lookup-uri\r\nX-Target: sip:quiet@example.com"),
                      ("127.0.0.1", PX2))
        got = answer(ua)
        caller.recv(65535)
        check("lookup(table, uri): the uri's AoR, not the R-URI's", got.startswith("MESSAGE sip:quiet@10.1.1.1 "), got[:60])

        # lookup_branches: the R-URI and an appended branch both resolved.
        drain(ua, ua2, caller)
        caller.sendto(msg("MESSAGE", "sip:quiet@127.0.0.1", "sip:quiet@127.0.0.1", "lb1", extra="X-Op: branches\r\nX-Other: single"),
                      ("127.0.0.1", PX2))
        got_a, got_b = answer(ua), answer(ua2)
        check("lookup_branches: R-URI and branch both looked up", got_a.startswith("MESSAGE sip:quiet@10.1.1.1 ")
              and got_b.startswith("MESSAGE sip:single@10.1.1.2 "), (got_a[:50], got_b[:50]))
        drain(ua, ua2, caller)
        caller.sendto(msg("MESSAGE", "sip:nobody@127.0.0.1", "sip:nobody@127.0.0.1", "lb2", extra="X-Op: branches\r\nX-Other: nobody2"),
                      ("127.0.0.1", PX2))
        r = caller.recv(65535).decode()
        check("lookup_branches: nothing registered → false", r.startswith("SIP/2.0 404"), r[:40])

        # unregister: one binding by ruid, then the whole AoR.
        r = ask(caller, "multi", f"X-Op: unregister\r\nX-Ruid: {ruid}")
        r2 = ask(caller, "multi", "X-Op: fetch")
        check("unregister(…, ruid) removes only that binding", r.startswith("SIP/2.0 200 Unregistered One")
              and (hdr(r2, "X-ULC") or "").startswith("1 multi sip:multi@10.2.0.1"), (r[:40], hdr(r2, "X-ULC")))
        r = ask(caller, "multi", f"X-Op: unregister\r\nX-Ruid: {ruid}")
        check("unregister(…, unknown ruid) → -3", r.startswith("SIP/2.0 404 No Such Ruid -3"), r[:40])
        r = ask(caller, "multi", "X-Op: unregister")
        check("unregister(table, uri) removes the AoR (fetch: no contacts, count $null)", r.startswith("SIP/2.0 200 Unregistered")
              and ask(caller, "multi", "X-Op: fetch").startswith("SIP/2.0 404 No Contacts []"), r[:40])
    finally:
        proxy.terminate()
        err = proxy.communicate(timeout=5)[1]
        check("no panics in proxy log (second proxy)", "panic" not in err, err)


if __name__ == "__main__":
    main()
