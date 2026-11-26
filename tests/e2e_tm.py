#!/usr/bin/env python3
"""End-to-end checks for tm reliability on UDP (Phase 14):
- our CANCEL is retransmitted (T1 doubling, capped at T2) until it is
  answered, and the 200 to it is not forwarded;
- a CANCEL that is never answered ends the branch after 64·T1, and the
  caller gets 487;
- the hop-by-hop ACK is resent byte-identical for retransmitted finals;
- `t_next_contact_flow()` (RFC 5626) tries another flow of the same
  `+sip.instance` after a 430 Flow Failed;
- `retr_timer1` / `retr_timer2`;
- `t_forward_nonack*()`, `t_lookup_request()`, `t_save_lumps()`,
  `event_route[tm:local-request]` / `[tm:local-response]` and the
  `t_load_contacts()` modes;
- `failure_reply_mode` 0..3 and `t_drop_replies()`: which earlier replies
  still compete once a failure route forked again (Kamailio t_reply.c
  t_should_relay_response());
- `max_branches` caps the whole transaction, failure rounds included:
  then `t_relay` fails with 500 Forking capacity exceeded (12/TM);
- the core `max_branches=4`: the destination set holds 3 (Kamailio core
  dset.c), so `append_branch()` fails past it and `lookup()` drops the
  contacts that don't fit;
- a winning 503 is answered with Kamailio's local 500 Service Unavailable
  (t_reply.c relay_reply()), not the 503 with a new status line;
- relay errors carry Kamailio's reason (core error.c err2reason_phrase()):
  every next hop blocklisted → 477 ... (477/TM), in a request route and in
  a failure route;
- one final per request: in a failure route send_reply(), t_reply() and
  t_reply_error() (and send_reply_error()) answer through the transaction,
  and the best reply is not relayed after them (Kamailio sl.c send_reply()
  → tm t_reply); sl_send_reply() / sl_reply_error() from a route[] the
  failure route calls are stateless, and the best reply follows them;
- a t_relay() that fails in the request route is answered by tm when the
  script ends (Kamailio's delayed_reply): sl_reply_error() /
  send_reply_error() send nothing, t_reply() / send_reply() /
  t_reply_error() replace tm's reply, sl_send_reply() doesn't.

Run from the repo root after `cargo build --release`.
"""
import os, re, socket, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_routing import make_reply, first, hdr  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOCK = os.path.join(ROOT, "target/e2e_tm.sock")


def stat(name):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, "stats.get_statistics", name], capture_output=True, text=True, timeout=5).stdout
    m = re.search(r'": (-?\d+)', out)
    return int(m.group(1)) if m else -1
PROXY, CALLER, UAS, F1, F2 = 7600, 7699, 7601, 7611, 7612
T1, T2 = 100, 400

CFG = f"""
loadmodule "tm"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "cfgutils"
loadmodule "sl"
loadmodule "pv"
loadmodule "textops"
modparam("tm", "retr_timer1", {T1})
modparam("tm", "retr_timer2", {T2})
modparam("tm", "fr_inv_timer", 30000)
request_route {{
    if method == "REGISTER" {{ save("location"); exit; }}
    if ruri_user_prefix("getshv") {{ sl_send_reply(200, "ack=$shv(ackrefused) lk=$shv(lk) lr=$shv(lr) lrs=$shv(lrs)"); exit; }}
    # t_forward_nonack() refuses an ACK.
    if method == "ACK" && ruri_user_prefix("fwd") {{
        if !t_forward_nonack("127.0.0.1", {UAS}) {{ $shv(ackrefused) = 1; }}
        exit;
    }}
    if method == "CANCEL" || method == "ACK" {{ t_relay(); exit; }}
    if ruri_user_prefix("fwdudp") {{ t_newtran(); t_forward_nonack_udp("127.0.0.1", {UAS}); exit; }}
    # t_forward_nonack() needs the transaction (t_newtran()), as in Kamailio.
    if ruri_user_prefix("fwdnotx") {{ $du = "sip:127.0.0.1:{UAS}"; if !t_forward_nonack() {{ sl_send_reply(500, "fwd failed"); }} exit; }}
    if ruri_user_prefix("fwd") {{ t_newtran(); $du = "sip:127.0.0.1:{UAS}"; if !t_forward_nonack() {{ t_reply(500, "fwd failed"); }} exit; }}
    # t_lookup_request(): a retransmission is recognised, nothing is resent.
    if ruri_user_prefix("lookup") {{
        if t_lookup_request() {{ $shv(lk) = $shv(lk) + 1; exit; }}
        t_relay("udp:127.0.0.1:{UAS}");
        exit;
    }}
    # Without t_save_lumps(), the edits up to the first relay reach the
    # failure_route's branches (tm saves them there).
    if ruri_user_prefix("nolumps") {{
        append_hdr("X-Early: 1\r\n");
        t_newtran();
        append_hdr("X-Before-Relay: 1\r\n");
        t_on_failure("AGAIN");
        t_relay("udp:127.0.0.1:{UAS}");
        exit;
    }}
    # Edits before t_save_lumps() reach the failure_route's branches; later
    # ones don't.
    if ruri_user_prefix("lumps") {{
        append_hdr("X-Early: 1\r\n");
        t_newtran();
        append_hdr("X-Saved: 1\r\n");
        t_save_lumps();
        append_hdr("X-Late: 1\r\n");
        t_on_failure("AGAIN");
        t_relay("udp:127.0.0.1:{UAS}");
        exit;
    }}
    if ruri_user_prefix("uac") {{
        t_uac_send("OPTIONS", "sip:probe@127.0.0.1:{UAS}", "", "", "X-Orig: $rU\r\n", "");
        sl_send_reply(200, "sent");
        exit;
    }}
    if ruri_user_prefix("lresp") {{ t_newtran(); t_reply(404, "Nobody"); exit; }}
    if ruri_user_prefix("prop") || ruri_user_prefix("std") {{
        $var(mode) = 0;
        if ruri_user_prefix("prop") {{ $var(mode) = 1; }}
        $rU = "qq";
        if !lookup("location") {{ sl_send_reply(404, "Not Found"); exit; }}
        if $var(mode) == 1 {{ t_load_contacts(1); }} else {{ t_load_contacts(0); }}
        t_next_contacts();
        t_on_failure("NEXT");
        t_relay();
        exit;
    }}
    # t_newtran(): the transaction exists before slow work (here a blocking
    # pause); retransmissions meanwhile are absorbed, not routed again.
    if ruri_user_prefix("ntrelay") {{
        t_newtran();
        usleep(700000);
        t_relay("udp:127.0.0.1:{UAS}");
        exit;
    }}
    if ruri_user_prefix("ntreply") {{
        t_newtran();
        $shv(nt) = $shv(nt) + 1;
        usleep(500000);
        sl_send_reply(486, "Busy $shv(nt)");
        exit;
    }}
    if ruri_user_prefix("flow") {{
        if !lookup("location") {{ reply(404, "Not Found"); exit; }}
        t_load_contacts();
        t_next_contacts();
        t_on_failure("FLOW");
        t_relay();
        exit;
    }}
    t_relay("udp:127.0.0.1:{UAS}");
}}
failure_route[AGAIN] {{
    t_relay("udp:127.0.0.1:{F1}");
}}
failure_route[NEXT] {{
    if t_next_contacts() {{ t_on_failure("NEXT"); t_relay(); }}
}}
event_route[tm:local-request] {{
    if $hdr(X-Orig) == "uacdrop" {{ drop; }}
    append_hdr("X-Local: $rm\r\n");
}}
event_route[tm:local-response] {{
    $shv(lr) = $T_reply_code;
    $shv(lrs) = $rs;
}}
failure_route[FLOW] {{
    if t_next_contact_flow() {{ t_on_failure("FLOW"); t_relay(); }}
}}
"""

# failure_reply_mode: one proxy per mode. MODES forks twice: round 1 adds
# F1 and F2 (two relays: two steps), round 2 the UAS again; round 3 adds
# nothing and records the reply it sees. max_branches 4: CAP loops to F1
# until no branch is left.
PROXY2, DEAD = 7620, 7613
MODES_CFG = """
loadmodule "tm"
loadmodule "sl"
loadmodule "pv"
loadmodule "blst"
loadmodule "kex"
loadmodule "usrloc"
loadmodule "registrar"
modparam("tm", "failure_reply_mode", {mode})
max_branches=4
request_route {{
    if ($rm == "REGISTER") {{ save("location"); exit; }}
    if (ruri_user_prefix("getshv")) {{ sl_send_reply(200, "code=$shv(code)"); exit; }}
    if (ruri_user_prefix("getdset")) {{ sl_send_reply(200, "dset=$shv(dset)"); exit; }}
    # The destination set holds max_branches - 1 = 3 (core dset.c): the
    # 4th append_branch() fails; lookup() keeps 3 of its 4 extra contacts.
    if (ruri_user_prefix("dset")) {{
        $shv(dset) = "";
        append_branch("sip:d1@127.0.0.1:{uas}");
        append_branch("sip:d2@127.0.0.1:{uas}");
        if (append_branch("sip:d3@127.0.0.1:{uas}")) {{ $shv(dset) = $shv(dset) + "3ok"; }}
        if (!append_branch("sip:d4@127.0.0.1:{uas}")) {{ $shv(dset) = $shv(dset) + ",4full"; }}
        t_relay("udp:127.0.0.1:{uas}");
        exit;
    }}
    if (ruri_user_prefix("many")) {{
        if (!lookup("location")) {{ sl_send_reply(404, "Not Found"); exit; }}
        if (!append_branch("sip:extra@127.0.0.1:{uas}")) {{ $shv(dset) = $shv(dset) + ",lookupfull"; }}
        t_relay();
        exit;
    }}
    if (ruri_user_prefix("cap")) {{ t_on_failure("CAP"); t_relay("udp:127.0.0.1:{uas}"); exit; }}
    # A blocklisted next hop: nothing is sent, E_SEND.
    if (ruri_user_prefix("blk")) {{
        $du = "sip:127.0.0.1:{dead}";
        blst_add(30);
        if (ruri_user_prefix("blkfr")) {{ resetdsturi(); t_on_failure("BLK"); t_relay("udp:127.0.0.1:{uas}"); exit; }}
        if (!t_relay()) {{ sl_reply_error(); }}
        exit;
    }}
    # A relay that fails in the request route: tm answers it when the
    # script ends, unless the script answered through tm (Kamailio
    # t_funcs.c:340-378, delayed_reply).
    if (ruri_user_prefix("rq")) {{
        $du = "sip:127.0.0.1:{dead}";
        blst_add(30);
        if (ruri_user_prefix("rqbare")) {{ t_relay(); exit; }}
        if (ruri_user_prefix("rqsre")) {{ if (!t_relay()) {{ send_reply_error(); }} exit; }}
        if (ruri_user_prefix("rqterr")) {{ if (!t_relay()) {{ t_reply_error(); }} exit; }}
        if (ruri_user_prefix("rqsend")) {{ if (!t_relay()) {{ send_reply("503", "Mine"); }} exit; }}
        if (ruri_user_prefix("rqtrep")) {{ if (!t_relay()) {{ t_reply("503", "Mine"); }} exit; }}
        if (ruri_user_prefix("rqsl")) {{ if (!t_relay()) {{ sl_send_reply("503", "Mine"); }} exit; }}
        exit;
    }}
    # A reply from a failure route (the UAS answers 486).
    if (ruri_user_prefix("fr")) {{
        if (ruri_user_prefix("frsend")) {{ t_on_failure("FR_SEND"); }}
        if (ruri_user_prefix("frtrep")) {{ t_on_failure("FR_TREPLY"); }}
        if (ruri_user_prefix("frterr")) {{ t_on_failure("FR_TRE"); }}
        if (ruri_user_prefix("frsl")) {{ t_on_failure("FR_SL"); }}
        if (ruri_user_prefix("frslerr")) {{ t_on_failure("FR_SLERR"); }}
        t_relay("udp:127.0.0.1:{uas}");
        exit;
    }}
    if (ruri_user_prefix("dropall")) {{ t_on_failure("DROP"); t_relay("udp:127.0.0.1:{uas}"); exit; }}
    if (ruri_user_prefix("fan")) {{
        append_branch("sip:fan1@127.0.0.1:{uas}");
        append_branch("sip:fan2@127.0.0.1:{uas}");
        append_branch("sip:fan3@127.0.0.1:{uas}");
        append_branch("sip:fan4@127.0.0.1:{uas}");
        t_relay("udp:127.0.0.1:{uas}");
        exit;
    }}
    t_on_failure("MODES");
    t_relay("udp:127.0.0.1:{uas}");
}}
failure_route[MODES] {{
    if ($avp(r) == $null) {{
        $avp(r) = 1;
        t_on_failure("MODES");
        $ru = "sip:modes@127.0.0.1:{f1}";
        t_relay();
        $ru = "sip:modes@127.0.0.1:{f2}";
        t_relay();
        exit;
    }}
    if ($avp(r) == 1) {{
        $avp(r) = 2;
        t_on_failure("MODES");
        $ru = "sip:modes@127.0.0.1:{uas}";
        t_relay();
        exit;
    }}
    $shv(code) = $T_reply_code;
}}
failure_route[CAP] {{
    t_on_failure("CAP");
    $ru = "sip:cap@127.0.0.1:{f1}";
    if (!t_relay()) {{ send_reply_error(); }}
}}
failure_route[BLK] {{
    $du = "sip:127.0.0.1:{dead}";
    if (!t_relay()) {{ send_reply_error(); }}
}}
failure_route[DROP] {{
    t_drop_replies();
}}
failure_route[FR_SEND] {{
    send_reply("503", "From failure route");
}}
failure_route[FR_TREPLY] {{
    t_reply("503", "From failure route");
}}
failure_route[FR_TRE] {{
    $du = "sip:127.0.0.1:{dead}";
    if (!t_relay()) {{ t_reply_error(); }}
}}
# sl_send_reply / sl_reply_error are request_route functions in Kamailio:
# not allowed in a failure_route block, they run from a route[] it calls,
# statelessly, and tm still relays the best reply.
failure_route[FR_SL] {{
    route(SL);
}}
failure_route[FR_SLERR] {{
    route(SLERR);
}}
route[SL] {{
    sl_send_reply("503", "Stateless");
}}
route[SLERR] {{
    $du = "sip:127.0.0.1:{dead}";
    if (!t_relay()) {{ sl_reply_error(); }}
}}
"""

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


class Sock:
    def __init__(self, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.port = port

    def recv(self, timeout):
        self.s.settimeout(max(0.01, timeout))
        try:
            d, a = self.s.recvfrom(65535)
            return d, a, time.time()
        except socket.timeout:
            return None, None, None

    def collect(self, timeout, until=None):
        out, end = [], time.time() + timeout
        while time.time() < end:
            d, a, t = self.recv(end - time.time())
            if d is None:
                break
            out.append((d, a, t))
            if until and until(out):
                break
        return out

    def first(self, prefix, timeout=2):
        for d, a, t in self.collect(timeout, until=lambda l: l[-1][0].startswith(prefix)):
            if d.startswith(prefix):
                return d, a, t
        return None, None, None


def invite(user, callid):
    seq[0] += 1
    br = f"z9hG4bKt{seq[0]}x{time.time_ns()}"
    head = (f"Via: SIP/2.0/UDP 127.0.0.1:{CALLER};branch={br}\r\nMax-Forwards: 70\r\nFrom: <sip:c@x>;tag=c{seq[0]}\r\n"
            f"To: <sip:{user}@x>\r\nCall-ID: {callid}\r\n")
    inv = f"INVITE sip:{user}@127.0.0.1:{PROXY} SIP/2.0\r\n{head}CSeq: 1 INVITE\r\nContact: <sip:c@127.0.0.1:{CALLER}>\r\nContent-Length: 0\r\n\r\n"
    can = f"CANCEL sip:{user}@127.0.0.1:{PROXY} SIP/2.0\r\n{head}CSeq: 1 CANCEL\r\nContent-Length: 0\r\n\r\n"
    return inv.encode(), can.encode()


def failure_modes(caller, uas, f1, f2):
    """failure_reply_mode 0..3 (and t_drop_replies, the branch cap)."""
    def req(user):
        seq[0] += 1
        return (f"MESSAGE sip:{user}@127.0.0.1:{PROXY2} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch=z9hG4bKfm{seq[0]}x{time.time_ns()}\r\n"
                f"Max-Forwards: 70\r\nFrom: <sip:c@x>;tag=fm{seq[0]}\r\nTo: <sip:{user}@x>\r\nCall-ID: fm{seq[0]}-{time.time_ns()}\r\n"
                f"CSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n").encode()

    def answer(sock, code, reason, extra=""):
        d, a, _ = sock.first(b"MESSAGE", 2)
        if d:
            sock.s.sendto(make_reply(d, code, reason, extra), a)
        return d

    last = [b""]

    def final():
        for d, _, _ in caller.collect(2, until=lambda l: not l[-1][0].startswith(b"SIP/2.0 1")):
            if not d.startswith(b"SIP/2.0 1"):
                last[0] = d
                return first(d)
        return None

    def finals(wait=0.6):
        """Every final the caller gets: the first, then whatever else
        comes within `wait` (a request has one final)."""
        f = final()
        if f is None:
            return []
        return [f] + [first(d) for d, _, _ in caller.collect(wait) if not d.startswith(b"SIP/2.0 1")]

    # (code the third round sees, the caller's final): 0 keeps every reply;
    # 1 drops all of them each round, so the last round (no new branch)
    # fails; 2 drops only the last relay's (F2's, not F1's 486), and fails
    # too; 3 drops all only when the round forked again.
    sorry = "SIP/2.0 500 I'm terribly sorry, server error occurred (1/TM)"
    want = {0: ("404", "SIP/2.0 404 Not Found"), 1: ("503", sorry), 2: ("486", sorry), 3: ("503", "SIP/2.0 500 Service Unavailable")}
    cfg = os.path.join(ROOT, "target/e2e_tm_modes.cfg")
    for mode, (seen, final_want) in want.items():
        open(cfg, "w").write(MODES_CFG.format(mode=mode, uas=UAS, f1=F1, f2=F2, dead=DEAD))
        p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY2}", "-n", "2"], stderr=subprocess.PIPE, text=True)
        err = []
        threading.Thread(target=lambda err=err, p=p: err.extend(p.stderr), daemon=True).start()
        try:
            end = time.time() + 5
            while time.time() < end and not any("listening on" in l for l in err):
                time.sleep(0.05)
            for sk in (uas, f1, f2, caller):
                sk.collect(0.1)
            send = lambda m: caller.s.sendto(m, ("127.0.0.1", PROXY2))
            send(req("modes"))
            answer(uas, 404, "Not Found")
            answer(f1, 486, "Busy Here")
            answer(f2, 500, "Server Error")
            answer(uas, 503, "Service Unavailable", "Retry-After: 30\r\nX-Upstream: 503\r\n")
            got = final()
            send(req("getshv"))
            d, _, _ = caller.first(b"SIP/2.0 200", 2)
            code = (first(d) or "").rsplit("code=", 1)[-1] if d else None
            check(f"failure_reply_mode {mode}: the last failure round sees {seen}, the caller gets {final_want[8:]}",
                  code == seen and got == final_want, (code, got))
            if mode == 3:
                # Kamailio t_reply.c relay_reply() (remap_503_500): a new
                # 500 built from the request, reason "Service Unavailable";
                # nothing of the 503 is copied, the To-tag is ours.
                d = last[0].decode(errors="replace")
                check("a winning 503 → Kamailio's local 500 Service Unavailable (no Retry-After or other 503 header, our To-tag)",
                      got == "SIP/2.0 500 Service Unavailable" and "Retry-After" not in d and "X-Upstream" not in d and "tag=uas" not in hdr(last[0], "To"),
                      d)
            if mode == 0:
                send(req("dropall"))
                answer(uas, 404, "Not Found")
                got = final()
                check("t_drop_replies() and no new branch → 500 (E_UNSPEC)", got == sorry, got)
            if mode == 3:
                send(req("cap"))
                answer(uas, 486, "Busy Here")
                n = 0
                while answer(f1, 486, "Busy Here") is not None:
                    n += 1
                got = finals()
                check("max_branches 4: the failure rounds stop at 4 branches in all (3 to F1), then 500 Forking capacity exceeded",
                      n == 3 and got[:1] == ["SIP/2.0 500 Forking capacity exceeded (12/TM)"], (n, got))
                check("…send_reply_error() answered through tm: the only final (the best 486 is not relayed after it)",
                      got == ["SIP/2.0 500 Forking capacity exceeded (12/TM)"], got)
                send(req("fan"))
                fan = list({hdr(d, "Via"): d for d, _, _ in uas.collect(1.0) if d.startswith(b"MESSAGE")}.values())
                check("max_branches 4: a relay to 5 targets sends 4 branches", len(fan) == 4, [first(d) for d in fan])
                for d in fan:
                    uas.s.sendto(make_reply(d, 486, "Busy Here", ""), ("127.0.0.1", PROXY2))
                got = finals()
                check("…one final for the 4 branches", got == ["SIP/2.0 486 Busy Here"], got)
                # max_branches = 4 as the core parameter: the destination
                # set takes 3 (Kamailio core dset.c append_branch()).
                send(req("dset"))
                legs = list({hdr(d, "Via"): d for d, _, _ in uas.collect(1.0) if d.startswith(b"MESSAGE")}.values())
                for d in legs:
                    uas.s.sendto(make_reply(d, 486, "Busy Here", ""), ("127.0.0.1", PROXY2))
                final()
                # lookup(): R-URI + 4 contacts → 3 of them in the destination set.
                seq[0] += 1
                contacts = ", ".join(f"<sip:m{i}@127.0.0.1:{UAS}>;q=0.{9 - i}" for i in range(5))
                # From the UAS's socket: the contacts are reached there.
                uas.s.sendto((f"REGISTER sip:127.0.0.1:{PROXY2} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UAS};branch=z9hG4bKrg{seq[0]}x{time.time_ns()}\r\n"
                      f"Max-Forwards: 70\r\nFrom: <sip:many@127.0.0.1>;tag=rg{seq[0]}\r\nTo: <sip:many@127.0.0.1>\r\nCall-ID: rg{seq[0]}\r\n"
                      f"CSeq: 1 REGISTER\r\nContact: {contacts}\r\nExpires: 60\r\nContent-Length: 0\r\n\r\n").encode(), ("127.0.0.1", PROXY2))
                d, _, _ = uas.first(b"SIP/2.0 200", 2)
                reg = first(d) if d else None
                send(req("many"))
                lk = list({hdr(d, "Via"): d for d, _, _ in uas.collect(1.0) if d.startswith(b"MESSAGE")}.values())
                for d in lk:
                    uas.s.sendto(make_reply(d, 486, "Busy Here", ""), ("127.0.0.1", PROXY2))
                final()
                send(req("getdset"))
                d, _, _ = caller.first(b"SIP/2.0 200", 2)
                dset = (first(d) or "").rsplit("dset=", 1)[-1] if d else None
                check("core max_branches=4: append_branch() fails past 3 entries (the R-URI is branch 0); 4 branches sent",
                      dset is not None and dset.startswith("3ok,4full") and len(legs) == 4, (dset, [first(d) for d in legs]))
                check("…lookup() keeps 3 of the 4 extra contacts: the destination set is full after it, 4 branches sent",
                      reg == "SIP/2.0 200 OK" and dset == "3ok,4full,lookupfull" and sorted(first(d).split()[1] for d in lk) == [f"sip:m{i}@127.0.0.1:{UAS}" for i in range(4)],
                      (reg, dset, [first(d) for d in lk]))
                caller.collect(0.5)
                e_send = "SIP/2.0 477 Unfortunately error on sending to next hop occurred (477/TM)"
                send(req("blk"))
                got = finals()
                check("the only next hop blocklisted → 477 (477/TM) (E_SEND, err2reason_phrase)", got == [e_send], got)
                send(req("blkfr"))
                answer(uas, 486, "Busy Here")
                got = finals()
                check("…and from a failure route's t_relay + send_reply_error (its only final)", got == [e_send], got)
                # Request route, t_relay fails (Kamailio t_funcs.c:340-378,
                # t_lookup.c:2101-2110): tm's 477 when the script ends;
                # sl_reply_error / send_reply_error send nothing meanwhile
                # (FL_DELAYED_REPLY), t_reply / send_reply / t_reply_error
                # replace it, sl_send_reply doesn't (stateless: two finals).
                for user, want, what in (
                    ("rqbare", [e_send], "no reply in the script → tm's 477 when the script ends"),
                    ("rqsre", [e_send], "+ send_reply_error() → only tm's 477"),
                    ("rqterr", [e_send], "+ t_reply_error() → its 477, the only final"),
                    ("rqsend", ["SIP/2.0 503 Mine"], "+ send_reply(503) → only that (it answers through tm)"),
                    ("rqtrep", ["SIP/2.0 503 Mine"], "+ t_reply(503) → only that"),
                    ("rqsl", ["SIP/2.0 503 Mine", e_send], "+ sl_send_reply(503) → that, statelessly, then tm's 477"),
                ):
                    send(req(user))
                    got = finals()
                    check(f"request route, t_relay fails: {what}", got == want, got)
                # An INVITE gets its 100 Trying before the error (t_funcs.c:330-335).
                seq[0] += 1
                send((f"INVITE sip:rqbare@127.0.0.1:{PROXY2} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch=z9hG4bKfi{seq[0]}x{time.time_ns()}\r\n"
                      f"Max-Forwards: 70\r\nFrom: <sip:c@x>;tag=fi{seq[0]}\r\nTo: <sip:rqbare@x>\r\nCall-ID: fi{seq[0]}-{time.time_ns()}\r\n"
                      f"CSeq: 1 INVITE\r\nContact: <sip:c@127.0.0.1:{CALLER}>\r\nContent-Length: 0\r\n\r\n").encode())
                got = [first(d) for d, _, _ in caller.collect(1.0)]
                check("…an INVITE: 100 Trying, then the 477", got == ["SIP/2.0 100 Trying", e_send], got)
                # Failure route (the UAS answers 486): send_reply / t_reply /
                # t_reply_error answer through tm, the only final (Kamailio
                # sl.c:296-303 → tm.c:1594); sl_send_reply / sl_reply_error
                # from a route[] it calls are stateless, then tm relays the 486.
                for user, want, what in (
                    ("frsend", ["SIP/2.0 503 From failure route"], "send_reply(503): the only final"),
                    ("frtrep", ["SIP/2.0 503 From failure route"], "t_reply(503): the only final"),
                    ("frterr", [e_send], "t_relay fails, t_reply_error(): the only final"),
                    ("frslerr", ["SIP/2.0 477 Unfortunately error on sending to next hop occurred (477/SL)", "SIP/2.0 486 Busy Here"],
                     "a route[] with t_relay failing + sl_reply_error(): its stateless 477 (477/SL, sl_funcs.c:437), then the 486"),
                    ("frsl", ["SIP/2.0 503 Stateless", "SIP/2.0 486 Busy Here"], "a route[] with sl_send_reply(503): its stateless 503, then the 486"),
                ):
                    send(req(user))
                    answer(uas, 486, "Busy Here")
                    got = finals()
                    check(f"failure route: {what}", got == want, got)
        finally:
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
            log = "".join(err)
            check(f"failure_reply_mode {mode}: no panics in proxy log", "panicked" not in log, log[-2000:])


def main():
    caller, uas, f1, f2 = Sock(CALLER), Sock(UAS), Sock(F1), Sock(F2)
    failure_modes(caller, uas, f1, f2)
    cfg = os.path.join(ROOT, "target/e2e_tm.cfg")
    open(cfg, "w").write(CFG)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY}", "-n", "2", "--rpc-socket", SOCK],
                         stderr=subprocess.PIPE, text=True)
    err = []
    threading.Thread(target=lambda: err.extend(p.stderr), daemon=True).start()
    try:
        end = time.time() + 5
        while time.time() < end and not any("listening on" in l for l in err):
            time.sleep(0.05)
        send = lambda m: caller.s.sendto(m, ("127.0.0.1", PROXY))

        # 0. t_newtran(): retransmissions during slow routing are absorbed.
        inv, _ = invite("ntrelay", f"nt1-{time.time_ns()}")
        send(inv)
        time.sleep(0.3)
        send(inv)
        invs = [d for d, _, _ in uas.collect(2.0) if d.startswith(b"INVITE")]
        got = caller.collect(0.3)
        # One branch (our own UDP retransmissions of it repeat its Via).
        branches = {hdr(d, "Via") for d in invs}
        check("t_newtran: an INVITE retransmitted while the route is busy is relayed once (one branch)",
              len(branches) == 1, branches)
        check("…and the caller got 100 Trying (from the transaction t_newtran made)",
              any(d.startswith(b"SIP/2.0 100") for d, _, _ in got), [first(d) for d, _, _ in got])
        if invs:
            uas.s.sendto(make_reply(invs[0], 486, "Busy Here", ""), ("127.0.0.1", PROXY))
            caller.collect(0.5)
        inv, _ = invite("ntreply", f"nt2-{time.time_ns()}")
        send(inv)
        time.sleep(0.2)
        send(inv)
        finals = [first(d) for d, _, _ in caller.collect(2.0) if d.startswith(b"SIP/2.0 486")]
        check("t_newtran + sl_send_reply: the retransmission gets the same reply again, the route ran once",
              finals and all(f == "SIP/2.0 486 Busy 1" for f in finals), finals)

        # 1. CANCEL retransmitted until answered.
        inv, can = invite("a", f"tm1-{time.time_ns()}")
        send(inv)
        d, a, _ = uas.first(b"INVITE")
        uas.s.sendto(make_reply(d, 180, "Ringing", "", ) if d else b"", a) if d else None
        caller.collect(0.2)
        send(can)
        cans = []
        while len(cans) < 3:
            m, a2, t = uas.recv(2)
            if m is None:
                break
            if m.startswith(b"CANCEL"):
                cans.append((m, t))
        gaps = [round((cans[i + 1][1] - cans[i][1]) * 1000) for i in range(len(cans) - 1)]
        check("our CANCEL is retransmitted with T1 doubling", len(cans) == 3 and cans[0][0] == cans[1][0] and 70 <= gaps[0] <= 200 and 150 <= gaps[1] <= 320,
              (len(cans), gaps))
        if cans:
            uas.s.sendto(make_reply(cans[-1][0], 200, "OK", ""), a2)
            uas.s.sendto(make_reply(d, 487, "Request Terminated", ""), a2)
        after = uas.collect(0.8)
        check("…stops once answered; the 487 is ACKed", not any(m.startswith(b"CANCEL") for m, _, _ in after) and any(m.startswith(b"ACK") for m, _, _ in after),
              [first(m) for m, _, _ in after])
        rs = caller.collect(0.5)
        finals = [first(m) for m, _, _ in rs if m.startswith(b"SIP/2.0") and not m.startswith(b"SIP/2.0 1")]
        check("…the caller gets 200 (its CANCEL) and 487, not the callee's 200-to-CANCEL",
              sorted(finals) == ["SIP/2.0 200 OK", "SIP/2.0 487 Request Terminated"] and not any(b"CSeq: 1 CANCEL" in m and hdr(m, "To").endswith("tag=uas") for m, _, _ in rs),
              finals)
        acks = [m for m, _, _ in after if m.startswith(b"ACK")]
        uas.s.sendto(make_reply(d, 487, "Request Terminated", ""), a2)
        again = [m for m, _, _ in uas.collect(0.5) if m.startswith(b"ACK")]
        check("retransmitted final → the same ACK again", acks and again and again[0] == acks[0], (acks, again))

        # 2. CANCEL never answered → 64·T1, then 487 to the caller.
        inv, can = invite("b", f"tm2-{time.time_ns()}")
        send(inv)
        d, a, _ = uas.first(b"INVITE")
        if d:
            uas.s.sendto(make_reply(d, 180, "Ringing", ""), a)
        caller.collect(0.2)
        t0 = time.time()
        send(can)
        msgs = uas.collect(64 * T1 / 1000 + 1.5, until=lambda l: False)
        cans = [t for m, _, t in msgs if m.startswith(b"CANCEL")]
        gaps = [cans[i + 1] - cans[i] for i in range(len(cans) - 1)]
        rs = [m for m, _, _ in caller.collect(1.0)]
        r487 = [m for m in rs if m.startswith(b"SIP/2.0 487")]
        check("unanswered CANCEL: retransmissions capped at T2, then give up", len(cans) >= 10 and max(gaps) < (T2 + 150) / 1000 and cans[-1] - t0 < 64 * T1 / 1000 + 0.3,
              (len(cans), gaps and max(gaps)))
        check("…the caller gets 487 after 64·T1", len(r487) == 1, [first(m) for m in rs])

        # 3. RFC 5626 flows: same instance, reg-id 1 and 2 on two sockets.
        inst = '+sip.instance="<urn:uuid:00000000-0000-1000-8000-000000000001>"'
        for sock, port, rid in ((f1, F1, 1), (f2, F2, 2)):
            seq[0] += 1
            reg = (f"REGISTER sip:127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKf{seq[0]}\r\nMax-Forwards: 70\r\n"
                   f"From: <sip:flowuser@127.0.0.1>;tag=f{rid}\r\nTo: <sip:flowuser@127.0.0.1>\r\nCall-ID: flow-{rid}\r\nCSeq: 1 REGISTER\r\n"
                   f"Supported: outbound\r\nContact: <sip:flowuser@127.0.0.1:{port};ob>;{inst};reg-id={rid}\r\nExpires: 600\r\nContent-Length: 0\r\n\r\n")
            sock.s.sendto(reg.encode(), ("127.0.0.1", PROXY))
            sock.first(b"SIP/2.0 200")
        seq[0] += 1
        m = (f"MESSAGE sip:flowuser@127.0.0.1:{PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch=z9hG4bKm{seq[0]}\r\nMax-Forwards: 70\r\n"
             f"From: <sip:c@x>;tag=m{seq[0]}\r\nTo: <sip:flowuser@x>\r\nCall-ID: flowmsg-{time.time_ns()}\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n")
        send(m.encode())
        got = {}

        def grab(sock, name):
            d, a, _ = sock.first(b"MESSAGE", 2)
            if d:
                got[name] = (d, a)
        th = [threading.Thread(target=grab, args=(s, n)) for s, n in ((f1, "f1"), (f2, "f2"))]
        for t in th:
            t.start()
        time.sleep(0.4)
        firsts = dict(got)
        check("t_load_contacts: only one flow of the instance is tried first", len(firsts) == 1, list(firsts))
        if firsts:
            name, (d, a) = next(iter(firsts.items()))
            (f1 if name == "f1" else f2).s.sendto(make_reply(d, 430, "Flow Failed", ""), a)
        for t in th:
            t.join(3)
        check("…430 Flow Failed → t_next_contact_flow() tries the other flow", len(got) == 2, list(got))
        other = [n for n in got if n not in firsts]
        if other:
            d, a = got[other[0]]
            (f1 if other[0] == "f1" else f2).s.sendto(make_reply(d, 200, "OK", ""), a)
        r = [x for x, _, _ in caller.collect(1.5, until=lambda l: l[-1][0].startswith(b"SIP/2.0 2"))]
        check("…and its 200 reaches the caller", any(x.startswith(b"SIP/2.0 200") for x in r), [first(x) for x in r])
        # 4. t_forward_nonack*(), t_lookup_request(), t_save_lumps(),
        # event_route[tm:local-request] / [tm:local-response].
        def req(method, user, callid=None, branch=None, extra=""):
            seq[0] += 1
            return (f"{method} sip:{user}@127.0.0.1:{PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{CALLER};branch={branch or f'z9hG4bKq{seq[0]}x{time.time_ns()}'}\r\n"
                    f"Max-Forwards: 70\r\nFrom: <sip:c@x>;tag=q{seq[0]}\r\nTo: <sip:{user}@x>\r\nCall-ID: {callid or f'q{seq[0]}-{time.time_ns()}'}\r\n"
                    f"CSeq: 1 {method}\r\n{extra}Content-Length: 0\r\n\r\n").encode()

        def shv():
            send(req("OPTIONS", "getshv"))
            d, _, _ = caller.first(b"SIP/2.0 200", 2)
            return first(d) if d else ""

        def drain():
            for sk in (uas, f1, f2, caller):
                sk.collect(0.15)

        def answer(sock, code, reason, method=b"MESSAGE", timeout=2):
            d, a, _ = sock.first(method, timeout)
            if d:
                sock.s.sendto(make_reply(d, code, reason, ""), a)
            return d

        drain()
        send(req("MESSAGE", "fwdudp"))
        d = answer(uas, 200, "OK")
        check("t_forward_nonack_udp(ip, port): relayed statefully", d is not None and hdr(d, "Via").startswith("SIP/2.0/UDP"), d)
        r = caller.first(b"SIP/2.0 200", 2)[0]
        check("…and the 200 comes back", r is not None)
        send(req("MESSAGE", "fwd"))
        d = answer(uas, 200, "OK")
        check("t_forward_nonack(): to $du", d is not None and caller.first(b"SIP/2.0 200", 2)[0] is not None, d)
        send(req("MESSAGE", "fwdnotx"))
        r = caller.first(b"SIP/2.0 500", 2)[0]
        sent = [m for m, _, _ in uas.collect(0.3) if m.startswith(b"MESSAGE")]
        check("t_forward_nonack() without a transaction: false, nothing sent", r is not None and b"fwd failed" in r and not sent, (r, sent))
        send(req("ACK", "fwd"))
        acks = [m for m, _, _ in uas.collect(0.4) if m.startswith(b"ACK")]
        check("t_forward_nonack() refuses an ACK", not acks and "ack=1" in shv(), (acks, shv()))

        m = req("MESSAGE", "lookup", branch=f"z9hG4bKlk{time.time_ns()}")
        send(m)
        d, a, _ = uas.first(b"MESSAGE", 2)
        send(m)  # retransmission: matched, nothing resent
        again = [x for x, _, _ in uas.collect(0.5) if x.startswith(b"MESSAGE") and hdr(x, "Via") != hdr(d or b"", "Via")]
        got = caller.collect(0.3)
        check("t_lookup_request(): the retransmission matches (counted once), the first request didn't",
              "lk=1" in shv() and not again and not got, (shv(), len(again), [first(x) for x, _, _ in got]))
        if d:
            uas.s.sendto(make_reply(d, 200, "OK", ""), a)
            caller.collect(0.3)

        drain()
        send(req("MESSAGE", "lumps"))
        d0 = answer(uas, 486, "Busy Here")
        d1, a1, _ = f1.first(b"MESSAGE", 2)
        check("t_newtran + append_hdr: the first branch has every edit",
              d0 is not None and all(h in d0 for h in (b"X-Early: 1", b"X-Saved: 1", b"X-Late: 1")), d0)
        check("…failure_route's branch: edits before t_newtran and up to t_save_lumps(), not later ones",
              d1 is not None and b"X-Early: 1" in d1 and b"X-Saved: 1" in d1 and b"X-Late" not in d1, d1)
        if d1:
            f1.s.sendto(make_reply(d1, 200, "OK", ""), a1)
        check("…its 200 reaches the caller", caller.first(b"SIP/2.0 200", 2)[0] is not None)
        drain()
        send(req("MESSAGE", "nolumps"))
        d0 = answer(uas, 486, "Busy Here")
        d1, a1, _ = f1.first(b"MESSAGE", 2)
        check("t_newtran without t_save_lumps(): failure_route's branch has the edits up to the first relay",
              d1 is not None and b"X-Early: 1" in d1 and b"X-Before-Relay: 1" in d1, d1)
        if d1:
            f1.s.sendto(make_reply(d1, 200, "OK", ""), a1)
        caller.first(b"SIP/2.0 200", 2)

        send(req("MESSAGE", "uac"))
        d, a, _ = uas.first(b"OPTIONS", 2)
        check("event_route[tm:local-request]: a t_uac_send() request carries the route's header",
              d is not None and b"X-Local: OPTIONS" in d and b"X-Orig: uac" in d, d)
        if d:
            uas.s.sendto(make_reply(d, 200, "OK", ""), a)
        caller.collect(0.3)
        send(req("MESSAGE", "uacdrop"))
        dropped = [x for x, _, _ in uas.collect(0.5) if x.startswith(b"OPTIONS")]
        check("…`drop` there: the request is not sent", not dropped, [first(x) for x in dropped])
        caller.collect(0.2)

        send(req("MESSAGE", "lresp"))
        r = caller.first(b"SIP/2.0 404", 2)[0]
        time.sleep(0.1)
        check("event_route[tm:local-response] runs on the reply t_reply() sent: $T_reply_code and $rs are its status", r is not None and "lr=404" in shv() and "lrs=404" in shv(), (r, shv()))

        # t_load_contacts(mode): two contacts with equal q.
        for sock, port in ((f1, F1), (f2, F2)):
            seq[0] += 1
            reg = (f"REGISTER sip:127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKr{seq[0]}\r\nMax-Forwards: 70\r\n"
                   f"From: <sip:qq@127.0.0.1>;tag=r{port}\r\nTo: <sip:qq@127.0.0.1>\r\nCall-ID: qq-{port}\r\nCSeq: 1 REGISTER\r\n"
                   f"Contact: <sip:qq@127.0.0.1:{port}>;q=0.5\r\nExpires: 600\r\nContent-Length: 0\r\n\r\n")
            sock.s.sendto(reg.encode(), ("127.0.0.1", PROXY))
            sock.first(b"SIP/2.0 200")

        def fork(user):
            drain()
            send(req("MESSAGE", user))
            got = {}

            def grab(sock, name):
                d, a, _ = sock.first(b"MESSAGE", 1.5)
                if d:
                    got[name] = (d, a)
            th = [threading.Thread(target=grab, args=(s, n)) for s, n in ((f1, "f1"), (f2, "f2"))]
            for t in th:
                t.start()
            time.sleep(0.4)
            firsts = dict(got)
            for n, (d, a) in firsts.items():
                (f1 if n == "f1" else f2).s.sendto(make_reply(d, 486, "Busy Here", ""), a)
            for t in th:
                t.join(3)
            for n, (d, a) in got.items():
                if n not in firsts:
                    (f1 if n == "f1" else f2).s.sendto(make_reply(d, 486, "Busy Here", ""), a)
            r = caller.first(b"SIP/2.0 486", 2)[0]
            return firsts, got, r
        firsts, got, r = fork("std")
        check("t_load_contacts(0): equal q → both contacts in parallel", len(firsts) == 2 and r is not None, (list(firsts), list(got)))
        firsts, got, r = fork("prop")
        check("t_load_contacts(1): proportional → one contact at a time, then the other", len(firsts) == 1 and len(got) == 2 and r is not None,
              (list(firsts), list(got)))

        # The unanswered CANCEL above ended in a local 408; the INVITEs that
        # got no provisional were retransmitted.
        check("tm:timeouts and tm:retransmissions counted", stat("tm:timeouts") >= 1 and stat("tm:retransmissions") >= 1,
              (stat("tm:timeouts"), stat("tm:retransmissions")))
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
