#!/usr/bin/env python3
"""End-to-end checks for the Phase 5 modules: presence, presence_xml,
presence_dialoginfo, pua, pua_dialoginfo, sca, msilo, rls. The proxy is
its own presence server (pua_dialoginfo publishes to itself).
Run from the repo root after `cargo build --release`.
"""
import json, os, re, shutil, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402
from e2e_routing import Peer, make_reply, hdr, first  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PX = 6360
W, P, A, S1, S2, U = 6300, 6301, 6302, 6311, 6312, 6320
SOCK = os.path.join(ROOT, "target/e2e_presence.sock")
DB = os.path.join(ROOT, "target/e2e_presence_db")

CFG = r"""
loadmodule "tm"
loadmodule "sl"
loadmodule "siputils"
loadmodule "textops"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "dialog"
loadmodule "presence"
loadmodule "presence_xml"
loadmodule "presence_dialoginfo"
loadmodule "pua"
loadmodule "pua_dialoginfo"
loadmodule "sca"
loadmodule "msilo"
loadmodule "rls"
modparam("tm", "fr_timer", 1500)
modparam("presence_dialoginfo", "force_dummy_dialog", 1)
modparam("pua_dialoginfo", "presence_server", "sip:127.0.0.1:6360")
modparam("pua_dialoginfo", "caller_trying", 0)
modparam("msilo", "db_url", "text://DB")
modparam("rls", "db_url", "text://DB")

request_route {
    if (is_method("PUBLISH")) { handle_publish(); exit; }
    if (is_method("SUBSCRIBE")) {
        if ($hdr(Event) == "call-info" || $hdr(Event) == "line-seize") { sca_handle_subscribe(); exit; }
        if (rls_handle_subscribe()) { exit; }
        handle_subscribe();
        exit;
    }
    if (is_method("REGISTER")) { save("location"); m_dump(); exit; }
    if (is_method("MESSAGE") && $rU == "offline") {
        if (m_store()) { sl_send_reply(202, "Accepted"); } else { sl_send_reply(500, "not stored"); }
        exit;
    }
    if (has_totag()) { sca_call_info_update(); t_relay(); exit; }
    if (is_method("INVITE")) {
        dlg_manage();
        sca_call_info_update();
        t_on_reply("sca");
        t_relay("udp:127.0.0.1:6302");
        exit;
    }
    sl_send_reply(404, "Not here");
}

onreply_route[sca] {
    sca_call_info_update();
}
"""

RLS_DOC = ('<?xml version="1.0"?><rls-services xmlns="urn:ietf:params:xml:ns:rls-services"><service uri="sip:friends@127.0.0.1">'
           '<list name="f"><entry uri="sip:alice@127.0.0.1"/><entry uri="sip:carol@127.0.0.1"/></list>'
           '<packages><package>presence</package></packages></service></rls-services>')
TABLES = {
    "silo": "id(int,auto) src_addr(string) dst_addr(string) username(string) domain(string) inc_time(int) exp_time(int) ctype(string) body(string)\n",
    "xcap": "id(int,auto) username(string) domain(string) doc(string) doc_type(int) etag(string,null) source(int) doc_uri(string) port(int)\n"
            + "1:friends:127.0.0.1:" + RLS_DOC.replace(":", "\\:") + ":6::0:x:0\n",
}

failures = 0
seq = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def req(method, ruri, port, extra="", frm=None, to=None, body="", ctype=None, callid=None, cseq=1, ftag=None):
    seq[0] += 1
    ex = "".join(l + "\r\n" for l in extra.split("\n") if l) if extra else ""
    ct = f"Content-Type: {ctype}\r\n" if body else ""
    frm = frm or f"sip:u{port}@127.0.0.1"
    return (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKp{seq[0]}x{time.time_ns()}\r\n"
            f"Max-Forwards: 70\r\nFrom: <{frm}>;tag={ftag or 't' + str(port)}\r\nTo: {to or '<' + ruri + '>'}\r\n"
            f"Call-ID: {callid or f'pr-{seq[0]}-{time.time_ns()}'}\r\nCSeq: {cseq} {method}\r\nContact: <sip:u{port}@127.0.0.1:{port}>\r\n"
            f"{ex}{ct}Content-Length: {len(body)}\r\n\r\n{body}").encode()


def pidf(entity, tid, basic):
    return (f'<?xml version="1.0" encoding="UTF-8"?><presence xmlns="urn:ietf:params:xml:ns:pidf" entity="{entity}">'
            f'<tuple id="{tid}"><status><basic>{basic}</basic></status></tuple></presence>')


def notify(peer, timeout=3.0):
    """Next NOTIFY to `peer` (answered with 200)."""
    m = peer.expect("NOTIFY", timeout)
    if m:
        peer.s.sendto(make_reply(m, 200, "OK"), peer.addr)
    return m


def ctl(*args):
    out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", SOCK, *args], capture_output=True, text=True, timeout=5)
    try:
        return json.loads(out.stdout) if out.stdout.strip() else out.stderr.strip()
    except json.JSONDecodeError:
        return out.stdout


def body_of(m):
    return m.split(b"\r\n\r\n", 1)[1].decode() if m else ""


def main():
    shutil.rmtree(DB, ignore_errors=True)
    os.makedirs(DB)
    for t, body in TABLES.items():
        open(os.path.join(DB, t), "w").write(body)
    cfg = os.path.join(ROOT, "target/e2e_presence.cfg")
    open(cfg, "w").write(CFG.replace("text://DB", "text://" + DB))
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}", "-n", "2", "--rpc-socket", SOCK],
                             stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    if proxy.poll() is not None:
        print(proxy.stderr.read())
        sys.exit(1)
    w, p, a, s1, s2, u = Peer(W), Peer(P), Peer(A), Peer(S1), Peer(S2), Peer(U)

    def send(peer, m):
        peer.s.sendto(m, ("127.0.0.1", PX))

    def ask(peer, m):
        send(peer, m)
        return peer.final()

    try:
        # ------------------------------------------------------------ presence
        alice = f"sip:alice@127.0.0.1:{PX}"
        r = ask(w, req("SUBSCRIBE", alice, W, "Event: presence\nExpires: 60"))
        totag = re.search(r"tag=([^;>\s]+)", hdr(r or b"", "To"))
        check("SUBSCRIBE presence → 200 with To tag and Expires", first(r) == "SIP/2.0 200 OK" and totag and hdr(r, "Expires") == "60", r)
        n = notify(w)
        check("initial NOTIFY: active, no state yet", n is not None and hdr(n, "Subscription-State").startswith("active;expires=")
              and hdr(n, "Event") == "presence" and body_of(n) == "", n)
        r = ask(p, req("PUBLISH", alice, P, "Event: presence\nExpires: 60", body=pidf("sip:alice@127.0.0.1", "t1", "open"), ctype="application/pidf+xml"))
        etag1 = hdr(r or b"", "SIP-ETag")
        check("PUBLISH → 200 + SIP-ETag", first(r) == "SIP/2.0 200 OK" and etag1, r)
        n = notify(w)
        check("watcher notified with the PIDF", n is not None and "<basic>open</basic>" in body_of(n) and hdr(n, "Content-Type") == "application/pidf+xml", n)
        r = ask(p, req("PUBLISH", alice, P, "Event: presence\nExpires: 60", body=pidf("sip:alice@127.0.0.1", "t2", "closed"), ctype="application/pidf+xml"))
        n = notify(w)
        b = body_of(n)
        check("second publication aggregated (two tuples)", b.count("<tuple") == 2 and "open" in b and "closed" in b, b)
        r = ask(p, req("PUBLISH", alice, P, f"Event: presence\nExpires: 60\nSIP-If-Match: {etag1}"))
        etag1b = hdr(r or b"", "SIP-ETag")
        check("refresh with SIP-If-Match → new etag, no NOTIFY", first(r) == "SIP/2.0 200 OK" and etag1b and etag1b != etag1 and w.expect("NOTIFY", 0.5) is None, r)
        r = ask(p, req("PUBLISH", alice, P, "Event: presence\nExpires: 60\nSIP-If-Match: nope"))
        check("unknown etag → 412", first(r) == "SIP/2.0 412 Conditional Request Failed", first(r))
        r = ask(p, req("PUBLISH", alice, P, "Event: foo\nExpires: 60", body="x", ctype="text/plain"))
        check("unknown event → 489 + Allow-Events", first(r) == "SIP/2.0 489 Bad Event" and "presence" in hdr(r, "Allow-Events") and "dialog" in hdr(r, "Allow-Events"), r)
        show = ctl("presence.presentity_show", "sip:alice@127.0.0.1")
        check("presence.presentity_show", isinstance(show, dict) and show["body"].count("<tuple") == 2, show)
        check("presence.watcher_list", any(x["watcher"].startswith(f"sip:u{W}@") for x in ctl("presence.watcher_list")))
        cid = hdr(r, "Call-ID")
        subcid = None
        # unsubscribe in the dialog
        for x in ctl("presence.watcher_list"):
            if x["pres_uri"] == "sip:alice@127.0.0.1":
                subcid = x["callid"]
        r = ask(w, req("SUBSCRIBE", alice, W, "Event: presence\nExpires: 0", callid=subcid, cseq=2, to=f"<{alice}>;tag={totag.group(1) if totag else ''}"))
        n = notify(w)
        check("unsubscribe → 200 + NOTIFY terminated", first(r) == "SIP/2.0 200 OK" and n is not None and hdr(n, "Subscription-State").startswith("terminated"), n)
        _ = cid

        # ------------------------------------------------------------ dialog-info via pua_dialoginfo
        r = ask(w, req("SUBSCRIBE", "sip:caller@x", W, "Event: dialog\nExpires: 60"))
        n = notify(w)
        check("SUBSCRIBE dialog: dummy dialog-info (force_dummy_dialog)", first(r) == "SIP/2.0 200 OK" and n is not None
              and "<dialog-info" in body_of(n) and "<dialog " not in body_of(n), body_of(n))
        cid = f"call-{time.time_ns()}"
        send(p, req("INVITE", "sip:bob@x", P, frm="sip:caller@x", callid=cid))
        inv = a.expect("INVITE")
        early = w.expect("NOTIFY", 0.8)
        check("caller_trying=0 (Sipwise): no Trying publication before the first 18x", early is None, early)
        a.s.sendto(make_reply(inv, 180, "Ringing"), a.addr)
        n = notify(w)
        b = body_of(n)
        check("18x → dialog-info early, initiator, tags", n is not None and "<state>early</state>" in b and 'direction="initiator"' in b
              and f'call-id="{cid}"' in b and 'local-tag="t6301"' in b and 'remote-tag="uas"' in b, b)
        v1 = re.search(r'version="(\d+)"', b)
        a.s.sendto(make_reply(inv, 200, "OK", f"Contact: <sip:bob@127.0.0.1:{A}>\r\n"), a.addr)
        n = notify(w)
        b = body_of(n)
        v2 = re.search(r'version="(\d+)"', b)
        check("2xx → confirmed, version increased", "<state>confirmed</state>" in b and v1 and v2 and int(v2.group(1)) > int(v1.group(1)), b)
        p.final()
        send(p, req("BYE", f"sip:bob@127.0.0.1:{A}", P, frm="sip:caller@x", callid=cid, cseq=2, to="<sip:bob@x>;tag=uas"))
        a.answer("BYE")
        p.final()
        n = notify(w)
        check("BYE → terminated", n is not None and "<state>terminated</state>" in body_of(n), body_of(n))

        # ------------------------------------------------------------ rls
        friends = f"sip:friends@127.0.0.1:{PX}"
        r = ask(w, req("SUBSCRIBE", friends, W, "Event: presence\nExpires: 60"))
        check("rls: no Supported: eventlist → 421", first(r) == "SIP/2.0 421 Extension Required", first(r))
        r = ask(w, req("SUBSCRIBE", friends, W, "Event: presence\nExpires: 60\nSupported: eventlist"))
        n = notify(w)
        b = body_of(n)
        check("rls: NOTIFY multipart/related with RLMI listing the members", first(r) == "SIP/2.0 200 OK" and n is not None
              and hdr(n, "Content-Type").startswith("multipart/related") and "Require" in n.decode() and 'uri="sip:friends@127.0.0.1"' in b
              and '<resource uri="sip:alice@127.0.0.1">' in b and '<resource uri="sip:carol@127.0.0.1">' in b and b.count("<basic>") == 2, b)
        ask(p, req("PUBLISH", f"sip:carol@127.0.0.1:{PX}", P, "Event: presence\nExpires: 60", body=pidf("sip:carol@127.0.0.1", "c1", "open"), ctype="application/pidf+xml"))
        n = notify(w)
        b = body_of(n)
        check("rls: member change re-notifies the list (carol now included)", n is not None and b.count("<basic>") == 3 and 'version="2"' in b, b)

        # ------------------------------------------------------------ sca
        line = f"sip:line@127.0.0.1:{PX}"
        for ph in (s1, s2):
            r = ask(ph, req("SUBSCRIBE", line, ph.s.getsockname()[1], "Event: call-info\nExpires: 60"))
            n = notify(ph)
            check(f"sca: call-info subscription ({ph.s.getsockname()[1]}) → idle", first(r) == "SIP/2.0 200 OK"
                  and hdr(n or b"", "Call-Info") == "<sip:line@127.0.0.1>;appearance-index=*;appearance-state=idle", n)
        r = ask(s1, req("SUBSCRIBE", line, S1, "Event: line-seize\nExpires: 30"))
        n = notify(s1)
        check("sca: line-seize → appearance 1 seized", n is not None and hdr(n, "Event") == "line-seize"
              and hdr(n, "Call-Info") == "<sip:line@127.0.0.1>;appearance-index=1;appearance-state=seized", n)
        n1, n2 = notify(s1), notify(s2)
        check("…both phones see it in call-info", all(x is not None and "appearance-index=1;appearance-state=seized" in hdr(x, "Call-Info") for x in (n1, n2)), (n1, n2))
        cid = f"sca-{time.time_ns()}"
        send(s1, req("INVITE", "sip:bob@x", S1, "Call-Info: <sip:line@127.0.0.1>;appearance-index=1", frm="sip:line@127.0.0.1", callid=cid))
        inv = a.expect("INVITE")
        states = []
        n = notify(s2)
        states.append(hdr(n or b"", "Call-Info"))
        notify(s1)
        a.s.sendto(make_reply(inv, 180, "Ringing"), a.addr)
        n = notify(s2)
        states.append(hdr(n or b"", "Call-Info"))
        notify(s1)
        a.s.sendto(make_reply(inv, 200, "OK", f"Contact: <sip:bob@127.0.0.1:{A}>\r\n"), a.addr)
        n = notify(s2)
        states.append(hdr(n or b"", "Call-Info"))
        notify(s1)
        s1.final()
        check("sca: progressing → alerting → active with appearance-uri",
              [re.search(r"appearance-state=(\w+)", x).group(1) if x else None for x in states] == ["progressing", "alerting", "active"]
              and 'appearance-uri="<sip:bob@x>"' in states[-1], states)
        hold = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\na=sendonly\r\n"
        send(s1, req("INVITE", f"sip:bob@127.0.0.1:{A}", S1, frm="sip:line@127.0.0.1", callid=cid, cseq=2, to="<sip:bob@x>;tag=uas", body=hold, ctype="application/sdp"))
        a.answer("INVITE", 200, "OK", f"Contact: <sip:bob@127.0.0.1:{A}>\r\n")
        n = notify(s2)
        notify(s1)
        s1.final()
        check("sca: re-INVITE a=sendonly → held", "appearance-state=held" in hdr(n or b"", "Call-Info"), n)
        send(a, req("BYE", f"sip:line@127.0.0.1:{S1}", A, frm="sip:bob@x", ftag="uas", callid=cid, cseq=10, to="<sip:line@127.0.0.1>;tag=t6311"))
        m = s1.answer("BYE")
        n = notify(s2)
        notify(s1)
        a.final()
        check("sca: BYE from the far end (upstream flow) → idle", m is not None and hdr(n or b"", "Call-Info").endswith("appearance-index=*;appearance-state=idle"), n)
        # incoming call to the shared line, answered by a phone
        cid = f"scain-{time.time_ns()}"
        send(p, req("INVITE", line, P, frm="sip:caller@x", callid=cid))
        inv = a.expect("INVITE")
        a.s.sendto(make_reply(inv, 200, "OK", f"Contact: <sip:line@127.0.0.1:{A}>\r\n"), a.addr)
        r = p.final()
        n = notify(s2)
        notify(s1)
        check("sca: answered call to the line takes appearance 1 (Call-Info in the 2xx)", hdr(r or b"", "Call-Info") == "<sip:line@127.0.0.1>;appearance-index=1"
              and "appearance-index=1;appearance-state=active" in hdr(n or b"", "Call-Info"), (r, n))
        apps = ctl("sca.all_appearances")
        check("sca.all_appearances", isinstance(apps, list) and len(apps) == 1 and apps[0]["state"] == "active", apps)
        check("sca.release_appearance", ctl("sca.release_appearance", "sip:line@127.0.0.1", "1") == 0)
        notify(s1), notify(s2)

        # ------------------------------------------------------------ msilo
        r = ask(p, req("MESSAGE", f"sip:offline@127.0.0.1:{PX}", P, frm="sip:caller@x", body="you were away", ctype="text/plain"))
        rows = open(os.path.join(DB, "silo")).read().splitlines()[1:]
        check("m_store: 202 and stored in silo", first(r) == "SIP/2.0 202 Accepted" and len(rows) == 1 and rows[0].endswith(":text/plain:you were away"), rows)
        r = ask(u, req("REGISTER", f"sip:127.0.0.1:{PX}", U, frm="sip:offline@127.0.0.1", to="<sip:offline@127.0.0.1>"))
        m = u.expect("MESSAGE")
        check("m_dump on REGISTER: stored message delivered with Date", first(r) == "SIP/2.0 200 OK" and m is not None
              and m.endswith(b"you were away") and hdr(m, "From").startswith("<sip:caller@x>") and hdr(m, "Date").endswith("GMT"), m)
        if m:
            u.s.sendto(make_reply(m, 200, "OK"), u.addr)
        time.sleep(0.3)
        check("…and deleted once delivered", open(os.path.join(DB, "silo")).read().count("\n") == 1)
    finally:
        proxy.terminate()
        try:
            _, err = proxy.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proxy.kill()
            _, err = proxy.communicate()
        check("no panics in proxy log", "panicked" not in err, err[-2000:])
        if failures:
            print("--- proxy stderr ---\n" + err[-4000:])
    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
