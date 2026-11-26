"""l12-imported-failure-routes: Kamailio's stock kamailio.cfg with
WITH_VOICEMAIL, WITH_BLOCK3XX and WITH_BLOCK401407, run as the original .cfg
and as its import (examples/scenarios/l12-imported-failure-routes/import.sh,
which runs l08's script with these defines). route(RELAY)'s t_on_failure +
t_relay imports as `await txn.relay` + match, and failure_route
[MANAGE_FAILURE] as a function called after it. The same failure traffic
goes to both, and both must answer it the same way.

The voicemail server is a UA; both proxies get its address over RPC
(`cfg.set_now_string voicemail srv_ip|srv_port`, the cfg vars the script
reads with $sel(cfg_get.voicemail.*)). tm's timers can't be changed over RPC,
so both get the same short ones at startup: the .cfg as a copy with the two
modparams edited, the import with --set."""
import os, re

import sipkit
from scenarios.l08_imported_kamailio import KCFG, cfg_proxy, import_stock

DEFINES = ("ACTIVE", "WITH_VOICEMAIL", "WITH_BLOCK3XX", "WITH_BLOCK401407")
FR_TIMER, FR_INV_TIMER = 2, 3  # seconds; the stock cfg has 30 and 120
WAIT = 15  # for a final reply: well above both timers, and a voicemail leg after them


def short_timers_cfg(sc):
    """The stock cfg with fr_timer / fr_inv_timer shortened, in the temp
    directory (its `import_file "kamailio-local.cfg"` is optional, as in
    the stock directory)."""
    text = open(KCFG).read()
    text, n1 = re.subn(r'modparam\("tm", "fr_timer", 30000\)', f'modparam("tm", "fr_timer", {FR_TIMER * 1000})', text)
    text, n2 = re.subn(r'modparam\("tm", "fr_inv_timer", 120000\)', f'modparam("tm", "fr_inv_timer", {FR_INV_TIMER * 1000})', text)
    sc.check("the stock cfg's fr_timer and fr_inv_timer modparams are found (and shortened in a copy)", (n1, n2) == (1, 1), (n1, n2))
    path = os.path.join(sc.tmp, "kamailio.cfg")
    open(path, "w").write(text)
    return path


def invites(ua, call_id):
    """How many INVITE branches reached `ua` for this call (retransmissions
    of one branch count once)."""
    return len({x.all("via")[0] for x in ua.received if x.method == "INVITE" and x.get("call-id") == call_id})


def silent(ua):
    """No reply at all to an INVITE (not even 100)."""
    ua.handler = lambda m: None


def traffic(sc, label, proxy, port):
    seen = {}
    alice = sc.ua("alice", port, domain="127.0.0.1")
    bob = sc.ua("bob", port, domain="127.0.0.1")
    vm = sc.ua("vm", port, domain="127.0.0.1")

    def check(what, cond, got):
        sc.check(f"{label}: {what}", cond, got)
        seen[what] = got

    def first(m):
        return m.first if m is not None else None

    proxy.rpc("cfg.set_now_string", "voicemail", "srv_ip", "127.0.0.1")
    proxy.rpc("cfg.set_now_string", "voicemail", "srv_port", vm.port)
    got = (proxy.rpc("cfg.get", "voicemail", "srv_ip"), proxy.rpc("cfg.get", "voicemail", "srv_port"))
    sc.check(f"{label}: voicemail.srv_ip / srv_port set over RPC", got == ("127.0.0.1", str(vm.port)), got)

    alice.auto_answer()
    r = alice.register(expires=300)
    check("REGISTER alice: 200", r is not None and r.code == 200, first(r))

    def call(timeout=WAIT):
        """INVITE alice; (final reply, the sent INVITE). A 2xx is ACKed and
        hung up, a negative final ACKed."""
        sent = bob.invite("sip:alice@127.0.0.1")
        r = bob.final(timeout, method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"])
        if r is not None and r.code >= 300:
            bob._ack_neg(sent, r)
        elif r is not None:
            d = sipkit.Dialog(bob, sent, r)
            d.ack()
            d.bye()
        return r, sent

    def legs(sent):
        return invites(alice, sent["call_id"]), invites(vm, sent["call_id"])

    # 1. Busy: MANAGE_FAILURE's 486|408 → TOVOICEMAIL → RELAY again.
    alice.auto_answer(code=486, reason="Busy Here")
    vm.auto_answer()
    r, sent = call()
    check("alice busy (486) → voicemail answers → 200", r is not None and r.code == 200, first(r))
    check("…one INVITE to alice, one to voicemail", legs(sent) == (1, 1), legs(sent))

    # 2. Voicemail busy too: every 486 serially forks to voicemail again,
    # until the transaction has max_branches (12) branches: alice's and 11
    # to voicemail. Then t_relay fails at once in failure code
    # (E_TOO_MANY_BRANCHES; send_reply_error, in the import the `!r.sent`
    # arm).
    vm.auto_answer(code=486, reason="Busy Here")
    r, sent = call()
    check("alice 486, voicemail 486 → serial forking to voicemail until 500 Forking capacity exceeded",
          r is not None and r.code == 500 and r.reason == "Forking capacity exceeded (12/TM)", first(r))
    check("…one INVITE to alice, 11 to voicemail (max_branches 12 in all)", legs(sent) == (1, 11), legs(sent))

    # 2b. Voicemail 503: failure_reply_mode 3 dropped alice's 486 when the
    # voicemail leg started, so t_check_status sees the 503 (no voicemail
    # again) and the caller gets tm's own 500 "Service Unavailable" (a 503
    # isn't forwarded: Kamailio t_reply.c relay_reply(), remap_503_500).
    vm.auto_answer(code=503, reason="Service Unavailable")
    r, sent = call()
    check("alice 486, voicemail 503 → 500 Service Unavailable upstream (alice's 486 no longer competes)", r is not None and r.code == 500 and r.reason == "Service Unavailable", first(r))
    check("…one INVITE to alice, one to voicemail", legs(sent) == (1, 1), legs(sent))
    vm.auto_answer()

    # 3. 404 is not in any failure case: forwarded.
    alice.auto_answer(code=404, reason="Not Found")
    r, sent = call()
    check("alice 404 → forwarded 404", r is not None and r.code == 404 and r.reason == "Not Found", first(r))
    check("…voicemail not tried", legs(sent) == (1, 0), legs(sent))

    # 4. Ringing without an answer: fr_inv_timer → 408 → voicemail.
    alice.auto_answer(code=None, ring=True)
    r, sent = call()
    check(f"alice rings and never answers → fr_inv_timer ({FR_INV_TIMER}s) → voicemail 200", r is not None and r.code == 200, first(r))
    check("…alice got a CANCEL", any(x.method == "CANCEL" and x.get("call-id") == sent["call_id"] for x in alice.received), None)
    check("…one INVITE branch to alice, one to voicemail", legs(sent) == (1, 1), legs(sent))

    # 5. Silent: fr_timer → 408 → voicemail.
    silent(alice)
    r, sent = call()
    check(f"alice silent → fr_timer ({FR_TIMER}s) → voicemail 200", r is not None and r.code == 200, first(r))
    check("…one INVITE branch to alice (retransmitted), one to voicemail", legs(sent) == (1, 1), legs(sent))

    # 6. BLOCK3XX / BLOCK401407: t_reply("404", "Not found").
    for code, reason in ((302, "Moved Temporarily"), (401, "Unauthorized"), (407, "Proxy Authentication Required")):
        alice.auto_answer(code=code, reason=reason)
        r, sent = call()
        check(f"alice {code} → 404 Not found", r is not None and r.code == 404 and r.reason == "Not found", first(r))
        check(f"…voicemail not tried after {code}", legs(sent) == (1, 0), legs(sent))

    # 7. 500 is not in any failure case: forwarded.
    alice.auto_answer(code=500, reason="Server Internal Error")
    r, sent = call()
    check("alice 500 → forwarded 500", r is not None and r.code == 500, first(r))
    check("…voicemail not tried after 500", legs(sent) == (1, 0), legs(sent))

    # 8. The caller cancels while voicemail rings: the voicemail leg gets
    # the CANCEL and answers 487, and MANAGE_FAILURE exits (t_is_canceled).
    # The caller gets the 487: alice's 486 was dropped when the voicemail
    # leg started (failure_reply_mode 3).
    alice.auto_answer(code=486, reason="Busy Here")
    vm.auto_answer(code=None, ring=True)
    sent = bob.invite("sip:alice@127.0.0.1")
    ring = bob.recv(WAIT, lambda x: x.is_reply and x.code == 180 and x.get("call-id") == sent["call_id"])
    check("alice busy, voicemail rings: its 180 reaches the caller", ring is not None, first(ring))
    bob.cancel(sent)
    r = bob.final(WAIT, method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"])
    check("the caller cancels during the voicemail leg → 487 (alice's 486 no longer competes)", r is not None and r.code == 487, first(r))
    if r is not None:
        bob._ack_neg(sent, r)
    check("…voicemail got the CANCEL", any(x.method == "CANCEL" and x.get("call-id") == sent["call_id"] for x in vm.received), None)
    check("…one INVITE to alice, one to voicemail", legs(sent) == (1, 1), legs(sent))
    return seen


def run(sc):
    got = import_stock(sc)
    if got is None:
        return
    out, fsr = got
    sc.check("route(RELAY) imports as `await txn.relay` + match, MANAGE_FAILURE as `fn manage_failure`",
             "let res = await txn.relay(msg)" in fsr and "_ => manage_failure(msg)" in fsr and "fn manage_failure(msg: Request) {" in fsr
             and "t_on_failure" not in fsr, "")
    sc.check("the import has the voicemail and 3xx / 401 / 407 cases", "fn tovoicemail(msg: Request) {" in fsr and "txn.code in 300..399" in fsr
             and "txn.code == ProxyAuthenticationRequired" in fsr, "")

    cfg = short_timers_cfg(sc)
    po, pi = sc.port(), sc.port()
    orig = cfg_proxy(sc, out, po, "kamailio.cfg", cfg=cfg, defines=DEFINES)
    env = sc.env()
    imp = sc.proxy(out, env, name="imported",
                   extra=["-l", f"udp:127.0.0.1:{pi}", "--rpc-socket", env["RPC_SOCK"],
                          "--set", f"modules.tm.fr_timer={FR_TIMER}s", "--set", f"modules.tm.fr_inv_timer={FR_INV_TIMER}s"])
    a = traffic(sc, "kamailio.cfg", orig, po)
    b = traffic(sc, "imported", imp, pi)
    for what in a:
        same = what in b and str(a[what]).replace(str(po), "PORT") == str(b[what]).replace(str(pi), "PORT")
        sc.check(f"the import answers like the original: {what}", same, (a[what], b.get(what)))
    for p in list(sc.proxies):
        log = "".join(p.lines)
        sc.check(f"{p.name}: no script errors in the log", "ERROR" not in log, log[-800:])
