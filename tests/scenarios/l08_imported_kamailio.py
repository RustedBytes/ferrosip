"""l08-imported-kamailio: Kamailio's stock kamailio.cfg, imported at test
time (`ferrosip import … --define ACTIVE`, then `lint --fix`, `check`,
`lint -D warnings`, `fmt --check`: examples/scenarios/l08-imported-kamailio/
import.sh), then run. The same traffic goes to the original .cfg and to
the import, and both must answer it the same way."""
import os, subprocess

import sipkit

KCFG = f"{sipkit.ROOT}/tests/compat/kamailio/etc/kamailio.cfg"


def cfg_proxy(sc, conf_dir, port, name, cfg=KCFG, defines=("ACTIVE",)):
    """A Proxy running the original .cfg with -f (sipkit.Proxy only knows
    ferrosip.toml: a local helper that swaps the command line). l12 uses it
    too."""
    env = sc.env()
    p = sipkit.Proxy(conf_dir, env, name=name)
    p.args = [sipkit.BIN, "-f", cfg, *(a for d in defines for a in ("--define", d)), "-l", f"udp:127.0.0.1:{port}", "--rpc-socket", env["RPC_SOCK"]]
    sc.proxies.append(p)
    return p.start()


def traffic(sc, label, port):
    """tests/e2e_compat.py's stock traffic, and a few more edge cases;
    {check: what came back} so the two runs can be compared."""
    seen = {}
    alice = sc.ua("alice", port, domain="127.0.0.1")
    alice.auto_answer()
    bob = sc.ua("bob", port, domain="127.0.0.1")

    def check(what, cond, got):
        sc.check(f"{label}: {what}", cond, got)
        seen[what] = got

    def first(m):
        return m.first if m is not None else None

    o = bob.request("OPTIONS", f"sip:127.0.0.1:{port}")
    r = bob.final(call_id=o["call_id"])
    check("OPTIONS to the server → 200 Keepalive", r is not None and r.code == 200 and r.reason == "Keepalive", first(r))

    r = alice.register(expires=60)
    check("REGISTER saved: 200 with alice's contact", r is not None and r.code == 200 and f"127.0.0.1:{alice.port}" in (r.get("contact") or ""),
          first(r))

    sent = bob.invite("sip:carol@127.0.0.1")
    r = bob.final(method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"])
    check("INVITE to an unknown user → 404 Not Found", r is not None and r.code == 404 and r.reason == "Not Found", first(r))
    if r is not None:
        bob._ack_neg(sent, r)
        extra = bob.recv(0.5, lambda m: m.get("call-id") == sent["call_id"])
        check("…the ACK for the 404 is not answered", extra is None, first(extra))

    n = len(alice.received)
    m = bob.request("MESSAGE", "sip:alice@127.0.0.1", body="hi", content_type="text/plain")
    r = bob.final(call_id=m["call_id"], method="MESSAGE")
    fwd = [x for x in alice.received[n:] if x.method == "MESSAGE" and x.get("call-id") == m["call_id"]]
    check("MESSAGE to alice is relayed to her registered contact", len(fwd) >= 1 and fwd[0].ruri == alice.contact,
          ["alice's contact" if x.ruri == alice.contact else x.ruri for x in fwd])
    check("…and alice's 200 comes back to the sender", r is not None and r.code == 200, first(r))
    # A retransmission after the final: absorbed by the transaction (the
    # 200 is resent), not relayed again.
    bob.send(m["raw"])
    again = bob.recv(1.0, lambda x: x.is_reply and x.get("call-id") == m["call_id"])
    relayed = {x.all("via")[0] for x in alice.received if x.method == "MESSAGE" and x.get("call-id") == m["call_id"]}
    check("…a retransmitted MESSAGE is absorbed (200 resent, nothing relayed again)",
          again is not None and again.code == 200 and len(relayed) == 1, (first(again), len(relayed)))

    r, d = bob.call("sip:alice@127.0.0.1", timeout=6)
    check("INVITE to alice: relayed, 200", r is not None and r.code == 200 and d is not None, first(r))
    if d:
        check("…with the proxy's Record-Route", len(r.all("record-route")) >= 1, r.all("record-route"))
        rep = d.bye()
        check("…and the BYE through it → 200", rep is not None and rep.code == 200, first(rep))

    alice.auto_answer(code=486, reason="Busy Here")
    r, _ = bob.call("sip:alice@127.0.0.1", timeout=6)
    check("alice busy: her 486 is forwarded (MANAGE_FAILURE: a failure route / after await)", r is not None and r.code == 486, first(r))

    # An INVITE whose Via has no branch: t_relay fails at once, so
    # send_reply_error answers with its error and no failure route runs (in
    # the import: the `Final(r) if !r.sent` arm after `await txn.relay`).
    bob.via = lambda branch: f"SIP/2.0/UDP 127.0.0.1:{bob.port};rport"
    sent = bob.invite("sip:alice@127.0.0.1")
    del bob.via
    r = bob.final(method="INVITE", call_id=sent["call_id"], timeout=6)
    check("INVITE without a Via branch: the relay fails at once → 400 from send_reply_error",
          r is not None and r.code == 400 and r.reason == "Missing Via branch (RFC 2543 not supported)", first(r))
    check("…and alice never got it", not any(x.method == "INVITE" and x.get("call-id") == sent["call_id"] for x in alice.received), None)

    alice.auto_answer(code=None, ring=True)
    sent = bob.invite("sip:alice@127.0.0.1")
    ring = bob.recv(4, lambda x: x.is_reply and x.code == 180 and x.get("call-id") == sent["call_id"])
    check("alice rings: the 180 reaches the caller", ring is not None, first(ring))
    bob.cancel(sent)
    r = bob.final(method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"], timeout=6)
    check("the caller cancels: 487", r is not None and r.code == 487, first(r))
    if r is not None:
        bob._ack_neg(sent, r)
    check("…and alice got the CANCEL", any(x.method == "CANCEL" and x.get("call-id") == sent["call_id"] for x in alice.received), None)
    alice.auto_answer()

    m = bob.request("MESSAGE", "sip:alice@127.0.0.1", max_forwards=0, body="x", content_type="text/plain")
    r = bob.final(call_id=m["call_id"])
    check("Max-Forwards 0 → 483 Too Many Hops", r is not None and r.code == 483, first(r))

    m = bob.request("BYE", "sip:alice@127.0.0.1", to="<sip:alice@127.0.0.1>;tag=nosuchdialog")
    r = bob.final(call_id=m["call_id"])
    check("an in-dialog BYE nobody knows → 404 Not here", r is not None and r.code == 404 and r.reason == "Not here", first(r))

    m = bob.request("OPTIONS", f"sip:127.0.0.1:{port}", headers={"User-Agent": "friendly-scanner"})
    check("a scanner's User-Agent is dropped silently", bob.recv(1.0, lambda x: x.get("call-id") == m["call_id"]) is None, None)

    long = "x" * 600
    m = bob.request("MESSAGE", f"sip:{long}@127.0.0.1", body="x", content_type="text/plain")
    r = bob.final(call_id=m["call_id"])
    check("an R-URI over 512 bytes → 403 R-URI too large", r is not None and r.code == 403 and r.reason == "R-URI too large", first(r))
    return seen


def import_stock(sc):
    """Run the scenario's import.sh into the temp directory and check each of
    its steps; (output directory, routes/main.fsr) or None. l12 uses it too."""
    out = os.path.join(sc.tmp, "imported")
    script = os.path.join(sc.dir, "import.sh")
    r = subprocess.run(["sh", script, out], capture_output=True, text=True, timeout=120, env={**os.environ, "FERROSIP": sipkit.BIN})
    log = r.stdout + r.stderr
    for step in ("import", "lint --fix", "check", "lint -D warnings", "fmt --check"):
        sc.check(f"import.sh: {step} succeeds on the imported configuration", f"ok: {step}" in r.stdout, log[-1500:])
    sc.check("the import passes `ferrosip check` (config OK)", "config OK" in log, log[-800:])
    if not os.path.exists(os.path.join(out, "ferrosip.toml")):
        return None
    return out, open(os.path.join(out, "routes", "main.fsr")).read()


def run(sc):
    got = import_stock(sc)
    if got is None:
        return
    out, fsr = got
    sc.check("lint --fix removed the trailing returns the import left", "\n    return\n}" not in fsr, "")
    # send_reply(…); exit; → reply(Name), and sl_send_reply(…); exit; too
    # where no transaction can exist yet (all of them in this script).
    named = ["reply(NotFound)\n", "reply(MethodNotAllowed)\n", "reply(TooManyHops)\n", 'reply(NotFound, "Not here")\n', 'reply(Forbidden, "Not relaying")\n']
    sc.check("the import answers with named codes: " + ", ".join(n.strip() for n in named), all(n in fsr for n in named), [n for n in named if n not in fsr])
    sc.check("no sl_send_reply is left raw (no transaction exists at any of them)", "sl_send_reply" not in fsr, "")
    sc.check("route(RELAY)'s t_on_failure + t_relay is `await txn.relay` + match; MANAGE_FAILURE is a function it calls",
             "let res = await txn.relay(msg)" in fsr and "_ => manage_failure(msg)" in fsr and "fn manage_failure(msg: Request) {" in fsr
             and "t_on_failure" not in fsr and "kamailio.failure_route" not in fsr, "")

    po, pi = sc.port(), sc.port()
    cfg_proxy(sc, out, po, "kamailio.cfg")
    env = sc.env()
    sc.proxy(out, env, extra=["-l", f"udp:127.0.0.1:{pi}", "--rpc-socket", env["RPC_SOCK"]], name="imported")
    orig = traffic(sc, "kamailio.cfg", po)
    imp = traffic(sc, "imported", pi)
    for what in orig:
        same = what in imp and str(orig[what]).replace(str(po), "PORT") == str(imp[what]).replace(str(pi), "PORT")
        sc.check(f"the import answers like the original: {what}", same, (orig[what], imp.get(what)))
    for p in list(sc.proxies):
        log = "".join(p.lines)
        sc.check(f"{p.name}: no script errors in the log", "ERROR" not in log, log[-800:])
