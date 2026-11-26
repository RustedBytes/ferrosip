"""s04-digest-auth: 401/407 challenges from a users file, wrong passwords,
stale nonces, nc replay, user mismatch (403), SHA-256 and MD5."""
import time

import sipkit


def challenge_for(reply, alg):
    """(params, header name) of the reply's challenge for `alg`, or (None, None)."""
    for a, p, hdr in sipkit.challenges(reply):
        if a.upper() == alg.upper():
            return p, hdr
    return None, None


def attempt(ua, method, ruri, password, alg="SHA-256", user=None, to=None, from_uri=None, wait=0.0,
            digest_uri=None, drop_alg=False, nc=1, body=""):
    """Send `method` without credentials, answer the `alg` challenge (as `user`
    with `password`), and return (challenge reply, final reply, sent request, credentials header)."""
    user = user or ua.user
    to = to or f"<{ruri.split(';')[0]}>" if method != "REGISTER" else to or f"<{ua.aor}>"
    hs = {"Expires": "300"} if method == "REGISTER" else {}
    sent = ua.request(method, ruri, to=to, headers=hs, from_uri=from_uri, body=body)
    ch = ua.final(method=method, call_id=sent["call_id"], cseq=sent["cseq"])
    if ch is None or ch.code not in (401, 407):
        return ch, ch, sent, None
    if method == "INVITE":
        ua._ack_neg(sent, ch)
    p, hdr = challenge_for(ch, alg)
    if p is None:
        return ch, None, sent, None
    if wait:
        time.sleep(wait)
    name, value = sipkit.credentials(user, password, p, method, digest_uri or ruri, hdr, alg, nc)
    if drop_alg:
        value = value.replace(f", algorithm={alg}", "")
    hs = dict(hs)
    hs[name] = value
    sent = ua.request(method, ruri, to=to, call_id=sent["call_id"], from_tag=sent["from_tag"], cseq=sent["cseq"] + 1,
                      headers=hs, from_uri=from_uri, body=body)
    rep = ua.final(method=method, call_id=sent["call_id"], cseq=sent["cseq"])
    if method == "INVITE" and rep is not None and rep.code >= 300:
        ua._ack_neg(sent, rep)
    return ch, rep, sent, (name, value)


def invites_at(up, cid):
    return [m for m in up.received if m.method == "INVITE" and m.get("call-id") == cid]


def run(sc):
    sip, sip2 = sc.port(), sc.port()
    up = sc.ua("pbx", sip)
    mode = {"ring": False}

    def h(m):
        if m.method == "INVITE":
            if mode["ring"]:
                up.respond(m, 180, "Ringing")
                return None
            return (200, "OK")
        if m.method == "CANCEL":
            up.respond(m, 200)
            inv = next((x for x in reversed(up.received) if x.method == "INVITE" and x.get("call-id") == m.get("call-id")), None)
            if inv is not None:
                up.respond(inv, 487, "Request Terminated")
            return None
        if m.method == "ACK":
            return None
        return (200, "OK")
    up.handler = h
    px_env = dict(SIP_PORT=sip, UPSTREAM=f"sip:127.0.0.1:{up.port}", NONCE_EXPIRE="2s")
    sc.proxy(env=sc.env(**px_env), name="auth")
    alice = sc.ua("alice", sip, password="secret-a")

    # --- REGISTER: 401 with one WWW-Authenticate per algorithm, SHA-256 first.
    sent = alice.request("REGISTER", "sip:example.com", to=f"<{alice.aor}>", headers={"Expires": "300"})
    ch = alice.final(call_id=sent["call_id"])
    chs = sipkit.challenges(ch) if ch is not None else []
    sc.check("REGISTER without credentials → 401", ch is not None and ch.code == 401, ch)
    sc.check("…with WWW-Authenticate for SHA-256 then MD5 (RFC 8760 §2.4: preferred first)",
             [a for a, _, _ in chs] == ["SHA-256", "MD5"] and all(h == "www-authenticate" for _, _, h in chs), [(a, h) for a, _, h in chs])
    sc.check("…realm example.com and qop=auth", all(p.get("realm") == "example.com" and "auth" in (p.get("qop") or "") for _, p, _ in chs), chs)

    for alg in ("SHA-256", "MD5"):
        _, rep, _, _ = attempt(alice, "REGISTER", "sip:example.com", "secret-a", alg)
        sc.check(f"alice REGISTERs with {alg} credentials → 200", rep is not None and rep.code == 200, rep)
    _, rep, _, _ = attempt(alice, "REGISTER", "sip:example.com", "secret-a", "MD5", drop_alg=True)
    sc.check("credentials without algorithm= are MD5 (RFC 2617) → 200", rep is not None and rep.code == 200, rep)

    # --- stored HA1s: bob has a SHA-256 HA1, carol an MD5 one.
    bob = sc.ua("bob", sip, password="secret-b")
    _, rep, _, _ = attempt(bob, "REGISTER", "sip:example.com", "secret-b", "SHA-256")
    sc.check("bob (stored sha256 HA1) with SHA-256 credentials → 200", rep is not None and rep.code == 200, rep)
    _, rep, _, _ = attempt(bob, "REGISTER", "sip:example.com", "secret-b", "MD5")
    sc.check("bob (stored sha256 HA1) with MD5 credentials → refused (401)", rep is not None and rep.code == 401, rep)
    carol = sc.ua("carol", sip, password="secret-c")
    _, rep, _, _ = attempt(carol, "REGISTER", "sip:example.com", "secret-c", "MD5")
    sc.check("carol (stored md5 HA1) with MD5 credentials → 200", rep is not None and rep.code == 200, rep)

    # --- wrong password, unknown user, digest uri that isn't the R-URI.
    _, rep, _, _ = attempt(alice, "REGISTER", "sip:example.com", "wrong", "SHA-256")
    sc.check("REGISTER with a wrong password → a new 401, not 200", rep is not None and rep.code == 401, rep)
    mallory = sc.ua("mallory", sip, password="x")
    _, rep, _, _ = attempt(mallory, "REGISTER", "sip:example.com", "x", "MD5")
    sc.check("an unknown user → 401", rep is not None and rep.code == 401, rep)
    _, rep, _, _ = attempt(alice, "REGISTER", "sip:example.com", "secret-a", "MD5", digest_uri="sip:other.example.com")
    sc.check("digest uri differing from the R-URI → refused (401)", rep is not None and rep.code == 401, rep)

    # --- INVITE: 407 with Proxy-Authenticate; credentials consumed before relaying.
    sent = alice.invite("sip:dest@example.com")
    ch = alice.final(method="INVITE", call_id=sent["call_id"])
    chs = sipkit.challenges(ch) if ch is not None else []
    sc.check("INVITE without credentials → 407", ch is not None and ch.code == 407, ch)
    sc.check("…with Proxy-Authenticate (not WWW-Authenticate)", chs and all(h == "proxy-authenticate" for _, _, h in chs), chs)
    if ch is not None:
        alice._ack_neg(sent, ch)
    time.sleep(0.2)
    sc.check("…and nothing reached the upstream", not invites_at(up, sent["call_id"]))
    r, d = alice.call("sip:dest@example.com")
    sc.check("alice calls with credentials → 200", r is not None and r.code == 200 and d is not None, r)
    inv = invites_at(up, d.call_id) if d else []
    sc.check("…the relayed INVITE carries no Proxy-Authorization (consumed)", inv and inv[-1].get("proxy-authorization") is None,
             inv and inv[-1].raw)
    if d:
        rep = d.bye()
        sc.check("…the BYE follows the Record-Route without a challenge → 200", rep is not None and rep.code == 200, rep)
    ch, rep, sent, _ = attempt(alice, "INVITE", "sip:dest@example.com", "wrong", "SHA-256")
    sc.check("INVITE with a wrong password → a new 407", rep is not None and rep.code == 407, rep)
    time.sleep(0.2)
    sc.check("…and nothing reached the upstream", not invites_at(up, sent["call_id"]))

    # --- user mismatch (auth.check flags 1): valid credentials of another user → 403.
    _, rep, _, _ = attempt(alice, "REGISTER", "sip:example.com", "secret-a", "SHA-256", to="<sip:bob@example.com>")
    sc.check("REGISTER for bob (To) with alice's valid credentials → 403", rep is not None and rep.code == 403, rep)
    _, rep, sent, _ = attempt(alice, "INVITE", "sip:dest@example.com", "secret-a", "SHA-256", from_uri="sip:bob@example.com")
    sc.check("INVITE From bob with alice's valid credentials → 403", rep is not None and rep.code == 403, rep)
    time.sleep(0.2)
    sc.check("…and nothing reached the upstream", not invites_at(up, sent["call_id"]))

    # --- stale nonce (nonce_expire 2s): 401 with stale=true, then the new nonce works.
    ch, rep, sent, _ = attempt(alice, "REGISTER", "sip:example.com", "secret-a", "SHA-256", wait=2.6)
    p, _ = challenge_for(rep, "SHA-256") if rep is not None else (None, None)
    sc.check("credentials for a nonce older than nonce_expire → 401", rep is not None and rep.code == 401, rep)
    sc.check("…with stale=true (RFC 2617 §3.2.1)", p is not None and (p.get("stale") or "").lower() == "true", rep and rep.raw)
    if p is not None:
        name, value = sipkit.credentials("alice", "secret-a", p, "REGISTER", "sip:example.com", "www-authorization", "SHA-256", 1)
        s2 = alice.request("REGISTER", "sip:example.com", to=sent["to"], call_id=sent["call_id"], from_tag=sent["from_tag"],
                           cseq=sent["cseq"] + 1, headers={"Expires": "300", "Authorization": value})
        rep = alice.final(call_id=s2["call_id"], cseq=s2["cseq"])
        sc.check("…answering the fresh challenge → 200", rep is not None and rep.code == 200, rep)

    # --- nc replay: the same credentials (same nonce and nc) on a new request are stale.
    ch, rep, sent, cred = attempt(alice, "REGISTER", "sip:example.com", "secret-a", "SHA-256")
    sc.check("a fresh REGISTER → 200", rep is not None and rep.code == 200, rep)
    if cred:
        s2 = alice.request("REGISTER", "sip:example.com", to=sent["to"], call_id=sent["call_id"], from_tag=sent["from_tag"],
                           cseq=sent["cseq"] + 1, headers={"Expires": "300", cred[0]: cred[1]})
        rep = alice.final(call_id=s2["call_id"], cseq=s2["cseq"])
        sc.check("replaying the same nonce and nc → 401 (stale), not 200", rep is not None and rep.code == 401, rep)

    # --- CANCEL is never challenged: it follows the authenticated INVITE.
    mode["ring"] = True
    p, hdr = None, None
    sent = alice.invite("sip:dest@example.com")
    ch = alice.final(method="INVITE", call_id=sent["call_id"])
    if ch is not None and ch.code == 407:
        alice._ack_neg(sent, ch)
        p, hdr = challenge_for(ch, "SHA-256")
    if p is not None:
        name, value = sipkit.credentials("alice", "secret-a", p, "INVITE", "sip:dest@example.com", hdr, "SHA-256", 1)
        s2 = alice.request("INVITE", "sip:dest@example.com", call_id=sent["call_id"], from_tag=sent["from_tag"], cseq=sent["cseq"] + 1,
                           headers={name: value}, body=sipkit.sdp(alice.port + 1000))
        ring = alice.recv(3, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == s2["call_id"])
        sc.check("authenticated INVITE rings at the upstream", ring is not None, ring)
        alice.cancel(s2)
        c = alice.recv(3, lambda m: m.is_reply and m.cseq_method == "CANCEL" and m.get("call-id") == s2["call_id"])
        rep = alice.final(4, method="INVITE", call_id=s2["call_id"], cseq=s2["cseq"])
        sc.check("CANCEL without credentials → 200 (not challenged), INVITE → 487",
                 c is not None and c.code == 200 and rep is not None and rep.code == 487, (c, rep))
        if rep is not None:
            alice._ack_neg(s2, rep)
    else:
        sc.check("authenticated INVITE rings at the upstream", False, ch)
    mode["ring"] = False

    # --- a proxy offering only SHA-256: MD5 credentials are refused.
    sc.proxy(env=sc.env(**{**px_env, "SIP_PORT": sip2, "AUTH_ALG": "SHA-256"}), name="auth-sha256")
    a2 = sc.ua("alice", sip2, password="secret-a")
    sent = a2.request("REGISTER", "sip:example.com", to=f"<{a2.aor}>", headers={"Expires": "300"})
    ch = a2.final(call_id=sent["call_id"])
    sc.check("algorithm = SHA-256 only: one challenge, SHA-256", ch is not None and [a for a, _, _ in sipkit.challenges(ch)] == ["SHA-256"],
             ch and ch.raw)
    if ch is not None:
        p = sipkit.challenges(ch)[0][1]
        name, value = sipkit.credentials("alice", "secret-a", p, "REGISTER", "sip:example.com", "www-authenticate", "MD5", 1)
        s2 = a2.request("REGISTER", "sip:example.com", to=sent["to"], call_id=sent["call_id"], from_tag=sent["from_tag"],
                        cseq=sent["cseq"] + 1, headers={"Expires": "300", name: value})
        rep = a2.final(call_id=s2["call_id"], cseq=s2["cseq"])
        sc.check("…MD5 credentials for that nonce are refused (algorithm not offered)", rep is not None and rep.code == 401, rep)
    _, rep, _, _ = attempt(a2, "REGISTER", "sip:example.com", "secret-a", "SHA-256")
    sc.check("…SHA-256 credentials → 200", rep is not None and rep.code == 200, rep)
