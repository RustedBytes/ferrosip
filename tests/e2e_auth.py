#!/usr/bin/env python3
"""End-to-end checks for digest authentication (auth module).

The client side computes digests with Python's hashlib (independent of the
proxy's implementation). Run from the repo root after `cargo build --release`.
"""
import hashlib, os, re, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PX, PX2, REALM = 5460, 5461, "example.com"
H = {"MD5": lambda s: hashlib.md5(s.encode()).hexdigest(), "SHA-256": lambda s: hashlib.sha256(s.encode()).hexdigest()}
H["SHA-512"] = lambda s: hashlib.sha512(s.encode()).hexdigest()
H["SHA-512-256"] = lambda s: hashlib.new("sha512_256", s.encode()).hexdigest()
H["MD5-sess"], H["SHA-256-sess"] = H["MD5"], H["SHA-256"]
ERIN_HA1 = H["MD5"](f"erin:{REALM}:erinpw")
USERS = f"""# test users
alice secret
bob md5:{H["MD5"](f"bob:{REALM}:bobpw")}
carol sha256:{H["SHA-256"](f"carol:{REALM}:carolpw")}
"""
CFG = """loadmodule "tm"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "textops"
loadmodule "auth"
modparam("auth", "users_file", "USERS")
modparam("auth", "nonce_expire", 2)
modparam("auth", "algorithm", "SHA-256,MD5")
modparam("auth", "username_spec", "$var(user)")
modparam("auth", "password_spec", "$var(pass)")
request_route {
    if ruri_user_prefix("has") {
        if has_credentials("example.com") { reply(200, "has credentials"); exit; }
        reply(404, "no credentials");
        exit;
    }
    if ruri_user_prefix("pv") {
        # password_spec holds an MD5 HA1 (calculate_ha1 0, the default).
        $var(user) = $fU;
        $var(pass) = "ERIN_HA1";
        if !pv_proxy_authorize("example.com") {
            if rc == -5 { proxy_challenge("example.com", 1); exit; }
            reply(403, "pv rc=$rc");
            exit;
        }
        reply(200, "pv ok");
        exit;
    }
    if ruri_user_prefix("newpv") {
        # Kamailio's pv_proxy_authenticate(realm, passwd, flags): flags 1 =
        # passwd is the HA1; 4: on failure a qop=auth challenge goes into
        # $avp(digest_challenge).
        if !pv_proxy_authenticate("example.com", "$hdr(X-Pw)", "$hdr(X-Flags)") {
            $var(rc) = $rc;
            if $var(rc) == -5 { proxy_challenge("example.com", 1); exit; }
            append_to_reply("X-Ch: $avp(digest_challenge)");
            reply(403, "pvn rc=$var(rc)");
            exit;
        }
        reply(200, "pvn ok");
        exit;
    }
    if ruri_user_prefix("chk") {
        # Kamailio's pv_auth_check(realm, passwd, flags, checks): REGISTER
        # against Authorization, else Proxy-Authorization; checks 1: identity.
        if !pv_auth_check("example.com", "$hdr(X-Pw)", "0", "$hdr(X-Checks)") {
            $var(rc) = $rc;
            if $var(rc) == -5 { auth_challenge("example.com", 1); exit; }
            reply(403, "pvc rc=$var(rc)");
            exit;
        }
        reply(200, "pvc ok");
        exit;
    }
    if ruri_user_prefix("credvars") {
        $var(nu) = "no";
        if $au == $null { $var(nu) = "au"; }
        if $adu == $null { $var(nu) = $var(nu) + ",adu"; }
        append_to_reply("X-N: $var(nu)\r\n");
        append_to_reply("X-A: au=$au ad=$ad aU=$aU ar=$ar adu=$adu aa=$aa adn=$adn adc=$adc adr=$adr ado=$ado\r\n");
        reply(200, "pvars");
        exit;
    }
    if ruri_user_prefix("getwww") {
        auth_get_www_authenticate("example.com", 1, "$var(h)");
        append_to_reply("$var(h)");
        reply(401, "Unauthorized");
        exit;
    }
    if ruri_user_prefix("flags") {
        # 1 qop=auth, 16 stale=true, 32 no algorithm=MD5.
        proxy_challenge("example.com", 49);
        exit;
    }
    if ruri_user_prefix("twice") {
        # The same credentials checked twice on one request (e.g. with and
        # without the identity check): not a replay.
        if !proxy_authorize("example.com", "subscriber") { proxy_challenge("example.com", 1); exit; }
        if !proxy_authorize("example.com", "subscriber") { reply(500, "second check failed"); exit; }
        reply(200, "twice ok");
        exit;
    }
    if ruri_user_prefix("int") {
        if !proxy_authorize("example.com", "subscriber") { proxy_challenge("example.com", 3); exit; }
        reply(200, "int ok");
        exit;
    }
    if method == "REGISTER" {
        if !auth_check("$td", "subscriber", 1) {
            if rc == -8 { reply(403, "Forbidden: auth user != To user"); exit; }
            www_challenge("$td", 1);
            exit;
        }
        consume_credentials();
        save("location");
        exit;
    }
    if !proxy_authorize("example.com", "subscriber") {
        proxy_challenge("example.com", 1);
        exit;
    }
    consume_credentials();
    if !lookup("location") { reply(404, "Not Found"); exit; }
    t_relay();
}
"""
CFG2 = """loadmodule "auth"
modparam("auth", "users_file", "USERS")
modparam("auth", "algorithm", "SHA-256-sess,MD5-sess")
modparam("auth", "qop", "auth")
modparam("auth", "one_time_nonce", 1)
modparam("auth", "realm_prefix", "sip.")
modparam("auth", "add_authinfo_hdr", 1)
modparam("auth", "username_spec", "$var(user)")
modparam("auth", "password_spec", "$var(pass)")
modparam("auth", "calculate_ha1", 1)
modparam("auth", "force_stateless_reply", 1)
modparam("auth", "use_next_nonce", 0)
request_route {
    if ruri_user_prefix("alg") {
        if !auth_algorithm("$hdr(X-Alg)") { reply(400, "alg rc=$rc"); exit; }
        if !www_authorize("", "subscriber") { www_challenge("", 0); exit; }
        reply(200, "alg ok");
        exit;
    }
    if ruri_user_prefix("pv") {
        $var(user) = $fU;
        $var(pass) = "pvsecret";
        if !pv_www_authorize("") {
            if rc == -5 { www_challenge("", 0); exit; }
            reply(403, "pv rc=$rc");
            exit;
        }
        reply(200, "pv ok");
        exit;
    }
    if ruri_user_prefix("pfx") { www_challenge("sip.example.com", 0); exit; }
    if !www_authorize("", "subscriber") {
        if rc == -6 { reply(403, "nonce reused"); exit; }
        www_challenge("", 0);
        exit;
    }
    reply(200, "ok");
}
"""
failures = 0
n = [0]


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def request(method, ruri, to_user, from_user, auth=None, port=5401, contact=None, domain=REALM, extra=""):
    n[0] += 1
    h = [f"{method} {ruri} SIP/2.0", f"Via: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bKa{n[0]}x{time.time_ns()}",
         "Max-Forwards: 70", f"From: <sip:{from_user}@{domain}>;tag=t{n[0]}", f"To: <sip:{to_user}@{domain}>",
         f"Call-ID: auth-{from_user}-{method}", f"CSeq: {n[0]} {method}"]
    if contact:
        h.append(f"Contact: {contact}")
    if auth:
        h.append(auth)
    h.extend(line for line in extra.split("\r\n") if line)
    return ("\r\n".join(h) + "\r\nContent-Length: 0\r\n\r\n").encode()


def challenges(reply, hdr="WWW-Authenticate"):
    """[(algorithm, {params})] in order."""
    out = []
    for line in re.findall(rf"^{hdr}: Digest (.*?)\r?$", reply, re.M):
        p = dict(re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', line) and
                 [(k, a or b) for k, a, b in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', line)])
        out.append((p.get("algorithm", "MD5"), p))
    return out


def creds(user, pw, ch, method, uri, alg="MD5", nc=1, hdr="Authorization", ha1=None, qop=True, realm=REALM):
    h = H[alg]
    ncs, cnonce = f"{nc:08x}", "0a4f113b"
    ha1 = ha1 or h(f"{user}:{realm}:{pw}")
    if alg.endswith("-sess"):  # RFC 7616 §3.4.2: H(H(user:realm:pw):nonce:cnonce)
        ha1 = h(f"{ha1}:{ch['nonce']}:{cnonce}")
    ha2 = h(f"{method}:{uri}")
    if qop:
        resp = h(f"{ha1}:{ch['nonce']}:{ncs}:{cnonce}:auth:{ha2}")
        extra = f', qop=auth, nc={ncs}, cnonce="{cnonce}"'
    else:
        resp, extra = h(f"{ha1}:{ch['nonce']}:{ha2}"), ""
    return (f'{hdr}: Digest username="{user}", realm="{realm}", nonce="{ch["nonce"]}", uri="{uri}", '
            f'response="{resp}", algorithm={alg}{extra}')


def main():
    users = os.path.join(ROOT, "target/e2e_users.txt")
    open(users, "w").write(USERS)
    cfg = os.path.join(ROOT, "target/e2e_auth.cfg")
    open(cfg, "w").write(CFG.replace("USERS", users).replace("ERIN_HA1", ERIN_HA1))
    open(cfg2 := os.path.join(ROOT, "target/e2e_auth2.cfg"), "w").write(CFG2.replace("USERS", users))
    sock_path = os.path.join(ROOT, "target/e2e_auth.sock")
    proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PX}", "-n", "2", "--rpc-socket", sock_path],
                             stderr=subprocess.PIPE, text=True)
    wait_listening(proxy)
    proxy2 = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg2, "-l", f"udp:127.0.0.1:{PX2}", "-n", "1"], stderr=subprocess.PIPE, text=True)
    wait_listening(proxy2)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 5401))
    s.settimeout(2)
    ua = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # alice's phone (call target)
    ua.bind(("127.0.0.1", 5402))
    ua.settimeout(2)

    def send(m, sock=s):
        sock.sendto(m, ("127.0.0.1", PX))
        return sock.recv(65535).decode()

    def status(r):
        return r.split("\r\n")[0]

    def register(user, pw=None, alg="MD5", **kw):
        r = send(request("REGISTER", "sip:example.com", user, user))
        chs = dict(challenges(r))
        if pw is None:
            return r, chs
        return send(request("REGISTER", "sip:example.com", user, user, creds(user, pw, chs[alg], "REGISTER", "sip:example.com", alg, **kw),
                            contact=f"<sip:{user}@127.0.0.1:{5402 if user == 'alice' else 5401}>")), chs[alg]

    try:
        # 1. Challenge.
        r, chs = register("alice")
        algs = [a for a, _ in challenges(r)]
        check("REGISTER without credentials → 401", status(r) == "SIP/2.0 401 Unauthorized", status(r))
        check("one challenge per algorithm, SHA-256 first (RFC 8760)", algs == ["SHA-256", "MD5"], algs)
        check("challenge has realm and qop=auth", chs["MD5"]["realm"] == REALM and chs["MD5"].get("qop") == "auth", chs)

        # 2. Successful authentication, MD5 and SHA-256.
        r, ch = register("alice", "secret", "MD5")
        check("correct MD5 credentials → 200 (registered)", status(r) == "SIP/2.0 200 OK", status(r))
        r, _ = register("alice", "secret", "SHA-256")
        check("correct SHA-256 credentials → 200", status(r) == "SIP/2.0 200 OK", status(r))

        # 3. Failures re-challenge (not stale).
        r, _ = register("alice", "wrong", "MD5")
        check("wrong password → 401, not stale", status(r).startswith("SIP/2.0 401") and "stale" not in r, r[:200])
        r, _ = register("mallory", "x", "MD5")
        check("unknown user → 401", status(r).startswith("SIP/2.0 401"), status(r))

        # 4. Stored HA1 hashes.
        r, _ = register("bob", None, "MD5", ha1=None)
        r, _ = register("bob", "bobpw", "MD5")
        check("user with stored MD5 HA1 → 200", status(r) == "SIP/2.0 200 OK", status(r))
        r, _ = register("carol", "carolpw", "SHA-256")
        check("user with stored SHA-256 HA1 → 200", status(r) == "SIP/2.0 200 OK", status(r))
        r, _ = register("carol", "carolpw", "MD5")
        check("SHA-256-only user answering with MD5 → 401", status(r).startswith("SIP/2.0 401"), status(r))

        # 5. Replay protection via nonce-count.
        r0 = send(request("REGISTER", "sip:example.com", "alice", "alice"))
        ch = dict(challenges(r0))["MD5"]
        a1 = creds("alice", "secret", ch, "REGISTER", "sip:example.com", nc=1)
        r1 = send(request("REGISTER", "sip:example.com", "alice", "alice", a1))
        r2 = send(request("REGISTER", "sip:example.com", "alice", "alice", a1))
        check("first use of nonce → 200", status(r1) == "SIP/2.0 200 OK", status(r1))
        check("replayed nc → 401 stale=true", status(r2).startswith("SIP/2.0 401") and "stale=true" in r2, r2[:300])
        a3 = creds("alice", "secret", ch, "REGISTER", "sip:example.com", nc=2)
        check("same nonce, next nc → 200", status(send(request("REGISTER", "sip:example.com", "alice", "alice", a3))) == "SIP/2.0 200 OK")

        # 6. Expired nonce → stale.
        time.sleep(2.3)
        a4 = creds("alice", "secret", ch, "REGISTER", "sip:example.com", nc=3)
        r = send(request("REGISTER", "sip:example.com", "alice", "alice", a4))
        check("expired nonce → 401 stale=true", status(r).startswith("SIP/2.0 401") and "stale=true" in r, r[:300])

        # 7. Forged nonce / wrong URI / no qop.
        r0 = send(request("REGISTER", "sip:example.com", "alice", "alice"))
        ch = dict(challenges(r0))["MD5"]
        forged = dict(ch, nonce=ch["nonce"][:40] + ("0" if ch["nonce"][40] != "0" else "1") + ch["nonce"][41:])
        r = send(request("REGISTER", "sip:example.com", "alice", "alice", creds("alice", "secret", forged, "REGISTER", "sip:example.com")))
        check("forged nonce → 401, not stale", status(r).startswith("SIP/2.0 401") and "stale" not in r, r[:200])
        r = send(request("REGISTER", "sip:example.com", "alice", "alice", creds("alice", "secret", ch, "REGISTER", "sip:other.example")))
        check("digest uri ≠ Request-URI → 401", status(r).startswith("SIP/2.0 401"), status(r))
        r = send(request("REGISTER", "sip:example.com", "alice", "alice", creds("alice", "secret", ch, "REGISTER", "sip:example.com", qop=False),
                         contact="<sip:alice@127.0.0.1:5402>"))
        check("RFC 2069-style (no qop) credentials → 200", status(r) == "SIP/2.0 200 OK", status(r))

        # 8. Identity: alice's credentials can't register bob.
        r0 = send(request("REGISTER", "sip:example.com", "bob", "alice"))
        ch = dict(challenges(r0))["MD5"]
        r = send(request("REGISTER", "sip:example.com", "bob", "alice", creds("alice", "secret", ch, "REGISTER", "sip:example.com")))
        check("auth user ≠ To user → 403 (auth_check flag 1, rc == -8)", status(r).startswith("SIP/2.0 403"), status(r))

        # 9. Proxy authentication for calls; credentials consumed before relaying.
        #    alice registers from her phone's socket (bindings route to the source).
        ch = dict(challenges(send(request("REGISTER", "sip:example.com", "alice", "alice"), sock=ua)))["MD5"]
        r = send(request("REGISTER", "sip:example.com", "alice", "alice", creds("alice", "secret", ch, "REGISTER", "sip:example.com"),
                         contact="<sip:alice@127.0.0.1:5402>"), sock=ua)
        check("alice registers from her phone", status(r) == "SIP/2.0 200 OK", status(r))
        r = send(request("MESSAGE", f"sip:alice@{REALM}", "alice", "bob"))
        pchs = dict(challenges(r, "Proxy-Authenticate"))
        check("MESSAGE without credentials → 407 + Proxy-Authenticate", status(r).startswith("SIP/2.0 407") and "MD5" in pchs, status(r))
        pa = creds("bob", "bobpw", pchs["MD5"], "MESSAGE", f"sip:alice@{REALM}", hdr="Proxy-Authorization")
        s.sendto(request("MESSAGE", f"sip:alice@{REALM}", "alice", "bob", pa), ("127.0.0.1", PX))
        d, a = ua.recvfrom(65535)
        got = d.decode()
        check("authenticated MESSAGE relayed to registered alice", got.startswith("MESSAGE sip:alice@127.0.0.1:5402 "), got[:60])
        check("Proxy-Authorization consumed (not forwarded)", "Proxy-Authorization" not in got, got)
        lines = got.split("\r\n")
        keep = [l for l in lines if l.split(":")[0] in ("Via", "From", "To", "Call-ID", "CSeq")]
        ua.sendto(("SIP/2.0 200 OK\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n").encode(), a)
        check("…and its 200 reaches bob", status(s.recv(65535).decode()) == "SIP/2.0 200 OK")

        # qop=auth-int: the body is part of HA2.
        def with_body(method, ruri, user, body, auth=None):
            n[0] += 1
            h = [f"{method} {ruri} SIP/2.0", f"Via: SIP/2.0/UDP 127.0.0.1:5401;branch=z9hG4bKi{n[0]}x{time.time_ns()}", "Max-Forwards: 70",
                 f"From: <sip:{user}@{REALM}>;tag=i{n[0]}", f"To: <{ruri}>", f"Call-ID: int-{user}", f"CSeq: {n[0]} {method}",
                 "Content-Type: text/plain"] + ([auth] if auth else [])
            return ("\r\n".join(h) + f"\r\nContent-Length: {len(body)}\r\n\r\n{body}").encode()

        def int_creds(user, pw, ch, method, uri, body, nc=1):
            h = H["MD5"]
            ha1, ha2 = h(f"{user}:{REALM}:{pw}"), h(f"{method}:{uri}:{h(body)}")
            ncs = f"{nc:08x}"
            resp = h(f"{ha1}:{ch['nonce']}:{ncs}:0a4f113b:auth-int:{ha2}")
            return (f'Proxy-Authorization: Digest username="{user}", realm="{REALM}", nonce="{ch["nonce"]}", uri="{uri}", '
                    f'response="{resp}", algorithm=MD5, qop=auth-int, nc={ncs}, cnonce="0a4f113b"')

        uri = f"sip:int@{REALM}"
        r = send(with_body("MESSAGE", uri, "bob", "hello"))
        ich = dict(challenges(r, "Proxy-Authenticate"))
        check("challenge flags 3 → qop=\"auth-int\" (2 wins, as in Kamailio)", 'qop="auth-int"' in r and "MD5" in ich, r)
        r = send(with_body("MESSAGE", uri, "bob", "hello", int_creds("bob", "bobpw", ich["MD5"], "MESSAGE", uri, "hello")))
        check("qop=auth-int with the body hashed into HA2 → accepted", status(r) == "SIP/2.0 200 int ok", status(r))
        r = send(with_body("MESSAGE", uri, "bob", "HELLO", int_creds("bob", "bobpw", ich["MD5"], "MESSAGE", uri, "hello", nc=2)))
        check("…a changed body fails (new challenge)", status(r).startswith("SIP/2.0 407"), status(r))

        # Two checks of the same credentials on one request.
        tw = f"sip:twice@{REALM}"
        r = send(with_body("MESSAGE", tw, "bob", "x"))
        tch = dict(challenges(r, "Proxy-Authenticate"))["MD5"]
        r = send(with_body("MESSAGE", tw, "bob", "x", creds("bob", "bobpw", tch, "MESSAGE", tw, hdr="Proxy-Authorization")))
        check("the same credentials checked twice on one request: both pass (not a replay)", status(r) == "SIP/2.0 200 twice ok", status(r))

        # auth.reload: users_file re-read at run time.
        r = send(with_body("MESSAGE", uri, "dave", "x"))
        dch = dict(challenges(r, "Proxy-Authenticate"))["MD5"]
        r = send(with_body("MESSAGE", uri, "dave", "x", int_creds("dave", "davepw", dch, "MESSAGE", uri, "x")))
        before = status(r)
        open(users, "a").write("dave davepw\n")
        out = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", sock_path, "auth.reload"], capture_output=True, text=True).stdout.strip()
        r = send(with_body("MESSAGE", uri, "dave", "x"))
        dch = dict(challenges(r, "Proxy-Authenticate"))["MD5"]
        r = send(with_body("MESSAGE", uri, "dave", "x", int_creds("dave", "davepw", dch, "MESSAGE", uri, "x")))
        check("RPC auth.reload: a user added to users_file can authenticate", before.startswith("SIP/2.0 407") and out == "4"
              and status(r) == "SIP/2.0 200 int ok", (before, out, status(r)))

        # -sess algorithms (RFC 7616): accepted when their hash is configured.
        for alg, base in (("MD5-sess", "MD5"), ("SHA-256-sess", "SHA-256")):
            r0 = send(request("REGISTER", "sip:example.com", "alice", "alice"))
            ch = dict(challenges(r0))[base]
            r = send(request("REGISTER", "sip:example.com", "alice", "alice", creds("alice", "secret", ch, "REGISTER", "sip:example.com", alg),
                             contact="<sip:alice@127.0.0.1:5402>"))
            check(f"{alg} credentials (password) → 200", status(r) == "SIP/2.0 200 OK", status(r))
        r, _ = register("bob", "bobpw", "MD5")
        ch = dict(challenges(send(request("REGISTER", "sip:example.com", "bob", "bob"))))["MD5"]
        r = send(request("REGISTER", "sip:example.com", "bob", "bob", creds("bob", "bobpw", ch, "REGISTER", "sip:example.com", "MD5-sess")))
        check("MD5-sess with a stored MD5 HA1 → 200", status(r) == "SIP/2.0 200 OK", status(r))
        ch = dict(challenges(send(request("REGISTER", "sip:example.com", "carol", "carol"))))["SHA-256"]
        r = send(request("REGISTER", "sip:example.com", "carol", "carol", creds("carol", "carolpw", ch, "REGISTER", "sip:example.com", "SHA-256-sess")))
        check("SHA-256-sess with a stored SHA-256 HA1 → 200", status(r) == "SIP/2.0 200 OK", status(r))
        ch = dict(challenges(send(request("REGISTER", "sip:example.com", "alice", "alice"))))["MD5"]
        a = creds("alice", "secret", ch, "REGISTER", "sip:example.com", "MD5-sess", qop=False).replace('"0a4f113b"', "")
        r = send(request("REGISTER", "sip:example.com", "alice", "alice", a))
        check("MD5-sess without a cnonce → 401", status(r).startswith("SIP/2.0 401"), status(r))

        # has_credentials(realm).
        hu = f"sip:has@{REALM}"
        r = send(request("MESSAGE", hu, "has", "bob"))
        check("has_credentials: none → false", status(r) == "SIP/2.0 404 no credentials", status(r))
        fake = 'Authorization: Digest username="bob", realm="other.org", nonce="x", uri="sip:has@example.com", response="y"'
        r = send(request("MESSAGE", hu, "has", "bob", fake))
        check("has_credentials: only another realm's → false", status(r) == "SIP/2.0 404 no credentials", status(r))
        r = send(request("MESSAGE", hu, "has", "bob", fake.replace("Authorization", "Proxy-Authorization").replace("other.org", REALM)))
        check("has_credentials: Proxy-Authorization for the realm → true", status(r) == "SIP/2.0 200 has credentials", status(r))
        r = send(request("MESSAGE", hu, "has", "bob", fake.replace("other.org", REALM)))
        check("has_credentials: Authorization for the realm → true", status(r) == "SIP/2.0 200 has credentials", status(r))

        # pv_proxy_authorize: user and HA1 from username_spec / password_spec.
        pu = f"sip:pv@{REALM}"
        r = send(request("MESSAGE", pu, "pv", "erin"))
        pch = dict(challenges(r, "Proxy-Authenticate"))
        check("pv_proxy_authorize without credentials → -5 → 407", status(r).startswith("SIP/2.0 407") and "MD5" in pch, status(r))
        r = send(request("MESSAGE", pu, "pv", "erin", creds("erin", "erinpw", pch["MD5"], "MESSAGE", pu, hdr="Proxy-Authorization")))
        check("pv_proxy_authorize: password_spec holds the HA1 → 200", status(r) == "SIP/2.0 200 pv ok", status(r))
        r = send(request("MESSAGE", pu, "pv", "erin", creds("erin", "nope", pch["MD5"], "MESSAGE", pu, nc=2, hdr="Proxy-Authorization")))
        check("pv_proxy_authorize: wrong password → -2", status(r) == "SIP/2.0 403 pv rc=-2", status(r))
        r = send(request("MESSAGE", pu, "pv", "erin", creds("zed", "erinpw", pch["MD5"], "MESSAGE", pu, nc=3, hdr="Proxy-Authorization")))
        check("pv_proxy_authorize: credentials user ≠ username_spec → -3", status(r) == "SIP/2.0 403 pv rc=-3", status(r))
        r = send(request("MESSAGE", pu, "pv", "erin", creds("erin", "erinpw", pch["SHA-256"], "MESSAGE", pu, "SHA-256", hdr="Proxy-Authorization")))
        check("pv_proxy_authorize: SHA-256 answer to an MD5 HA1 → -2", status(r) == "SIP/2.0 403 pv rc=-2", status(r))
        r = send(request("MESSAGE", pu, "pv", "erin", creds("erin", "erinpw", pch["MD5"], "MESSAGE", pu, nc=4, hdr="Proxy-Authorization")))
        check("pv_proxy_authorize: the same nonce with the next nc → 200", status(r) == "SIP/2.0 200 pv ok", status(r))
        r = send(request("MESSAGE", pu, "pv", "erin", creds("erin", "erinpw", pch["MD5"], "MESSAGE", pu, nc=4, hdr="Proxy-Authorization")))
        check("pv_proxy_authorize: repeated nc → -4 (stale, as Kamailio's nonce_count)", status(r) == "SIP/2.0 403 pv rc=-4", status(r))

        # pv_proxy_authenticate(realm, passwd, flags), Kamailio's API.
        nu = f"sip:newpv@{REALM}"
        r = send(request("MESSAGE", nu, "newpv", "erin", extra="X-Pw: x\r\nX-Flags: 0\r\n"))
        nch = dict(challenges(r, "Proxy-Authenticate"))
        check("pv_proxy_authenticate without credentials → -5 → 407", status(r).startswith("SIP/2.0 407") and "MD5" in nch, status(r))
        a = creds("erin", "erinpw", nch["MD5"], "MESSAGE", nu, hdr="Proxy-Authorization")
        r = send(request("MESSAGE", nu, "newpv", "erin", a, extra=f"X-Pw: {ERIN_HA1}\r\nX-Flags: 1\r\n"))
        check("pv_proxy_authenticate(realm, HA1, 1) → 200", status(r) == "SIP/2.0 200 pvn ok", status(r))
        a = creds("erin", "erinpw", nch["MD5"], "MESSAGE", nu, nc=2, hdr="Proxy-Authorization")
        r = send(request("MESSAGE", nu, "newpv", "erin", a, extra="X-Pw: erinpw\r\nX-Flags: 0\r\n"))
        check("pv_proxy_authenticate(realm, password, 0) → 200", status(r) == "SIP/2.0 200 pvn ok", status(r))
        a = creds("erin", "erinpw", nch["MD5"], "MESSAGE", nu, nc=3, hdr="Proxy-Authorization")
        r = send(request("MESSAGE", nu, "newpv", "erin", a, extra="X-Pw: wrong\r\nX-Flags: 4\r\n"))
        check("…wrong password → -2, flags 4: a qop=auth challenge in $avp(digest_challenge)", status(r) == "SIP/2.0 403 pvn rc=-2"
              and re.search(r'^X-Ch: Proxy-Authenticate: Digest realm="example.com", nonce="[0-9a-f]+", qop="auth"', r, re.M) is not None, r)

        # pv_auth_check(realm, passwd, flags, checks).
        cu = f"sip:chk@{REALM}"
        r = send(request("MESSAGE", cu, "pvc", "erin", extra="X-Pw: erinpw\r\nX-Checks: 1\r\n"))
        cch = dict(challenges(r, "Proxy-Authenticate"))
        check("pv_auth_check: MESSAGE without credentials → -5 → 407", status(r).startswith("SIP/2.0 407") and "MD5" in cch, status(r))
        a = creds("erin", "erinpw", cch["MD5"], "MESSAGE", cu, hdr="Proxy-Authorization")
        r = send(request("MESSAGE", cu, "pvc", "erin", a, extra="X-Pw: erinpw\r\nX-Checks: 1\r\n"))
        check("pv_auth_check: Proxy-Authorization, user = From user → 200", status(r) == "SIP/2.0 200 pvc ok", status(r))
        a = creds("erin", "erinpw", cch["MD5"], "MESSAGE", cu, nc=2, hdr="Proxy-Authorization")
        r = send(request("MESSAGE", cu, "pvc", "frank", a, extra="X-Pw: erinpw\r\nX-Checks: 1\r\n"))
        check("pv_auth_check checks 1: credentials user ≠ From user → -8", status(r) == "SIP/2.0 403 pvc rc=-8", status(r))
        a = creds("erin", "erinpw", cch["MD5"], "MESSAGE", cu, nc=3, hdr="Proxy-Authorization")
        r = send(request("MESSAGE", cu, "pvc", "frank", a, extra="X-Pw: erinpw\r\nX-Checks: 0\r\n"))
        check("…checks 0: no identity check → 200", status(r) == "SIP/2.0 200 pvc ok", status(r))
        a = creds("erin", "erinpw", cch["MD5"], "MESSAGE", cu, nc=4, hdr="Proxy-Authorization")
        r = send(request("MESSAGE", cu, "pvc", "erin", a, extra="X-Pw: wrong\r\nX-Checks: 1\r\n"))
        check("…wrong password → -2", status(r) == "SIP/2.0 403 pvc rc=-2", status(r))
        r = send(request("REGISTER", cu, "erin", "erin", extra="X-Pw: erinpw\r\nX-Checks: 1\r\n"))
        rch = dict(challenges(r))
        check("pv_auth_check: REGISTER without credentials → 401 (Authorization)", status(r).startswith("SIP/2.0 401") and "MD5" in rch, status(r))
        a = creds("erin", "erinpw", rch["MD5"], "REGISTER", cu)
        r = send(request("REGISTER", cu, "erin", "erin", a, extra="X-Pw: erinpw\r\nX-Checks: 1\r\n"))
        check("pv_auth_check: REGISTER, user = To user = From user → 200", status(r) == "SIP/2.0 200 pvc ok", status(r))
        a = creds("erin", "erinpw", rch["MD5"], "REGISTER", cu, nc=2)
        r = send(request("REGISTER", cu, "erin", "frank", a, extra="X-Pw: erinpw\r\nX-Checks: 1\r\n"))
        check("pv_auth_check: REGISTER with From user ≠ To user → -8", status(r) == "SIP/2.0 403 pvc rc=-8", status(r))
        a = creds("erin", "erinpw", rch["MD5"], "REGISTER", cu, nc=3, hdr="Proxy-Authorization")
        r = send(request("REGISTER", cu, "erin", "erin", a, extra="X-Pw: erinpw\r\nX-Checks: 1\r\n"))
        check("pv_auth_check: REGISTER with only Proxy-Authorization → -5", status(r).startswith("SIP/2.0 401"), status(r))

        # Credentials variables $au $ad $aU $ar $adu $aa $adn $adc $adr $ado.
        vu = f"sip:credvars@{REALM}"
        pa = ('Proxy-Authorization: Digest username="joe@example.org", realm="r.example", nonce="n1", uri="sip:credvars@example.com", '
              'response="abc", opaque="op,q", cnonce="cn", nc=00000001, qop=auth, algorithm=SHA-256')
        r = send(request("MESSAGE", vu, "pvars", "joe", pa, extra='Authorization: Digest username="other", realm="x", nonce="z", response="w"'))
        xa = re.search(r"^X-A: (.*?)\r?$", r, re.M)
        check("credentials variables from Proxy-Authorization (before Authorization)", xa is not None and xa.group(1) ==
              "au=joe ad=example.org aU=joe@example.org ar=r.example adu=sip:credvars@example.com aa=SHA-256 adn=n1 adc=cn adr=abc ado=op,q", r)
        r = send(request("MESSAGE", vu, "pvars", "joe", 'Authorization: Digest username="ann", realm="x", nonce="z", response="w"'))
        xa = re.search(r"^X-A: (.*?)\r?$", r, re.M)
        check("…from Authorization; absent fields empty, empty $adu null", xa is not None and xa.group(1) ==
              "au=ann ad= aU=ann ar=x adu= aa= adn=z adc= adr=w ado=" and "X-N: no,adu\r\n" in r, r)
        r = send(request("MESSAGE", vu, "pvars", "joe"))
        xa = re.search(r"^X-A: (.*?)\r?$", r, re.M)
        check("…no credentials: null", xa is not None and "X-N: au,adu\r\n" in r, r)

        # auth_get_www_authenticate into a variable (here appended to a reply).
        r = send(request("MESSAGE", f"sip:getwww@{REALM}", "getwww", "alice"))
        gch = dict(challenges(r))
        check("auth_get_www_authenticate: one header per algorithm, qop=auth", list(gch) == ["SHA-256", "MD5"]
              and gch["MD5"]["realm"] == REALM and gch["MD5"].get("qop") == "auth" and "stale" not in r, r)
        r = send(request("REGISTER", "sip:example.com", "alice", "alice", creds("alice", "secret", gch["MD5"], "REGISTER", "sip:example.com"),
                         contact="<sip:alice@127.0.0.1:5402>"))
        check("…its nonce authenticates a REGISTER", status(r) == "SIP/2.0 200 OK", status(r))

        # Challenge flags 16 (stale=true) and 32 (no algorithm=MD5).
        r = send(request("MESSAGE", f"sip:flags@{REALM}", "flags", "alice"))
        lines = re.findall(r"^Proxy-Authenticate: (.*?)\r?$", r, re.M)
        check("challenge flags 16|32: stale=true, MD5 without algorithm=", len(lines) == 2 and all("stale=true" in l and 'qop="auth"' in l for l in lines)
              and "algorithm=SHA-256" in lines[0] and "algorithm" not in lines[1], lines)

        # Second proxy: -sess offered, qop parameter, one_time_nonce,
        # realm_prefix, add_authinfo_hdr, calculate_ha1 for pv_www_authorize.
        sd = "sip.example.com"

        def send2(m):
            s.sendto(m, ("127.0.0.1", PX2))
            return s.recv(65535).decode()

        def reg2(user, ruri=f"sip:{sd}", a=None):
            return send2(request("REGISTER", ruri, user, user, a, domain=sd))

        r = reg2("alice")
        c2 = challenges(r)
        check("algorithm=SHA-256-sess,MD5-sess: both offered, in order", [a for a, _ in c2] == ["SHA-256-sess", "MD5-sess"], c2)
        check("realm \"\" → To host without realm_prefix \"sip.\"", all(p["realm"] == REALM for _, p in c2), c2)
        check("qop parameter: challenges with flags 0 still offer no qop (only the flags choose it)", all("qop" not in p for _, p in c2), c2)
        c2 = dict(c2)
        a1 = creds("alice", "secret", c2["MD5-sess"], "REGISTER", f"sip:{sd}", "MD5-sess")
        r = reg2("alice", a=a1)
        check("MD5-sess credentials → 200", status(r) == "SIP/2.0 200 ok", status(r))
        ai = re.search(r'^Authentication-Info: qop=auth, rspauth="([0-9a-f]+)", cnonce="0a4f113b", nc=00000001\r?$', r, re.M)
        h = H["MD5"]
        ha1 = h(f"{h(f'alice:{REALM}:secret')}:{c2['MD5-sess']['nonce']}:0a4f113b")
        want = h(f"{ha1}:{c2['MD5-sess']['nonce']}:00000001:0a4f113b:auth:{h(f':sip:{sd}')}")
        check("add_authinfo_hdr: Authentication-Info with the right rspauth", ai is not None and ai.group(1) == want, (r, want))
        r = reg2("alice", a=creds("alice", "secret", c2["MD5-sess"], "REGISTER", f"sip:{sd}", "MD5-sess", nc=2))
        check("one_time_nonce: the same nonce again (next nc) → -6", status(r) == "SIP/2.0 403 nonce reused", status(r))
        r = reg2("alice", a=creds("alice", "secret", c2["SHA-256-sess"], "REGISTER", f"sip:{sd}", "SHA-256-sess"))
        check("SHA-256-sess credentials → 200", status(r) == "SIP/2.0 200 ok", status(r))
        r = send2(request("REGISTER", f"sip:pfx@{sd}", "alice", "alice", domain=sd))
        check("realm_prefix is stripped from a realm given as an argument too", [p["realm"] for _, p in challenges(r)] == [REALM, REALM], r)
        r = send2(request("REGISTER", f"sip:pv@{sd}", "frank", "frank", domain=sd))
        fch = dict(challenges(r))
        r = send2(request("REGISTER", f"sip:pv@{sd}", "frank", "frank", creds("frank", "pvsecret", fch["MD5-sess"], "REGISTER", f"sip:pv@{sd}", "MD5-sess"), domain=sd))
        check("pv_www_authorize with calculate_ha1=1 (plain password in password_spec) → 200", status(r) == "SIP/2.0 200 pv ok", status(r))
        r = send2(request("REGISTER", f"sip:pv@{sd}", "frank", "frank", creds("frank", "bad", fch["SHA-256-sess"], "REGISTER", f"sip:pv@{sd}", "SHA-256-sess"), domain=sd))
        check("…wrong password → -2", status(r) == "SIP/2.0 403 pv rc=-2", status(r))

        # auth_algorithm(alg): challenges and credentials without algorithm=
        # use it from now on (last: it replaces the algorithm parameter).
        au = f"sip:alg@{sd}"
        r = send2(request("REGISTER", au, "alice", "alice", domain=sd, extra="X-Alg: sha-512\r\n"))
        check("auth_algorithm: unknown (case-sensitive) name → -1", status(r) == "SIP/2.0 400 alg rc=-1", status(r))
        for alg in ("SHA-512", "SHA-512-256"):
            r = send2(request("REGISTER", au, "alice", "alice", domain=sd, extra=f"X-Alg: {alg}\r\n"))
            ach = challenges(r)
            check(f"auth_algorithm(\"{alg}\"): one challenge, algorithm={alg}", [a for a, _ in ach] == [alg], r)
            a = creds("alice", "secret", ach[0][1], "REGISTER", au, alg).replace(f", algorithm={alg}", "")
            r = send2(request("REGISTER", au, "alice", "alice", a, domain=sd, extra=f"X-Alg: {alg}\r\n"))
            check(f"…{alg} credentials without algorithm= → 200", status(r) == "SIP/2.0 200 alg ok", status(r))
    finally:
        proxy.terminate()
        err = proxy.communicate(timeout=5)[1]
        check("no panics in proxy log", "panic" not in err, err)
        proxy2.terminate()
        err = proxy2.communicate(timeout=5)[1]
        check("no panics in second proxy log", "panic" not in err, err)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
