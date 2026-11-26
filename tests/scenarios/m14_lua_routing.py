"""m14-lua-routing: Lua (app_lua, `lua.run`) makes the routing decision:
it reads the message through KSR, sets headers, sets $du or rejects.
Lua errors, a missing Lua function, a false return, reloading the script
(and editing it without a reload), per-worker Lua state, and UTF-8 in
headers."""
import os
import re
import shutil
import subprocess
import time

import sipkit


def send_invite(ua, ruri, display=None, headers=None):
    """An INVITE with a From display name (UA.request can't write one);
    the sent-request dict, as UA.request returns it (for Dialog/_ack_neg)."""
    branch, cid, ftag = sipkit.rnd(12), f"{sipkit.rnd(10)}@127.0.0.1", sipkit.rnd(8)
    to = f"<{ruri}>"
    frm = (f"{display} " if display else "") + f"<{ua.aor}>;tag={ftag}"
    body = sipkit.sdp(ua.port + 1000)
    hs = [f"Via: {ua.via(branch)}", f"From: {frm}", f"To: {to}", f"Call-ID: {cid}", "CSeq: 1 INVITE",
          "Max-Forwards: 70", f"Contact: <{ua.contact}>"]
    hs += [f"{k}: {v}" for k, v in (headers or {}).items()]
    hs += ["Content-Type: application/sdp", f"Content-Length: {len(body.encode())}"]
    raw = f"INVITE {ruri} SIP/2.0\r\n" + "\r\n".join(hs) + "\r\n\r\n" + body
    ua.send(raw)
    return {"method": "INVITE", "ruri": ruri, "branch": branch, "call_id": cid, "from_tag": ftag, "cseq": 1,
            "to": to, "raw": raw, "headers": headers or {}, "body": body}


def call(ua, ruri, display=None, headers=None, timeout=6):
    """(final reply, call-id); a 2xx is ACKed and hung up."""
    sent = send_invite(ua, ruri, display, headers)
    r = ua.final(timeout, method="INVITE", call_id=sent["call_id"], cseq=1)
    if r is not None and r.code >= 300:
        ua._ack_neg(sent, r)
    elif r is not None:
        d = sipkit.Dialog(ua, sent, r)
        d.ack()
        d.bye()
    return r, sent["call_id"]


def invite_at(u, cid):
    return next((m for m in u.received if m.method == "INVITE" and m.get("call-id") == cid), None)


def run(sc):
    sip = sc.port()
    pbx = sc.ua("pbx", sip).auto_answer()
    gw = sc.ua("gw", sip).auto_answer()
    # The proxy runs on a copy of the Lua script, so the test can edit it.
    lua_path = os.path.join(sc.tmp, "route.lua")
    src = open(os.path.join(sc.dir, "routes", "route.lua")).read()
    shutil.copy(os.path.join(sc.dir, "routes", "route.lua"), lua_path)
    px = sc.proxy(env=sc.env(SIP_PORT=sip, LUA_SCRIPT=lua_path, PBX=f"sip:127.0.0.1:{pbx.port}", GATEWAY=f"sip:127.0.0.1:{gw.port}"))
    ua = sc.ua("alice", sip)

    # --- The script file changes on disk, without a reload. app_lua loaded
    # it "into every worker's Lua state at startup" (crates/mod-lua/README.md;
    # Kamailio loads it in each child at child_init): the running routing must
    # not change until app_lua.reload. Done before any Lua call.
    open(lua_path, "w").write(src.replace('VERSION = "v1"', 'VERSION = "edited-no-reload"'))
    seen = []
    for _ in range(4):
        r, cid = call(ua, "sip:sales@example.com")
        inv = invite_at(pbx, cid)
        seen.append(inv.get("x-lua-version") if inv else (r.code if r else None))
    sc.check("script edited on disk without app_lua.reload → calls still run the loaded v1", seen == ["v1"] * 4, seen)
    open(lua_path, "w").write(src)

    # --- Lua picks the target and stamps headers.
    r, cid = call(ua, "sip:sales@example.com")
    inv = invite_at(pbx, cid)
    sc.check("sales → Lua sets $du to the PBX: 200, the gateway not tried",
             r is not None and r.code == 200 and inv is not None and invite_at(gw, cid) is None, r)
    sc.check("…the INVITE carries X-Lua-Route: pbx, set from Lua with KSR.hdr.append",
             inv is not None and inv.get("x-lua-route") == "pbx", inv and inv.raw)
    sc.check("…and the Record-Route the .fsr added before lua.run",
             inv is not None and len(inv.all("record-route")) == 1, inv and inv.all("record-route"))

    r, cid = call(ua, "sip:+4930123456@example.com")
    inv = invite_at(gw, cid)
    sc.check("+4930123456 → a number: Lua routes it to the gateway, X-Lua-Route: gateway",
             r is not None and r.code == 200 and inv is not None and inv.get("x-lua-route") == "gateway", (r, inv and inv.raw))

    r, cid = call(ua, "sip:nobody@example.com")
    sc.check("unknown user → Lua answers 404 No route in Lua (sl_send_reply + KSR.x.exit)",
             r is not None and r.code == 404 and r.reason == "No route in Lua", r)
    sc.check("…nothing relayed", invite_at(pbx, cid) is None and invite_at(gw, cid) is None)

    spam = sc.ua("spammer", sip)
    r, cid = call(spam, "sip:sales@example.com")
    sc.check("From spammer → Lua reads $fU and answers 403 Blocked by Lua",
             r is not None and r.code == 403 and r.reason == "Blocked by Lua" and invite_at(pbx, cid) is None, r)

    r, cid = call(ua, "sip:anything@example.com", headers={"X-Tenant": "acme"})
    inv = invite_at(pbx, cid)
    sc.check("X-Tenant: acme → the .fsr calls route_acme: to the PBX with X-Lua-Route: acme-pbx",
             r is not None and r.code == 200 and inv is not None and inv.get("x-lua-route") == "acme-pbx", (r, inv and inv.raw))

    # --- Failures in Lua: the proxy answers, and keeps working.
    for user, what in (("boom", "error()"), ("nilindex", "indexing nil"), ("badksr", "an unknown KSR function")):
        r, cid = call(ua, f"sip:{user}@example.com")
        sc.check(f"Lua runtime error ({what}) → 500 Lua routing failed, nothing relayed",
                 r is not None and r.code == 500 and r.reason == "Lua routing failed"
                 and invite_at(pbx, cid) is None and invite_at(gw, cid) is None, r)
    r, cid = call(ua, "sip:anything@example.com", headers={"X-Tenant": "ghost"})
    sc.check("X-Tenant: ghost → route_ghost doesn't exist in Lua: 500, no crash",
             r is not None and r.code == 500 and invite_at(pbx, cid) is None, r)
    r, cid = call(ua, "sip:anything@example.com", headers={"X-Tenant": "closed"})
    sc.check("X-Tenant: closed → route_closed returns false: 500", r is not None and r.code == 500 and invite_at(pbx, cid) is None, r)
    r, cid = call(ua, "sip:anything@example.com", headers={"X-Tenant": "os.exit"})
    sc.check("X-Tenant: os.exit (not letters) → 400 before any Lua", r is not None and r.code == 400, r)
    r, cid = call(ua, "sip:support@example.com")
    sc.check("…after all those errors the next call is routed by Lua as usual: 200",
             r is not None and r.code == 200 and invite_at(pbx, cid) is not None, r)
    sc.check("the proxy process is still running", px.p.poll() is None)

    # --- UTF-8 through Lua: the display name (a lua.run argument) and a
    # header read with KSR.pv.get, written back with KSR.hdr.append.
    name = "Jürgen Müller 日本"
    note = "café ☕ ünïcödé"
    r, cid = call(ua, "sip:sales@example.com", display=f'"{name}"', headers={"X-Note": note})
    inv = invite_at(pbx, cid)
    got = inv.get("x-caller-name") if inv else None
    sc.check("UTF-8 display name → X-Caller-Name holds it intact (no U+FFFD)",
             got is not None and name in got and "�" not in got, got)
    nbytes = inv.get("x-caller-name-bytes") if inv else None
    sc.check("…Lua's #display counts the UTF-8 bytes of what it got",
             got is not None and nbytes == str(len(got.encode())), (got, nbytes))
    echo = inv.get("x-note-echo") if inv else None
    sc.check("UTF-8 header read with KSR.pv.get and appended back: intact, byte length right",
             echo == f"{note} ({len(note.encode())} bytes)", echo)
    raw_len = int(inv.get("content-length")) if inv else -1
    sc.check("…Content-Length of the relayed INVITE still matches its body",
             inv is not None and raw_len == len(inv.body.encode()), (raw_len, inv and len(inv.body.encode())))

    # --- Per-worker Lua state: each state counts its own calls. UDP
    # workers share the port with SO_REUSEPORT, so a source address always
    # hits the same worker: calls from 12 sources reach both workers (all
    # on one: about 1 in 2000). Sequential calls: within one state the
    # counter goes up by exactly one per call; no counter is shared.
    phones = [sc.ua(f"phone{i}", sip) for i in range(12)]
    obs = []
    for _ in range(2):
        for p in phones:
            r, cid = call(p, "sip:sales@example.com")
            inv = invite_at(pbx, cid)
            if inv is not None:
                obs.append((p.port, inv.get("x-lua-state"), int(inv.get("x-lua-count") or 0)))
    by, src_states = {}, {}
    for port, st, n in obs:
        by.setdefault(st, []).append(n)
        src_states.setdefault(port, set()).add(st)
    sc.check("24 calls from 12 sources, each stamped with its Lua state and that state's counter",
             len(obs) == 24 and all(st for _, st, _ in obs), obs)
    sc.check("…within one Lua state the counter goes up by exactly one per call (sequential calls)",
             all(all(b - a == 1 for a, b in zip(v, v[1:])) for v in by.values()), by)
    sc.check("…two Lua states, one per UDP worker (workers = 2): globals are not shared", len(by) == 2, {k: len(v) for k, v in by.items()})
    sc.check("…a source always meets the same Lua state (its worker)", all(len(s) == 1 for s in src_states.values()), src_states)

    # --- Reload: a new version of the script, then a broken one.
    open(lua_path, "w").write(src.replace('VERSION = "v1"', 'VERSION = "v2"'))
    rr = px.rpc("app_lua.reload")
    sc.check("app_lua.reload of a valid script → the new generation number", isinstance(rr, int) and rr >= 1, rr)
    vers, counts = set(), []
    for _ in range(6):
        r, cid = call(ua, "sip:sales@example.com")
        inv = invite_at(pbx, cid)
        vers.add(inv.get("x-lua-version") if inv else None)
        counts.append(int(inv.get("x-lua-count") or 0) if inv else -1)
    sc.check("…every call after the reload runs v2", vers == {"v2"}, vers)
    sc.check("…in fresh Lua states: the per-worker counters started again from 1", min(counts) == 1, counts)

    open(lua_path, "w").write(src.replace('VERSION = "v1"', 'VERSION = "v3"') + "\nfunction broken(\n")
    rr = subprocess.run([sipkit.CTL, "-s", px.env["RPC_SOCK"], "app_lua.reload"], capture_output=True, text=True, timeout=10)
    sc.check("app_lua.reload of a script with a syntax error → refused (an error from ferroctl)",
             rr.returncode != 0 or "error" in (rr.stdout + rr.stderr).lower(), rr.stdout + rr.stderr)
    vers = set()
    for _ in range(4):
        r, cid = call(ua, "sip:sales@example.com")
        inv = invite_at(pbx, cid)
        vers.add(inv.get("x-lua-version") if inv else (r.code if r else None))
    sc.check("…and calls keep running v2", vers == {"v2"}, vers)
    log = "".join(px.lines)
    sc.check("the Lua errors were logged with their message",
             "deliberate error for boom" in log and re.search(r"app_lua: .*route_ghost|app_lua: .*nil", log) is not None, log[-1500:])
    time.sleep(0.1)
