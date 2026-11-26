"""s08-feature-overlays: one routing under envs/dev.toml and envs/prod.toml
(and --set over both); behaviour and timers follow the overlay."""
import os
import subprocess
import time

import sipkit


def explain(sc, *extra):
    env = {**os.environ, "RPC_SOCK": os.path.join(sc.tmp, "explain.sock")}
    r = subprocess.run([sipkit.BIN, "check", "--config", "ferrosip.toml", *extra, "--explain"], capture_output=True, text=True,
                       env=env, cwd=sc.dir, timeout=60)
    return r.returncode, r.stdout + r.stderr


def line(out, key):
    """`key = value  # source` of the effective configuration, normalised."""
    for l in out.splitlines():
        if l.startswith(key + " = "):
            v, _, src = l.partition("#")
            return v.split("=", 1)[1].strip(), src.strip()
    return None


def upstream(sc, sip):
    up = sc.ua("upstream", sip)
    up.handler = lambda m: None if m.method == "ACK" or m.get("x-silent") else (200, "OK")
    return up


def at(up, cid):
    ms = [m for m in up.received if m.get("call-id") == cid]
    return ms[0] if ms else None


def silent_408(ua, ua_auth=False):
    """A MESSAGE the upstream never answers: (final reply, seconds)."""
    t0 = time.time()
    sent = ua.request("MESSAGE", "sip:bob@example.com", body="x", content_type="text/plain", headers={"X-Silent": "1"})
    rep = ua.final(6, call_id=sent["call_id"])
    if ua_auth and rep is not None and rep.code == 407:
        t0 = time.time()
        rep, _ = ua.with_auth(sent, rep)
        if rep is not None and rep.code < 200:
            rep = None
    return rep, time.time() - t0


def run(sc):
    # --- the effective configuration of each environment, with sources.
    rc, out = explain(sc, "--overlay", "envs/prod.toml")
    sc.check("check --explain with envs/prod.toml succeeds", rc == 0, out[-600:])
    sc.check("prod: fr_timer 3s from envs/prod.toml", line(out, "modules.txn.fr_timer") == ('"3s"', "envs/prod.toml"), line(out, "modules.txn.fr_timer"))
    sc.check("prod: log_level notice and workers 4 from envs/prod.toml",
             line(out, "core.log_level") == ('"notice"', "envs/prod.toml") and line(out, "core.workers") == ("4", "envs/prod.toml"), out[:600])
    sc.check("prod: require_auth stays the base's true (tables merge)", line(out, "feature.require_auth") == ("true", "ferrosip.toml"),
             line(out, "feature.require_auth"))
    rc, out = explain(sc, "--overlay", "envs/dev.toml")
    sc.check("dev: require_auth false and fr_timer 1s from envs/dev.toml",
             line(out, "feature.require_auth") == ("false", "envs/dev.toml") and line(out, "modules.txn.fr_timer") == ('"1s"', "envs/dev.toml"),
             out[:800])
    rc, out = explain(sc, "--overlay", "envs/dev.toml", "--overlay", "envs/prod.toml")
    sc.check("two overlays: the later wins (dev then prod → fr_timer 3s, but dev's require_auth=false is kept)",
             line(out, "modules.txn.fr_timer") == ('"3s"', "envs/prod.toml") and line(out, "feature.require_auth") == ("false", "envs/dev.toml"),
             out[:800])
    rc, out = explain(sc, "--overlay", "envs/prod.toml", "--set", "feature.env_name=staging")
    sc.check("--set wins over the overlay", line(out, "feature.env_name") == ('"staging"', "--set"), line(out, "feature.env_name"))

    # A broken overlay (written to the temp dir): refused, with the reason.
    bad = os.path.join(sc.tmp, "bad.toml")
    with open(bad, "w") as f:
        f.write('[modules.txn]\nfr_timr = "1s"\n')
    rc, out = explain(sc, "--overlay", bad)
    sc.check("an overlay with a misspelt key is refused, with a did-you-mean", rc != 0 and "fr_timer" in out, out[-400:])
    with open(bad, "w") as f:
        f.write('[modules.txn]\nfr_timer = "soon"\n')
    rc, out = explain(sc, "--overlay", bad)
    sc.check("an overlay with a value of the wrong type is refused", rc != 0 and "fr_timer" in out, out[-400:])
    rc, out = explain(sc, "--overlay", os.path.join(sc.tmp, "missing.toml"))
    sc.check("a missing overlay file is an error, not silently ignored", rc != 0, out[-400:])

    # --- the two environments, live.
    dev_port, prod_port, stg_port = sc.port(), sc.port(), sc.port()
    dev_up = upstream(sc, dev_port)
    prod_up = upstream(sc, prod_port)
    sc.proxy(env=sc.env(SIP_PORT=dev_port, UPSTREAM=f"sip:127.0.0.1:{dev_up.port}", PROD_UPSTREAM=f"sip:127.0.0.1:{prod_up.port}"),
             extra=("--overlay", "envs/dev.toml"), name="dev")
    sc.proxy(env=sc.env(SIP_PORT=prod_port, UPSTREAM=f"sip:127.0.0.1:{dev_up.port}", PROD_UPSTREAM=f"sip:127.0.0.1:{prod_up.port}"),
             extra=("--overlay", "envs/prod.toml"), name="prod")
    dev = sc.ua("alice", dev_port)
    prod = sc.ua("alice", prod_port, password="secret-a")

    # dev: no auth, debug headers, the base upstream.
    r = dev.request("MESSAGE", "sip:bob@example.com", body="hi", content_type="text/plain")
    rep = dev.final(call_id=r["call_id"])
    m = at(dev_up, r["call_id"])
    sc.check("dev: MESSAGE without credentials is relayed → 200", rep is not None and rep.code == 200 and m is not None, rep)
    sc.check("dev: X-Env: dev", m is not None and m.get("x-env") == "dev", m and m.raw)
    sc.check("dev: X-Debug names the source ip:port and the upstream",
             m is not None and m.get("x-debug") == f"from 127.0.0.1:{dev.port} to sip:127.0.0.1:{dev_up.port}", m and m.get("x-debug"))
    rep, dt = silent_408(dev)
    sc.check("dev: a silent upstream → 408 after fr_timer 1s (0.8..2s)", rep is not None and rep.code == 408 and 0.8 <= dt < 2.0, (rep, dt))

    # prod: 407 first, then relayed to the prod upstream, no debug header.
    sent = prod.request("MESSAGE", "sip:bob@example.com", body="hi", content_type="text/plain")
    rep = prod.final(call_id=sent["call_id"])
    sc.check("prod: MESSAGE without credentials → 407", rep is not None and rep.code == 407, rep)
    sc.check("…and nothing is relayed", at(prod_up, sent["call_id"]) is None and at(dev_up, sent["call_id"]) is None)
    rep, _ = prod.with_auth(sent, rep) if rep is not None else (None, None)
    m = at(prod_up, sent["call_id"])
    sc.check("prod: with credentials → 200 from the prod upstream (PROD_UPSTREAM)", rep is not None and rep.code == 200 and m is not None, rep)
    sc.check("prod: the dev upstream never sees it", at(dev_up, sent["call_id"]) is None)
    sc.check("prod: X-Env: prod, no X-Debug, credentials consumed",
             m is not None and m.get("x-env") == "prod" and m.get("x-debug") is None and m.get("proxy-authorization") is None, m and m.raw)
    rep, dt = silent_408(prod, ua_auth=True)
    sc.check("prod: a silent upstream → 408 after fr_timer 3s (2.6..4.5s)", rep is not None and rep.code == 408 and 2.6 <= dt < 4.5, (rep, dt))

    # --set over the overlay, live.
    sc.proxy(env=sc.env(SIP_PORT=stg_port, PROD_UPSTREAM=f"sip:127.0.0.1:{prod_up.port}"),
             extra=("--overlay", "envs/prod.toml", "--set", "feature.env_name=staging", "--set", "feature.require_auth=false"), name="staging")
    stg = sc.ua("alice", stg_port)
    r = stg.request("MESSAGE", "sip:bob@example.com", body="hi", content_type="text/plain")
    rep = stg.final(call_id=r["call_id"])
    m = at(prod_up, r["call_id"])
    sc.check("prod + --set require_auth=false: relayed without a challenge", rep is not None and rep.code == 200 and m is not None, rep)
    sc.check("…with X-Env: staging (--set wins over the overlay)", m is not None and m.get("x-env") == "staging", m and m.get("x-env"))
