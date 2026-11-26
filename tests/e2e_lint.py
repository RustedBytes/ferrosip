#!/usr/bin/env python3
"""`ferrosip lint`: clippy-style lints for ferrosip.toml and the routing.

- a .fsr with many problems: each lint fires where expected, a deny-level
  lint (infinite_loop) fails the run, warnings alone pass;
- levels: -A / -W / -D by lint and by group, `-D warnings`, `[lint]` in
  ferrosip.toml, `// lint: allow(…)` and `# lint: allow(…)` comments;
- `--fix` applies every machine fix (overlapping ones in later rounds),
  keeps a formatted file formatted, and the result still passes
  `ferrosip check`;
- ferrosip.toml: a parameter at its default (and --fix removes it), a
  password in a URL or a secret key (but not `${ENV}`), an unused
  [feature];
- .cfg: an unused route, a modparam at its default, the routing-wide
  security lints (open relay, no Max-Forwards check, REGISTER without
  auth), which go away when the routing does authenticate;
- --format json, --explain, --list, an unknown lint name;
- docs/lints-reference.md is what `ferrosip lint --list --markdown` prints.
Run from the repo root after `cargo build --release`.
"""
import json, os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = f"{ROOT}/target/release/ferrosip"
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


def lint(*args, cwd):
    p = subprocess.run([BIN, "lint", *args], cwd=cwd, capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout, p.stderr


def names(*args, cwd):
    code, out, err = lint("--format", "json", *args, cwd=cwd)
    rows = [json.loads(l) for l in out.splitlines() if l.strip()]
    return code, [r["lint"] for r in rows], rows, err


d = tempfile.mkdtemp(prefix="ferrosip-e2e-lint-")
os.makedirs(f"{d}/routes")

MESSY = """import txn, location, auth, nat
import { features } from config

flag NATED
flag UNUSED

route main(msg: Request) {
    let caller = msg.from.user
    if msg.method == INVITE {
        if msg.has_to_tag == false {
            reply(404, "Not Found")
        }
    } else {
        if msg.method == REGISTER {
            location.save(msg)
        }
    }
    if true {
        reply(499)
    }
    match msg.method {
        OPTIONS => reply(200)
        OPTIONS => drop
        _ => exit
        BYE => exit
    }
    msg.ruri = "sip:pstn@10.20.30.40"
    log.info("{features.pstn}")
    while true {
        log.info("spin")
    }
    relay(msg)
}

fn helper(msg: Request) {
    exit
}

shared table seen: Map<Str, Int>
"""
TOML = """[[listen]]
proto = "udp"
addr = "127.0.0.1:7900"

[feature]
pstn = "sip:10.0.0.9"
unused_one = true

[modules.txn]   # tm
fr_timer = "30s"
fr_inv_timer = "90s"

[modules.location]
db_mode = "off"
# lint: allow(redundant_default)
default_expires = "1h"

[modules.sql]
sqlcon = "ca=>mysql://ferrosip:s3cret@127.0.0.1/ferrosip"

[modules.auth]
secret = "hunter2"
password_column = "password"
db_url = "${AUTH_DB_URL:-mysql://ferrosip:fallback@127.0.0.1/ferrosip}"

[routing]
entry = "routes/main.fsr"
"""
open(f"{d}/routes/main.fsr", "w").write(MESSY)
open(f"{d}/ferrosip.toml", "w").write(TOML)

# ---------------------------------------------------------------- .fsr ---
code, got, rows, err = names("--config", "ferrosip.toml", "-W", "pedantic", cwd=d)
want = ["needless_import", "unused_import", "unused_flag", "unused_variable", "bool_comparison", "redundant_reply_reason",
        "collapsible_else_if", "constant_condition", "unknown_reply_reason", "unreachable_arm", "hardcoded_address",
        "infinite_loop", "unused_function", "unused_state", "table_without_ttl", "missing_max_forwards", "open_relay",
        "register_without_auth", "redundant_default", "plaintext_secret", "unused_feature"]
for w in want:
    check(f"{w} fires", w in got, f"{sorted(set(got))} {err[-500:]}")
check("deny-level infinite_loop fails the run", code == 1, code)
row = next((r for r in rows if r["lint"] == "infinite_loop"), {})
check("infinite_loop is an error at the `true` of `while true`", row.get("level") == "deny" and row.get("line") == 29 and row.get("column") == 11, row)
check("two unreachable arms (repeat, after _)", got.count("unreachable_arm") == 2, got)
check("pedantic lints are off by default", "hardcoded_address" not in names("--config", "ferrosip.toml", cwd=d)[1])
check("hardcoded_address is not about [feature]", all(r["file"].endswith(".fsr") for r in rows if r["lint"] == "hardcoded_address"))
check("redundant_default: only fr_timer and db_mode (default_expires is allowed by comment; password_column is the default too)",
      sorted(r["message"].split(" is ")[0] for r in rows if r["lint"] == "redundant_default")
      == ["modules.auth.password_column", "modules.location.db_mode", "modules.txn.fr_timer"],
      [r["message"] for r in rows if r["lint"] == "redundant_default"])
check("plaintext_secret: the URL password and the secret key", sorted(r["message"] for r in rows if r["lint"] == "plaintext_secret")
      == ["modules.auth.secret is written in the file", "modules.sql.sqlcon has a password in its URL"],
      [r["message"] for r in rows if r["lint"] == "plaintext_secret"])
check("unused_feature: the features the routing doesn't read",
      [r["message"] for r in rows if r["lint"] == "unused_feature"] == ["feature `unused_one` is never read"],
      [r["message"] for r in rows if r["lint"] == "unused_feature"])

# Human output: clippy-like, with a note once per lint and a summary.
code, out, err = lint("--config", "ferrosip.toml", cwd=d)
check("human output: header, location, source line and caret",
      "warning: `caller` is never read\n --> routes/main.fsr:8:9\n  |\n8 |     let caller = msg.from.user\n  |         ^^^^^^\n" in err, err[:800])
check("help and fixable", "= help: if this is intentional, prefix it with an underscore: `_caller` (fixable)" in err)
check("note once per lint", err.count("`unused_import` on by default") == 1 and err.count("is imported but never used") == 2, err[:2000])
check("summary counts errors and fixable warnings", "error: could not pass lint: 1 error," in err and "fixable with `ferrosip lint --fix`" in err, err[-300:])

# Levels.
code, got, _, _ = names("--config", "ferrosip.toml", "-A", "infinite_loop", cwd=d)
check("-A infinite_loop: warnings only → exit 0", code == 0 and "infinite_loop" not in got, (code, got))
code, got, rows, _ = names("--config", "ferrosip.toml", "-A", "infinite_loop", "-D", "warnings", cwd=d)
check("-D warnings turns warnings into errors", code == 1 and all(r["level"] == "deny" for r in rows), code)
code, got, _, _ = names("--config", "ferrosip.toml", "-A", "style", "-A", "correctness", cwd=d)
check("-A a group", not {"bool_comparison", "needless_import", "infinite_loop"} & set(got) and "unused_variable" in got, got)
code, got, _, _ = names("--config", "ferrosip.toml", "-A", "suspicious", "-W", "unused_flag", cwd=d)
check("a lint level overrides its group's", "unused_flag" in got and "unused_variable" not in got, got)
code, out, err = lint("--config", "ferrosip.toml", "-W", "unused_varible", cwd=d)
check("unknown lint: error with a suggestion", code != 0 and "unused_variable" in err, err)

# [lint] in ferrosip.toml, and allow comments in .fsr.
open(f"{d}/ferrosip.toml", "w").write(TOML + '\n[lint]\nallow = ["security", "unused_feature"]\ndeny = ["unused_flag"]\n')
open(f"{d}/routes/main.fsr", "w").write(MESSY.replace("    let caller", "    // lint: allow(unused_variable)\n    let caller")
                                         .replace("    while true {", "    while true {  // lint: allow(infinite_loop)"))
code, got, rows, err = names("--config", "ferrosip.toml", cwd=d)
check("[lint] allow: a group and a lint", not {"open_relay", "plaintext_secret", "unused_feature"} & set(got), got)
check("[lint] deny", all(r["level"] == "deny" for r in rows if r["lint"] == "unused_flag") and code == 1, rows)
check("// lint: allow(…) before a statement and at its end", "unused_variable" not in got and "infinite_loop" not in got, got)
chk = subprocess.run([BIN, "check", "--config", "ferrosip.toml"], cwd=d, capture_output=True, text=True)
check("ferrosip check accepts [lint]", chk.returncode == 0, chk.stderr[-400:])

# --fix: everything fixable is fixed (in rounds), the file stays formatted
# and still compiles.
open(f"{d}/ferrosip.toml", "w").write(TOML.replace('secret = "hunter2"\n', '').replace('ferrosip:s3cret@', 'ferrosip@'))
open(f"{d}/routes/main.fsr", "w").write(MESSY)
subprocess.run([BIN, "fmt", "routes"], cwd=d, check=True, capture_output=True)
code, out, err = lint("--config", "ferrosip.toml", "--fix", "-A", "infinite_loop", cwd=d)
fixed = open(f"{d}/routes/main.fsr").read()
toml = open(f"{d}/ferrosip.toml").read()
check("--fix reports what it applied", "applied" in err, err[-500:])
check("--fix: imports", fixed.startswith("import location\nimport { features } from config\n"), fixed[:80])
check("--fix: _caller, !x, reply(404), else if",
      "let _caller" in fixed and "if !msg.has_to_tag {" in fixed and "reply(404)\n" in fixed and "} else if msg.method == REGISTER {" in fixed, fixed)
check("--fix: the file is still formatted", subprocess.run([BIN, "fmt", "--check", "routes"], cwd=d, capture_output=True).returncode == 0)
check("--fix: ferrosip.toml defaults removed (not the allowed one)",
      'fr_timer = "30s"' not in toml and 'db_mode' not in toml and 'default_expires = "1h"' in toml and 'fr_inv_timer = "90s"' in toml, toml)
check("--fix: nothing fixable left", "fixable" not in err.splitlines()[-1], err.splitlines()[-1])
code, got, _, _ = names("--config", "ferrosip.toml", "-A", "infinite_loop", cwd=d)
check("after --fix only unfixable lints remain", not {"needless_import", "unused_import", "bool_comparison", "redundant_default", "collapsible_else_if"} & set(got), got)
chk = subprocess.run([BIN, "check", "--config", "ferrosip.toml"], cwd=d, capture_output=True, text=True)
check("the fixed configuration passes ferrosip check", chk.returncode == 0, chk.stderr[-500:])

# A clean, authenticated .fsr has nothing to say.
CLEAN = """import location, auth, route_set

route main(msg: Request) {
    guard msg.max_forwards > 0 else reply(483)
    if msg.has_to_tag {
        guard route_set.follow() else reply(404)
        relay(msg)
    }
    route_set.record()
    match msg.method {
        REGISTER => register(msg)
        _ => {
            guard auth.check("example.com") else auth.proxy_challenge("example.com")
            relay(msg)
        }
    }
}

fn register(msg: Request) {
    guard auth.check("example.com") else auth.www_challenge("example.com")
    location.save(msg)
}
"""
os.makedirs(f"{d}/clean")
open(f"{d}/clean/main.fsr", "w").write(CLEAN)
code, out, err = lint("-f", "main.fsr", cwd=f"{d}/clean")
check("a clean routing: no problems, exit 0", code == 0 and "no problems found" in err, err)

# ----------------------------------------------------------------- .cfg ---
CFG = """loadmodule "tm"
loadmodule "rr"
loadmodule "usrloc"
loadmodule "registrar"
modparam("tm", "fr_timer", 30000)
modparam("tm", "fr_inv_timer", 90000)
modparam("rr", "enable_full_lr", 0)   # lint: allow(redundant_default)
modparam("usrloc", "use_domain", 0)

request_route {
    record_route();
    if (is_method("REGISTER")) {
        save("location");
        exit;
    }
    route(RELAY);
}

route[RELAY] {
    t_relay();
}

route[OLD] {
    drop;
}

failure_route[MISSED] {
    exit;
}
"""
os.makedirs(f"{d}/cfg")
open(f"{d}/cfg/k.cfg", "w").write(CFG)
code, got, rows, err = names("-f", "k.cfg", cwd=f"{d}/cfg")
check(".cfg: unused route and failure_route",
      sorted(r["message"] for r in rows if r["lint"] == "unused_route") == ["failure_route[MISSED] is never used", "route[OLD] is never used"], rows)
check(".cfg: modparams at their default (one allowed by comment)",
      sorted(r["line"] for r in rows if r["lint"] == "redundant_default") == [5, 8], [(r["line"], r["message"]) for r in rows if r["lint"] == "redundant_default"])
for w in ["open_relay", "missing_max_forwards", "register_without_auth", "record_route_without_loose_route"]:
    check(f".cfg: {w}", w in got, got)
code, out, err = lint("-f", "k.cfg", "--fix", cwd=f"{d}/cfg")
cfg = open(f"{d}/cfg/k.cfg").read()
check(".cfg --fix removes the default modparams", "fr_timer" not in cfg and "use_domain" not in cfg and "enable_full_lr" in cfg and "fr_inv_timer" in cfg, cfg)
AUTHED = CFG.replace('        save("location");', '        if (!www_authorize("example.com", "subscriber")) { www_challenge("example.com", "0"); exit; }\n        save("location");') \
            .replace("request_route {\n", "request_route {\n    if (!mf_process_maxfwd_header(10)) { sl_send_reply(483, \"Too Many Hops\"); exit; }\n    if (has_totag() && loose_route()) { t_relay(); exit; }\n")
open(f"{d}/cfg/k.cfg", "w").write(AUTHED)
code, got, rows, err = names("-f", "k.cfg", cwd=f"{d}/cfg")
check(".cfg with auth, Max-Forwards and loose_route: no security lints",
      not {"open_relay", "missing_max_forwards", "register_without_auth", "record_route_without_loose_route"} & set(got), got)

# ----------------------------------------------------- explain, list, docs ---
out = subprocess.run([BIN, "lint", "--explain", "open_relay"], capture_output=True, text=True).stdout
check("--explain", out.startswith("open_relay\n") and "group: security (default: warn)" in out and "toll fraud" in out, out)
out = subprocess.run([BIN, "lint", "--explain", "style"], capture_output=True, text=True).stdout
check("--explain a group", "bool_comparison" in out and "infinite_loop" not in out, out)
out = subprocess.run([BIN, "lint", "--list"], capture_output=True, text=True).stdout
check("--list shows every group", all(g in out for g in ["correctness (default: deny)", "pedantic (default: allow)"]), out[:300])
ref = subprocess.run([BIN, "lint", "--list", "--markdown"], capture_output=True, text=True).stdout
check("docs/lints-reference.md is up to date (ferrosip lint --list --markdown)", ref == open(f"{ROOT}/docs/lints-reference.md").read())

print()
print("all passed" if failures == 0 else f"{failures} failed")
sys.exit(1 if failures else 0)
