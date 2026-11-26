# `ferrosip import`: from a Kamailio `.cfg` to `.fsr`

`ferrosip import` turns a Kamailio-style `.cfg` into:
- `ferrosip.toml`: core settings, listeners, modules and their parameters;
- `routes/main.fsr`: the routing.

The result is then checked the way `ferrosip check --config` checks it.

```bash
ferrosip import kamailio.cfg -o myproxy --define WITH_AUTH --define WITH_MYSQL
ferrosip --config myproxy/ferrosip.toml
```

```text
ferrosip import: wrote myproxy/ferrosip.toml and myproxy/routes/main.fsr
  18 routes, 113 typed forms, 103 escape-hatch uses (`ferrosip lint -W raw_kamailio --config myproxy/ferrosip.toml` lists them)
  note: statements after an exit/drop/return were dropped (they never run)
ferrosip import: myproxy/ferrosip.toml: config OK
```

**The goal is the same behaviour.** The imported configuration answers
the same traffic the same way as the `.cfg` it came from. Readability
comes second:
- Where a typed `.fsr` form lowers to exactly the same thing, the import
  uses it.
- Everything else goes through `.fsr`'s escape hatch to Kamailio (below).
  `ferrosip lint -W raw_kamailio` then lists what is left to make typed,
  and you can do that step by step, with `ferrosip test` and real
  traffic to confirm nothing changed.

## What it translates

| Kamailio | ferrosip |
|---|---|
| `listen=`, `children=`, `tcp_*`, `debug=`, `alias=` | `[[listen]]`, `[core] workers`, `tcp_*`, `log_level`, `aliases` |
| other core settings | a `# … (no effect in ferrosip)` comment |
| `group.name = value desc "…"` | `[cfg_vars.group] name = { value = …, desc = "…" }` |
| `loadmodule "x"` + `modparam("x", …)` | `[modules.x]`, values typed by the module's schema (`30000` → `"30s"`, `1` → `true`, `2` → `"write-back"`) |
| a parameter the schema doesn't list | `[modules.x.kamailio]`, passed to the module as written |
| a parameter without effect in ferrosip | a comment |
| `modparam("tls", …)` | `[tls.default]` (`profile` for a `tls.cfg`) |
| `request_route` | `route main(msg: Request)` |
| `route[NAME]` | `fn name(msg: Request)`, or `-> Bool` when it's called for its value (`if (route(X))`) |
| `failure_route[X]`, `branch_route[X]`, `onreply_route[X]` | `on kamailio.failure_route(msg: Request, name: "X")` … (a failure route armed right before `t_relay`: below) |
| `[if (is_method("INVITE")) {] [if (!t_is_set("failure_route"))] t_on_failure("F"); [}]` then `t_relay();` or `if (!t_relay()) { send_reply_error(); }` (or `sl_reply_error()`), then `exit;` | `[if msg.method == INVITE {] let res = await txn.relay(msg)` + `match res { Final(r) if !r.sent => stateless.reply_error_and_continue(); Final(r) if r.code < 300 => {}; _ => f(msg) } exit [}` and, for the other requests, the relay as written`]`; `failure_route[F]` becomes `fn f(msg: Request)`. Only when it means the same, see [Failure routes](#failure-routes) |
| `event_route[x:y]` | `on kamailio.event_route(name: "x:y")` |
| `reply_route` / unnamed `onreply_route` | `on reply(msg: Reply)` |
| `$ru $rU $rd $du $fu $tU $si …` (request code) | `msg.ruri`, `msg.ruri.user`, … |
| `is_method("A\|B")`, `$rm == "A"`, `has_totag()` | `msg.method == A \|\| …`, `msg.has_to_tag` |
| `$rs`, `$rr`, `$fu` … in an `onreply_route` / `reply_route` (where `msg` is the reply) | `msg.code`, `msg.reason`, `msg.from.uri` … |
| `t_check_status("486\|408")`, `"3[0-9][0-9]"`, `"5[0-9][0-9]\|486"` in a failure, onreply or branch route (or a `route[…]` only they call) | `txn.code == BusyHere \|\| txn.code == RequestTimeout`, `txn.code in 300..399`, `txn.code in 500..599 \|\| txn.code == BusyHere`: exact codes and whole hundreds; any other pattern stays `txn.status_is("…")` |
| `t_check_status("[12][0-9][0-9]")`, `"[15][0-9][0-9]"` | `txn.code in 100..299` (consecutive hundreds as one range), `txn.code in 100..199 \|\| txn.code in 500..599` |
| `$T_reply_code`, `$T_reply_reason` there | `txn.code`, `txn.reason` |
| `$rs =~ "[12][0-9][0-9]"` (also `status`), `$T_reply_code =~ "486\|5[0-9][0-9]"`, `!~` where the code is `msg.code` / `txn.code` | `msg.code in 100..299`, `txn.code == BusyHere \|\| txn.code in 500..599`, `!(…)` / `!=`: the `t_check_status` patterns, each alternative exactly three positions long (`=~` isn't anchored, so `"4"` or `"4.."` would match inside a code: those stay `pv("$rs") =~ "…"`) |
| `$T_reply_code == 486`, `$rs != "180"` | `txn.code == BusyHere`, `msg.code != Ringing` (by name; `<`, `>=` … keep the number) |
| `setflag(FLT_ACC)`, `isflagset(…)`, `resetflag(…)`: a literal message flag 0..31, where the code has `msg` | `msg.set(FLT_ACC)`, `msg.is(…)`, `msg.reset(…)`, with `flag FLT_ACC = 1` declared at the same bit (module parameters such as acc's `log_flag` name it). The name is the `#!define` with that value (a `FLT_` one first, never a `FLB_` one), else `FLAG_1` |
| `setbflag(FLB_NATB)`, `isbflagset(…)`, `resetbflag(…)`, also with a literal branch (`setbflag(FLB_NATB, 0)`) | `msg.set(FLB_NATB)`, `msg.is(…)`, `msg.reset(…[, branch: 0])`, with `branch flag FLB_NATB = 6`: they lower to the same `setbflag(6)`. Named like message flags, the other way round (a `FLB_` define first, never a `FLT_` one; else `BFLAG_6`) |
| `force_rport()`, `set_reply_no_connect()`, `set_forward_no_connect()` (core functions, whatever the modules) | `sip.force_rport()`, `sip.reply_no_connect()`, `sip.forward_no_connect()` |
| `send_reply_error()` as a statement: `if (!t_relay()) { send_reply_error(); } exit;` | `stateless.reply_error_and_continue()`, which lowers to the bare call (the route goes on, as in the `.cfg`; `stateless.reply_error()` would end it) |
| `xlog("…")`, `xlog("L_INFO", "…")` with a literal level (`L_ERR`, `L_WARN`, `L_NOTICE`, `L_INFO`, `L_DBG`, `L_ALERT`, `L_CRIT`, `L_BUG`) | `log.error("…")`, `log.info("…")` …: they lower to `xerr`, `xinfo` …, xlog's shortcuts for the same level (no level is `L_ERR`). Tested for its value, or a level in a variable: kept |
| `$hdr(Event)` (a plain header name) | `msg.headers["Event"]`, which reads `$hdr(Event)`; compared with a number it stays `pv` |
| `"from $si:$sp"`, `$cs`, `$rp` inside a template | `"from {msg.src.ip}:{msg.src.port}"`, `{msg.cseq}`, `{msg.ruri.port}`: as text these Int fields read the same; in a comparison they stay `pv` |
| a number written as text for a number parameter: `mf_process_maxfwd_header("10")`, `sanity_check("17895", "7")` | `sip.process(10)`, `sip.check(17895, 7)`: both Kamailio and ferrosip read `"10"` as 10 (`sip.check` in a `reply_route` too, where Kamailio also allows it) |
| a module function with an exact `.fsr` signature | `ns.fn(…)`: `lookup("location")` → `location.lookup()` |
| `if (!f(…)) { sl_reply_error(); } exit;` for a function that answers | `ns.f(…)` (it lowers to exactly that) |
| `sl_send_reply("404", "Not Found"); exit;` or `send_reply(…); exit;` with a literal code, in `request_route` or a `route[…]` only it calls; `sl_send_reply` only where no transaction can exist yet: not after `t_newtran`, `t_relay` and similar on the same path, including through called routes | `reply(NotFound)`; a reason other than exactly the standard phrase is kept, as it goes on the wire: `reply(NotFound, "Not here")`, `reply(NotFound, "Not found")`; a code without a name stays a number: `reply(499, "x")` |
| `t_reply("404", "Not found"); exit;` with a literal final code (200–699), in a `failure_route` or a `route[…]` only failure routes call | `reply(NotFound, "Not found")`, with the same reason rule: `reply()` lowers to `t_reply` there. In request, branch and onreply code `t_reply` stays as it is |
| any other function | `kamailio.call("name", args…)` |
| any other pseudo-variable | `pv("$avp(x)")`, read or assigned |
| `"text $rU"` | `"text {msg.ruri.user}"` |
| `switch` | `let switch_1 = …` and an `if` chain, with fall-through kept |
| `return(0)`; `return(1)` / `return(-1)` in a route used as a condition | `exit`; `return true` / `return false` |
| `\|`, `&` | `kamailio.bitor(a, b)`, `kamailio.bitand(a, b)` |
| `myself` | `kamailio.myself` |

Routes keep their Kamailio name (`fn TICK(msg: Request)`) when a string
names them, as in `modparam("rtimer", "exec", "timer=t;route=TICK")` or
`t_on_failure("X")`. Modules look such routes up by name. Other routes
get snake_case names, with a `// route[NAME]` comment.

## Failure routes

A Kamailio failure route is armed with `t_on_failure("F")` and runs when
the transaction `t_relay` started ends with a negative final or a timeout,
canceled or not; a 2xx goes upstream without it. In `.fsr` that is the
code after `await txn.relay`, where the result says what happened. So
the stock `route(RELAY)`

```c
if (is_method("INVITE")) {
    if(!t_is_set("failure_route")) t_on_failure("MANAGE_FAILURE");
}
if (!t_relay()) {
    send_reply_error();
}
exit;
```

imports as

```rust
if msg.method == INVITE {
    let res = await txn.relay(msg)
    match res {
        Final(r) if !r.sent => stateless.reply_error_and_continue()   // t_relay() failed at once
        Final(r) if r.code < 300 => {}                                 // a 2xx went upstream
        _ => manage_failure(msg)                                       // negative final, Timeout
    }
    exit
}
if !kamailio.call("t_relay") {
    stateless.reply_error_and_continue()
}
exit
```

with `failure_route[MANAGE_FAILURE]` as `fn manage_failure(msg:
Request)`. It runs in the same failure context, so `txn.is_canceled()`,
`txn.code` and `reply()` (`t_reply`) mean what they did. When it relays
again (to voicemail, through `route(RELAY)`), that relay is an `await`
too, as `t_on_failure` re-armed the route in Kamailio.

The import does this only where it provably means the same, and keeps
`kamailio.call("t_on_failure", …)` and the `on kamailio.failure_route`
handler otherwise:
- `t_on_failure` appears once in the script, with a literal name,
  directly before the relay (alone, behind `!t_is_set("failure_route")`,
  or inside an `if` whose condition only tests the method, the To tag or
  variables), and `exit` follows the relay. So where the relay runs no
  other failure route is armed, and `t_is_set("failure_route")` is false
  (it may appear only as that guard: a branch route would see it set);
- the relay is `t_relay()` without arguments, and what runs when it
  fails at once is nothing, `send_reply_error()` or `sl_reply_error()`;
- the route it is in has the request, runs in request or failure code
  only, and neither it nor a route on the way to it is used for its value
  (`await` can't wait inside a condition);
- `failure_route[F]` exists once and no module parameter names it.

`t_on_branch` and `t_on_reply` stay: branch and onreply routes are their
own handlers in `.fsr` too.

`#!ifdef` blocks are resolved with the `--define`s given, so one import
is one variant of the config. Comments are not carried over, because the
preprocessor drops them. Statements after `exit`, `drop` or `return`
never run, so they are dropped, with a note.

## The escape hatch

What `.fsr` can't say in a typed way it can say like Kamailio does:

```rust
pv("$avp(dst)") = "sip:{pv("$rU")}@10.0.0.1"          // any pseudo-variable, read or assigned
if kamailio.call("is_from_local") { … }                // any function, by its Kamailio name
pv("$var(flags)") = kamailio.bitor(pv("$var(flags)"), 4)
if msg.ruri == kamailio.myself { … }
kamailio.call("t_on_failure", "MISSED")                // arm a route…
on kamailio.failure_route(msg: Request, name: "MISSED") { … }   // …written as a Kamailio route
```

- These values are untyped (Str or Int at run time). They can be compared
  with anything, tested in conditions, and added. They work wherever a
  value does.
- `pv("$avp(x)") = v` assigns exactly as the `.cfg` did: for an AVP that
  adds a value. A typed `let` replaces it.
- `kamailio.call` arguments are templates, like a `.cfg`'s:
  `"to {pv("$rU")}"` passes `"to $rU"`.
- None of it is checked. A typo in a variable or function name only shows
  at run time, which is why `ferrosip lint -W raw_kamailio` points at
  every use.

## Making it typed

`ferrosip lint --config myproxy/ferrosip.toml -W raw_kamailio` lists the
escape-hatch uses. The usual rewrites:

| imported | typed |
|---|---|
| `pv("$var(x)") = …` read later in the same route | `let x = …` |
| `kamailio.call("t_on_failure", "F")` … `kamailio.call("t_relay")` + `on kamailio.failure_route(…, name: "F")` | `let r = await txn.relay(msg)` + `match r { … }`. The import does this itself where it means the same ([Failure routes](#failure-routes)) |
| `on kamailio.event_route(name: "dialog:end")` | `on dialog.ended(d: Dialog)` |
| `kamailio.call("sl_send_reply", "404", "Not Found")` + `exit` | `reply(NotFound)`. The import does this itself, except where it wouldn't mean the same: outside request code (a branch, onreply or event route, a failure route other than `t_reply`, or a `route[…]` one of them calls), for an `sl_send_reply` where a transaction may already exist (after `t_newtran`, `t_relay`, `t_reply`, `t_suspend`, `async_*` and the like on a path to it, through called routes too; `t_check_trans` makes none), since `reply` replies statefully once a transaction exists and `sl_send_reply` never does, or with a variable code |
| `kamailio.call("xlog", pv("$var(level)"), "…")` | `log.info("…")`, when the level is known. The import does this itself for a literal level |

`ferrosip lint --fix` also removes what the import made redundant:
- trailing `return`s;
- parameters set to their default;
- nested `if`s that can be merged.

## How it's checked

- `tests/compat/check.sh` imports each of the 44 Kamailio configs and
  define sets in CI, and each import must pass `ferrosip check`.
- `tests/e2e_compat.py` runs the same traffic twice, once against the
  stock `kamailio.cfg` and the compatibility script, and once against
  their imports. Every check must pass both times:
  - OPTIONS keepalive;
  - REGISTER;
  - INVITE to an unknown user;
  - MESSAGE relayed to the contact, with the retransmission absorbed;
  - casts, selects, cfg vars, `exec_dset`, counters and `dlgs`.
- Unit tests in `bin/ferrosip/src/import.rs` cover:
  - `switch` fall-through;
  - routes used as conditions;
  - the typed Action idiom;
  - native replies with named codes, and where they stay `kamailio.call`;
  - flags and branch flags named by their `#!define`, xlog levels,
    `$hdr(X)` and numbers written as text;
  - core functions and `send_reply_error` as a statement;
  - failure routes as `await txn.relay`, and the shapes that keep the
    handler;
  - templates with transformations;
  - modparam conversion.
