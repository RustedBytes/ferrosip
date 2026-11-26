# The `.cfg` script language

The Kamailio-style routing language (`.cfg`): expressions, pseudo-variables and routes; running Kamailio configs as is; failure and reply routes; reloading. For the typed language see [fsr.md](fsr.md).

## Script language

> Full reference: [`sip-script`](../crates/sip-script/README.md).

Kamailio's native config language (`.cfg`): the same keywords, variables
and operators, compiled once at startup. New routing is easier to write in
`.fsr` ([Routing in `.fsr`](running.md#routing-in-fsr), [docs/fsr.md](fsr.md)),
which compiles to the same thing; this section is the Kamailio-compatible
language, which keeps working. `ferroctl fmt FILE` re-indents a script
in place. It refuses anything that doesn't parse, and guarantees that the
tokens are unchanged. `--check` is for CI.

```
request_route {
    if ($rm == "OPTIONS" && $ru == myself) { reply(200, "OK"); exit; }
    $var(n) = $hdrc(Via) * 2 + 1;
    if ($fU =~ "^\\+49" || $(rU{s.len}) > 10) { route(INTL); }
    switch ($rU) { case "1000": $du = "sip:10.0.0.5"; break; default: setflag(1); }
    $avp(orig) = $ru;                    # travels with the transaction
    t_on_failure("FAIL"); t_on_branch("BR");
    t_relay();
}
route[INTL] { append_hdr("X-Intl: $(fU{s.substr,0,3})"); return(1); }
branch_route[BR] { if ($T_branch_idx > 0) { drop; } }
failure_route[FAIL] { if ($T_reply_code == 486) { $ru = $avp(orig); t_relay("udp:10.0.0.9"); } }
event_route[dispatcher:dst-down] { log("gateway $ru down"); }
```

- **Expressions**: `+ - * / %` (`mod`), binary `| &`, comparisons, `=~` /
  `!~` (regex compiled at startup when constant), `&& || !`, `(int)` /
  `(str)` casts. `+` is typed by its left operand
  (integer add, string concatenation), as in Kamailio. Statements:
  `if/else`, `while`, `switch/case/default/break`, `route(NAME)` /
  `return(n)` (sets `$rc`), `exit`, `drop`, assignments. `//`, `/* */` and
  `#` comments.
- **Variables** (`sip-core/src/pv.rs`, `pvcore.rs`):
  - `$ru $rU $rd $rp $du` are writable; `$fu $fU $fd $fn $ft $tu $tU $td
    $tn $tt $ci $cs $rm $rs $rr $si $sp $pr $Ri $Rp $hdr(Name)[i] $hdrc
    $ua $ct $cT $rb $ml $mb` are read-only.
  - Digest credentials (Proxy-Authorization, else Authorization; null
    for ACK / CANCEL): `$au` user, `$ad` domain (of `user@domain`), `$aU`
    the whole username, `$ar` realm, `$adu` uri, `$aa` algorithm, `$adn`
    nonce, `$adc` cnonce, `$adr` response, `$ado` opaque.
  - Storage: `$var(x)`; `$avp(x)` / `$xavp(r=>f)` and message flags, which
    belong to the transaction (failure, reply and branch routes see them);
    `$shv(x)`, shared by all workers.
  - Misc: `$rc $T_reply_code $T_branch_idx $Ts $RANDOM $env(X) $null`.
  - Modules register their own (`$sht(…)`, `$dlg_var(…)`…).
- **Transformations**: `$(fU{s.len})`, `{s.substr,a,b}`, `{s.select,i,sep}`,
  `{s.tolower}`, `{uri.user|host|port|param,x}`, `{param.value,name}`,
  `{tobody.tag}` and more, chained left to right.
- **Function arguments** may contain variables (`append_hdr("X-A: $fU")`):
  they compile into templates. Functions that need a constant say so at
  startup.
- **`myself`**: `$ru == myself` matches our listen/advertise addresses and
  aliases (`-A host`; the domain module adds its domains).

### Running Kamailio configs

> Details and the survey of Kamailio's own configs: [`docs/kamailio-compat.md`](kamailio-compat.md).

Kamailio's stock `etc/kamailio.cfg` runs unmodified, with any combination
of its `WITH_*` features except `WITH_JSONRPC` (xhttp on the SIP port) and
`WITH_NAT` without `WITH_RTPENGINE` (there is no `rtpproxy` module).

```bash
target/release/ferrosip -c -f kamailio.cfg --define WITH_AUTH --define WITH_MYSQL   # check only, like kamailio -c
target/release/ferrosip -f kamailio.cfg --define ACTIVE
```

- The preprocessor (`#!define`, `#!ifdef`, `#!ifexp`, `#!subst`,
  `include_file`, …) and the core parameters (`listen=`, `children=`,
  `tcp_*`, …) are handled. Command-line options override the core
  parameters.
- Kamailio modules whose job ferrosip does natively (`ctl`, `tls`,
  `websocket`, the `db_*` drivers) load as no-ops.
- Kamailio parameters that tune behaviour ferrosip fixes are accepted with
  a notice. Unknown ones are still errors.
- CI checks 22 of Kamailio's configs in 44 combinations with `-c`
  (`tests/compat/check.sh`), and runs the stock config end to end
  (`tests/e2e_compat.py`).
- `ferrosip import kamailio.cfg -o myproxy [--define WITH_X]…` converts a
  config to `ferrosip.toml` + `routes/main.fsr` with the same behaviour
  ([docs/import.md](import.md)):
  - typed where that is exact (`msg.ruri.user`, `location.lookup()`);
  - `pv("$avp(x)")` / `kamailio.call(…)` elsewhere, which
    `ferrosip lint -W raw_kamailio` then lists.

  CI imports all 44 combinations, and the end-to-end test runs the same
  traffic against the stock config and its import.

## failure_route and onreply_route

> Full reference: [`mod-txn`](../crates/mod-txn/README.md).

In `.fsr` the transaction's result is a value, so there is no separate
failure route ([`await`](fsr.md#await)):

```rust
route main(msg: Request) {
    let res = await txn.relay(msg)
    match res {
        Final(r) if r.code == BusyHere => voicemail(msg)
        Timeout => {
            msg.headers["X-Reason"] = "no-answer"
            voicemail(msg)
        }
        Final(r) => forward(r)          // the best reply goes upstream
    }
}

fn voicemail(msg: Request) -> Action {
    msg.ruri = "sip:vm@10.0.0.9"
    relay(msg)                          // a new branch on the same transaction
}

on reply(r: Reply) {                    // every reply, before tm
    if r.code == SessionProgress {
        drop                            // drop provisionals
    }
    r.headers.remove("X-Internal")
}
```

The same in a Kamailio-style `.cfg`, with per-transaction routes:

```
request_route {
    t_on_failure("VOICEMAIL");          # arm for this transaction
    t_on_reply("REPLIES");
    t_relay();
}
failure_route[VOICEMAIL] {              # every branch failed (no 2xx)
    if t_check_status("486|408") {      # winning reply; regex, anchored
        if t_branch_timeout() { append_hdr("X-Reason: no-answer"); }
        rewriteuri("sip:vm@10.0.0.9");
        t_relay();                       # new branch on the same transaction
    }                                    # else: the best reply goes upstream
}
onreply_route[REPLIES] {                 # replies of this transaction
    if t_check_status("183") { drop; }   # drop provisionals
    remove_hdr("X-Internal");
}
reply_route {                            # every reply, before tm
    append_hdr("X-Seen: 1");
}
```

- **failure_route** runs when a transaction would send a final ≥300 upstream:
  all branches failed, timed out, or a 6xx arrived. It runs on a context
  rebuilt from the original request, like Kamailio's "faked" request, so
  header edits and `rewriteuri()` apply to new branches.
  - `t_relay()` there adds branches to the *same* transaction, and the
    caller never sees the intermediate failure.
  - `t_on_failure()` inside the route re-arms it for another round (A → B → C).
  - `t_reply()` answers the caller directly.
  - If the route does none of these, the best reply goes upstream.
  - It does not run after the caller CANCELs.
- **onreply_route[name]** runs for each reply of the transaction before tm
  processes it. It can edit the reply (`append_hdr`, `remove_hdr`) or `drop`
  a provisional. The global **reply_route** runs for every reply first.
  Finals can't be dropped, because they belong to the transaction.
- **New functions**: `t_on_failure`, `t_on_reply`, `t_check_status`,
  `t_branch_timeout`, `t_reply`; core `rewriteuri`; `drop;` as a statement.
- **How tm runs script routes**: tm can't depend on the script engine (it
  depends on tm), so sip-core has a small `RouteHub`. The engine registers
  route *names* before compiling, so `t_on_failure("x")` resolves to an index
  at startup and a typo is a config error. It registers itself as the
  *runner* afterwards. tm queues the failure route as an action and runs it
  after releasing the transaction lock, because the route's `t_relay()` locks
  the same transaction again.

## Reloading the script (`cfg.reload`)

`ferroctl cfg.reload` re-reads the config file and swaps in the new routes
while ferrosip runs:
- Every message loads the current compiled script through an `ArcSwap`:
  one atomic load, no lock. Messages already being processed finish on the
  old script.
- Only routes may change. A different `loadmodule` or `modparam` is refused
  with the difference (those were applied at startup), and so is a script
  that doesn't compile. The running script then stays as it was.
- Route indices are stable across a reload. Every kind of route (`route`,
  `failure_route`, `onreply_route`, `branch_route`, `event_route`) keeps its
  old index for an existing name; a removed route becomes empty and new
  routes are appended. A transaction armed with `t_on_failure("B")` before
  the reload therefore runs the new `failure_route[B]`.
- A request suspended before the reload (an `await`, `t_suspend`, an
  async query) resumes in the script version that suspended it: where it
  stopped is a position in that version, which an edit before it would
  shift. New requests run the new script.

Kamailio cannot reload its native config. It reloads KEMI scripts
(`app_lua.reload`, which ferrosip has too).
