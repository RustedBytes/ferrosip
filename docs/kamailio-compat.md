# Running Kamailio configs

ferrosip reads Kamailio's native config language. This page says how far
that goes, measured against Kamailio's own configs.

## How it's checked

`ferrosip -c -f kamailio.cfg` parses the file, loads the modules, applies
the modparams and runs every fixup, then exits. Like `kamailio -c`, it opens
no sockets and no databases (a `db_url` is only checked for a known scheme).

- **CI** (`tests/compat/check.sh`): 22 configs from Kamailio's tree, vendored
  unmodified in `tests/compat/kamailio/` (GPL-2.0-or-later, which ferrosip
  can distribute under its GPL-3.0-or-later), in 44 runs. The stock `etc/kamailio.cfg` is checked with each `WITH_*`
  feature and with all of them on. All 44 must print `config OK`.
- **e2e** (`tests/e2e_compat.py`): the stock `kamailio.cfg` (with `ACTIVE`
  defined, as it requires) serves traffic. OPTIONS gets `200 Keepalive`,
  REGISTER is saved, an INVITE to an unknown user gets 404, and a MESSAGE
  to a registered user is relayed with its 200 coming back. Retransmissions
  are absorbed by `t_check_trans()`.
- **`ferrosip import`:** each of the 44 runs is also imported to
  `ferrosip.toml` + `.fsr`, and the import must pass `ferrosip check`. The
  e2e test runs the same traffic against the stock config's import and
  expects the same results. See [import.md](import.md).

## Survey of Kamailio's example configs

Every `.cfg` under `etc/` and `misc/examples/` (66 files, obsolete ones
excluded) at kamailio/kamailio `b6505a67`:

| Result | Files |
|---|---|
| `config OK` | 22 (the vendored set) |
| Not valid configs | 13: unbalanced `#!ifdef`/`#!endif` (3); `include_file` fragments without `loadmodule`s, or with their includes shipped as `.sample` (8); `listen=a.b.c.d` placeholders (2) |
| Invalid in current Kamailio too | 7: `exec_msg` scripts with shell variables written `$SIP_OUSER` (Kamailio needs `$$`); a legacy `db_url` path |
| Need the network or files | 4: hostnames resolved at startup (`t_relay("udp:iptel.org:5060")`), a missing `dispatcher.list` |
| Need something ferrosip doesn't have | 20, ranked below |

### Gaps, by number of configs affected

| Missing | Configs | Notes |
|---|---|---|
| modules `rtpproxy`, `uri`, `avp`, `print`, `vm`, `snmp`, `stun`, `sipcapture` | 8 | `rtpengine` covers what `rtpproxy` does (`kamailio.cfg` with `WITH_NAT WITH_RTPENGINE` passes); `uri` and `avp` are SER-era modules |
| `lookup("aliases")`: more than one usrloc table | 2 | usrloc has the one `location` table |
| `xhttp` on the SIP TCP port | 2 | ferrosip's xhttp needs its own `listen`; this also blocks `kamailio.cfg` `WITH_JSONRPC` |
| `src_ip == host.name` (hostname resolved in a comparison) | 2 | |
| `t_on_branch_failure()` / `event_route[tm:branch-failure:…]` | 1 | RFC 5626 flow failover in the outbound example |
| `via_add_srvid()` | 1 | anycast example |
| SER syntax: `%avp`, `forward(uri:host, uri:port)` | 2 | removed from Kamailio long ago |

## What was added for these configs

- **Preprocessor**: `#!define` (with values and `--define NAME[=VALUE]`),
  `#!trydef`, `#!redefine`, `#!undef`, `#!ifdef`/`#!ifndef`/`#!else`/
  `#!endif`, `#!ifexp` (`!`, `&&`, `||`, parentheses), `#!subst`,
  `#!substdef`, `#!substdefs`, `include_file`/`import_file` (relative to the
  including file, depth 16). Line numbers in errors point into the right
  file.
- **Core parameters** (`listen=`, `children=`, `tcp_*`, `alias=`, `debug=`,
  …) map to ferrosip settings. Command-line options win over them. Settings
  ferrosip has no equivalent for are accepted with a notice.
- **Custom config variables** (`pstn.gw_ip = "" desc "…"`): read with
  `$sel(cfg_get.pstn.gw_ip)` or `@cfg_get.pstn.gw_ip`, changed at runtime
  with `ferroctl cfg.set_now_string pstn gw_ip 10.0.0.1` (and
  `cfg.set_now_int`, `cfg.get`, `cfg.list`).
- **Syntax**:
  - strings spanning lines, and adjacent strings joined;
  - IPv4 literals;
  - `if` without braces, and no `;` needed before `else`/`}`;
  - numeric route names;
  - `"a" + $var(x)` in function arguments;
  - `(int)`/`(str)` casts, `mod`, binary `|` and `&`;
  - `msg:len` and `max_len`;
  - selects (`@to.tag`, `@via[2]`, `@ruri.user`, …);
  - core keywords `dst_ip`, `dst_port`, `from_uri`, `to_uri`, `af`, and
    `UDP`/`TCP`/`TLS`/`WS`/`WSS`/`INET`/`INET6`;
  - `loadmodule "/path/x.so"`;
  - `modparam("a|b", …)`;
  - `yes`/`no`/`on`/`off` as integers.
- **Built-in modules**: `ctl`, `cfg_rpc`, `xmlrpc`, `mi_fifo`, the `db_*`
  drivers, `tls`, `websocket`, `kemix` and `debugger` load as no-ops,
  because ferrosip does their job natively. `modparam("tls", …)` maps to
  the `--tls-*` settings. `ws_handle_handshake()` returns false, since
  `ws:`/`wss:` listeners upgrade before any route runs.
- **Parameters with no effect** (`bin/ferrosip/src/compat.rs`, `NO_EFFECT`):
  66 Kamailio modparams that tune behaviour ferrosip fixes are accepted
  with a one-time notice. Any other unknown parameter is still an error,
  which is what catches typos.
- **Default `db_url`**: as in Kamailio, modules that need a database and
  have no `db_url` use `mysql://kamailio:kamailiorw@localhost/kamailio`.
- **Functions**:
  - tm: `t_check_trans`, `t_newtran` (creates the transaction: later
    retransmissions are absorbed and a stateless reply becomes its reply),
    `t_is_set`, `t_is_canceled`, `t_release`,
    `t_relay_to_udp|tcp|tls`, `t_forward_nonack[_udp|_tcp|_tls]`,
    `t_lookup_request`, `t_save_lumps`, `t_reply_error`, `t_load_contacts(mode)` (standard
    and proportional), `event_route[tm:local-request]` and
    `[tm:local-response]`, `t_on_failure("0")` to disarm;
  - core: `set_reply_no_connect`, `set_forward_no_connect`,
    `set_reply_close` / `set_forward_close` (notice only), `strempty`,
    `strnotempty`, `len_gt`, `seturi`, `strip`, `strip_tail`, `prefix`,
    `rewriteuser|host|port|hostport` and their `set*` names, `log(level, msg)`;
  - other modules: `send_reply_error`, `msg_apply_changes`, `is_first_hop`,
    `append_urihf`, `mf_process_maxfwd_header` (Kamailio's return codes),
    `is_maxfwd_lt`.
- **Parameters**: tm `wt_timer`, tm `auto_inv_100`, tm `contact_flows_avp`,
  maxfwd `max_limit`, core `max_branches` (the transaction's branches and
  the destination set's `max_branches - 1`, as `dset.c`).
- **Variables and transformations**: `$msg(len|buf|body|hdrs|fline)` and
  `{re.subst,/re/repl/flags}`.
- **Modules**: `exec` (`exec_msg`, `exec_dset`, `exec_avp`, `exec_cmd`),
  `counters`, `dlgs`.
- **Replies after a failed relay or in a failure route** are Kamailio's:
  a request-route `t_relay()` failure is answered by tm when the script
  ends (`delayed_reply`; `sl_reply_error()` / `send_reply_error()` send
  nothing then, so the stock `route[RELAY]` sends one final, tm's);
  `send_reply()` / `send_reply_error()` / `t_reply_error()` in a failure
  route answer through the transaction (no best reply after them);
  `sl_send_reply()` / `sl_reply_error()` in a failure_route block are a
  config error.
- **Behaviour fix**: an ACK is never answered statelessly. The stock config
  sends `404` from code that an ACK without a transaction also reaches;
  RFC 3261 forbids answering it, and Kamailio's `sl` drops it.
