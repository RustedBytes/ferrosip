# mod-extra

This crate collects the remaining [Kamailio](../../docs/glossary.md#kamailio)
[modules](../../docs/glossary.md#module) that are worth having. Each one is
a separate `loadmodule`. Look here when you need one of these features:

- SIP tracing to a [HEP](../../docs/glossary.md#hep) collector;
- credit control on [dialogs](../../docs/glossary.md#dialog);
- [transaction](../../docs/glossary.md#transaction) helpers and redirects;
- database-driven data modules: [AVPs](../../docs/glossary.md#avp), raw
  SQL, prefix trees, prefix routing, speed dial;
- [ENUM](../../docs/glossary.md#enum) over DNS;
- RFC 5626 outbound flow tokens;
- transaction storage for late registrations;
- periodic routes;
- an HTTP server with [Prometheus metrics](../../docs/glossary.md#prometheus-metric);
- a Redis client.

Modules that use [tm](../../docs/glossary.md#tm), dialog or
[usrloc](../../docs/glossary.md#usrloc) must be loaded after those.
Database URLs are `sip-db` URLs (for example `text://dir`,
`sqlite://file`).

The examples use [`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml) for
parameters and [`.fsr`](../../docs/glossary.md#fsr) for routing
([docs/fsr.md](../../docs/fsr.md)). The modules load when the routing uses
them. The `.fsr` names are in
[docs/functions-reference.md](../../docs/functions-reference.md). Where
`.fsr` has no form yet, the example stays in Kamailio-style
[`.cfg`](../../docs/glossary.md#cfg).

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `trace` | `siptrace` | HEPv3 copies of SIP traffic and logs to a capture server |
| `credit` | `cnxcc` | Credit, time and channel limits per customer |
| `txn` | `tmx` | Route-type checks, `$T_req` / `$T_rpl` |
| `redirect` | `uac_redirect` | Turn the Contacts of a 3xx reply into new branches |
| `vars` | `avpops` | AVPs from/to `usr_preferences`, AVP operations |
| `sql` | `sqlops` | Raw SQL queries and results |
| `prefix_tree` | `mtree` | Prefix trees from tables |
| `prefix_routes` | `prefix_route` | Run a route chosen by number prefix |
| `speed_dial` | `speeddial` | Per-user short codes |
| `enum` | `enum` | [E.164](../../docs/glossary.md#e164) number to URI through DNS NAPTR |
| `outbound` | `outbound` | RFC 5626 flow tokens for edge proxies |
| `pending_calls` | `tsilo` | Add branches to ringing calls when the callee registers |
| `timers` | `rtimer` | Run a route periodically |
| `http` | `xhttp` | HTTP server: script event route and JSON-RPC |
| `xhttp_prom` | `xhttp_prom` | Prometheus metrics of all statistics |
| `redis` | `ndb_redis` | Redis client (RESP) |

## trace (siptrace)

[siptrace](../../docs/glossary.md#siptrace) sends copies of SIP traffic to
a HEP capture server such as
[Homer](https://github.com/sipcapture/homer), as HEPv3 over UDP. Use it to
see every message of a call in one place when you debug. The Kamailio 4.x
and 5.x configs from Homer's wiki
([Examples: Kamailio](https://github.com/sipcapture/homer/wiki/Examples%3A-Kamailio))
work as they are. `tests/e2e_siptrace.py` runs both against a fake
collector.

- `sip_trace()` traces the current message. With mode `t` (transaction) or
  `d` (dialog), every later message of the same
  [Call-ID](../../docs/glossary.md#call-id) is traced too, received or
  sent:
  - `t` lasts until the transaction is quiet: 32 s after the last traced
    message, and at least 180 s for an
    [INVITE](../../docs/glossary.md#invite);
  - `d` lasts 12 h.
- Each message reaches the collector once. The correlation ID defaults to
  the Call-ID.
- **`trace_flag`** (Kamailio 4.x style): a request is traced as a
  transaction when it carries the flag at the moment ferrosip first sends
  something for it (`t_relay`, a reply). That covers:
  - the request received;
  - the copies sent out;
  - the [100 Trying](../../docs/glossary.md#provisional-reply);
  - the replies, received and sent.

  `setflag(22)` alone is enough. `sip_trace()` on a flagged request traces
  the transaction too. In `.fsr`, [flags](../../docs/glossary.md#flags) get
  their bits from the compiler, so use `trace.set_mode("transaction")` and
  `trace.capture()` instead.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `duplicate_uri` | none (required) | Collector, e.g. `sip:10.0.0.9:9060` |
| `hep_mode_on` | 1 | 0 sends plain SIP copies instead of HEP (then there is no `hlog`) |
| `hep_version` | 3 | Only 3 is accepted |
| `hep_capture_id` | 1 | HEP capture agent ID |
| `auth_key` | none | HEP authentication key chunk |
| `trace_flag` | none | Message flag (0..63) that marks requests to trace |
| `trace_on` | 1 | Tracing switch (also `siptrace.status`) |
| `send_sock_addr` | any | Source IP of the HEP packets, e.g. `sip:10.2.0.2:5000`. The system picks the port, because the SIP listeners own theirs |

`trace_to_database=1` logs a note: there is no database storage, only
HEP. These are accepted with a one-time notice: `db_url`, `table`,
`trace_mode`, `xheaders_write`, `xheaders_read`, `force_send_sock`,
`send_sock_name`, `trace_local_ip`, `trace_sl_acks`, `trace_init_mode`,
`trace_dialog_ack`, `trace_dialog_spiral`, `trace_delayed` and
`hep_vendor_id`.

**Functions**

| Signature | Description |
|---|---|
| `sip_trace([dst[, correlation_id[, mode]]])` | Trace this message (and, for mode `t`/`d`, the rest of the call). `dst` is the collector for this call: `sip:host:port`, or `""` for `duplicate_uri`. Use several calls for several copies. `correlation_id` may contain variables (`"$ci-abc"`). Returns 1 |
| `sip_trace_mode(mode)` | Default mode (`m`, `t`, `d`) for `sip_trace()` calls on this message that give none. Returns 1 |
| `hlog([correlation_id,] message)` | Send a HEP log record (type 100) to `duplicate_uri`. Returns 1 |

**[RPC](../../docs/glossary.md#rpc) commands**

| Command | Description |
|---|---|
| `siptrace.status on\|off\|check` | Switch tracing. Returns "enabled" or "disabled" |

**Example** ([Homer](../../docs/glossary.md#homer))

```toml
[modules.trace]                       # siptrace
duplicate_uri = "sip:10.0.0.1:9060"   # Homer / heplify-server, HEP over UDP
hep_mode_on = true
trace_on = true
```

```rust
import trace

route main(msg: Request) {
    trace.set_mode("transaction")     // sip_trace_mode("t"): the whole transaction
    trace.capture()                   // sip_trace()
    trace.log_with_id(msg.call_id, "routed by ferrosip")   // hlog("$ci", …)
    relay(msg)
}
```

**Differences from Kamailio**:
- HEPv3 over UDP only;
- no database storage;
- no X-headers;
- `sip_trace(dst)` takes a constant address;
- `send_sock_addr` sets the source IP, not the port.

## credit (cnxcc)

`cnxcc` stops customers from spending more than they are allowed. It
controls credit on calls that the `dialog` module tracks. Load `dialog`
first and call `dlg_manage()`. A limit applies to all calls of a customer.
Every 500 ms it checks the customers. When a customer's answered calls
have used up the credit, all their calls are ended with
[BYEs](../../docs/glossary.md#bye) to both sides.

**Parameters**: none. `redis`, `credit_check_period` and `dlg_flag` are
accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `cnxcc_set_max_credit(customer, max_credit, connect_cost, cost_per_second, initial_pulse, final_pulse)` | Money limit. cost = connect_cost + billed seconds * cost_per_second, billed in pulses |
| `cnxcc_set_max_time(customer, max_seconds)` | Limit on the total talk time of the customer's calls |
| `cnxcc_set_max_channels(customer, max)` | Limit on concurrent calls |
| `cnxcc_get_channel_count(customer, $var)` | Number of tracked calls. 1 / -1 |
| `cnxcc_terminate_all(customer)` | End all calls of the customer. Returns 1 |

The `set_max_*` functions return 1 when the call is admitted. They return
-1 when the channel limit is reached, when the credit is already used up,
or when the request has no Call-ID.

**RPC commands**

| Command | Description |
|---|---|
| `cnxcc.active_clients` | Customers with calls: client_id, calls |
| `cnxcc.check_client <customer>` | Limit type, max, consumed, calls |
| `cnxcc.kill_call <callid>` | End one call |

**Example**

```rust
import dialog, credit

route main(msg: Request) {
    dialog.manage()
    guard credit.set_max_time("cust1", 120s) else reply(PaymentRequired, "No credit")
    relay(msg)
}
```

**Differences from Kamailio**: no Redis storage. The check period is fixed.

## txn (tmx)

Transaction helpers on top of tm. Load `tm` first. There are no
parameters.

**Functions** (1 = true, -1 = false)

| Signature | Description |
|---|---|
| `t_is_failure_route()` | Running in a [failure_route](../../docs/glossary.md#failure-route) |
| `t_is_branch_route()` | Running in a [branch_route](../../docs/glossary.md#branch-route) |
| `t_is_reply_route()` | Processing a reply |
| `t_is_request_route()` | Processing a request outside failure/branch routes |
| `t_precheck_trans()` | The request already has a transaction (it is a [retransmission](../../docs/glossary.md#retransmission)) |
| `t_flush_flags()` | No-op (flags are always carried). Returns 1 |

**[Pseudo-variables](../../docs/glossary.md#pseudo-variable-pv)**

| Name | Description |
|---|---|
| `$T_req(pv)` | Evaluate `pv` on the transaction's request |
| `$T_rpl(pv)` | Evaluate `pv` on the reply: the winning reply in failure_route, the reply itself in [reply routes](../../docs/glossary.md#reply-route) |

**Example**

In `.fsr` the failure_route is the code after
[`await`](../../docs/glossary.md#await). `r` is the winning reply:

```rust
route main(msg: Request) {
    let res = await txn.relay(msg)
    match res {
        Final(r) if r.code >= 300 => {
            if txn.in_failure_route() && !txn.in_branch_route() {
                reply(ServerInternalError, "{r.code}-{r.reason}")
            }
        }
        _ => {}
    }
}
```

`$T_req` / `$T_rpl` have no `.fsr` form. So reply headers such as `X-Why`
are read in a Kamailio-style `.cfg`:

```
failure_route[tmx] {
    if (t_is_failure_route() && !t_is_branch_route()) {
        t_reply(500, "$T_rpl($rs)-$T_rpl($hdr(X-Why))");
    }
}
```

## redirect (uac_redirect)

`uac_redirect` follows redirects for the caller. When the callee answers
with a 3xx reply, it turns the reply's
[Contacts](../../docs/glossary.md#contact) into new
[branches](../../docs/glossary.md#branch), so the proxy tries them itself.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `accept_filter` | none | Regex of Contacts to accept (repeatable) |
| `deny_filter` | none | Regex of Contacts to refuse (repeatable, checked first) |
| `default_filter` | `accept` | `accept` or `deny` for Contacts matching no filter |

`acc_function`, `acc_db_table`, `bflags`, `flags_hdr_mode` and `q_value`
are accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `get_redirects(max[, reason])` | In a failure_route: the Contacts of the 3xx become the [R-URI](../../docs/glossary.md#r-uri) and new branches. They are taken highest [q](../../docs/glossary.md#q-value) first, at most `max` (0 = all; for `"a:b"` the last number counts). `t_relay()` then [forks](../../docs/glossary.md#forking) to them. Returns the number added, or -1 |

**Example**

The failure_route is the code after `await`. `redirect.add_branches()` is
`get_redirects()`:

```rust
import redirect

route main(msg: Request) {
    let res = await txn.relay(msg)
    match res {
        Final(r) if r.code in 300..399 => {
            if redirect.add_branches(3) {
                relay(msg)               // forks to the redirect Contacts
            }
        }
        Timeout | Final(_) => {}         // the best reply goes upstream
    }
}
```

**Differences from Kamailio**: `reason` is ignored. Redirects are not
accounted.

## vars (avpops)

`avpops` loads per-user settings from the database into AVPs and works
on AVPs. The settings are AVPs loaded from and stored to the
`usr_preferences` table. Its columns are uuid, username, domain,
attribute, type and value (type 1 = integer). `source` is a URI string
(such as `$fu`). `name` is `$avp(x)` or `*`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none | Database URL (needed for the `avp_db_*` functions) |
| `avp_table` | `usr_preferences` | Table name |
| `use_domain` | 0 | Also match the domain of `source` |

The `*_column` parameters and `db_scheme` are accepted and ignored.

**Functions** (1 = success, -1 = nothing found / error)

| Signature | Description |
|---|---|
| `avp_db_load(source, name)` | Load the user's AVPs (all with `*`) |
| `avp_db_store(source, name)` | Insert the AVP(s) as rows |
| `avp_db_delete(source, name)` | Delete the user's rows (1 only if rows were deleted) |
| `avp_delete(name)` | Remove an AVP (`*` = all) |
| `avp_copy(src, "dst[/flags]")` | Append `src`'s newest value to `dst`. Flags, combinable (`/gd`): `g` every value, `d` remove what was copied from `src`, `n` / `s` cast to integer / string |
| `avp_pushto(dest, $avp(x))` | Last value into `$ru`, `$du`, `$ru/username` or `$ru/domain` |
| `avp_check($avp(x), "op/value[/flags]")` | True if the newest value matches, or with `/g` any value. Ops: `eq ne lt le gt ge re fm`, plus `band bor bxor` on integers (numeric when both sides are integers). On strings `lt`…`ge` and `re` ignore case, `eq`/`ne`/`fm` only with `/i`, as in Kamailio |
| `avp_print()` | Log all AVPs (L_INFO). Returns 1 |

**Example**

```toml
[modules.vars]
db_url = "text:///etc/ferrosip/db"
```

`.fsr` has no AVPs, so this stays in a Kamailio-style `.cfg`. In `.fsr`,
read `usr_preferences` with `sql.query_value` instead.

```
request_route {
    avp_db_load("$fu", "*");
    if (avp_check("$avp(limit)", "gt/3")) { xlog("L_INFO", "high limit\n"); }
}
```

## sql (sqlops)

Raw SQL on named connections.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `sqlcon` | none | `name=>db_url` (repeatable) |

`sqlres`, `tr_buf_size`, `connect_mode` and `results_maxsize` are
accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `sql_query(con, query[, res])` | Run a query. Rows are kept in `res`. 1 = rows or a non-SELECT, 2 = SELECT without rows, -1 = error |
| `sql_query_async(con, query)` | Queue the statement on a background thread (in order, no result). 1 / -1 |
| `sql_xquery(con, query, xavp)` | One `$xavp(xavp)` item per row, with column names as keys. 1 = rows, 2 = none, -1 = error |
| `sql_pvquery(con, query, "$var(a),$avp(b)")` | First row's columns into the listed variables. 1 / 2 (no row) / -1 |
| `sql_result_free(res)` | Drop a result. Returns 1 |

**Pseudo-variables**: `$dbr(res=>rows)`, `$dbr(res=>cols)`,
`$dbr(res=>[row,col])`, `$dbr(res=>colname[col])`.

**Example**

```toml
[modules.sql]                          # sqlops
sqlcon = ["db=>sqlite:///var/lib/ferrosip/data.sqlite"]
```

```rust
import sql

route main(msg: Request) {
    let name = ""
    sql.query_value("db", "select name from numbers where num = {sql.quote(msg.ruri.user)}", name)
    if name != "" {
        log.info("name: {name}\n")
    }
    reply(NotFound)
}
```

Message values go into SQL through `sql.quote(v)`. That is Kamailio's
`{sql.val.str}`: the value goes in quotes, with `'` and `\` doubled. Never
interpolate message values raw, because a quote is legal in a SIP user
part. In a `.cfg`, use `$(rU{sql.val})`, `{sql.val.int}` or
`{sql.val.str}`.

`sql.query` (`sql_query`) keeps the rows for `$dbr`. `.fsr` reads them
with `pv("$dbr(r=>[0,0])")`, the
[escape hatch](../../docs/glossary.md#escape-hatch). For several rows or
columns, a `.cfg` route reads more easily:

```
request_route {
    sql_query("db", "select name from numbers where num=$(rU{sql.val})", "r");
    if ($dbr(r=>rows) > 0) { xlog("L_INFO", "name: $dbr(r=>[0,0])\n"); }
    sql_result_free("r");
}
```

## prefix_tree (mtree)

`mtree` looks up the longest matching prefix of a number in a table, for
example to find the gateway for a dialled number. The prefix trees are
loaded from tables with `tprefix` and `tvalue` columns.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database URL |
| `mtree` | none | `name=<tree>;dbtable=<table>` (repeatable). `dbtable` defaults to `mtree` |
| `pv_value` | `$avp(tvalue)` | Variable that receives the matched value(s) |

These are accepted and ignored: `db_table`, `char_list`, `fetch_rows`,
`pv_dstid`, `pv_weight`, `pv_count`, `mt_tree_type`,
`mt_ignore_duplicates`, `mt_allow_duplicates`, `tprefix_column` and
`tvalue_column`.

**Functions**

| Signature | Description |
|---|---|
| `mt_match(tree, value, mode)` | Mode 0: values of the longest matching prefix. Mode 1: values of all matching prefixes (longest first). The values go into `pv_value`. 1 / -1 |

**RPC commands**

| Command | Description |
|---|---|
| `mtree.reload` | Reload all trees. Returns the number of rows |
| `mtree.list [tree]` | Entries: tree, tprefix, tvalue |
| `mtree.match <tree> <value> [mode]` | Matching values |

**Example**

```toml
[modules.prefix_tree]
db_url = "text:///etc/ferrosip/db"
mtree = ["name=gw;dbtable=mtree"]
```

```rust
import prefix_tree

route main(msg: Request) {
    if prefix_tree.lookup("gw", msg.ruri.user) {
        log.info("{msg.ruri.user} has a gateway\n")
    }
    reply(NotFound)
}
```

The matched value goes to `$avp(tvalue)` (`pv_value`), which `.fsr`
cannot read. To use it, write that part in a Kamailio-style `.cfg`:

```
request_route {
    if (mt_match("gw", "$rU", "0")) { xlog("L_INFO", "gateway $avp(tvalue)\n"); }
}
```

## prefix_routes (prefix_route)

`prefix_route` picks a [route block](../../docs/glossary.md#route-block)
from the dialled number. It runs `route[NAME]` for the longest prefix of
the number found in the table. The table has the columns `prefix` and
`route`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database URL |
| `db_table` | `prefix_route` | Table name |

`exit` is accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `prefix_route([user])` | Match `user` (default: the R-URI user) and run its route. Returns the route's result, or -1 when no prefix or route matches |

**RPC commands**:

- `prefix_route.reload` returns the number of prefixes.
- `prefix_route.dump` shows the prefix to route map.

**Example**

The table's route names are `.fsr` route names. `route PR_DE` is
`route[PR_DE]`. The routes of a file imported `as pstn` are `pstn__NAME`.

```toml
[modules.prefix_routes]
db_url = "text:///etc/ferrosip/db"
```

```rust
import prefix_routes

route main(msg: Request) {
    prefix_routes.run()
    reply(NotFound, "No route for this prefix")
}

route PR_DE(msg: Request) {
    txn.relay("udp:10.0.0.49:5060")   // relays, then the script ends
}
```

**Differences from Kamailio**: the `exit` parameter is ignored. The script
continues after `prefix_route()` unless the route itself exits.

## speed_dial (speeddial)

`speeddial` lets each user dial short codes that expand to full
addresses.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database URL |
| `use_domain` | 0 | Also match the owner's domain |

The `*_column` parameters and `domain_prefix` are accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `sd_lookup(table[, owner])` | The R-URI user is a short code of `owner` (default: the From URI). The row's `new_uri` becomes the R-URI. Columns: username, domain, sd_username, sd_domain, new_uri. 1 / -1 |

**Example**

```toml
[modules.speed_dial]
db_url = "text:///etc/ferrosip/db"
```

Inside `route main(msg: Request)`, with `import speed_dial`:

```rust
if msg.ruri.user =~ "^1[0-9]$" {
    if speed_dial.lookup("speed_dial") {
        relay(msg)
    }
}
```

## enum

`enum` turns an E.164 phone number (`+4930...`) into a SIP URI by asking
DNS. It reads DNS NAPTR records (RFC 6116, see
[DNS resolution](../../docs/glossary.md#dns-resolution)). It takes the
first matching record: flag `u`, the configured service, ordered by order
and preference. It applies that record's regexp to the number. The
resolver is a minimal DNS-over-UDP client.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `domain_suffix` | `e164.arpa.` | ENUM tree |
| `service` | `e2u+sip` | NAPTR service |
| `nameserver` | first server in `/etc/resolv.conf` | ferrosip-only: `ip[:port]` of the DNS server |

`tel_uri_params`, `i_enum_suffix`, `branchlabel` and `bl_algorithm` are
accepted and ignored.

**Functions** (1 = found, -1 = not found)

| Signature | Description |
|---|---|
| `enum_query([suffix[, service]])` | Rewrite the R-URI from its E.164 user |
| `i_enum_query([suffix[, service]])` | Same as `enum_query` |
| `enum_pv_query(number[, suffix[, service]])` | Same for a given number or URI. The result becomes the R-URI |
| `is_from_user_enum([suffix[, service]])` | 1 when the From user's number maps to a URI of this proxy |

**Example**

```toml
[modules.enum]
nameserver = "127.0.0.1:53"
```

Inside `route main(msg: Request)`, with `import enum`:

```rust
if msg.ruri.user =~ "^\\+" {
    if enum.query() {
        relay(msg)
    }
}
```

**Differences from Kamailio**: no infrastructure ENUM (`i_enum_query` is
an alias), and no branch-label handling.

## outbound

`outbound` implements [RFC 5626](../../docs/glossary.md#sip-outbound) for
edge proxies. It lets requests reach a client over the same connection the
client opened, even behind [NAT](../../docs/glossary.md#nat).

It turns on HMAC-signed flow tokens in the user part of
[Path](../../docs/glossary.md#path) /
[Record-Route](../../docs/glossary.md#record-route). The `path` and `rr`
modules use them. A token is added in either of these cases:

- the client is the direct neighbour (one [Via](../../docs/glossary.md#via))
  and its Contact has `;ob`;
- the force flag is set.

`loose_route()` on such a token sends the request back over the client's
flow. There are no script functions.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `flow_token_secret` | random at startup | HMAC secret for the tokens |
| `force_outbound_flag` | none | Message flag that forces a flow token without `;ob` |

`force_no_outbound_flag` is accepted and ignored.

**Example**

```toml
[modules.outbound]
flow_token_secret = "change-me"

[modules.location]                     # registrar
outbound_mode = "on"
```

## pending_calls (tsilo)

`tsilo` handles a callee whose phone registers while a call to it is
already ringing, for example a mobile client that wakes up on a push
notification. The new device still gets the call.

It works by transaction storage. An INVITE's transaction is stored under
the callee's [AoR](../../docs/glossary.md#aor). A client that registers
while the call still rings gets a branch of that transaction. Load `tm`
and `usrloc` first. Entries are kept for at most 180 s, and only while
the transaction is pending.

**Parameters**: none. `hash_size` and `use_dialog` are accepted and
ignored.

**Functions**

| Signature | Description |
|---|---|
| `ts_store([uri])` | After `t_relay()`: store the transaction under the AoR of `uri` (default: the R-URI). 1 / -1 |
| `ts_append(table[, uri])` | After `save()`: add the just-saved contacts as branches to the transactions stored for `uri` (default: the To URI). Returns the number of branches added, or -1. `table` is not used |

**RPC commands**: `ts.dump` lists the stored transactions per AoR.

**Example**

`location.save_and_continue()` answers the
[REGISTER](../../docs/glossary.md#register) like `location.save()`. But the
route goes on, so `pending_calls.append()` can follow it:

```rust
import location, pending_calls

route main(msg: Request) {
    if msg.method == REGISTER {
        if location.save_and_continue() {
            pending_calls.append(uri: "sip:{msg.to.user}@{msg.to.host}")
        }
        exit
    }
    guard location.lookup() else reply(NotFound, "Not Found")
    relay(msg)
}
```

`ts_store()` must follow `t_relay()`, because `t_newtran()` does not create
the transaction here. And `relay()` ends a `.fsr` route. So storing the
INVITE stays in a Kamailio-style `.cfg`:

```
if (lookup("location")) { t_relay(); ts_store(); exit; }
```

## timers (rtimer)

`rtimer` runs routes periodically, for example for cleanup or counters.
Each timer runs on its own thread.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `timer` | none | `name=<name>;interval=<n>` (repeatable). The interval is in s, or with an `ms` / `us` suffix. Default 60 s |
| `exec` | none | `timer=<name>;route=<ROUTE>` (repeatable): run `route[ROUTE]` on that timer |

`default_interval` is accepted and ignored.

**Example**

In `.fsr`, `on timer(every: …)` sets up the rtimer timer and route. No
parameters are needed:

```rust
shared table counters: Map<Str, Counter>

on timer(every: 10s) {
    counters.incr("ticks")
}
```

The `timer` / `exec` parameters run a route of a Kamailio-style `.cfg`.
`.fsr` uses `on timer` instead.

```toml
[modules.timers]
timer = ["name=t1;interval=10"]
exec = ["timer=t1;route=TICK"]
```

```
route[TICK] { $shv(ticks) = $shv(ticks) + 1; }
```

## http (xhttp)

`xhttp` lets the proxy answer HTTP requests: a status page, a webhook or
remote control. It is an HTTP/1.1 server on its own listener, with
keep-alive and bodies up to 1 MB.

- `POST /RPC` is JSON-RPC 2.0 against the RPC table.
- Other URLs run `event_route[xhttp:request]`, an
  [event route](../../docs/glossary.md#event-route). There the HTTP request
  is presented as a SIP message, so `$hdr(name)` and `$rb` work.
- Without an event route, or without a reply from it, the answer is 404.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `listen` | none (required) | `ip:port` to listen on |
| `url_match` | none | Regex: only matching URLs reach the script |
| `url_skip` | none | Regex: matching URLs do not reach the script |

`event_callback` is accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `xhttp_reply(code, reason, ctype, body)` | Answer the HTTP request (only in the xhttp event route). 1 / -1 |

**Pseudo-variables**: `$hu` (URL), `$hm` (method).

**Event routes**: `event_route[xhttp:request]`.

**Example**

```toml
[modules.http]                         # xhttp
listen = "127.0.0.1:8080"
```

`event_route[xhttp:request]` is `on http`. `req.reply` is `xhttp_reply`:

```rust
on http(req: HttpRequest) {
    req.reply(200, "url={req.url} method={req.method} body={req.body}", "text/plain")
}
```

**Differences from Kamailio**: Kamailio serves HTTP on its SIP TCP
sockets. ferrosip uses the separate `listen` address.

## xhttp_prom

`xhttp_prom` lets Prometheus scrape ferrosip's
[statistics](../../docs/glossary.md#statistics). It serves the metrics on
the `xhttp` listener, so load `xhttp` first. Every statistic becomes a
[gauge](../../docs/glossary.md#gauge) named `<prefix><group>_<name>`.
Non-alphanumeric characters become `_`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `xhttp_prom_path` | `/metrics` | URL path |
| `xhttp_prom_beginning` | `kamailio_` | Metric name prefix (keeps existing dashboards working) |
| `xhttp_prom_stats` | `all` | `all` or a comma-separated list of statistic groups |

These are accepted and ignored: `prom_counter`, `prom_gauge`,
`prom_histogram`, `xhttp_prom_buf_size`, `xhttp_prom_timeout`,
`xhttp_prom_tags` and `xhttp_prom_pkg_stats`.

**Differences from Kamailio**: no custom counters, gauges or histograms
from the script.

## redis (ndb_redis)

`ndb_redis` lets the script read and write a Redis server, for example to
share state between proxies. It is a Redis client over RESP/TCP with one
connection per server.

- A dropped connection is opened again, with AUTH and SELECT.
- A command that times out is not retried. The connection is opened again
  for the next command.
- Other failures are counted in the `redis:errors` statistic. These are:
  connection refused or lost, and AUTH/SELECT refused.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `server` | none | `name=<srv>;addr=<host>;port=<port>;db=<n>;pass=<pw>` (repeatable). addr defaults to 127.0.0.1, port to 6379 |
| `connect_timeout` | `1s` | Timeout of a connection attempt |
| `cmd_timeout` | `1s` | Timeout of a command (its reply) |
| `allowed_timeouts` | `-1` | Consecutive timeouts after which a server is skipped for `disable_time` (-1: never) |
| `disable_time` | `0s` | How long a server that timed out too often is skipped. Its commands fail at once |

These are accepted and ignored: `init_without_redis`, `cluster`,
`flush_on_reconnect`, `allow_dynamic_nodes`, `debug` and `ca_path`.

**Functions**

| Signature | Description |
|---|---|
| `redis_cmd(srv, command[, args...], res)` | The command is split on spaces. `%s`/`%d`/`%b` take the next argument whole (spaces kept). 1, or -1 for an unknown server, a connection error or a Redis error reply |
| `redis_free(res)` | Drop a result. Returns 1 |

**Pseudo-variables**:

- `$redis(res=>type)`: 1 string, 2 array, 3 integer, 4 nil, 5 status,
  6 error;
- `$redis(res=>value)`;
- `$redis(res=>info)`: the status or error text;
- `$redis(res=>size)`: the array length;
- `$redis(res=>value[n])`.

**Example**

```toml
[modules.redis]
server = ["name=r1;addr=127.0.0.1;port=6379"]
```

```rust
import redis

route main(msg: Request) {
    redis.exec_with("r1", "SET k %s", msg.headers["X-V"], "a")   // redis_cmd
    redis.free("a")
    reply(OK)
}
```

Replies are read through `$redis`. `.fsr` reads it with
`pv("$redis(r=>value)")`, the escape hatch. In a Kamailio-style `.cfg`:

```
request_route {
    redis_cmd("r1", "GET k", "b");
    xlog("L_INFO", "$redis(b=>value) type $redis(b=>type)\n");
    redis_free("b");
}
```

**Differences from Kamailio**: no cluster mode, no TLS.

## Testing

- `tests/e2e_extra.py` covers every module here:
  - siptrace (fake HEP collector, transaction mode);
  - cnxcc (max time ends the call with BYEs);
  - tmx, uac_redirect, avpops, sqlops (SQLite), mtree, prefix_route,
    speeddial;
  - enum (fake DNS);
  - outbound flow tokens, tsilo, rtimer;
  - xhttp (event route and `/RPC`), xhttp_prom;
  - ndb_redis (fake Redis).

  The same suite also tests `auth_ephemeral`, `app_lua` and registrar
  [GRUU](../../docs/glossary.md#gruu), which live in other crates.
- `tests/e2e_async.py` covers `sql_query_async`.
- Unit tests: cnxcc pulse billing, ENUM NAPTR parsing and regexp
  rewriting, Prometheus metric names, RESP encoding/decoding and
  `redis_cmd` tokenizing.
- Fuzzing: `fuzz/fuzz_targets/dns.rs` covers the DNS response parser that
  `enum` uses.
