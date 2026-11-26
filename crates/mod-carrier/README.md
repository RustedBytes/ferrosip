# mod-carrier

This crate holds the modules a carrier or a PBX trunk needs to route calls
to gateways and bill for them. Use it when ferrosip sends calls to the
phone network, rewrites numbers, keeps call records, registers to upstream
providers or must hide the internal network from peers.

It provides five features:

- number translation (`dialplan`);
- [least cost routing](../../docs/glossary.md#lcr) over gateways, with the
  [Sipwise](../../docs/glossary.md#sipwise) patches (`lcr`);
- transaction accounting and [CDRs](../../docs/glossary.md#cdr) (`acc`);
- the proxy acting as a client (`uac`): From/To replacement, digest
  answers, requests from the script and remote registrations;
- [topology hiding](../../docs/glossary.md#topology-hiding) (`topoh`,
  `topos`).

`lcr` (for `ping_interval`), `acc` and `uac` use the
[tm](../../docs/glossary.md#tm) module. `acc` CDRs also need `dialog`. With
[`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml) the load order
follows from these dependencies. In a plain
[`.cfg`](../../docs/glossary.md#cfg), load `tm` (and `dialog`) first.

The examples use `ferrosip.toml` for parameters and
[`.fsr`](../../docs/glossary.md#fsr) for routing
([docs/fsr.md](../../docs/fsr.md)). In `.fsr` the modules have new names:
`dialplan`, `carriers` (lcr), `cdr` (acc), `client` (uac) and `topology`
(topoh). `topos` keeps its name. The `.fsr` function names are in
[docs/functions-reference.md](../../docs/functions-reference.md). Where
`.fsr` has no form yet, the example stays in
[Kamailio](../../docs/glossary.md#kamailio)-style `.cfg`.

| Module | Kamailio [module](../../docs/glossary.md#module) (`loadmodule`) | Purpose |
|---|---|---|
| `dialplan` | `dialplan` | Match and translate numbers with rules from the `dialplan` table |
| `carriers` | `lcr` (Sipwise build) | Pick gateways by prefix, priority and weight. Failover. Gateway statistics |
| `cdr` | `acc` | Accounting records to the log and database. CDRs from dialogs |
| `client` | `uac` | From/To replacement with restore, `uac_auth`, `uac_req_send`, remote registrations |
| `topology` | `topoh` | Topology hiding, with the hidden data encoded in the message |
| `topos` | `topos` | Topology hiding, with the hidden data stored on the proxy |

## dialplan

`dialplan` rewrites numbers, for example to normalise a dialled number
before routing. Rules are read from the database at startup and with
`dialplan.reload`.

The rules of a dialplan id are tried by ascending `pr`. A rule matches when
both of these hold:

- `match_len` is 0 or equals the input length;
- `match_exp` matches the input. `match_op` says how: 0 is string equality,
  1 is a regular expression, 2 is a shell glob with `*`, `?`, `[a-z]`,
  `[!x]`.

The first matching rule is applied:

- With a `subst_exp`, its first match in the input is replaced by
  `repl_exp`. `\1`... are back-references.
- Without one, the output is `repl_exp`. When `repl_exp` is empty, the
  input is returned unchanged.

The rule's `attrs` go to `attrs_pvar`. A rule that fails to compile is
logged and skipped. It is not fatal (Sipwise patch).

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database with the rules |
| `table_name` | `dialplan` | Rules table |
| `attrs_pvar` | none | Variable that receives the matching rule's `attrs` |

Accepted for compatibility and ignored: `fetch_rows`, `match_dynamic`,
`append_branch`, `reload_delta` and the `*_col` column-name parameters.

**Functions**

| Signature | Description |
|---|---|
| `dp_translate(id[, "$src/$dst"])` | Translates the value of `$src` into `$dst` (default `$rU/$rU`). 1 if a rule matched, -1 otherwise |
| `dp_match(id, input)` | 1 if a rule of `id` matches `input` (sets `attrs_pvar`), -1 otherwise |
| `dp_replace(id, input, $dst)` | Translates `input` into `$dst`. 1 or -1 |

**[RPC](../../docs/glossary.md#rpc) commands**

| Command | Description |
|---|---|
| `dialplan.reload` | Re-reads the table. Returns the number of rules loaded |
| `dialplan.dump <dpid>` | Rules of a dialplan: PRIORITY, MATCH EXPR, MATCH LEN, SUBST EXPR, REPLACE EXPR, ATTRS |
| `dialplan.translate <dpid> <input>` | `{"Output", "Attributes"}`, or an error when no rule matched |

**Database tables**: `dialplan` (`dpid`, `pr`, `match_op`, `match_exp`,
`match_len`, `subst_exp`, `repl_exp`, `attrs`). See `etc/schema/`.

**Example**

```toml
[modules.dialplan]
db_url = "sqlite:///var/lib/ferrosip/ferrosip.db"
```

```rust
import dialplan

route main(msg: Request) {
    let input = msg.ruri.user
    if dialplan.replace(1, input, out) {     // dp_replace: the result goes into `out`
        log.info("{input} -> {out}\n")
        msg.ruri.user = out
    }
    relay(msg)
}
```

- `dialplan.translate(1)` translates the
  [R-URI](../../docs/glossary.md#r-uri) user in place.
- `attrs_pvar` names a
  [pseudo-variable](../../docs/glossary.md#pseudo-variable-pv), which
  `.fsr` can't read. To use a rule's `attrs`, keep that part in a
  Kamailio-style `.cfg`:
  `modparam("dialplan", "attrs_pvar", "$avp(dpattrs)")`, then read
  `$avp(dpattrs)` after `dp_translate()` or `dp_match()`.

**Differences from Kamailio**

- Patterns use Rust's `regex` syntax. There is no look-around, and no
  back-references inside the pattern itself.
- Column names are fixed. The `*_col` parameters are ignored.
- The `src/dst` argument of `dp_translate` must be exactly two variables
  separated by `/`.

## carriers (lcr)

`lcr` picks the gateways that can take a call and tries them in order. It
reads gateways, rules and rule targets at startup and with `lcr.reload`.

`load_gws()` collects the gateways of every enabled rule of the given
`lcr_id` that meets all three conditions:

- its `prefix` starts the user part;
- its `from_uri` regex matches the caller URI;
- its `request_uri` regex matches the R-URI.

An empty pattern matches anything. Gateways with `lcr_id` 0 serve every
lcr_id. Defunct and inactive gateways are skipped.

The list is ordered by longest prefix, then lowest priority, then a
weighted random draw. With `priority_ordering=1` only priority and weight
count. A gateway listed by several rules keeps its best position. The list
is kept with the [transaction](../../docs/glossary.md#transaction), so
`next_gw()` also works in a
[`failure_route`](../../docs/glossary.md#failure-route). In `.fsr` that place
is after `await txn.relay(…)`. See [await](../../docs/glossary.md#await).

Stopper rules:

- By default (`stopper_mode=0`), a matching stopper rule hides the rules
  with shorter prefixes.
- With the Sipwise `stopper_mode=1`, all matching rules take part. But the
  ordered list ends after the first gateway that came from a stopper rule.

`next_gw()` rewrites the R-URI for the next gateway:

1. It takes the original user part, saved on the first call.
2. It removes `strip` leading characters and adds `prefix`. Both steps are
   skipped when `dont_strip_or_prefix_flag` is set.
3. It builds the URI: `sip:` or `sips:` (`uri_scheme` 2), the gateway host,
   port, `params` and `;transport=` (`transport` 1 udp, 2 tcp, 3 tls,
   4 sctp).

A gateway with both `hostname` and `ip_addr` gets the hostname in the R-URI.
The IP (with port and transport) goes in `$du`, the
[destination URI](../../docs/glossary.md#destination-uri).

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database with the tables |
| `lcr_gw_table` | `lcr_gw` | Gateways table |
| `lcr_rule_table` | `lcr_rule` | Rules table |
| `lcr_rule_target_table` | `lcr_rule_target` | Rule targets table |
| `priority_ordering` | 0 | 1: order by priority and weight, ignoring prefix length |
| `stopper_mode` | 0 | Sipwise: non-zero cuts the gateway list after a stopper rule's gateway (see above) |
| `lcr_stats` | 0 | Sipwise: count requests and replies received from each gateway |
| `dont_strip_or_prefix_flag` | none | Transaction flag that turns off strip/prefix in `next_gw()` |
| `ping_interval` | 0 | Seconds between [OPTIONS](../../docs/glossary.md#options) pings of inactive gateways. 0 = off (needs tm) |
| `ping_from` | `sip:lcr@localhost` | From URI of the pings |
| `ping_valid_reply_codes` | empty | Comma-separated codes that also re-activate a gateway (2xx always do) |
| `tag_avp` | none | Variable set to the gateway's `tag` (`next_gw`, `from_gw`, `from_any_gw`) |
| `flags_avp` | none | Variable set to the gateway's `flags` (same functions) |
| `rule_id_avp` | none | Variable set to the rule id by `next_gw()` |
| `gw_id_avp` | none | Sipwise: variable set to the gateway id by `next_gw()` |
| `lcr_id_avp` | none | Variable set to the lcr_id by `next_gw()` |

Accepted for compatibility and ignored: `gw_uri_avp`, `ruri_user_avp`,
`defunct_gw_avp`, `defunct_capability`, `lcr_count`, `lcr_rule_hash_size`,
`lcr_gw_count`, `fetch_rows`, `ping_inactivate_threshold`, `ping_socket`,
`mt_pv_values`, `mtree` and every `*_column` parameter.

**Functions**

| Signature | Description |
|---|---|
| `load_gws(lcr_id[, uri_user[, caller_uri]])` | Selects and orders the gateways (`uri_user` defaults to the R-URI user). 1 if any matched. 2 if none matched (then `next_gw()` fails). -1 on a bad `lcr_id` |
| `next_gw()` | Rewrites the R-URI (and `$du`) for the next gateway. -1 when none is left |
| `defunct_gw(period)` | Marks the gateway chosen by the last `next_gw()` as defunct for `period` seconds (min 1). -1 if there is none |
| `inactivate_gw()` | Marks that gateway inactive until a ping succeeds or `lcr.defunct_gw ... 0`. -1 if there is none |
| `from_gw(lcr_id[, ip, proto[, port]])` | 1 if the source address (or the given one) is a gateway of `lcr_id`, -1 otherwise. `proto` is `1`/`udp`, `2`/`tcp` or `3`/`tls`. The port is compared only when given (gateway default 5060) |
| `from_any_gw([ip, proto[, port]])` | The matching gateway's lcr_id (at least 1), or -1 |
| `to_gw(lcr_id[, ip, proto])` | 1 if the R-URI host (an IP) and transport parameter, or the given ones, are a gateway of `lcr_id`. -1 otherwise |
| `to_any_gw([ip, proto])` | The matching gateway's lcr_id, or -1 |

**RPC commands**

| Command | Description |
|---|---|
| `lcr.reload` | Re-reads the tables (defunct state is kept). Returns `{"gws", "rules"}` counts |
| `lcr.dump_gws` | Gateways with `state` (active / defunct / inactive), `defunct_until` and, with `lcr_stats=1`, `stats` |
| `lcr.dump_rules` | Rules with prefix, from_uri, request_uri, stopper and targets (gw_id, priority, weight) |
| `lcr.defunct_gw <lcr_id> <gw_id> <period>` | Makes a gateway defunct for `period` seconds. `period` <= 0 re-activates it |
| `lcr.load_gws <lcr_id> <uri_user> [caller_uri] [request_uri]` | The ordered selection `load_gws` would make: gw_id, gw_name, rule_id, priority |
| `lcr.stats` | Per-gateway statistics. An error unless `lcr_stats=1` |

**[Statistics](../../docs/glossary.md#statistics)**: these need
`lcr_stats=1`. `lcr.dump_gws` and `lcr.stats` show them. They are not in
the core statistics. They are kept per gateway, matched by source IP,
transport and port:

- `rcv_gw_reqs`;
- `rcv_gw_reqs_<method>` (`invite`, `cancel`, `ack`, `bye`, `info`,
  `register`, `subscribe`, `notify`, `other`);
- `rcv_gw_rpl_1xx` ... `rcv_gw_rpl_6xx`.

**Database tables**: `lcr_gw`, `lcr_rule`, `lcr_rule_target` (see
`etc/schema/`). In `lcr_gw`, `defunct` > 0 is a Unix time until which the
gateway is defunct. Rules with `enabled` = 0 are skipped. Target weights
are clamped to 1-254.

**Example**

```toml
[modules.carriers]                # lcr
db_url = "sqlite:///var/lib/ferrosip/ferrosip.db"
lcr_stats = true
gw_id_avp = "$avp(gwid)"
```

```rust
import carriers

route main(msg: Request) {
    guard carriers.load_gateways(1) else reply(ServerInternalError, "LCR error")
    // Each gateway in turn; a 503 or no answer takes it out for 60s.
    while carriers.next_gateway() {
        let res = await txn.relay(msg)
        match res {
            Final(r) if r.code == ServiceUnavailable => carriers.defunct_gateway(60s)
            Timeout => carriers.defunct_gateway(60s)
            Final(r) => forward(r)
        }
    }
    reply(ServiceUnavailable, "No gateway")
}
```

`await` replaces `t_on_failure()` and the `failure_route`. The loop goes on
with the next gateway after a 503 or a timeout.

**Differences from Kamailio**

- No `mtree` support (`mt_tvalue` is not used).
- Pings only probe gateways put out of service with `inactivate_gw()`.
- `from_uri` and `request_uri` use Rust's `regex` syntax.
- `load_gws()` returns 2 (still true) when no gateway matched.

## cdr (acc)

`acc` writes a record for each call attempt, for billing and reporting.

Transactions are accounted when tm sends their
[final reply](../../docs/glossary.md#final-reply) upstream. Only
transactions that carry the configured [flags](../../docs/glossary.md#flags)
are recorded. Set the flags before `t_relay()`.

- `log_flag` / `db_flag` record answered transactions (< 300). They also
  record failed ones when `failed_transaction_flag` is set.
- `log_missed_flag` / `db_missed_flag` record failed transactions (>= 300)
  as missed calls.
- With `early_media=1`, a 183 is recorded as well.

A record holds these fields:

- the [method](../../docs/glossary.md#method);
- the From [tag](../../docs/glossary.md#tag);
- the To tag (from the reply);
- the [Call-ID](../../docs/glossary.md#call-id);
- the reply code and reason;
- the time (Unix seconds);
- the `log_extra` / `db_extra` values, evaluated on the request.

Log records are written at NOTICE level as
`ACC: transaction answered: timestamp=...;method=...;from_tag=...;to_tag=...;call_id=...;code=...;reason=...`
(`call missed` for failures).

With `cdr_enable=1`, each confirmed [dialog](../../docs/glossary.md#dialog)
that ends produces a CDR. It is logged as
`CDR: call_start_time=...;duration=...;...`. It is also written to
`cdrs_table` when `db_url` is set.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `log_flag` | -1 (off) | Flag: log answered transactions |
| `log_missed_flag` | -1 (off) | Flag: log failed transactions as missed calls |
| `db_flag` | -1 (off) | Flag: write answered transactions to `db_table_acc` |
| `db_missed_flag` | -1 (off) | Flag: write failed transactions to `db_table_missed_calls` |
| `failed_transaction_flag` | -1 (off) | Flag: `log_flag` / `db_flag` also record failed transactions |
| `early_media` | 0 | 1: also record 183 replies |
| `db_url` | none | Database for records and CDRs |
| `db_table_acc` | `acc` | Table for `db_flag` records |
| `db_table_missed_calls` | `missed_calls` | Table for `db_missed_flag` records |
| `log_extra` | empty | `name=$pv;...` added to log records |
| `db_extra` | empty | `name=$pv;...` added to database records (each name is a column) |
| `cdr_enable` | 0 | 1: CDRs from the dialog module (load `dialog` first) |
| `cdrs_table` | `cdrs` | CDR table |
| `cdr_extra` | empty | `name=$dlg_var(x);...` added to CDRs (only `$dlg_var`) |

Accepted for compatibility and ignored: `log_level`, `log_facility`,
`report_ack`, `report_cancels`, `detect_direction`, `multi_leg_info`,
`db_insert_mode`, `time_mode`, `cdr_start_on_confirmed`, `cdr_log_enable`,
`acc_time_column`, `acc_sip_code_column`, `acc_sip_reason_column`.

**Functions**

| Signature | Description |
|---|---|
| `acc_log_request(comment)` | Logs the current request now (`comment` = `"code reason"`). 1, or -1 for a reply |
| `acc_db_request(comment, table)` | Writes the current request to `table` now. -1 without `db_url` |

**Database tables**:

- `acc` and `missed_calls`: `method`, `from_tag`, `to_tag`, `callid`,
  `sip_code`, `sip_reason`, `time`, plus a column per `db_extra` name. The
  schema has `src_user` and `dst_user`.
- `cdrs`: `sip_call_id`, `sip_from_tag`, `sip_to_tag`, `src_username`,
  `src_domain`, `dst_username`, `dst_domain`, `call_start_time`,
  `duration`, plus `cdr_extra` columns.

See `etc/schema/`.

**Example**

```toml
[modules.cdr]                     # acc
log_flag = 1
db_flag = 2
db_missed_flag = 3
db_url = "sqlite:///var/lib/ferrosip/ferrosip.db"
db_extra = "src_user=$fU;dst_user=$rU"
cdr_enable = true

[routing]
entry = "main.cfg"
```

The routing stays in a Kamailio-style `.cfg`. acc selects transactions by
flag number, and `.fsr` flags get their bits from the compiler.

```
request_route {
    if (is_method("INVITE") && !has_totag()) {
        dlg_manage();
        setflag(1); setflag(2); setflag(3);
    }
    t_relay();
}
```

**Differences from Kamailio**

- Only log and SQL backends. There is no RADIUS or Diameter backend.
- Record fields are fixed, and the time is in Unix seconds. The
  column-name and format parameters listed above are ignored.
- `cdr_extra` takes only `$dlg_var(name)` values.

## client (uac)

`uac` lets the proxy act as a client: it can change the caller's identity,
log in to an upstream provider and send requests of its own.

**From/To replacement.** `uac_replace_from()` / `uac_replace_to()` rewrite
the From / To URI (and display name) of an
[initial request](../../docs/glossary.md#initial-request). With
`restore_mode` `"auto"` the originals come back automatically:

- replies get the caller's values again;
- later [in-dialog requests](../../docs/glossary.md#in-dialog-request)
  from the caller are rewritten again;
- requests from the callee get the original values in To / From.

The originals are kept in memory per Call-ID and From tag for
`restore_ttl` seconds.

**Digest answers.** `uac_auth()` answers a 401 / 407
[challenge](../../docs/glossary.md#challenge) in a `failure_route`. It adds
an `Authorization` / `Proxy-Authorization` header for the challenge's
[realm](../../docs/glossary.md#realm). It answers
[digest](../../docs/glossary.md#digest-authentication) with MD5, SHA-256
or SHA-512-256, each also as `-sess` (RFC 7616, RFC 8760), with `qop=auth`
when offered. When the server sends several challenges, they are in its
order of preference: the first one with a supported algorithm (and, for
`uac_auth`, credentials for its realm) is answered. Remote registrations
choose the same way. The script then relays again. Credentials come from the
`auth_*_avp` variables when the username is set and the realm variable is
empty or matches. Otherwise they come from a `credential` with that realm.

**Remote registrations.** Each `uacreg` row is registered upstream:

- as `sip:<r_username>@<r_domain>`;
- at `sip:<r_domain>`, through `auth_proxy` when set;
- with Contact `sip:<l_uuid>@<reg_contact_addr>`;
- answering digest challenges with `auth_username` (or `r_username`) and
  `auth_password`.

A registration is refreshed at half the granted expiry. After a failure it
is retried every `reg_retry_interval` seconds. Rows with `flags` bit 1 are
disabled.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `restore_mode` | `auto` | `auto`: restore automatically. Any other value: only `uac_restore_from/to()` |
| `restore_ttl` | 43200 | Seconds the original From/To are kept |
| `credential` | none | `user:realm:password`. Repeat for more |
| `auth_username_avp` | none | Variable with the username for `uac_auth()` |
| `auth_password_avp` | none | Variable with the password |
| `auth_realm_avp` | none | Variable with the realm |
| `reg_db_url` | none | Database with the `uacreg` table. No remote registrations without it |
| `reg_contact_addr` | `127.0.0.1:5060` | `host:port` used in the registration Contact |
| `reg_retry_interval` | 60 | Seconds before retrying a failed registration |

Accepted for compatibility and ignored: `restore_dlg`,
`rr_from_store_param`, `rr_to_store_param`, `restore_passwd`,
`reg_timer_interval`, `reg_hash_size`, `reg_db_table`, `reg_keep_callid`,
`reg_random_delay`, `reg_active`, `reg_gc_interval`, `auth_hdr_avp`,
`uac_auth_mode`.

**Functions**

| Signature | Description |
|---|---|
| `uac_replace_from([display,] uri)` | Replaces the From URI and display name. `""` removes the display name, and leaving it out keeps it. 1, or -1 without Call-ID/From tag |
| `uac_replace_to([display,] uri)` | Same for To |
| `uac_restore_from()` / `uac_restore_to()` | With `restore_mode` other than `auto`: apply the stored restore to this message. Always 1 |
| `uac_auth([mode])` | In `failure_route` after a 401/407: add the digest answer. 1, or -1 (no challenge, no credentials). `mode` is ignored |
| `uac_req_send()` | Sends the request described by `$uac_req(...)` through tm. -1 without method or R-URI |
| `uac_reg_lookup(uuid, $dst)` | Sets `$dst` to `sip:<l_username>@<l_domain>` of the registration `uuid` (or of a URI whose user is the uuid). 1 or -1 |
| `uac_reg_status(uuid)` | 1 registered, -2 known but not registered, -1 unknown |

**Pseudo-variables**

| Name | Description |
|---|---|
| `$uac_req(key)` | Request for `uac_req_send()`. Keys: `method`, `ruri`, `furi`, `turi`, `ouri` ([outbound proxy](../../docs/glossary.md#outbound-proxy)), `hdrs`, `body`, `callid`. `$uac_req(all) = $null` clears it. Per message |

**RPC commands**

| Command | Description |
|---|---|
| `uac.reg_dump` | Remote registrations with `state` (Idle, Registering, Registered, Failed, AuthFailed, Disabled), `registered_until`, `cseq` |
| `uac.reg_reload` | Re-reads `uacreg` (state of known rows kept). Returns the count |
| `uac.reg_refresh <l_uuid>` | Registers that row now |

**Database tables**: `uacreg` (`l_uuid`, `l_username`, `l_domain`,
`r_username`, `r_domain`, `realm`, `auth_username`, `auth_password`,
`auth_proxy`, `expires`, `flags`). See `etc/schema/`.

**Example**

```toml
[modules.client]                  # uac
restore_mode = "auto"
credential = ["u1:gw:pw1"]
```

```rust
import client

route main(msg: Request) {
    if msg.has_to_tag {
        relay(msg)
    }
    client.replace_from_named("Anon", "sip:anonymous@anonymous.invalid")
    let res = await txn.relay(msg)
    match res {
        // A 401/407: answer the challenge and relay again.
        Final(r) if r.code == Unauthorized || r.code == ProxyAuthenticationRequired => {
            if client.auth() {
                relay(msg)
            }
        }
        _ => {}
    }
}
```

`client.auth()` (`uac_auth()`) runs only after `await`, where a `.cfg`
has its `failure_route`.

**Differences from Kamailio**

- The original From/To are kept in memory instead of in a
  [Record-Route](../../docs/glossary.md#record-route) parameter. So
  restoring works only on this proxy, and only for `restore_ttl` seconds.
- The `uacreg` table name is fixed.

## topology (topoh / topos)

Topology hiding keeps the addresses of your internal hosts out of the
messages that leave the proxy. It works as a filter on every message
ferrosip sends:

- Requests: the [Via](../../docs/glossary.md#via) headers of previous hops
  are removed. They are carried in a `;<vparam_name>=<token>` parameter of
  the proxy's own Via. Replies get them back before they are forwarded.
- Requests and replies: every [Contact](../../docs/glossary.md#contact) URI
  becomes `sip:<mask_ip>:<port>;<uparam_name>=<token>`. So in-dialog
  requests come to the proxy, which sends them on to the real contact.
- Requests: the Record-Route URIs of other proxies become masked URIs of
  the same form (with `;lr`). A receive filter gives back a request's
  [Route](../../docs/glossary.md#route) URIs and a reply's Record-Route
  URIs before routing. So in-dialog requests still pass through those
  proxies, while the other side never sees their addresses.

The two modules store the hidden data in different places:

- `topoh` puts the hidden data in the token. It XORs the data with a
  keystream from `mask_key`, then encodes it as base64url. This is
  obfuscation, not encryption.
- `topos` keeps the data in memory for `storage_ttl` seconds. It puts only
  a random 16-hex-digit id on the wire.

Only one of the two can be loaded. There are no script functions.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `mask_key` | `aL9.n8~Hm]Z` | topoh: key for the token keystream |
| `mask_ip` | the proxy's advertised address | Host put in masked Contacts |
| `vparam_name` | `th` | Via parameter carrying the hidden Vias |
| `uparam_name` | `line` | Contact URI parameter carrying the token |
| `storage_ttl` | 43200 | topos: seconds stored data is kept (min 60). `dialog_expire` is an alias |
| `mask_callid` | 0 | Only 0 is accepted |

Accepted for compatibility and ignored: `uparam_prefix`, `vparam_prefix`,
`callid_prefix`, `sanity_checks`, `uri_prefix_checks`, `event_callback`,
`event_mode`, `use_mode`, `db_url`, `storage`, `clean_interval`,
`branch_expire`.

**Example**

```toml
[modules.topos]                   # [modules.topology] for topoh
mask_ip = "203.0.113.10"
```

```rust
route main(msg: Request) {
    if msg.has_to_tag {
        relay(msg)
    }
    txn.relay(to: "udp:10.0.0.20:5060")
}
```

**Differences from Kamailio**

- No Call-ID masking. `mask_callid=1` is refused at startup.
- topos storage is in memory only. There is no database storage.

## Testing

- `tests/e2e_carrier.py`:
  - dialplan: regex substitution with `\1` and attrs, string and glob
    rules, no match, a broken rule skipped, `dialplan.dump`,
    `dialplan.translate`;
  - lcr: ordering, stopper rule, `next_gw` strip/prefix with
    `gw_id_avp`/`tag_avp`, failover with `defunct_gw`, `lcr_stats`,
    `from_gw`, `lcr.dump_gws`, `lcr.defunct_gw`;
  - acc: answered and missed calls with `db_extra`, `acc_db_request`, CDRs
    from dialog;
  - uac: `uac_replace_from` with restore in both directions, `uac_auth` on
    a 407, `uac_req_send`, a remote registration with digest auth,
    `uac_reg_lookup`;
  - topoh and topos: hidden Vias, masked Contacts, in-dialog routing back
    to the real Contact.
- Unit tests: dialplan rule matching and `\1` conversion, lcr ordering and
  both stopper modes, uac digest answers and challenge parsing, topoh/topos
  token round trip, glob and base64 helpers.
