# mod-routing

This crate holds the modules that decide where a request goes and who may
send it. Use them for:

- [Record-Route](../../docs/glossary.md#record-route) and
  [loose routing](../../docs/glossary.md#loose-routing);
- [Path](../../docs/glossary.md#path);
- [NAT](../../docs/glossary.md#nat) traversal on the signalling side;
- load balancing with failover;
- access control and identity lookups driven by tables.

The modules share helpers for URIs, subnets and table loading. That is why
they live in one crate. Each one is a separate
[module](../../docs/glossary.md#module). It is active only after its own
`loadmodule`. With [`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml),
it is active when the routing uses it or when it has a `[modules.x]`
section. Modules backed by a database read `db_url` through `sip-db`
(`text:///dir` or `sqlite:///file`). They use
[Kamailio](../../docs/glossary.md#kamailio)'s table layouts.

The examples below are `ferrosip.toml` parameters plus
[`.fsr`](../../docs/glossary.md#fsr) routing
([docs/fsr.md](../../docs/fsr.md)). In `ferrosip.toml` and `.fsr` the
modules use their ferrosip names, from the first column of the table below:

- `rr` is `route_set`;
- `nathelper` is `nat`;
- `dispatcher` is `balancer`;
- `permissions` is `acl`;
- `domain`, `alias_db` and `group` are `domains`, `aliases` and `groups`.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `route_set` | `rr` | Record-Route and loose routing (RFC 3261 §16.6, §16.12) |
| `path` | `path` | Path headers for REGISTERs through edge proxies (RFC 3327) |
| `nat` | `nathelper` | NAT detection, Contact and SDP fixing, `;alias`, keep-alive pings |
| `balancer` | `dispatcher` | Load balancing and failover over destination sets, with probing |
| `acl` | `permissions` | Address and trusted tables, allow and deny rule files |
| `domains` | `domain` | Local domain table |
| `aliases` | `alias_db` | R-URI alias lookup in a table |
| `groups` | `group` | Group membership checks |

## route_set (rr)

`record_route()` only records that the request needs a Record-Route.
[tm](../../docs/glossary.md#tm) writes the header for each
[branch](../../docs/glossary.md#branch) once the outgoing transport and
interface are known.

- A call that crosses transports or interfaces gets two entries with
  `;r2=on`. The top one faces the callee.
- `loose_route()` removes our own entries, including both entries of an r2
  pair. It then sends to the next [Route](../../docs/glossary.md#route), or
  to the [R-URI](../../docs/glossary.md#r-uri) when none is left.
- A top Route that isn't ours is followed as is.
- [RFC 5626](../../docs/glossary.md#sip-outbound) flow tokens (`;ob`) in our
  own entries are honoured.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `enable_double_rr` | 1 | Two entries when the call crosses transports or interfaces. |
| `append_fromtag` | 1 | Add `;ftag=`. `is_direction` needs it. |
| `enable_full_lr` | 0 | Write `;lr=on` instead of `;lr`. |

**Functions**

| Signature | Description |
|---|---|
| `record_route([params])` | Add Record-Route, with extra `;params`. -1 on a reply. |
| `record_route_preset(addr[, addr2])` | Record-Route with a fixed address. With two addresses, both get `;r2=on`. |
| `record_route_advertised_address(addr)` | Record-Route with a fixed address. |
| `add_rr_param(params)` | Add parameters to our Record-Route. Works before or after `record_route()`. |
| `remove_record_route()` | Drop the Record-Route requested so far. |
| `loose_route()` | Process Route headers as above. 1 if there was a Route, -1 otherwise. |
| `loose_route_preloaded()` | `loose_route()` for [initial requests](../../docs/glossary.md#initial-request) only. -1 if the To header has a [tag](../../docs/glossary.md#tag). |
| `check_route_param(regex)` | Match the parameters of the Route consumed by `loose_route()`. |
| `is_direction("downstream"\|"upstream")` | Compare the From tag with the consumed Route's `ftag`. |

**Pseudo-variables**: `$route_uri`, the Route URI consumed by `loose_route()`.

**Example** (`route_set.follow()` is `loose_route()`, `route_set.record()`
is `record_route()`)

```rust
import route_set

route main(msg: Request) {
    if msg.has_to_tag {
        if route_set.follow() {
            relay(msg)
        }
        reply(NotFound, "Not here")
    }
    route_set.record()
    relay(msg)
}
```

## path

**Parameters**

| Name | Default | Description |
|---|---|---|
| `use_received` | 0 | Accepted. `loose_route()` always honours `;received` on our own Route. |
| `enable_r2`, `sockname_mode` | none | Accepted and ignored. |

**Functions**

| Signature | Description |
|---|---|
| `add_path([user])` | Add a Path header for us, with an optional user part. -1 on a reply. |
| `add_path_received([user])` | Same, with `;received=<source URI>` (escaped). On the way back, `loose_route()` sends to that address. |

With an RFC 5626 Outbound request and no `user`, the Path carries a flow token
and `;ob`.

**Example**

A fragment of a route (`import path`):

```rust
if msg.method == REGISTER {
    path.add_received()  // add_path_received()
    txn.relay(to: "udp:10.0.0.5:5060")
}
```

## nat (nathelper)

This module handles clients behind NAT. It:

- detects them;
- rewrites their [Contact](../../docs/glossary.md#contact) or
  [SDP](../../docs/glossary.md#sdp) to the address the packet came from;
- adds Kamailio's `;alias=ip~port~proto`, so requests reuse the client's NAT
  binding;
- pings registered contacts to keep the bindings open (see
  [keepalive](../../docs/glossary.md#keepalive)).

"Private" means RFC 1918, 100.64.0.0/10 and fc00::/7.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `natping_interval` | 0 | Seconds between keep-alive rounds. 0 = off. Needs [`usrloc`](../../docs/glossary.md#usrloc) loaded first. |
| `ping_nated_only` | 0 | Only ping contacts with `nat_bflag`. |
| `nat_bflag` | -1 (unset) | [Branch flag](../../docs/glossary.md#branch-flags) that marks contacts behind NAT. |
| `sipping_bflag` | -1 (unset) | Contacts with this flag get a SIP request. Others get CRLFCRLF (TCP/TLS/WS) or 4 zero bytes (UDP). |
| `sipping_from` | `sip:pinger@ferrosip.invalid` | From URI of SIP pings. |
| `sipping_method` | `OPTIONS` | Method of SIP pings. |
| `received_avp`, `natping_processes`, `natping_socket`, `force_socket`, `keepalive_timeout`, `udpping_from_path` | none | Accepted and ignored. |

**Functions**

| Signature | Description |
|---|---|
| `nat_uac_test(flags)` | 1 if any test in `flags` matches: 1 Contact private, 2 [Via](../../docs/glossary.md#via) address ≠ source, 4 Via private, 8 SDP `c=` private, 16 Via port ≠ source port, 32 source private, 64 [WebSocket](../../docs/glossary.md#websocket) client, 128 Contact port ≠ source port, 256 SDP `c=` ≠ source. |
| `fix_nated_contact()` | Rewrite the first Contact's host:port to the source address. |
| `fix_nated_register()` | 1 for a REGISTER, -1 otherwise. It has nothing to do, because the registrar always stores the source address. |
| `set_contact_alias([ip, port, proto])` / `add_contact_alias(…)` | Add `;alias=` to the first Contact URI. The source address is the default. 1 if already present. |
| `handle_ruri_alias()` | Move the R-URI's `;alias` into [`$du`](../../docs/glossary.md#destination-uri) and remove it. 1 done, 2 no alias, -1 bad alias. |
| `add_rcv_param([1])` | Add `;received="<source URI>"` to the Contact. With `1`, add it as a URI parameter. |
| `fix_nated_sdp(flags[, ip])` | Rewrite the SDP with `ip`. The source address is the default. Flags: 1 add `a=direction:active`, 2 rewrite `c=`, 8 rewrite `o=`. -1 without a body. |
| `is_rfc1918(ip)` | `ip` is private, as defined above. |

**Statistics**: `nathelper:pings_sent`.

The module absorbs the replies to SIP pings.

**Example**

```toml
[modules.nat]                          # nathelper
natping_interval = "30s"
ping_nated_only = true
nat_bflag = 6
sipping_bflag = 7
```

The routing stays in a Kamailio-style [`.cfg`](../../docs/glossary.md#cfg)
(`[routing] entry = "main.cfg"`), because `.fsr` has no branch flags
(`setbflag`).

```
request_route {
    if (is_method("REGISTER")) {
        if (nat_uac_test(19)) { fix_nated_contact(); setbflag(6); setbflag(7); }
        save("location");
        exit;
    }
}
```

**Differences from Kamailio**: `received_avp` is not needed, and it is
ignored. Only the first Contact is fixed. `fix_nated_sdp` supports flags 1,
2 and 8.

## balancer (dispatcher)

This module spreads requests over groups of destinations and fails over
when one stops answering. It is Kamailio's
[dispatcher](../../docs/glossary.md#dispatcher).

The [destination sets](../../docs/glossary.md#destination-set) come from one
of two sources. One of them is required:

- `list_file`, with lines `setid uri [flags [priority [attrs]]]`;
- the `dispatcher` table of `db_url`, with columns `setid`, `destination`,
  `flags`, `priority` and `attrs`.

A selection keeps the remaining destinations, in failover order, in
[`$xavp(_dsdst_)`](../../docs/glossary.md#xavp). Its fields are `uri`, `grp`,
`attrs` and `priority`. tm carries it into
[`failure_route`](../../docs/glossary.md#failure-route). In `.fsr`, it is
carried past `await txn.relay(…)`. Destinations within a set are ordered by
priority, highest first.

Algorithms:

| Number | Algorithm |
|---|---|
| 0 | hash Call-ID |
| 1 | hash From (user@host) |
| 2 | hash To |
| 3 | hash R-URI |
| 4 | round-robin |
| 5 | hash auth username |
| 6 | random |
| 7 | hash `hash_pvar` |
| 8 | priority order |
| 9 | `weight=` attribute |
| 10 | call load: fewest calls relative to `maxload=`. Tracked by Call-ID. Released by `ds_load_unset()`, `ds_load_update()` or the dialog ending. Moved by `ds_next_dst` |
| 11 | `rweight=` among active destinations |
| 12 | parallel [forking](../../docs/glossary.md#forking) to the whole set (`ds_select_dst` only) |
| 13 | lowest estimated probe latency |

Hash algorithms fall back to round-robin when the input is missing.
Inactive and disabled destinations are skipped.

Probing sends `ds_ping_method` through tm's
[UAC](../../docs/glossary.md#uac) API every `ds_ping_interval`. A
destination becomes inactive after `ds_probing_threshold` failures. It
becomes active again after `ds_inactive_threshold` successes.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `list_file` | none | Destination list file. |
| `db_url` | none | Database with the destination table. |
| `table_name` | `dispatcher` | Destination table. |
| `ds_ping_interval` | 0 | Probe interval in seconds. 0 = off. Needs `tm` loaded first. |
| `ds_ping_method` | `OPTIONS` | Probe method. |
| `ds_ping_from` | `sip:dispatcher@localhost` | Probe From URI. |
| `ds_probing_mode` | `inactive` (0) | 0 probes only destinations in probing state, 1 probes all. |
| `ds_probing_threshold` | 1 | Failed probes before inactive. |
| `ds_inactive_threshold` | 1 | Successful probes before active again. |
| `ds_ping_reply_codes` | none | Extra success codes: `code=404;class=3`. 2xx always counts. |
| `hash_pvar` | none | Format string hashed by algorithm 7. |
| `setid_pvname` | none | Variable that `ds_is_from_list` sets to the matching set. |
| `attrs_pvname` | none | Variable that `ds_is_from_list` sets to the matching attrs. |
| `ds_ping_latency_stats` | 0 | Show probe latency (AVG/STD/EST/MAX/TIMEOUT) in `dispatcher.list`. |
| `ds_latency_estimator_alpha` | 900 | Weight of the old estimate, in thousandths (algorithm 13). |
| `flags`, `use_default`, `force_dst`, `xavp_dst`, `xavp_ctx`, `ds_hash_size`, `ds_timer_mode` | none | Accepted and ignored. |

**Functions**

| Signature | Description |
|---|---|
| `ds_select_dst(set, alg[, limit])` | Select from `set` and set `$du`. `limit` caps the failover list. -1 if the set is unknown or has no active destination. |
| `ds_select_domain(set, alg[, limit])` | Same, but rewrites the R-URI host:port. |
| `ds_select(set, alg[, limit])` | Only build `$xavp(_dsdst_)`. |
| `ds_next_dst()` / `ds_next_domain()` | Drop the current destination and apply the next one. -1 when the list is exhausted. |
| `ds_set_dst()` / `ds_set_domain()` | Apply the current destination of the list. |
| `ds_mark_dst([state])` | Set the state of the current destination, or of `$du`. Letters: `i` inactive, `d` disabled, `t` trying, `p` probing, `a` active. Default `ip` with probing on, else `i`. |
| `ds_is_from_list([group[, mode[, uri]]])` | The source address, or `uri`, belongs to a set. `-1` = any set. `mode` bit 1 ignores the port, bit 2 the protocol. |
| `ds_list_exists(set)` | The set exists. |
| `ds_is_active(set[, uri])` | The set has an active destination, or `uri` is active. |
| `ds_load_unset()` | Release this call's load (algorithm 10). |
| `ds_load_update()` | Release the load on [BYE](../../docs/glossary.md#bye) or [CANCEL](../../docs/glossary.md#cancel). Always 1. |

**Event routes**: `event_route[dispatcher:dst-down]` and
`event_route[dispatcher:dst-up]`, with `$ru` set to the destination URI. See
[event route](../../docs/glossary.md#event-route).

**RPC commands**

| Command | Description |
|---|---|
| `dispatcher.reload` | Reload the sets. Known destinations keep their states. Returns the count. |
| `dispatcher.list` | Sets with URI, FLAGS (`A`/`I`/`T`/`D` + `P`/`X`), PRIORITY, ATTRS, LOAD and optionally LATENCY. |
| `dispatcher.set_state <state> <group> <uri\|all>` | Set states by hand. |
| `dispatcher.ping_active 0\|1` | Set the probing mode. |

See [RPC](../../docs/glossary.md#rpc).

**Example**

```toml
[modules.balancer]                     # dispatcher
list_file = "/etc/ferrosip/dispatcher.list"
ds_ping_interval = "10s"
```

`await txn.relay(…)` replaces `t_on_failure` and the `failure_route`. The
example works like this:

- On a 5xx, a 408 or no answer, the gateway is marked (`balancer.mark`, that
  is `ds_mark_dst`).
- The next one is tried (`balancer.next`, `ds_next_dst`).
- When none is left, the best reply goes upstream.

`on balancer.down` is `event_route[dispatcher:dst-down]`.

```rust
import balancer

route main(msg: Request) {
    guard balancer.select(1, 4) else reply(ServiceUnavailable, "No gateway")
    while true {
        let res = await txn.relay(msg)
        match res {
            Final(r) if r.code < 500 && r.code != RequestTimeout => forward(r)
            _ => {}
        }
        balancer.mark("ip")
        if !balancer.next() {
            break
        }
    }
}

on balancer.down(e: Destination) {
    log.warn("gateway {e.uri} is down\n")
}
```

## acl (permissions)

This module decides which peers and calls are allowed. It uses two tables
and two rule files.

The tables are cached from `db_url` at startup and reloaded by RPC:

- `address`: columns `grp`, `ip_addr`, `mask`, `port` and `tag`. Port 0
  means any port.
- `trusted`: columns `src_ip`, `proto`, `from_pattern`, `ruri_pattern`,
  `tag` and `priority`. The highest priority is tried first.

The allow and deny files use Kamailio syntax: `"from-regex" : "ruri-regex"`,
comma lists, `ALL`, `EXCEPT` and `#` comments. They are evaluated in this
order:

1. A match in the allow file allows.
2. Then a match in the deny file denies.
3. Otherwise the request is allowed.

A missing file means no rules.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none | Database for `address` / `trusted`. Without it, the tables are not loaded. |
| `address_table` | `address` | Address table. |
| `trusted_table` | `trusted` | Trusted table. |
| `peer_tag_avp` | none | Variable set to the matching rule's `tag`. |
| `default_allow_file` | `permissions.allow` | Allow file for `allow_routing()`. |
| `default_deny_file` | `permissions.deny` | Deny file for `allow_routing()`. |
| `db_mode`, `load_backends`, `max_subnets`, `reload_delta`, `check_all_branches`, `allow_suffix`, `deny_suffix` | none | Accepted and ignored. |

**Functions**

| Signature | Description |
|---|---|
| `allow_source_address([grp])` | The source IP and port are in group `grp`. The default group is 1. |
| `allow_address(grp, ip, port)` | `ip`/`port` is in group `grp`. |
| `allow_source_address_group()` | Returns the group of the source address, -1 if none. |
| `allow_address_group(ip, port)` | Returns the group of `ip`/`port`, -1 if none. |
| `allow_trusted()` / `allow_trusted(ip, proto[, ruri])` | A trusted rule matches the source (or `ip`/`proto`), the From URI and the R-URI (or `ruri`). |
| `allow_routing()` / `allow_routing(basename)` / `allow_routing(allow_file, deny_file)` | Check From URI → R-URI. `basename` means `basename.allow` / `basename.deny`. |
| `allow_register(basename)` / `allow_register(allow_file, deny_file)` | Check the To URI against every Contact. |

**RPC commands**

| Command | Description |
|---|---|
| `permissions.reload` | Re-read the allow and deny files. |
| `permissions.addressReload` / `permissions.trustedReload` | Reload a table. Returns the row count. |
| `permissions.addressDump` / `permissions.trustedDump` | Show a table. |

**Example**

`acl.source_allowed()` is `allow_source_address()`. `acl.routing_allowed()`
is `allow_routing()`.

```toml
[modules.acl]                          # permissions
db_url = "text:///etc/ferrosip/db"
```

```rust
import acl

route main(msg: Request) {
    if acl.source_allowed() {
        log.info("peer {msg.src.ip}\n")
    }
    guard acl.routing_allowed("/etc/ferrosip/permissions") else reply(Forbidden, "Forbidden")
    relay(msg)
}
```

`.fsr` can't read [AVPs](../../docs/glossary.md#avp). Logging the matching
rule's tag (`peer_tag_avp`) therefore needs a Kamailio-style `.cfg`:

```
modparam("permissions", "peer_tag_avp", "$avp(tag)")
request_route {
    if (allow_source_address()) { xinfo("peer $avp(tag)\n"); }
}
```

## domains (domain)

This module lists the domains the proxy treats as local. It reads them from
the `domain` table, caches them and reloads them by RPC.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database with the domain table. |
| `domain_table` | `domain` | Table (column `domain`). |
| `register_myself` | 0 | Also make the domains match `uri == myself` (see [myself](../../docs/glossary.md#myself)). |
| `domain_attrs_table`, `did_col`, `domain_col`, `name_col`, `type_col`, `value_col` | none | Accepted and ignored. |

**Functions**

| Signature | Description |
|---|---|
| `is_domain_local(domain\|uri)` | The domain, or the URI's host, is local. Case-insensitive. |
| `is_from_local()` | The From URI host is local. |
| `is_uri_host_local()` | The R-URI host is local. |

**RPC commands**: `domain.reload`, `domain.dump`.

**Example**

```toml
[modules.domains]
db_url = "text:///etc/ferrosip/db"
```

A fragment of a route (`import domains`). `domains.is_ruri_local()` is
`is_uri_host_local()`:

```rust
guard domains.is_ruri_local() else reply(Forbidden, "Not our domain")
```

**Differences from Kamailio**: there are no domain attributes and no
multi-domain `did`. The column name is fixed.

## aliases (alias_db)

This module looks up the R-URI in an alias table on every call. It rewrites
the R-URI to `sip:user@domain`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database. |
| `use_domain` | 0 | Match the domain too. |
| `alias_user_column` | `alias_username` | |
| `alias_domain_column` | `alias_domain` | |
| `user_column` | `username` | |
| `domain_column` | `domain` | |
| `domain_prefix`, `append_branches` | none | Accepted and ignored. |

**Functions**

| Signature | Description |
|---|---|
| `alias_db_lookup(table[, flags])` | Rewrite the R-URI. Flags: `d` ignore the domain, `r` reverse (user → alias), `m` add every further match as a branch. -1 if not found. |

**Example**

```toml
[modules.aliases]
db_url = "text:///etc/ferrosip/db"
```

A fragment of a route (`import aliases`). `aliases.lookup()` is
`alias_db_lookup()`:

```rust
if aliases.lookup("dbaliases") {
    relay(msg)
}
```

## groups (group)

This module checks group membership in the `grp` table on every call.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database. |
| `table` | `grp` | Membership table. |
| `use_domain` | 0 | Match the domain too. |
| `user_column` | `username` | |
| `domain_column` | `domain` | |
| `group_column` | `grp` | |
| `re_table`, `re_exp_column`, `re_gid_column`, `multiple_gid` | none | Accepted and ignored. |

**Functions**

| Signature | Description |
|---|---|
| `is_user_in(who, group)` | `who` is `"Request-URI"`, `"To"`, `"From"`, `"Credentials"` or a URI. A URI may be a variable. `"Credentials"` takes the username and [realm](../../docs/glossary.md#realm) from the Authorization or Proxy-Authorization header. |

**Example**

```toml
[modules.groups]
db_url = "text:///etc/ferrosip/db"
```

A fragment of a route (`import groups`). `groups.is_member()` is
`is_user_in()`:

```rust
guard groups.is_member("From", "admins") else reply(Forbidden, "Forbidden")
```

**Differences from Kamailio**: there are no regular-expression groups
(`re_table`, `get_user_group`).

## Testing

- `tests/e2e_routing.py` tests all eight modules with `db_text` tables and a
  dispatcher list file. It covers:
  - Record-Route: single, double (UDP → TCP) and preset;
  - loose routing;
  - Path with `;received`;
  - nathelper tests, fixes, aliases and pinging;
  - permissions tables and rule files;
  - domain, alias_db and group;
  - dispatcher selection, failover, probing, events, algorithms 10, 12 and
    13, and the RPCs.
- `tests/e2e_sqldb.py`: dispatcher sets from an SQL database and
  `dispatcher.reload`.
- Unit tests (`cargo test -p mod-routing`): subnets and private ranges,
  dispatcher list parsing, allow/deny rule parsing and evaluation.
