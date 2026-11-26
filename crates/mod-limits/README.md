# mod-limits

This crate holds the modules that protect the proxy. They keep state that
all [workers](../../docs/glossary.md#worker) share, and they use it to stop
abuse. Use them for:

- named hash tables;
- flood detection;
- rate limiting;
- block and allow lists driven by a database.

The modules share helpers for locking, time and option parsing. That is why
they live in one crate. Each one is a separate
[module](../../docs/glossary.md#module). It loads in one of three ways: by
its own `loadmodule`, by a `[modules.*]` section in
[`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml), or by a call from
the routing. Modules backed by a database read `db_url` through `sip-db`
(`text:///dir` or `sqlite:///file`). They use
[Kamailio](../../docs/glossary.md#kamailio)'s table layouts. Dialog tracking
is not here. It lives in `mod-dialog`.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `shared_tables` | `htable` | Shared key/value tables with expiry, loaded from and stored to a database |
| `limits` | `pike` | Flood detection per source IP |
| `limits` | `ratelimit` | Static pipes fed by method queues |
| `pipe_limits` | `pipelimit` | Named pipes from the database or created from the script |
| `security_filter` | `secfilter` | Block and allow lists of user agents, users, domains, IPs, countries and destinations; SQL injection checks |
| `blocklist` | `userblocklist` | Block and allow lists of number prefixes, per user and global |

## shared_tables (htable)

This module provides named tables of strings and integers that every worker
can read and write. See [htable](../../docs/glossary.md#htable). The tables
live in a sharded map. Items can expire on their own.

Tables are declared in one of two places:

- in `ferrosip.toml`: `htable = ["name=>opt=v;opt=v"]` under
  `[modules.shared_tables]`, or `modparam("htable", "htable", …)`;
- in [`.fsr`](../../docs/glossary.md#fsr): `shared table name: Map<K, V> ttl 5m`.
  This is an htable table with `autoexpire`. It takes no other options, so
  there is no `dbtable`. See [shared table](../../docs/glossary.md#shared-table).

An expired item is invisible at once. It is swept every `timer_interval`.

Table options:

| Option | Default | Description |
|---|---|---|
| `autoexpire` | 0 | Seconds until an item expires. 0 = never. |
| `initval` | none | Integer returned for missing keys. Without it, `$null` is returned. |
| `updateexpire` | 1 | Refresh the expiry when an item is updated. |
| `dbtable` | none | Load the table from this table of `db_url` at startup. |
| `dbmode` | 0 | 1: write the table back every `timer_interval` when it changed, and on `htable.store`. |
| `size`, `array`, `dmqreplicate`, `coldelim`, `colnull` | none | Accepted and ignored. |

The database table has Kamailio's columns `key_name`, `key_type`,
`value_type` (1 = integer), `key_value` and `expires`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `htable` | none | Table definition. Repeatable. |
| `db_url` | none | Database for `dbtable`. Required when any table has one. |
| `timer_interval` | 20 | Seconds between expiry sweeps and write-backs. |
| `key_name_column`, `key_type_column`, `value_type_column`, `key_value_column`, `expires_column`, `array_size_suffix`, `fetch_rows`, `timer_procs`, `event_callback`, `enable_dmq`, `db_expires` | none | Accepted and ignored. |

**[Pseudo-variables](../../docs/glossary.md#pseudo-variable-pv)**

| Variable | Description |
|---|---|
| `$sht(t=>key)` | Read or write an item. The key may contain variables. Assigning `$null` deletes it. |
| `$shtex(t=>key)` | Seconds until expiry. 0 = never. Assigning sets the expiry. |
| `$shtinc(t=>key)` / `$shtdec(t=>key)` | Atomic +1 / -1. Returns the new value. |
| `$shtcn(t=>pattern)` / `$shtcv(t=>pattern)` | Number of names / values that match. Patterns: `~~regex`, `%~prefix`, `~%suffix`, `==string`, else a regex. |
| `$shtrecord(key)` / `$shtrecord(value)` | The expired item, in `event_route[htable:expired:<table>]`. |

**Functions**

| Signature | Description |
|---|---|
| `sht_rm(table, key)` | Delete a key. 1 if it existed. |
| `sht_rm_name_re("t=>regex")` / `sht_rm_value_re("t=>regex")` | Delete items whose name / value matches. |
| `sht_rm_name(table, op, val)` / `sht_rm_value(table, op, val)` | Delete by name / value. `op` is `re`, `sw`, `ew`, `eq` or `in` (contains). |
| `sht_has_name(table, op, val)` / `sht_has_str_value(table, op, val)` | 1 if a name / value matches. |
| `sht_reset(table)` | Empty the table. |
| `sht_setxs(table, key, value, expire)` / `sht_setxi(…)` | Set a string / integer with its own expiry in seconds. 0 = never. |
| `sht_is_null("t=>key")` | 1 if the item is unset. The key is taken literally. |
| `sht_lock(name)` / `sht_unlock(name)` | Take / release a named lock. Blocks while it is held. |

**[Event routes](../../docs/glossary.md#event-route)**:
`event_route[htable:mod-init]` runs once at startup.
`event_route[htable:expired:<table>]` runs for each expired item.

**[RPC](../../docs/glossary.md#rpc) commands**

| Command | Description |
|---|---|
| `htable.get <table> <key>` | Value of a key. |
| `htable.sets <table> <key> <value>` / `htable.seti …` | Set a string / integer. |
| `htable.delete <table> <key>` | Delete a key. |
| `htable.dump <table>` | Items with their remaining expiry. |
| `htable.flush <table>` | Empty the table. |
| `htable.reload <table>` | Reload from the database. |
| `htable.store <table>` | Write to the database. |
| `htable.listTables` | Tables and their options. |

**Example**

The table backed by a database goes in `ferrosip.toml`:

```toml
[modules.shared_tables]           # htable
htable = ["acc=>dbtable=htable;dbmode=1;"]
db_url = "text:///etc/ferrosip/db"
```

The ban table is declared in `.fsr`. It is an htable table,
`ipban=>autoexpire=300`:

```rust
shared table ipban: Map<Str, Bool> ttl 5m

route main(msg: Request) {
    if ipban.contains(msg.src.ip) { exit }
    …
}
```

The next part is a Kamailio-style [`.cfg`](../../docs/glossary.md#cfg),
because `.fsr` has no `htable:expired` event. `.fsr` also only reaches the
tables it declares itself. So it cannot reach `acc`, which needs `dbtable`:

```
event_route[htable:expired:ipban] {
    xinfo("unbanned $shtrecord(key)\n");
}
request_route {
    $var(n) = $shtinc(acc=>$fU);
}
```

**Differences from Kamailio**: there is no [DMQ](../../docs/glossary.md#dmq) replication and there are no
array keys. The column names are fixed. `sht_lock` locks any name, not a
table slot.

## limits (pike)

This module detects floods from a single source IP. It counts requests per
source IP in windows of `sampling_time_unit` seconds.

- An address is blocked once a window exceeds `reqs_density_per_unit`.
- It is unblocked when the previous window was back at or below that limit.
- Idle, unblocked addresses are forgotten after `remove_latency`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `sampling_time_unit` | 2 | Window length in seconds. |
| `reqs_density_per_unit` | 30 | Requests allowed per window. |
| `remove_latency` | 120 | Seconds before an idle, unblocked address is dropped. |
| `pike_log_level` | none | Accepted and ignored. Blocking is logged at WARN. |

**Functions**

| Signature | Description |
|---|---|
| `pike_check_req()` | Count the request's source. 1 allowed, -1 blocked. |
| `pike_check_ip(ip)` | Same for `ip`. Also -1 for an invalid address. |

**Event routes**: `event_route[pike:blocked]` runs once when
`pike_check_req()` blocks an address. `$si` is set to that address.

**RPC commands**: `pike.top [ALL|HOT]` lists the blocked addresses with
their counters. With `ALL`, it lists every tracked address.

**Example**

```toml
[modules.limits]                  # pike
sampling_time_unit = "2s"
reqs_density_per_unit = 30
```

```rust
import limits

shared table ipban: Map<Str, Bool> ttl 5m

on limits.blocked(e: Source) {    // event_route[pike:blocked]
    ipban.set(e.ip, true)
}

route main(msg: Request) {
    guard limits.check_flood() else exit
    …
}
```

## limits (ratelimit)

This module limits the request rate with static pipes. A pipe is a counter
with an algorithm and a limit of requests per `timer_interval`. Queues map
[methods](../../docs/glossary.md#method) to pipes.

Algorithms:

- `TAILDROP` drops everything above the limit.
- `RED` also drops at random, starting from 3/4 of the limit.
- `NETWORK` and `FEEDBACK` are accepted and behave as `TAILDROP`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `pipe` | none | `id:ALGORITHM:limit`. Repeatable. |
| `queue` | none | `id:METHOD` (or `id:*`). Repeatable. The pipe must exist. |
| `timer_interval` | 10 | Seconds per counting interval. |
| `reply_code`, `reply_reason`, `hash_size`, `load_source`, `limit_hash_size` | none | Accepted and ignored. |

**Functions**

| Signature | Description |
|---|---|
| `rl_check([pipe])` | Count against `pipe`, or against the first queue that matches the method. 1 accepted, also when no queue matches. -1 over the limit. -2 unknown pipe. |

**RPC commands**

| Command | Description |
|---|---|
| `rl.stats` / `rl.get_pipes` | Pipes with algorithm, limit, counter, last counter and dropped. |
| `rl.set_pipe <id> <ALGORITHM> <limit>` | Change an existing pipe. |

**Example**

```toml
[modules.limits]                  # ratelimit
pipe = ["0:TAILDROP:100"]
queue = ["0:INVITE"]
```

```rust
import limits

route main(msg: Request) {
    if !limits.check_rate() { reply(ServiceUnavailable, "Rate limited") }
    …
}
```

## pipe_limits (pipelimit)

This module provides named pipes. They are loaded from a table, or created
from the script on first use. Counting and algorithms are the same as in
`ratelimit`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none | Database with the pipe table. Optional. |
| `plp_table_name` / `table_name` | `pl_pipes` | Pipe table (`pipeid`, `algorithm`, `plimit`). |
| `timer_interval` | 10 | Seconds per counting interval. |
| `reply_code` | 503 | Code sent by `pl_drop`. |
| `reply_reason` | `Server Unavailable` | Reason sent by `pl_drop`. |
| `hash_size`, `load_source`, `clean_unused`, `plp_pipeid_column`, `plp_limit_column`, `plp_algorithm_column` | none | Accepted and ignored. |

**Functions**

| Signature | Description |
|---|---|
| `pl_check(name)` | Count against an existing pipe. 1 accepted, -1 over the limit, -2 unknown pipe. |
| `pl_check(name, ALGORITHM, limit)` | Same, but creates the pipe if needed. |
| `pl_drop([retry_after[, low, high]])` | Reply with `reply_code`/`reply_reason`. With one argument, add `Retry-After: retry_after`. With three, add a random value in `[low, high]`. Integer constants only. |

**RPC commands**

| Command | Description |
|---|---|
| `pl.stats` / `pl.list` | Pipes and counters. |
| `pl.set_pipe <name> <ALGORITHM> <limit>` | Change or create a pipe. |
| `pl.reload` | Reload pipes from the database. |

**Example**

```rust
import pipe_limits

route main(msg: Request) {
    if !pipe_limits.check_or_create(msg.src.ip, "TAILDROP", 20) {
        pipe_limits.reject(5s)          // pl_drop: 503 with Retry-After: 5
    }
    …
}
```

## security_filter (secfilter)

This module blocks or allows requests by matching them against lists. The
lists come from the `secfilter` table. They are loaded at startup and
compared case-insensitively. The table has three columns:

- `action`: 0 blocklist, 1 allowlist, 2 destination blocklist;
- `type`: 0 [user agent](../../docs/glossary.md#user-agent), 1 country,
  2 domain, 3 IP, 4 user;
- `data`: the value to match.

The checks return 2 for allowlisted, 1 for not listed and -2 for
blocklisted. The allowlist wins.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database. |
| `table_name` | `secfilter` | List table. |
| `dst_exact_match` | 0 | `secf_check_dst` matches whole numbers instead of prefixes. |
| `action_col`, `type_col`, `data_col` | none | Accepted and ignored. |

**Functions**

| Signature | Description |
|---|---|
| `secf_check_ua()` | User-Agent contains a listed string. 1 without a User-Agent. |
| `secf_check_from_hdr()` / `secf_check_to_hdr()` / `secf_check_contact_hdr()` | Checks the header's user (or display name) and domain. |
| `secf_check_ip()` | Source IP. Matches the whole address, or a prefix entry that ends in `.` or `:`. |
| `secf_check_country(code)` | A country code from the script. |
| `secf_check_dst(number)` | -2 if the number is in the destination blocklist, else 1. |
| `secf_check_sqli_all()` | -1 if the [R-URI](../../docs/glossary.md#r-uri) user, User-Agent, From, To or Contact contains `'`, `--`, `#`, `/*`, `%27`, `%24` or `%60`. Else 1. |
| `secf_check_sqli_hdr(value)` | Same test on `value`. |

**RPC commands**

| Command | Description |
|---|---|
| `secfilter.reload` | Reload the table. |
| `secfilter.print` | Show the lists. |
| `secfilter.add_bl <ua\|country\|domain\|ip\|user> <value>` / `secfilter.add_wl …` | Add an entry in memory. |
| `secfilter.add_dst <number>` | Add a blocked destination in memory. |
| `secfilter.stats` | Number of blocked checks. |

**Example**

```toml
[modules.security_filter]
db_url = "text:///etc/ferrosip/db"
```

```rust
import security_filter

route main(msg: Request) {
    // false: blocklisted / SQL injection found
    if !security_filter.check_user_agent() || !security_filter.check_sql_injection() { exit }
    …
}
```

**Differences from Kamailio**: entries added by RPC are not written to the
database. They are lost on `secfilter.reload`.

## blocklist (userblocklist)

This module blocks or allows calls by the prefix of the dialled number.
There are two kinds of lists:

- per user, in `userblocklist` (`username`, `domain`, `prefix`,
  `allowlist`). It is queried on each check.
- global, in `globalblocklist` (`prefix`, `allowlist`). It is cached.

The longest matching prefix decides. A leading `+` is ignored.

If the database cannot be reached or a query fails, the error is logged and
the list counts as empty:

- The `*_blocklist` checks fail open: 1, not blocked.
- The `*_allowlist` checks fail closed: -1, not allowed.
- The cached global list keeps its last loaded contents.

Failed queries are counted in two
[counters](../../docs/glossary.md#counter):
`userblocklist:db_unreachable` when the database is down, and
`userblocklist:db_errors` when the query was refused.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database. |
| `use_domain` | 0 | Match the user's domain too. |
| `db_table` / `userblocklist_table` | `userblocklist` | Per-user table. |
| `globalblocklist_table` | `globalblocklist` | Global table. |
| `match_mode` | none | Accepted and ignored. |

**Functions**

| Signature | Description |
|---|---|
| `check_user_blocklist(user, domain[, number[, table]])` | -1 if the longest prefix of `number` is a block entry, else 1. `number` defaults to the R-URI user. |
| `check_user_allowlist(user, domain[, number[, table]])` | 1 only if the longest prefix is an allow entry. |
| `check_blocklist([table])` | Global list on the R-URI user: -1 blocked, else 1. |
| `check_allowlist([table])` | Global list: 1 only if allowlisted. |

**RPC commands**

| Command | Description |
|---|---|
| `userblocklist.reload_blocklist` | Reload the global list. |
| `userblocklist.dump_blocklist` | Show the global list. |
| `userblocklist.check_blocklist <number>` | `allowlisted`, `blocklisted` or `not found`. |

**Example**

```toml
[modules.blocklist]
db_url = "text:///etc/ferrosip/db"
```

```rust
import blocklist

route main(msg: Request) {
    if !blocklist.check_user(msg.from.user, msg.from.host) { reply(Forbidden, "Blocked") }
    if !blocklist.check_global() { reply(Forbidden, "Blocked number") }
    …
}
```

## Testing

- `tests/e2e_state.py` tests all six modules with `db_text` tables. It
  covers:
  - variable keys, `$shtinc`, `$shtcn` and expiry;
  - `htable:mod-init` / `htable:expired`;
  - database preload and write-back across a restart;
  - pike blocking and `pike:blocked`;
  - ratelimit and pipelimit with `Retry-After`;
  - secfilter lists and SQL injection;
  - user and global blocklists;
  - the RPCs.

  The same suite covers `mod-dialog`, [usrloc](../../docs/glossary.md#usrloc)
  `db_mode` and `auth_db`.
- `tests/e2e_async.py` also loads `htable`.
- Unit tests (`cargo test -p mod-limits`): htable semantics and match
  patterns, TAILDROP and pike windows, longest-prefix matching and the SQL
  injection test.
