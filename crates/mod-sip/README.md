# mod-sip

This crate holds the small message-utility modules that almost every
[Kamailio](../../docs/glossary.md#kamailio) config loads. Use them to send
simple replies, edit headers and bodies, test messages and IP addresses, run
sanity checks, log, set flags, take locks, count events and manage the
destination blocklist.

The modules share helpers: header matching, sed-style substitution and
variable arguments. That is why they live in one crate. Each one is still a
separate [module](../../docs/glossary.md#module):

- A [`.cfg`](../../docs/glossary.md#cfg) loads it with `loadmodule`.
- With [`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml), it loads when
  the routing uses one of its functions.

Function names and their behavior follow Kamailio. An argument may contain
variables wherever the [fixup](../../docs/glossary.md#fixup) takes a dynamic
string or integer.

The examples are [`.fsr`](../../docs/glossary.md#fsr) (see `docs/fsr.md`). In
`.fsr` and `ferrosip.toml` the modules use their ferrosip names, from the
first column of the table below. The functions are `<name>.<function>()`,
for example `text.append_header()` or `log.info()`. They are all listed in
`docs/functions-reference.md`. Most examples are statements from a
`route main(msg: Request)` body. The file needs `import <name>` for each
module it calls. `log` and `txn` need no import. Parameters go in
`ferrosip.toml` under `[modules.<name>]`, or under the Kamailio name.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `stateless` | `sl` | Stateless replies |
| `text` | `textops` | Search, insert, remove and replace in headers and body; reply headers; string compares |
| `text` | `textopsx` | Remove the body, change a reply's status, keep only some headers, glob match |
| `sip` | `siputils` | SIP tests (To tag, [E.164](../../docs/glossary.md#e164), URI compare, Supported), `options_reply`, `tel2sip` |
| `sip` | `sanity` | Checks that a request is well formed, with automatic error replies |
| `log` | `xlog` | Formatted logging with variables |
| `utils` | `cfgutils` | Random events, sleep, named locks, global flags |
| `utils` | `corex` | Raw send, extended flags, file read and write |
| `utils` | `kex` | Script flags, `$du` helpers, `pv_printf`, branches, log level |
| `stats` | `statistics` | Counters defined by the script |
| `vars` | `pv` | Variable tests, `xavp_params_explode` |
| `ip` | `ipops` | IP address tests, subnets, DNS lookups |
| `blocklist` | `blst` | Script access to the core destination blocklist |

The body edits are `set_body`, `replace_body*`, `subst_body` and
`remove_body`. They all work on the core's single body override, so you can
combine them. Content-Length is fixed when the message is rendered.
Content-Type is fixed too, when one is given.

## stateless (sl)

This module sends [stateless](../../docs/glossary.md#stateless-proxy) replies
through the core reply path. See also [sl](../../docs/glossary.md#sl).

**Functions**

| Signature | Description |
|---|---|
| `sl_send_reply(code, reason)` | Send a stateless reply. `code` must be 100–699. A constant code is checked at startup. Returns 1 when sent, -1 otherwise. Includes headers and body added by `append_to_reply`, `set_reply_body` and `append_time`. |
| `send_reply(code, reason)` | As Kamailio's: where tm answers for the request, through the transaction (a failure route; a request route whose `t_relay()` failed), else like `sl_send_reply`. In a failure route the reply is the transaction's only final: the best reply is not relayed after it. -1 if the transaction already has its final. |
| `send_reply_error()` | Answers with the error of the last failed function. Where tm answers for the request, through the transaction in tm's words (`t_reply_error()`, `(N/TM)`), else statelessly in sl's (`(N/SL)`; with no error `500 I'm terribly sorry, server error occurred (1/SL)`). Sends nothing (-3) while tm owes a failed `t_relay()` its reply, and after an `sl_send_reply()` final (-2). |
| `sl_forward_reply()` | Accepted for compatibility. Always returns -1. |

**Statistics**: `sl:sent_replies`, `sl:1xx_replies` … `sl:6xx_replies`.
The core counts them for every stateless reply.

**Example**

```rust
import stateless

route main(msg: Request) {
    stateless.reply(404, "Not here: {msg.ruri.user}")
}
```

The builtin `reply(code, reason)` is `send_reply`.

As in Kamailio, `sl_send_reply()` and `sl_reply_error()` are for
`request_route`: in a [failure route](../../docs/glossary.md#failure-route)
block they are a config error. In a `route[…]` a failure route calls, they
reply statelessly and tm still relays the best reply after the route.

**Differences from Kamailio**: `send_reply()` after `t_newtran()` or in a
resumed request is stateless, and the transaction takes it as its reply.
`sl_forward_reply()` is a stub.

## text (textops)

This module edits headers and the body, by name or by regex. It also has a
few string helpers.

- Header names also match their compact forms, such as `f` for `From`.
- The regex header functions (`*_re`, `remove_hf_exp`) ignore case.
- Replacement text uses Kamailio syntax: `\1` back-references, `\n`, `\r`
  and `\t`. It may contain variables.

**Functions**

| Signature | Description |
|---|---|
| `is_present_hf(name)` | 1 if a [header](../../docs/glossary.md#header-field) with this name exists. |
| `is_present_hf_re(regex)` | 1 if a header name matches. |
| `append_hf(text[, after_hdr])` | Append a header line at the end of the headers, or right after the first `after_hdr`. Adds CRLF if missing. -1 if `after_hdr` is absent. |
| `insert_hf(text[, before_hdr])` | Insert after the request or status line, or before the first `before_hdr`. |
| `remove_hf(name)` | Remove all headers with this name. Returns the count, -1 if none. |
| `remove_hf_re(regex)` | Remove headers whose name matches. Returns the count, -1 if none. |
| `remove_hf_exp(regex, skip_regex)` | Remove headers that match `regex` but not `skip_regex`. |
| `search(regex)` | 1 if the whole message matches. |
| `search_body(regex)` | 1 if the body matches. |
| `search_hf(name, regex[, flags])` | Match the header bodies. Flags: `a` any (default), `f` first, `l` last. |
| `search_append(regex, text)` | Insert `text` after the first match in the message. |
| `replace(regex, text)` / `replace_all(regex, text)` | Replace the first match / every match in the message. Returns the number of replacements, -1 if none. |
| `replace_body(regex, text)` / `replace_body_all(regex, text)` / `replace_body_atonce(regex, text)` | Replace in the body, including earlier edits to it. `_atonce` behaves like `_all`. |
| `subst('/re/repl/flags')` | sed-style substitution on the header part. Flags: `i` ignores case, `g` replaces every match. Any delimiter works. Returns the count, -1 if none. |
| `subst_uri('/re/repl/flags')` | Substitute on the [R-URI](../../docs/glossary.md#r-uri). |
| `subst_user('/re/repl/flags')` | Substitute on the R-URI user. |
| `subst_body('/re/repl/flags')` | Substitute on the body. |
| `subst_hf(name, '/re/repl/flags')` | Substitute on the body of the first `name` header. |
| `has_body([content_type])` | 1 if there is a body. Optionally checks its type. |
| `is_method("INVITE\|BYE")` | The [method](../../docs/glossary.md#method) of a request is in the list. For a reply, the [CSeq](../../docs/glossary.md#cseq) method is checked. |
| `set_body(body, content_type)` | Replace the body and Content-Type. |
| `set_reply_body(body, content_type)` | Set the body for the next stateless reply. |
| `append_to_reply(text)` | Add a header line to the next stateless reply. |
| `append_time()` | Add a `Date:` header in RFC 7231 format to the next stateless reply. |
| `starts_with(str, prefix)` | 1 if `str` starts with `prefix`. |
| `cmp_str(a, b)` / `cmp_istr(a, b)` | Equality test. The first is case-sensitive, the second ignores case. |
| `str_find(str, needle)` | Position of `needle`, counting from 1. -1 if not found. |

**Example**

```rust
// import textops
if msg.headers.has("X-Foo") && text.search_header("X-Foo", "bar1", "f") {
    text.append_to_reply("X-Result: present")
}
text.append_header("X-Appended: {msg.from.user}")
text.remove_header_re("^X-Gone-")
text.subst_user("/^edit$/edited/")
if text.has_body("text/plain") {
    text.subst_body("/w(or)ld/W\\1LD/")    // \\ in a .fsr string is one backslash
}
```

**Differences from Kamailio**: `subst()` edits only the header part. Use
`subst_body()` for the body. `replace_body_atonce` is the same as
`replace_body_all`.

## text (textopsx)

**Functions**

| Signature | Description |
|---|---|
| `remove_body()` | Drop the body and Content-Type. -1 if there is no body. |
| `change_reply_status(code, reason)` | Rewrite the status line of a reply, in reply routes. -1 on a request or a bad code. |
| `keep_hf(regex)` | Remove every header whose name does not match. Always keeps Via, From, To, Call-ID, CSeq, Content-Length, Content-Type, Max-Forwards, Contact, Route and Record-Route. |
| `fnmatch(value, pattern[, flags])` | Shell glob match (`*`, `?`, `[a-z]`, `[!x]`). |

**Example**

```rust
// import textopsx
text.keep_headers("^X-Keep")
if text.fnmatch(msg.ruri.user, "+49*") {
    log.info("German number\n")
}
```

**Differences from Kamailio**: the `fnmatch` flags argument is accepted but
ignored.

## sip (siputils)

**Functions**

| Signature | Description |
|---|---|
| `has_totag()` | 1 if the To header has a non-empty [tag](../../docs/glossary.md#tag). |
| `is_user(user)` | The R-URI user equals `user`. |
| `is_e164(str)` | `+` followed by 2–15 digits. |
| `is_uri_user_e164(uri)` | The user part of `uri` is E.164. |
| `is_alphanum(str)` / `is_numeric(str)` | Non-empty and only ASCII letters and digits / only digits. |
| `uri_param(name[, value])` | The R-URI has parameter `name`, optionally with this value. |
| `add_uri_param(param)` | Append `;param` to the R-URI. |
| `cmp_uri(a, b)` | RFC 3261 URI comparison. It is simplified: it compares scheme, host, port and the `transport`, `user`, `ttl`, `method` and `maddr` parameters. The user is case-sensitive. |
| `cmp_aor(a, b)` | Same user and host. The host ignores case. |
| `is_request()` / `is_reply()` | Message type. |
| `is_supported(option)` | The option tag is in a `Supported` (`k`) header. |
| `options_reply()` | Answer an [OPTIONS](../../docs/glossary.md#options) whose R-URI has no user with 200 and Allow and Accept headers. -1 otherwise. |
| `tel2sip(uri, host, $result)` | Writes `sip:+15550100;p=x@host;user=phone` to `$result` for `tel:+1-555-0100;p=x`. -1 if not a [tel URI](../../docs/glossary.md#tel-uri). |

**Example**

```rust
// import siputils
if msg.method == OPTIONS && msg.ruri.user == "" {
    sip.options_reply()
    exit
}
if !msg.has_to_tag && sip.is_e164(msg.ruri.user) {
    sip.tel_to_sip("tel:{msg.ruri.user}", "sip:gw.example", t)   // the result goes into the local t
}
```

## sip (sanity)

This module checks a message against a bit mask of Kamailio's sanity checks.
When a check fails, it:

1. logs at NOTICE;
2. sends an error reply, unless the message is an
   [ACK](../../docs/glossary.md#ack) or a reply, or `noreply` is set;
3. returns 0 with `autodrop`, so the script stops.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `default_checks` | 3047 | Checks used when `sanity_check()` has no argument. |
| `uri_checks` | 7 | URI checks: 1 R-URI, 2 From, 4 To, 8 Contact. |
| `autodrop` | 1 | Return 0 on failure, which stops the script. With 0, return -1. |
| `noreply` | 0 | Don't send the error reply. |

The check bits are:

| Bit | Check |
|---|---|
| 2 | R-URI scheme (416) |
| 4 | required headers |
| 8 | Via version |
| 16 | Via transport |
| 32 | CSeq method |
| 64 | CSeq value |
| 128 | Content-Length (UDP only) |
| 256 | Expires |
| 512 | Proxy-Require (420 + `Unsupported`) |
| 1024 | parse URIs |
| 2048 | digest credentials |
| 4096 | duplicate From/To tags |

Bit 1 (R-URI SIP version) is enforced by the parser.

**Functions**

| Signature | Description |
|---|---|
| `sanity_check([checks[, uri_checks]])` | 1 when the message passes. On failure: 0 with `autodrop`, or -1. |

**Statistics**: `sanity:failed`.

**Example**

```toml
[modules.sip]
autodrop = true
```

```rust
import sip

route main(msg: Request) {
    guard sip.check(3047, 7) else exit
    …
}
```

`msg.is_sane()` is `sanity_check()` with the module's default checks.

**Differences from Kamailio**: the digest check (2048) only verifies that
Digest credentials contain `username` and `response`.

## log (xlog)

**Functions**

| Signature | Description |
|---|---|
| `xlog([level,] format)` | Log `format` at `level`, with variables expanded. The level is `L_ERR` by default. It can be `L_ALERT`, `L_BUG`, `L_CRIT`, `L_ERR`, `L_WARN`, `L_NOTICE`, `L_INFO`, `L_DBG`, a number or a variable. Always returns 1. |
| `xlogl([level,] format)` | Same as `xlog`. |
| `xalert`, `xcrit`, `xerr`, `xwarn`, `xnotice`, `xinfo`, `xdbg`, `xbug` `(format)` | Log at a fixed level. |

A message above the current log level is not formatted at all. The log level
is set with `--debug`, `setdebug()` or the [RPC](../../docs/glossary.md#rpc)
`corex.debug`.

**Example**

```rust
log.info("req {msg.method} from {msg.src.ip} to {msg.ruri.user}\n")
log.warn("gateway {msg.ruri} is down\n")
```

`log.write(level, text)` takes the level as an argument, such as `"warn"`.

**Differences from Kamailio**: `xlogl` does not prefix the config line.

## utils (cfgutils)

**Parameters**

| Name | Default | Description |
|---|---|---|
| `initial_probability` | 10 | Probability in % for `rand_event()`, 0–100. |
| `initial_gflags` | 0 | Initial global flag bits. |

**Functions**

| Signature | Description |
|---|---|
| `rand_event()` | 1 with the current probability. |
| `rand_set_prob(p)` / `rand_reset_prob()` | Set the probability / reset it to `initial_probability`. |
| `rand_get_prob()` | Returns the probability as the return value. |
| `sleep(secs)` / `usleep(usecs)` | Block the [worker](../../docs/glossary.md#worker). |
| `lock(key)` | Take a named global lock. Waits if it is held. |
| `trylock(key)` | 1 if taken, -1 if already held. |
| `unlock(key)` | Release. -1 if not held. |
| `set_gflag(n)` / `reset_gflag(n)` / `is_gflag(n)` | Global [flags](../../docs/glossary.md#flags) 0–63, shared by all workers. |

**RPC commands**

| Command | Description |
|---|---|
| `cfgutils.get_prob` | Current `rand_event` probability. |
| `cfgutils.set_gflag <mask>` | OR the mask into the global flags. Returns the flags. |
| `cfgutils.get_gflags` | Global flags. |

**Example**

```toml
[modules.utils]
initial_probability = 100
```

```rust
// import cfgutils
utils.lock("k")
if !utils.try_lock("k") {
    log.info("held\n")
}
utils.unlock("k")
if utils.random_event() {
    utils.set_global_flag(5)
}
```

## utils (corex)

**Functions**

| Signature | Description |
|---|---|
| `send_data(uri, data)` | Send `data` raw to the address of `uri`. |
| `send([uri])` | Forward the message unchanged, statelessly and with no Via added. It goes to `uri`, else `$du`, else the R-URI. |
| `setxflag(n)` / `resetxflag(n)` / `isxflagset(n)` | Extended per-message flags 0–63. |
| `is_faked_msg()` | 1 where the context is built around a synthetic message, as in event routes and failure routes. |
| `has_ruri_user()` | The R-URI has a non-empty user. |
| `file_read(path, $var)` | Read a whole file into a variable. -1 on error. |
| `file_write(path, content)` | Write a file, replacing its content. |

**Example**

```rust
// import corex
utils.set_xflag(2)
if utils.has_xflag(2) && !utils.is_faked() {
    utils.send_data("sip:127.0.0.1:5802", "RAW {msg.ruri.user}")
}
```

## utils (kex)

**Functions**

| Signature | Description |
|---|---|
| `setsflag(n)` / `resetsflag(n)` / `issflagset(n)` | Script flags 0–63. |
| `setdsturi(uri)` / `resetdsturi()` / `isdsturiset()` | Set, clear or test [`$du`](../../docs/glossary.md#destination-uri). |
| `pv_printf($var, format)` | Assign the formatted string to a variable. |
| `km_append_branch([uri])` | Add a [branch](../../docs/glossary.md#branch) with `uri`, or with the R-URI and `$du`. |
| `setdebug(level)` / `resetdebug()` | Change the global log level / reset it to INFO. |

**RPC commands**

| Command | Description |
|---|---|
| `corex.debug [level]` | Get or set the log level. `kex` registers it. |

**Example**

```rust
// import kex
utils.set_dst("sip:127.0.0.1:5802")        // or: msg.dst_uri = "sip:127.0.0.1:5802"
if utils.has_dst() {
    utils.printf(p, "dst={msg.dst_uri}")    // into the local p; or: let p = "dst={msg.dst_uri}"
}
```

**Differences from Kamailio**: `resetdebug()` goes back to INFO, not to the
level given at startup.

## stats (statistics)

**Parameters**

| Name | Default | Description |
|---|---|---|
| `variable` | none | Declare a [counter](../../docs/glossary.md#counter) `group:name`, or `name` in group `script`. Anything after `/` is ignored. Repeatable. |

**Functions**

| Signature | Description |
|---|---|
| `update_stat(name, value)` | Add `value` to the counter. `value` may be negative. Creates the counter if needed. |
| `reset_stat(name)` | Set the counter to 0. |

Read the counters with `ferroctl stats.get_statistics script:`.

**Example**

```toml
[modules.stats]
variable = ["script:hits"]
```

```rust
import stats

route main(msg: Request) {
    stats.update("script:hits", 1)
    …
}
```

## vars (pv)

**Functions**

| Signature | Description |
|---|---|
| `pv_isset($v)` / `pv_unset($v)` | Not null / set to null. |
| `is_int($v)` | Holds an integer. |
| `typeof($v, "int"\|"str"\|"null")` | Type test. |
| `not_empty($v)` | Truthy value. |
| `xavp_params_explode("a=1;b=2", "name")` | Add an item to `$xavp(name)` with one string field per parameter. |

**Example**

`$var` and [`$xavp`](../../docs/glossary.md#xavp) have no `.fsr` form. In
`.fsr` these functions are `vars.explode_params()`, `vars.is_type()` and the
others, and they work on locals. This example is a Kamailio-style `.cfg`:

```
xavp_params_explode("a=1;b=two", "xp");
if (typeof("$var(x)", "int")) { xinfo("$xavp(xp=>b)\n"); }
```

## ip (ipops)

**Functions**

| Signature | Description |
|---|---|
| `is_ip(s)` / `is_ipv4(s)` / `is_ipv6(s)` | IP address. An IPv6 address may be in brackets. |
| `is_pure_ip(s)` | IP address without brackets. |
| `is_ipv6_reference(s)` | `[IPv6]`. |
| `ip_type(s)` | 1 IPv4, 2 IPv6, 3 IPv6 reference, -1 not an IP. |
| `compare_ips(a, b)` | Same address. `::1` equals `[::1]`. |
| `ip_is_in_subnet(ip, "net/len,net/len")` / `is_in_subnet(…)` | In any of the comma-separated subnets. A bare address counts as /32 or /128. |
| `is_ip_rfc1918(ip)` | 10/8, 172.16/12 or 192.168/16. |
| `dns_sys_match_ip(host, ip)` | `host` resolves to `ip` through the system resolver. |
| `dns_query(host, id)` | Resolve `host` and keep the results under `id`. -1 if no address. |

**Pseudo-variables**: `$dns(id=>key)` holds the results of `dns_query`. The
keys are `addr[i]` (default `addr[0]`), `count`, `ipv4` / `ipv6` (1 if any)
and `type[i]` (4 or 6). See
[pseudo-variable](../../docs/glossary.md#pseudo-variable-pv).

**Example**

```rust
// import ipops
if ip.in_subnet(msg.src.ip, "192.168.0.0/16,10.0.0.0/8") {
    log.info("internal\n")
}
```

`dns_query` is `ip.resolve(host, id)`. Its results are only in `$dns(…)`,
which has no `.fsr` form. In a Kamailio-style `.cfg`:

```
if (dns_query("localhost", "d")) { xinfo("first: $dns(d=>addr[0]) of $dns(d=>count)\n"); }
```

**Differences from Kamailio**: DNS lookups go through the system resolver.

## blocklist (blst)

This module gives the script access to the core
[destination blocklist](../../docs/glossary.md#destination-blocklist)
(`dst_blocklist`). It acts on the current next hop: `$du`, else the R-URI's
address. [tm](../../docs/glossary.md#tm) also adds entries, see
`use_dst_blocklist` and `blst_503` in the core. The core `dst_blocklist.*`
RPCs manage the entries.

**Functions**

| Signature | Description |
|---|---|
| `blst_add([secs])` | Block the next hop for `secs`. The default is the core `dst_blocklist_expire`. |
| `blst_add_retry_after(min, max)` | Block for the reply's Retry-After, clamped to `[min, max]`. Uses `min` when Retry-After is absent. Reads the message in a reply route, and the winning reply in a failure route. |
| `blst_del()` | Remove the next hop. -1 if it wasn't listed. |
| `blst_is_blocklisted()` | 1 if the next hop is blocked. |

**Example**

```rust
import blocklist

on reply(r: Reply) where r.code == ServiceUnavailable {
    blocklist.add_retry_after(30s, 5m)
}
```

## Testing

- `tests/e2e_utils.py`: runs sl, textops, textopsx, siputils, sanity, xlog,
  cfgutils, corex, kex, statistics, pv and ipops against a running proxy. It
  also checks the reply statistics through `ferroctl`.
- `tests/e2e_dns.py`: `blst_add` / `blst_is_blocklisted` and entry expiry.
- Unit tests (`cargo test -p mod-sip`): HTTP dates and replacement syntax,
  substitution parsing, E.164 and URI comparison, glob matching, subnets.
