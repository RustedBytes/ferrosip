# `.fsr`: ferrosip's routing language

Phase 2 of the configuration redesign (the design: "ferrosip
Configuration & Routing Language"; phase 1: [config-toml.md](config-toml.md)).
`ferrosip.toml` says **what runs**; `.fsr` files say **how messages are
routed**.

```toml
[routing]
entry = "routes/main.fsr"
```

`.fsr` compiles to the same route tree as a Kamailio-style `.cfg`:
- the same functions, fixups and reload;
- the same suspend/resume machinery;
- the same speed.

`ferrosip check --lowered` prints the equivalent `.cfg`. `.cfg` files
keep working.

Status:
- **Step 2a (done):** the core language, `await`, and typed signatures
  for every module function
  ([functions-reference.md](functions-reference.md)).
- **Step 2b (done):** event handlers (dialogs, timers, HTTP, …), shared
  tables and dialog variables.
- **Step 2c (done):** `await` anywhere (inside `if`, `match`, loops and
  called functions), `for` loops, helper functions without a message.
- **Step 2d (done):** `ferrosip test`.
- **Step 2e (done):** `ferrosip import` ([import.md](import.md)) and the
  escape hatch to Kamailio (below).
- **Later steps:** tracing.

## Example

```rust
import txn, location, auth, nat, media
import { features } from config

flag NATED            // named flags, the compiler assigns bits

route main(msg: Request) {
    guard msg.max_forwards > 0 else reply(TooManyHops)
    guard msg.is_sane() else drop

    if features.nat && nat.is_behind(msg) {
        msg.set(NATED)
        nat.fix_contact(msg)
    }
    if msg.has_to_tag {
        return in_dialog(msg)
    }
    match msg.method {
        REGISTER => register(msg)
        INVITE => invite(msg)
        OPTIONS => reply(OK)
        _ => reply(MethodNotAllowed)
    }
}

fn invite(msg: Request) -> Action {
    let found = location.lookup() else return reply(NotFound)
    if msg.is(NATED) { media.offer(msg) }

    // the transaction result is a value, not a separate failure block
    let res = await txn.relay(msg, timeout: 30s)
    match res {
        Final(r) if r.code in 200..299 => forward(r)
        Final(r) if r.code == BusyHere => voicemail(msg)
        Timeout | Final(_) => reply(TemporarilyUnavailable)
    }
}

on reply(r: Reply) where r.code in 180..183 {
    if r.has_sdp { media.answer(r) }
}
```

## Syntax

**Lexical:**
- Comments are `// …` and `/* … */`.
- Statements need no separators (`;` is allowed). A newline only ends an
  optional value: `return` and `drop` at the end of a line take nothing,
  and a line starting with `-` starts a new statement.
- Strings: `"…"`, or `"""…"""` across lines.
  - Escapes: `\n \t \r \" \\`.
  - `{expr}` interpolates; `\{` and `\}` are literal braces.
- Durations: `500ms`, `30s`, `2m`, `1h30m`, `1d`.
- Integers may contain `_`.

**Items:**
```
import txn, location                 // modules the routes use (loaded implicitly)
import { features } from config      // [feature] values from ferrosip.toml, as constants
import "./pstn.fsr" as pstn          // another file, in its own namespace
flag NATED                           // a named message flag (the compiler picks the bit)
flag FLT_ACC = 1                     // … or a fixed bit 0..31, for one a module parameter names
branch flag FLB_NATB = 6             // a branch flag (its own 32 bits; also with the bit picked)
shared table bans: Map<Str, Bool> ttl 10m   // shared memory, with expiry
dialog var caller: Str               // lives as long as the dialog
route main(msg: Request) { … }       // main = request_route; others are named routes
fn name(msg: Request, x: Int) -> Action { … }
fn helper(x: Str) { … }              // no message: event handlers can call it too
on reply(r: Reply) where <cond> { … }
on dialog.ended(d: Dialog) { … }     // and the other events below
```

**Statements:**
```
let x = expr                         // let x: Type = expr
let c = expr else <statement>        // the else runs when expr is empty/false
target = expr                        // msg.ruri.user = "bob", msg.headers["X-A"] = "1", x = x + 1
if cond { … } else if cond { … } else { … }
while cond { … }
for x in [a, b] { … }                // also: for i in 1..3 { … }; break leaves it
guard cond else <statement>
match expr { Pattern [| Pattern] [if cond] => statement | { block } … }
return [expr]    drop    exit    break
expr                                 // a call: module.fn(args, name: value), name(msg)
```

**Patterns:**
- `_`;
- a literal (`486`, `"x"`) or a constant (`INVITE`);
- an inclusive range `200..299`;
- `Final(r)`, `Final(_)` and `Timeout` for `await` results;
- several patterns joined with `|`.

**Expressions, loosest to tightest:**
1. `||`
2. `&&`
3. `== != < <= > >= in =~`
4. `a..b` (an inclusive range)
5. `+ -`
6. `* / %`
7. unary `! -`, then `await`
8. postfix: calls `f(…)`, fields `.name`, indexing `[i]`

Lists are written `[a, b]`.

Formatting: `ferrosip fmt routes/` writes the canonical layout:
- 4-space indents;
- one blank line between items, kept between statements where the
  source had one;
- comments where they were.

It is idempotent.

Lints: `ferrosip lint` points at unused variables, imports and functions,
loops that never end, an open relay and more, and `ferrosip lint --fix`
applies the mechanical fixes ([lint.md](lint.md)).

## Types and the message

Values are `Int`, `Str`, `Bool`, `Duration` (`30s`), `Method` (`INVITE`),
`Transport` (`UDP` … `WSS`) and named flags. The checker rejects what
doesn't fit: a string where a duration goes, `msg.ruri` set on a reply, an
unknown field or function (with "did you mean"), a function used where it
can't run (`location.save` in `on reply`).

| `.fsr` | lowers to |
|---|---|
| `msg.ruri`, `.ruri.user/host/port` | `$ru`, `$rU`, `$rd`, `$rp` (settable) |
| `msg.dst_uri` | `$du` (settable) |
| `msg.from.uri/user/host/tag/display`, `msg.to.*` | `$fu $fU $fd $ft $fn`, `$tu $tU $td $tt` |
| `msg.method`, `.call_id`, `.cseq`, `.user_agent`, `.body` | `$rm $ci $cs $ua $rb` |
| `msg.src.ip/port/transport` | `$si $sp $pr` |
| `r.code`, `r.reason` (replies) | `$rs $rr` |
| `msg.headers["X"]` / `= v` / `.remove("X")` / `.has("X")` | `$hdr(X)` / `remove_hf` + `append_hf` / `remove_hf` / `is_present_hf` |
| `msg.has_sdp`, `msg.has_to_tag`, `msg.is_sane()` | `has_body("application/sdp")`, `has_totag()`, `sanity_check()` |
| `guard msg.max_forwards > 0 else …` | `mf_process_maxfwd_header(70)` (checks and decrements) |
| `msg.set/is/reset(F)` | `setflag/isflagset/resetflag(n)`; bits from 31 down, or the fixed one (`flag F = n`) |
| `msg.set/is/reset(B[, branch: i])` for a `branch flag B` | `setbflag/isbflagset/resetbflag(n[, i])` (branch 0: the R-URI's) |
| `reply(code[, reason])` | `send_reply` (`t_reply` after `await`), then the route ends |

`sql.quote(v)` makes a value safe to put into an SQL statement (a quoted,
escaped literal; Kamailio's `{sql.val.str}`):
`"SELECT target FROM numbers WHERE num = {sql.quote(msg.ruri.user)}"`.
Never put a message value into SQL without it.

Function calls are `namespace.name(args, name: value)`. The namespaces are
the ferrosip module names of ferrosip.toml (`txn`, `location`, `auth`,
`sip`, `text`, `nat`, `media`, `balancer`, `log`, …; the table is in
[config-toml.md](config-toml.md)), and every function has a
signature: parameter types, which may be left out, which must be
constants, what it returns, where it may run. A call returns:
- `Bool`: a check, used in conditions;
- `Action`: it answers or relays the request, so the route ends after it;
  if it fails the request is answered with its error (`sl_reply_error`;
  for a relay, tm answers it when the route ends, as in Kamailio);
- nothing.

`let` variables and extra function parameters are AVPs, so they belong to
the transaction and are still there after `await`.

### Status codes

A [status code](glossary.md#status-code) can be written by name wherever
an `Int` code goes: `reply(NotFound)`, `r.code == BusyHere`,
`r.code in Ringing..SessionProgress`, match arms (`Ringing | Queued => …`,
`Ringing..SessionProgress => …`), `req.reply(OK)`. A misspelt name is a
compile error with a suggestion; a `let` of the same name shadows it.

```rust
let found = location.lookup() else return reply(NotFound)

on reply(r: Reply) {
    match r.code {
        Ringing..SessionProgress => log.info("early {r.code}\n")
        BusyHere | BusyEverywhere => log.info("busy\n")
        _ => {}
    }
}
```

| name | code | default reason |
|---|---|---|
| `Trying` | 100 | Trying |
| `Ringing` | 180 | Ringing |
| `CallIsBeingForwarded` | 181 | Call Is Being Forwarded |
| `Queued` | 182 | Queued |
| `SessionProgress` | 183 | Session Progress |
| `EarlyDialogTerminated` | 199 | Early Dialog Terminated |
| `OK` | 200 | OK |
| `Accepted` | 202 | Accepted |
| `NoNotification` | 204 | No Notification |
| `MultipleChoices` | 300 | Multiple Choices |
| `MovedPermanently` | 301 | Moved Permanently |
| `MovedTemporarily` | 302 | Moved Temporarily |
| `UseProxy` | 305 | Use Proxy |
| `AlternativeService` | 380 | Alternative Service |
| `BadRequest` | 400 | Bad Request |
| `Unauthorized` | 401 | Unauthorized |
| `PaymentRequired` | 402 | Payment Required |
| `Forbidden` | 403 | Forbidden |
| `NotFound` | 404 | Not Found |
| `MethodNotAllowed` | 405 | Method Not Allowed |
| `NotAcceptable` | 406 | Not Acceptable |
| `ProxyAuthenticationRequired` | 407 | Proxy Authentication Required |
| `RequestTimeout` | 408 | Request Timeout |
| `Conflict` | 409 | Conflict |
| `Gone` | 410 | Gone |
| `LengthRequired` | 411 | Length Required |
| `ConditionalRequestFailed` | 412 | Conditional Request Failed |
| `RequestEntityTooLarge` | 413 | Request Entity Too Large |
| `RequestUriTooLong` | 414 | Request-URI Too Long |
| `UnsupportedMediaType` | 415 | Unsupported Media Type |
| `UnsupportedUriScheme` | 416 | Unsupported URI Scheme |
| `UnknownResourcePriority` | 417 | Unknown Resource-Priority |
| `BadExtension` | 420 | Bad Extension |
| `ExtensionRequired` | 421 | Extension Required |
| `SessionIntervalTooSmall` | 422 | Session Interval Too Small |
| `IntervalTooBrief` | 423 | Interval Too Brief |
| `BadLocationInformation` | 424 | Bad Location Information |
| `BadAlertMessage` | 425 | Bad Alert Message |
| `UseIdentityHeader` | 428 | Use Identity Header |
| `ProvideReferrerIdentity` | 429 | Provide Referrer Identity |
| `FlowFailed` | 430 | Flow Failed |
| `AnonymityDisallowed` | 433 | Anonymity Disallowed |
| `BadIdentityInfo` | 436 | Bad Identity-Info |
| `UnsupportedCertificate` | 437 | Unsupported Certificate |
| `InvalidIdentityHeader` | 438 | Invalid Identity Header |
| `FirstHopLacksOutboundSupport` | 439 | First Hop Lacks Outbound Support |
| `MaxBreadthExceeded` | 440 | Max-Breadth Exceeded |
| `BadInfoPackage` | 469 | Bad Info Package |
| `ConsentNeeded` | 470 | Consent Needed |
| `TemporarilyUnavailable` | 480 | Temporarily Unavailable |
| `CallDoesNotExist` | 481 | Call/Transaction Does Not Exist |
| `LoopDetected` | 482 | Loop Detected |
| `TooManyHops` | 483 | Too Many Hops |
| `AddressIncomplete` | 484 | Address Incomplete |
| `Ambiguous` | 485 | Ambiguous |
| `BusyHere` | 486 | Busy Here |
| `RequestTerminated` | 487 | Request Terminated |
| `NotAcceptableHere` | 488 | Not Acceptable Here |
| `BadEvent` | 489 | Bad Event |
| `RequestPending` | 491 | Request Pending |
| `Undecipherable` | 493 | Undecipherable |
| `SecurityAgreementRequired` | 494 | Security Agreement Required |
| `ServerInternalError` | 500 | Server Internal Error |
| `NotImplemented` | 501 | Not Implemented |
| `BadGateway` | 502 | Bad Gateway |
| `ServiceUnavailable` | 503 | Service Unavailable |
| `ServerTimeout` | 504 | Server Time-out |
| `VersionNotSupported` | 505 | Version Not Supported |
| `MessageTooLarge` | 513 | Message Too Large |
| `PushNotificationServiceNotSupported` | 555 | Push Notification Service Not Supported |
| `PreconditionFailure` | 580 | Precondition Failure |
| `BusyEverywhere` | 600 | Busy Everywhere |
| `Decline` | 603 | Decline |
| `DoesNotExistAnywhere` | 604 | Does Not Exist Anywhere |
| `GlobalNotAcceptable` | 606 | Not Acceptable |
| `Unwanted` | 607 | Unwanted |
| `Rejected` | 608 | Rejected |

## `await`

```rust
let res = await txn.relay(msg, timeout: 30s, to: "udp:10.0.0.5:5060")
match res {
    Final(r) if r.code in 200..299 => forward(r)
    Final(r) if r.code == BusyHere => voicemail(msg)
    Timeout | Final(_) => reply(TemporarilyUnavailable)
}
```

`await txn.relay(…)` relays statefully (tm's `t_relay_await`) and stops;
the statements after it run when the transaction has its final reply:
- **a negative final** (or no final within `timeout`): before anything goes
  upstream, in the failure context. The code may relay again (on the same
  transaction, e.g. to voicemail or the next gateway, even with another
  `await`) or `reply`. If it does neither, the best reply goes upstream
  (`forward(r)` says exactly that).
- **a 2xx**: it is forwarded upstream at once, then the code after `await`
  runs too (to log or account the call); replying is no longer possible.

`timeout:` replaces both `fr_timer` and `fr_inv_timer` for this relay: a
next hop that sends nothing ends `timeout` after the request, and one
that rings without answering ends `timeout` after its first provisional
(the ring time). Without it the `[modules.txn]` timers apply (or
`txn.set_timeout(inv, non_inv)` before the `await`), so a silent hop can
be given up on sooner than a ringing one.

The result is `Final(r)`, with `r.code` and `r.reason` (`$T_reply_code`,
`$T_reply_reason`), or `Timeout` (`$T_timeout`: our own 408). A `match` on
it must handle both. A relay that fails at once (an unresolvable
destination, too many branches) doesn't wait: the script goes on at
once, and the result is `Final` with the local error code (also after an
earlier `await`) and `r.sent` false (`$rc` after the call; true for a
final that came back). As for a `.cfg`'s `t_relay()` (Kamailio's
`delayed_reply`), tm answers that error when the script ends, unless the
code replies first with `reply(…)`; `stateless.reply_error_and_continue()`
then sends nothing, as `if (!t_relay()) { send_reply_error(); }`:

```rust
let res = await txn.relay(msg)
match res {
    Final(r) if !r.sent => stateless.reply_error_and_continue()
    Final(r) if r.code < 300 => {}         // a 2xx went upstream
    _ => no_answer(msg)                    // a negative final or Timeout
}
exit
```

That is a Kamailio `failure_route`: it runs on a negative final or a
timeout (on a canceled transaction too: `txn.is_canceled()`), not after
a 2xx; `ferrosip import` writes it this way ([import.md](import.md)).

`await` may be anywhere a statement goes: inside `if`, `match` arms and
loops, and in any function. When the transaction has its final, the
script goes on exactly as if it had not stopped: the rest of the block,
then after the enclosing `if`, around the loop again, back into the
calling function. So a failover loop is ordinary code:

```rust
fn to_gateways(msg: Request) -> Action {
    for gw in ["sip:10.0.0.10", "sip:10.0.0.11", "sip:10.0.0.12"] {
        msg.dst_uri = gw
        let res = await txn.relay(msg, timeout: 5s)
        match res {
            Final(r) if r.code < 500 => forward(r)   // answered: done
            _ => {}                                    // 5xx or no answer: next
        }
    }
    reply(ServiceUnavailable, "All gateways failed")
}
```

Rules:
- not in a function returning `Bool`: its caller tests the value at once,
  so it can't wait;
- after an `await` (also after an `if` that may have awaited) only what is
  allowed after the final can be called, and `reply()` answers the
  transaction;
- after `await txn.relay` nothing else can be awaited (the request is
  relayed).

Values kept across `await`: `let` locals, parameters and loop variables
(they belong to the transaction). Message changes made before it (R-URI,
headers) are on the request the next relay sends.

### Awaiting other calls

Functions whose result takes time are called with `await` too, and give
a typed record:

```rust
import http

route main(msg: Request) {
    let r = await http.get("http://routing.local/route?user={msg.ruri.user}", timeout: 300ms)
    if r.ok && r.status == 200 {
        msg.dst_uri = "sip:{r.body}"
        relay(msg)
    }
    reply(ServiceUnavailable, "Routing service down")
}
```

| call | result |
|---|---|
| `await http.get(url[, headers][, timeout:])`, `http.post(url, body[, content_type][, headers][, timeout:])`, `http.request(method, url[, body][, headers][, timeout:])` | `HttpResponse`: `ok`, `status`, `reason`, `body`, `error`, `ms` |
| `await ims_icscf.authorize([capabilities])` (Cx UAR) | `UarResult`: `code` (1 ok, -2 user unknown, -3 identities don't match, -4 roaming not allowed, -1 error) |
| `await ims_icscf.locate([originating])` (Cx LIR) | `LirResult`: `code` |

- HTTP calls run on a worker pool: the request waits (its transaction
  suspended) and the workers handle other messages meanwhile.
- The IMS Diameter exchanges suspend the transaction until the peer
  answers, as HTTP calls do: retransmissions are absorbed meanwhile and
  the worker goes on with other messages. Cx: `await ims_icscf.authorize()`
  / `.locate()`, and the MAR and SAR behind `ims_auth.www_challenge` and
  `ims_registrar_scscf.save`; Rx: `await ims_qos.authorize_media(dir)`; Ro:
  `await ims_charging.reserve(dir, units)` (each result has `code`: 1 ok,
  -1 not).
- A function that must be awaited can't be called without `await`, and
  `await` on one that gives its result at once is an error.
- `headers` are `Name: value` lines.

`location.save_and_continue()` answers a REGISTER like `location.save()`
but lets the route go on (for code that must run after it, like tsilo's
`pending_calls.append()` or msilo's `offline_messages.dump()`); end the route yourself.
`stateless.reply_error_and_continue()` is the same for
`stateless.reply_error()` (`send_reply_error()`): it answers with the
last error and the route goes on.

## The escape hatch to Kamailio

For what has no typed form (mostly configs from `ferrosip import`):

| `.fsr` | lowers to |
|---|---|
| `pv("$avp(x)")`, `pv("$avp(x)") = v` | `$avp(x)`, `$avp(x) = v` (exactly: for an AVP that adds a value) |
| `kamailio.call("fn", a, b)` | `fn(a, b)`, any module function, arguments as templates |
| `kamailio.bitor(a, b)`, `kamailio.bitand(a, b)` | `a \| b`, `a & b` |
| `kamailio.myself` | `myself` (compare a URI or host with it) |
| `on kamailio.failure_route(msg: Request, name: "X") { … }` | `failure_route[X]`, armed with `kamailio.call("t_on_failure", "X")` |
| `on kamailio.branch_route(msg: Request, name: "X")`, `on kamailio.onreply_route(msg: Reply, name: "X")` | `branch_route[X]`, `onreply_route[X]` |
| `on kamailio.event_route(name: "x:y")` | `event_route[x:y]` |

- The values are untyped (Str or Int at run time): they compare with
  anything, test as conditions, and add.
- Nothing is checked: not names, not arguments, not where a call may run.
  `ferrosip lint -W raw_kamailio` lists every use, so they can be replaced
  one by one.

In a failure, reply or branch handler (and after an `await`), `txn.code:
Int` and `txn.reason: Str` are the reply `txn.status_is("…")` tests: the
winning reply in a failure route, the current reply in a reply route
(`$T_reply_code`, `$T_reply_reason`). They are read-only, compare with
[status code](#status-codes) names, and are a compile error in a request
route:

```rust
on kamailio.failure_route(msg: Request, name: "F") {
    if txn.code == BusyHere || txn.code == RequestTimeout {
        msg.ruri = "sip:voicemail@10.0.0.2"
        txn.relay(msg)
    }
}
```

## Lowering

`.fsr` compiles to the route tree a `.cfg` parses to; `ferrosip check
--lowered` prints it as `.cfg`:
- `route main` → `request_route`; other routes and functions →
  `route[name]` (`route[pstn__name]` for a file imported as `pstn`);
- `on reply(r) where c` → `reply_route`, starting with `if (!c) return;`;
- `match` → an `if`/`else if` chain; `x in 200..299` → `x >= 200 && x <= 299`;
- an `Action` call → `if (!f(…)) { sl_reply_error(); } exit;`;
- `for x in [a, b]` → a `while` over an index local, the item picked by
  an `if` chain;
- `[feature]` values are constants: `if features.nat { … }` disappears
  when `nat = false`.

## Events

Handlers run when something happens outside a request. Several handlers
may be written for one event; each runs when its `where` holds, in source
order (`on http`: the first that matches answers).

| handler | when | the parameter |
|---|---|---|
| `on reply(r: Reply)` | every reply | `r.code`, `r.reason`, the message fields |
| `on dialog.started(d: Dialog)` | a dialog is confirmed (2xx) | see below |
| `on dialog.ended(d: Dialog)` | it ends (BYE, timeout, admin, keep-alive) | also `d.duration`, `d.end_reason` |
| `on dialog.failed(d: Dialog)` | it fails before a 2xx | also `d.code` |
| `on timer(every: 30s)` | every 30s | none |
| `on http(req: HttpRequest)` | an HTTP request to `[modules.http] listen` | `req.method url path query body headers["X"]`, `req.reply(code[, body][, content_type])` |
| `on balancer.up/down(e: Destination)` | a dispatcher destination changes state | `e.uri` |
| `on keepalive.up/down(e: Destination)` | a keepalive destination changes state | `e.uri` |
| `on limits.blocked(e: Source)` | pike blocks a source | `e.ip`, `e.port` |
| `on diameter.request(req: DiameterRequest)` | a Diameter request no IMS module handles (`event_route[diameter:request]`) | `req.command`, `req.application`, `req.avps` (the AVPs as JSON), `req.answer_avps` (the answer so far), `req.answer(avps)` |
| `on diameter.response(ans: DiameterAnswer)` | the answer to `ims_diameter_server.request_async(…)` (`event_route[diameter:response]`) | `ans.avps` (the answer's AVPs as JSON) |

A `Dialog` has `call_id`, `from_uri`, `to_uri`, `from_tag`, `to_tag`,
`state`, `started_at`, `timeout`, its declared variables, and `d.end()`
(BYE to both sides; not once it has ended). `end_reason` is
`caller_bye`, `callee_bye`, `timeout`, `admin`, `keepalive` or `failed`.

`req.answer(avps)` sets the Diameter answer's AVPs (Kamailio's JSON
list, `$diameter_response`); it is sent when the handlers have run, with
Session-Id, Origin-Host/-Realm and Result-Code 2001 added when missing.
Without an answer no reply is sent, as in Kamailio. Several handlers run
in order, so a later one can test `req.answer_avps == ""`:

```rust
on diameter.request(req: DiameterRequest) where req.application == 16777217 && req.command == 306 {
    req.answer("[\{\"avpCode\":702,\"vendorId\":10415,\"string\":\"<Sh-Data/>\"\}]")
}

on diameter.response(ans: DiameterAnswer) where ans.avps =~ "\"int32\":2001" {
    log.info("answered: {ans.avps}\n")
}
```

There is no request in a handler: `reply()`, `relay()` and functions that
need one are errors there. Shared tables, dialog variables, `log`, `sql`,
HTTP clients… are fine.

```rust
dialog var caller: Str

fn invite(msg: Request) -> Action {
    dialog.manage()
    dialog.caller = msg.from.user
    relay(msg)
}

on dialog.ended(d: Dialog) where d.duration > 0 {
    log.info("cdr {d.call_id} {d.caller} {d.duration}s {d.end_reason}\n")
}

on http(req: HttpRequest) where req.path == "/api/bans" && req.method == "DELETE" {
    bans.clear()
    req.reply(204)
}

on timer(every: 1m) {
    stats.incr("minutes")
}
```

The modules events need load by themselves (dialog, the HTTP server,
rtimer, htable…); the HTTP server needs `[modules.http] listen`.

## State

- `let x = …`: the message and its transaction (also after `await`).
- `dialog var name: Str|Int|Bool`: the dialog's. `dialog.name` in routes
  (after `dialog.manage()`), `d.name` in dialog handlers.
- `shared table name: Map<Str|Int, Bool|Int|Str|Counter> [ttl 10m]`:
  shared by every worker; items expire `ttl` after their last update
  (counted in whole seconds, as in Kamailio: an item lives between `ttl`
  and `ttl` + 1s).

| table method | does |
|---|---|
| `t.get(k)` | the value (`false`/`0`/empty when missing) |
| `t.contains(k)` | there is an item |
| `t.set(k, v[, ttl: 30s])` | store (with its own expiry) |
| `t.remove(k)` | delete |
| `t.incr(k)` / `t.decr(k)` | count (Int or Counter), giving the new value |
| `t.clear()` | delete everything |
| `t.count()` | how many keys it holds (expired ones not counted) |

There is no loop over a table's items; `ferroctl htable.dump <table>` lists
them.

```rust
shared table hits: Map<Str, Counter> ttl 10s
shared table bans: Map<Str, Bool> ttl 10m

route main(msg: Request) {
    if bans.contains(msg.src.ip) { drop }
    if hits.incr(msg.src.ip) > 50 {
        bans.set(msg.src.ip, true)
        drop
    }
    …
}
```

`now()` is the current Unix time (seconds). Inside `"…{…}"` a hole may
hold strings of its own: `"{hits.get("total")}"`.

Lowering: tables are htable tables (`$sht(t=>k)`, also visible to `.cfg`
code and the htable RPCs), dialog variables are `$dlg_var(x)`, timers are
rtimer routes (`route[timer__N]`), handlers are `event_route[…]` blocks.

## Tests

```rust
test "busy goes to voicemail" {
    location.lookup = true                    // a mock: lookup() succeeds
    send("INVITE sip:bob@10.0.0.5:5060")
    assert(relay_uri() == "sip:bob@10.0.0.5:5060")
    answer(BusyHere)
    assert(relay_uri(2) == "sip:vm@127.0.0.1:5090")
    answer(OK)
    assert(reply_code() == OK)
}
```

```bash
ferrosip test --config ferrosip.toml routes/main_test.fsr [--filter voicemail]
```

`test` blocks may be in the routing's files or in test files named on the
command line (compiled with the routing, so they see its tables, flags and
functions). Normal runs ignore them. Each test runs in its own process
with the real modules (transactions, timers, `await` included) and a
network that only records what is sent: no sockets, no database.

| in a test | does |
|---|---|
| `send(text[, from: "ip:port"])` | hands a SIP message to the routing; missing Via, From, To, Call-ID, CSeq and Max-Forwards are filled in, so `send("INVITE sip:bob@x")` is enough. `"""…"""` for more headers or a body |
| `answer(code[, reason])` | the destination of the last relayed request replies |
| `wait(2s)` | lets time pass (transaction timeouts); it is real time, so long waits make slow tests |
| `reply_code()`, `reply_reason()` | the final reply sent back for the last `send` (0 / empty: none yet; a 100 or 180 doesn't count) |
| `relays()`, `relay_uri([n])`, `relay_dest([n])` | the requests relayed since the last `send`, one per branch (retransmissions don't count): how many, the n-th one's R-URI / `ip:port` (no n: the last) |
| `ns.fn = true` / `false` / a number | a mock: the function returns that (its arguments are still checked) |
| `calls(ns.fn)` | how often a mocked function ran |
| `assert(cond)` | a failure is reported with its position and, for a comparison, the left side's value |

Shared tables, dialog variables and `log` work in tests as in routes.
`ferrosip test` exits non-zero when a test fails.
